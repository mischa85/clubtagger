/*
 * nfs_client.c - NFS Client for CDJ Database Fetching
 *
 * NFSv2 client for fetching rekordbox export.pdb from CDJs.
 * Ported from working cdj-sniffer.c implementation.
 */

#include "nfs_client.h"
#include "nfs_protocol.h"
#include "pdb.h"
#include "registration.h"
#include "../common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>

/*
 * ============================================================================
 * Module State
 * ============================================================================
 */

static int nfs_sock = -1;
static uint32_t nfs_xid = 0x12345678;
extern uint32_t our_ip;  /* From registration module */
extern const char *capture_interface;  /* From registration module */
extern int verbose;      /* From main */

pthread_mutex_t nfs_fetch_mu = PTHREAD_MUTEX_INITIALIZER;

/*
 * ============================================================================
 * Socket Management
 * ============================================================================
 */

void nfs_init_socket(void) {
    if (nfs_sock >= 0) return;  /* Already initialized */
    
    nfs_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (nfs_sock < 0) {
        logmsg("nfs", "Failed to create socket: %s", strerror(errno));
        return;
    }

    /* Bind to interface for link-local routing */
    if (capture_interface) {
        if (setsockopt(nfs_sock, SOL_SOCKET, SO_BINDTODEVICE, capture_interface,
                       strlen(capture_interface) + 1) < 0) {
            logmsg("nfs", "SO_BINDTODEVICE(%s) failed: %s",
                   capture_interface, strerror(errno));
            /* Continue anyway */
        }
    }
    
    /* Bind to our Pro DJ Link IP with ephemeral port */
    struct sockaddr_in bind_addr;
    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = 0;  /* Let OS assign port */
    bind_addr.sin_addr.s_addr = our_ip;
    if (bind(nfs_sock, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0) {
        logmsg("nfs", "bind to our_ip=%s failed: %s",
               ip_to_str(our_ip), strerror(errno));
    }
    
    /* Set socket timeout */
    struct timeval tv;
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    setsockopt(nfs_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
}

void nfs_close_socket(void) {
    if (nfs_sock >= 0) {
        close(nfs_sock);
        nfs_sock = -1;
    }
}

int nfs_socket_ready(void) {
    return nfs_sock >= 0;
}

/*
 * ============================================================================
 * RPC Helpers
 * ============================================================================
 */

/* Build RPC header using struct */
static int build_rpc_call(uint8_t *buf, uint32_t xid, uint32_t prog, uint32_t vers, 
                          uint32_t proc, const uint8_t *cred, size_t cred_len) {
    int pos = 0;
    
    /* RPC Call Header */
    rpc_call_header_t *hdr = (rpc_call_header_t *)buf;
    RPC_PUT_U32((uint8_t *)&hdr->xid, xid);
    RPC_PUT_U32((uint8_t *)&hdr->msg_type, RPC_CALL);
    RPC_PUT_U32((uint8_t *)&hdr->rpc_vers, 2);
    RPC_PUT_U32((uint8_t *)&hdr->prog, prog);
    RPC_PUT_U32((uint8_t *)&hdr->vers, vers);
    RPC_PUT_U32((uint8_t *)&hdr->proc, proc);
    pos = sizeof(rpc_call_header_t);
    
    /* Credentials: AUTH_UNIX or AUTH_NULL */
    if (cred && cred_len > 0) {
        memcpy(buf + pos, cred, cred_len);
        pos += cred_len;
    } else {
        /* AUTH_UNIX credentials (like python-prodj-link uses) */
        rpc_auth_unix_t *auth = (rpc_auth_unix_t *)(buf + pos);
        RPC_PUT_U32((uint8_t *)&auth->flavor, AUTH_UNIX);
        RPC_PUT_U32((uint8_t *)&auth->length, 20);
        RPC_PUT_U32((uint8_t *)&auth->stamp, 0xdeadbeef);
        RPC_PUT_U32((uint8_t *)&auth->machine_len, 0);
        RPC_PUT_U32((uint8_t *)&auth->uid, 0);
        RPC_PUT_U32((uint8_t *)&auth->gid, 0);
        RPC_PUT_U32((uint8_t *)&auth->gids_len, 0);
        pos += sizeof(rpc_auth_unix_t);
        
        /* AUTH_NULL verifier */
        rpc_auth_null_t *verifier = (rpc_auth_null_t *)(buf + pos);
        RPC_PUT_U32((uint8_t *)&verifier->flavor, AUTH_NULL);
        RPC_PUT_U32((uint8_t *)&verifier->length, 0);
        pos += sizeof(rpc_auth_null_t);
    }
    
    return pos;
}

/* Send RPC and receive reply using persistent socket.
 * max_retries bounds the send/recv attempts: 3 for normal calls, 1 for the
 * cheap probes the read loop fires while skipping over a silent region (a
 * silent chunk costs max_retries × SO_RCVTIMEO, so probes must stay at 1). */
static int nfs_rpc_call(uint32_t server_ip, uint16_t port, const uint8_t *request,
                        size_t req_len, uint8_t *response, size_t max_resp,
                        int max_retries) {
    /* Ensure socket is initialized */
    nfs_init_socket();
    if (nfs_sock < 0) {
        logmsg("nfs", "rpc_call: socket not ready (server=%s port=%u)",
               ip_to_str(server_ip), port);
        return -1;
    }
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = server_ip;
    
    /* Retry loop for UDP reliability */
    ssize_t received = -1;
    int send_errno = 0;
    int recv_errno = 0;
    for (int retry = 0; retry < max_retries; retry++) {
        /* Send request */
        if (sendto(nfs_sock, request, req_len, 0, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            send_errno = errno;
            continue;
        }

        /* Receive response */
        socklen_t addr_len = sizeof(addr);
        received = recvfrom(nfs_sock, response, max_resp, 0,
                            (struct sockaddr *)&addr, &addr_len);
        if (received > 0) break;  /* Success */
        recv_errno = errno;
    }

    if (received <= 0) {
        logmsg("nfs", "rpc_call to %s:%u: no reply after %d tr%s (send_errno=%d:%s recv_errno=%d:%s)",
               ip_to_str(server_ip), port, max_retries, max_retries == 1 ? "y" : "ies",
               send_errno, send_errno ? strerror(send_errno) : "ok",
               recv_errno, recv_errno ? strerror(recv_errno) : "timeout");
    }

    return (int)received;
}

/*
 * ============================================================================
 * Portmapper
 * ============================================================================
 */

int rpc_portmap_getport(uint32_t server_ip, uint32_t program, uint32_t version) {
    uint8_t request[128];
    uint8_t response[128];
    
    /* Build RPC CALL for PORTMAP GETPORT */
    int pos = build_rpc_call(request, ++nfs_xid, PORTMAP_PROGRAM, 2, PORTMAP_PROC_GETPORT, NULL, 0);
    
    /* GETPORT arguments */
    portmap_getport_args_t *args = (portmap_getport_args_t *)(request + pos);
    RPC_PUT_U32((uint8_t *)&args->prog, program);
    RPC_PUT_U32((uint8_t *)&args->vers, version);
    RPC_PUT_U32((uint8_t *)&args->prot, PORTMAP_PROT_UDP);
    RPC_PUT_U32((uint8_t *)&args->port, 0);  /* Query */
    pos += sizeof(portmap_getport_args_t);
    
    /* Send to portmapper on port 111 */
    int received = nfs_rpc_call(server_ip, PORTMAPPER_PORT, request, pos, response, sizeof(response), 3);
    
    if (received < (int)(sizeof(rpc_reply_header_t) + sizeof(portmap_getport_reply_t))) {
        logmsg("nfs", "PORTMAP getport(prog=%u vers=%u) from %s:111: short/no reply (%d bytes)",
               program, version, ip_to_str(server_ip), received);
        return -1;
    }

    /* Parse response */
    rpc_reply_header_t *reply = (rpc_reply_header_t *)response;
    uint32_t accept_stat = RPC_GET_U32((uint8_t *)&reply->accept_stat);
    if (accept_stat != RPC_SUCCESS) {
        logmsg("nfs", "PORTMAP getport(prog=%u vers=%u) from %s: RPC accept_stat=%u",
               program, version, ip_to_str(server_ip), accept_stat);
        return -1;
    }
    
    portmap_getport_reply_t *result = (portmap_getport_reply_t *)(response + sizeof(rpc_reply_header_t));
    int port = (int)RPC_GET_U32((uint8_t *)&result->port);
    
    if (verbose) {
        vlogmsg("cdj", "[PORTMAP] Program %u @ %s -> port %d", program, ip_to_str(server_ip), port);
    }
    
    return port;
}

/*
 * ============================================================================
 * Mount Operations
 * ============================================================================
 */

int nfs_mount_to_port(uint32_t server_ip, uint16_t mount_port, const char *export_path, 
                      uint8_t *root_fh, size_t *fh_len) {
    uint8_t request[256];
    uint8_t response[512];
    
    int pos = build_rpc_call(request, ++nfs_xid, MOUNT_PROGRAM, MOUNT_VERSION, MOUNT_PROC_MNT, NULL, 0);
    
    /* Path - CDJ expects UTF-16LE encoding! */
    size_t ascii_len = strlen(export_path);
    size_t path_len = ascii_len * 2;  /* UTF-16LE = 2 bytes per char */
    RPC_PUT_U32(request + pos, (uint32_t)path_len);
    pos += 4;
    /* Convert ASCII to UTF-16LE (little-endian) */
    for (size_t i = 0; i < ascii_len; i++) {
        request[pos++] = export_path[i];  /* Low byte = ASCII char */
        request[pos++] = 0x00;            /* High byte = 0 */
    }
    while (pos % 4 != 0) request[pos++] = 0;
    
    if (verbose) {
        vlogmsg("cdj", "[NFS] Mount %s:%d export=%s", ip_to_str(server_ip), mount_port, export_path);
    }
    
    int received = nfs_rpc_call(server_ip, mount_port, request, pos, response, sizeof(response), 3);

    /* Minimum: RPC reply header (24) + mount status (4) = 28 bytes.
     * Mount error replies carry no file handle. */
    if (received < (int)(sizeof(rpc_reply_header_t) + sizeof(uint32_t))) {
        logmsg("nfs", "Mount %s:%u export=%s: transport short reply (%d bytes)",
               ip_to_str(server_ip), mount_port, export_path, received);
        return -1;
    }

    /* Read mount status — valid even on 28-byte error replies */
    uint32_t mount_stat = RPC_GET_U32(response + sizeof(rpc_reply_header_t));

    if (verbose) {
        vlogmsg("cdj", "[NFS] Mount status: %u", mount_stat);
    }

    if (mount_stat != 0) {
        const char *stat_label =
            (mount_stat == NFSERR_NOENT)  ? " (NOENT — export not present)" :
            (mount_stat == NFSERR_ACCES)  ? " (ACCES)" : "";
        logmsg("nfs", "Mount %s:%u export=%s rejected: mount_stat=%u%s",
               ip_to_str(server_ip), mount_port, export_path, mount_stat, stat_label);
        return (mount_stat == NFSERR_NOENT) ? -ENOENT : -1;
    }

    /* Success path needs full reply: status (4) + fh (32) */
    if (received < (int)(sizeof(rpc_reply_header_t) + sizeof(mount_mnt_reply_t))) {
        logmsg("nfs", "Mount %s:%u export=%s: OK status but reply truncated (%d bytes)",
               ip_to_str(server_ip), mount_port, export_path, received);
        return -1;
    }

    /* File handle - MNT v1 returns fixed 32-byte handle */
    mount_mnt_reply_t *reply = (mount_mnt_reply_t *)(response + sizeof(rpc_reply_header_t));
    memcpy(root_fh, reply->fh, NFS_FHSIZE);
    *fh_len = NFS_FHSIZE;
    
    return 0;
}

/*
 * ============================================================================
 * NFS Operations
 * ============================================================================
 */

/* NFS LOOKUP - find file handle (NFSv2 - fixed 32-byte handles) */
int nfs_lookup(uint32_t server_ip, uint16_t nfs_port, const uint8_t *dir_fh,
               const char *name, uint8_t *file_fh, uint32_t *out_size) {
    uint8_t request[512];
    uint8_t response[1024];

    if (out_size) *out_size = 0;
    
    if (verbose) {
        vlogmsg("cdj", "[NFS] LOOKUP '%s' in dir fh[0..3]=%02x%02x%02x%02x (port %u)", 
                    name, dir_fh[0], dir_fh[1], dir_fh[2], dir_fh[3], nfs_port);
    }
    
    /* Use NFS version 2 */
    int pos = build_rpc_call(request, ++nfs_xid, NFS_PROGRAM, NFS_VERSION, NFS_PROC_LOOKUP, NULL, 0);
    
    /* Directory file handle (fixed 32 bytes in NFSv2) */
    memcpy(request + pos, dir_fh, NFS_FHSIZE);
    pos += NFS_FHSIZE;
    
    /* Filename - CDJ expects UTF-16LE encoding! */
    size_t ascii_len = strlen(name);
    size_t name_len = ascii_len * 2;  /* UTF-16LE = 2 bytes per char */
    RPC_PUT_U32(request + pos, (uint32_t)name_len);
    pos += 4;
    /* Convert ASCII to UTF-16LE */
    for (size_t i = 0; i < ascii_len; i++) {
        request[pos++] = name[i];   /* Low byte = ASCII char */
        request[pos++] = 0x00;      /* High byte = 0 */
    }
    while (pos % 4 != 0) request[pos++] = 0;
    
    int received = nfs_rpc_call(server_ip, nfs_port, request, pos, response, sizeof(response), 3);

    /* Minimum: RPC reply header (24) + NFS status (4) = 28 bytes.
     * NFS error replies (NOENT/STALE/ACCES) carry no file handle, so they
     * are exactly 28 bytes — must NOT be rejected as "short response". */
    if (received < (int)(sizeof(rpc_reply_header_t) + sizeof(uint32_t))) {
        logmsg("nfs", "LOOKUP '%s' on %s:%u: transport short reply (%d bytes)",
               name, ip_to_str(server_ip), nfs_port, received);
        return -1;
    }

    /* Check RPC reply status */
    rpc_reply_header_t *rpc = (rpc_reply_header_t *)response;
    uint32_t reply_stat = RPC_GET_U32((uint8_t *)&rpc->reply_stat);
    if (reply_stat != RPC_MSG_ACCEPTED) {
        logmsg("nfs", "LOOKUP '%s' on %s:%u: RPC rejected (reply_stat=%u)",
               name, ip_to_str(server_ip), nfs_port, reply_stat);
        return -1;
    }

    /* Read NFS status — valid even on 28-byte error replies */
    uint32_t lookup_stat = RPC_GET_U32(response + sizeof(rpc_reply_header_t));
    if (lookup_stat != NFS_OK) {
        /* NOENT is expected protocol behavior — caller is probing alternate
         * extensions or checking for non-rekordbox media, and logs the
         * meaningful message at its own layer. Other NFS errors are real. */
        if (lookup_stat == NFSERR_NOENT) {
            vlogmsg("nfs", "LOOKUP '%s' on %s:%u: NOENT",
                    name, ip_to_str(server_ip), nfs_port);
            return -ENOENT;
        }
        const char *stat_label =
            (lookup_stat == NFSERR_STALE) ? " (STALE — filehandle expired)" :
            (lookup_stat == NFSERR_ACCES) ? " (ACCES)" : "";
        logmsg("nfs", "LOOKUP '%s' on %s:%u failed: nfs_stat=%u%s",
               name, ip_to_str(server_ip), nfs_port, lookup_stat, stat_label);
        return -1;
    }

    /* Success path needs the full reply: status (4) + fh (32) */
    if (received < (int)(sizeof(rpc_reply_header_t) + sizeof(nfs_lookup_reply_t))) {
        logmsg("nfs", "LOOKUP '%s' on %s:%u: OK status but reply truncated (%d bytes)",
               name, ip_to_str(server_ip), nfs_port, received);
        return -1;
    }

    /* File handle - NFSv2 is fixed 32 bytes */
    nfs_lookup_reply_t *reply = (nfs_lookup_reply_t *)(response + sizeof(rpc_reply_header_t));
    memcpy(file_fh, reply->fh, NFS_FHSIZE);

    /* The fattr follows the fh in the LOOKUP reply (status + fh + fattr).
     * Hand the file size back so the caller can size its read buffer to the
     * real length instead of a worst-case cap. */
    if (out_size &&
        received >= (int)(sizeof(rpc_reply_header_t) + sizeof(nfs_lookup_reply_t) + sizeof(nfs_fattr_t))) {
        const nfs_fattr_t *fattr =
            (const nfs_fattr_t *)(response + sizeof(rpc_reply_header_t) + sizeof(nfs_lookup_reply_t));
        *out_size = RPC_GET_U32((const uint8_t *)&fattr->size);
    }

    if (verbose) {
        vlogmsg("cdj", "[NFS] LOOKUP '%s' OK -> fh[0..3]=%02x%02x%02x%02x",
                    name, file_fh[0], file_fh[1], file_fh[2], file_fh[3]);
    }

    return 0;
}

/* 8 KB chunks. The CDJ-3000X NFS server appears to have an 8K-aligned page
 * cache; smaller reads (4K tested) trigger IO errors on pages 8K reads serve
 * fine. Keep this at 8192. */
#define NFS_READ_CHUNK    8192
#define NFS_READ_DEADLINE 20                 /* whole-file backstop (s)   */
#define NFS_PROBE_MAX     (1 * 1024 * 1024)  /* max silent-skip stride    */

/* Result of a single chunk read. */
typedef enum {
    NREAD_DATA = 0,   /* got data: *n bytes written to buf+off          */
    NREAD_EOF,        /* server returned 0 bytes (true end of file)     */
    NREAD_SILENT,     /* no usable reply (transport timeout)            */
    NREAD_BADPAGE,    /* NFSERR_IO — server refuses this byte range     */
    NREAD_FATAL       /* RPC reject / invalid / NOENT / STALE / ACCES   */
} nread_result_t;

/* Read up to NFS_READ_CHUNK bytes at `off` into buf+off (clamped to cap).
 * retries is passed to nfs_rpc_call (3 normal, 1 for cheap probes). On
 * NREAD_DATA, *n is the byte count. *fsize gets the file size from the reply
 * fattr (0 if absent); *nstat gets the NFS status (for NOENT classification).
 * Logs the specific reason for fatal/non-IO errors; silence/IO/EOF are
 * expected and left for the caller to account. */
static nread_result_t nfs_read_chunk(uint32_t server_ip, uint16_t nfs_port,
                                     const uint8_t *file_fh, uint8_t *buf,
                                     size_t off, size_t cap, int retries,
                                     size_t *n, uint32_t *fsize, uint32_t *nstat) {
    *n = 0; *fsize = 0; *nstat = 0;

    uint8_t request[256];
    uint8_t *response = malloc(NFS_READ_CHUNK + 256);
    if (!response) {
        logmsg("nfs", "READ malloc failed (chunk=%d) at offset=%zu", NFS_READ_CHUNK + 256, off);
        return NREAD_FATAL;
    }

    int pos = build_rpc_call(request, ++nfs_xid, NFS_PROGRAM, NFS_VERSION, NFS_PROC_READ, NULL, 0);
    nfs_read_args_t *args = (nfs_read_args_t *)(request + pos);
    memcpy(args->fh, file_fh, NFS_FHSIZE);
    RPC_PUT_U32((uint8_t *)&args->offset, (uint32_t)off);
    RPC_PUT_U32((uint8_t *)&args->count, NFS_READ_CHUNK);
    RPC_PUT_U32((uint8_t *)&args->totalcount, 0);  /* Unused in NFSv2 */
    pos += sizeof(nfs_read_args_t);

    int received = nfs_rpc_call(server_ip, nfs_port, request, pos, response,
                                NFS_READ_CHUNK + 256, retries);
    if (received < (int)(sizeof(rpc_reply_header_t) + sizeof(uint32_t))) {
        free(response);
        return NREAD_SILENT;
    }

    rpc_reply_header_t *rpc = (rpc_reply_header_t *)response;
    if (RPC_GET_U32((uint8_t *)&rpc->reply_stat) != RPC_MSG_ACCEPTED) {
        logmsg("nfs", "READ on %s:%u: RPC rejected at offset=%zu",
               ip_to_str(server_ip), nfs_port, off);
        free(response);
        return NREAD_FATAL;
    }

    /* NFS status — valid even on 28-byte error replies (no fattr) */
    int rpos = sizeof(rpc_reply_header_t);
    uint32_t st = RPC_GET_U32(response + rpos);
    *nstat = st;
    if (st != NFS_OK) {
        if (st == NFSERR_IO) { free(response); return NREAD_BADPAGE; }
        const char *lbl =
            (st == NFSERR_NOENT) ? " (NOENT — file not present)" :
            (st == NFSERR_STALE) ? " (STALE — filehandle expired)" :
            (st == NFSERR_ACCES) ? " (ACCES)" : "";
        logmsg("nfs", "READ on %s:%u nfs_stat=%u%s at offset=%zu",
               ip_to_str(server_ip), nfs_port, st, lbl, off);
        free(response);
        return NREAD_FATAL;
    }

    if (received >= rpos + (int)sizeof(uint32_t) + (int)sizeof(nfs_fattr_t)) {
        const nfs_fattr_t *fattr = (const nfs_fattr_t *)(response + rpos + sizeof(uint32_t));
        *fsize = RPC_GET_U32((const uint8_t *)&fattr->size);
    }

    rpos += sizeof(uint32_t) + sizeof(nfs_fattr_t);
    uint32_t data_size = RPC_GET_U32(response + rpos);
    rpos += 4;
    if (data_size > NFS_READ_CHUNK || rpos + (int)data_size > received) {
        logmsg("nfs", "READ on %s:%u: invalid data_size=%u rpos=%d received=%d at offset=%zu",
               ip_to_str(server_ip), nfs_port, data_size, rpos, received, off);
        free(response);
        return NREAD_FATAL;
    }
    if (data_size == 0) { free(response); return NREAD_EOF; }
    if (off + data_size > cap) data_size = (uint32_t)(cap - off);
    memcpy(buf + off, response + rpos, data_size);
    *n = data_size;
    free(response);
    return NREAD_DATA;
}

/* ----- read-region diagnostics ------------------------------------------
 * The per-chunk status array is the source of truth; the segment list below
 * is derived from it at the end to report which byte ranges were read OK,
 * tried-and-failed, or never tried (skipped and not recovered). */
typedef enum { RSEG_OK = 0, RSEG_FAIL, RSEG_UNTRIED } rseg_kind_t;

#define RSEG_MAX   48   /* cap on tracked regions (coalesced runs)      */
#define RSEG_BAR_W 48   /* width of the at-a-glance visualization bar   */

typedef struct { size_t off, len; rseg_kind_t kind; } rseg_t;

static void rseg_add(rseg_t *segs, int *n, int *truncated,
                     size_t off, size_t len, rseg_kind_t kind) {
    if (len == 0) return;
    if (*n > 0) {
        rseg_t *last = &segs[*n - 1];
        if (last->kind == kind && last->off + last->len == off) {
            last->len += len;   /* coalesce contiguous same-kind runs */
            return;
        }
    }
    if (*n >= RSEG_MAX) { *truncated = 1; return; }
    segs[*n] = (rseg_t){ off, len, kind };
    (*n)++;
}

/* Per-chunk fill status. calloc gives ST_UNTRIED (0) for free — anything we
 * never touch stays untried without a write. */
enum { ST_UNTRIED = 0, ST_OK = 1, ST_FAIL = 2 };

/* Back-fill a [start,end) gap the stride just skipped, the instant a read past
 * it succeeds — the CDJ is responsive right now, so the gap is most likely
 * readable in this window. Recovered chunks become OK, the rest FAIL (tried
 * again). Bounded by the read deadline. Returns chunks recovered. */
static int nfs_backfill_gap(uint32_t server_ip, uint16_t nfs_port,
                            const uint8_t *file_fh, uint8_t *buf,
                            size_t start, size_t end, size_t cap,
                            uint8_t *status, time_t deadline) {
    int recovered = 0;
    for (size_t coff = start; coff < end; coff += NFS_READ_CHUNK) {
        size_t c = coff / NFS_READ_CHUNK;
        if (status[c] == ST_OK) continue;
        if (time(NULL) > deadline) break;
        size_t n = 0; uint32_t fsize = 0, nstat = 0;
        nread_result_t r = nfs_read_chunk(server_ip, nfs_port, file_fh, buf,
                                          coff, cap, 1, &n, &fsize, &nstat);
        if (r == NREAD_DATA) { status[c] = ST_OK; recovered++; }
        else                   status[c] = ST_FAIL;   /* tried again, still bad */
    }
    return recovered;
}

/* NFS READ - read file data */
int nfs_read_file(uint32_t server_ip, uint16_t nfs_port, const uint8_t *file_fh,
                  const char *name, uint8_t *buf, size_t buf_len, size_t *bytes_read) {
    const char *nm = name ? name : "(file)";
    if (verbose) {
        vlogmsg("cdj", "[NFS] READ %s fh[0..3]=%02x%02x%02x%02x (port %u)",
                    nm, file_fh[0], file_fh[1], file_fh[2], file_fh[3], nfs_port);
    }

    /* Offset-addressed fill into a pre-zeroed buffer: any region we cannot
     * read simply stays zero, so a "hole" costs nothing to represent. We fill
     * [0, target) by offset; target is the real file size once the first good
     * reply reports it, otherwise the caller's buffer cap.
     *
     * Forward pass crosses gaps without aborting: NFSERR_IO skips one 8K page
     * (the server replies instantly); transport silence skips a stride that
     * doubles per consecutive silent probe (8K → 1MB) with single-attempt
     * probes, so a dead region is crossed in a handful of cheap reads instead
     * of thousands of stalls. A back-fill pass then revisits interior gaps. */
    memset(buf, 0, buf_len);

    size_t   nchunks   = (buf_len + NFS_READ_CHUNK - 1) / NFS_READ_CHUNK;
    uint8_t *status    = calloc(nchunks ? nchunks : 1, 1);
    if (!status)
        logmsg("nfs", "READ %s on %s:%u: status alloc failed — coverage map unavailable",
               nm, ip_to_str(server_ip), nfs_port);

    size_t   off       = 0;               /* next read position / fill offset */
    size_t   target    = buf_len;         /* refined to file size on 1st read */
    int      skips     = 0;               /* forward-pass skip events         */
    size_t   stride    = NFS_READ_CHUNK;  /* grows during a silent run        */
    uint32_t file_size = 0;
    int      got_first = 0;               /* read at least one good chunk?    */
    int      eof       = 0;
    int      in_run    = 0;               /* mid silent run (skipping)?       */
    size_t   run_start = 0;               /* offset the current silent run began */
    int      refilled  = 0;               /* chunks recovered by back-fill    */
    time_t   deadline  = time(NULL) + NFS_READ_DEADLINE;

    /* ---- forward pass ---- */
    while (!eof && off < target) {
        if (time(NULL) > deadline) {
            logmsg("nfs", "READ %s timeout from %s:%u after %ds at offset=%zu of %u — keeping partial",
                   nm, ip_to_str(server_ip), nfs_port, NFS_READ_DEADLINE, off, file_size);
            break;  /* keep what we have — the rest is already zero */
        }

        /* Cheap single-attempt probes while skipping a silent run; robust
         * 3-attempt reads otherwise. */
        int recovering = (stride > NFS_READ_CHUNK);
        size_t n = 0; uint32_t fsize = 0, nstat = 0;
        nread_result_t r = nfs_read_chunk(server_ip, nfs_port, file_fh, buf,
                                          off, target, recovering ? 1 : 3,
                                          &n, &fsize, &nstat);

        if (r == NREAD_SILENT) {
            if (!got_first) {
                logmsg("nfs", "READ %s on %s:%u: no reply at offset 0 — file unreadable",
                       nm, ip_to_str(server_ip), nfs_port);
                free(status); *bytes_read = 0; return -1;
            }
            /* The probed chunk was tried (failed); the rest of the stride is
             * jumped over and left UNTRIED until a read past it succeeds, at
             * which point we back-fill the gap (see the NREAD_DATA branch). */
            if (!in_run) { run_start = off; in_run = 1; }
            if (status) status[off / NFS_READ_CHUNK] = ST_FAIL;
            size_t skip = stride;
            if (off + skip > target) skip = target - off;
            off    += skip;
            skips++;
            stride  = (stride * 2 > NFS_PROBE_MAX) ? NFS_PROBE_MAX : stride * 2;
            continue;
        }
        if (r == NREAD_FATAL) {
            if (!got_first) {
                free(status); *bytes_read = 0;
                return (nstat == NFSERR_NOENT) ? -ENOENT : -1;
            }
            if (status) status[off / NFS_READ_CHUNK] = ST_FAIL;
            off += NFS_READ_CHUNK; skips++;
            continue;
        }
        if (r == NREAD_BADPAGE) {
            /* Server-confirmed bad page: skip one chunk. (No got_first gate —
             * an IO error at offset 0 just means page 1 is bad; keep going.) */
            if (status) status[off / NFS_READ_CHUNK] = ST_FAIL;
            off += NFS_READ_CHUNK; skips++;
            continue;
        }
        if (r == NREAD_EOF) { eof = 1; continue; }

        /* NREAD_DATA. Capture the real file size from the first good reply. */
        if (!got_first) {
            file_size = fsize;
            if (fsize > 0 && fsize <= buf_len) {
                target = fsize;
            } else if (fsize > buf_len) {
                logmsg("nfs", "READ %s on %s:%u: file is %u bytes, exceeds %zu-byte cap — fetch will be partial",
                       nm, ip_to_str(server_ip), nfs_port, fsize, buf_len);
            }
        }
        /* Resumed past a silent run → the CDJ is responsive now, so seek back
         * and fill the gap the stride skipped before continuing forward. */
        if (in_run) {
            if (status)
                refilled += nfs_backfill_gap(server_ip, nfs_port, file_fh, buf,
                                             run_start, off, target, status, deadline);
            in_run = 0;
        }
        if (status) status[off / NFS_READ_CHUNK] = ST_OK;
        off       += n;
        got_first  = 1;
        stride     = NFS_READ_CHUNK;       /* success → out of any silent run */
        if (n < NFS_READ_CHUNK) eof = 1;   /* short read = end of file        */
    }

    if (!got_first) {
        logmsg("nfs", "READ %s on %s:%u: no data read", nm, ip_to_str(server_ip), nfs_port);
        free(status); *bytes_read = 0; return -1;
    }

    *bytes_read = eof ? off : target;

    /* A trailing silent run never resumes, so its gap was never back-filled —
     * those chunks stay UNTRIED (the dead tail), which is the honest report. */
    if (refilled)
        logmsg("nfs", "READ %s on %s:%u: back-fill recovered %d chunk(s) (%d KB)",
               nm, ip_to_str(server_ip), nfs_port, refilled,
               refilled * NFS_READ_CHUNK / 1024);

    /* ---- derive byte counters + region map from the per-chunk status ---- */
    if (status) {
        size_t ok_bytes = 0, fail_bytes = 0, untried_bytes = 0;
        rseg_t segs[RSEG_MAX]; int nsegs = 0, seg_trunc = 0;
        size_t used = *bytes_read;
        for (size_t c = 0; c < nchunks; c++) {
            size_t coff = c * NFS_READ_CHUNK;
            if (coff >= used) break;
            size_t clen = (coff + NFS_READ_CHUNK > used) ? used - coff : NFS_READ_CHUNK;
            rseg_kind_t k = status[c] == ST_OK   ? RSEG_OK
                          : status[c] == ST_FAIL ? RSEG_FAIL : RSEG_UNTRIED;
            if      (k == RSEG_OK)   ok_bytes      += clen;
            else if (k == RSEG_FAIL) fail_bytes    += clen;
            else                     untried_bytes += clen;
            rseg_add(segs, &nsegs, &seg_trunc, coff, clen, k);
        }

        /* Always report coverage for every NFS read — clean or holey. */
        const char *tag = (fail_bytes || untried_bytes) ? "" : " (clean)";
        logmsg("nfs", "READ %s on %s:%u done: %zu/%u read, %zu failed, %zu untried, %d skip(s)%s",
               nm, ip_to_str(server_ip), nfs_port, ok_bytes, file_size,
               fail_bytes, untried_bytes, skips, tag);

        /* At-a-glance bar, severity-priority so even a single failed page is
         * visible: any fail in a cell → 'x', else any untried → '.', else ok. */
        char bar[RSEG_BAR_W + 1];
        size_t span = used ? used : 1;
        for (int b = 0; b < RSEG_BAR_W; b++) {
            size_t cs = (size_t)b       * span / RSEG_BAR_W;
            size_t ce = (size_t)(b + 1) * span / RSEG_BAR_W;
            size_t ov[3] = { 0, 0, 0 };
            for (int i = 0; i < nsegs; i++) {
                size_t s = segs[i].off, e = s + segs[i].len;
                size_t lo = s > cs ? s : cs;
                size_t hi = e < ce ? e : ce;
                if (lo < hi) ov[segs[i].kind] += hi - lo;
            }
            bar[b] = ov[RSEG_FAIL] ? 'x' : (ov[RSEG_UNTRIED] ? '.' : '#');
        }
        bar[RSEG_BAR_W] = '\0';
        logmsg("nfs", "READ %s on %s:%u  [%s]  (# ok  x fail  . untried)",
               nm, ip_to_str(server_ip), nfs_port, bar);

        /* One line per region, with hex byte ranges. */
        for (int i = 0; i < nsegs; i++) {
            const char *lbl = segs[i].kind == RSEG_OK ? "READ OK"
                            : segs[i].kind == RSEG_FAIL ? "FAIL" : "UNTRIED";
            logmsg("nfs", "READ %s on %s:%u    0x%08zx - 0x%08zx  %-7s  (%zu bytes)",
                   nm, ip_to_str(server_ip), nfs_port,
                   segs[i].off, segs[i].off + segs[i].len, lbl, segs[i].len);
        }
        if (seg_trunc)
            logmsg("nfs", "READ %s on %s:%u    …(more regions than %d, truncated)",
                   nm, ip_to_str(server_ip), nfs_port, RSEG_MAX);
    } else {
        logmsg("nfs", "READ %s on %s:%u done: %zu bytes (coverage map unavailable)",
               nm, ip_to_str(server_ip), nfs_port, *bytes_read);
    }

    free(status);
    return 0;
}

int nfs_fetch_path(uint32_t server_ip, uint16_t nfs_port, uint16_t mount_port,
                   uint8_t slot, const char *path,
                   uint8_t *buf, size_t buf_len, size_t *bytes_read) {
    if (!path || path[0] != '/') {
        logmsg("nfs", "fetch_path: bad path=%s (server=%s slot=%u)",
               path ? path : "(null)", ip_to_str(server_ip), slot);
        return -1;
    }
    if (nfs_port == 0 || mount_port == 0) {
        logmsg("nfs", "fetch_path: missing ports for %s (nfs=%u mount=%u) — announce portmap discovery did not complete",
               ip_to_str(server_ip), nfs_port, mount_port);
        return -1;
    }

    /* Determine export path from slot (same as OneLibrary/PDB fetch) */
    const char *export_path;
    switch (slot) {
        case 2: export_path = "/B/"; break;  /* SD */
        case 3: export_path = "/C/"; break;  /* USB */
        default:
            logmsg("nfs", "fetch_path: unsupported slot=%u (server=%s path=%s)",
                   slot, ip_to_str(server_ip), path);
            return -1;
    }

    /* Ensure socket is open (may have been closed by previous fetch) */
    if (!nfs_socket_ready()) nfs_init_socket();

    uint8_t root_fh[NFS_FHSIZE];
    size_t fh_len = 0;

    int mount_rc = nfs_mount_to_port(server_ip, mount_port,
                                     export_path, root_fh, &fh_len);
    if (mount_rc != 0) {
        if (mount_rc == -ENOENT) {
            logmsg("nfs", "fetch_path: export %s NOENT on %s:%u — slot has no rekordbox media (will not retry)",
                   export_path, ip_to_str(server_ip), mount_port);
            return -ENOENT;
        }
        logmsg("nfs", "fetch_path: mount %s on %s:%u failed",
               export_path, ip_to_str(server_ip), mount_port);
        return -1;
    }

    /* Walk path components */
    uint8_t dir_fh[NFS_FHSIZE], file_fh[NFS_FHSIZE];
    memcpy(dir_fh, root_fh, NFS_FHSIZE);

    char pathbuf[256];
    strncpy(pathbuf, path + 1, sizeof(pathbuf) - 1);
    pathbuf[sizeof(pathbuf) - 1] = '\0';

    char *saveptr = NULL;
    char *component = strtok_r(pathbuf, "/", &saveptr);
    while (component) {
        char *next = strtok_r(NULL, "/", &saveptr);
        int lk = nfs_lookup(server_ip, nfs_port, dir_fh, component, file_fh, NULL);
        if (lk != 0) {
            if (lk == -ENOENT) {
                logmsg("nfs", "fetch_path: NOENT at '%s' in %s — file not present (will not retry)",
                       component, path);
                return -ENOENT;
            }
            logmsg("nfs", "fetch_path: lookup failed at '%s' in %s (rc=%d)", component, path, lk);
            return -1;
        }
        if (next) memcpy(dir_fh, file_fh, NFS_FHSIZE);
        component = next;
    }

    /* Read the file */
    int rc = nfs_read_file(server_ip, nfs_port, file_fh, path, buf, buf_len, bytes_read);
    nfs_close_socket();
    if (rc == -ENOENT) {
        logmsg("nfs", "fetch_path: READ NOENT for %s — file vanished mid-fetch (will not retry)", path);
        return -ENOENT;
    }
    return rc;
}

int send_nfs_unlock(uint32_t target_ip) {
    (void)target_ip;
    return -1;  /* Not implemented */
}

/*
 * ============================================================================
 * NFS Traffic Parsing (Passive Eavesdropping)
 * ============================================================================
 * 
 * When connected to a SPAN port, we can observe NFS traffic between CDJs
 * and extract file paths and data being transferred.
 */

/*
 * File handle cache - maps file handles to paths for passive sniffing.
 * When we see a LOOKUP response, we record the handle->path mapping.
 * When we see a READ request, we can identify what file is being read.
 */
#define FH_CACHE_SIZE 64

typedef struct {
    uint8_t  fh[NFS_FHSIZE];
    uint32_t server_ip;
    char     path[256];
    time_t   last_seen;
} fh_cache_entry_t;

static fh_cache_entry_t fh_cache[FH_CACHE_SIZE];
static int fh_cache_count = 0;

/* Find cached file handle */
static fh_cache_entry_t *find_fh_cache(const uint8_t *fh, uint32_t server_ip) {
    for (int i = 0; i < fh_cache_count; i++) {
        if (fh_cache[i].server_ip == server_ip && 
            memcmp(fh_cache[i].fh, fh, NFS_FHSIZE) == 0) {
            return &fh_cache[i];
        }
    }
    return NULL;
}

/* Add file handle to cache */
static void add_fh_cache(const uint8_t *fh, uint32_t server_ip, const char *path) {
    fh_cache_entry_t *entry = find_fh_cache(fh, server_ip);
    if (!entry) {
        if (fh_cache_count < FH_CACHE_SIZE) {
            entry = &fh_cache[fh_cache_count++];
        } else {
            /* Evict oldest entry */
            time_t oldest = time(NULL);
            int oldest_idx = 0;
            for (int i = 0; i < FH_CACHE_SIZE; i++) {
                if (fh_cache[i].last_seen < oldest) {
                    oldest = fh_cache[i].last_seen;
                    oldest_idx = i;
                }
            }
            entry = &fh_cache[oldest_idx];
        }
    }
    memcpy(entry->fh, fh, NFS_FHSIZE);
    entry->server_ip = server_ip;
    strncpy(entry->path, path, sizeof(entry->path) - 1);
    entry->path[sizeof(entry->path) - 1] = '\0';
    entry->last_seen = time(NULL);
}

/*
 * Pending LOOKUP cache - track LOOKUP requests by XID to correlate with responses.
 */
#define PENDING_LOOKUP_SIZE 32

typedef struct {
    uint32_t xid;
    uint32_t client_ip;
    uint32_t server_ip;
    uint8_t  dir_fh[NFS_FHSIZE];
    char     name[128];
    time_t   timestamp;
} pending_lookup_t;

static pending_lookup_t pending_lookups[PENDING_LOOKUP_SIZE];
static int pending_lookup_count = 0;

/* Record a pending LOOKUP request */
static void add_pending_lookup(uint32_t xid, uint32_t client_ip, uint32_t server_ip,
                               const uint8_t *dir_fh, const char *name) {
    /* Evict stale entries (older than 5 seconds) */
    time_t now = time(NULL);
    for (int i = 0; i < pending_lookup_count; ) {
        if (now - pending_lookups[i].timestamp > 5) {
            pending_lookups[i] = pending_lookups[--pending_lookup_count];
        } else {
            i++;
        }
    }
    
    if (pending_lookup_count < PENDING_LOOKUP_SIZE) {
        pending_lookup_t *p = &pending_lookups[pending_lookup_count++];
        p->xid = xid;
        p->client_ip = client_ip;
        p->server_ip = server_ip;
        memcpy(p->dir_fh, dir_fh, NFS_FHSIZE);
        strncpy(p->name, name, sizeof(p->name) - 1);
        p->name[sizeof(p->name) - 1] = '\0';
        p->timestamp = now;
    }
}

/* Find and remove pending LOOKUP by XID */
static pending_lookup_t *find_pending_lookup(uint32_t xid, uint32_t server_ip) {
    for (int i = 0; i < pending_lookup_count; i++) {
        if (pending_lookups[i].xid == xid && pending_lookups[i].server_ip == server_ip) {
            return &pending_lookups[i];
        }
    }
    return NULL;
}

static void remove_pending_lookup(uint32_t xid, uint32_t server_ip) {
    for (int i = 0; i < pending_lookup_count; i++) {
        if (pending_lookups[i].xid == xid && pending_lookups[i].server_ip == server_ip) {
            pending_lookups[i] = pending_lookups[--pending_lookup_count];
            return;
        }
    }
}

/*
 * Passive PDB reassembly - capture export.pdb when another device fetches it.
 */
#define MAX_PDB_REASSEMBLY 4  /* Track up to 4 concurrent PDB transfers */

typedef struct {
    uint32_t server_ip;           /* CDJ serving the file */
    uint32_t client_ip;           /* Device requesting it */
    uint8_t  fh[NFS_FHSIZE];      /* File handle for the database file */
    uint32_t file_size;           /* Expected size from fattr */
    uint32_t received;            /* Bytes received so far */
    uint8_t *buffer;              /* Reassembly buffer */
    time_t   last_activity;       /* For timeout */
    uint8_t  is_onelibrary;       /* 1 = exportLibrary.db, 0 = export.pdb */
} pdb_reassembly_t;

static pdb_reassembly_t pdb_reassembly[MAX_PDB_REASSEMBLY];

/* Pending READ cache - track READ requests to correlate with responses */
#define PENDING_READ_SIZE 64

typedef struct {
    uint32_t xid;
    uint32_t client_ip;
    uint32_t server_ip;
    uint8_t  fh[NFS_FHSIZE];
    uint32_t offset;
    uint32_t count;
    time_t   timestamp;
} pending_read_t;

static pending_read_t pending_reads[PENDING_READ_SIZE];
static int pending_read_count = 0;

static void add_pending_read(uint32_t xid, uint32_t client_ip, uint32_t server_ip,
                             const uint8_t *fh, uint32_t offset, uint32_t count) {
    time_t now = time(NULL);
    /* Evict stale entries */
    for (int i = 0; i < pending_read_count; ) {
        if (now - pending_reads[i].timestamp > 10) {
            pending_reads[i] = pending_reads[--pending_read_count];
        } else {
            i++;
        }
    }
    if (pending_read_count < PENDING_READ_SIZE) {
        pending_read_t *p = &pending_reads[pending_read_count++];
        p->xid = xid;
        p->client_ip = client_ip;
        p->server_ip = server_ip;
        memcpy(p->fh, fh, NFS_FHSIZE);
        p->offset = offset;
        p->count = count;
        p->timestamp = now;
    }
}

static pending_read_t *find_pending_read(uint32_t xid, uint32_t server_ip) {
    for (int i = 0; i < pending_read_count; i++) {
        if (pending_reads[i].xid == xid && pending_reads[i].server_ip == server_ip) {
            return &pending_reads[i];
        }
    }
    return NULL;
}

static void remove_pending_read(uint32_t xid, uint32_t server_ip) {
    for (int i = 0; i < pending_read_count; i++) {
        if (pending_reads[i].xid == xid && pending_reads[i].server_ip == server_ip) {
            pending_reads[i] = pending_reads[--pending_read_count];
            return;
        }
    }
}

static pdb_reassembly_t *find_pdb_reassembly(uint32_t server_ip, const uint8_t *fh) {
    for (int i = 0; i < MAX_PDB_REASSEMBLY; i++) {
        if (pdb_reassembly[i].buffer && pdb_reassembly[i].server_ip == server_ip &&
            memcmp(pdb_reassembly[i].fh, fh, NFS_FHSIZE) == 0) {
            return &pdb_reassembly[i];
        }
    }
    return NULL;
}

static void start_pdb_reassembly(uint32_t server_ip, uint32_t client_ip,
                                  const uint8_t *fh, uint32_t file_size) {
    /* Find free slot or evict oldest */
    pdb_reassembly_t *slot = NULL;
    time_t oldest = time(NULL);
    int oldest_idx = 0;
    
    for (int i = 0; i < MAX_PDB_REASSEMBLY; i++) {
        if (!pdb_reassembly[i].buffer) {
            slot = &pdb_reassembly[i];
            break;
        }
        if (pdb_reassembly[i].last_activity < oldest) {
            oldest = pdb_reassembly[i].last_activity;
            oldest_idx = i;
        }
    }
    
    if (!slot) {
        /* Evict oldest */
        slot = &pdb_reassembly[oldest_idx];
        free(slot->buffer);
        slot->buffer = NULL;
    }
    
    slot->buffer = calloc(1, file_size);
    if (!slot->buffer) return;
    
    slot->server_ip = server_ip;
    slot->client_ip = client_ip;
    memcpy(slot->fh, fh, NFS_FHSIZE);
    slot->file_size = file_size;
    slot->received = 0;
    slot->last_activity = time(NULL);
    
    vlogmsg("cdj", "[NFS-SNIFF] Started passive PDB capture from %s (%u bytes)",
               ip_to_str(server_ip), file_size);
}

static void add_pdb_data(pdb_reassembly_t *r, uint32_t offset, const uint8_t *data, uint32_t len) {
    if (offset + len > r->file_size) {
        len = r->file_size - offset;  /* Clamp */
    }
    if (offset < r->file_size) {
        memcpy(r->buffer + offset, data, len);
        /* Simple tracking - mark high water mark */
        if (offset + len > r->received) {
            r->received = offset + len;
        }
        r->last_activity = time(NULL);
    }
}

static void complete_pdb_reassembly(pdb_reassembly_t *r) {
    if (r->is_onelibrary) {
        /* TODO: passive OneLibrary ingestion is disabled until the
         * onelibrary_thread worker exposes an "ingest pre-decrypted bytes"
         * API. The active fetch path covers our needs; passive sniff was
         * an opportunistic shortcut. */
        vlogmsg("cdj", "[NFS-SNIFF] Passive OneLibrary capture from %s (%u bytes) — ignored (disabled)",
                   ip_to_str(r->server_ip), r->received);
    } else {
        vlogmsg("cdj", "[NFS-SNIFF] Passive PDB capture complete from %s (%u bytes)",
                   ip_to_str(r->server_ip), r->received);
        parse_pdb_buffer(r->buffer, r->received, r->server_ip);
    }

    /* Cleanup */
    free(r->buffer);
    r->buffer = NULL;
}

/* Skip AUTH credentials in RPC packet, return position after credentials+verifier */
static size_t skip_rpc_auth(const uint8_t *data, size_t len, size_t pos) {
    if (pos + 8 > len) return len;
    
    /* Credentials: flavor (4) + length (4) + data */
    uint32_t cred_len = RPC_GET_U32(data + pos + 4);
    pos += 8 + cred_len;
    
    if (pos + 8 > len) return len;
    
    /* Verifier: flavor (4) + length (4) + data */
    uint32_t verf_len = RPC_GET_U32(data + pos + 4);
    pos += 8 + verf_len;
    
    return pos;
}

void parse_nfs_request(const uint8_t *data, size_t len,
                       uint32_t src_ip, uint32_t dst_ip) {
    /* Ignore our own NFS requests (we already know what we're doing) */
    if (src_ip == our_ip) return;
    
    /* Minimum size: RPC header (24) + some args */
    if (len < sizeof(rpc_call_header_t)) return;
    
    rpc_call_header_t *hdr = (rpc_call_header_t *)data;
    
    uint32_t xid = RPC_GET_U32((uint8_t *)&hdr->xid);
    uint32_t prog = RPC_GET_U32((uint8_t *)&hdr->prog);
    uint32_t proc = RPC_GET_U32((uint8_t *)&hdr->proc);
    
    /* Only NFS program */
    if (prog != NFS_PROGRAM) return;
    
    /* Skip credentials and verifier */
    size_t pos = skip_rpc_auth(data, len, sizeof(rpc_call_header_t));
    
    if (proc == NFS_PROC_LOOKUP) {
        /* LOOKUP: fhandle (32) + name_len (4) + name */
        if (pos + NFS_FHSIZE + 4 > len) return;
        
        const uint8_t *dir_fh = data + pos;
        pos += NFS_FHSIZE;
        
        uint32_t name_len = RPC_GET_U32(data + pos);
        pos += 4;
        
        if (pos + name_len > len || name_len > 256) return;
        
        /* Decode filename (CDJs use UTF-16LE) */
        char name[128];
        utf16le_to_utf8(data + pos, name_len, name, sizeof(name));
        
        /* Skip empty or dot names */
        if (name[0] == '\0' || (name[0] == '.' && name[1] == '\0')) return;
        
        if (verbose > 1) {
            vlogmsg("cdj", "[NFS-SNIFF] LOOKUP from %s -> %s: '%s'",
                       ip_to_str(src_ip), ip_to_str(dst_ip), name);
        }
        
        /* Record pending lookup to correlate with response */
        add_pending_lookup(xid, src_ip, dst_ip, dir_fh, name);
    }
    else if (proc == NFS_PROC_READ) {
        /* READ: fhandle (32) + offset (4) + count (4) + totalcount (4) */
        if (pos + sizeof(nfs_read_args_t) > len) return;
        
        nfs_read_args_t *args = (nfs_read_args_t *)(data + pos);
        uint32_t offset = RPC_GET_U32((uint8_t *)&args->offset);
        uint32_t count = RPC_GET_U32((uint8_t *)&args->count);
        
        /* Track this READ for passive PDB capture */
        add_pending_read(xid, src_ip, dst_ip, args->fh, offset, count);
        
        /* Look up what file this handle refers to */
        fh_cache_entry_t *fh_entry = find_fh_cache(args->fh, dst_ip);
        
        if (verbose > 1 && fh_entry) {
            vlogmsg("cdj", "[NFS-SNIFF] READ from %s: '%s' offset=%u count=%u",
                       ip_to_str(dst_ip), fh_entry->path, offset, count);
        }
    }
}

void parse_nfs_response(const uint8_t *data, size_t len,
                        uint32_t src_ip, uint32_t dst_ip) {
    /* Ignore responses to our own NFS requests */
    if (dst_ip == our_ip) return;
    
    /* Minimum size: RPC reply header (24) */
    if (len < sizeof(rpc_reply_header_t)) return;
    
    rpc_reply_header_t *hdr = (rpc_reply_header_t *)data;
    
    uint32_t xid = RPC_GET_U32((uint8_t *)&hdr->xid);
    uint32_t reply_stat = RPC_GET_U32((uint8_t *)&hdr->reply_stat);
    uint32_t accept_stat = RPC_GET_U32((uint8_t *)&hdr->accept_stat);
    
    if (reply_stat != RPC_MSG_ACCEPTED || accept_stat != RPC_SUCCESS) return;
    
    /* Find pending request by XID */
    pending_lookup_t *pending = find_pending_lookup(xid, src_ip);
    
    if (pending) {
        /* This is a LOOKUP response */
        size_t pos = sizeof(rpc_reply_header_t);
        
        if (pos + sizeof(nfs_lookup_reply_t) > len) return;
        
        nfs_lookup_reply_t *reply = (nfs_lookup_reply_t *)(data + pos);
        uint32_t status = RPC_GET_U32((uint8_t *)&reply->status);
        
        if (status == NFS_OK) {
            /* Build full path from directory + name */
            fh_cache_entry_t *dir_entry = find_fh_cache(pending->dir_fh, src_ip);
            char full_path[256];
            
            if (dir_entry && dir_entry->path[0] != '\0') {
                snprintf(full_path, sizeof(full_path), "%s/%s", 
                        dir_entry->path, pending->name);
            } else {
                snprintf(full_path, sizeof(full_path), "/%s", pending->name);
            }
            
            /* Cache the file handle -> path mapping */
            add_fh_cache(reply->fh, src_ip, full_path);
            
            if (verbose) {
                vlogmsg("cdj", "[NFS-SNIFF] LOOKUP OK: %s -> '%s'",
                           ip_to_str(src_ip), full_path);
            }
            
            /* Detect database files and start passive capture */
            int is_pdb = (strstr(pending->name, "export.pdb") ||
                         strstr(pending->name, "EXPORT.PDB"));
            int is_olib = (strstr(pending->name, "exportLibrary.db") ||
                          strstr(pending->name, "EXPORTLIBRARY.DB"));

            if (is_pdb || is_olib) {
                vlogmsg("cdj", "[NFS-SNIFF] Detected %s access: %s requesting '%s' from %s",
                           is_olib ? "OneLibrary" : "PDB",
                           ip_to_str(pending->client_ip), full_path, ip_to_str(src_ip));

                /* Get file size from fattr (follows file handle in response) */
                pos += sizeof(uint32_t) + NFS_FHSIZE;  /* status + fh */
                if (pos + sizeof(nfs_fattr_t) <= len) {
                    nfs_fattr_t *fattr = (nfs_fattr_t *)(data + pos);
                    uint32_t file_size = RPC_GET_U32((uint8_t *)&fattr->size);
                    if (file_size > 0 && file_size < 50 * 1024 * 1024) {
                        start_pdb_reassembly(src_ip, pending->client_ip, reply->fh, file_size);
                        /* Mark the reassembly slot as OneLibrary if applicable */
                        if (is_olib) {
                            pdb_reassembly_t *r = find_pdb_reassembly(src_ip, reply->fh);
                            if (r) r->is_onelibrary = 1;
                        }
                    }
                }
            }
        }
        
        remove_pending_lookup(xid, src_ip);
    }
    else {
        /* Check if this is a READ response we're tracking */
        pending_read_t *pread = find_pending_read(xid, src_ip);
        
        size_t pos = sizeof(rpc_reply_header_t);
        
        if (pos + sizeof(nfs_read_reply_t) > len) return;
        
        nfs_read_reply_t *reply = (nfs_read_reply_t *)(data + pos);
        uint32_t status = RPC_GET_U32((uint8_t *)&reply->status);
        
        if (status == NFS_OK) {
            /* Skip status + fattr to get to data */
            pos += sizeof(uint32_t) + sizeof(nfs_fattr_t);
            
            if (pos + 4 > len) return;
            
            uint32_t data_len = RPC_GET_U32(data + pos);
            pos += 4;
            
            if (data_len > 0 && pos + data_len <= len) {
                const uint8_t *read_data = data + pos;
                
                /* Check if this is for a PDB we're reassembling */
                if (pread) {
                    pdb_reassembly_t *r = find_pdb_reassembly(src_ip, pread->fh);
                    if (r) {
                        add_pdb_data(r, pread->offset, read_data, data_len);
                        
                        /* Check if complete */
                        if (r->received >= r->file_size) {
                            complete_pdb_reassembly(r);
                        }
                    }
                    remove_pending_read(xid, src_ip);
                }
                
                /* Legacy: scan for embedded metadata */
                scan_nfs_data_for_metadata(read_data, data_len, src_ip, dst_ip);
            }
        } else if (pread) {
            remove_pending_read(xid, src_ip);
        }
    }
}

void scan_nfs_data_for_metadata(const uint8_t *data, size_t len,
                                uint32_t server_ip, uint32_t player_ip) {
    (void)player_ip;
    
    /* Look for PDB file signatures or track metadata patterns */
    
    /* PDB header magic at byte 0 */
    if (len >= 4 && data[0] == 0x00 && data[1] == 0x00 && 
        data[2] == 0x00 && data[3] == 0x00) {
        /* Might be start of PDB - would need full reassembly */
        if (verbose) {
            vlogmsg("cdj", "[NFS-SNIFF] Possible PDB data from %s (%zu bytes)",
                       ip_to_str(server_ip), len);
        }
    }
    
    /* 
     * Look for UTF-16 string patterns that might be track titles.
     * Track titles in PDB are preceded by recognizable byte patterns.
     * This is a heuristic - full PDB parsing requires reassembling the file.
     */
    for (size_t i = 0; i + 10 < len; i++) {
        /* Look for string marker followed by printable UTF-16LE */
        if (data[i] >= 0x20 && data[i] < 0x7F && data[i + 1] == 0x00 &&
            data[i + 2] >= 0x20 && data[i + 2] < 0x7F && data[i + 3] == 0x00 &&
            data[i + 4] >= 0x20 && data[i + 4] < 0x7F && data[i + 5] == 0x00) {
            
            /* Found what looks like UTF-16LE string - extract it */
            char text[128];
            size_t j = 0;
            for (size_t k = i; k + 1 < len && j < sizeof(text) - 1; k += 2) {
                uint16_t cp = data[k] | (data[k + 1] << 8);
                if (cp == 0 || cp < 0x20 || cp > 0x7F) break;
                text[j++] = (char)cp;
            }
            text[j] = '\0';
            
            /* Only log if substantial (likely a title/artist) */
            if (j >= 4 && verbose > 1) {
                vlogmsg("cdj", "[NFS-SNIFF] Possible metadata string: '%s'", text);
            }
            
            /* Skip past this string */
            i += j * 2;
        }
    }
}
