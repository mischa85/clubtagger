/*
 * nfs_client.c - NFS Client for CDJ Database Fetching
 *
 * NFSv2 client for fetching rekordbox export.pdb from CDJs.
 * Ported from working cdj-sniffer.c implementation.
 */

#include "nfs_client.h"
#include "nfs_protocol.h"
#include "pdb_parser.h"
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

/*
 * ============================================================================
 * Module State
 * ============================================================================
 */

static int nfs_sock = -1;
static uint32_t nfs_xid = 0x12345678;
extern uint32_t our_ip;  /* From registration module */
extern int verbose;      /* From main */

/*
 * ============================================================================
 * Socket Management
 * ============================================================================
 */

void nfs_init_socket(void) {
    if (nfs_sock >= 0) return;  /* Already initialized */
    
    nfs_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (nfs_sock < 0) {
        log_message("[NFS] Failed to create socket");
        return;
    }
    
    /* Bind to our Pro DJ Link IP with ephemeral port */
    struct sockaddr_in bind_addr;
    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = 0;  /* Let OS assign port */
    bind_addr.sin_addr.s_addr = our_ip;
    if (bind(nfs_sock, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0) {
        log_message("[NFS] Warning: Failed to bind to our IP");
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

/* Send RPC and receive reply using persistent socket */
static int nfs_rpc_call(uint32_t server_ip, uint16_t port, const uint8_t *request, 
                        size_t req_len, uint8_t *response, size_t max_resp) {
    /* Ensure socket is initialized */
    nfs_init_socket();
    if (nfs_sock < 0) return -1;
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = server_ip;
    
    /* Retry loop for UDP reliability */
    ssize_t received = -1;
    for (int retry = 0; retry < 3; retry++) {
        /* Send request */
        if (sendto(nfs_sock, request, req_len, 0, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            continue;
        }
        
        /* Receive response */
        socklen_t addr_len = sizeof(addr);
        received = recvfrom(nfs_sock, response, max_resp, 0, 
                            (struct sockaddr *)&addr, &addr_len);
        if (received > 0) break;  /* Success */
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
    int received = nfs_rpc_call(server_ip, PORTMAPPER_PORT, request, pos, response, sizeof(response));
    
    if (received < (int)(sizeof(rpc_reply_header_t) + sizeof(portmap_getport_reply_t))) {
        if (verbose) {
            log_message("[PORTMAP] No response from %s:111", ip_to_str(server_ip));
        }
        return -1;
    }
    
    /* Parse response */
    rpc_reply_header_t *reply = (rpc_reply_header_t *)response;
    if (RPC_GET_U32((uint8_t *)&reply->accept_stat) != RPC_SUCCESS) {
        return -1;
    }
    
    portmap_getport_reply_t *result = (portmap_getport_reply_t *)(response + sizeof(rpc_reply_header_t));
    int port = (int)RPC_GET_U32((uint8_t *)&result->port);
    
    if (verbose) {
        log_message("[PORTMAP] Program %u @ %s -> port %d", program, ip_to_str(server_ip), port);
    }
    
    return port;
}

int query_pioneer_portmapper(uint32_t server_ip) {
    return rpc_portmap_getport(server_ip, MOUNT_PROGRAM, MOUNT_VERSION);
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
        log_message("[NFS] Mount %s:%d export=%s", ip_to_str(server_ip), mount_port, export_path);
    }
    
    int received = nfs_rpc_call(server_ip, mount_port, request, pos, response, sizeof(response));
    
    if (received < (int)(sizeof(rpc_reply_header_t) + sizeof(mount_mnt_reply_t))) {
        if (verbose) {
            log_message("[NFS] Mount failed - no response");
        }
        return -1;
    }
    
    /* Parse reply using struct */
    mount_mnt_reply_t *reply = (mount_mnt_reply_t *)(response + sizeof(rpc_reply_header_t));
    uint32_t mount_stat = RPC_GET_U32((uint8_t *)&reply->status);
    
    if (verbose) {
        log_message("[NFS] Mount status: %u", mount_stat);
    }
    
    if (mount_stat != 0) return -1;
    
    /* File handle - MNT v1 returns fixed 32-byte handle */
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
               const char *name, uint8_t *file_fh) {
    uint8_t request[512];
    uint8_t response[1024];
    
    if (verbose) {
        log_message("[NFS] LOOKUP '%s' in dir fh[0..3]=%02x%02x%02x%02x (port %u)", 
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
    
    int received = nfs_rpc_call(server_ip, nfs_port, request, pos, response, sizeof(response));
    if (received < (int)(sizeof(rpc_reply_header_t) + sizeof(nfs_lookup_reply_t))) {
        if (verbose) log_message("[NFS] LOOKUP '%s' failed: short response (%d bytes)", name, received);
        return -1;
    }
    
    /* Check RPC reply status */
    rpc_reply_header_t *rpc = (rpc_reply_header_t *)response;
    if (RPC_GET_U32((uint8_t *)&rpc->reply_stat) != RPC_MSG_ACCEPTED) {
        if (verbose) log_message("[NFS] LOOKUP '%s' failed: RPC rejected", name);
        return -1;
    }
    
    /* Parse NFS reply using struct */
    nfs_lookup_reply_t *reply = (nfs_lookup_reply_t *)(response + sizeof(rpc_reply_header_t));
    uint32_t lookup_stat = RPC_GET_U32((uint8_t *)&reply->status);
    if (lookup_stat != NFS_OK) {
        if (verbose) log_message("[NFS] LOOKUP '%s' failed: nfs_stat=%u", name, lookup_stat);
        return -1;
    }
    
    /* File handle - NFSv2 is fixed 32 bytes */
    memcpy(file_fh, reply->fh, NFS_FHSIZE);
    
    if (verbose) {
        log_message("[NFS] LOOKUP '%s' OK -> fh[0..3]=%02x%02x%02x%02x", 
                    name, file_fh[0], file_fh[1], file_fh[2], file_fh[3]);
    }
    
    return 0;
}

/* NFS READ - read file data */
int nfs_read_file(uint32_t server_ip, uint16_t nfs_port, const uint8_t *file_fh,
                  uint8_t *buf, size_t buf_len, size_t *bytes_read) {
    if (verbose) {
        log_message("[NFS] READ file fh[0..3]=%02x%02x%02x%02x (port %u)", 
                    file_fh[0], file_fh[1], file_fh[2], file_fh[3], nfs_port);
    }
    
    size_t total_read = 0;
    int eof = 0;
    
    while (!eof && total_read < buf_len) {
        uint8_t request[256];
        uint8_t *response = malloc(1536);
        if (!response) return -1;
        
        /* Use NFS version 2 */
        int pos = build_rpc_call(request, ++nfs_xid, NFS_PROGRAM, NFS_VERSION, NFS_PROC_READ, NULL, 0);
        
        /* NFS READ arguments using struct */
        nfs_read_args_t *args = (nfs_read_args_t *)(request + pos);
        memcpy(args->fh, file_fh, NFS_FHSIZE);
        RPC_PUT_U32((uint8_t *)&args->offset, (uint32_t)total_read);
        RPC_PUT_U32((uint8_t *)&args->count, 1280);
        RPC_PUT_U32((uint8_t *)&args->totalcount, 0);  /* Unused in NFSv2 */
        pos += sizeof(nfs_read_args_t);
        
        int received = nfs_rpc_call(server_ip, nfs_port, request, pos, response, 1536);
        if (received < (int)sizeof(rpc_reply_header_t)) {
            if (verbose) log_message("[NFS] Read failed: only received %d bytes", received);
            free(response);
            return -1;
        }
        
        /* Check RPC reply status */
        rpc_reply_header_t *rpc = (rpc_reply_header_t *)response;
        if (RPC_GET_U32((uint8_t *)&rpc->reply_stat) != RPC_MSG_ACCEPTED) {
            if (verbose) log_message("[NFS] Read failed: RPC rejected");
            free(response);
            return -1;
        }
        
        /* NFS READ reply: status + fattr (68 bytes) + data */
        int rpos = sizeof(rpc_reply_header_t);
        nfs_read_reply_t *nfs_reply = (nfs_read_reply_t *)(response + rpos);
        uint32_t nfs_stat = RPC_GET_U32((uint8_t *)&nfs_reply->status);
        
        if (nfs_stat != NFS_OK) {
            if (verbose) log_message("[NFS] Read failed: nfs_stat=%u (NFSERR)", nfs_stat);
            free(response);
            return -1;
        }
        
        /* Skip status + fattr to get to data length */
        rpos += sizeof(uint32_t) + sizeof(nfs_fattr_t);
        
        /* Data length */
        uint32_t data_size = RPC_GET_U32(response + rpos);
        rpos += 4;
        
        if (data_size > 1280 || rpos + (int)data_size > received) {
            if (verbose) log_message("[NFS] Read failed: data_size=%u rpos=%d received=%d", 
                                    data_size, rpos, received);
            free(response);
            return -1;
        }
        
        if (data_size == 0) {
            eof = 1;
        } else {
            if (total_read + data_size > buf_len) {
                data_size = buf_len - total_read;
            }
            memcpy(buf + total_read, response + rpos, data_size);
            total_read += data_size;
            
            if (data_size < 1280) {
                eof = 1;
            }
        }
        
        free(response);
    }
    
    *bytes_read = total_read;
    return 0;
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
    uint8_t  fh[NFS_FHSIZE];      /* File handle for export.pdb */
    uint32_t file_size;           /* Expected size from fattr */
    uint32_t received;            /* Bytes received so far */
    uint8_t *buffer;              /* Reassembly buffer */
    time_t   last_activity;       /* For timeout */
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
    
    log_message("[NFS-SNIFF] Started passive PDB capture from %s (%u bytes)",
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
    log_message("[NFS-SNIFF] Passive PDB capture complete from %s (%u bytes)",
               ip_to_str(r->server_ip), r->received);
    
    /* Parse the captured database */
    parse_pdb_buffer(r->buffer, r->received, r->server_ip);
    
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
            log_message("[NFS-SNIFF] LOOKUP from %s -> %s: '%s'",
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
            log_message("[NFS-SNIFF] READ from %s: '%s' offset=%u count=%u",
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
                log_message("[NFS-SNIFF] LOOKUP OK: %s -> '%s'",
                           ip_to_str(src_ip), full_path);
            }
            
            /* If this is export.pdb, start passive capture */
            if (strstr(pending->name, "export.pdb") || 
                strstr(pending->name, "EXPORT.PDB")) {
                log_message("[NFS-SNIFF] Detected PDB access: %s requesting '%s' from %s",
                           ip_to_str(pending->client_ip), full_path, ip_to_str(src_ip));
                
                /* Get file size from fattr (follows file handle in response) */
                pos += sizeof(uint32_t) + NFS_FHSIZE;  /* status + fh */
                if (pos + sizeof(nfs_fattr_t) <= len) {
                    nfs_fattr_t *fattr = (nfs_fattr_t *)(data + pos);
                    uint32_t file_size = RPC_GET_U32((uint8_t *)&fattr->size);
                    if (file_size > 0 && file_size < 50 * 1024 * 1024) {  /* Sanity: <50MB */
                        start_pdb_reassembly(src_ip, pending->client_ip, reply->fh, file_size);
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
            log_message("[NFS-SNIFF] Possible PDB data from %s (%zu bytes)",
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
                log_message("[NFS-SNIFF] Possible metadata string: '%s'", text);
            }
            
            /* Skip past this string */
            i += j * 2;
        }
    }
}
