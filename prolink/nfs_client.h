/*
 * nfs_client.h - NFS Client for CDJ Database Fetching
 *
 * Minimal NFS v2 client for fetching rekordbox export.pdb from CDJs.
 */

#ifndef NFS_CLIENT_H
#define NFS_CLIENT_H

#include <stdint.h>
#include <stddef.h>
#include <pthread.h>

/* Upper bound on a single NFS fetch (OneLibrary exportLibrary.db, PDB
 * export.pdb). Doubles as the OOM guard for the read buffer: the buffer is
 * sized to the file's real length when LOOKUP reports it, clamped to this. */
#define NFS_MAX_FETCH_SIZE (64u * 1024 * 1024)  /* 64 MB */

/*
 * Serializes all NFS fetch transactions across threads. The NFS client
 * holds a single shared UDP socket + xid counter; concurrent fetches
 * from multiple worker threads (OneLibrary per-(player,slot), PDB per-
 * (player,slot), waveform on-demand) would race for socket replies.
 * Hold this mutex for the full fetch (mount-portmap → mount → lookup →
 * read → close socket). The NFS port is no longer global — each device's
 * port is discovered once at announce and stored on cdj_device_t::nfs_port,
 * then passed to fetchers as an argument.
 *
 * Locking is at the call-site, not inside nfs_fetch_path / mount / lookup,
 * so a single fetch can complete its multi-RPC sequence atomically without
 * another thread reusing the socket mid-transaction. The announce-time
 * portmap query in prolink.c (parse_keepalive was_new) also holds this
 * mutex for the same reason. */
extern pthread_mutex_t nfs_fetch_mu;

/*
 * NFS client return codes — POSIX -errno convention:
 *   0        = success
 *  -ENOENT   = file/export not present (caller MUST NOT retry the same path)
 *  -1        = generic/transient error (caller may retry)
 */

/*
 * ============================================================================
 * Socket Management
 * ============================================================================
 */

/* Initialize NFS socket */
void nfs_init_socket(void);

/* Close NFS socket */
void nfs_close_socket(void);

/* Check if NFS socket is open */
int nfs_socket_ready(void);

/*
 * ============================================================================
 * Portmapper Operations
 * ============================================================================
 */

/* Query portmapper for a service port */
int rpc_portmap_getport(uint32_t server_ip, uint32_t program, uint32_t version);

/*
 * ============================================================================
 * Mount Operations
 * ============================================================================
 */

/* Mount export and get root file handle */
int nfs_mount_to_port(uint32_t server_ip, uint16_t mount_port, 
                      const char *export_path,
                      uint8_t *root_fh, size_t *fh_len);

/*
 * ============================================================================
 * NFS Operations
 * ============================================================================
 */

/* Lookup a file by name in directory. If out_size is non-NULL it receives the
 * file's size in bytes from the reply's fattr (0 if unavailable) — use it to
 * size the read buffer before fetching. */
int nfs_lookup(uint32_t server_ip, uint16_t nfs_port,
               const uint8_t *dir_fh, const char *name,
               uint8_t *file_fh, uint32_t *out_size);

/* Read file contents. `name` is a label (filename/path) used only in the
 * coverage log lines; may be NULL. */
int nfs_read_file(uint32_t server_ip, uint16_t nfs_port,
                  const uint8_t *file_fh, const char *name,
                  uint8_t *buf, size_t buf_len, size_t *bytes_read);

/* Fetch a file by path (e.g. "/PIONEER/USBANLZ/.../ANLZ0001.EXT").
 * slot: media slot (2=SD, 3=USB) — determines NFS export path.
 * nfs_port, mount_port: the device's ports (cdj_device_t::nfs_port,
 *           mount_port — discovered at announce time). This function does
 *           not touch portmap. Both must be non-zero.
 * Handles mount, path traversal, and read. Caller provides buffer.
 * Returns 0 on success, -1 on failure. */
int nfs_fetch_path(uint32_t server_ip, uint16_t nfs_port, uint16_t mount_port,
                   uint8_t slot, const char *path,
                   uint8_t *buf, size_t buf_len, size_t *bytes_read);

/* Send NFS unlock request (Pioneer-specific) */
int send_nfs_unlock(uint32_t target_ip);

/*
 * ============================================================================
 * NFS Traffic Parsing (Passive Eavesdropping)
 * ============================================================================
 */

/* Parse NFS request packets */
void parse_nfs_request(const uint8_t *data, size_t len,
                       uint32_t src_ip, uint32_t dst_ip);

/* Parse NFS response packets */
void parse_nfs_response(const uint8_t *data, size_t len,
                        uint32_t src_ip, uint32_t dst_ip);

/* Scan NFS data payloads for embedded metadata */
void scan_nfs_data_for_metadata(const uint8_t *data, size_t len,
                                uint32_t server_ip, uint32_t player_ip);

#endif /* NFS_CLIENT_H */
