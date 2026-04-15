/*
 * nfs_client.h - NFS Client for CDJ Database Fetching
 *
 * Minimal NFS v2 client for fetching rekordbox export.pdb from CDJs.
 */

#ifndef NFS_CLIENT_H
#define NFS_CLIENT_H

#include <stdint.h>
#include <stddef.h>

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

/* Query Pioneer's non-standard portmapper */
int query_pioneer_portmapper(uint32_t server_ip);

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

/* Lookup a file by name in directory */
int nfs_lookup(uint32_t server_ip, uint16_t nfs_port,
               const uint8_t *dir_fh, const char *name,
               uint8_t *file_fh);

/* Read file contents */
int nfs_read_file(uint32_t server_ip, uint16_t nfs_port,
                  const uint8_t *file_fh,
                  uint8_t *buf, size_t buf_len, size_t *bytes_read);

/* Fetch a file by path (e.g. "/PIONEER/USBANLZ/.../ANLZ0001.EXT").
 * slot: media slot (2=SD, 3=USB) — determines NFS export path.
 * Handles mount, path traversal, and read. Caller provides buffer.
 * Returns 0 on success, -1 on failure. */
int nfs_fetch_path(uint32_t server_ip, uint8_t slot, const char *path,
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
