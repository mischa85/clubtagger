/*
 * dbserver.h - CDJ DBServer Client
 *
 * Query track metadata from CDJ's built-in database server (port 1051).
 */

#ifndef DBSERVER_H
#define DBSERVER_H

#include <stdint.h>
#include <stddef.h>
#include "cdj_types.h"

/*
 * ============================================================================
 * Connection Management
 * ============================================================================
 */

/* Connect to DBServer on specified IP */
int dbserver_connect(uint32_t server_ip);

/* Query Pioneer's portmapper for DBServer port */
int dbserver_query_port(uint32_t server_ip);

/* Setup context after connection (required before queries) */
int dbserver_setup(int sock, uint8_t device_num);

/* Send disconnect message and close socket */
int dbserver_disconnect(int sock);

/*
 * ============================================================================
 * Metadata Queries
 * ============================================================================
 */

/* Query metadata for a rekordbox-analyzed track */
int dbserver_request_metadata_rekordbox(int sock, uint8_t device, uint8_t slot,
                                        uint32_t rekordbox_id,
                                        char *title, size_t title_len,
                                        char *artist, size_t artist_len);

/* Query metadata for unanalyzed/CD track */
int dbserver_request_metadata_unanalyzed(int sock, uint8_t device, uint8_t slot,
                                         uint32_t track_id,
                                         char *title, size_t title_len,
                                         char *artist, size_t artist_len);

/* Combined query function that handles connection and protocol */
int dbserver_query_metadata(uint32_t device_ip, uint8_t our_device, uint8_t target_device,
                            uint8_t slot, uint8_t track_type, uint32_t track_id,
                            char *title, size_t title_len,
                            char *artist, size_t artist_len);

/* Find filename for unanalyzed track */
int dbserver_find_unanalyzed_filename(uint32_t device_ip, uint8_t our_device, 
                                      uint8_t slot, uint32_t track_id,
                                      char *filename, size_t filename_len);

/*
 * ============================================================================
 * Track Count
 * ============================================================================
 */

/* Request total track count for a slot */
int dbserver_request_all_tracks_count(int sock, uint8_t device, uint8_t slot);

/*
 * ============================================================================
 * DBServer Traffic Parsing (Passive Eavesdropping)
 * ============================================================================
 */

/* Parse eavesdropped DBServer TCP traffic */
void parse_dbserver_traffic(const uint8_t *data, size_t len, 
                            uint32_t src_ip, uint32_t dst_ip);

/*
 * ============================================================================
 * Internal Protocol Helpers
 * ============================================================================
 */

/* Build message header into buffer, returns bytes written */
int build_message_header(uint8_t *buf, uint32_t txid, uint16_t msg_type,
                        uint8_t num_args, const uint8_t *arg_tags);

/* Send message and wait for response */
int dbserver_transact(int sock, const uint8_t *msg, size_t msg_len,
                      uint8_t *resp, size_t resp_max);

#endif /* DBSERVER_H */
