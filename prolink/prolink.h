/*
 * prolink.h - Pro DJ Link Packet Parsing
 *
 * Parse keepalive, status, and beat packets from Pro DJ Link protocol.
 */

#ifndef PROLINK_H
#define PROLINK_H

#include <stdint.h>
#include <stddef.h>
#include "cdj_types.h"

/*
 * ============================================================================
 * Packet Parsing Functions
 * ============================================================================
 */

/* Parse keepalive packet (port 50000) - device announcements */
void parse_keepalive(const uint8_t *data, size_t len, uint32_t src_ip);

/* Parse CDJ status packet (port 50002) - track info, play state */
void parse_cdj_status(const uint8_t *data, size_t len, uint32_t src_ip);

/* Parse beat packet (port 50001) - beat sync */
void parse_beat(const uint8_t *data, size_t len, uint32_t src_ip);

/* Parse CDJ-3000 position packet (port 50001) - absolute position */
void parse_position(const uint8_t *data, size_t len, uint32_t src_ip);

/*
 * ============================================================================
 * Packet Validation
 * ============================================================================
 */

/* Check if packet has valid Pro DJ Link signature */
int is_prolink_packet(const uint8_t *data, size_t len);

/* Get packet type from Pro DJ Link packet */
uint8_t get_prolink_packet_type(const uint8_t *data);

/*
 * ============================================================================
 * Track Name Resolution
 * ============================================================================
 */

/* Try to resolve track title/artist for a device.
 * Returns: 0 = done (success or permanent failure), 1 = temporary skip (retry later) */
int try_resolve_track_name(cdj_device_t *dev);

/* Check if media slot changed and handle accordingly */
void check_media_change(cdj_device_t *dev);

#endif /* PROLINK_H */
