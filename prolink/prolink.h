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
#include "track_registry.h"

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
 * Track registry key
 * ============================================================================
 */

/* Build the track-registry key for a device's currently-loaded track.
 *
 * SLOT_CD lives in a separate id namespace (CD track number) and the source
 * is always the playing deck itself; everything else is keyed by
 * rekordbox_id at the source player. */
static inline track_key_t dev_track_key(const cdj_device_t *dev) {
    if (dev->track_slot == SLOT_CD) {
        return (track_key_t){
            .rekordbox_id  = dev->track_id,
            .source_player = dev->device_num,
            .slot          = SLOT_CD,
        };
    }
    return (track_key_t){
        .rekordbox_id  = dev->rekordbox_id,
        .source_player = dev->track_source_player,
        .slot          = dev->track_slot,
    };
}

/* OneLibrary SQLCipher passphrase, set by prolink_init from --olib-key.
 * Borrowed pointer (argv lifetime). NULL/empty → OneLibrary disabled.
 * Read by update_slot_media when spawning the per-slot worker. */
extern const char *prolink_olib_key;

/* Sweep for CDJs that have stopped sending keepalives. Stops their dbserver
 * worker and clears identity fields so the next announce re-fires the
 * was_new path with a fresh worker. Call once per second from the prolink
 * thread loop. */
void prolink_sweep_disappeared_cdjs(void);

#endif /* PROLINK_H */
