/*
 * track_cache.h - Track Metadata Cache
 *
 * Cache for track titles/artists learned from NFS sniffing or DBServer queries.
 */

#ifndef TRACK_CACHE_H
#define TRACK_CACHE_H

#include <stdint.h>
#include <time.h>

/*
 * ============================================================================
 * Cache Limits
 * ============================================================================
 */

#define MAX_TRACK_CACHE 4096

/*
 * ============================================================================
 * Track Cache Entry
 * ============================================================================
 */

typedef struct {
    uint32_t rekordbox_id;
    uint32_t track_num;
    char     title[128];
    char     artist[128];
    char     isrc[64];
    char     filename[128];
    uint32_t src_ip;          /* IP that owns this track */
    time_t   last_seen;
} track_cache_entry_t;

/*
 * ============================================================================
 * Cache State (extern)
 * ============================================================================
 */

extern track_cache_entry_t track_cache[MAX_TRACK_CACHE];
extern int track_cache_count;

/*
 * ============================================================================
 * Cache Functions
 * ============================================================================
 */

/* Find track by rekordbox ID (any source IP) */
track_cache_entry_t *find_track_by_id(uint32_t rekordbox_id);

/* Find track by track number and source IP */
track_cache_entry_t *find_track_by_num(uint32_t track_num, uint32_t src_ip);

/* Find track by rekordbox ID and source IP (exact match) */
track_cache_entry_t *find_track_cache(uint32_t rekordbox_id, uint32_t src_ip);

/* Add new entry to cache (returns existing if present) */
track_cache_entry_t *add_track_cache(uint32_t rekordbox_id, uint32_t src_ip);

/* Clear all cache entries */
void clear_track_cache(void);

#endif /* TRACK_CACHE_H */
