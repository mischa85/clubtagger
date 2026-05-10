/*
 * track_cache.h - Track Metadata Cache
 *
 * Cache for track titles/artists learned from NFS sniffing or DBServer queries.
 * Keyed by (rekordbox_id, source_player) — the same identity used in log tags.
 */

#ifndef TRACK_CACHE_H
#define TRACK_CACHE_H

#include <stdint.h>
#include <time.h>

#define MAX_TRACK_CACHE 4096

typedef struct {
    uint32_t rekordbox_id;
    uint32_t track_num;
    char     title[128];
    char     artist[128];
    char     isrc[64];
    char     filename[128];
    uint8_t  source_player;   /* CDJ device num (1-6) holding the media */
    time_t   last_seen;
} track_cache_entry_t;

extern track_cache_entry_t track_cache[MAX_TRACK_CACHE];
extern int track_cache_count;

/* Find track by (rekordbox_id, source_player) */
track_cache_entry_t *find_track_cache(uint32_t rekordbox_id, uint8_t source_player);

/* Add new entry to cache (returns existing if present) */
track_cache_entry_t *add_track_cache(uint32_t rekordbox_id, uint8_t source_player);

/* Clear all cache entries */
void clear_track_cache(void);

#endif /* TRACK_CACHE_H */
