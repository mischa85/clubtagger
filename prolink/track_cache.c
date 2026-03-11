/*
 * track_cache.c - Track Metadata Cache Implementation
 *
 * Cache for track titles/artists learned from NFS sniffing or DBServer queries.
 */

#include "track_cache.h"
#include <string.h>
#include <time.h>

/*
 * ============================================================================
 * Cache State
 * ============================================================================
 */

track_cache_entry_t track_cache[MAX_TRACK_CACHE];
int track_cache_count = 0;

/*
 * ============================================================================
 * Cache Functions
 * ============================================================================
 */

track_cache_entry_t *find_track_by_id(uint32_t rekordbox_id) {
    for (int i = 0; i < track_cache_count; i++) {
        if (track_cache[i].rekordbox_id == rekordbox_id && 
            track_cache[i].title[0] != '\0') {
            return &track_cache[i];
        }
    }
    return NULL;
}

track_cache_entry_t *find_track_by_num(uint32_t track_num, uint32_t src_ip) {
    for (int i = 0; i < track_cache_count; i++) {
        if (track_cache[i].track_num == track_num &&
            track_cache[i].src_ip == src_ip) {
            return &track_cache[i];
        }
    }
    return NULL;
}

track_cache_entry_t *find_track_cache(uint32_t rekordbox_id, uint32_t src_ip) {
    for (int i = 0; i < track_cache_count; i++) {
        if (track_cache[i].rekordbox_id == rekordbox_id &&
            track_cache[i].src_ip == src_ip) {
            return &track_cache[i];
        }
    }
    return NULL;
}

track_cache_entry_t *add_track_cache(uint32_t rekordbox_id, uint32_t src_ip) {
    /* Check if exists */
    track_cache_entry_t *entry = find_track_cache(rekordbox_id, src_ip);
    if (entry) return entry;
    
    /* Add new */
    if (track_cache_count < MAX_TRACK_CACHE) {
        entry = &track_cache[track_cache_count++];
        memset(entry, 0, sizeof(*entry));
        entry->rekordbox_id = rekordbox_id;
        entry->src_ip = src_ip;
        entry->last_seen = time(NULL);
        return entry;
    }
    return NULL;
}

void clear_track_cache(void) {
    memset(track_cache, 0, sizeof(track_cache));
    track_cache_count = 0;
}
