/*
 * track_cache.c - Track Metadata Cache Implementation
 */

#include "track_cache.h"
#include <string.h>
#include <time.h>

track_cache_entry_t track_cache[MAX_TRACK_CACHE];
int track_cache_count = 0;

track_cache_entry_t *find_track_cache(uint32_t rekordbox_id, uint8_t source_player) {
    for (int i = 0; i < track_cache_count; i++) {
        if (track_cache[i].rekordbox_id == rekordbox_id &&
            track_cache[i].source_player == source_player) {
            return &track_cache[i];
        }
    }
    return NULL;
}

track_cache_entry_t *add_track_cache(uint32_t rekordbox_id, uint8_t source_player) {
    track_cache_entry_t *entry = find_track_cache(rekordbox_id, source_player);
    if (entry) return entry;

    if (track_cache_count < MAX_TRACK_CACHE) {
        entry = &track_cache[track_cache_count++];
        memset(entry, 0, sizeof(*entry));
        entry->rekordbox_id = rekordbox_id;
        entry->source_player = source_player;
        entry->last_seen = time(NULL);
        return entry;
    }
    return NULL;
}

void clear_track_cache(void) {
    memset(track_cache, 0, sizeof(track_cache));
    track_cache_count = 0;
}
