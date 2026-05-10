/*
 * track_registry.h - Per-key candidate registry for CDJ track resolution
 *
 * Replaces the resolver cascade in prolink.c. Each (rekordbox_id, source_player)
 * key has a slot per resolver (OneLibrary, PDB, DBServer). Resolvers emit into
 * their own slot; readers compose a winner.
 *
 * Composition policy:
 *   - title/artist: DBServer wins (CDJ-live, no parsing); OneLibrary/PDB
 *     fall back when DBServer hasn't answered.
 *   - isrc, anlz_path: OneLibrary or PDB. Adopted only if title/artist
 *     agrees with DBServer (or DBServer hasn't answered). Dropped on
 *     disagreement; disputed=1 is set so callers can log a parser-bug warning.
 *
 * Step 1: passive data structure only. Resolvers don't yet emit; readers
 * don't yet consume. Hook-up happens in subsequent commits.
 */

#ifndef CLUBTAGGER_TRACK_REGISTRY_H
#define CLUBTAGGER_TRACK_REGISTRY_H

#include <pthread.h>
#include <stdint.h>
#include <time.h>

typedef enum {
    RES_ONELIBRARY = 0,
    RES_PDB        = 1,
    RES_DBSERVER   = 2,
    RES__COUNT     = 3
} resolver_id_t;

typedef struct {
    uint32_t rekordbox_id;
    uint8_t  source_player;     /* CDJ holding the media (1..6) */
} track_key_t;

typedef struct {
    uint8_t  filled;            /* 1 = this resolver has answered for this key */
    char     artist[128];
    char     title[128];
    char     isrc[64];
    char     anlz_path[256];    /* OneLibrary only; empty otherwise */
    time_t   resolved_at;
} candidate_t;

#define REG_MAX_KEYS 32

typedef struct {
    uint8_t     active;
    track_key_t key;
    candidate_t slots[RES__COUNT];
    time_t      first_seen;
} key_entry_t;

/* Composed result returned to consumers. */
typedef struct {
    char     artist[128];
    char     title[128];
    char     isrc[64];
    char     anlz_path[256];

    uint32_t resolved_by;       /* bitmask of (1u << resolver_id_t) */
    uint8_t  verified;          /* 2+ resolvers agree on title/artist */
    uint8_t  disputed;          /* DBServer disagrees with OneLibrary/PDB */
} track_identity_t;

typedef struct {
    pthread_mutex_t mu;
    key_entry_t     entries[REG_MAX_KEYS];
} track_registry_t;

extern track_registry_t g_track_registry;

/*
 * ============================================================================
 * Lifecycle
 * ============================================================================
 */

void track_registry_init(void);
void track_registry_destroy(void);

/*
 * ============================================================================
 * Producer (resolvers)
 * ============================================================================
 *
 * Emit a result into the per-(key, resolver) slot. Empty title means "I tried
 * and got nothing" — caller may still want to record a lookup attempt by
 * passing empty strings. A non-empty title is a successful resolution.
 *
 * Strings are copied; resolver may free its own buffers after return.
 *
 * Returns 0 on success, -ENOSPC if the registry is full (no free entry slot
 * for a new key and no existing entry to update).
 */
int track_registry_emit(track_key_t key, resolver_id_t resolver,
                        const char *artist, const char *title,
                        const char *isrc, const char *anlz_path);

/*
 * ============================================================================
 * Consumer (status loop, ws_server)
 * ============================================================================
 *
 * Compose the winning identity for a key from all filled slots.
 * Returns 1 if at least one resolver has answered (out is populated),
 * 0 otherwise (out is zeroed).
 */
int track_registry_winner(track_key_t key, track_identity_t *out);

/*
 * ============================================================================
 * Eviction
 * ============================================================================
 *
 * Drop all entries with the given source_player. Called on USB/SD/CD removal
 * or media swap — the rekordbox_id namespace is per-export, so the same
 * (rb_id, source_player) on a new mount may name a different track.
 *
 * Returns the number of entries evicted.
 */
int track_registry_evict_source(uint8_t source_player);

#endif /* CLUBTAGGER_TRACK_REGISTRY_H */
