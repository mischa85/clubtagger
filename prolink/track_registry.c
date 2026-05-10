/*
 * track_registry.c - Per-key candidate registry for CDJ track resolution
 *
 * Step 1: passive data structure. Resolvers don't yet emit; readers don't yet
 * consume. Lifecycle, emit, evict, and winner-composition logic live here so
 * subsequent commits can wire it in without touching this file.
 */

#include "track_registry.h"
#include "prolink_thread.h"
#include "../common.h"

#include <errno.h>
#include <stdint.h>
#include <string.h>

track_registry_t g_track_registry;

/*
 * ============================================================================
 * Lifecycle
 * ============================================================================
 */

void track_registry_init(void) {
    memset(&g_track_registry, 0, sizeof(g_track_registry));
    pthread_mutex_init(&g_track_registry.mu, NULL);
}

void track_registry_destroy(void) {
    pthread_mutex_destroy(&g_track_registry.mu);
    memset(&g_track_registry, 0, sizeof(g_track_registry));
}

/*
 * ============================================================================
 * Internal helpers — caller must hold g_track_registry.mu
 * ============================================================================
 */

static int key_eq(track_key_t a, track_key_t b) {
    return a.rekordbox_id == b.rekordbox_id
        && a.source_player == b.source_player
        && a.slot          == b.slot;
}

static key_entry_t *find_entry_locked(track_key_t key) {
    for (int i = 0; i < REG_MAX_KEYS; i++) {
        key_entry_t *e = &g_track_registry.entries[i];
        if (e->active && key_eq(e->key, key)) return e;
    }
    return NULL;
}

static key_entry_t *alloc_entry_locked(track_key_t key, time_t now) {
    for (int i = 0; i < REG_MAX_KEYS; i++) {
        key_entry_t *e = &g_track_registry.entries[i];
        if (!e->active) {
            memset(e, 0, sizeof(*e));
            e->active     = 1;
            e->key        = key;
            e->first_seen = now;
            return e;
        }
    }
    return NULL;
}

static void copy_field(char *dst, size_t dst_sz, const char *src) {
    if (!src) {
        dst[0] = '\0';
        return;
    }
    size_t n = strlen(src);
    if (n >= dst_sz) n = dst_sz - 1;
    memcpy(dst, src, n);
    dst[n] = '\0';
}

/* Two slots agree on title+artist using the existing fuzzy matcher. */
static int slots_agree(const candidate_t *a, const candidate_t *b) {
    if (!a->filled || !b->filled) return 0;
    if (a->title[0] == '\0' || b->title[0] == '\0') return 0;
    return prolink_matches_fingerprint(a->title, a->artist, b->title, b->artist);
}

/*
 * ============================================================================
 * Producer
 * ============================================================================
 */

int track_registry_emit(track_key_t key, resolver_id_t resolver,
                        const char *artist, const char *title,
                        const char *isrc, const char *anlz_path) {
    if ((unsigned)resolver >= RES__COUNT) {
        logmsg("registry", "emit: invalid resolver id %d", (int)resolver);
        return -EINVAL;
    }

    pthread_mutex_lock(&g_track_registry.mu);

    time_t now = time(NULL);
    key_entry_t *e = find_entry_locked(key);
    if (!e) {
        e = alloc_entry_locked(key, now);
        if (!e) {
            pthread_mutex_unlock(&g_track_registry.mu);
            logmsg("registry", "emit: full (REG_MAX_KEYS=%d), dropping rb_id=%u src=%u slot=%u",
                   REG_MAX_KEYS, key.rekordbox_id, key.source_player, key.slot);
            return -ENOSPC;
        }
    }

    candidate_t *slot = &e->slots[resolver];
    slot->filled = 1;
    copy_field(slot->artist,    sizeof(slot->artist),    artist);
    copy_field(slot->title,     sizeof(slot->title),     title);
    copy_field(slot->isrc,      sizeof(slot->isrc),      isrc);
    copy_field(slot->anlz_path, sizeof(slot->anlz_path), anlz_path);
    slot->resolved_at = now;

    pthread_mutex_unlock(&g_track_registry.mu);
    return 0;
}

/*
 * ============================================================================
 * Consumer
 * ============================================================================
 *
 * Composition policy:
 *   - Primary (title/artist): DBServer if filled with non-empty title,
 *     else OneLibrary, else PDB.
 *   - Enrichment (ISRC, anlz_path): OneLibrary, else PDB. Adopted only if
 *     it agrees with the primary (or DBServer hasn't answered).
 *   - verified=1 if 2+ slots agree on title+artist.
 *   - disputed=1 if any non-primary filled slot disagrees with the primary.
 */
int track_registry_winner(track_key_t key, track_identity_t *out) {
    if (!out) return 0;
    memset(out, 0, sizeof(*out));
    out->primary = RES__COUNT;

    pthread_mutex_lock(&g_track_registry.mu);

    key_entry_t *e = find_entry_locked(key);
    if (!e) {
        pthread_mutex_unlock(&g_track_registry.mu);
        return 0;
    }

    const candidate_t *db = &e->slots[RES_DBSERVER];
    const candidate_t *ol = &e->slots[RES_ONELIBRARY];
    const candidate_t *pd = &e->slots[RES_PDB];

    int any = db->filled || ol->filled || pd->filled;
    if (!any) {
        pthread_mutex_unlock(&g_track_registry.mu);
        return 0;
    }

    /* Pick primary for title/artist. */
    const candidate_t *primary = NULL;
    resolver_id_t primary_id = RES__COUNT;
    if (db->filled && db->title[0]) {
        primary = db;  primary_id = RES_DBSERVER;
    } else if (ol->filled && ol->title[0]) {
        primary = ol;  primary_id = RES_ONELIBRARY;
    } else if (pd->filled && pd->title[0]) {
        primary = pd;  primary_id = RES_PDB;
    }

    if (primary) {
        copy_field(out->artist, sizeof(out->artist), primary->artist);
        copy_field(out->title,  sizeof(out->title),  primary->title);
        out->primary = primary_id;
        out->resolved_by |= (1u << primary_id);
    }

    /* Enrichment: ISRC + anlz_path from OneLibrary or PDB. Adopted only if
     * primary either is one of them, or doesn't disagree. */
    const candidate_t *enrich = NULL;
    resolver_id_t enrich_id = RES__COUNT;
    if (ol->filled && ol->title[0]) {
        enrich = ol; enrich_id = RES_ONELIBRARY;
    } else if (pd->filled && pd->title[0]) {
        enrich = pd; enrich_id = RES_PDB;
    }

    if (enrich && primary) {
        int adopt = 1;
        if (primary != enrich) {
            adopt = slots_agree(primary, enrich);
        }
        if (adopt) {
            copy_field(out->isrc,      sizeof(out->isrc),      enrich->isrc);
            copy_field(out->anlz_path, sizeof(out->anlz_path), enrich->anlz_path);
            out->resolved_by |= (1u << enrich_id);
        }
    }

    /* Mark contributing slots in resolved_by even when not chosen as primary
     * or enrich (so callers can see who answered). */
    if (db->filled) out->resolved_by |= (1u << RES_DBSERVER);
    if (ol->filled) out->resolved_by |= (1u << RES_ONELIBRARY);
    if (pd->filled) out->resolved_by |= (1u << RES_PDB);

    /* verified: any two filled slots agree on title+artist. */
    int agree_pairs = 0;
    if (slots_agree(db, ol)) agree_pairs++;
    if (slots_agree(db, pd)) agree_pairs++;
    if (slots_agree(ol, pd)) agree_pairs++;
    out->verified = (agree_pairs > 0) ? 1 : 0;

    /* disputed: any non-primary filled slot with a non-empty title that
     * disagrees with the primary. */
    if (primary) {
        const candidate_t *others[3] = { db, ol, pd };
        for (int i = 0; i < 3; i++) {
            const candidate_t *o = others[i];
            if (o == primary) continue;
            if (!o->filled || o->title[0] == '\0') continue;
            if (!slots_agree(primary, o)) {
                out->disputed = 1;
                break;
            }
        }
    }

    pthread_mutex_unlock(&g_track_registry.mu);
    return 1;
}

/*
 * ============================================================================
 * Eviction
 * ============================================================================
 */

int track_registry_evict_source_slot(uint8_t source_player, uint8_t slot) {
    int evicted = 0;
    pthread_mutex_lock(&g_track_registry.mu);
    for (int i = 0; i < REG_MAX_KEYS; i++) {
        key_entry_t *e = &g_track_registry.entries[i];
        if (e->active
            && e->key.source_player == source_player
            && e->key.slot          == slot) {
            memset(e, 0, sizeof(*e));
            evicted++;
        }
    }
    pthread_mutex_unlock(&g_track_registry.mu);
    if (evicted > 0) {
        logmsg("registry", "evicted %d entries for source_player=%u slot=%u",
               evicted, source_player, slot);
    }
    return evicted;
}
