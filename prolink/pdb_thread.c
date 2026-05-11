/*
 * pdb_thread.c - Per-(source_player, slot) PDB worker
 *
 * Each worker owns one pdb_database_t. On spawn, it fetches export.pdb over
 * NFS in the background (with backoff on transient errors), parses it, and
 * serves enqueued lookup requests by emitting results into the track
 * registry under (rekordbox_id, source_player, slot).
 *
 * NFS fetches across all workers are serialized through nfs_fetch_mu —
 * the NFS client uses one shared UDP socket, so concurrent fetches would
 * race xids/replies. The NFS port is discovered once at announce time
 * (cdj_device_t::nfs_port) and passed in here, so the worker never queries
 * portmap on its own.
 */

#include "pdb_thread.h"
#include "pdb.h"
#include "nfs_client.h"
#include "track_registry.h"
#include "cdj_types.h"
#include "../common.h"

#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef enum {
    PDB_FETCH_PENDING = 0,  /* fetch hasn't succeeded yet */
    PDB_FETCH_LOADED,       /* db is parsed and queryable */
    PDB_FETCH_ABSENT,       /* media has no PDB (NOENT) — stop trying */
} pdb_fetch_state_t;

typedef struct {
    pthread_t       thread;
    pthread_mutex_t mu;
    pthread_cond_t  cv;
    int             stop;            /* set under mu */

    uint8_t  source_player;
    uint8_t  slot;
    uint32_t device_ip;              /* updated on respawn under mu */
    uint16_t nfs_port;               /* updated on respawn under mu */
    uint16_t mount_port;             /* updated on respawn under mu */

    pdb_fetch_state_t fetch_state;   /* under mu */
    pdb_database_t *db;              /* owned by worker — heap (~73MB), only touched on this thread */

    int      have_pending;           /* under mu */
    uint32_t pending_rb_id;          /* under mu */
} pdb_worker_t;

#define PDB_MAX_WORKERS (MAX_DEVICES * 2)

static pdb_worker_t    *g_workers[PDB_MAX_WORKERS];
static pthread_mutex_t  g_workers_mu = PTHREAD_MUTEX_INITIALIZER;

static int worker_index(uint8_t source_player, uint8_t slot) {
    if (source_player == 0 || source_player > MAX_DEVICES) return -1;
    if (slot != SLOT_USB && slot != SLOT_SD) return -1;
    int slot_idx = (slot == SLOT_USB) ? 0 : 1;
    return (source_player - 1) * 2 + slot_idx;
}

/*
 * ============================================================================
 * Fetch + lookup helpers (run on worker thread)
 * ============================================================================
 */

/* Attempt one fetch. Returns 0 on success, -ENOENT if media has no PDB
 * (caller should mark ABSENT), -1 on transient failure. */
static int try_fetch(pdb_worker_t *w) {
    pthread_mutex_lock(&w->mu);
    uint32_t ip    = w->device_ip;
    uint16_t nport = w->nfs_port;
    uint16_t mport = w->mount_port;
    pthread_mutex_unlock(&w->mu);

    pdb_database_t *fresh = calloc(1, sizeof(*fresh));
    if (!fresh) {
        logmsg("pdb", "CDJ%u/%s: calloc(%zu) failed for PDB buffer",
               w->source_player, cdj_slot_name(w->slot), sizeof(*fresh));
        return -1;
    }

    pthread_mutex_lock(&nfs_fetch_mu);
    int rc = fetch_rekordbox_database(ip, w->slot, nport, mport, fresh);
    pthread_mutex_unlock(&nfs_fetch_mu);

    if (rc == 0) {
        pthread_mutex_lock(&w->mu);
        pdb_database_t *old = w->db;
        w->db = fresh;
        w->fetch_state = PDB_FETCH_LOADED;
        pthread_mutex_unlock(&w->mu);
        free(old);
        return 0;
    }

    free(fresh);
    return rc;  /* -ENOENT or -1 */
}

/* Run one lookup against the loaded db and emit into the registry. */
static void run_lookup(pdb_worker_t *w, uint32_t rb_id) {
    if (rb_id == 0 || !w->db) return;

    pdb_database_t *db = w->db;
    TrackID *t = NULL;
    for (int i = 0; i < db->track_count; i++) {
        if (db->tracks[i].rekordbox_id == rb_id) {
            t = &db->tracks[i];
            break;
        }
    }

    if (!t) {
        logmsg("pdb", "[%u@CDJ%u/%s] PDB miss",
               rb_id, w->source_player, cdj_slot_name(w->slot));
        return;
    }

    if (t->title[0]) {
        if (t->artist[0]) {
            logmsg("pdb", "[%u@CDJ%u/%s] 🎵 %s - %s (via PDB)",
                   rb_id, w->source_player, cdj_slot_name(w->slot),
                   t->artist, t->title);
        } else {
            logmsg("pdb", "[%u@CDJ%u/%s] 🎵 %s (via PDB)",
                   rb_id, w->source_player, cdj_slot_name(w->slot), t->title);
        }
    }

    track_key_t k = { .rekordbox_id = rb_id,
                      .source_player = w->source_player,
                      .slot          = w->slot };
    track_registry_emit(k, RES_PDB,
                        t->artist, t->title,
                        (t->has_isrc ? t->isrc : ""),
                        t->anlz_path,
                        t->bitrate, t->sample_rate,
                        t->sample_depth, t->file_type);
}

/*
 * ============================================================================
 * Worker thread
 * ============================================================================
 */

static void *worker_main(void *arg) {
    pdb_worker_t *w = arg;

    logmsg("pdb", "PDB worker started for CDJ%u/%s",
           w->source_player, cdj_slot_name(w->slot));

    /* Backoff for fetch retries: 10s → 300s. */
    uint16_t fetch_backoff = 10;

    for (;;) {
        pthread_mutex_lock(&w->mu);
        if (w->stop) {
            pthread_mutex_unlock(&w->mu);
            break;
        }
        pdb_fetch_state_t fst = w->fetch_state;
        int have_pending = w->have_pending;
        uint32_t rb_id = w->pending_rb_id;
        pthread_mutex_unlock(&w->mu);

        if (fst == PDB_FETCH_PENDING) {
            int rc = try_fetch(w);
            if (rc == 0) {
                fetch_backoff = 10;
                continue;
            }
            if (rc == -ENOENT) {
                pthread_mutex_lock(&w->mu);
                w->fetch_state = PDB_FETCH_ABSENT;
                w->have_pending = 0;
                pthread_mutex_unlock(&w->mu);
                logmsg("pdb", "CDJ%u/%s: no PDB on this media — worker idle",
                       w->source_player, cdj_slot_name(w->slot));
                continue;
            }

            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            ts.tv_sec += fetch_backoff;

            pthread_mutex_lock(&w->mu);
            while (!w->stop) {
                int wrc = pthread_cond_timedwait(&w->cv, &w->mu, &ts);
                if (wrc == ETIMEDOUT) break;
            }
            pthread_mutex_unlock(&w->mu);

            if (fetch_backoff < 300) {
                fetch_backoff = (fetch_backoff * 2 > 300) ? 300 : fetch_backoff * 2;
            }
            continue;
        }

        if (have_pending) {
            pthread_mutex_lock(&w->mu);
            w->have_pending = 0;
            pthread_mutex_unlock(&w->mu);

            if (fst == PDB_FETCH_LOADED) {
                run_lookup(w, rb_id);
            }
            continue;
        }

        pthread_mutex_lock(&w->mu);
        while (!w->stop && !w->have_pending && w->fetch_state == fst) {
            pthread_cond_wait(&w->cv, &w->mu);
        }
        pthread_mutex_unlock(&w->mu);
    }

    free(w->db);
    w->db = NULL;
    logmsg("pdb", "PDB worker stopped for CDJ%u/%s",
           w->source_player, cdj_slot_name(w->slot));
    return NULL;
}

/*
 * ============================================================================
 * Public API
 * ============================================================================
 */

int pdb_thread_spawn(uint8_t source_player, uint8_t slot,
                     uint32_t device_ip,
                     uint16_t nfs_port, uint16_t mount_port) {
    int idx = worker_index(source_player, slot);
    if (idx < 0) {
        logmsg("pdb", "spawn: invalid (player=%u slot=%u)", source_player, slot);
        return -EINVAL;
    }

    pthread_mutex_lock(&g_workers_mu);
    pdb_worker_t *existing = g_workers[idx];
    if (existing) {
        pthread_mutex_lock(&existing->mu);
        existing->device_ip  = device_ip;
        existing->nfs_port   = nfs_port;
        existing->mount_port = mount_port;
        pthread_mutex_unlock(&existing->mu);
        pthread_mutex_unlock(&g_workers_mu);
        return 0;
    }

    pdb_worker_t *w = calloc(1, sizeof(*w));
    if (!w) {
        pthread_mutex_unlock(&g_workers_mu);
        logmsg("pdb", "spawn: calloc failed for CDJ%u/%s",
               source_player, cdj_slot_name(slot));
        return -ENOMEM;
    }

    pthread_mutex_init(&w->mu, NULL);
    pthread_cond_init(&w->cv, NULL);
    w->source_player = source_player;
    w->slot          = slot;
    w->device_ip     = device_ip;
    w->nfs_port      = nfs_port;
    w->mount_port    = mount_port;
    w->fetch_state   = PDB_FETCH_PENDING;

    int rc = pthread_create(&w->thread, NULL, worker_main, w);
    if (rc != 0) {
        pthread_cond_destroy(&w->cv);
        pthread_mutex_destroy(&w->mu);
        free(w);
        pthread_mutex_unlock(&g_workers_mu);
        logmsg("pdb", "spawn: pthread_create failed for CDJ%u/%s rc=%d",
               source_player, cdj_slot_name(slot), rc);
        return -rc;
    }

    g_workers[idx] = w;
    pthread_mutex_unlock(&g_workers_mu);
    return 0;
}

void pdb_thread_stop(uint8_t source_player, uint8_t slot) {
    int idx = worker_index(source_player, slot);
    if (idx < 0) return;

    pthread_mutex_lock(&g_workers_mu);
    pdb_worker_t *w = g_workers[idx];
    g_workers[idx] = NULL;
    pthread_mutex_unlock(&g_workers_mu);

    if (!w) return;

    pthread_mutex_lock(&w->mu);
    w->stop = 1;
    pthread_cond_signal(&w->cv);
    pthread_mutex_unlock(&w->mu);

    pthread_join(w->thread, NULL);
    pthread_cond_destroy(&w->cv);
    pthread_mutex_destroy(&w->mu);
    free(w);
}

int pdb_thread_enqueue(uint8_t source_player, uint8_t slot,
                       uint32_t rekordbox_id) {
    int idx = worker_index(source_player, slot);
    if (idx < 0) return -EINVAL;

    pthread_mutex_lock(&g_workers_mu);
    pdb_worker_t *w = g_workers[idx];
    if (!w) {
        pthread_mutex_unlock(&g_workers_mu);
        return -ENOENT;
    }

    pthread_mutex_lock(&w->mu);
    if (w->fetch_state == PDB_FETCH_ABSENT) {
        pthread_mutex_unlock(&w->mu);
        pthread_mutex_unlock(&g_workers_mu);
        return 0;
    }
    w->have_pending  = 1;
    w->pending_rb_id = rekordbox_id;
    pthread_cond_signal(&w->cv);
    pthread_mutex_unlock(&w->mu);

    pthread_mutex_unlock(&g_workers_mu);
    return 0;
}

void pdb_thread_stop_all(void) {
    for (uint8_t p = 1; p <= MAX_DEVICES; p++) {
        pdb_thread_stop(p, SLOT_USB);
        pdb_thread_stop(p, SLOT_SD);
    }
}
