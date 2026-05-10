/*
 * onelibrary_thread.c - Per-(source_player, slot) OneLibrary worker
 *
 * Each worker owns one onelibrary_t. On spawn, it fetches exportLibrary.db
 * over NFS in the background (with backoff on transient errors) and opens
 * the decrypted database. Once loaded, it serves enqueued lookup requests
 * and emits results into the track registry under
 * (rekordbox_id, source_player, slot).
 *
 * NFS fetches across all workers are serialized through nfs_fetch_mu —
 * the NFS client uses one shared UDP socket, so concurrent fetches would
 * race xids/replies. The NFS port is discovered once at announce time
 * (cdj_device_t::nfs_port) and passed in here, so the worker never queries
 * portmap on its own.
 */

#include "onelibrary_thread.h"
#include "onelibrary.h"
#include "nfs_client.h"
#include "track_registry.h"
#include "cdj_types.h"
#include "../common.h"

#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Worker state. Two valid slots per device (USB, SD), so 2*MAX_DEVICES.
 * Indexed by worker_index() below. */
typedef enum {
    OLIB_FETCH_PENDING = 0,  /* fetch hasn't succeeded yet */
    OLIB_FETCH_LOADED,       /* olib is open and queryable */
    OLIB_FETCH_ABSENT,       /* media has no OneLibrary (NOENT) — stop trying */
} olib_fetch_state_t;

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
    const char *passphrase;          /* borrowed pointer; must outlive worker */

    olib_fetch_state_t fetch_state;  /* under mu */
    onelibrary_t       olib;         /* owned by worker — only touched on this thread */

    int      have_pending;           /* under mu */
    uint32_t pending_rb_id;          /* under mu */
} olib_worker_t;

#define OLIB_MAX_WORKERS (MAX_DEVICES * 2)

static olib_worker_t   *g_workers[OLIB_MAX_WORKERS];
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

/* Attempt one fetch. Returns 0 on success, -ENOENT if media has no
 * OneLibrary (caller should mark ABSENT), -1 on transient failure. */
static int try_fetch(olib_worker_t *w) {
    pthread_mutex_lock(&w->mu);
    uint32_t ip    = w->device_ip;
    uint16_t nport = w->nfs_port;
    uint16_t mport = w->mount_port;
    pthread_mutex_unlock(&w->mu);

    onelibrary_t fresh;
    pthread_mutex_lock(&nfs_fetch_mu);
    int rc = fetch_onelibrary_database(&fresh, ip, w->slot, nport, mport, w->passphrase);
    pthread_mutex_unlock(&nfs_fetch_mu);

    if (rc == 0) {
        /* Replace under mu so a concurrent enqueue/lookup observes consistent state. */
        pthread_mutex_lock(&w->mu);
        onelibrary_close(&w->olib);
        w->olib = fresh;
        w->fetch_state = OLIB_FETCH_LOADED;
        pthread_mutex_unlock(&w->mu);
        return 0;
    }
    return rc;  /* -ENOENT or -1 */
}

/* Run one lookup against the loaded olib and emit into the registry. */
static void run_lookup(olib_worker_t *w, uint32_t rb_id) {
    if (rb_id == 0) return;

    char title[128]   = {0};
    char artist[128]  = {0};
    char isrc[64]     = {0};
    char anlz[256]    = {0};
    uint32_t bitrate = 0, srate = 0;
    uint8_t  format = 0, depth = 0;

    int rc = onelibrary_lookup(&w->olib, rb_id,
                               title, sizeof(title),
                               artist, sizeof(artist),
                               isrc, sizeof(isrc),
                               &bitrate, &format,
                               &srate, &depth,
                               anlz, sizeof(anlz));
    if (rc != 0) {
        logmsg("olib", "[%u@CDJ%u/%s] OneLibrary miss",
               rb_id, w->source_player, cdj_slot_name(w->slot));
        return;
    }

    if (title[0]) {
        if (artist[0]) {
            logmsg("olib", "[%u@CDJ%u/%s] 🎵 %s - %s (via OneLibrary)",
                   rb_id, w->source_player, cdj_slot_name(w->slot),
                   artist, title);
        } else {
            logmsg("olib", "[%u@CDJ%u/%s] 🎵 %s (via OneLibrary)",
                   rb_id, w->source_player, cdj_slot_name(w->slot), title);
        }
    }

    track_key_t k = { .rekordbox_id = rb_id,
                      .source_player = w->source_player,
                      .slot          = w->slot };
    track_registry_emit(k, RES_ONELIBRARY, artist, title, isrc, anlz);
}

/*
 * ============================================================================
 * Worker thread
 * ============================================================================
 */

static void *worker_main(void *arg) {
    olib_worker_t *w = arg;

    logmsg("olib", "OneLibrary worker started for CDJ%u/%s",
           w->source_player, cdj_slot_name(w->slot));

    /* Backoff for fetch retries: 10s → 300s. */
    uint16_t fetch_backoff = 10;

    for (;;) {
        /* Snapshot state under mu. */
        pthread_mutex_lock(&w->mu);
        if (w->stop) {
            pthread_mutex_unlock(&w->mu);
            break;
        }
        olib_fetch_state_t fst = w->fetch_state;
        int have_pending = w->have_pending;
        uint32_t rb_id = w->pending_rb_id;
        pthread_mutex_unlock(&w->mu);

        /* PENDING: try a fetch, then either loop (success/queue) or wait
         * out the backoff window before retrying. */
        if (fst == OLIB_FETCH_PENDING) {
            int rc = try_fetch(w);
            if (rc == 0) {
                fetch_backoff = 10;
                continue;  /* re-snapshot — pending lookup may now run */
            }
            if (rc == -ENOENT) {
                pthread_mutex_lock(&w->mu);
                w->fetch_state = OLIB_FETCH_ABSENT;
                /* Drop any pending lookup — it will never resolve here. */
                w->have_pending = 0;
                pthread_mutex_unlock(&w->mu);
                logmsg("olib", "CDJ%u/%s: no OneLibrary on this media — worker idle",
                       w->source_player, cdj_slot_name(w->slot));
                continue;
            }

            /* Transient: wait `fetch_backoff` seconds, then retry.
             * Wake early on stop. */
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

        /* LOADED or ABSENT: drain a pending lookup if there is one. */
        if (have_pending) {
            pthread_mutex_lock(&w->mu);
            w->have_pending = 0;
            pthread_mutex_unlock(&w->mu);

            if (fst == OLIB_FETCH_LOADED) {
                run_lookup(w, rb_id);
            }
            /* ABSENT: silently drop — the worker is intentionally idle. */
            continue;
        }

        /* Idle wait. */
        pthread_mutex_lock(&w->mu);
        while (!w->stop && !w->have_pending && w->fetch_state == fst) {
            pthread_cond_wait(&w->cv, &w->mu);
        }
        pthread_mutex_unlock(&w->mu);
    }

    onelibrary_close(&w->olib);
    logmsg("olib", "OneLibrary worker stopped for CDJ%u/%s",
           w->source_player, cdj_slot_name(w->slot));
    return NULL;
}

/*
 * ============================================================================
 * Public API
 * ============================================================================
 */

int onelibrary_thread_spawn(uint8_t source_player, uint8_t slot,
                            uint32_t device_ip,
                            uint16_t nfs_port, uint16_t mount_port,
                            const char *passphrase) {
    if (!passphrase || !passphrase[0]) {
        logmsg("olib", "spawn: NULL/empty passphrase for CDJ%u/%u", source_player, slot);
        return -EINVAL;
    }

    int idx = worker_index(source_player, slot);
    if (idx < 0) {
        logmsg("olib", "spawn: invalid (player=%u slot=%u)", source_player, slot);
        return -EINVAL;
    }

    pthread_mutex_lock(&g_workers_mu);
    olib_worker_t *existing = g_workers[idx];
    if (existing) {
        /* Already running — refresh device_ip / nfs_port / mount_port in case
         * slot-conflict reassignment or a fresh announce changed them without
         * re-mounting media. */
        pthread_mutex_lock(&existing->mu);
        existing->device_ip  = device_ip;
        existing->nfs_port   = nfs_port;
        existing->mount_port = mount_port;
        pthread_mutex_unlock(&existing->mu);
        pthread_mutex_unlock(&g_workers_mu);
        return 0;
    }

    olib_worker_t *w = calloc(1, sizeof(*w));
    if (!w) {
        pthread_mutex_unlock(&g_workers_mu);
        logmsg("olib", "spawn: calloc failed for CDJ%u/%s",
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
    w->passphrase    = passphrase;
    w->fetch_state   = OLIB_FETCH_PENDING;

    int rc = pthread_create(&w->thread, NULL, worker_main, w);
    if (rc != 0) {
        pthread_cond_destroy(&w->cv);
        pthread_mutex_destroy(&w->mu);
        free(w);
        pthread_mutex_unlock(&g_workers_mu);
        logmsg("olib", "spawn: pthread_create failed for CDJ%u/%s rc=%d",
               source_player, cdj_slot_name(slot), rc);
        return -rc;
    }

    g_workers[idx] = w;
    pthread_mutex_unlock(&g_workers_mu);
    return 0;
}

void onelibrary_thread_stop(uint8_t source_player, uint8_t slot) {
    int idx = worker_index(source_player, slot);
    if (idx < 0) return;

    pthread_mutex_lock(&g_workers_mu);
    olib_worker_t *w = g_workers[idx];
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

int onelibrary_thread_enqueue(uint8_t source_player, uint8_t slot,
                              uint32_t rekordbox_id) {
    int idx = worker_index(source_player, slot);
    if (idx < 0) return -EINVAL;

    pthread_mutex_lock(&g_workers_mu);
    olib_worker_t *w = g_workers[idx];
    if (!w) {
        pthread_mutex_unlock(&g_workers_mu);
        return -ENOENT;
    }

    pthread_mutex_lock(&w->mu);
    if (w->fetch_state == OLIB_FETCH_ABSENT) {
        pthread_mutex_unlock(&w->mu);
        pthread_mutex_unlock(&g_workers_mu);
        return 0;  /* silently drop */
    }
    w->have_pending  = 1;
    w->pending_rb_id = rekordbox_id;
    pthread_cond_signal(&w->cv);
    pthread_mutex_unlock(&w->mu);

    pthread_mutex_unlock(&g_workers_mu);
    return 0;
}

void onelibrary_thread_stop_all(void) {
    for (uint8_t p = 1; p <= MAX_DEVICES; p++) {
        onelibrary_thread_stop(p, SLOT_USB);
        onelibrary_thread_stop(p, SLOT_SD);
    }
}
