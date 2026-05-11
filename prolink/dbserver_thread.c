/*
 * dbserver_thread.c - Per-playing-deck DBServer worker
 *
 * One worker per CDJ. The prolink thread enqueues track-resolution
 * requests; the worker drains them, queries the playing deck's DBServer,
 * and emits results to the track registry.
 *
 * Pending work is a single-slot (latest-wins) buffer rather than a queue:
 * only the freshest track is worth resolving — older requests have been
 * superseded by newer track changes.
 */

#include "dbserver_thread.h"
#include "dbserver.h"
#include "track_registry.h"
#include "cdj_types.h"
#include "../common.h"

#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct {
    pthread_t       thread;
    pthread_mutex_t mu;
    pthread_cond_t  cv;
    int             stop;            /* set under mu */

    uint8_t  playing_device;

    int      have_pending;           /* under mu */
    uint32_t pending_rb_id;
    uint32_t pending_query_ip;
    uint8_t  pending_query_target;
    uint8_t  pending_source_slot;
    uint8_t  pending_track_type;

    /* Private retry state — replaces the globals at prolink.c:1016-1018. */
    int      query_fail_count;
    uint32_t last_emitted_rb_id;
    uint8_t  last_emitted_target;
} dbserver_worker_t;

static dbserver_worker_t *g_workers[MAX_DEVICES];
static pthread_mutex_t    g_workers_mu = PTHREAD_MUTEX_INITIALIZER;

static int worker_index(uint8_t playing_device) {
    if (playing_device == 0 || playing_device > MAX_DEVICES) return -1;
    return playing_device - 1;
}

/*
 * ============================================================================
 * Worker thread
 * ============================================================================
 */

static void run_query(dbserver_worker_t *w,
                      uint32_t rb_id,
                      uint32_t query_ip,
                      uint8_t  query_target,
                      uint8_t  source_slot,
                      uint8_t  track_type) {
    /* Dedup: skip if we already emitted for this (rb_id, source_player).
     * Track-source pair is the registry key, so different source players
     * are different tracks even with the same rb_id. */
    if (w->last_emitted_rb_id == rb_id &&
        w->last_emitted_target == query_target &&
        rb_id != 0) {
        return;
    }

    char title[128]  = {0};
    char artist[128] = {0};

    /* dbserver_query_metadata ignores our_device_param and uses
     * get_our_device_num() internally — pass 0. We trust the status
     * packet's track_type; no fallback to the other type. */
    int rc = dbserver_query_metadata(query_ip, 0, query_target,
                                     source_slot, track_type, rb_id,
                                     title, sizeof(title),
                                     artist, sizeof(artist));

    if (rc == 0 && title[0] == '\0') {
        logmsg("dbsrv", "[%u@CDJ%u] DBServer returned no rows (playing=CDJ%u slot=%s track_type=%u)",
               rb_id, query_target, w->playing_device,
               cdj_slot_name(source_slot), track_type);
    }

    if (rc == 0 && title[0] != '\0') {
        w->query_fail_count = 0;
        w->last_emitted_rb_id = rb_id;
        w->last_emitted_target = query_target;
        if (artist[0]) {
            logmsg("dbsrv", "[%u@CDJ%u] 🎵 %s - %s (via DBServer thread, playing=CDJ%u slot=%s)",
                   rb_id, query_target, artist, title,
                   w->playing_device, cdj_slot_name(source_slot));
        } else {
            logmsg("dbsrv", "[%u@CDJ%u] 🎵 %s (via DBServer thread, playing=CDJ%u slot=%s)",
                   rb_id, query_target, title,
                   w->playing_device, cdj_slot_name(source_slot));
        }
        track_key_t k = { .rekordbox_id = rb_id,
                          .source_player = query_target,
                          .slot          = source_slot };
        track_registry_emit(k, RES_DBSERVER, artist, title, "", "", 0, 0, 0, 0);
        return;
    }

    /* Failure — log lightly and grow private fail count. The next
     * track-change re-enqueue will retry; we don't loop here. */
    w->query_fail_count++;
    if (w->query_fail_count <= 3) {
        logmsg("dbsrv", "[%u@CDJ%u] DBServer query failed (playing=CDJ%u slot=%s rc=%d attempt=%d)",
               rb_id, query_target, w->playing_device,
               cdj_slot_name(source_slot), rc, w->query_fail_count);
    }
}

static void *worker_main(void *arg) {
    dbserver_worker_t *w = arg;

    logmsg("dbsrv", "DBServer worker started for CDJ%u", w->playing_device);

    for (;;) {
        pthread_mutex_lock(&w->mu);
        while (!w->stop && !w->have_pending) {
            pthread_cond_wait(&w->cv, &w->mu);
        }
        if (w->stop) {
            pthread_mutex_unlock(&w->mu);
            break;
        }

        uint32_t rb_id        = w->pending_rb_id;
        uint32_t query_ip     = w->pending_query_ip;
        uint8_t  query_target = w->pending_query_target;
        uint8_t  source_slot  = w->pending_source_slot;
        uint8_t  track_type   = w->pending_track_type;
        w->have_pending = 0;
        pthread_mutex_unlock(&w->mu);

        run_query(w, rb_id, query_ip, query_target, source_slot, track_type);
    }

    logmsg("dbsrv", "DBServer worker stopped for CDJ%u", w->playing_device);
    return NULL;
}

/*
 * ============================================================================
 * Public API
 * ============================================================================
 */

int dbserver_thread_spawn(uint8_t playing_device) {
    int idx = worker_index(playing_device);
    if (idx < 0) {
        logmsg("dbsrv", "spawn: invalid device_num=%u", playing_device);
        return -EINVAL;
    }

    pthread_mutex_lock(&g_workers_mu);
    if (g_workers[idx]) {
        pthread_mutex_unlock(&g_workers_mu);
        return 0;
    }

    dbserver_worker_t *w = calloc(1, sizeof(*w));
    if (!w) {
        pthread_mutex_unlock(&g_workers_mu);
        logmsg("dbsrv", "spawn: calloc failed for CDJ%u", playing_device);
        return -ENOMEM;
    }

    pthread_mutex_init(&w->mu, NULL);
    pthread_cond_init(&w->cv, NULL);
    w->playing_device = playing_device;

    int rc = pthread_create(&w->thread, NULL, worker_main, w);
    if (rc != 0) {
        pthread_cond_destroy(&w->cv);
        pthread_mutex_destroy(&w->mu);
        free(w);
        pthread_mutex_unlock(&g_workers_mu);
        logmsg("dbsrv", "spawn: pthread_create failed for CDJ%u rc=%d",
               playing_device, rc);
        return -rc;
    }

    g_workers[idx] = w;
    pthread_mutex_unlock(&g_workers_mu);
    return 0;
}

void dbserver_thread_stop(uint8_t playing_device) {
    int idx = worker_index(playing_device);
    if (idx < 0) return;

    pthread_mutex_lock(&g_workers_mu);
    dbserver_worker_t *w = g_workers[idx];
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

int dbserver_thread_enqueue(uint8_t playing_device,
                            uint32_t rekordbox_id,
                            uint32_t query_ip, uint8_t query_target,
                            uint8_t source_slot,
                            uint8_t track_type) {
    int idx = worker_index(playing_device);
    if (idx < 0) return -EINVAL;

    pthread_mutex_lock(&g_workers_mu);
    dbserver_worker_t *w = g_workers[idx];
    if (!w) {
        pthread_mutex_unlock(&g_workers_mu);
        return -ENOENT;
    }

    pthread_mutex_lock(&w->mu);
    w->have_pending          = 1;
    w->pending_rb_id         = rekordbox_id;
    w->pending_query_ip      = query_ip;
    w->pending_query_target  = query_target;
    w->pending_source_slot   = source_slot;
    w->pending_track_type    = track_type;
    pthread_cond_signal(&w->cv);
    pthread_mutex_unlock(&w->mu);

    pthread_mutex_unlock(&g_workers_mu);
    return 0;
}

void dbserver_thread_stop_all(void) {
    for (uint8_t p = 1; p <= MAX_DEVICES; p++) {
        dbserver_thread_stop(p);
    }
}
