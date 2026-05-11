/*
 * waveform_thread.c - Background ANLZ waveform fetcher (single worker, per-deck mailbox)
 *
 * One worker thread. Per-deck "pending request" mailbox — producer drops
 * the latest request into the mailbox for a deck; worker drains in
 * round-robin order. NFS fetches are serialized through nfs_fetch_mu
 * (shared with PDB/OneLibrary workers).
 *
 * Producer-side backoff (dev->waveform_backoff, waveform_last_attempt)
 * remains on the prolink thread. The worker does no retries: on failure,
 * the next status tick will see dev->waveform_data still empty and
 * re-enqueue once the backoff elapses.
 */

#include "waveform_thread.h"
#include "nfs_client.h"
#include "cdj_types.h"
#include "../common.h"
#include "../server/ws_server.h"

#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

pthread_mutex_t waveform_mu = PTHREAD_MUTEX_INITIALIZER;

typedef struct {
    int      filled;
    uint32_t rekordbox_id;
    uint32_t source_ip;
    uint16_t nfs_port;
    uint16_t mount_port;
    uint8_t  source_slot;
    char     anlz_path[256];
} wf_pending_t;

static wf_pending_t     g_pending[MAX_DEVICES];
static pthread_mutex_t  g_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t   g_cv = PTHREAD_COND_INITIALIZER;
static pthread_t        g_thread;
static int              g_started;
static int              g_stop;
static uint8_t          g_rr_cursor;  /* round-robin deck cursor */

/*
 * ============================================================================
 * Worker
 * ============================================================================
 */

/* Pop the next pending request, or wait. Returns 1 with *out filled, or 0
 * if stop was requested. Caller does not hold g_mu on entry. */
static int worker_pop(wf_pending_t *out, uint8_t *out_deck) {
    pthread_mutex_lock(&g_mu);
    for (;;) {
        if (g_stop) {
            pthread_mutex_unlock(&g_mu);
            return 0;
        }
        /* Round-robin from cursor so no single noisy deck starves others. */
        for (int i = 0; i < MAX_DEVICES; i++) {
            uint8_t idx = (g_rr_cursor + i) % MAX_DEVICES;
            if (g_pending[idx].filled) {
                *out = g_pending[idx];
                g_pending[idx].filled = 0;
                g_rr_cursor = (idx + 1) % MAX_DEVICES;
                *out_deck = idx + 1;
                pthread_mutex_unlock(&g_mu);
                return 1;
            }
        }
        pthread_cond_wait(&g_cv, &g_mu);
    }
}

/* Install fetched data on the deck, gated on rekordbox_id still matching.
 * On stale, frees `data`. */
static void worker_install(uint8_t deck_num, uint32_t rb_id,
                           uint8_t *data, size_t len) {
    cdj_device_t *dev = get_device(deck_num);
    if (!dev) { free(data); return; }

    pthread_mutex_lock(&waveform_mu);
    if (dev->rekordbox_id != rb_id) {
        pthread_mutex_unlock(&waveform_mu);
        logmsg("wf", "[%u@CDJ%u] 🌊 install skipped — deck moved on (now rb=%u)",
               rb_id, deck_num, dev->rekordbox_id);
        free(data);
        return;
    }
    free(dev->waveform_data);
    dev->waveform_data = data;
    dev->waveform_len  = len;
    pthread_mutex_unlock(&waveform_mu);

    ws_broadcast_waveform(deck_num, data, len);
}

static void worker_fetch_one(uint8_t deck_num, const wf_pending_t *req) {
    uint8_t *buf = malloc(ANLZ_MAX_SIZE);
    if (!buf) {
        logmsg("wf", "[%u@CDJ%u] 🌊 malloc(%d) failed",
               req->rekordbox_id, deck_num, ANLZ_MAX_SIZE);
        return;
    }

    const char *exts[] = { ".2EX", ".EXT", ".DAT", NULL };
    char ext_path[256];
    size_t got = 0;
    const char *winner_ext = NULL;

    pthread_mutex_lock(&nfs_fetch_mu);
    for (int i = 0; exts[i]; i++) {
        strncpy(ext_path, req->anlz_path, sizeof(ext_path) - 1);
        ext_path[sizeof(ext_path) - 1] = '\0';
        char *dot = strrchr(ext_path, '.');
        if (dot) strncpy(dot, exts[i], ext_path + sizeof(ext_path) - dot - 1);

        int rc = nfs_fetch_path(req->source_ip, req->nfs_port, req->mount_port,
                                req->source_slot, ext_path,
                                buf, ANLZ_MAX_SIZE, &got);
        if (rc == 0 && got > 0) {
            winner_ext = exts[i];
            break;
        }
        /* -ENOENT: this extension doesn't exist for the track — try next. */
    }
    pthread_mutex_unlock(&nfs_fetch_mu);

    if (!winner_ext) {
        free(buf);
        logmsg("wf", "[%u@CDJ%u] 🌊 no waveform (tried .2EX/.EXT/.DAT)",
               req->rekordbox_id, deck_num);
        return;
    }

    uint8_t *shrunk = realloc(buf, got);
    if (!shrunk) shrunk = buf;

    logmsg("wf", "[%u@CDJ%u] 🌊 fetched %s (%zu bytes)",
           req->rekordbox_id, deck_num, winner_ext + 1, got);
    worker_install(deck_num, req->rekordbox_id, shrunk, got);
}

static void *worker_main(void *arg) {
    (void)arg;
    logmsg("wf", "waveform worker started");

    for (;;) {
        wf_pending_t req;
        uint8_t deck_num;
        if (!worker_pop(&req, &deck_num)) break;
        worker_fetch_one(deck_num, &req);
    }

    logmsg("wf", "waveform worker stopped");
    return NULL;
}

/*
 * ============================================================================
 * Public API
 * ============================================================================
 */

int waveform_thread_start(void) {
    pthread_mutex_lock(&g_mu);
    if (g_started) {
        pthread_mutex_unlock(&g_mu);
        return 0;
    }
    g_stop = 0;
    int rc = pthread_create(&g_thread, NULL, worker_main, NULL);
    if (rc != 0) {
        pthread_mutex_unlock(&g_mu);
        logmsg("wf", "start: pthread_create failed rc=%d", rc);
        return -rc;
    }
    g_started = 1;
    pthread_mutex_unlock(&g_mu);
    return 0;
}

void waveform_thread_stop(void) {
    pthread_mutex_lock(&g_mu);
    if (!g_started) {
        pthread_mutex_unlock(&g_mu);
        return;
    }
    g_stop = 1;
    pthread_cond_signal(&g_cv);
    pthread_mutex_unlock(&g_mu);

    pthread_join(g_thread, NULL);

    pthread_mutex_lock(&g_mu);
    for (int i = 0; i < MAX_DEVICES; i++) g_pending[i].filled = 0;
    g_started = 0;
    pthread_mutex_unlock(&g_mu);
}

int waveform_thread_enqueue(uint8_t deck_num,
                            uint32_t rekordbox_id,
                            uint32_t source_ip,
                            uint16_t nfs_port,
                            uint16_t mount_port,
                            uint8_t  source_slot,
                            const char *anlz_path) {
    if (deck_num == 0 || deck_num > MAX_DEVICES) {
        logmsg("wf", "enqueue: invalid deck_num=%u", deck_num);
        return -EINVAL;
    }
    if (!anlz_path || !anlz_path[0]) {
        logmsg("wf", "enqueue: empty anlz_path for CDJ%u rb=%u",
               deck_num, rekordbox_id);
        return -EINVAL;
    }
    if (nfs_port == 0 || mount_port == 0) {
        logmsg("wf", "enqueue: missing ports for CDJ%u rb=%u (nfs=%u mount=%u)",
               deck_num, rekordbox_id, nfs_port, mount_port);
        return -EINVAL;
    }

    pthread_mutex_lock(&g_mu);
    if (!g_started) {
        pthread_mutex_unlock(&g_mu);
        return -ENOENT;
    }
    wf_pending_t *p = &g_pending[deck_num - 1];
    p->filled       = 1;
    p->rekordbox_id = rekordbox_id;
    p->source_ip    = source_ip;
    p->nfs_port     = nfs_port;
    p->mount_port   = mount_port;
    p->source_slot  = source_slot;
    strncpy(p->anlz_path, anlz_path, sizeof(p->anlz_path) - 1);
    p->anlz_path[sizeof(p->anlz_path) - 1] = '\0';
    pthread_cond_signal(&g_cv);
    pthread_mutex_unlock(&g_mu);
    return 0;
}

void waveform_thread_clear(uint8_t deck_num) {
    if (deck_num == 0 || deck_num > MAX_DEVICES) return;

    /* Cancel any pending enqueue for this deck — a fetch in flight for the
     * old track would still install (it's gated on rekordbox_id), but
     * dropping the mailbox slot is cheap and avoids the worker doing
     * wasted NFS work for a track we no longer care about. */
    pthread_mutex_lock(&g_mu);
    g_pending[deck_num - 1].filled = 0;
    pthread_mutex_unlock(&g_mu);

    cdj_device_t *dev = get_device(deck_num);
    if (dev) {
        pthread_mutex_lock(&waveform_mu);
        free(dev->waveform_data);
        dev->waveform_data = NULL;
        dev->waveform_len  = 0;
        pthread_mutex_unlock(&waveform_mu);
    }

    ws_broadcast_waveform(deck_num, NULL, 0);
}
