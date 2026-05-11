/*
 * waveform_thread.h - Background ANLZ waveform fetcher
 *
 * Single worker thread serving all decks. Waveforms are per-track and
 * demand-driven (one .2EX/.EXT/.DAT per rekordbox_id), so a per-(media)
 * worker like PDB/OneLibrary doesn't fit — instead, one global queue with
 * a per-deck pending slot (latest enqueue wins per deck).
 *
 * Producer (prolink event loop) snapshots the source device's NFS/MOUNT
 * ports and ANLZ path from the registry winner, and enqueues a request.
 * The worker fetches with the 3-extension fallback (.2EX → .EXT → .DAT)
 * under nfs_fetch_mu, installs the result on dev->waveform_data /
 * waveform_len under waveform_mu (gated on rekordbox_id still matching),
 * and broadcasts to UI.
 */

#ifndef CLUBTAGGER_WAVEFORM_THREAD_H
#define CLUBTAGGER_WAVEFORM_THREAD_H

#include <pthread.h>
#include <stdint.h>

/* Protects dev->waveform_data and dev->waveform_len on all CDJ devices.
 * Held briefly during install (worker thread) and during free / read
 * (prolink thread on track change; ws_server on client handshake). */
extern pthread_mutex_t waveform_mu;

/* Start the worker thread. Idempotent — second call is a no-op.
 * Returns 0 on success, -errno on pthread_create failure. */
int waveform_thread_start(void);

/* Signal stop and join the worker. Safe before start. */
void waveform_thread_stop(void);

/* Enqueue a fetch for (deck_num, rekordbox_id). Single-pending-slot per
 * deck: if a request is already queued for this deck, it is replaced
 * (latest wins). source_ip / nfs_port / mount_port / source_slot describe
 * the CDJ holding the media; anlz_path is the path returned by the
 * registry winner (any of the three extensions — the worker substitutes).
 *
 * Returns 0 if accepted, -EINVAL on bad params (e.g., deck_num out of
 * range or empty anlz_path), -ENOENT if the worker hasn't been started. */
int waveform_thread_enqueue(uint8_t deck_num,
                            uint32_t rekordbox_id,
                            uint32_t source_ip,
                            uint16_t nfs_port,
                            uint16_t mount_port,
                            uint8_t  source_slot,
                            const char *anlz_path);

/* Drop cached waveform for a deck (called on track change). Frees
 * dev->waveform_data under waveform_mu, cancels any pending enqueue
 * for the deck, and broadcasts an empty frame to clear the UI. */
void waveform_thread_clear(uint8_t deck_num);

#endif /* CLUBTAGGER_WAVEFORM_THREAD_H */
