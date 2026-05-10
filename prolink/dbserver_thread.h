/*
 * dbserver_thread.h - Per-playing-deck DBServer worker thread
 *
 * One worker per CDJ on the network. DBServer is a service hosted by every
 * CDJ; queries always TCP-connect to the *playing* deck (the one whose
 * status packet asked for a lookup), regardless of which deck physically
 * holds the media. The DMST byte inside the request identifies the source
 * player whose track we're looking up.
 *
 * That asymmetry — "DBServer goes to the player, not the media" — is why
 * this worker keys on the playing deck only. Slot is per-query, not per-
 * worker. OneLibrary/PDB are different (they parse files on a specific
 * mount, so they key on (source_player, slot)) and live in their own
 * threads.
 *
 * Lifecycle: spawn when a CDJ first announces itself (parse_keepalive
 * was_new branch); stop only at shutdown via stop_all. Workers idle on a
 * cond-var when no work is pending — harmless when the CDJ disappears.
 */

#ifndef CLUBTAGGER_DBSERVER_THREAD_H
#define CLUBTAGGER_DBSERVER_THREAD_H

#include <stdint.h>

/* Spawn a worker for the given playing deck. Idempotent — returns 0 if a
 * worker already exists for this device.
 *
 * Returns 0 on success, -EINVAL on bad device_num, -ENOMEM on alloc
 * failure, -errno on pthread_create failure. */
int dbserver_thread_spawn(uint8_t playing_device);

/* Stop the worker for this playing deck. Joins the thread (may block
 * briefly while an in-flight query completes — bounded by the dbserver
 * socket's 2s SO_RCVTIMEO/SO_SNDTIMEO).
 *
 * Safe to call when no worker exists. */
void dbserver_thread_stop(uint8_t playing_device);

/* Enqueue a query for the worker matching this playing deck. Latest
 * request overwrites pending — at most one query per worker is in flight
 * or queued at a time. The worker emits the result into the track
 * registry under (rekordbox_id, query_target, source_slot) on success.
 *
 * playing_device is the deck that issued the lookup (where to TCP-connect).
 * query_ip is its IP — passed per-call rather than cached so IP changes
 * (slot conflict reassignment) propagate without restarting the worker.
 * query_target is the DMST byte = device number of the CDJ holding the
 * media (= playing_device for self-mounted, = track_source_player for
 * Link Export).
 * source_slot is the slot field for the DBServer request (USB or SD on
 * the source player's media).
 * track_type is what the status packet reported. We trust it — no
 * fallback to the other type. Empty results are logged as "weird".
 *
 * Returns 0 if enqueued, -ENOENT if no worker exists for this device. */
int dbserver_thread_enqueue(uint8_t playing_device,
                            uint32_t rekordbox_id,
                            uint32_t query_ip, uint8_t query_target,
                            uint8_t source_slot,
                            uint8_t track_type);

/* Stop and join all workers. Called from main.c at shutdown, after the
 * prolink thread has stopped. */
void dbserver_thread_stop_all(void);

#endif /* CLUBTAGGER_DBSERVER_THREAD_H */
