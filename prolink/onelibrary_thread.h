/*
 * onelibrary_thread.h - Per-(source_player, slot) OneLibrary worker
 *
 * One worker per loaded media. The worker owns its onelibrary_t — fetches
 * exportLibrary.db over NFS, decrypts (SQLCipher 4), opens in-memory SQLite,
 * and serves lookup requests. Results are emitted into the track registry
 * under (rekordbox_id, source_player, slot).
 *
 * Lifecycle is driven by media insert/remove (parse_cdj_status →
 * update_slot_media). The worker handles fetch backoff (10→300s) and
 * detects "no OneLibrary on this media" (NFS NOENT) to stop retrying.
 *
 * Why separate from dbserver_thread: DBServer queries the *playing* CDJ
 * regardless of where the media lives, so it keys on the playing deck.
 * OneLibrary parses a file at a specific mount, so it keys on the
 * (source_player, slot) that holds the media.
 */

#ifndef CLUBTAGGER_ONELIBRARY_THREAD_H
#define CLUBTAGGER_ONELIBRARY_THREAD_H

#include <stdint.h>

/* Spawn a worker for (source_player, slot). Idempotent — if a worker
 * already exists, device_ip / nfs_port / mount_port are refreshed (slot-
 * conflict reassignment or a fresh announce can change them without
 * re-mounting media). USB and SD only.
 *
 * `nfs_port` and `mount_port` are the device's ports from
 * cdj_device_t::nfs_port / mount_port, discovered via portmap at announce.
 * The worker passes them directly into fetch_onelibrary_database — no
 * portmap query happens on the worker thread.
 *
 * `passphrase` is the SQLCipher decryption key (required, non-empty); the
 * worker stores the pointer (does NOT copy — caller must keep it alive for
 * the worker's lifetime, e.g., argv strings). Callers with no key
 * configured must skip the spawn entirely.
 *
 * Returns 0 on success, -EINVAL on bad params, -ENOMEM on alloc failure,
 * -errno on pthread_create failure. */
int onelibrary_thread_spawn(uint8_t source_player, uint8_t slot,
                            uint32_t device_ip,
                            uint16_t nfs_port, uint16_t mount_port,
                            const char *passphrase);

/* Stop the worker for (source_player, slot). Joins the thread (may block
 * briefly during an in-flight fetch — bounded by NFS timeouts) and
 * releases the SQLite database. Safe when no worker exists. */
void onelibrary_thread_stop(uint8_t source_player, uint8_t slot);

/* Enqueue a lookup. If the database isn't loaded yet, the request is
 * held until fetch completes (single-pending-slot, latest wins). If the
 * worker has determined this media has no OneLibrary, the request is
 * silently discarded.
 *
 * Returns 0 if accepted, -ENOENT if no worker exists for (player, slot). */
int onelibrary_thread_enqueue(uint8_t source_player, uint8_t slot,
                              uint32_t rekordbox_id);

/* Stop and join all workers. Called at shutdown after the prolink thread
 * has stopped. */
void onelibrary_thread_stop_all(void);

#endif /* CLUBTAGGER_ONELIBRARY_THREAD_H */
