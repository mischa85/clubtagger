/*
 * pdb_thread.h - Per-(source_player, slot) PDB worker
 *
 * One worker per loaded media. The worker owns its pdb_database_t — fetches
 * export.pdb over NFS, parses it, and serves lookup requests. Results are
 * emitted into the track registry under (rekordbox_id, source_player, slot).
 *
 * Lifecycle mirrors onelibrary_thread: spawn on USB/SD insert, stop on remove.
 * The worker handles fetch backoff (10→300s) and detects "no PDB on this
 * media" (NFS NOENT) to stop retrying.
 */

#ifndef CLUBTAGGER_PDB_THREAD_H
#define CLUBTAGGER_PDB_THREAD_H

#include <stdint.h>

/* Spawn a worker for (source_player, slot). Idempotent — if a worker
 * already exists, device_ip / nfs_port / mount_port are refreshed (slot-
 * conflict reassignment or a fresh announce can change them without
 * re-mounting media). USB and SD only.
 *
 * `nfs_port` and `mount_port` come from cdj_device_t::nfs_port / mount_port
 * (discovered via portmap at announce). The worker passes them directly into
 * fetch_rekordbox_database — no portmap query happens on the worker thread.
 *
 * Returns 0 on success, -EINVAL on bad params, -ENOMEM on alloc failure,
 * -errno on pthread_create failure. */
int pdb_thread_spawn(uint8_t source_player, uint8_t slot,
                     uint32_t device_ip,
                     uint16_t nfs_port, uint16_t mount_port);

/* Stop the worker for (source_player, slot). Joins the thread (may block
 * briefly during an in-flight fetch — bounded by NFS timeouts) and
 * releases the database. Safe when no worker exists. */
void pdb_thread_stop(uint8_t source_player, uint8_t slot);

/* Enqueue a lookup. If the database isn't loaded yet, the request is
 * held until fetch completes (single-pending-slot, latest wins). If the
 * worker has determined this media has no PDB, the request is silently
 * discarded.
 *
 * Returns 0 if accepted, -ENOENT if no worker exists for (player, slot). */
int pdb_thread_enqueue(uint8_t source_player, uint8_t slot,
                       uint32_t rekordbox_id);

/* Stop and join all workers. Called at shutdown after the prolink thread
 * has stopped. */
void pdb_thread_stop_all(void);

#endif /* CLUBTAGGER_PDB_THREAD_H */
