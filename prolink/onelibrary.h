/*
 * onelibrary.h - Rekordbox OneLibrary (exportLibrary.db) Support
 *
 * Decrypt and query the OneLibrary database format used by Rekordbox 6+
 * and supported by CDJ-3000X, OPUS-QUAD, XDJ-AZ, etc.
 * The database is a SQLCipher 4 encrypted SQLite file with a hardcoded key.
 */

#ifndef ONELIBRARY_H
#define ONELIBRARY_H

#include <stdint.h>
#include <stddef.h>
#include <time.h>

/* Forward declare sqlite3 to avoid including sqlite3.h in header */
struct sqlite3;
typedef struct sqlite3 sqlite3;

/*
 * ============================================================================
 * OneLibrary Database Handle
 * ============================================================================
 */

typedef struct {
    sqlite3  *db;           /* Decrypted SQLite handle (in-memory) */
    uint8_t  *data;         /* Deserialized buffer (we free, not SQLite) */
    uint32_t  device_ip;    /* CDJ IP that served this database */
    uint8_t   slot;         /* Media slot (2=SD, 3=USB) */
    int       track_count;  /* Number of tracks in database */
    time_t    fetched_at;   /* When this database was loaded */
} onelibrary_t;

/*
 * ============================================================================
 * Decryption
 * ============================================================================
 */

/* Decrypt a SQLCipher 4 encrypted OneLibrary database in memory using the
 * given passphrase. Returns malloc'd plaintext buffer (caller frees), or
 * NULL on failure. out_len receives the size of decrypted data. */
uint8_t *onelibrary_decrypt(const uint8_t *encrypted, size_t encrypted_len,
                            const char *passphrase, size_t *out_len);

/*
 * ============================================================================
 * Database Operations
 * ============================================================================
 */

/* Open decrypted data as in-memory SQLite database.
 * Takes ownership of decrypted_data (freed when closed).
 * Returns 0 on success, -1 on failure. */
int onelibrary_open(onelibrary_t *olib, uint8_t *decrypted_data, size_t data_len,
                    uint32_t device_ip, uint8_t slot);

/* Close and free OneLibrary handle (idempotent). */
void onelibrary_close(onelibrary_t *olib);

/*
 * ============================================================================
 * Track Lookup
 * ============================================================================
 */

/* Look up track by content_id (= rekordbox_id) in the given database.
 * Populates title/artist/isrc into provided buffers.
 * bitrate_out/format_out etc. may be NULL if not needed.
 * Returns 0 on success, -1 if not found / olib not loaded. */
int onelibrary_lookup(onelibrary_t *olib, uint32_t content_id,
                      char *title, size_t title_len,
                      char *artist, size_t artist_len,
                      char *isrc, size_t isrc_len,
                      uint32_t *bitrate_out, uint8_t *format_out,
                      uint32_t *samplerate_out, uint8_t *depth_out,
                      char *anlz_path, size_t anlz_path_len);

/*
 * ============================================================================
 * NFS Fetching
 * ============================================================================
 */

/* Fetch exportLibrary.db from CDJ via NFS, decrypt with `passphrase`, and
 * open into *out. On success *out is populated and owns its sqlite handle
 * + buffer (caller must release via onelibrary_close).
 *
 * `nfs_port` and `mount_port` are the device's ports discovered at announce
 * time (cdj_device_t::nfs_port, mount_port); the fetcher does not touch
 * portmap at all. Both must be non-zero.
 *
 * Returns 0 on success, -ENOENT if the export/file is absent (caller should
 * stop retrying), -1 on transient failure (caller may retry with backoff). */
int fetch_onelibrary_database(onelibrary_t *out,
                              uint32_t device_ip, uint8_t slot,
                              uint16_t nfs_port, uint16_t mount_port,
                              const char *passphrase);

#endif /* ONELIBRARY_H */
