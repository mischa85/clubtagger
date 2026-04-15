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

#define MAX_ONELIBRARY 12   /* 6 CDJs x 2 slots */

/*
 * ============================================================================
 * Decryption
 * ============================================================================
 */

/* Set the decryption passphrase (must be called before any decrypt operations) */
void onelibrary_set_key(const char *key);

/* Check if a decryption key has been set */
int onelibrary_key_available(void);

/* Decrypt a SQLCipher 4 encrypted OneLibrary database in memory.
 * Returns malloc'd plaintext buffer (caller frees), or NULL on failure.
 * out_len receives the size of decrypted data. */
uint8_t *onelibrary_decrypt(const uint8_t *encrypted, size_t encrypted_len,
                            size_t *out_len);

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

/* Close and free OneLibrary handle */
void onelibrary_close(onelibrary_t *olib);

/* Find loaded OneLibrary for device/slot */
onelibrary_t *find_onelibrary(uint32_t device_ip, uint8_t slot);

/* Remove OneLibrary for device/slot (e.g., media ejected) */
void remove_onelibrary(uint32_t device_ip, uint8_t slot);

/*
 * ============================================================================
 * Track Lookup
 * ============================================================================
 */

/* Look up track by content_id (= rekordbox_id) in a specific device's database.
 * If device_ip is 0, searches all loaded databases (legacy behavior).
 * Populates title/artist/isrc into provided buffers.
 * bitrate_out/format_out may be NULL if not needed.
 * Returns 0 on success, -1 if not found. */
int onelibrary_lookup(uint32_t content_id,
                      uint32_t device_ip, uint8_t slot,
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

/* Fetch exportLibrary.db from CDJ via NFS, decrypt, and open.
 * Returns 0 on success, -1 on failure. */
int fetch_onelibrary_database(uint32_t device_ip, uint8_t slot);

/* Process passively captured exportLibrary.db data */
void onelibrary_process_passive(const uint8_t *data, size_t len,
                                uint32_t server_ip, uint8_t slot);

#endif /* ONELIBRARY_H */
