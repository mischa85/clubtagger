/*
 * onelibrary.c - Rekordbox OneLibrary (exportLibrary.db) Support
 *
 * Decrypts SQLCipher 4 encrypted databases and queries track metadata.
 *
 * SQLCipher 4 parameters:
 *   Page size:    4096
 *   KDF:          PBKDF2-HMAC-SHA512, 256,000 iterations
 *   Cipher:       AES-256-CBC (no padding)
 *   Reserve:      80 bytes per page (16-byte IV + 64-byte HMAC-SHA512)
 *   Salt:         first 16 bytes of page 1
 *
 * The passphrase is hardcoded in Rekordbox; all exports use the same key.
 */

#include "onelibrary.h"
#include "nfs_client.h"
#include "nfs_protocol.h"
#include "cdj_types.h"
#include "../common.h"

#include <sqlite3.h>
#include <openssl/evp.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>

extern int verbose;
extern uint32_t our_ip;
extern const char *capture_interface;

/*
 * ============================================================================
 * Constants
 * ============================================================================
 */

#define OLIB_PAGE_SIZE     4096
#define OLIB_RESERVE_SIZE  80     /* 16 IV + 64 HMAC per page */
#define OLIB_IV_SIZE       16
#define OLIB_SALT_SIZE     16
#define OLIB_KEY_SIZE      32     /* AES-256 */
#define OLIB_KDF_ITER      256000

static const char SQLITE_MAGIC[16] = "SQLite format 3";

/*
 * ============================================================================
 * Decryption
 * ============================================================================
 */

/* Decrypt a single page using AES-256-CBC with no padding */
static int decrypt_page(const unsigned char *key, const unsigned char *iv,
                        const unsigned char *ct, int ct_len,
                        unsigned char *pt)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int out_len = 0, total = 0;

    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_CIPHER_CTX_set_padding(ctx, 0);  /* No PKCS7 padding */
    EVP_DecryptUpdate(ctx, pt, &out_len, ct, ct_len);
    total += out_len;
    EVP_DecryptFinal_ex(ctx, pt + total, &out_len);
    total += out_len;

    EVP_CIPHER_CTX_free(ctx);
    return total;
}

uint8_t *onelibrary_decrypt(const uint8_t *encrypted, size_t encrypted_len,
                            const char *passphrase, size_t *out_len)
{
    if (!encrypted || encrypted_len < OLIB_PAGE_SIZE ||
        encrypted_len % OLIB_PAGE_SIZE != 0) {
        logmsg("olib", "Invalid file size %zu (page=%d, multiple required) — encrypted=%p",
               encrypted_len, OLIB_PAGE_SIZE, (const void *)encrypted);
        return NULL;
    }

    if (!passphrase || !passphrase[0]) {
        logmsg("olib", "onelibrary_decrypt: NULL/empty passphrase; cannot decrypt %zu bytes",
               encrypted_len);
        return NULL;
    }

    int num_pages = (int)(encrypted_len / OLIB_PAGE_SIZE);

    /* Extract salt from first 16 bytes of page 1 */
    unsigned char salt[OLIB_SALT_SIZE];
    memcpy(salt, encrypted, OLIB_SALT_SIZE);

    /* Derive encryption key: PBKDF2-HMAC-SHA512 */
    unsigned char enc_key[OLIB_KEY_SIZE];
    vlogmsg("olib", "Deriving key (PBKDF2-HMAC-SHA512, %d iterations)...",
                OLIB_KDF_ITER);

    if (!PKCS5_PBKDF2_HMAC(passphrase, strlen(passphrase),
                            salt, OLIB_SALT_SIZE, OLIB_KDF_ITER,
                            EVP_sha512(), OLIB_KEY_SIZE, enc_key)) {
        logmsg("olib", "PBKDF2 key derivation failed");
        return NULL;
    }

    /* Allocate output buffer (same size as input) */
    uint8_t *output = malloc(encrypted_len);
    if (!output) {
        vlogmsg("olib", "Failed to allocate %zu bytes for decryption", encrypted_len);
        return NULL;
    }

    unsigned char page_out[OLIB_PAGE_SIZE];

    for (int p = 0; p < num_pages; p++) {
        int pgno = p + 1;
        const unsigned char *page = encrypted + (size_t)p * OLIB_PAGE_SIZE;
        int offset = (pgno == 1) ? OLIB_SALT_SIZE : 0;

        const unsigned char *iv = page + OLIB_PAGE_SIZE - OLIB_RESERVE_SIZE;
        const unsigned char *ct = page + offset;
        int ct_len = OLIB_PAGE_SIZE - offset - OLIB_RESERVE_SIZE;

        memset(page_out, 0, OLIB_PAGE_SIZE);

        if (pgno == 1) {
            /* Restore SQLite magic header (salt replaced first 16 bytes) */
            memcpy(page_out, SQLITE_MAGIC, 16);
            decrypt_page(enc_key, iv, ct, ct_len, page_out + OLIB_SALT_SIZE);
        } else {
            decrypt_page(enc_key, iv, ct, ct_len, page_out);
        }

        memcpy(output + (size_t)p * OLIB_PAGE_SIZE, page_out, OLIB_PAGE_SIZE);
    }

    /* Verify output has valid SQLite header */
    if (memcmp(output, SQLITE_MAGIC, 15) != 0) {
        logmsg("olib", "Decryption failed - invalid SQLite header (wrong key?)");
        free(output);
        return NULL;
    }

    /* Fix reserved_for_extensions in header (byte 20) to match page reserve */
    /* SQLite header byte 20 = reserved space at end of each page */
    output[20] = OLIB_RESERVE_SIZE;

    *out_len = encrypted_len;
    vlogmsg("olib", "Decrypted %d pages (%zu bytes), valid SQLite header",
                num_pages, encrypted_len);
    return output;
}

/*
 * ============================================================================
 * Database Operations
 * ============================================================================
 */

int onelibrary_open(onelibrary_t *olib, uint8_t *decrypted_data, size_t data_len,
                    uint32_t device_ip, uint8_t slot)
{
    if (!olib || !decrypted_data || data_len == 0) {
        free(decrypted_data);
        return -1;
    }

    sqlite3 *db = NULL;

    /* Open in-memory database and deserialize the decrypted data into it */
    int rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        logmsg("olib", "sqlite3_open failed: %s", sqlite3_errmsg(db));
        sqlite3_close(db);
        free(decrypted_data);
        return -1;
    }

    /* Deserialize without FREEONCLOSE — we free the buffer ourselves in
     * onelibrary_close() to avoid sqlite3_free/malloc mismatch. Read-only
     * so RESIZEABLE is not needed either. */
    rc = sqlite3_deserialize(db, "main", decrypted_data, (sqlite3_int64)data_len,
                             (sqlite3_int64)data_len, 0);
    if (rc != SQLITE_OK) {
        logmsg("olib", "sqlite3_deserialize failed: %s", sqlite3_errmsg(db));
        sqlite3_close(db);
        free(decrypted_data);
        return -1;
    }

    /* Count tracks by stepping rows, not COUNT(*). A holey DB (zero-filled
     * pages from an incomplete NFS fetch) makes a full-table aggregate abort
     * with SQLITE_CORRUPT and report 0 — even though per-id lookups still work
     * for every track outside the bad page. Stepping row-by-row keeps the
     * count of every row reachable before a corrupt page, so a partial DB
     * reports a real (floor) count instead of zero. */
    int track_count = 0;
    int partial = 0;
    sqlite3_stmt *stmt = NULL;
    rc = sqlite3_prepare_v2(db, "SELECT content_id FROM content", -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        int sr;
        while ((sr = sqlite3_step(stmt)) == SQLITE_ROW) track_count++;
        if (sr != SQLITE_DONE) partial = 1;   /* hit a corrupt/zero-filled page */
        sqlite3_finalize(stmt);
    }

    olib->db = db;
    olib->data = decrypted_data;
    olib->device_ip = device_ip;
    olib->slot = slot;
    olib->track_count = track_count;
    olib->fetched_at = time(NULL);

    logmsg("olib", "📚 OneLibrary loaded: %d tracks from %s @ %s%s",
           track_count, cdj_slot_name(slot), ip_to_str(device_ip),
           partial ? " (partial — DB has unreadable pages)" : "");

    /* Log content_id range for small libraries (debugging ID mismatches) */
    if (track_count > 0 && track_count <= 5) {
        sqlite3_stmt *s = NULL;
        if (sqlite3_prepare_v2(db,
                "SELECT content_id FROM content ORDER BY content_id", -1, &s, NULL) == SQLITE_OK) {
            char ids[128] = {0};
            int pos = 0;
            while (sqlite3_step(s) == SQLITE_ROW && pos < 120)
                pos += snprintf(ids + pos, sizeof(ids) - pos, "%s%d",
                                pos ? "," : "", sqlite3_column_int(s, 0));
            sqlite3_finalize(s);
            logmsg("olib", "📚 OneLibrary content_ids: [%s]", ids);
        }
    }

    return 0;
}

void onelibrary_close(onelibrary_t *olib)
{
    if (!olib) return;
    if (olib->db) {
        sqlite3_close(olib->db);
        olib->db = NULL;
    }
    if (olib->data) {
        free(olib->data);
        olib->data = NULL;
    }
    olib->track_count = 0;
    olib->fetched_at = 0;
}

/*
 * ============================================================================
 * Track Lookup
 * ============================================================================
 */

int onelibrary_lookup(onelibrary_t *olib, uint32_t content_id,
                      char *title, size_t title_len,
                      char *artist, size_t artist_len,
                      char *isrc, size_t isrc_len,
                      uint32_t *bitrate_out, uint8_t *format_out,
                      uint32_t *samplerate_out, uint8_t *depth_out,
                      char *anlz_path, size_t anlz_path_len)
{
    if (!olib || !olib->db || content_id == 0) return -1;

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(olib->db,
        "SELECT c.title, a.name, c.isrc, c.bitrate, c.fileType, c.samplingRate, c.bitDepth, c.analysisDataFilePath "
        "FROM content c "
        "LEFT JOIN artist a ON c.artist_id_artist = a.artist_id "
        "WHERE c.content_id = ?",
        -1, &stmt, NULL);

    if (rc != SQLITE_OK) {
        logmsg("olib", "sqlite3_prepare_v2 failed: %s", sqlite3_errmsg(olib->db));
        return -1;
    }

    sqlite3_bind_int(stmt, 1, (int)content_id);

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const char *t = (const char *)sqlite3_column_text(stmt, 0);
        const char *a = (const char *)sqlite3_column_text(stmt, 1);
        const char *isr = (const char *)sqlite3_column_text(stmt, 2);
        int br = sqlite3_column_int(stmt, 3);
        int ft = sqlite3_column_int(stmt, 4);
        int sr = sqlite3_column_int(stmt, 5);
        int bd = sqlite3_column_int(stmt, 6);

        if (t && title && title_len > 0) {
            strncpy(title, t, title_len - 1);
            title[title_len - 1] = '\0';
        }
        if (a && artist && artist_len > 0) {
            strncpy(artist, a, artist_len - 1);
            artist[artist_len - 1] = '\0';
        }
        if (isr && isr[0] && isrc && isrc_len > 0) {
            strncpy(isrc, isr, isrc_len - 1);
            isrc[isrc_len - 1] = '\0';
        } else if (isrc && isrc_len > 0) {
            isrc[0] = '\0';
        }
        if (bitrate_out) *bitrate_out = (uint32_t)br;
        if (format_out) *format_out = (uint8_t)ft;
        if (samplerate_out) *samplerate_out = (uint32_t)sr;
        if (depth_out) *depth_out = (uint8_t)bd;
        const char *ap = (const char *)sqlite3_column_text(stmt, 7);
        if (ap && ap[0] && anlz_path && anlz_path_len > 0) {
            strncpy(anlz_path, ap, anlz_path_len - 1);
            anlz_path[anlz_path_len - 1] = '\0';
        } else if (anlz_path && anlz_path_len > 0) {
            anlz_path[0] = '\0';
        }

        sqlite3_finalize(stmt);

        if (verbose) {
            vlogmsg("olib", "Found track %u: \"%s\" by \"%s\"",
                       content_id, title ? title : "", artist ? artist : "");
        }
        return 0;
    }

    sqlite3_finalize(stmt);
    return -1;
}

/*
 * ============================================================================
 * NFS Fetching
 * ============================================================================
 */

int fetch_onelibrary_database(onelibrary_t *out, uint32_t device_ip, uint8_t slot,
                              uint16_t nfs_port, uint16_t mount_port,
                              const char *passphrase)
{
    if (!out) {
        logmsg("olib", "fetch: NULL out pointer");
        return -1;
    }
    if (!passphrase || !passphrase[0]) {
        logmsg("olib", "fetch: NULL/empty passphrase for %s slot %s",
               ip_to_str(device_ip), cdj_slot_name(slot));
        return -1;
    }
    if (nfs_port == 0 || mount_port == 0) {
        logmsg("olib", "fetch: missing ports for %s slot %s (nfs=%u mount=%u) — announce portmap discovery did not complete",
               ip_to_str(device_ip), cdj_slot_name(slot), nfs_port, mount_port);
        return -1;
    }
    memset(out, 0, sizeof(*out));

    uint8_t root_fh[64], pioneer_fh[64], rb_fh[64], olib_fh[64];
    size_t root_fh_len;

    /* Determine export path based on slot */
    const char *export_path;
    switch (slot) {
        case 2: export_path = "/B/"; break;  /* SD card */
        case 3: export_path = "/C/"; break;  /* USB */
        default:
            vlogmsg("olib", "Unknown slot type %d", slot);
            return -1;
    }

    vlogmsg("olib", "📥 Fetching OneLibrary from %s (slot %s, export %s, nfs=%u mount=%u)...",
                ip_to_str(device_ip), cdj_slot_name(slot), export_path,
                nfs_port, mount_port);

    /* Step 2: Mount the export */
    int mrc = nfs_mount_to_port(device_ip, mount_port, export_path,
                                root_fh, &root_fh_len);
    if (mrc != 0) {
        logmsg("olib", "Mount %s failed on %s slot %s%s",
               export_path, ip_to_str(device_ip), cdj_slot_name(slot),
               mrc == -ENOENT ? " (export NOENT)" : "");
        return mrc == -ENOENT ? -ENOENT : -1;
    }

    /* Step 3: Lookup PIONEER/rekordbox/exportLibrary.db */
    int lrc = nfs_lookup(device_ip, nfs_port, root_fh, "PIONEER", pioneer_fh, NULL);
    if (lrc != 0) {
        logmsg("olib", "PIONEER dir not found on %s slot %s%s",
               ip_to_str(device_ip), cdj_slot_name(slot),
               lrc == -ENOENT ? " (NOENT)" : "");
        return lrc == -ENOENT ? -ENOENT : -1;
    }
    lrc = nfs_lookup(device_ip, nfs_port, pioneer_fh, "rekordbox", rb_fh, NULL);
    if (lrc != 0) {
        logmsg("olib", "rekordbox dir not found on %s slot %s%s",
               ip_to_str(device_ip), cdj_slot_name(slot),
               lrc == -ENOENT ? " (NOENT — non-rekordbox media)" : "");
        return lrc == -ENOENT ? -ENOENT : -1;
    }
    uint32_t olib_size = 0;
    lrc = nfs_lookup(device_ip, nfs_port, rb_fh, "exportLibrary.db", olib_fh, &olib_size);
    if (lrc != 0) {
        logmsg("olib", "exportLibrary.db not found on %s slot %s%s",
               ip_to_str(device_ip), cdj_slot_name(slot),
               lrc == -ENOENT ? " (NOENT — no OneLibrary on this media)" : "");
        return lrc == -ENOENT ? -ENOENT : -1;
    }

    /* Step 4: Size the buffer to the real file length (clamped to the fetch
     * cap as the OOM guard); fall back to the cap if LOOKUP gave no size. */
    size_t alloc = (olib_size > 0 && olib_size <= NFS_MAX_FETCH_SIZE)
                       ? olib_size : NFS_MAX_FETCH_SIZE;
    if (olib_size > NFS_MAX_FETCH_SIZE) {
        logmsg("olib", "exportLibrary.db is %u bytes, exceeds %u-byte cap — fetch will be partial",
               olib_size, NFS_MAX_FETCH_SIZE);
    }
    uint8_t *encrypted = malloc(alloc);
    if (!encrypted) {
        logmsg("olib", "malloc(%zu) failed for encrypted buffer", alloc);
        return -1;
    }

    vlogmsg("olib", "📖 Reading exportLibrary.db (%u bytes)...", olib_size);

    size_t total_read = 0;
    int rrc = nfs_read_file(device_ip, nfs_port, olib_fh, "exportLibrary.db",
                            encrypted, alloc, &total_read);
    if (rrc != 0) {
        logmsg("olib", "Read error fetching exportLibrary.db from %s slot %s (rc=%d)",
               ip_to_str(device_ip), cdj_slot_name(slot), rrc);
        nfs_close_socket();
        free(encrypted);
        return rrc == -ENOENT ? -ENOENT : -1;
    }

    vlogmsg("olib", "📄 Downloaded %zu bytes", total_read);
    nfs_close_socket();

    /* Step 5: Decrypt */
    size_t decrypted_len = 0;
    uint8_t *decrypted = onelibrary_decrypt(encrypted, total_read, passphrase, &decrypted_len);
    free(encrypted);

    if (!decrypted) {
        logmsg("olib", "Decryption failed");
        return -1;
    }

    /* Step 6: Open as SQLite into caller-owned struct. onelibrary_open
     * takes ownership of `decrypted` (frees on success or failure). */
    if (onelibrary_open(out, decrypted, decrypted_len, device_ip, slot) != 0) {
        logmsg("olib", "Failed to open decrypted database for %s slot %s",
               ip_to_str(device_ip), cdj_slot_name(slot));
        return -1;
    }

    return 0;
}
