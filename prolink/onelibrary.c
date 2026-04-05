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
#define OLIB_MAX_FILE_SIZE (16 * 1024 * 1024)  /* 16 MB max */

/* Passphrase set via --olib-key command line argument */
static const char *olib_passphrase = NULL;

void onelibrary_set_key(const char *key) {
    olib_passphrase = key;
}

int onelibrary_key_available(void) {
    return olib_passphrase && olib_passphrase[0];
}

static const char SQLITE_MAGIC[16] = "SQLite format 3";

/*
 * ============================================================================
 * Database Storage
 * ============================================================================
 */

static onelibrary_t olib_databases[MAX_ONELIBRARY];
static int olib_count = 0;

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
                            size_t *out_len)
{
    if (!encrypted || encrypted_len < OLIB_PAGE_SIZE ||
        encrypted_len % OLIB_PAGE_SIZE != 0) {
        vlogmsg("cdj", "[OLIB] Invalid file size %zu (must be multiple of %d)",
                    encrypted_len, OLIB_PAGE_SIZE);
        return NULL;
    }

    int num_pages = (int)(encrypted_len / OLIB_PAGE_SIZE);

    /* Extract salt from first 16 bytes of page 1 */
    unsigned char salt[OLIB_SALT_SIZE];
    memcpy(salt, encrypted, OLIB_SALT_SIZE);

    /* Derive encryption key: PBKDF2-HMAC-SHA512 */
    unsigned char enc_key[OLIB_KEY_SIZE];
    vlogmsg("cdj", "[OLIB] Deriving key (PBKDF2-HMAC-SHA512, %d iterations)...",
                OLIB_KDF_ITER);

    if (!olib_passphrase || !olib_passphrase[0]) {
        vlogmsg("cdj", "[OLIB] No decryption key set (use --olib-key)");
        return NULL;
    }

    if (!PKCS5_PBKDF2_HMAC(olib_passphrase, strlen(olib_passphrase),
                            salt, OLIB_SALT_SIZE, OLIB_KDF_ITER,
                            EVP_sha512(), OLIB_KEY_SIZE, enc_key)) {
        vlogmsg("cdj", "[OLIB] PBKDF2 key derivation failed");
        return NULL;
    }

    /* Allocate output buffer (same size as input) */
    uint8_t *output = malloc(encrypted_len);
    if (!output) {
        vlogmsg("cdj", "[OLIB] Failed to allocate %zu bytes for decryption", encrypted_len);
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
        vlogmsg("cdj", "[OLIB] Decryption failed - invalid SQLite header (wrong key?)");
        free(output);
        return NULL;
    }

    /* Fix reserved_for_extensions in header (byte 20) to match page reserve */
    /* SQLite header byte 20 = reserved space at end of each page */
    output[20] = OLIB_RESERVE_SIZE;

    *out_len = encrypted_len;
    vlogmsg("cdj", "[OLIB] Decrypted %d pages (%zu bytes), valid SQLite header",
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
        vlogmsg("cdj", "[OLIB] sqlite3_open failed: %s", sqlite3_errmsg(db));
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
        vlogmsg("cdj", "[OLIB] sqlite3_deserialize failed: %s", sqlite3_errmsg(db));
        sqlite3_close(db);
        free(decrypted_data);
        return -1;
    }

    /* Query track count */
    int track_count = 0;
    sqlite3_stmt *stmt = NULL;
    rc = sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM content", -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            track_count = sqlite3_column_int(stmt, 0);
        }
        sqlite3_finalize(stmt);
    }

    olib->db = db;
    olib->data = decrypted_data;
    olib->device_ip = device_ip;
    olib->slot = slot;
    olib->track_count = track_count;
    olib->fetched_at = time(NULL);

    logmsg("cdj", "📚 OneLibrary loaded: %d tracks from %s @ %s",
           track_count,
           slot == 3 ? "USB" : (slot == 2 ? "SD" : "?"),
           ip_to_str(device_ip));

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
            logmsg("cdj", "📚 OneLibrary content_ids: [%s]", ids);
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

onelibrary_t *find_onelibrary(uint32_t device_ip, uint8_t slot)
{
    for (int i = 0; i < olib_count; i++) {
        if (olib_databases[i].db &&
            olib_databases[i].device_ip == device_ip &&
            olib_databases[i].slot == slot) {
            return &olib_databases[i];
        }
    }
    return NULL;
}

void remove_onelibrary(uint32_t device_ip, uint8_t slot)
{
    for (int i = 0; i < olib_count; i++) {
        if (olib_databases[i].device_ip == device_ip &&
            olib_databases[i].slot == slot) {
            int track_count = olib_databases[i].track_count;
            onelibrary_close(&olib_databases[i]);

            /* Shift remaining down */
            for (int j = i; j < olib_count - 1; j++) {
                olib_databases[j] = olib_databases[j + 1];
            }
            memset(&olib_databases[olib_count - 1], 0, sizeof(onelibrary_t));
            olib_count--;

            vlogmsg("cdj", "🗑️ Removed OneLibrary: %s @ %s (%d tracks)",
                       slot == 3 ? "USB" : (slot == 2 ? "SD" : "?"),
                       ip_to_str(device_ip), track_count);
            return;
        }
    }
}

/*
 * ============================================================================
 * Track Lookup
 * ============================================================================
 */

int onelibrary_lookup(uint32_t content_id,
                      uint32_t device_ip, uint8_t slot,
                      char *title, size_t title_len,
                      char *artist, size_t artist_len,
                      char *isrc, size_t isrc_len,
                      uint32_t *bitrate_out, uint8_t *format_out)
{
    if (content_id == 0) return -1;

    for (int i = 0; i < olib_count; i++) {
        if (!olib_databases[i].db) continue;
        /* If device_ip specified, only search matching database */
        if (device_ip != 0 &&
            (olib_databases[i].device_ip != device_ip || olib_databases[i].slot != slot))
            continue;

        sqlite3_stmt *stmt = NULL;
        int rc = sqlite3_prepare_v2(olib_databases[i].db,
            "SELECT c.title, a.name, c.isrc, c.bitrate, c.fileType "
            "FROM content c "
            "LEFT JOIN artist a ON c.artist_id_artist = a.artist_id "
            "WHERE c.content_id = ?",
            -1, &stmt, NULL);

        if (rc != SQLITE_OK) continue;

        sqlite3_bind_int(stmt, 1, (int)content_id);

        if (sqlite3_step(stmt) == SQLITE_ROW) {
            const char *t = (const char *)sqlite3_column_text(stmt, 0);
            const char *a = (const char *)sqlite3_column_text(stmt, 1);
            const char *isr = (const char *)sqlite3_column_text(stmt, 2);
            int br = sqlite3_column_int(stmt, 3);
            int ft = sqlite3_column_int(stmt, 4);

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

            sqlite3_finalize(stmt);

            if (verbose) {
                vlogmsg("cdj", "[OLIB] Found track %u: \"%s\" by \"%s\"",
                           content_id, title ? title : "", artist ? artist : "");
            }
            return 0;
        }

        sqlite3_finalize(stmt);
    }

    if (olib_count > 0 && verbose) {
        logmsg("cdj", "⚠ OneLibrary miss: content_id=%u not found in %d database(s)",
               content_id, olib_count);
    }
    return -1;
}

/*
 * ============================================================================
 * NFS Fetching
 * ============================================================================
 */

/* Cached NFS port from portmapper (shared with pdb_parser.c) */
extern uint16_t g_nfs_port;

/* Simplified NFS lookup helper (reuses g_nfs_port) */
static int olib_nfs_lookup(uint32_t server_ip, const uint8_t *dir_fh,
                           const char *name, uint8_t *file_fh)
{
    return nfs_lookup(server_ip, g_nfs_port, dir_fh, name, file_fh);
}

int fetch_onelibrary_database(uint32_t device_ip, uint8_t slot)
{
    uint8_t root_fh[64], pioneer_fh[64], rb_fh[64], olib_fh[64];
    size_t root_fh_len;

    /* Determine export path based on slot */
    const char *export_path;
    switch (slot) {
        case 2: export_path = "/B/"; break;  /* SD card */
        case 3: export_path = "/C/"; break;  /* USB */
        default:
            vlogmsg("cdj", "[OLIB] Unknown slot type %d", slot);
            return -1;
    }

    vlogmsg("cdj", "📥 Fetching OneLibrary from %s (slot %s, export %s)...",
                ip_to_str(device_ip), cdj_slot_name(slot), export_path);

    /* Step 1: Query portmapper for mount port */
    int mount_port = rpc_portmap_getport(device_ip, MOUNT_PROGRAM, MOUNT_VERSION);
    if (mount_port <= 0) {
        vlogmsg("cdj", "[OLIB] Portmapper query failed");
        return -1;
    }

    /* Query portmapper for NFS port */
    int nfs_port = rpc_portmap_getport(device_ip, NFS_PROGRAM, NFS_VERSION);
    if (nfs_port <= 0) {
        nfs_port = 2049;
    }
    g_nfs_port = (uint16_t)nfs_port;

    /* Step 2: Mount the export */
    if (nfs_mount_to_port(device_ip, (uint16_t)mount_port, export_path,
                          root_fh, &root_fh_len) != 0) {
        vlogmsg("cdj", "[OLIB] Mount failed");
        return -1;
    }

    /* Step 3: Lookup PIONEER/rekordbox/exportLibrary.db */
    if (olib_nfs_lookup(device_ip, root_fh, "PIONEER", pioneer_fh) != 0) {
        vlogmsg("cdj", "[OLIB] PIONEER dir not found");
        return -1;
    }
    if (olib_nfs_lookup(device_ip, pioneer_fh, "rekordbox", rb_fh) != 0) {
        vlogmsg("cdj", "[OLIB] rekordbox dir not found");
        return -1;
    }
    if (olib_nfs_lookup(device_ip, rb_fh, "exportLibrary.db", olib_fh) != 0) {
        vlogmsg("cdj", "[OLIB] exportLibrary.db not found (no OneLibrary on media)");
        return -1;
    }

    /* Step 4: Read the file */
    uint8_t *encrypted = malloc(OLIB_MAX_FILE_SIZE);
    if (!encrypted) return -1;

    vlogmsg("cdj", "📖 Reading exportLibrary.db...");

    size_t total_read = 0;
    if (nfs_read_file(device_ip, g_nfs_port, olib_fh, encrypted,
                      OLIB_MAX_FILE_SIZE, &total_read) != 0) {
        vlogmsg("cdj", "[OLIB] Read error");
        nfs_close_socket();
        free(encrypted);
        return -1;
    }

    vlogmsg("cdj", "📄 Downloaded %zu bytes", total_read);
    nfs_close_socket();

    /* Step 5: Decrypt */
    size_t decrypted_len = 0;
    uint8_t *decrypted = onelibrary_decrypt(encrypted, total_read, &decrypted_len);
    free(encrypted);

    if (!decrypted) {
        vlogmsg("cdj", "[OLIB] Decryption failed");
        return -1;
    }

    /* Step 6: Open as SQLite and register */
    /* Find or create slot */
    onelibrary_t *olib = find_onelibrary(device_ip, slot);
    if (olib) {
        onelibrary_close(olib);
    } else {
        if (olib_count < MAX_ONELIBRARY) {
            olib = &olib_databases[olib_count++];
        } else {
            /* Evict oldest */
            time_t oldest = time(NULL);
            int oldest_idx = 0;
            for (int i = 0; i < MAX_ONELIBRARY; i++) {
                if (olib_databases[i].fetched_at < oldest) {
                    oldest = olib_databases[i].fetched_at;
                    oldest_idx = i;
                }
            }
            onelibrary_close(&olib_databases[oldest_idx]);
            olib = &olib_databases[oldest_idx];
        }
    }
    memset(olib, 0, sizeof(onelibrary_t));

    if (onelibrary_open(olib, decrypted, decrypted_len, device_ip, slot) != 0) {
        vlogmsg("cdj", "[OLIB] Failed to open decrypted database");
        return -1;
    }

    return 0;
}

/*
 * ============================================================================
 * Passive Sniffing
 * ============================================================================
 */

void onelibrary_process_passive(const uint8_t *data, size_t len,
                                uint32_t server_ip, uint8_t slot)
{
    vlogmsg("cdj", "[OLIB] Processing passively captured OneLibrary (%zu bytes) from %s",
               len, ip_to_str(server_ip));

    /* Decrypt */
    size_t decrypted_len = 0;
    uint8_t *decrypted = onelibrary_decrypt(data, len, &decrypted_len);
    if (!decrypted) {
        vlogmsg("cdj", "[OLIB] Passive decryption failed");
        return;
    }

    /* Find or create slot */
    onelibrary_t *olib = find_onelibrary(server_ip, slot);
    if (olib) {
        onelibrary_close(olib);
    } else {
        if (olib_count < MAX_ONELIBRARY) {
            olib = &olib_databases[olib_count++];
        } else {
            /* Evict oldest */
            time_t oldest = time(NULL);
            int oldest_idx = 0;
            for (int i = 0; i < MAX_ONELIBRARY; i++) {
                if (olib_databases[i].fetched_at < oldest) {
                    oldest = olib_databases[i].fetched_at;
                    oldest_idx = i;
                }
            }
            onelibrary_close(&olib_databases[oldest_idx]);
            olib = &olib_databases[oldest_idx];
        }
    }
    memset(olib, 0, sizeof(onelibrary_t));

    if (onelibrary_open(olib, decrypted, decrypted_len, server_ip, slot) != 0) {
        vlogmsg("cdj", "[OLIB] Failed to open passively captured database");
    }
}
