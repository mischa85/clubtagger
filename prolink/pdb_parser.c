/*
 * pdb_parser.c - Rekordbox PDB Database Parser
 *
 * Parse rekordbox export.pdb files to extract track metadata.
 * Reference: https://djl-analysis.deepsymmetry.org/rekordbox-export-analysis/exports.html
 */

#include "pdb_parser.h"
#include "pdb_protocol.h"
#include "nfs_client.h"
#include "nfs_protocol.h"
#include "cdj_types.h"
#include "../common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

extern int verbose;

/*
 * ============================================================================
 * Database Storage
 * ============================================================================
 */

pdb_database_t pdb_databases[MAX_DATABASES];
int pdb_database_count = 0;

/*
 * ============================================================================
 * Database Management
 * ============================================================================
 */

pdb_database_t *find_pdb_database(uint32_t device_ip, uint8_t slot) {
    for (int i = 0; i < pdb_database_count; i++) {
        if (pdb_databases[i].device_ip == device_ip && 
            pdb_databases[i].slot == slot) {
            return &pdb_databases[i];
        }
    }
    return NULL;
}

pdb_database_t *create_pdb_database(uint32_t device_ip, uint8_t slot) {
    pdb_database_t *db;
    
    if (pdb_database_count >= MAX_DATABASES) {
        /* Evict oldest - just reset header, track array cleared by parse_pdb_file */
        time_t oldest = time(NULL);
        int oldest_idx = 0;
        for (int i = 0; i < MAX_DATABASES; i++) {
            if (pdb_databases[i].fetched_at < oldest) {
                oldest = pdb_databases[i].fetched_at;
                oldest_idx = i;
            }
        }
        db = &pdb_databases[oldest_idx];
    } else {
        db = &pdb_databases[pdb_database_count++];
    }
    
    /* Reset header fields only - track array handled by parse_pdb_file() */
    db->device_ip = device_ip;
    db->slot = slot;
    db->track_count = 0;
    db->fetched_at = 0;
    db->fetch_in_progress = 0;
    db->fetch_failed = 0;
    return db;
}

void remove_pdb_database(uint32_t device_ip, uint8_t slot) {
    for (int i = 0; i < pdb_database_count; i++) {
        if (pdb_databases[i].device_ip == device_ip && 
            pdb_databases[i].slot == slot) {
            int track_count = pdb_databases[i].track_count;
            
            /* Shift remaining databases down */
            for (int j = i; j < pdb_database_count - 1; j++) {
                pdb_databases[j] = pdb_databases[j + 1];
            }
            pdb_database_count--;
            
            log_message("🗑️ Removed database: %s @ %s (%d tracks)", 
                       slot == SLOT_USB ? "USB" : (slot == SLOT_SD ? "SD" : "?"),
                       ip_to_str(device_ip), track_count);
            return;
        }
    }
}

TrackID *lookup_pdb_track(uint32_t rekordbox_id, uint32_t device_ip, uint8_t slot) {
    for (int d = 0; d < pdb_database_count; d++) {
        pdb_database_t *db = &pdb_databases[d];
        if (device_ip != 0 && (db->device_ip != device_ip || db->slot != slot))
            continue;
        for (int t = 0; t < db->track_count; t++) {
            if (db->tracks[t].rekordbox_id == rekordbox_id) {
                if (verbose) {
                    log_message("[PDB] Found track %u: \"%s\" (from %s @ %s)", 
                               rekordbox_id, db->tracks[t].title,
                               db->slot == SLOT_USB ? "USB" : (db->slot == SLOT_SD ? "SD" : "?"),
                               ip_to_str(db->device_ip));
                }
                return &db->tracks[t];
            }
        }
    }
    if (verbose && pdb_database_count > 0) {
        log_message("[PDB] Track %u not found in %d databases", rekordbox_id, pdb_database_count);
    }
    return NULL;
}

/*
 * ============================================================================
 * PDB Parsing - Proper Page-based Navigation
 * ============================================================================
 */

/* Forward declaration */
static int parse_devicesql_string(const uint8_t *data, size_t data_len, size_t offset,
                                   char *out, size_t out_len);

/* Parse DeviceSQL ISRC string (special format with 0x03 prefix)
 * ISRC strings are marked with kind 0x90 but contain ASCII data:
 * [0x90][length_lo][length_hi][pad][0x03][ASCII data...][0x00]
 */
static int parse_isrc_string(const uint8_t *data, size_t data_len, size_t offset,
                              char *out, size_t out_len) {
    if (offset >= data_len || out_len == 0) return -1;
    
    const uint8_t *str_ptr = data + offset;
    uint8_t flags = str_ptr[0];
    
    /* ISRC should be a long string with 0x90 flag */
    if (flags & PDB_STRING_FLAG_SHORT) return -1;
    if (offset + 5 > data_len) return -1;
    
    uint16_t field_len = str_ptr[1] | (str_ptr[2] << 8);
    if (field_len < 6) return -1;  /* Need at least header + 0x03 + 1 char + null */
    
    /* Skip: flags(1) + length(2) + pad(1) + 0x03(1) */
    size_t str_start = offset + 5;
    size_t str_len = field_len - 6;  /* Subtract header and trailing null */
    
    if (str_start + str_len + 1 > data_len) return -1;
    
    /* Check for 0x03 prefix byte */
    if (str_ptr[4] != 0x03) {
        /* Fall back to normal parsing if no 0x03 prefix */
        return parse_devicesql_string(data, data_len, offset, out, out_len);
    }
    
    /* Copy ASCII ISRC (standard format: 12 characters like NLCK42225004) */
    size_t copy_len = (str_len < out_len - 1) ? str_len : out_len - 1;
    memcpy(out, data + str_start, copy_len);
    out[copy_len] = '\0';
    
    return (out[0] != '\0') ? 0 : -1;
}

/* Parse DeviceSQL string at given offset */
static int parse_devicesql_string(const uint8_t *data, size_t data_len, size_t offset, 
                                   char *out, size_t out_len) {
    if (offset >= data_len || out_len == 0) return -1;
    
    const uint8_t *str_ptr = data + offset;
    uint8_t flags = str_ptr[0];
    
    size_t str_len, str_start_offset;
    int is_utf16 = 0;
    
    if (flags & PDB_STRING_FLAG_SHORT) {
        /* Short ASCII: length = flags >> 1 (includes flags byte) */
        str_len = PDB_STRING_SHORT_LEN(flags);
        if (str_len > 1) str_len -= 1;  /* Subtract header byte */
        str_start_offset = offset + 1;
    } else {
        /* Long string: flags byte + 2-byte length + 1-byte pad + data */
        if (offset + 4 > data_len) return -1;
        uint16_t field_len = str_ptr[1] | (str_ptr[2] << 8);
        str_len = (field_len > 4) ? (field_len - 4) : 0;
        str_start_offset = offset + 4;
        
        /* Check for UTF-16LE (flags = 0x90) */
        if (flags == PDB_STRING_UTF16LE) {
            is_utf16 = 1;
        }
    }
    
    if (str_len == 0 || str_start_offset + str_len > data_len) return -1;
    
    /* Decode string using common UTF-8 converters */
    if (is_utf16) {
        /* UTF-16LE to UTF-8 conversion (handles surrogate pairs) */
        utf16le_to_utf8(data + str_start_offset, str_len, out, out_len);
    } else {
        /* Latin-1 to UTF-8 conversion (properly encodes 0x80-0xFF) */
        latin1_to_utf8(data + str_start_offset, str_len, out, out_len);
    }
    return (out[0] != '\0') ? 0 : -1;
}

/* Parse artist from Artists table given artist_id */
static int find_artist_name(const uint8_t *data, size_t len, uint32_t page_size,
                            uint32_t artist_id, char *out, size_t out_len) {
    if (artist_id == 0 || page_size == 0) return -1;
    
    /* Read file header */
    const pdb_file_header_t *header = (const pdb_file_header_t *)data;
    uint32_t num_tables = header->num_tables;
    
    if (num_tables > 20) return -1;
    
    /* Find ARTISTS table (type 2) */
    for (uint32_t t = 0; t < num_tables; t++) {
        size_t ptr_offset = sizeof(pdb_file_header_t) + t * sizeof(pdb_table_pointer_t);
        if (ptr_offset + sizeof(pdb_table_pointer_t) > len) break;
        
        const pdb_table_pointer_t *tbl = (const pdb_table_pointer_t *)(data + ptr_offset);
        if (tbl->type != PDB_TABLE_ARTISTS) continue;
        
        /* Walk pages of Artists table */
        uint32_t page_idx = tbl->first_page;
        while (page_idx != 0 && page_idx != 0x1FFFFFFF) {
            size_t page_offset = (size_t)page_idx * page_size;
            if (page_offset + page_size > len) break;
            
            const pdb_page_header_t *page = (const pdb_page_header_t *)(data + page_offset);
            
            /* Check page flags for data page */
            if (!PDB_PAGE_IS_DATA(page->page_flags)) {
                page_idx = page->next_page;
                continue;
            }
            
            uint16_t num_rows = PDB_NUM_ROWS(page->row_counts);
            uint16_t num_row_offsets = PDB_NUM_ROW_OFFSETS(page->row_counts);

            /* Parse rows using offset table at end of page */
            for (uint16_t ri = 0; ri < num_rows && ri < num_row_offsets; ri++) {
                size_t offset_pos = page_offset + page_size - (ri + 1) * 2;
                if (offset_pos + 2 > len) continue;
                uint16_t row_offset = data[offset_pos] | (data[offset_pos + 1] << 8);

                size_t pos = page_offset + PDB_HEAP_OFFSET + row_offset;
                if (pos + 10 > page_offset + page_size) continue;

                uint16_t subtype = data[pos] | (data[pos+1] << 8);

                if (subtype == PDB_ARTIST_SUBTYPE_NEAR || subtype == PDB_ARTIST_SUBTYPE_FAR) {
                    const pdb_artist_row_header_t *artist = (const pdb_artist_row_header_t *)(data + pos);
                    
                    if (artist->id == artist_id) {
                        /* Found the artist - get name offset */
                        size_t name_offset;
                        if (subtype == PDB_ARTIST_SUBTYPE_NEAR) {
                            /* Near: marker byte + 1-byte offset */
                            uint8_t ofs = data[pos + 9];
                            name_offset = pos + ofs;
                        } else {
                            /* Far: 2-byte marker + 2-byte offset */
                            uint16_t ofs = data[pos + 10] | (data[pos + 11] << 8);
                            name_offset = pos + ofs;
                        }
                        
                        return parse_devicesql_string(data, len, name_offset, out, out_len);
                    }
                    
                }
            }
            page_idx = page->next_page;
        }
        break;
    }
    return -1;
}

int parse_pdb_file(const uint8_t *data, size_t len, pdb_database_t *db) {
    if (!data || !db || len < 4096) return -1;
    
    db->track_count = 0;
    
    /* Parse file header */
    const pdb_file_header_t *header = (const pdb_file_header_t *)data;
    uint32_t page_size = header->page_size;
    uint32_t num_tables = header->num_tables;
    
    if (page_size == 0 || page_size > 65536 || num_tables > 20) {
        log_message("[PDB] Invalid header: page_size=%u num_tables=%u", page_size, num_tables);
        return -1;
    }
    
    if (verbose) {
        log_message("[PDB] File header: page_size=%u num_tables=%u", page_size, num_tables);
    }
    
    /* Find TRACKS table (type 0) */
    uint32_t tracks_first_page = 0;
    
    for (uint32_t t = 0; t < num_tables; t++) {
        size_t ptr_offset = sizeof(pdb_file_header_t) + t * sizeof(pdb_table_pointer_t);
        if (ptr_offset + sizeof(pdb_table_pointer_t) > len) break;
        
        const pdb_table_pointer_t *tbl = (const pdb_table_pointer_t *)(data + ptr_offset);
        
        if (verbose) {
            log_message("[PDB] Table %u: type=%u first_page=%u last_page=%u", 
                       t, tbl->type, tbl->first_page, tbl->last_page);
        }
        
        if (tbl->type == PDB_TABLE_TRACKS) {
            tracks_first_page = tbl->first_page;
            break;
        }
    }
    
    if (tracks_first_page == 0) {
        log_message("[PDB] No TRACKS table found");
        return -1;
    }
    
    /* Walk pages of TRACKS table */
    uint32_t page_idx = tracks_first_page;
    int pages_walked = 0;
    
    while (page_idx != 0 && page_idx != 0x1FFFFFFF && pages_walked < 1000) {
        size_t page_offset = (size_t)page_idx * page_size;
        if (page_offset + page_size > len) {
            if (verbose) log_message("[PDB] Page %u out of bounds", page_idx);
            break;
        }
        
        const pdb_page_header_t *page = (const pdb_page_header_t *)(data + page_offset);
        pages_walked++;
        
        /* Skip strange pages (only parse data pages) */
        if (!PDB_PAGE_IS_DATA(page->page_flags)) {
            if (verbose) log_message("[PDB] Page %u: skipping (flags 0x%02x)", page_idx, page->page_flags);
            page_idx = page->next_page;
            continue;
        }
        
        uint16_t num_rows = PDB_NUM_ROWS(page->row_counts);
        
        if (verbose) {
            log_message("[PDB] Page %u: flags=0x%02x rows=%u", page_idx, page->page_flags, num_rows);
        }
        
        /* Parse rows using the row offset table at end of page.
         * Row offsets are 16-bit values stored backwards from the end of the page.
         * Each offset points to the start of a row within the heap. */
        uint16_t num_row_offsets = PDB_NUM_ROW_OFFSETS(page->row_counts);

        for (uint16_t ri = 0; ri < num_rows && ri < num_row_offsets; ri++) {
            /* Row offset table: 16-bit entries at end of page, growing backwards.
             * First entry at page_end - 2, second at page_end - 4, etc. */
            size_t offset_pos = page_offset + page_size - (ri + 1) * 2;
            if (offset_pos + 2 > len || offset_pos < page_offset + PDB_HEAP_OFFSET)
                continue;
            uint16_t row_offset = data[offset_pos] | (data[offset_pos + 1] << 8);

            size_t pos = page_offset + PDB_HEAP_OFFSET + row_offset;
            if (pos + sizeof(pdb_track_row_t) > page_offset + page_size)
                continue;

            const pdb_track_row_t *row = (const pdb_track_row_t *)(data + pos);

            /* Verify this is a track row */
            if (row->subtype != PDB_TRACK_SUBTYPE)
                continue;

            /* Sanity check: track ID should be reasonable */
            if (row->id == 0 || row->id > 999999)
                continue;
            
            /* Check for duplicate */
            int duplicate = 0;
            for (int t = 0; t < db->track_count; t++) {
                if (db->tracks[t].rekordbox_id == row->id) {
                    duplicate = 1;
                    break;
                }
            }
            
            if (duplicate) {
                pos += sizeof(pdb_track_row_t);
                continue;
            }
            
            if (db->track_count >= MAX_PDB_TRACKS) {
                log_message("[PDB] Warning: reached max tracks (%d), some tracks may be missing", MAX_PDB_TRACKS);
                break;
            }
            
            /* Add track */
            TrackID *track = &db->tracks[db->track_count];
            memset(track, 0, sizeof(*track));
            track->rekordbox_id = row->id;
            track->bpm = row->tempo / 100;
            track->duration_ms = (uint32_t)row->duration * 1000;
            track->sources = TRACK_SRC_CDJ;
            track->confidence = 70;
            
            /* Read title from string_offsets[PDB_STR_TITLE] (index 17) */
            uint16_t title_offset = row->string_offsets[PDB_STR_TITLE];
            if (title_offset > 0 && title_offset < 500) {
                parse_devicesql_string(data, len, pos + title_offset, 
                                       track->title, sizeof(track->title));
            }
            
            /* Look up artist name from Artists table */
            if (row->artist_id != 0) {
                find_artist_name(data, len, page_size, row->artist_id, 
                                track->artist, sizeof(track->artist));
            }
            
            /* Read ISRC from string_offsets[PDB_STR_ISRC] (index 0) */
            uint16_t isrc_offset = row->string_offsets[PDB_STR_ISRC];
            if (isrc_offset > 0 && isrc_offset < 500) {
                parse_isrc_string(data, len, pos + isrc_offset, 
                                 track->isrc, sizeof(track->isrc));
                track->has_isrc = (track->isrc[0] != '\0');
            }
            
            if (track->title[0] == '\0') {
                snprintf(track->title, sizeof(track->title), "Track %u", row->id);
            }
            
            track->valid = (track->title[0] != '\0' || track->artist[0] != '\0');
            
            log_message("[PDB] Parsed track ID=%u: \"%s\" by \"%s\" (%d BPM)%s%s", 
                       track->rekordbox_id, track->title, 
                       track->artist[0] ? track->artist : "(unknown)", track->bpm,
                       track->has_isrc ? " ISRC=" : "", track->has_isrc ? track->isrc : "");
            
            db->track_count++;
        }
        
        page_idx = page->next_page;
    }
    
    if (verbose) {
        log_message("[PDB] Walked %d pages, found %d tracks", pages_walked, db->track_count);
    }
    
    return db->track_count > 0 ? 0 : -1;
}

/*
 * ============================================================================
 * Database Fetching
 * ============================================================================
 */

/* Internal helper for NFS lookup with just dir_fh and output fh */
uint16_t g_nfs_port = 2049;  /* Cached NFS port from portmapper (shared with onelibrary.c) */

static int nfs_lookup_simple(uint32_t server_ip, const uint8_t *dir_fh, 
                             const char *name, uint8_t *file_fh) {
    return nfs_lookup(server_ip, g_nfs_port, dir_fh, name, file_fh);
}

int fetch_rekordbox_database(uint32_t device_ip, uint8_t slot, pdb_database_t *db) {
    uint8_t root_fh[64], pioneer_fh[64], rb_fh[64], pdb_fh[64];
    size_t root_fh_len;
    
    if (!db) return -1;
    
    /* Determine export path based on slot */
    const char *export_path;
    switch (slot) {
        case 2: export_path = "/B/"; break;  /* SD card */
        case 3: export_path = "/C/"; break;  /* USB */
        default:
            log_message("❌ Unknown slot type %d", slot);
            db->fetch_in_progress = 0;
            db->fetch_failed = 1;
            return -1;
    }
    
    log_message("📥 Fetching database from %s (slot %s, export %s)...", 
                ip_to_str(device_ip), cdj_slot_name(slot), export_path);
    
    db->fetch_in_progress = 1;
    
    /* Step 1: Query portmapper for mount port */
    log_message("🔍 Querying portmapper on %s:111...", ip_to_str(device_ip));
    int mount_port = rpc_portmap_getport(device_ip, MOUNT_PROGRAM, MOUNT_VERSION);
    
    if (mount_port <= 0) {
        log_message("❌ Portmapper query failed - no mount service");
        db->fetch_in_progress = 0;
        db->fetch_failed = 1;
        return -1;
    }
    
    /* Query portmapper for NFS port (CDJs often use non-standard ports) */
    int nfs_port = rpc_portmap_getport(device_ip, NFS_PROGRAM, NFS_VERSION);
    if (nfs_port <= 0) {
        log_message("⚠️ NFS port query failed, using default 2049");
        nfs_port = 2049;
    } else {
        log_message("✅ NFS port: %d", nfs_port);
    }
    g_nfs_port = (uint16_t)nfs_port;
    log_message("✅ Mount port: %d", mount_port);
    
    /* Step 2: Mount the export */
    if (nfs_mount_to_port(device_ip, (uint16_t)mount_port, export_path, 
                          root_fh, &root_fh_len) != 0) {
        log_message("❌ Mount failed - USB may not have rekordbox export");
        db->fetch_in_progress = 0;
        db->fetch_failed = 1;
        return -1;
    }
    
    log_message("✅ Mounted %s", export_path);
    
    /* Step 3: Lookup PIONEER directory */
    if (nfs_lookup_simple(device_ip, root_fh, "PIONEER", pioneer_fh) != 0) {
        log_message("❌ PIONEER not found");
        db->fetch_in_progress = 0;
        db->fetch_failed = 1;
        return -1;
    }
    
    /* Step 4: Lookup rekordbox directory */
    if (nfs_lookup_simple(device_ip, pioneer_fh, "rekordbox", rb_fh) != 0) {
        log_message("❌ rekordbox dir not found");
        db->fetch_in_progress = 0;
        db->fetch_failed = 1;
        return -1;
    }
    
    /* Step 5: Lookup export.pdb */
    if (nfs_lookup_simple(device_ip, rb_fh, "export.pdb", pdb_fh) != 0) {
        log_message("❌ export.pdb not found");
        db->fetch_in_progress = 0;
        db->fetch_failed = 1;
        return -1;
    }
    
    /* Step 6: Read the file (up to 8MB) */
    #define MAX_PDB_SIZE (8 * 1024 * 1024)
    uint8_t *pdb_data = malloc(MAX_PDB_SIZE);
    if (!pdb_data) {
        db->fetch_in_progress = 0;
        db->fetch_failed = 1;
        return -1;
    }
    
    log_message("📖 Reading export.pdb...");
    
    size_t total_read = 0;
    if (nfs_read_file(device_ip, g_nfs_port, pdb_fh, pdb_data, MAX_PDB_SIZE, &total_read) != 0) {
        log_message("❌ Read error");
        nfs_close_socket();
        free(pdb_data);
        db->fetch_in_progress = 0;
        db->fetch_failed = 1;
        return -1;
    }
    
    log_message("📄 Downloaded %zu bytes", total_read);
    
    /* Close NFS socket after download */
    nfs_close_socket();
    
    /* Parse the PDB */
    if (parse_pdb_file(pdb_data, total_read, db) != 0) {
        logmsg("cdj", "⚠️ PDB parse found no tracks");
    } else {
        logmsg("cdj", "✅ Loaded %d tracks from database", db->track_count);
    }
    
    free(pdb_data);
    db->fetch_in_progress = 0;
    db->fetched_at = time(NULL);
    
    return 0;
}

/*
 * Parse a PDB buffer captured passively from NFS traffic.
 * Used when we observe another device fetching the database.
 */
void parse_pdb_buffer(const uint8_t *data, size_t len, uint32_t device_ip) {
    /* Use slot 0xFF to indicate passively captured database */
    pdb_database_t *db = find_pdb_database(device_ip, 0xFF);
    if (!db) {
        db = create_pdb_database(device_ip, 0xFF);
    }
    
    if (parse_pdb_file(data, len, db) != 0) {
        log_message("[NFS-SNIFF] Passive PDB parse found no tracks");
    } else {
        log_message("[NFS-SNIFF] ✅ Passively captured %d tracks from %s",
                   db->track_count, ip_to_str(device_ip));
    }
    
    db->fetched_at = time(NULL);
}
