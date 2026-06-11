/*
 * pdb.c - Rekordbox PDB database: fetch over NFS + parse pages.
 * Reference: https://djl-analysis.deepsymmetry.org/rekordbox-export-analysis/exports.html
 */

#include "pdb.h"
#include "pdb_protocol.h"
#include "nfs_client.h"
#include "cdj_types.h"
#include "../common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>

extern int verbose;

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
            
            uint16_t num_row_offsets = PDB_NUM_ROW_OFFSETS(page->row_counts);

            for (uint16_t ri = 0; ri < num_row_offsets; ri++) {
                size_t pos = pdb_row_offset(data, len, page_offset, page_size, ri);
                if (!pos || pos + 10 > page_offset + page_size) continue;

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
    if (!data || !db || len < 4096) {
        logmsg("pdb", "parse_pdb_file: invalid args (data=%p db=%p len=%zu)",
               (void *)data, (void *)db, len);
        return -1;
    }

    db->track_count = 0;

    /* Parse file header */
    const pdb_file_header_t *header = (const pdb_file_header_t *)data;
    uint32_t page_size = header->page_size;
    uint32_t num_tables = header->num_tables;

    if (page_size == 0 || page_size > 65536 || num_tables > 20) {
        logmsg("pdb", "Invalid header: page_size=%u num_tables=%u (file_size=%zu, first 16 bytes: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x)",
               page_size, num_tables, len,
               data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
               data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15]);
        return -1;
    }
    
    if (verbose) {
        vlogmsg("pdb", "File header: page_size=%u num_tables=%u", page_size, num_tables);
    }
    
    /* Find TRACKS table (type 0) */
    uint32_t tracks_first_page = 0;
    
    for (uint32_t t = 0; t < num_tables; t++) {
        size_t ptr_offset = sizeof(pdb_file_header_t) + t * sizeof(pdb_table_pointer_t);
        if (ptr_offset + sizeof(pdb_table_pointer_t) > len) break;
        
        const pdb_table_pointer_t *tbl = (const pdb_table_pointer_t *)(data + ptr_offset);
        
        if (verbose) {
            vlogmsg("pdb", "Table %u: type=%u first_page=%u last_page=%u", 
                       t, tbl->type, tbl->first_page, tbl->last_page);
        }
        
        if (tbl->type == PDB_TABLE_TRACKS) {
            tracks_first_page = tbl->first_page;
            break;
        }
    }
    
    if (tracks_first_page == 0) {
        vlogmsg("pdb", "No TRACKS table found");
        return -1;
    }
    
    /* Walk pages of TRACKS table */
    uint32_t page_idx = tracks_first_page;
    int pages_walked = 0;
    
    while (page_idx != 0 && page_idx != 0x1FFFFFFF && pages_walked < 1000) {
        size_t page_offset = (size_t)page_idx * page_size;
        if (page_offset + page_size > len) {
            if (verbose) vlogmsg("pdb", "Page %u out of bounds", page_idx);
            break;
        }
        
        const pdb_page_header_t *page = (const pdb_page_header_t *)(data + page_offset);
        pages_walked++;
        
        /* Skip strange pages (only parse data pages) */
        if (!PDB_PAGE_IS_DATA(page->page_flags)) {
            if (verbose) vlogmsg("pdb", "Page %u: skipping (flags 0x%02x)", page_idx, page->page_flags);
            page_idx = page->next_page;
            continue;
        }
        
        uint16_t num_row_offsets = PDB_NUM_ROW_OFFSETS(page->row_counts);

        if (verbose) {
            vlogmsg("pdb", "Page %u: flags=0x%02x offsets=%u", page_idx, page->page_flags, num_row_offsets);
        }

        for (uint16_t ri = 0; ri < num_row_offsets; ri++) {
            size_t pos = pdb_row_offset(data, len, page_offset, page_size, ri);
            if (!pos) {
                if (verbose)
                    vlogmsg("pdb", "Page %u row %d: offset returned 0 (empty/deleted slot)", page_idx, ri);
                continue;
            }
            if (pos + sizeof(pdb_track_row_t) > page_offset + page_size) {
                if (verbose)
                    vlogmsg("pdb", "Page %u row %d: row extends past page (pos=%zu, need %zu, page_end=%zu)",
                           page_idx, ri, pos, pos + sizeof(pdb_track_row_t), page_offset + page_size);
                continue;
            }

            const pdb_track_row_t *row = (const pdb_track_row_t *)(data + pos);

            if (row->subtype != PDB_TRACK_SUBTYPE) {
                if (verbose)
                    vlogmsg("pdb", "Page %u row %d: subtype=0x%04x (expected 0x%04x), raw id=%u, pos=%zu",
                           page_idx, ri, row->subtype, PDB_TRACK_SUBTYPE, row->id, pos - page_offset);
                continue;
            }

            if (row->id == 0 || row->id > 999999) {
                if (verbose)
                    vlogmsg("pdb", "Page %u row %d: bad track id=%u (out of range)", page_idx, ri, row->id);
                continue;
            }

            /* Check for duplicate */
            int duplicate = 0;
            for (int t = 0; t < db->track_count; t++) {
                if (db->tracks[t].rekordbox_id == row->id) {
                    duplicate = 1;
                    break;
                }
            }

            if (duplicate) {
                if (verbose)
                    vlogmsg("pdb", "Page %u row %d: duplicate track id=%u, skipping", page_idx, ri, row->id);
                continue;
            }

            if (db->track_count >= MAX_PDB_TRACKS) {
                vlogmsg("pdb", "Warning: reached max tracks (%d), some tracks may be missing", MAX_PDB_TRACKS);
                break;
            }
            
            /* Add track */
            TrackID *track = &db->tracks[db->track_count];
            memset(track, 0, sizeof(*track));
            track->rekordbox_id = row->id;
            track->bpm = row->tempo / 100;
            track->duration_ms = (uint32_t)row->duration * 1000;
            track->bitrate = row->bitrate;
            track->sample_rate = row->sample_rate;
            track->sample_depth = (uint8_t)row->sample_depth;
            track->file_type = (uint8_t)row->file_type;
            track->sources = TRACK_SRC_CDJ;
            track->confidence = 70;
            
            /* Read title from string_offsets[PDB_STR_TITLE] (index 17) */
            uint16_t title_offset = row->string_offsets[PDB_STR_TITLE];
            if (title_offset > 0 && title_offset < 500) {
                parse_devicesql_string(data, len, pos + title_offset,
                                       track->title, sizeof(track->title));
            } else if (verbose) {
                vlogmsg("pdb", "Track %u: title_offset=%u out of range", row->id, title_offset);
            }

            /* Look up artist name from Artists table */
            if (row->artist_id != 0) {
                int art_rc = find_artist_name(data, len, page_size, row->artist_id,
                                track->artist, sizeof(track->artist));
                if (art_rc < 0 && verbose)
                    vlogmsg("pdb", "Track %u: artist_id=%u not found in Artists table", row->id, row->artist_id);
            }

            /* Read ISRC from string_offsets[PDB_STR_ISRC] (index 0) */
            uint16_t isrc_offset = row->string_offsets[PDB_STR_ISRC];
            if (isrc_offset > 0 && isrc_offset < 500) {
                parse_isrc_string(data, len, pos + isrc_offset,
                                 track->isrc, sizeof(track->isrc));
                track->has_isrc = (track->isrc[0] != '\0');
            }

            /* Read ANLZ path from string_offsets[PDB_STR_ANALYZE_PATH] (index 14) */
            uint16_t anlz_offset = row->string_offsets[PDB_STR_ANALYZE_PATH];
            if (anlz_offset > 0 && anlz_offset < 500) {
                parse_devicesql_string(data, len, pos + anlz_offset,
                                       track->anlz_path, sizeof(track->anlz_path));
            }

            if (track->title[0] == '\0') {
                snprintf(track->title, sizeof(track->title), "Track %u", row->id);
            }
            
            track->valid = (track->title[0] != '\0' || track->artist[0] != '\0');
            
            vlogmsg("pdb", "Parsed track ID=%u: \"%s\" by \"%s\" (%d BPM)%s%s", 
                       track->rekordbox_id, track->title, 
                       track->artist[0] ? track->artist : "(unknown)", track->bpm,
                       track->has_isrc ? " ISRC=" : "", track->has_isrc ? track->isrc : "");
            
            db->track_count++;
        }
        
        if (verbose)
            vlogmsg("pdb", "Page %u: parsed %d tracks (next_page=%u)", page_idx, db->track_count, page->next_page);
        page_idx = page->next_page;
    }

    vlogmsg("pdb", "Walked %d pages, found %d tracks", pages_walked, db->track_count);
    
    return db->track_count > 0 ? 0 : -1;
}

/*
 * ============================================================================
 * Database Fetching
 * ============================================================================
 */

int fetch_rekordbox_database(uint32_t device_ip, uint8_t slot,
                             uint16_t nfs_port, uint16_t mount_port,
                             pdb_database_t *db) {
    uint8_t root_fh[64], pioneer_fh[64], rb_fh[64], pdb_fh[64];
    size_t root_fh_len;

    if (!db) return -1;
    if (nfs_port == 0 || mount_port == 0) {
        logmsg("pdb", "❌ fetch_rekordbox_database: missing ports for %s slot %s (nfs=%u mount=%u) — announce portmap discovery did not complete",
               ip_to_str(device_ip), cdj_slot_name(slot), nfs_port, mount_port);
        db->fetch_failed = 1;
        return -1;
    }

    /* Determine export path based on slot */
    const char *export_path;
    switch (slot) {
        case 2: export_path = "/B/"; break;  /* SD card */
        case 3: export_path = "/C/"; break;  /* USB */
        default:
            vlogmsg("pdb", "❌ Unknown slot type %d", slot);
            db->fetch_in_progress = 0;
            db->fetch_failed = 1;
            return -1;
    }

    vlogmsg("pdb", "📥 Fetching database from %s (slot %s, export %s, nfs=%u mount=%u)...",
                ip_to_str(device_ip), cdj_slot_name(slot), export_path,
                nfs_port, mount_port);

    db->fetch_in_progress = 1;

    /* Step 2: Mount the export */
    int mrc = nfs_mount_to_port(device_ip, mount_port, export_path,
                                root_fh, &root_fh_len);
    if (mrc != 0) {
        logmsg("pdb", "❌ Mount failed for %s on slot %s%s",
               export_path, cdj_slot_name(slot),
               mrc == -ENOENT ? " (export NOENT — slot has no rekordbox media)" : "");
        db->fetch_in_progress = 0;
        db->fetch_failed = 1;
        return mrc == -ENOENT ? -ENOENT : -1;
    }

    vlogmsg("pdb", "✅ Mounted %s", export_path);

    /* Step 3: Lookup PIONEER directory */
    int lrc = nfs_lookup(device_ip, nfs_port, root_fh, "PIONEER", pioneer_fh, NULL);
    if (lrc != 0) {
        logmsg("pdb", "❌ PIONEER not found on %s slot %s%s",
               ip_to_str(device_ip), cdj_slot_name(slot),
               lrc == -ENOENT ? " (NOENT — non-rekordbox media)" : "");
        db->fetch_in_progress = 0;
        db->fetch_failed = 1;
        return lrc == -ENOENT ? -ENOENT : -1;
    }

    /* Step 4: Lookup rekordbox directory */
    lrc = nfs_lookup(device_ip, nfs_port, pioneer_fh, "rekordbox", rb_fh, NULL);
    if (lrc != 0) {
        logmsg("pdb", "❌ rekordbox dir not found on %s slot %s%s",
               ip_to_str(device_ip), cdj_slot_name(slot),
               lrc == -ENOENT ? " (NOENT — no rekordbox export on this stick)" : "");
        db->fetch_in_progress = 0;
        db->fetch_failed = 1;
        return lrc == -ENOENT ? -ENOENT : -1;
    }

    /* Step 5: Lookup export.pdb */
    uint32_t pdb_size = 0;
    lrc = nfs_lookup(device_ip, nfs_port, rb_fh, "export.pdb", pdb_fh, &pdb_size);
    if (lrc != 0) {
        logmsg("pdb", "❌ export.pdb not found on %s slot %s%s",
               ip_to_str(device_ip), cdj_slot_name(slot),
               lrc == -ENOENT ? " (NOENT — rekordbox dir exists but no export.pdb)" : "");
        db->fetch_in_progress = 0;
        db->fetch_failed = 1;
        return lrc == -ENOENT ? -ENOENT : -1;
    }

    /* Step 6: Size the buffer to the real file length (clamped to the fetch
     * cap as the OOM guard); fall back to the cap if LOOKUP gave no size. */
    size_t alloc = (pdb_size > 0 && pdb_size <= NFS_MAX_FETCH_SIZE)
                       ? pdb_size : NFS_MAX_FETCH_SIZE;
    if (pdb_size > NFS_MAX_FETCH_SIZE) {
        logmsg("pdb", "⚠️ export.pdb is %u bytes, exceeds %u-byte cap — fetch will be partial",
               pdb_size, NFS_MAX_FETCH_SIZE);
    }
    uint8_t *pdb_data = malloc(alloc);
    if (!pdb_data) {
        logmsg("pdb", "❌ malloc(%zu) failed for PDB buffer", alloc);
        db->fetch_in_progress = 0;
        db->fetch_failed = 1;
        return -1;
    }

    vlogmsg("pdb", "📖 Reading export.pdb (%u bytes)...", pdb_size);

    size_t total_read = 0;
    int rrc = nfs_read_file(device_ip, nfs_port, pdb_fh, "export.pdb", pdb_data, alloc, &total_read);
    if (rrc != 0) {
        logmsg("pdb", "❌ Read error fetching export.pdb from %s slot %s (rc=%d)",
               ip_to_str(device_ip), cdj_slot_name(slot), rrc);
        nfs_close_socket();
        free(pdb_data);
        db->fetch_in_progress = 0;
        db->fetch_failed = 1;
        return rrc == -ENOENT ? -ENOENT : -1;
    }
    
    vlogmsg("pdb", "📄 Downloaded %zu bytes", total_read);
    
    /* Close NFS socket after download */
    nfs_close_socket();
    
    /* Parse the PDB */
    if (parse_pdb_file(pdb_data, total_read, db) != 0) {
        logmsg("pdb", "📚 PDB loaded: 0 tracks from %s @ %s (parse found no tracks)",
               cdj_slot_name(slot), ip_to_str(device_ip));
    } else {
        logmsg("pdb", "📚 PDB loaded: %d tracks from %s @ %s",
               db->track_count, cdj_slot_name(slot), ip_to_str(device_ip));
    }
    
    free(pdb_data);
    db->fetch_in_progress = 0;
    db->fetched_at = time(NULL);
    
    return 0;
}

/*
 * Passive PDB ingestion from sniffed NFS traffic.
 *
 * Disabled — pdb_thread workers own the parsed database per (source_player,
 * slot) and there is no API for ingesting pre-fetched bytes. The active fetch
 * path covers our needs; passive sniff was an opportunistic shortcut.
 */
void parse_pdb_buffer(const uint8_t *data, size_t len, uint32_t device_ip) {
    (void)data; (void)len;
    vlogmsg("pdb", "[NFS-SNIFF] Passive PDB capture from %s — ignored (disabled)",
            ip_to_str(device_ip));
}
