/*
 * pdb_protocol.h - Rekordbox PDB Database File Format Structures
 *
 * Reference: https://djl-analysis.deepsymmetry.org/rekordbox-export-analysis/exports.html
 *
 * PDB files are found at: /PIONEER/rekordbox/export.pdb
 * All multi-byte values are little-endian.
 */

#ifndef PDB_PROTOCOL_H
#define PDB_PROTOCOL_H

#include <stddef.h>
#include <stdint.h>

/*
 * ============================================================================
 * PDB File Header (starts at byte 0, first page)
 * ============================================================================
 * Reference: File Header section
 *
 * Verified offsets:
 *   [0x00-0x03] zeros (always 0)
 *   [0x04-0x07] len_page - Page size in bytes (usually 4096)
 *   [0x08-0x0b] num_tables - Number of tables in file
 *   [0x0c-0x0f] next_unused_page
 *   [0x10-0x13] unknown
 *   [0x14-0x17] sequence_db - Incremented on each edit
 *   [0x18-0x1b] unknown (often zero)
 *   [0x1c+]     Table pointers array
 */
typedef struct __attribute__((packed)) {
    uint32_t zeros;             /* 0x00-0x03: Always 0 */
    uint32_t page_size;         /* 0x04-0x07: Size of each page (usually 4096) */
    uint32_t num_tables;        /* 0x08-0x0b: Number of tables */
    uint32_t next_unused_page;  /* 0x0c-0x0f: Points past end of file */
    uint32_t unknown1;          /* 0x10-0x13: Unknown */
    uint32_t sequence_db;       /* 0x14-0x17: Sequence number, incremented on edit */
    uint32_t unknown2;          /* 0x18-0x1b: Unknown (often zero) */
    /* Table pointers follow at 0x1c */
} pdb_file_header_t;

_Static_assert(sizeof(pdb_file_header_t) == 28, "pdb_file_header_t must be 28 bytes");

/*
 * ============================================================================
 * Table Pointer (16 bytes each, starting at offset 0x1c in header)
 * ============================================================================
 * Reference: Table Pointer structure
 */
typedef struct __attribute__((packed)) {
    uint32_t type;              /* 0x00-0x03: Table type (see PDB_TABLE_* below) */
    uint32_t empty_candidate;   /* 0x04-0x07: May link to empty pages chain */
    uint32_t first_page;        /* 0x08-0x0b: Index of first page of this table */
    uint32_t last_page;         /* 0x0c-0x0f: Index of last page of this table */
} pdb_table_pointer_t;

_Static_assert(sizeof(pdb_table_pointer_t) == 16, "pdb_table_pointer_t must be 16 bytes");

/* Table type values */
typedef enum {
    PDB_TABLE_TRACKS            = 0x00,
    PDB_TABLE_GENRES            = 0x01,
    PDB_TABLE_ARTISTS           = 0x02,
    PDB_TABLE_ALBUMS            = 0x03,
    PDB_TABLE_LABELS            = 0x04,
    PDB_TABLE_KEYS              = 0x05,
    PDB_TABLE_COLORS            = 0x06,
    PDB_TABLE_PLAYLIST_TREE     = 0x07,
    PDB_TABLE_PLAYLIST_ENTRIES  = 0x08,
    PDB_TABLE_ARTWORK           = 0x0d,
    PDB_TABLE_COLUMNS           = 0x10,
    PDB_TABLE_HISTORY_PLAYLISTS = 0x11,
    PDB_TABLE_HISTORY_ENTRIES   = 0x12,
    PDB_TABLE_HISTORY           = 0x13
} pdb_table_type_t;

/*
 * ============================================================================
 * Table Page Header (40 bytes at start of each page)
 * ============================================================================
 * Reference: Table Pages section
 *
 * Verified offsets:
 *   [0x00-0x03] zeros (always 0)
 *   [0x04-0x07] page_index - Index of this page
 *   [0x08-0x0b] type - Table type
 *   [0x0c-0x0f] next_page - Index of next page in table
 *   [0x10-0x13] sequence_page
 *   [0x14-0x17] unknown2
 *   [0x18-0x1a] row_counts (packed: 13 bits num_row_offsets, 11 bits num_rows)
 *   [0x1b]      page_flags
 *   [0x1c-0x1d] free_size
 *   [0x1e-0x1f] used_size
 *   [0x20-0x21] transaction_row_count
 *   [0x22-0x23] transaction_row_index
 *   [0x24-0x25] u6
 *   [0x26-0x27] u7
 *   [0x28+]     heap (row data)
 */
typedef struct __attribute__((packed)) {
    uint32_t zeros;             /* 0x00-0x03: Always 0 */
    uint32_t page_index;        /* 0x04-0x07: Index of this page */
    uint32_t type;              /* 0x08-0x0b: Table type */
    uint32_t next_page;         /* 0x0c-0x0f: Next page index in table */
    uint32_t sequence_page;     /* 0x10-0x13: Sequence number for this page */
    uint32_t unknown2;          /* 0x14-0x17: Unknown (often zero) */
    uint8_t  row_counts[3];     /* 0x18-0x1a: Packed row counts */
    uint8_t  page_flags;        /* 0x1b: Page flags (0x24/0x34 = data, 0x44/0x64 = strange) */
    uint16_t free_size;         /* 0x1c-0x1d: Free space in heap */
    uint16_t used_size;         /* 0x1e-0x1f: Used space in heap */
    uint16_t transaction_row_count; /* 0x20-0x21: Rows touched in last transaction */
    uint16_t transaction_row_index; /* 0x22-0x23: First row touched in last transaction */
    uint16_t u6;                /* 0x24-0x25: 0x1004 for strange, 0x0000 for data */
    uint16_t u7;                /* 0x26-0x27: Usually 0 */
    /* Heap starts at 0x28 */
} pdb_page_header_t;

_Static_assert(sizeof(pdb_page_header_t) == 40, "pdb_page_header_t must be 40 bytes");

/* Page flags - data pages have bit 6 clear */
#define PDB_PAGE_FLAG_STRANGE   0x40
#define PDB_PAGE_IS_DATA(flags) (((flags) & PDB_PAGE_FLAG_STRANGE) == 0)

/* Extract row counts from packed 3-byte field:
 * num_row_offsets: bits 0-12 (first 13 bits)
 * num_rows: bits 13-23 (last 11 bits) */
#define PDB_NUM_ROW_OFFSETS(rc) (((rc)[0] | ((rc)[1] << 8)) & 0x1FFF)
#define PDB_NUM_ROWS(rc) ((((rc)[1] >> 5) | ((rc)[2] << 3)) & 0x7FF)

/*
 * ============================================================================
 * Row Offset Table (at end of each data page, grows backwards)
 * ============================================================================
 * Reference: Row Offsets section
 *
 * 16-bit offsets relative to the heap start (page + PDB_HEAP_OFFSET).
 * Entry 0 is at page_end - 2, entry 1 at page_end - 4, etc.
 * Use pdb_row_offset() to get the absolute file offset for a row.
 */
#ifndef PDB_HEAP_OFFSET
#define PDB_HEAP_OFFSET 0x28
#endif

/*
 * Row offset table: rows are in groups of 16, each group has a 4-byte
 * header (2B transaction flags + 2B row-present flags) then 16 offsets.
 * Groups grow backward from page end, stride = 4 + 16*2 = 36 (0x24).
 */
static inline size_t pdb_row_offset(const uint8_t *file, size_t file_len,
                                     size_t page_offset, uint32_t page_size,
                                     uint16_t row_index) {
    uint16_t group = row_index / 16;
    uint16_t row_in_group = row_index % 16;
    /* Each group: [ofs15..ofs0][rowpf][tranrf] packed backward from page end */
    size_t group_end = page_offset + page_size - group * 0x24;
    size_t entry = group_end - 6 - row_in_group * 2;  /* skip 4B header + first entry at -6 */
    if (entry + 2 > file_len || entry < page_offset + PDB_HEAP_OFFSET)
        return 0;
    uint16_t off = file[entry] | (file[entry + 1] << 8);
    size_t abs = page_offset + PDB_HEAP_OFFSET + off;
    return (abs + 4 <= page_offset + page_size) ? abs : 0;
}

/*
 * ============================================================================
 * Track Row (132 bytes + string offsets, subtype 0x0024)
 * ============================================================================
 * Reference: Track Rows section
 *
 * Track rows describe audio tracks and provide links to artists, albums, etc.
 * All string offsets are relative to the start of the row.
 *
 * Verified offsets:
 *   [0x00-0x01] subtype (0x0024)
 *   [0x02-0x03] index_shift
 *   [0x04-0x07] bitmask
 *   [0x08-0x0b] sample_rate
 *   [0x0c-0x0f] composer_id (Artist table ID)
 *   [0x10-0x13] file_size (bytes)
 *   [0x14-0x17] unknown2
 *   [0x18-0x19] u3 (always 19048?)
 *   [0x1a-0x1b] u4 (always 30967?)
 *   [0x1c-0x1f] artwork_id (Artwork table ID)
 *   [0x20-0x23] key_id (Key table ID)
 *   [0x24-0x27] original_artist_id
 *   [0x28-0x2b] label_id
 *   [0x2c-0x2f] remixer_id
 *   [0x30-0x33] bitrate
 *   [0x34-0x37] track_number (position in album)
 *   [0x38-0x3b] tempo (BPM * 100)
 *   [0x3c-0x3f] genre_id
 *   [0x40-0x43] album_id
 *   [0x44-0x47] artist_id
 *   [0x48-0x4b] id (rekordbox track ID)
 *   [0x4c-0x4d] disc_number
 *   [0x4e-0x4f] play_count
 *   [0x50-0x51] year
 *   [0x52-0x53] sample_depth (bits per sample)
 *   [0x54-0x55] duration (seconds)
 *   [0x56-0x57] u5 (always 0x0029)
 *   [0x58]      color_id
 *   [0x59]      rating (0-5 stars)
 *   [0x5a-0x5b] file_type
 *   [0x5c-0x5d] u7 (always 0x0003)
 *   [0x5e-0x83] string_offsets[19] (16-bit offsets, indices 0-18)
 */
typedef struct __attribute__((packed)) {
    uint16_t subtype;           /* 0x00-0x01: Always 0x0024 */
    uint16_t index_shift;       /* 0x02-0x03: Unknown purpose */
    uint32_t bitmask;           /* 0x04-0x07: Unknown flags */
    uint32_t sample_rate;       /* 0x08-0x0b: Sample rate in Hz */
    uint32_t composer_id;       /* 0x0c-0x0f: Composer (Artist table ID) */
    uint32_t file_size;         /* 0x10-0x13: File size in bytes */
    uint32_t unknown2;          /* 0x14-0x17: Unknown */
    uint16_t u3;                /* 0x18-0x19: Usually 19048 */
    uint16_t u4;                /* 0x1a-0x1b: Usually 30967 */
    uint32_t artwork_id;        /* 0x1c-0x1f: Artwork table ID */
    uint32_t key_id;            /* 0x20-0x23: Key table ID */
    uint32_t original_artist_id;/* 0x24-0x27: Original artist (remakes) */
    uint32_t label_id;          /* 0x28-0x2b: Label table ID */
    uint32_t remixer_id;        /* 0x2c-0x2f: Remixer (Artist table ID) */
    uint32_t bitrate;           /* 0x30-0x33: Bitrate in kbps */
    uint32_t track_number;      /* 0x34-0x37: Track number in album */
    uint32_t tempo;             /* 0x38-0x3b: BPM * 100 */
    uint32_t genre_id;          /* 0x3c-0x3f: Genre table ID */
    uint32_t album_id;          /* 0x40-0x43: Album table ID */
    uint32_t artist_id;         /* 0x44-0x47: Artist table ID */
    uint32_t id;                /* 0x48-0x4b: Rekordbox track ID */
    uint16_t disc_number;       /* 0x4c-0x4d: Disc number */
    uint16_t play_count;        /* 0x4e-0x4f: Play count */
    uint16_t year;              /* 0x50-0x51: Year recorded */
    uint16_t sample_depth;      /* 0x52-0x53: Bits per sample */
    uint16_t duration;          /* 0x54-0x55: Duration in seconds */
    uint16_t u5;                /* 0x56-0x57: Usually 0x0029 */
    uint8_t  color_id;          /* 0x58: Color label ID */
    uint8_t  rating;            /* 0x59: Rating 0-5 */
    uint16_t file_type;         /* 0x5a-0x5b: Audio format */
    uint16_t u7;                /* 0x5c-0x5d: Usually 0x0003 */
    uint16_t string_offsets[19];/* 0x5e-0x83: String offset array (19 entries) */
} pdb_track_row_t;

_Static_assert(sizeof(pdb_track_row_t) == 132, "pdb_track_row_t must be 132 bytes");

/* Track row subtype magic */
#define PDB_TRACK_SUBTYPE       0x0024

/* File type values — use cdj_file_format_t from cdj_types.h */

/* String offset indices for track rows (0x5e-0x83 = 19 entries)
 * EMPIRICALLY VERIFIED from actual rekordbox exports:
 * Index 17 contains the track title, not index 15 as documentation suggests */
typedef enum {
    PDB_STR_ISRC           = 0,   /* 0x5e: ISRC code (mangled format) */
    PDB_STR_LYRICIST       = 1,   /* 0x60: Lyricist */
    PDB_STR_UNKNOWN_2      = 2,   /* 0x62: ASCII number "1" */
    PDB_STR_UNKNOWN_3      = 3,   /* 0x64: ASCII number "1" */
    PDB_STR_MESSAGE        = 4,   /* 0x66: Track message field */
    PDB_STR_PUBLISH_INFO   = 5,   /* 0x68: Usually empty */
    PDB_STR_AUTOLOAD_HOTCUES = 6, /* 0x6a: "ON" or empty */
    PDB_STR_UNKNOWN_5      = 7,   /* 0x6c: "ON" or empty */
    PDB_STR_UNKNOWN_6      = 8,   /* 0x6e: Usually empty */
    PDB_STR_UNKNOWN_7      = 9,   /* 0x70: Usually empty */
    PDB_STR_DATE_ADDED     = 10,  /* 0x72: YYYY-MM-DD (when added to collection) */
    PDB_STR_RELEASE_DATE   = 11,  /* 0x74: Usually empty */
    PDB_STR_UNKNOWN_8      = 12,  /* 0x76: Usually empty */
    PDB_STR_KUVO_PUBLIC    = 13,  /* 0x78: "Y" or empty */
    PDB_STR_ANALYZE_PATH   = 14,  /* 0x7a: Analysis file path */
    PDB_STR_ANALYZE_DATE   = 15,  /* 0x7c: YYYY-MM-DD */
    PDB_STR_COMMENT        = 16,  /* 0x7e: DJ comment */
    PDB_STR_TITLE          = 17,  /* 0x80: Track title ← VERIFIED */
    PDB_STR_MIX_NAME       = 18   /* 0x82: Mix/remix name or next offset */
} pdb_track_string_idx_t;

/*
 * ============================================================================
 * Artist Row (10 or 12 bytes depending on subtype)
 * ============================================================================
 * Reference: Artist Rows section
 *
 * subtype 0x0060: nearby name (1-byte offset at byte 0x09)
 * subtype 0x0064: far name (2-byte offset at bytes 0x0a-0x0b)
 */
typedef struct __attribute__((packed)) {
    uint16_t subtype;           /* 0x00-0x01: 0x0060 (near) or 0x0064 (far) */
    uint16_t index_shift;       /* 0x02-0x03: Unknown */
    uint32_t id;                /* 0x04-0x07: Artist ID */
    /* For subtype 0x0060: uint8_t marker (0x03), uint8_t ofs_name_near */
    /* For subtype 0x0064: uint16_t marker (0x0003), uint16_t ofs_name_far */
} pdb_artist_row_header_t;

#define PDB_ARTIST_SUBTYPE_NEAR 0x0060
#define PDB_ARTIST_SUBTYPE_FAR  0x0064

/*
 * ============================================================================
 * Album Row (22 or 24 bytes depending on subtype)
 * ============================================================================
 * Reference: Album Rows section
 *
 * subtype 0x0080: nearby name
 * subtype 0x0084: far name
 */
typedef struct __attribute__((packed)) {
    uint16_t subtype;           /* 0x00-0x01: 0x0080 (near) or 0x0084 (far) */
    uint16_t index_shift;       /* 0x02-0x03: Unknown */
    uint32_t unknown1;          /* 0x04-0x07: Unknown */
    uint32_t artist_id;         /* 0x08-0x0b: Associated artist ID */
    uint32_t id;                /* 0x0c-0x0f: Album ID */
    uint32_t unknown2;          /* 0x10-0x13: Unknown */
    /* For subtype 0x0080: uint8_t marker (0x03), uint8_t ofs_name_near */
    /* For subtype 0x0084: uint16_t marker (0x0003), uint16_t ofs_name_far */
} pdb_album_row_header_t;

#define PDB_ALBUM_SUBTYPE_NEAR  0x0080
#define PDB_ALBUM_SUBTYPE_FAR   0x0084

/*
 * ============================================================================
 * DeviceSQL String Header
 * ============================================================================
 * Reference: DeviceSQL Strings section
 *
 * First byte is length/kind flags:
 *   bit 0 (S): If set, short ASCII string (other bits = length)
 *   bit 4 (W): UTF-16 encoding
 *   bit 5 (N): UTF-8 encoding (narrow)
 *   bit 6 (A): ASCII encoding
 *   bit 7 (E): Little-endian (for UTF-16)
 *
 * Short ASCII (S=1): First byte >> 1 = total field length including header
 * Long string (S=0): Followed by 2-byte length, 1-byte pad, then data
 */
#define PDB_STRING_FLAG_SHORT   0x01
#define PDB_STRING_FLAG_WIDE    0x10
#define PDB_STRING_FLAG_NARROW  0x20
#define PDB_STRING_FLAG_ASCII   0x40
#define PDB_STRING_FLAG_LE      0x80

/* For short ASCII: length = flags >> 1 (includes the flags byte) */
#define PDB_STRING_SHORT_LEN(flags) ((flags) >> 1)

/* Common string type patterns seen in practice */
#define PDB_STRING_ASCII_LONG   0x40  /* Long ASCII string */
#define PDB_STRING_UTF16LE      0x90  /* UTF-16 little-endian */

/*
 * ============================================================================
 * Helper Macros
 * ============================================================================
 */

/* Calculate page offset in file: page_index * page_size */
#define PDB_PAGE_OFFSET(page_idx, page_size) ((size_t)(page_idx) * (size_t)(page_size))

/* Calculate heap offset within page (after page header) */
#define PDB_HEAP_OFFSET 0x28

/* Row index is built backwards from end of page
 * Each group of 16 rows uses: 16 * 2-byte offsets + 2-byte presence mask + 2-byte transaction mask
 * = 36 bytes per group */
#define PDB_ROW_GROUP_SIZE      36
#define PDB_ROWS_PER_GROUP      16

#endif /* PDB_PROTOCOL_H */
