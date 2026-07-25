/*
 * dbserver_protocol.h - CDJ DBServer Protocol Constants
 *
 * Pioneer DBServer (port 1051) message types for metadata queries.
 */

#ifndef DBSERVER_PROTOCOL_H
#define DBSERVER_PROTOCOL_H

#include <stdint.h>

/*
 * ============================================================================
 * DBServer Network Constants
 * ============================================================================
 */

#define DBSERVER_PORT           1051
#define DBSERVER_MAGIC          0x872349ae

/* Transaction ID for setup messages */
#define DB_SETUP_TXID           0xfffffffe

/*
 * ============================================================================
 * DBServer Message Types (Request)
 * ============================================================================
 */

typedef enum {
    /* Setup and control */
    DBMSG_SETUP           = 0x0000,  /* Context setup */
    DBMSG_DISCONNECT      = 0x0100,  /* Polite disconnect */
    
    /* Menu navigation */
    DBMSG_ROOT_MENU       = 0x1000,  /* Root menu request */
    DBMSG_MENU_NAVIGATE   = 0x1002,  /* Navigate into subfolder/submenu */
    DBMSG_ALL_TRACKS      = 0x1004,  /* Request all tracks */
    DBMSG_PLAYLIST        = 0x1105,  /* Request playlist/folder */
    
    /* Metadata requests */
    DBMSG_METADATA_REQ    = 0x2002,  /* Rekordbox track metadata setup */
    DBMSG_UNANALYZED_REQ  = 0x2202,  /* Non-rekordbox/CD track metadata setup */
    DBMSG_ARTWORK_REQ     = 0x2003,  /* Album art request */
    DBMSG_WAVEFORM_PREVIEW= 0x2004,  /* Monochrome waveform preview */
    DBMSG_CUE_POINTS      = 0x2104,  /* Cue points and loops */
    DBMSG_BEAT_GRID       = 0x2204,  /* Beat grid request */
    DBMSG_WAVEFORM_DETAIL = 0x2904,  /* Detailed waveform */
    DBMSG_CUE_POINTS_NXS2 = 0x2b04,  /* Extended cue points (nxs2) */
    DBMSG_ANALYSIS_TAG    = 0x2c04,  /* Request analysis file tag */
    
    /* Rendering */
    DBMSG_RENDER_MENU     = 0x3000   /* Render (fetch) menu items */
} dbserver_msg_type_t;

/*
 * ============================================================================
 * DBServer Message Types (Response)
 * ============================================================================
 */

typedef enum {
    DBMSG_SUCCESS           = 0x4000,  /* Data available response */
    DBMSG_MENU_HEADER       = 0x4001,  /* Menu header */
    DBMSG_MENU_ITEM         = 0x4101,  /* Menu item */
    DBMSG_MENU_FOOTER       = 0x4201,  /* Menu footer */
    DBMSG_ARTWORK_RESP      = 0x4002,  /* Artwork response */
    DBMSG_WAVEFORM_RESP     = 0x4402,  /* Waveform preview response */
    DBMSG_BEAT_GRID_RESP    = 0x4602,  /* Beat grid response */
    DBMSG_CUE_RESP          = 0x4702,  /* Cue points response */
    DBMSG_WAVEFORM_DTL_RESP = 0x4a02,  /* Waveform detail response */
    DBMSG_CUE_NXS2_RESP     = 0x4e02,  /* Extended cue points response */
    DBMSG_ANALYSIS_RESP     = 0x4f02   /* Analysis tag response */
} dbserver_resp_type_t;

/*
 * ============================================================================
 * Menu Item Types
 * ============================================================================
 */

typedef enum {
    MENU_FOLDER         = 0x0001,
    MENU_ALBUM          = 0x0002,
    MENU_DISC           = 0x0003,
    MENU_TRACK_TITLE    = 0x0004,
    MENU_GENRE          = 0x0006,
    MENU_ARTIST         = 0x0007,
    MENU_PLAYLIST       = 0x0008,
    MENU_RATING         = 0x000a,
    MENU_DURATION       = 0x000b,
    MENU_TEMPO          = 0x000d,
    MENU_LABEL          = 0x000e,
    MENU_KEY            = 0x000f,
    MENU_BITRATE        = 0x0010,
    MENU_YEAR           = 0x0011,
    MENU_COMMENT        = 0x0023,
    MENU_DATE_ADDED     = 0x002e
} menu_item_type_t;

/*
 * ============================================================================
 * Menu Item Row Layout (DBMSG_MENU_ITEM = 0x4101)
 * ============================================================================
 * A menu-item row carries 12 arguments. Verified against captured CDJ
 * traffic (both root-menu and track-metadata renders):
 *
 *   arg0  int32   row id / parent id
 *   arg1  int32   main id (track id, artist id, duration in seconds, …)
 *   arg2  int32   byte length of label1
 *   arg3  string  label1 — the row's value (track title, artist name, …)
 *   arg4  int32   byte length of label2
 *   arg5  string  label2 — secondary value, usually empty
 *   arg6  int32   item type (menu_item_type_t: 0x0004 title, 0x0007 artist, …)
 *   arg7+ int32   flags / artwork id / colour
 *
 * A track-metadata render is one row per attribute, e.g.
 *   type=0x0004 label1="They Just Let You"   (title)
 *   type=0x0007 label1="Cøre & Einerlei"     (artist)
 *   type=0x0002 label1="Mystery Bodega Box"  (album)
 *
 * The two byte-length args are why the item type must be read by argument
 * INDEX and never by scanning for "an int32 that looks like a type": arg4 is
 * 2 for an empty label2, which is indistinguishable from MENU_ALBUM (0x0002).
 */
#define MENU_ITEM_ARG_LABEL1     3
#define MENU_ITEM_ARG_LABEL2     5
#define MENU_ITEM_ARG_ITEM_TYPE  6
#define MENU_ITEM_MIN_ARGS       7          /* through the item-type arg */
#define MENU_ITEM_TYPE_NONE      0xffffffffu /* no type read from the row */

/*
 * ============================================================================
 * Menu Location Constants
 * ============================================================================
 */

#define MENU_TYPE_FOLDER        0x08    /* Folder contents browse */
#define MENU_LOC_FOLDER         0x07    /* Menu location for FOLDER browsing */
#define MENU_LOC_DATA           0x01    /* Menu location for metadata queries */

/*
 * ============================================================================
 * DBServer Field Type Prefixes
 * ============================================================================
 * Each field in a DBServer message is prefixed with a type byte.
 */

#define DBFIELD_INT8      0x0f  /* 8-bit integer (2 bytes: type + value) */
#define DBFIELD_INT16     0x10  /* 16-bit integer (3 bytes: type + value) */
#define DBFIELD_INT32     0x11  /* 32-bit integer (5 bytes: type + value) */
#define DBFIELD_BINARY    0x14  /* Binary blob (1 + 4 len + data) */
#define DBFIELD_STRING    0x26  /* UTF-16 string (1 + 4 len + data) */

/* Size of argument tags blob */
#define DBFIELD_TAGS_LEN  12

/*
 * ============================================================================
 * DBServer Argument Tags  
 * ============================================================================
 * These identify argument types within the 12-byte tags field.
 */

typedef enum {
    FIELD_INT8    = 0x04,
    FIELD_INT16   = 0x05,
    FIELD_INT32   = 0x06,
    FIELD_BINARY  = 0x03,
    FIELD_STRING  = 0x02
} dbserver_field_tag_t;

/*
 * ============================================================================
 * DMST (Device/Menu/Slot/Type) Helper
 * ============================================================================
 * 
 * The DMST value is a 32-bit field commonly used in DBServer messages:
 * Bits 31-24: Device number
 * Bits 23-16: Menu location
 * Bits 15-8:  Slot (CD/SD/USB/rekordbox)
 * Bits 7-0:   Track type
 */

static inline uint32_t build_dmst(uint8_t device, uint8_t menu_loc, 
                                   uint8_t slot, uint8_t track_type) {
    return ((uint32_t)device << 24) | 
           ((uint32_t)menu_loc << 16) | 
           ((uint32_t)slot << 8) | 
           track_type;
}

/*
 * ============================================================================
 * DBServer Message Header
 * ============================================================================
 * 
 * All DBServer messages start with:
 * - 4 bytes: Magic (0x872349ae or similar)
 * - 4 bytes: Transaction ID
 * - 2 bytes: Message type
 * - 1 byte:  Number of arguments
 * - N bytes: Argument tags (12 bytes padded)
 * - Variable: Arguments
 */

/* Wire-format offsets within a DBServer message, relative to msg_start
 * (the byte position of the magic field's INT32 type prefix). Each header
 * field is field-tag-prefixed on the wire, so the offsets here include
 * those prefixes.
 *
 *   [INT32 magic ]  5 bytes  @ 0
 *   [INT32 txid  ]  5 bytes  @ 5
 *   [INT16 type  ]  3 bytes  @ 10  (value at +11..+12)
 *   [INT8  argc  ]  2 bytes  @ 13  (value at +14)
 *   [BINARY tags ]  variable @ 15  (prefix +0, length +1..+4, data +5..)
 *   [args...     ]           @ 15 + 5 + tags_len
 *
 * Argtags blob is variable on responses: requests we send pad to
 * DBFIELD_TAGS_LEN=12 bytes, but CDJ-3000X replies trim to only as many
 * tag bytes as argc demands. Compute arg offsets via dbmsg_args_offset()
 * below — never hardcode. */
#define DBMSG_OFF_MAGIC           0
#define DBMSG_OFF_TXID            5
#define DBMSG_OFF_MSG_TYPE        10
#define DBMSG_OFF_MSG_TYPE_VALUE  11
#define DBMSG_OFF_ARGC            13
#define DBMSG_OFF_ARGC_VALUE      14
#define DBMSG_OFF_ARGTAGS         15
#define DBMSG_OFF_ARGTAGS_LEN     16  /* 4-byte BE length of tags blob */
#define DBMSG_OFF_ARGTAGS_DATA    20  /* tag bytes start here; args follow */

/* Field sizes on the wire including type prefix. */
#define DBFIELD_SIZE_INT8         2
#define DBFIELD_SIZE_INT16        3
#define DBFIELD_SIZE_INT32        5

/* Minimum bytes needed to safely read msg_type from a message header. */
#define DBMSG_MIN_HEADER_BYTES    (DBMSG_OFF_ARGC)

#include <stddef.h>
#include <stdint.h>

static inline uint32_t dbmsg_read_be32(const uint8_t *buf) {
    return ((uint32_t)buf[0] << 24) | ((uint32_t)buf[1] << 16) |
           ((uint32_t)buf[2] << 8)  |  (uint32_t)buf[3];
}

/* Offset (relative to start of resp) where the first argument begins for
 * the message at msg_start. Returns -1 if the response is too short to
 * contain the argtags blob. */
static inline int dbmsg_args_offset(const uint8_t *resp, size_t resp_len,
                                    size_t msg_start) {
    if (msg_start + DBMSG_OFF_ARGTAGS_DATA > resp_len) return -1;
    uint32_t tags_len = dbmsg_read_be32(&resp[msg_start + DBMSG_OFF_ARGTAGS_LEN]);
    return (int)(msg_start + DBMSG_OFF_ARGTAGS_DATA + tags_len);
}

/* Read the Nth (0-indexed) INT32 argument given the offset from
 * dbmsg_args_offset(). Returns 0 on success, -1 on bounds error or wrong
 * field type. */
static inline int dbmsg_read_int32_arg(const uint8_t *resp, size_t resp_len,
                                       int args_offset, int arg_idx,
                                       uint32_t *out) {
    if (args_offset < 0) return -1;
    int off = args_offset + arg_idx * DBFIELD_SIZE_INT32;
    if (off < 0 || (size_t)off + DBFIELD_SIZE_INT32 > resp_len) return -1;
    if (resp[off] != DBFIELD_INT32) return -1;
    *out = dbmsg_read_be32(&resp[off + 1]);
    return 0;
}
#define DBMSG_HEADER_NARGS_OFF   10
#define DBMSG_HEADER_TAGS_OFF    11

#endif /* DBSERVER_PROTOCOL_H */
