/*
 * prolink_protocol.h - Pro DJ Link Protocol Constants
 *
 * Pioneer Pro DJ Link protocol definitions for UDP ports 50000-50002.
 */

#ifndef PROLINK_PROTOCOL_H
#define PROLINK_PROTOCOL_H

#include <stdint.h>

/*
 * ============================================================================
 * Pro DJ Link Network Ports
 * ============================================================================
 */

#define PROLINK_KEEPALIVE_PORT  50000
#define PROLINK_STATUS_PORT     50001
#define PROLINK_BEAT_PORT       50002

/*
 * ============================================================================
 * Packet Signature and Types
 * ============================================================================
 */

/* All Pro DJ Link packets start with this 10-byte signature */
#define PROLINK_SIGNATURE       "Qspt1WmJOL"
#define PROLINK_SIG_LEN         10

/* Packet type identifiers (byte 10 after signature) */
typedef enum {
    PKT_TYPE_DEVICE_ANNOUNCE = 0x06,
    PKT_TYPE_KEEPALIVE       = 0x0a,
    PKT_TYPE_CDJ_STATUS      = 0x0a,  /* On port 50001 */
    PKT_TYPE_BEAT            = 0x28
} prolink_pkt_type_t;

/*
 * ============================================================================
 * CDJ Status Packet Offsets (Port 50001)
 * ============================================================================
 * 
 * Status packets are 0xd4 (212) bytes for CDJ-2000NXS2.
 * Key fields and their byte offsets:
 */

/* Header fields */
#define STATUS_OFF_TYPE           0x0a   /* Packet type (0x0a) */
#define STATUS_OFF_DEVICE_NAME    0x0b   /* Device name (20 bytes) */
#define STATUS_OFF_DEVICE_NUM     0x21   /* Device number (1 byte) */
#define STATUS_OFF_PKT_LEN        0x22   /* Packet length (2 bytes) */

/* Playback state fields */
#define STATUS_OFF_TRACK_ID       0x2c   /* Track ID in playlist (2 bytes) */
#define STATUS_OFF_TRACK_SLOT     0x29   /* Media slot (1 byte) */
#define STATUS_OFF_TRACK_TYPE     0x2a   /* Track type (1 byte) */
#define STATUS_OFF_REKORDBOX_ID   0x2c   /* Rekordbox ID (4 bytes) */
#define STATUS_OFF_TRACK_NUM      0x32   /* Track number (2 bytes) */

/* BPM and sync */
#define STATUS_OFF_BPM            0x92   /* BPM * 100 (2 bytes) */
#define STATUS_OFF_PITCH          0x8c   /* Pitch adjustment (4 bytes) */
#define STATUS_OFF_BEAT_NUM       0xa6   /* Beat number (4 bytes) */

/* Play state flags */
#define STATUS_OFF_FLAGS_1        0x89   /* Play state flags byte 1 */
#define STATUS_OFF_FLAGS_2        0x8a   /* Play state flags byte 2 */

/* Position */
#define STATUS_OFF_POSITION_MS    0x4e   /* Position in ms (4 bytes) */

/*
 * ============================================================================
 * Play State Flag Bits
 * ============================================================================
 */

#define STATE_FLAG_PLAYING        0x40
#define STATE_FLAG_MASTER         0x20
#define STATE_FLAG_SYNC           0x10
#define STATE_FLAG_ON_AIR         0x08
#define STATE_FLAG_CUED           0x04

/*
 * ============================================================================
 * Keepalive Packet Offsets (Port 50000)
 * ============================================================================
 */

#define KEEPALIVE_OFF_DEVICE_NAME  0x0c   /* Device name string */
#define KEEPALIVE_OFF_PKT_TYPE     0x22   /* Packet subtype */
#define KEEPALIVE_OFF_DEVICE_NUM   0x24   /* Device number */
#define KEEPALIVE_OFF_MAC          0x26   /* MAC address (6 bytes) */
#define KEEPALIVE_OFF_IP           0x2c   /* IP address (4 bytes) */

/* Keepalive packet subtypes */
typedef enum {
    KEEPALIVE_SUBTYPE_INITIAL   = 0x00,  /* Initial presence */
    KEEPALIVE_SUBTYPE_CLAIM     = 0x02,  /* Number claim */
    KEEPALIVE_SUBTYPE_MIXER     = 0x04,  /* Mixer assignment */
    KEEPALIVE_SUBTYPE_ACTIVE    = 0x06   /* Regular keepalive */
} keepalive_subtype_t;

/*
 * ============================================================================
 * Pro DJ Link Constants
 * ============================================================================
 */

#define PROLINK_BROADCAST_ADDR       "169.254.255.255"
#define PROLINK_BROADCAST_IP         0xA9FEFFFF  /* 169.254.255.255 in host order */
#define PROLINK_KEEPALIVE_INTERVAL_MS  1500

/* Device types in keepalive packets */
typedef enum {
    PROLINK_DEVICE_CDJ       = 0x01,  /* CDJ player */
    PROLINK_DEVICE_DJM       = 0x02,  /* DJM mixer */
    PROLINK_DEVICE_REKORDBOX = 0x03   /* rekordbox software */
} prolink_device_type_t;

/* Virtual CDJ identity */
#define VIRTUAL_CDJ_DEVICE_NUM   3
#define VIRTUAL_CDJ_NAME         "CLUBTAGGER"

/* Network timing constants */
#define DEVICE_TIMEOUT_SEC       10    /* Consider device gone after this */
#define KEEPALIVE_TIMEOUT_COUNT  300   /* Release slot after this many keepalives (~5 min) */
#define REACTIVATION_DELAY_US    200000 /* 200ms between re-activation keepalives */
#define REACTIVATION_BURST_COUNT 3     /* Keepalives sent during re-activation */

/* Player slot limits */
#define MAX_PLAYERS_NXS2         4     /* Maximum players on NXS2 network */
#define MAX_PLAYERS_CDJ3000      6     /* Maximum players on CDJ-3000 network */

/*
 * ============================================================================
 * Keepalive Packet Structure (54 bytes on port 50000)
 * ============================================================================
 * Sent periodically to announce presence on the Pro DJ Link network.
 * Reference: https://djl-analysis.deepsymmetry.org/djl-analysis/startup.html
 */

typedef struct __attribute__((packed)) {
    uint8_t  magic[10];         /* 0x00-0x09: "Qspt1WmJOL" */
    uint8_t  packet_type;       /* 0x0a (10): PKT_TYPE_DEVICE_ANNOUNCE (0x06) */
    uint8_t  subtype;           /* 0x0b (11): Keepalive subtype */
    char     device_name[20];   /* 0x0c-0x1f (12-31): Device name (null-padded) */
    uint8_t  struct_version;    /* 0x20 (32): Structure version (0x01) */
    uint8_t  _reserved1;        /* 0x21 (33): Reserved (0x00) */
    uint8_t  device_type;       /* 0x22 (34): 1=CDJ, 2=DJM, 3=rekordbox */
    uint8_t  _reserved2;        /* 0x23 (35): Reserved (0x00) */
    uint8_t  device_num;        /* 0x24 (36): Device number (1-6) */
    uint8_t  _reserved3;        /* 0x25 (37): Reserved (0x01) */
    uint8_t  mac_addr[6];       /* 0x26-0x2b (38-43): MAC address */
    uint8_t  ip_addr[4];        /* 0x2c-0x2f (44-47): IP address */
    uint8_t  presence_flag;     /* 0x30 (48): Presence flag (0x01) */
    uint8_t  _reserved4[5];     /* 0x31-0x35 (49-53): Reserved */
} keepalive_packet_t;

_Static_assert(sizeof(keepalive_packet_t) == 54, "keepalive_packet_t must be 54 bytes");

/*
 * ============================================================================
 * CDJ Status Packet Structure (0x0a on port 50002, 212-512 bytes)
 * ============================================================================
 * Packed structures for direct packet parsing. All multi-byte fields are
 * big-endian and need byte swapping on little-endian systems.
 * Reference: https://djl-analysis.deepsymmetry.org/djl-analysis/vcdj.html
 *
 * Packet sizes vary by player:
 *   - Older CDJs: 0xd0 (208) bytes
 *   - Nexus: 0xd4 (212) bytes
 *   - Nexus 2: 0x11c (284) or 0x124 (292) bytes
 *   - CDJ-3000: 0x200 (512) bytes
 *
 * Verified offsets:
 *   [0x0a]     Subtype (0x0a for status)
 *   [0x0b-0x1e] Device name (20 chars, space-padded)
 *   [0x21]     Device number D (1-6)
 *   [0x27]     Activity flag A (0=idle, 1=active)
 *   [0x28]     Dr - Source device for track
 *   [0x29]     Sr - Slot (0=none, 1=CD, 2=SD, 3=USB, 4=Link)
 *   [0x2a]     Tr - Track type (0=none, 1=rekordbox, 2=unanalyzed, 5=CD)
 *   [0x2c-0x2f] Rekordbox ID (big-endian uint32)
 *   [0x32-0x33] Track number (big-endian uint16)
 *   [0x7b]     P1 - Play state
 *   [0x89]     F - Status flags (bit6=play, bit5=master, bit4=sync, bit3=on-air)
 *   [0x92-0x93] BPM * 100 (big-endian uint16)
 *   [0xa0-0xa3] Beat counter (big-endian uint32)
 *   [0xa6]     Bb - Beat within bar (1-4)
 */

/* Common packet header (first 11 bytes of all Pro DJ Link packets) */
typedef struct __attribute__((packed)) {
    uint8_t  magic[10];         /* 0x00-0x09: "Qspt1WmJOL" */
    uint8_t  subtype;           /* 0x0a (10): Packet subtype */
} prolink_header_t;

/* CDJ Status packet (minimum 212 bytes, subtype 0x0a on port 50002) */
typedef struct __attribute__((packed)) {
    prolink_header_t header;    /* 0x00-0x0a (0-10): Common header */
    char     device_name[20];   /* 0x0b-0x1e (11-30): Device name (space-padded) */
    uint8_t  _reserved1;        /* 0x1f (31): Always 0x01 */
    uint8_t  subtype2;          /* 0x20 (32): Subtype variant (0x03-0x06) */
    uint8_t  device_num;        /* 0x21 (33): Device number 1-6 */
    uint8_t  len_remaining[2];  /* 0x22-0x23 (34-35): Bytes remaining */
    uint8_t  device_num2;       /* 0x24 (36): Device number (redundant) */
    uint8_t  _reserved2[2];     /* 0x25-0x26 (37-38) */
    uint8_t  activity;          /* 0x27 (39): 0=idle, 1=active */
    uint8_t  source_player;     /* 0x28 (40): Dr - Source player (or self) */
    uint8_t  track_slot;        /* 0x29 (41): Sr - 1=CD, 2=SD, 3=USB, 4=Link */
    uint8_t  track_type;        /* 0x2a (42): Tr - 0=none, 1=rb, 2=unanalyzed, 5=CD */
    uint8_t  _reserved3;        /* 0x2b (43) */
    uint8_t  rekordbox_id_be[4];/* 0x2c-0x2f (44-47): Rekordbox ID (big-endian) */
    uint8_t  _reserved4[2];     /* 0x30-0x31 (48-49) */
    uint8_t  track_num_be[2];   /* 0x32-0x33 (50-51): Track number (big-endian) */
    uint8_t  _reserved5a[3];    /* 0x34-0x36 (52-54) */
    uint8_t  usb_local;         /* 0x37 (55): USB mounted locally (0=no, slot=yes) */
    uint8_t  sd_local;          /* 0x38 (56): SD mounted locally (0=no, slot=yes) */
    uint8_t  usb_remote;        /* 0x39 (57): USB available via Link */
    uint8_t  sd_remote;         /* 0x3a (58): SD available via Link */
    uint8_t  _reserved5b[64];   /* 0x3b-0x7a (59-122) */
    uint8_t  play_state;        /* 0x7b (123): P1 - Play state */
    uint8_t  firmware[4];       /* 0x7c-0x7f (124-127): Firmware version ASCII */
    uint8_t  _reserved6[9];     /* 0x80-0x88 (128-136) */
    uint8_t  status_flags;      /* 0x89 (137): F - Status flag bits */
    uint8_t  _reserved7;        /* 0x8a (138): P2 */
    uint8_t  _reserved8;        /* 0x8b (139) */
    uint8_t  pitch1_be[4];      /* 0x8c-0x8f (140-143): Pitch adjustment 1 */
    uint8_t  _reserved9[2];     /* 0x90-0x91 (144-145): Mv */
    uint8_t  bpm_be[2];         /* 0x92-0x93 (146-147): BPM * 100 (big-endian) */
    uint8_t  _reserved10[12];   /* 0x94-0x9f (148-159) */
    uint8_t  beat_num_be[4];    /* 0xa0-0xa3 (160-163): Beat counter (big-endian) */
    uint8_t  cue_countdown[2];  /* 0xa4-0xa5 (164-165): Cue countdown */
    uint8_t  beat_in_bar;       /* 0xa6 (166): Bb - Beat within bar (1-4) */
    uint8_t  _reserved11[65];   /* 0xa7-0xe7 (167-231): Remaining to 232 */
} cdj_status_packet_t;

/* Compile-time verification of struct size (minimum nexus size) */
_Static_assert(sizeof(cdj_status_packet_t) == 232, "cdj_status_packet_t must be 232 bytes");

/* Play state values */
typedef enum {
    PLAY_STATE_EMPTY    = 0x00,
    PLAY_STATE_LOADING  = 0x02,
    PLAY_STATE_PLAYING  = 0x03,
    PLAY_STATE_LOOPING  = 0x04,
    PLAY_STATE_PAUSED   = 0x05,
    PLAY_STATE_CUED     = 0x06
} cdj_play_state_t;

/* Helper macros for big-endian to host conversion */
#define BE16_TO_HOST(ptr) (((uint16_t)(ptr)[0] << 8) | (ptr)[1])
#define BE32_TO_HOST(ptr) (((uint32_t)(ptr)[0] << 24) | ((uint32_t)(ptr)[1] << 16) | \
                           ((uint32_t)(ptr)[2] << 8) | (ptr)[3])

/* Keepalive/Announce packet (54 bytes, subtype 0x06 on port 50000) */
typedef struct __attribute__((packed)) {
    prolink_header_t header;    /* 0x00-0x0a (0-10): Common header */
    uint8_t  _reserved1;        /* 0x0b (11) */
    char     device_name[20];   /* 0x0c-0x1f (12-31): Device name */
    uint8_t  _reserved2[2];     /* 0x20-0x21 (32-33) */
    uint8_t  device_type;       /* 0x22 (34): 1=CDJ, 2=DJM, 3=rekordbox */
    uint8_t  _reserved3;        /* 0x23 (35) */
    uint8_t  device_num;        /* 0x24 (36): Device number */
    uint8_t  _reserved4;        /* 0x25 (37) */
    uint8_t  mac_addr[6];       /* 0x26-0x2b (38-43): MAC address */
    uint8_t  ip_addr[4];        /* 0x2c-0x2f (44-47): IP address */
    uint8_t  _reserved5[6];     /* 0x30-0x35 (48-53): Remaining to 54 */
} prolink_announce_packet_t;

/* Compile-time verification of struct size */
_Static_assert(sizeof(prolink_announce_packet_t) == 54, "prolink_announce_packet_t must be 54 bytes");

/* Keepalive packet (44 bytes, subtype 0x0a on port 50000)
 * Sent periodically to maintain network presence
 * Verified offsets:
 *   [33]     Device number
 *   [38-43]  MAC address */
typedef struct __attribute__((packed)) {
    prolink_header_t header;    /* 0x00-0x0a (0-10): Common header (subtype=0x0a) */
    char     device_name[20];   /* 0x0b-0x1e (11-30): Device name */
    uint8_t  _reserved1[2];     /* 0x1f-0x20 (31-32) */
    uint8_t  device_num;        /* 0x21 (33): Device number */
    uint8_t  _reserved2[4];     /* 0x22-0x25 (34-37) */
    uint8_t  mac_addr[6];       /* 0x26-0x2b (38-43): MAC address */
} prolink_keepalive_packet_t;

/* Compile-time verification of struct size */
_Static_assert(sizeof(prolink_keepalive_packet_t) == 44, "prolink_keepalive_packet_t must be 44 bytes");

/* Beat packet (96 bytes, subtype 0x28 on port 50001)
 * Sent on each beat when playing rekordbox-analyzed tracks
 * Reference: https://djl-analysis.deepsymmetry.org/djl-analysis/beats.html
 *
 * Verified offsets:
 *   [0x0a]     Packet type (0x28)
 *   [0x0b-0x1e] Device name (20 bytes)
 *   [0x21]     Device number
 *   [0x24-0x27] Next beat in ms (big-endian)
 *   [0x28-0x2b] 2nd beat in ms
 *   [0x2c-0x2f] Next bar in ms
 *   [0x54-0x57] Pitch adjustment
 *   [0x5a-0x5b] BPM * 100 (big-endian)
 *   [0x5c]     Beat within bar (1-4)
 *   [0x5f]     Device number (redundant) */
typedef struct __attribute__((packed)) {
    prolink_header_t header;    /* 0x00-0x0a (0-10): Common header (subtype=0x28) */
    char     device_name[20];   /* 0x0b-0x1e (11-30): Device name */
    uint8_t  sub_indicator;     /* 0x1f (31): Always 0x01 */
    uint8_t  subtype2;          /* 0x20 (32): Subtype (0x00 for beat packets) */
    uint8_t  device_num;        /* 0x21 (33): Device number */
    uint8_t  len_remaining[2];  /* 0x22-0x23 (34-35): Bytes remaining (0x003c) */
    uint8_t  next_beat_be[4];   /* 0x24-0x27 (36-39): Next beat in ms (BE) */
    uint8_t  second_beat_be[4]; /* 0x28-0x2b (40-43): 2nd beat in ms (BE) */
    uint8_t  next_bar_be[4];    /* 0x2c-0x2f (44-47): Next bar in ms (BE) */
    uint8_t  fourth_beat_be[4]; /* 0x30-0x33 (48-51): 4th beat in ms (BE) */
    uint8_t  second_bar_be[4];  /* 0x34-0x37 (52-55): 2nd bar in ms (BE) */
    uint8_t  eighth_beat_be[4]; /* 0x38-0x3b (56-59): 8th beat in ms (BE) */
    uint8_t  _reserved1[24];    /* 0x3c-0x53 (60-83): Reserved (0xff) */
    uint8_t  pitch_be[4];       /* 0x54-0x57 (84-87): Pitch adjustment (BE) */
    uint8_t  _reserved2[2];     /* 0x58-0x59 (88-89) */
    uint8_t  bpm_be[2];         /* 0x5a-0x5b (90-91): BPM * 100 (BE) */
    uint8_t  beat_in_bar;       /* 0x5c (92): Beat within bar (1-4) */
    uint8_t  _reserved3[2];     /* 0x5d-0x5e (93-94) */
    uint8_t  device_num2;       /* 0x5f (95): Device number (redundant) */
} cdj_beat_packet_t;

/* Compile-time verification of struct size */
_Static_assert(sizeof(cdj_beat_packet_t) == 96, "cdj_beat_packet_t must be 96 bytes");

#endif /* PROLINK_PROTOCOL_H */
