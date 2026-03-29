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
#define PROLINK_BEAT_PORT       50001   /* Beat sync + CDJ-3000 position */
#define PROLINK_STATUS_PORT     50002   /* CDJ status updates */

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
    PKT_TYPE_CDJ_STATUS      = 0x0a,  /* On port 50002 */
    PKT_TYPE_BEAT            = 0x28
} prolink_pkt_type_t;

/*
 * ============================================================================
 * CDJ Status Packet Offsets (Port 50002)
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
#define MAX_DEVICE_NUM           15    /* Highest device number we'll try (0x0F) */

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

/* CDJ Status packet (subtype 0x0a on port 50002)
 * Packet sizes: older=0xd0, nexus=0xd4, nexus2=0x11c/0x124, CDJ-3000=0x200
 * Reference: https://djl-analysis.deepsymmetry.org/djl-analysis/vcdj.html
 *
 * This struct covers the common 232-byte layout. Fields beyond 0xe7 exist
 * in nexus2/CDJ-3000 packets and are accessed via raw data[] offsets. */
typedef struct __attribute__((packed)) {
    prolink_header_t header;    /* 0x00-0x0a (0-10): Common header */
    char     device_name[20];   /* 0x0b-0x1e (11-30): Device name (space-padded) */
    uint8_t  _pad1f;            /* 0x1f (31): Always 0x01 */
    uint8_t  subtype2;          /* 0x20 (32): Subtype variant (0x03=status w/track) */
    uint8_t  device_num;        /* 0x21 (33): D - Device number 1-6 */
    uint8_t  len_remaining[2];  /* 0x22-0x23 (34-35): Bytes remaining after this */
    uint8_t  device_num2;       /* 0x24 (36): D - Device number (redundant) */
    uint8_t  _pad25[2];         /* 0x25-0x26 (37-38) */
    uint8_t  activity;          /* 0x27 (39): A - 0x00=idle, 0x01=active */
    uint8_t  source_player;     /* 0x28 (40): Dr - Device track loaded from (0=none) */
    uint8_t  track_slot;        /* 0x29 (41): Sr - Slot (see slot_type_t) */
    uint8_t  track_type;        /* 0x2a (42): Tr - Track type (see track_type_t) */
    uint8_t  _pad2b;            /* 0x2b (43) */
    uint8_t  rekordbox_id_be[4];/* 0x2c-0x2f (44-47): Rekordbox ID (big-endian) */
    uint8_t  _pad30[2];         /* 0x30-0x31 (48-49) */
    uint8_t  track_num_be[2];   /* 0x32-0x33 (50-51): Track position in list (BE) */
    uint8_t  _pad34;            /* 0x34 (52) */
    uint8_t  track_sort;        /* 0x35 (53): tsrt - Sort mode when loaded */
    uint8_t  _pad36;            /* 0x36 (54) */
    uint8_t  track_menu;        /* 0x37 (55): tsrc - Menu track was loaded from */
    uint8_t  menu_cat1[3];      /* 0x38-0x3a (56-58): tcat1 - Menu category 1 */
    uint8_t  menu_cat2[5];      /* 0x3b-0x3f (59-63): tcat2 - Menu category 2 */
    uint8_t  _pad40[6];         /* 0x40-0x45 (64-69) */
    uint8_t  disc_track_count[2]; /* 0x46-0x47 (70-71): dn - Track count on disc/menu */
    uint8_t  _pad48[16];        /* 0x48-0x57 (72-87) */
    uint8_t  load_indicator1;   /* 0x58 (88): ld1 - 0x80 briefly on new song (nxs2) */
    uint8_t  _pad59;            /* 0x59 (89) */
    uint8_t  cue_update[2];     /* 0x5a-0x5b (90-91): uc1 - 0xffff on cue add/delete */
    uint8_t  _pad5c[2];         /* 0x5c-0x5d (92-93) */
    uint8_t  tag_update[2];     /* 0x5e-0x5f (94-95): ut - Changes when song tagged */
    uint8_t  _pad60[6];         /* 0x60-0x65 (96-101) */
    uint8_t  load_indicator2[2]; /* 0x66-0x67 (102-103): ld2 - 0xffff on load done (nxs2) */
    uint8_t  _pad68[2];         /* 0x68-0x69 (104-105) */
    uint8_t  usb_activity;      /* 0x6a (106): Ua - Alternates 0x04/0x06 during USB activity */
    uint8_t  sd_activity;       /* 0x6b (107): Sa - SD activity indicator */
    uint8_t  _pad6c[3];         /* 0x6c-0x6e (108-110) */
    uint8_t  usb_state;         /* 0x6f (111): Ul - USB local: 0x04=none, 0x00=loaded, 0x02-03=ejecting */
    uint8_t  _pad70[3];         /* 0x70-0x72 (112-114) */
    uint8_t  sd_state;          /* 0x73 (115): Sl - SD local: 0x04=none, 0x00=loaded, 0x02-03=ejecting */
    uint8_t  _pad74;            /* 0x74 (116) */
    uint8_t  link_available;    /* 0x75 (117): L - 0x01 if any USB/SD/CD present on network */
    uint8_t  _pad76[5];         /* 0x76-0x7a (118-122) */
    uint8_t  play_state;        /* 0x7b (123): P1 - Play mode (see cdj_play_state_t) */
    uint8_t  firmware[4];       /* 0x7c-0x7f (124-127): Firmware version ASCII */
    uint8_t  _pad80[4];         /* 0x80-0x83 (128-131) */
    uint8_t  sync_counter_be[4]; /* 0x84-0x87 (132-135): Syncn - Increments on master handoff */
    uint8_t  _pad88;            /* 0x88 (136) */
    uint8_t  status_flags;      /* 0x89 (137): F - Status flag bits */
    uint8_t  _pad8a;            /* 0x8a (138) */
    uint8_t  play_state2;       /* 0x8b (139): P2 - 0x7a=playing, 0x7e=stopped, 0x6e=jog */
    uint8_t  pitch1_be[4];      /* 0x8c-0x8f (140-143): Pitch1 - Current effective pitch */
    uint8_t  master_valid[2];   /* 0x90-0x91 (144-145): Mv - 0x7fff=no track, 0x8000=rb */
    uint8_t  bpm_be[2];         /* 0x92-0x93 (146-147): BPM * 100 (big-endian) */
    uint8_t  master_slip[2];    /* 0x94-0x95 (148-149): Mslip - 0x7fff when not slipping */
    uint8_t  bpm_slip[2];       /* 0x96-0x97 (150-151): BPMslip - Slip mode BPM */
    uint8_t  pitch2_be[4];      /* 0x98-0x9b (152-155): Pitch2 - Fader position w/ brake */
    uint8_t  _pad9c;            /* 0x9c (156) */
    uint8_t  play_state3;       /* 0x9d (157): P3 - 0x09=vinyl fwd, 0x0d=CDJ fwd, 0x0b=slip */
    uint8_t  master_meaningful; /* 0x9e (158): Mm - 0x00=not master, 0x01=rb master */
    uint8_t  master_handoff;    /* 0x9f (159): Mh - 0xff normal, else device# taking over */
    uint8_t  beat_num_be[4];    /* 0xa0-0xa3 (160-163): Beat counter (big-endian) */
    uint8_t  cue_countdown[2];  /* 0xa4-0xa5 (164-165): Cue - Bars to next cue (0x01ff=none) */
    uint8_t  beat_in_bar;       /* 0xa6 (166): Bb - Beat within bar (1-4, 0=no rb track) */
    uint8_t  _pada7[12];        /* 0xa7-0xb2 (167-178) */
    uint8_t  grid_update;       /* 0xb3 (179): ug - 0xff when beat grid modified */
    uint8_t  _padb4[3];         /* 0xb4-0xb6 (180-182) */
    uint8_t  media_presence;    /* 0xb7 (183): Mp - CDJ-3000 media presence bitmask */
    uint8_t  usb_unsafe_eject;  /* 0xb8 (184): Ue - 0x01 if USB ejected unsafely */
    uint8_t  sd_unsafe_eject;   /* 0xb9 (185): Se - 0x01 if SD ejected unsafely */
    uint8_t  emergency_loop;    /* 0xba (186): el - 0x01 when emergency loop active */
    uint8_t  _padbb[5];         /* 0xbb-0xbf (187-191) */
    uint8_t  pitch3_be[4];      /* 0xc0-0xc3 (192-195): Pitch3 - Effective pitch (dup) */
    uint8_t  pitch4_be[4];      /* 0xc4-0xc7 (196-199): Pitch4 - Fader position (instant) */
    uint8_t  packet_counter_be[4]; /* 0xc8-0xcb (200-203): Packet counter */
    uint8_t  hardware_type;     /* 0xcc (204): nx - 0x05=older, 0x0f=nexus, 0x1f=CDJ-3000 */
    uint8_t  touch_audio;       /* 0xcd (205): t - Touch Audio support (bit 5) */
    uint8_t  _padce[26];        /* 0xce-0xe7 (206-231): Remaining to 232 */
} cdj_status_packet_t;

/* Compile-time verification of struct size (minimum nexus size) */
_Static_assert(sizeof(cdj_status_packet_t) == 232, "cdj_status_packet_t must be 232 bytes");

/* Track sort mode values (byte 0x35, tsrt) */
typedef enum {
    TRACK_SORT_DEFAULT  = 0x00,
    TRACK_SORT_TITLE    = 0x01,
    TRACK_SORT_ARTIST   = 0x02,
    TRACK_SORT_ALBUM    = 0x03,
    TRACK_SORT_BPM      = 0x04,
    TRACK_SORT_RATING   = 0x05,
    TRACK_SORT_KEY      = 0x0c,
} track_sort_t;

/* Track source menu values (byte 0x37, tsrc) */
typedef enum {
    TRACK_MENU_NONE     = 0x00,
    TRACK_MENU_ARTIST   = 0x02,
    TRACK_MENU_ALBUM    = 0x03,
    TRACK_MENU_TRACK    = 0x04,
    TRACK_MENU_PLAYLIST = 0x05,
    TRACK_MENU_BPM      = 0x06,
    TRACK_MENU_KEY      = 0x0c,
    TRACK_MENU_FOLDER   = 0x11, /* Also CD */
    TRACK_MENU_SEARCH   = 0x12,
    TRACK_MENU_HISTORY  = 0x16,
    TRACK_MENU_SEARCH_ARTIST = 0x1f,
    TRACK_MENU_SEARCH_ALBUM  = 0x20,
    TRACK_MENU_TAG_LIST = 0x28,
    TRACK_MENU_INSTANT_DOUBLE = 0x32,
} track_menu_t;

/* USB/SD local state values (bytes 0x6f Ul, 0x73 Sl) */
typedef enum {
    MEDIA_STATE_LOADED   = 0x00, /* Media present and ready */
    MEDIA_STATE_EJECTING = 0x02, /* Media being ejected */
    MEDIA_STATE_CLOSING  = 0x03, /* Media slot closing */
    MEDIA_STATE_NONE     = 0x04, /* No media present */
} media_state_t;

/* Hardware type values (byte 0xcc, nx) */
typedef enum {
    HW_TYPE_OLDER   = 0x05,
    HW_TYPE_NEXUS   = 0x0f,
    HW_TYPE_CDJ3000 = 0x1f, /* Also XDJ-XZ */
} hardware_type_t;

/* Play state values */
typedef enum {
    PLAY_STATE_EMPTY    = 0x00,
    PLAY_STATE_LOADING  = 0x02,
    PLAY_STATE_PLAYING  = 0x03,
    PLAY_STATE_LOOPING  = 0x04,
    PLAY_STATE_PAUSED       = 0x05,
    PLAY_STATE_CUED         = 0x06,
    PLAY_STATE_CUING        = 0x07,
    PLAY_STATE_PLATTER_HELD = 0x08,
    PLAY_STATE_SEARCHING    = 0x09,
    PLAY_STATE_SPUN_DOWN    = 0x0e,
    PLAY_STATE_ENDED        = 0x11,
    PLAY_STATE_EMERGENCY_LOOP = 0x12
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

/* Beat packet (96 bytes, subtype 0x28 on port 50001 / PROLINK_BEAT_PORT)
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

/* CDJ-3000 Absolute Position packet (subtype 0x0a, subtype2 0x00, on port 50001)
 * Sent every ~30ms while a track is loaded. Only CDJ-3000 and newer.
 * Reference: alphatheta-connect analysis + live CDJ-3000X testing.
 *
 * Note: deepsymmetry docs show a longer variant with BPM at 0x40-0x43.
 * Our CDJ-3000X testing confirms BPM at 0x30-0x33 in the short variant.
 * Both variants may exist; we parse the minimum confirmed layout. */
typedef struct __attribute__((packed)) {
    prolink_header_t header;    /* 0x00-0x0a (0-10): Common header (subtype=0x0a) */
    char     device_name[20];   /* 0x0b-0x1e (11-30): Device name */
    uint8_t  sub_indicator;     /* 0x1f (31): Always 0x01 */
    uint8_t  subtype2;          /* 0x20 (32): 0x00 for position packets */
    uint8_t  device_num;        /* 0x21 (33): Device number */
    uint8_t  len_remaining[2];  /* 0x22-0x23 (34-35): Bytes remaining */
    uint8_t  track_length_be[4];/* 0x24-0x27 (36-39): Track length in seconds (BE) */
    uint8_t  playhead_be[4];    /* 0x28-0x2b (40-43): Playhead in ms (BE) */
    uint8_t  pitch_be[4];       /* 0x2c-0x2f (44-47): Pitch * 6400 (BE signed) */
    uint8_t  bpm_be[4];         /* 0x30-0x33 (48-51): BPM * 10 (BE, 0xffffffff=unknown) */
} cdj_position_packet_t;

_Static_assert(sizeof(cdj_position_packet_t) == 52, "cdj_position_packet_t must be 52 bytes");

/*
 * ============================================================================
 * CDJ-3000 Extended Status Fields (beyond 232-byte base struct)
 * ============================================================================
 * CDJ-3000 sends 512-byte (0x200) status packets. Fields beyond the base
 * struct are accessed via raw data[] offsets. All multi-byte values big-endian.
 *
 * Settings Block 1 (0xd0-0xef):
 *   0xd0-0xd3   Magic: 0x12345678
 *   0xd8        Setting 1 (always 0x01)
 *   0xd9        Setting 2 (always 0x01)
 *   0xda        Waveform color: 0x01=blue, 0x03=RGB, 0x04=3-band
 *   0xdb        Setting 4 (always 0x01)
 *   0xdc        Setting 5 (always 0x01)
 *   0xdd        Waveform position: 0x01=center, 0x02=left
 *
 * Settings Block 2 (0xff-0x11e, CDJ-3000 only):
 *   0xff-0x102  Magic: 0x12345678
 *   0x108-0x10d Six bytes (typically 01 01 01 00 01 01)
 *
 * Playback & Grid:
 *   0x113       P4 - Play state bitmask (details not yet identified)
 *   0x116-0x117 Tb - Time steps in current bar
 *   0x11a-0x11b Tpos - Position within current bar
 *   0x11c       Next memory point index (0x00 if none upcoming)
 *
 * Buffer Status:
 *   0x11d       Buff - Forward buffer length from playhead
 *   0x11e       Bufb - Backward buffer length from playhead
 *   0x11f       Bufs - Buffer status: 0x01 when entire track buffered
 *   0x120-0x124 Needle drag position (touch screen timestamp)
 *
 * Key & Master Tempo (CDJ-3000):
 *   0x158       Mt - Master Tempo: 0x00=off, 0x01=on
 *   0x15c       Key note (0x00-0x0b, C through B)
 *   0x15d       Key scale: 0x00=minor, 0x01=major
 *   0x15e       Key accidental: 0x00=natural, 0x01=sharp, 0xff=flat
 *   0x164-0x16b Key shift: 64-bit signed, semitones * 100 cents
 *
 * Loop Status (CDJ-3000):
 *   0x1b6-0x1b9 Loop start position in ms
 *   0x1be-0x1c1 Loop end position in ms
 *   0x1c8-0x1c9 Loop length in beats
 */

#endif /* PROLINK_PROTOCOL_H */
