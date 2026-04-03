/*
 * cdj_types.h - Common types and constants for CDJ Sniffer
 *
 * Core type definitions and constants used throughout the project.
 */

#ifndef CDJ_TYPES_H
#define CDJ_TYPES_H

#include <stdint.h>
#include <time.h>

/*
 * ============================================================================
 * Network Constants
 * ============================================================================
 */

/* Ethernet/IP/UDP header sizes */
#define ETHER_HDR_LEN           14
#define IP_HDR_MIN_LEN          20
#define UDP_HDR_LEN             8
#define TCP_HDR_MIN_LEN         20

/*
 * ============================================================================
 * Device Types and Limits
 * ============================================================================
 */

#define MAX_DEVICES             8

typedef enum {
    DEVICE_TYPE_UNKNOWN   = 0,
    DEVICE_TYPE_CDJ       = 1,
    DEVICE_TYPE_DJM       = 2,
    DEVICE_TYPE_REKORDBOX = 3
} cdj_device_type_t;

/*
 * ============================================================================
 * Media Slots
 * ============================================================================
 */

typedef enum {
    SLOT_UNKNOWN   = 0x00,
    SLOT_CD        = 0x01,
    SLOT_SD        = 0x02,
    SLOT_USB       = 0x03,
    SLOT_LINK      = 0x04,  /* Track loaded via Pro DJ Link from another player */
    SLOT_STREAMING = 0x06,  /* Streaming Direct Play (Beatport LINK, etc.) */
    SLOT_BEATPORT  = 0x09   /* Beatport streaming service */
} cdj_slot_t;

/*
 * ============================================================================
 * Track Types
 * ============================================================================
 */

typedef enum {
    TRACK_REKORDBOX   = 0x01,  /* Analyzed rekordbox track */
    TRACK_UNANALYZED  = 0x02,  /* Non-rekordbox track from media */
    TRACK_CD_AUDIO    = 0x05,  /* CD audio track */
    TRACK_STREAMING   = 0x06   /* Streaming service track */
} cdj_track_type_t;

/*
 * ============================================================================
 * Device State Structure
 * ============================================================================
 */

typedef struct {
    uint8_t  active;
    uint8_t  device_num;        /* Device number (1-4 for CDJs) */
    uint8_t  device_type;       /* cdj_device_type_t */
    uint32_t ip_addr;
    uint8_t  mac_addr[6];
    char     name[32];
    
    /* Track state */
    uint8_t  playing;
    uint8_t  cued;
    uint16_t track_id;
    uint32_t track_number;
    uint8_t  track_slot;        /* cdj_slot_t */
    uint8_t  track_type;        /* cdj_track_type_t */
    uint8_t  track_source_player; /* Source player when using Link */
    uint8_t  track_source_slot;   /* Original slot when using Link */
    uint16_t bpm_raw;           /* BPM * 100 */
    int32_t  pitch_raw;         /* Pitch * 6400, signed (from position packets) */
    uint32_t beat_number;
    uint8_t  beat_in_bar;       /* 1-4 within current bar (0=unknown) */

    /* Loop state */
    uint8_t  looping;           /* 1 = loop active (play_state or extended fields) */
    uint16_t loop_beats;        /* Loop length in beats (0=unknown, CDJ-3000 only) */

    /* Key (CDJ-3000 extended status) */
    uint8_t  key_note;          /* 0x00=C .. 0x0b=B (0xff=unknown) */
    uint8_t  key_scale;         /* 0x00=minor, 0x01=major */
    uint8_t  key_accidental;    /* 0x00=natural, 0x01=sharp, 0xff=flat */
    uint8_t  master_tempo;      /* 0x00=off, 0x01=on */
    uint32_t position_ms;       /* Current position in ms (from position packets) */
    uint32_t track_length_sec;  /* Track length in seconds (from position packets) */
    uint32_t last_position_ms;  /* Previous playhead (for detecting stalls) */
    time_t   last_position_time;/* When we last saw playhead advance */
    uint8_t  playhead_stalled;  /* 1 = playhead not advancing (scratch/hold) */
    uint32_t rekordbox_id;      /* rekordbox track ID */
    
    /* Track metadata */
    char     track_title[128];
    char     track_artist[128];
    char     track_isrc[64];    /* ISRC from PDB (if available) */
    uint32_t lookup_failed_id;  /* rekordbox_id of last failed lookup (prevent retry spam) */
    time_t   last_lookup_time;  /* Rate-limit lookups (don't retry more than once per 5s) */
    
    /* Database fetch tracking */
    uint8_t  db_fetched;        /* Have we fetched DB for this slot? */
    uint8_t  last_slot;         /* Last slot seen (detect changes) */
    time_t   db_fetch_time;     /* When we fetched the DB */
    
    /* Media presence (from status packets) */
    uint8_t  usb_present;       /* USB available (usb_local != 0) */
    uint8_t  sd_present;        /* SD available (sd_local != 0) */
    uint8_t  usb_local_raw;     /* Raw usb_local byte (0x37) for local vs Link detection */
    uint8_t  sd_local_raw;      /* Raw sd_local byte (0x38) */
    uint8_t  usb_db_fetched;    /* Have we fetched USB database? */
    uint8_t  sd_db_fetched;     /* Have we fetched SD database? */
    uint8_t  usb_olib_fetched;  /* Have we fetched USB OneLibrary? */
    uint8_t  sd_olib_fetched;   /* Have we fetched SD OneLibrary? */
    time_t   usb_fetch_attempt; /* Last USB fetch attempt (throttle retries) */
    time_t   sd_fetch_attempt;  /* Last SD fetch attempt (throttle retries) */
    uint8_t  usb_fetch_fails;   /* Consecutive USB NFS fetch failures */
    uint8_t  sd_fetch_fails;    /* Consecutive SD NFS fetch failures */
    
    /* On-air and playback tracking (for CDJ-only tagging) */
    uint8_t  on_air;            /* Currently on-air (from DJM) */
    uint8_t  on_air_available;  /* Have we ever seen on_air change? */
    time_t   play_started;      /* When continuous playback started */
    uint32_t logged_rekordbox_id; /* Last track logged to DB for this deck */
    
    time_t   last_seen;
} cdj_device_t;

/*
 * ============================================================================
 * Global Device Array (extern declaration)
 * ============================================================================
 */

extern cdj_device_t devices[MAX_DEVICES];
cdj_device_t *get_device(uint8_t device_num);

/*
 * ============================================================================
 * Registration State
 * ============================================================================
 */

typedef enum {
    REG_IDLE = 0,           /* Not registered, not trying */
    REG_OBSERVING,          /* Listening to network before claiming slot */
    REG_STAGE_0,            /* Sent type 0x00 (initial presence) */
    REG_STAGE_2,            /* Sent type 0x02 (number claim) */
    REG_STAGE_4,            /* Sent type 0x04 (mixer assignment) */
    REG_ACTIVE,             /* Fully registered, sending keepalives */
    REG_PASSIVE             /* Database fetched, stopped keepalives */
} reg_state_t;

/*
 * ============================================================================
 * Error Codes
 * ============================================================================
 */

typedef enum {
    CDJ_OK               =  0,
    CDJ_ERR_CONNECT      = -1,
    CDJ_ERR_TIMEOUT      = -2,
    CDJ_ERR_PROTOCOL     = -3,
    CDJ_ERR_NO_DATA      = -4,
    CDJ_ERR_BUFFER_FULL  = -5,
    CDJ_ERR_SOCKET       = -6,
    CDJ_ERR_NOT_FOUND    = -7,
    CDJ_ERR_INVALID_ARGS = -8
} cdj_error_t;

/*
 * ============================================================================
 * Utility Functions
 * ============================================================================
 */

const char *ip_to_str(uint32_t ip);
const char *mac_to_str(const uint8_t *mac);
const char *cdj_slot_name(uint8_t slot);
const char *device_type_name(uint8_t type);

/* Find device by device number */
cdj_device_t *find_device(uint8_t device_num);

/* Find another CDJ's device number (for queries) */
uint8_t find_other_cdj_device_num(uint32_t exclude_ip);

#endif /* CDJ_TYPES_H */
