/*
 * types.h - Core type definitions for clubtagger
 */
#ifndef CLUBTAGGER_TYPES_H
#define CLUBTAGGER_TYPES_H

#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
#include <time.h>

/* AF_XDP and pcap have conflicting struct bpf_insn definitions.
 * When AF_XDP is enabled, we use raw sockets for NFS observation 
 * instead of pcap, avoiding the conflict entirely. */
#ifdef HAVE_AF_XDP
#include <xdp/xsk.h>
#elif defined(HAVE_PCAP)
#include <pcap.h>
#endif

/* Forward declarations */
struct sqlite3;
typedef struct sqlite3 sqlite3;

/* ─────────────────────────────────────────────────────────────────────────────
 * TrackID - Track identification result (unified for audio + CDJ sources)
 * ───────────────────────────────────────────────────────────────────────────── */

/* Track identification source flags */
typedef enum {
    TRACK_SRC_NONE     = 0,
    TRACK_SRC_SHAZAM   = (1 << 0),  /* Identified via audio fingerprint */
    TRACK_SRC_CDJ      = (1 << 1),  /* Identified via CDJ/rekordbox */
    TRACK_SRC_SLINK    = (1 << 2),  /* Identified via S-Link CD-text */
} track_source_t;

/* Shazam thread state (for web UI status display) */
typedef enum {
    SHAZAM_IDLE = 0,       /* Thread started, waiting for audio or in hold period */
    SHAZAM_LISTENING,      /* Enough audio, checking RMS */
    SHAZAM_FINGERPRINTING, /* Generating fingerprint */
    SHAZAM_QUERYING,       /* Sending to Shazam API */
    SHAZAM_CONFIRMING,     /* Got match, waiting for confirmations */
    SHAZAM_MATCHED,        /* Track confirmed and logged */
    SHAZAM_THROTTLED,      /* Waiting between API calls */
    SHAZAM_DISABLED,       /* libvibra not available */
    SHAZAM_NO_MATCH,       /* Shazam returned no suggestions */
    SHAZAM_ERROR,          /* Shazam API error */
} shazam_state_t;

typedef struct TrackID {
    /* Core identification fields (common to all sources) */
    char artist[256];
    char title[256];
    char isrc[64];           /* ISRC code (from Shazam or rekordbox) */
    
    /* CDJ/rekordbox specific */
    uint32_t rekordbox_id;   /* rekordbox track ID (0 if not from CDJ) */
    uint16_t bpm;            /* BPM * 100 */
    uint32_t duration_ms;    /* Duration in milliseconds */
    uint32_t bitrate;        /* kbps (0 = unknown) */
    uint32_t sample_rate;    /* Hz (0 = unknown) */
    uint8_t  sample_depth;   /* bits per sample (0 = unknown) */
    uint8_t  file_type;      /* cdj_file_format_t */
    char filename[256];      /* Original filename (from rekordbox) */
    char anlz_path[256];     /* ANLZ analysis file path (from PDB or OneLibrary) */

    /* Source tracking */
    uint8_t sources;         /* Bitmask of track_source_t */
    int confidence;          /* 0-100 confidence percentage */
    
    /* Validity flags */
    int valid;               /* Is this a valid identification? */
    int has_isrc;            /* Does this have an ISRC code? */
} TrackID;

/* ─────────────────────────────────────────────────────────────────────────────
 * SLink channel mapping - maps named stereo channels to packet sample indices
 * ───────────────────────────────────────────────────────────────────────────── */
#define SLINK_MAX_CHANNELS 8

typedef struct {
    char name[32];       /* Logical name (e.g., "main", "booth") */
    int  left;           /* SLink sample index for L */
    int  right;          /* SLink sample index for R */
} slink_channel_t;

/* ─────────────────────────────────────────────────────────────────────────────
 * Config - Application configuration from CLI
 * ───────────────────────────────────────────────────────────────────────────── */
typedef struct {
    const char *device;
    unsigned    rate;
    unsigned    channels;
    unsigned    frames_per_read;
    unsigned    fingerprint_sec;
    unsigned    identify_interval_sec;
    const char *user_agent;
    const char *timezone;
    unsigned    shazam_gap_sec;
    unsigned    same_track_hold_sec;
    unsigned    threshold;
    float       sustain_sec;
    float       silence_sec;
    const char *prefix;
    const char *source;            /* "alsa" or "slink" */
    int         bytes_per_sample;  /* 2 for 16-bit, 3 for 24-bit */
    unsigned    max_file_sec;      /* max seconds per WAV file (0 = no limit) */
    unsigned    ring_sec;          /* ring buffer size in seconds */
    const char *db_path;           /* SQLite database path for track logging */
    const char *outdir;            /* output directory for audio files */
    const char *format;            /* output format: "wav" or "flac" */
    unsigned    pcap_buffer_mb;    /* pcap kernel buffer size in MB (0 = default) */
    const char *slink_backend;     /* "pcap" or "afxdp" */
    const char *ws_socket;         /* Unix socket path for WebSocket server (NULL = disabled) */
    const char *ws_token;          /* WebSocket auth token (NULL = no auth) */
    const char *prolink_interface; /* Network interface for CDJ sniffing (NULL = disabled) */
    int         prolink_passive;   /* SPAN port mode: no registration, eavesdrop only */
    const char *olib_key;          /* OneLibrary decryption passphrase (NULL = disabled) */
    unsigned    match_threshold;    /* 0-100 similarity % for fuzzy track matching */
    slink_channel_t slink_channels[SLINK_MAX_CHANNELS];
    int             slink_channel_count;  /* number of configured SLink channels */

    /* Mode flags - which features to enable (default: all off) */
    int         enable_record;     /* Enable audio recording */
    int         enable_audio_tag;  /* Enable Shazam/audio fingerprinting */
    int         enable_cdj_tag;    /* Enable CDJ/Pro DJ Link tagging */
} Config;

/* ─────────────────────────────────────────────────────────────────────────────
 * AudioBuffer - descriptor for atomic file writing (WAV/FLAC)
 * ───────────────────────────────────────────────────────────────────────────── */
typedef struct {
    uint8_t *data;
    size_t   frames;
    size_t   capacity_frames;
    size_t   frame_bytes;
    unsigned channels;
    unsigned rate;
    int      bytes_per_sample;
    time_t   start_time;
    /* Pre-allocated FLAC conversion buffer (optional) */
    int32_t *flac_buf;
    size_t   flac_buf_samples;
} AudioBuffer;

/* ─────────────────────────────────────────────────────────────────────────────
 * AsyncWriter - fixed-size ring buffer with async disk writes
 * 
 * Capture thread continuously writes samples (overwrites oldest when full).
 * Writer thread copies ranges from ring and writes to disk asynchronously.
 * ───────────────────────────────────────────────────────────────────────────── */
typedef struct {
    /* Ring buffer (fixed size, lock-free for capture thread) */
    uint8_t        *data;
    size_t          capacity;       /* fixed capacity in frames */
    _Atomic size_t  total_written;  /* monotonic counter: total frames ever written */
    size_t          frame_bytes;
    unsigned        channels;
    unsigned        rate;
    int             bytes_per_sample;
    
    /* Async write state */
    uint8_t        *write_buf;      /* snapshot buffer for async writes */
    size_t          write_capacity;
    size_t          write_frames;
    size_t          write_from;
    size_t          write_to;
    time_t          write_start_time;
    char            write_channel[32]; /* SLink channel name for filename */
    int             write_pending;
    
    /* Pre-allocated FLAC conversion buffer */
    int32_t        *flac_buf;
    size_t          flac_buf_samples;
    
    /* Config */
    const char     *outdir;
    const char     *prefix;
    const char     *format;
    
    /* Stats */
    _Atomic uint64_t bytes_on_disk;  /* total audio bytes written to disk */
    
    /* Threading */
    pthread_mutex_t mu;
    pthread_cond_t  cv;
    pthread_t       thread;
    int             shutdown;
    int             initialized;
} AsyncWriter;

/* ─────────────────────────────────────────────────────────────────────────────
 * App - Main application state
 * ───────────────────────────────────────────────────────────────────────────── */
typedef struct {
    Config      cfg;
    AsyncWriter aw;                /* central audio buffer with async disk writes */
    pthread_t   th_cap;
    pthread_t   th_id;
    pthread_t   th_wrt;
    sqlite3    *db;
    pthread_mutex_t db_mu;
    char        current_wav[512];  /* current WAV file being recorded */
    uint8_t    *cap_buf;           /* pre-allocated capture buffer */
    size_t      cap_buf_size;      /* size of cap_buf in bytes */
    uint8_t    *wrt_buf;           /* pre-allocated writer read buffer */
    unsigned   *wrt_window;        /* pre-allocated writer sliding window */
    unsigned    wrt_window_size;   /* size of wrt_window in elements */
    uint8_t    *id_buf;            /* pre-allocated id_main audio window */
    int16_t    *id_buf_s16;        /* pre-allocated id_main s16 conversion buffer */
    size_t      id_buf_frames;     /* size of id_buf in frames */
    /* WebSocket server state */
    pthread_t   th_ws;
    _Atomic uint16_t vu_left;      /* current VU level left channel (0-32767) */
    _Atomic uint16_t vu_right;     /* current VU level right channel (0-32767) */
    _Atomic uint32_t track_seq;    /* monotonic counter, bumps on new track */
    char        last_artist[256];  /* protected by db_mu */
    char        last_title[256];   /* protected by db_mu */
    /* Pro DJ Link CDJ integration (optional) */
    void *prolink;                 /* ProlinkThread* - CDJ sniffer (NULL if disabled) */
    /* Shazam thread state (for web UI) */
    _Atomic int shazam_state;      /* shazam_state_t value */
    char shazam_candidate[512];    /* protected by db_mu: "Artist — Title" of pending match */
    int shazam_confirms;           /* protected by db_mu: confirmation count (e.g., 2/3) */
    int shazam_confidence;         /* protected by db_mu: current confidence % */
    int shazam_confirms_needed;    /* protected by db_mu: how many confirms needed (2 or 3) */
    int shazam_cdj_confirmed;      /* protected by db_mu: 1 if CDJ confirmed the match */
    int shazam_no_match_count;     /* protected by db_mu: consecutive no-match attempts before CDJ fallback */
    char last_source[16];          /* protected by db_mu: "audio", "cdj", or "both" */
    int last_confidence;           /* protected by db_mu: confidence of last match */
    char last_isrc[64];            /* protected by db_mu: ISRC code if available */
    int last_deck;                 /* protected by db_mu: CDJ deck number (0 if none) */
    /* Audio statistics (for web UI nerd info) */
    _Atomic int      slink_active_ch;  /* index into cfg.slink_channels[] (-1 = none) */
    _Atomic uint32_t audio_rms;    /* current RMS level */
    _Atomic uint64_t audio_lost;   /* total lost samples (sequence discontinuities) */
    _Atomic uint64_t audio_frames; /* total frames captured */
    _Atomic int is_recording;      /* 1 if actively writing to file */
    /* Session counters */
    time_t start_time;             /* set once in main() */
    _Atomic uint32_t shazam_queries;  /* total Shazam API calls */
    _Atomic uint32_t shazam_matches;  /* successful matches */
    _Atomic uint64_t prolink_packets; /* total Pro DJ Link packets received */
} App;

#endif /* CLUBTAGGER_TYPES_H */
