/*
 * confidence.h - Track Confidence Accumulation Model
 *
 * Unified model for track identification using multiple signals:
 * CDJ metadata, play state, on-air status, Shazam fingerprints, ISRC.
 * Each deck accumulates a confidence score; tracks are accepted when
 * confidence crosses a threshold.
 */

#ifndef CONFIDENCE_H
#define CONFIDENCE_H

#include <stdint.h>
#include <time.h>
#include <pthread.h>

/*
 * ============================================================================
 * Signal Types
 * ============================================================================
 */

typedef enum {
    SIG_NONE            = 0,
    SIG_CDJ_LOADED      = (1 << 0),   /* Track metadata resolved */
    SIG_CDJ_PLAYING     = (1 << 1),   /* Deck started playing */
    SIG_CDJ_DURATION    = (1 << 2),   /* Continuous play duration tick */
    SIG_CDJ_ON_AIR      = (1 << 3),   /* DJM reports deck on-air */
    SIG_CDJ_ON_AIR_EDGE = (1 << 4),   /* Moment deck transitioned to on-air */
    SIG_SHAZAM_MATCH    = (1 << 5),   /* Shazam returned a result */
    SIG_SHAZAM_CONFIRM  = (1 << 6),   /* Consecutive Shazam match */
    SIG_ISRC_MATCH      = (1 << 7),   /* ISRC match between CDJ and Shazam */
    SIG_FUZZY_MATCH     = (1 << 8),   /* Fuzzy title+artist match */
    SIG_SHAZAM_DISAGREE = (1 << 9),   /* Shazam returned different track */
    SIG_SHAZAM_NO_MATCH = (1 << 10),  /* Shazam found nothing */
    SIG_CDJ_OFF_AIR     = (1 << 11),  /* Deck went off-air (fader down) */
} signal_flag_t;

/*
 * ============================================================================
 * Signal Weights
 * ============================================================================
 */

#define W_CDJ_LOADED        150
#define W_CDJ_PLAYING        50
#define W_CDJ_DURATION       50   /* Per 10s tick — the clock that proves commitment */
#define W_CDJ_ON_AIR        100
#define W_CDJ_ON_AIR_EDGE   150   /* Fader up — strong boost but needs duration too */
#define W_SHAZAM_MATCH      100   /* Single hit is just a hint (may be false positive) */
#define W_SHAZAM_CONFIRM    200   /* Consistency is the real signal */
#define W_ISRC_MATCH        300   /* CDJ + Shazam ISRC agree — very strong */
#define W_FUZZY_MATCH       200   /* CDJ + Shazam title/artist match */
#define W_SHAZAM_DISAGREE  -150   /* Scaled by confidence — consistent disagreement outpaces duration */
#define W_SHAZAM_NO_MATCH   -10   /* Very mild — Shazam often misses niche tracks */
#define W_CDJ_OFF_AIR      -150   /* Fader down — no longer audible */

#define DURATION_TICK_SEC    10   /* Award CDJ_DURATION every N seconds */
#define DURATION_MAX_TICKS   15   /* Cap total duration ticks */

#define CONF_MAX_SCORE     1000
#define CONF_DEFAULT_ACCEPT 550
#define CONF_DEFAULT_DECAY    1   /* Score units lost per second of no signals */
#define CONF_DEFAULT_COOLDOWN 120 /* Seconds after accept before re-accept */

/*
 * ============================================================================
 * Per-Deck Confidence State
 * ============================================================================
 */

#define CONF_MAX_DECKS 8  /* Matches MAX_DEVICES */

typedef struct {
    /* Track identity */
    char     artist[256];
    char     title[256];
    char     isrc[64];
    uint32_t rekordbox_id;

    /* Confidence score (0-1000, displayed as 0.0-100.0%) */
    int      score;
    int      peak_score;

    /* Signal tracking */
    uint32_t signals_seen;     /* Bitmask of signals ever contributed */
    uint32_t signals_active;   /* Bitmask of signals currently active */

    /* Timestamps */
    time_t   first_seen;       /* When this candidate appeared */
    time_t   last_signal;      /* When last signal was applied */

    /* Duration tick counter */
    int      duration_ticks;   /* Number of 10s ticks awarded */

    /* Shazam state */
    int      shazam_confirms;
    int      shazam_confidence; /* Skew-based (40-100) */
    int      shazam_flips;     /* Times Shazam changed its answer (reduces trust) */

    /* Acceptance */
    int      accepted;         /* 1 = logged to DB */
    time_t   accepted_at;

    /* Deck number (1-6, or 0 for audio-only slot) */
    uint8_t  deck_num;
} deck_confidence_t;

/*
 * ============================================================================
 * Global Confidence State
 * ============================================================================
 */

typedef struct {
    deck_confidence_t decks[CONF_MAX_DECKS];  /* Per-deck */
    deck_confidence_t audio_only;              /* Audio-only candidate (no CDJ) */
    pthread_mutex_t   mu;

    /* Thresholds (set at init, then read-only) */
    int accept_threshold;
    int decay_rate;
    int cooldown_sec;
} confidence_state_t;

extern confidence_state_t g_confidence;

/*
 * ============================================================================
 * API
 * ============================================================================
 */

/* Initialize. Call once from main() before threads start. */
void confidence_init(int accept_threshold, int decay_rate, int cooldown_sec);

/* Apply a signal to a deck.
 * deck_idx: index into devices[] (0-7), or -1 for audio-only slot.
 * sig: which signal.
 * value: signal-specific (e.g., shazam skew confidence).
 * artist/title/isrc: track identity to associate (NULL to keep existing).
 * rekordbox_id: 0 to keep existing. */
void confidence_signal(int deck_idx, signal_flag_t sig, int value,
                       const char *artist, const char *title,
                       const char *isrc, uint32_t rekordbox_id);

/* Tick the model (~1Hz). Applies decay, awards duration ticks,
 * checks acceptance. Returns bitmask of newly accepted deck indices
 * (bit 8 = audio-only slot). */
uint32_t confidence_tick(time_t now);

/* Copy a deck's state (thread-safe read for UI). */
void confidence_get_deck(int deck_idx, deck_confidence_t *out);

/* Get audio-only slot state. */
void confidence_get_audio(deck_confidence_t *out);

/* Find the highest-confidence playing deck. Returns deck_idx or -1. */
int confidence_best_deck(void);

/* Reset a deck (e.g., track changed). */
void confidence_reset_deck(int deck_idx);

/* Derive source string from signals_seen bitmask. */
const char *confidence_source_string(uint32_t signals_seen);

#endif /* CONFIDENCE_H */
