/*
 * prolink_thread.h - Pro DJ Link Integration for clubtagger
 *
 * Runs CDJ network sniffing in a background thread and provides
 * track metadata to supplement audio fingerprinting.
 */

#ifndef PROLINK_THREAD_H
#define PROLINK_THREAD_H

#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>

/*
 * ============================================================================
 * Identification Source
 * ============================================================================
 */

typedef enum {
    ID_SOURCE_NONE      = 0,
    ID_SOURCE_AUDIO     = 1,  /* Audio fingerprint only */
    ID_SOURCE_CDJ       = 2,  /* CDJ network only */
    ID_SOURCE_BOTH      = 3   /* Both sources confirmed */
} id_source_t;

/*
 * ============================================================================
 * CDJ Tagging Configuration
 * ============================================================================
 */

/* Minimum playback duration (seconds) before logging track when ON_AIR unavailable */
#define CDJ_TAG_MIN_PLAYTIME_SEC    90   /* 1.5 minutes */

/* Confidence value for CDJ-only logged tracks */
#define CDJ_TAG_CONFIDENCE          75

/*
 * ============================================================================
 * Prolink Thread State
 * ============================================================================
 */

/* Callback for CDJ-only track logging */
typedef void (*cdj_tag_callback_t)(void *user_data, int deck, 
                                   const char *artist, const char *title,
                                   int confidence, const char *source);

typedef struct {
    pthread_t thread;
    const char *interface;      /* Network interface (e.g., "en0") */
    _Atomic int running;
    void *pcap_handle;          /* pcap_t* */
    
    /* CDJ-only tagging callback (optional) */
    cdj_tag_callback_t on_track_confirmed;
    void *callback_user_data;
    
    /* Internal state for CDJ tagging */
    int tagging_enabled;        /* Enable CDJ-only track logging */
} ProlinkThread;

/*
 * ============================================================================
 * Prolink Thread API
 * ============================================================================
 */

/* Initialize and start the prolink thread */
int prolink_init(ProlinkThread *pt, const char *interface, int verbose_level);

/* Shutdown the prolink thread */
void prolink_shutdown(ProlinkThread *pt);

/* Get the currently playing track info from any active deck
 * Returns 0 on success, -1 if no track playing
 * Sets *deck_num to the deck number (1-4) */
int prolink_get_playing_track(ProlinkThread *pt, 
                               char *title, size_t title_sz,
                               char *artist, size_t artist_sz,
                               int *deck_num);

/* Check if a CDJ track matches fingerprint result (fuzzy match)
 * Returns 1 if match, 0 if no match */
int prolink_matches_fingerprint(const char *cdj_title, const char *cdj_artist,
                                 const char *fp_title, const char *fp_artist);

/* Enable CDJ-only tagging mode
 * When enabled, tracks are logged to DB when:
 *   1. ON_AIR goes active while playing (if DJM detected), OR
 *   2. Track plays continuously for CDJ_TAG_MIN_PLAYTIME_SEC (fallback)
 * The callback is invoked when a track should be logged */
void prolink_enable_tagging(ProlinkThread *pt, 
                            cdj_tag_callback_t callback, 
                            void *user_data);

/* Called periodically to check if any tracks should be logged
 * This should be called about once per second */
void prolink_check_tagging(ProlinkThread *pt);

/* Check if any deck is currently ON AIR and playing
 * Returns 1 if any deck is on_air && playing, 0 otherwise
 * Returns -1 if no ON_AIR data available (no DJM detected) */
int prolink_any_deck_on_air(ProlinkThread *pt);

/* Check how many active CDJ decks are detected
 * Returns the count of active CDJs (0 if none) */
int prolink_active_deck_count(ProlinkThread *pt);

#endif /* PROLINK_THREAD_H */
