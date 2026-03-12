/*
 * id_thread.c - Audio fingerprint identification thread
 * 
 * Simplified decision logic:
 * 1. If Shazam matches CDJ (ISRC or fuzzy) → immediate accept (source="both")
 * 2. If Shazam only → need 2 confirms (source="audio")  
 * 3. If Shazam fails 3x and CDJ has track → use CDJ (source="cdj")
 */
#include "id_thread.h"
#include "../writer/async_writer.h"
#include "../audio/audio_analysis.h"
#include "../common.h"
#include "../db/database.h"
#include "shazam.h"
#include "../prolink/prolink_thread.h"

#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#ifdef HAVE_VIBRA
/* External vibra library functions */
typedef struct Fingerprint Fingerprint;
extern Fingerprint *vibra_get_fingerprint_from_signed_pcm(const char *raw_pcm, int pcm_data_size,
                                                          int sample_rate, int sample_width_bits,
                                                          int channel_count);
extern const char *vibra_get_uri_from_fingerprint(Fingerprint *fingerprint);
extern unsigned int vibra_get_sample_ms_from_fingerprint(Fingerprint *fingerprint);
extern void vibra_free_fingerprint(Fingerprint *fingerprint);

/* Record a confirmed match - updates state and DB */
static void record_match(App *app, const char *artist, const char *title, 
                         const char *isrc, int confidence, const char *source) {
    char tsbuf[64];
    now_timestamp(tsbuf, sizeof(tsbuf));
    
    if (isrc && isrc[0])
        logmsg("id", "%s MATCH: %s — %s [%s] (%d%%, %s)", tsbuf, artist, title, isrc, confidence, source);
    else
        logmsg("id", "%s MATCH: %s — %s (%d%%, %s)", tsbuf, artist, title, confidence, source);
    
    db_insert_play(app, tsbuf, artist, title, isrc ? isrc : "", confidence, source);
    
    pthread_mutex_lock(&app->db_mu);
    snprintf(app->last_artist, sizeof(app->last_artist), "%s", artist);
    snprintf(app->last_title, sizeof(app->last_title), "%s", title);
    snprintf(app->last_source, sizeof(app->last_source), "%s", source);
    snprintf(app->last_isrc, sizeof(app->last_isrc), "%s", isrc ? isrc : "");
    app->last_confidence = confidence;
    app->shazam_candidate[0] = '\0';
    app->shazam_confirms = 0;
    app->shazam_no_match_count = 0;
    pthread_mutex_unlock(&app->db_mu);
    
    atomic_store_explicit(&app->shazam_state, SHAZAM_MATCHED, memory_order_release);
    atomic_fetch_add_explicit(&app->track_seq, 1, memory_order_release);
}

/* Get CDJ track info if available */
static int get_cdj_track(App *app, char *title, size_t tsz, char *artist, size_t asz,
                         char *isrc, size_t isz, int *deck) {
    if (!app->prolink) return -1;
    return prolink_get_playing_track(app->prolink, title, tsz, artist, asz, isrc, isz, deck);
}
#endif /* HAVE_VIBRA */

void *id_main(void *arg) {
    App *app = (App *)arg;
    Config *cfg = &app->cfg;

#ifndef HAVE_VIBRA
    /* libvibra not available - audio fingerprinting disabled */
    logmsg("id", "WARNING: libvibra not available, audio fingerprinting disabled");
    logmsg("id", "Use --cdj-tag for CDJ-only track identification");
    atomic_store_explicit(&app->shazam_state, SHAZAM_DISABLED, memory_order_release);
    while (g_running) {
        struct timespec ts = {.tv_sec = 1, .tv_nsec = 0};
        nanosleep(&ts, NULL);
    }
    return NULL;
#else
    const size_t look_frames = app->id_buf_frames;
    const size_t fb = cfg->channels * cfg->bytes_per_sample;
    uint8_t *window = app->id_buf;
    int16_t *window_s16 = app->id_buf_s16;

    logmsg("id", "started: fingerprint=%us interval=%us threshold=%u",
           cfg->fingerprint_sec, cfg->identify_interval_sec, cfg->threshold);

    time_t last_lookup = 0;
    time_t last_good_match = 0;
    TrackID current = {0};   /* Currently confirmed track */
    TrackID pending = {0};   /* Candidate awaiting confirmation */
    int pending_confirms = 0;
    int shazam_fails = 0;    /* Consecutive Shazam failures */

    /* Initial state: listening for audio */
    atomic_store_explicit(&app->shazam_state, SHAZAM_LISTENING, memory_order_release);

    while (g_running) {
        size_t got = asyncwr_copy_last(&app->aw, window, look_frames);

        /* Convert to 16-bit for RMS and vibra */
        if (cfg->bytes_per_sample == 2) {
            memcpy(window_s16, window, got * fb);
        } else if (cfg->bytes_per_sample == 3) {
            for (size_t i = 0; i < got * cfg->channels; ++i) {
                /* Little-endian 24-bit */
                int32_t s = ((int32_t)window[i * 3 + 2] << 16) | ((int32_t)window[i * 3 + 1] << 8) | (int32_t)window[i * 3];
                if (s & 0x800000) s |= 0xFF000000;
                window_s16[i] = (int16_t)(s >> 8);
            }
        }

        unsigned r = rms_s16_interleaved(window_s16, got, cfg->channels);
        vlogmsg("id", "peek=%zu frames, rms=%u (threshold=%u)", got, r, cfg->threshold);

        /* Use same threshold as writer for "is there music" detection */
        if (got > 0 && r >= cfg->threshold && got >= (size_t)(cfg->rate * cfg->fingerprint_sec * 3 / 4)) {
            time_t nowt = time(NULL);
            if (current.valid && (unsigned)(nowt - last_good_match) < cfg->same_track_hold_sec) {
                vlogmsg("id", "hold: same-track window active (%us)", cfg->same_track_hold_sec);
                goto sleep_loop;
            }
            if (last_lookup && (unsigned)(nowt - last_lookup) < cfg->shazam_gap_sec) {
                vlogmsg("id", "throttle: waiting %us between lookups", cfg->shazam_gap_sec);
                goto sleep_loop;
            }
            last_lookup = nowt;

            /* Update state: fingerprinting */
            atomic_store_explicit(&app->shazam_state, SHAZAM_FINGERPRINTING, memory_order_release);

            const int bytes = (int)(got * cfg->channels * sizeof(int16_t));
            Fingerprint *fp = vibra_get_fingerprint_from_signed_pcm(
                (const char *)window_s16, bytes, (int)cfg->rate, 16, (int)cfg->channels);
            if (!fp) {
                logmsg("vibra", "fingerprint failed");
            } else {
                const char *uri = vibra_get_uri_from_fingerprint(fp);
                unsigned sample_ms = vibra_get_sample_ms_from_fingerprint(fp);
                char url[512];
                char body[32768];  /* Fingerprint URI can be ~13KB */
                char json[65536];
                build_shazam_request(uri, sample_ms, cfg->timezone, url, body, sizeof(body));
                const char *ua = cfg->user_agent ? cfg->user_agent : "Dalvik/2.1.0 (Linux; U; Android 5.0.2; VS980 4G Build/LRX22G)";

                /* Update state: querying Shazam */
                atomic_store_explicit(&app->shazam_state, SHAZAM_QUERYING, memory_order_release);

                /* Always get CDJ track info for comparison */
                char cdj_title[256] = {0}, cdj_artist[256] = {0}, cdj_isrc[64] = {0};
                int cdj_deck = 0;
                int have_cdj = (get_cdj_track(app, cdj_title, sizeof(cdj_title),
                                              cdj_artist, sizeof(cdj_artist),
                                              cdj_isrc, sizeof(cdj_isrc), &cdj_deck) == 0 && cdj_title[0]);

                if (shazam_post(url, ua, body, json, sizeof(json)) == 0) {
                    vlogmsg("id", "shazam response: %.500s", json);

                    char title[256] = {0}, artist[256] = {0}, isrc[64] = {0};
                    json_extract_field(json, "title", title, sizeof(title));
                    json_extract_field(json, "subtitle", artist, sizeof(artist));
                    if (!artist[0]) json_extract_field(json, "artist", artist, sizeof(artist));
                    json_extract_field(json, "isrc", isrc, sizeof(isrc));

                    /* Calculate confidence from Shazam skew values */
                    char timeskew_str[64] = {0}, freqskew_str[64] = {0};
                    json_extract_field(json, "timeskew", timeskew_str, sizeof(timeskew_str));
                    json_extract_field(json, "frequencyskew", freqskew_str, sizeof(freqskew_str));
                    double timeskew = timeskew_str[0] ? atof(timeskew_str) : 0.02;
                    double freqskew = freqskew_str[0] ? atof(freqskew_str) : 0.02;
                    double ts_abs = timeskew < 0 ? -timeskew : timeskew;
                    double fs_abs = freqskew < 0 ? -freqskew : freqskew;
                    
                    /* Lower skew = higher confidence: 0.00=100%, 0.01=85%, 0.03=55%, 0.05=25% */
                    double max_skew = ts_abs > fs_abs ? ts_abs : fs_abs;
                    int shazam_confidence = (int)(100.0 - max_skew * 1500.0);
                    if (shazam_confidence < 40) shazam_confidence = 40;
                    if (shazam_confidence > 100) shazam_confidence = 100;
                    vlogmsg("id", "shazam skew: ts=%.4f fs=%.4f → %d%%", timeskew, freqskew, shazam_confidence);

                    if (title[0] || artist[0]) {
                        shazam_fails = 0;  /* Reset fail counter on any result */

                        /* Check if this matches current track */
                        TrackID match = {0};
                        match.valid = 1;
                        snprintf(match.artist, sizeof(match.artist), "%s", artist);
                        snprintf(match.title, sizeof(match.title), "%s", title);
                        snprintf(match.isrc, sizeof(match.isrc), "%s", isrc);
                        match.has_isrc = isrc[0] != 0;

                        if (current.valid && same_track(&match, &current)) {
                            /* Same track still playing */
                            last_good_match = time(NULL);
                            vlogmsg("id", "still playing: %s — %s", artist, title);
                        }
                        /* KEY SIMPLIFICATION: If Shazam matches CDJ, accept immediately */
                        else if (have_cdj && (prolink_isrc_matches(cdj_isrc, isrc) ||
                                              prolink_matches_fingerprint(cdj_title, cdj_artist, title, artist))) {
                            /* ISRC match = 100%, otherwise use skew confidence + CDJ bonus */
                            int confidence = prolink_isrc_matches(cdj_isrc, isrc) ? 100 : (shazam_confidence + 10 > 100 ? 100 : shazam_confidence + 10);
                            vlogmsg("id", "Shazam+CDJ agree: %s — %s (%d%%)", artist, title, confidence);
                            current = match;
                            last_good_match = time(NULL);
                            record_match(app, artist, title, isrc, confidence, "both");
                            pending.valid = 0;
                            pending_confirms = 0;
                            shazam_fails = 0;
                        }
                        /* Same as pending? Confirm it */
                        else if (pending.valid && same_track(&match, &pending)) {
                            pending_confirms++;
                            vlogmsg("id", "confirming: %s — %s (%d/2)", artist, title, pending_confirms);
                            
                            pthread_mutex_lock(&app->db_mu);
                            snprintf(app->shazam_candidate, sizeof(app->shazam_candidate), "%s — %s", artist, title);
                            app->shazam_confirms = pending_confirms;
                            app->shazam_confidence = shazam_confidence;
                            pthread_mutex_unlock(&app->db_mu);
                            atomic_store_explicit(&app->shazam_state, SHAZAM_CONFIRMING, memory_order_release);

                            if (pending_confirms >= 2) {
                                current = match;
                                last_good_match = time(NULL);
                                record_match(app, artist, title, isrc, shazam_confidence, "audio");
                                pending.valid = 0;
                                pending_confirms = 0;
                            }
                        }
                        /* New candidate */
                        else {
                            pending = match;
                            pending_confirms = 1;
                            vlogmsg("id", "candidate: %s — %s (need confirm)", artist, title);
                            
                            pthread_mutex_lock(&app->db_mu);
                            snprintf(app->shazam_candidate, sizeof(app->shazam_candidate), "%s — %s", artist, title);
                            app->shazam_confirms = 1;
                            app->shazam_confidence = shazam_confidence;
                            app->shazam_no_match_count = 0;
                            pthread_mutex_unlock(&app->db_mu);
                            atomic_store_explicit(&app->shazam_state, SHAZAM_CONFIRMING, memory_order_release);
                        }
                    } else {
                        /* Shazam returned no track */
                        shazam_fails++;
                        logmsg("id", "no track in response (%d/3)", shazam_fails);
                        goto try_cdj_fallback;
                    }
                } else {
                    /* Shazam API error */
                    shazam_fails++;
                    logmsg("id", "shazam error (%d/3)", shazam_fails);
                    goto try_cdj_fallback;
                }
                goto done_fingerprint;

            try_cdj_fallback:
                /* After 3 Shazam failures, trust CDJ */
                pthread_mutex_lock(&app->db_mu);
                app->shazam_no_match_count = shazam_fails;
                pthread_mutex_unlock(&app->db_mu);
                
                if (shazam_fails >= 3 && have_cdj) {
                    TrackID cdj_match = {0};
                    cdj_match.valid = 1;
                    snprintf(cdj_match.artist, sizeof(cdj_match.artist), "%s", cdj_artist);
                    snprintf(cdj_match.title, sizeof(cdj_match.title), "%s", cdj_title);
                    snprintf(cdj_match.isrc, sizeof(cdj_match.isrc), "%s", cdj_isrc);
                    cdj_match.has_isrc = cdj_isrc[0] != 0;

                    if (!current.valid || !same_track(&cdj_match, &current)) {
                        vlogmsg("id", "CDJ fallback: %s — %s (deck %d)", cdj_artist, cdj_title, cdj_deck);
                        current = cdj_match;
                        last_good_match = time(NULL);
                        record_match(app, cdj_artist, cdj_title, cdj_isrc, 70, "cdj");
                        pending.valid = 0;
                        pending_confirms = 0;
                        shazam_fails = 0;
                    } else {
                        last_good_match = time(NULL);
                    }
                } else {
                    atomic_store_explicit(&app->shazam_state, SHAZAM_NO_MATCH, memory_order_release);
                }

            done_fingerprint:
                vibra_free_fingerprint(fp);
            }
        }
    sleep_loop:
        /* Back to listening state (unless we're still confirming, matched, no_match, or error) */
        {
            int cur_state = atomic_load_explicit(&app->shazam_state, memory_order_relaxed);
            if (cur_state != SHAZAM_CONFIRMING && cur_state != SHAZAM_MATCHED &&
                cur_state != SHAZAM_NO_MATCH && cur_state != SHAZAM_ERROR) {
                atomic_store_explicit(&app->shazam_state, SHAZAM_LISTENING, memory_order_release);
            }
        }

        for (unsigned s = 0; s < cfg->identify_interval_sec && g_running; ++s) {
            struct timespec ts = {.tv_sec = 0, .tv_nsec = 200 * 1000 * 1000};
            nanosleep(&ts, NULL);
        }
    }

    logmsg("id", "exit");
    return NULL;
#endif /* HAVE_VIBRA */
}
