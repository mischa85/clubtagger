/*
 * id_thread.c - Audio fingerprint identification thread
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
    TrackID current = {0};
    TrackID pending = {0};
    int pending_confirms = 0;
    int pending_confidence = 0;  /* Accumulated confidence for pending track */
    int shazam_attempts = 0;     /* Count unconfirmed Shazam attempts before CDJ fallback */

    /* Confidence thresholds */
    const int MIN_CONFIDENCE = 60;      /* Minimum % to accept a match */
    const int CDJ_BONUS = 15;           /* Bonus for CDJ confirmation */
    const int CDJ_ONLY_CONFIDENCE = 70; /* Confidence for CDJ-only matches */

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

                if (shazam_post(url, ua, body, json, sizeof(json)) == 0) {
                    vlogmsg("id", "shazam response: %.500s", json);

                    /* Count number of matches - more matches = more ambiguous */
                    int match_count = 0;
                    const char *mp = json;
                    while ((mp = strstr(mp, "\"id\":\"")) != NULL) {
                        match_count++;
                        mp += 6;
                    }

                    /* Check match quality via skew values */
                    char timeskew_str[64] = {0}, freqskew_str[64] = {0};
                    json_extract_field(json, "timeskew", timeskew_str, sizeof(timeskew_str));
                    json_extract_field(json, "frequencyskew", freqskew_str, sizeof(freqskew_str));
                    double timeskew = timeskew_str[0] ? atof(timeskew_str) : 999;
                    double freqskew = freqskew_str[0] ? atof(freqskew_str) : 999;
                    double ts_abs = timeskew < 0 ? -timeskew : timeskew;
                    double fs_abs = freqskew < 0 ? -freqskew : freqskew;

                    /* Calculate confidence from Shazam skew values
                     * Lower skew = higher confidence
                     * Formula: 100 - (max_skew * 1500)
                     *   0.00 skew = 100%
                     *   0.01 skew = 85%
                     *   0.03 skew = 55%
                     *   0.05 skew = 25%
                     *   0.067+ skew = 0%
                     * Penalty for multiple matches: -5% per extra match */
                    double max_skew = ts_abs > fs_abs ? ts_abs : fs_abs;
                    int shazam_confidence = (int)(100.0 - max_skew * 1500.0);
                    shazam_confidence -= (match_count - 1) * 5;  /* Ambiguity penalty */
                    if (shazam_confidence < 0) shazam_confidence = 0;
                    if (shazam_confidence > 100) shazam_confidence = 100;

                    vlogmsg("id", "shazam confidence: %d%% (ts=%.4f fs=%.4f matches=%d)", 
                           shazam_confidence, ts_abs, fs_abs, match_count);

                    char title[256] = {0}, artist[256] = {0}, isrc[64] = {0};
                    json_extract_field(json, "title", title, sizeof(title));
                    json_extract_field(json, "subtitle", artist, sizeof(artist));
                    if (!artist[0]) json_extract_field(json, "artist", artist, sizeof(artist));
                    json_extract_field(json, "isrc", isrc, sizeof(isrc));

                    if (title[0] || artist[0] || isrc[0]) {
                        TrackID match = {0};
                        match.valid = 1;
                        snprintf(match.isrc, sizeof(match.isrc), "%s", isrc);
                        snprintf(match.artist, sizeof(match.artist), "%s", artist);
                        snprintf(match.title, sizeof(match.title), "%s", title);
                        match.has_isrc = isrc[0] != 0;

                        if (current.valid && same_track(&match, &current)) {
                            /* Same track still playing */
                            last_good_match = time(NULL);
                            vlogmsg("id", "still playing: %s — %s (%d%%)", artist, title, shazam_confidence);
                        } else {
                            /* All matches require confirmation to reduce false positives
                             * This is especially important for vinyl where Shazam may return
                             * multiple candidate matches and pick the wrong one */
                            if (pending.valid && same_track(&match, &pending)) {
                                pending_confirms++;
                                /* Accumulate confidence: weighted average favoring recent */
                                pending_confidence = (pending_confidence + shazam_confidence * 2) / 3;
                                vlogmsg("id", "confirming: %s — %s (%d/3, %d%%)", artist, title, pending_confirms, pending_confidence);

                                /* Update state: confirming with candidate info */
                                pthread_mutex_lock(&app->db_mu);
                                snprintf(app->shazam_candidate, sizeof(app->shazam_candidate), "%s — %s", artist, title);
                                app->shazam_confirms = pending_confirms;
                                app->shazam_confidence = pending_confidence;
                                pthread_mutex_unlock(&app->db_mu);
                                atomic_store_explicit(&app->shazam_state, SHAZAM_CONFIRMING, memory_order_release);

                                if (pending_confirms >= 3) {
                                    /* Check CDJ for confirmation boost */
                                    char cdj_title[256] = {0}, cdj_artist[256] = {0};
                                    int cdj_deck = 0;
                                    const char *source = "audio";
                                    int final_confidence = pending_confidence;
                                    if (app->prolink && prolink_get_playing_track(app->prolink, 
                                                                                   cdj_title, sizeof(cdj_title),
                                                                                   cdj_artist, sizeof(cdj_artist),
                                                                                   &cdj_deck) == 0) {
                                        if (prolink_matches_fingerprint(cdj_title, cdj_artist, title, artist)) {
                                            source = "both";
                                            final_confidence += CDJ_BONUS;
                                            if (final_confidence > 100) final_confidence = 100;
                                            vlogmsg("id", "CDJ confirms: deck %d playing %s - %s (+%d%%)", cdj_deck, cdj_artist, cdj_title, CDJ_BONUS);
                                        } else {
                                            vlogmsg("id", "CDJ mismatch: deck %d playing %s - %s vs fingerprint %s - %s", 
                                                   cdj_deck, cdj_artist, cdj_title, artist, title);
                                        }
                                    }
                                    
                                    /* Reject if below threshold after confirmations */
                                    if (final_confidence < MIN_CONFIDENCE) {
                                        vlogmsg("id", "rejecting after confirms: %d%% < %d%% threshold", final_confidence, MIN_CONFIDENCE);
                                        pending.valid = 0;
                                        pending_confirms = 0;
                                        pending_confidence = 0;
                                    } else {
                                        current = match;
                                        last_good_match = time(NULL);
                                        char tsbuf[64];
                                        now_timestamp(tsbuf, sizeof(tsbuf));
                                        if (match.has_isrc)
                                            logmsg("id", "%s MATCH: %s — %s [ISRC %s] (%d%%, %s)", tsbuf, artist, title, isrc, final_confidence, source);
                                        else
                                            logmsg("id", "%s MATCH: %s — %s (%d%%, %s)", tsbuf, artist, title, final_confidence, source);
                                        db_insert_play(app, tsbuf, artist, title, isrc, final_confidence, source);
                                        /* Notify SSE server of track change */
                                        pthread_mutex_lock(&app->db_mu);
                                        snprintf(app->last_artist, sizeof(app->last_artist), "%s", artist);
                                        snprintf(app->last_title, sizeof(app->last_title), "%s", title);
                                        snprintf(app->last_source, sizeof(app->last_source), "%s", source);
                                        snprintf(app->last_isrc, sizeof(app->last_isrc), "%s", isrc);
                                        app->last_confidence = final_confidence;
                                        app->shazam_candidate[0] = '\0';
                                        app->shazam_confirms = 0;
                                        app->shazam_no_match_count = 0;
                                        pthread_mutex_unlock(&app->db_mu);
                                        atomic_store_explicit(&app->shazam_state, SHAZAM_MATCHED, memory_order_release);
                                        atomic_fetch_add_explicit(&app->track_seq, 1, memory_order_release);
                                        pending.valid = 0;
                                        pending_confirms = 0;
                                        pending_confidence = 0;
                                        shazam_attempts = 0;
                                    }
                                }
                            } else {
                                /* New candidate - different from pending, count as unconfirmed attempt */
                                shazam_attempts++;
                                pthread_mutex_lock(&app->db_mu);
                                app->shazam_no_match_count = shazam_attempts;
                                pthread_mutex_unlock(&app->db_mu);
                                
                                pending = match;
                                pending_confirms = 1; /* first sighting counts as 1 */
                                pending_confidence = shazam_confidence;
                                vlogmsg("id", "candidate: %s — %s (need 3 confirms, %d%%, attempt %d/5)", artist, title, shazam_confidence, shazam_attempts);

                                /* Update state: new candidate */
                                pthread_mutex_lock(&app->db_mu);
                                snprintf(app->shazam_candidate, sizeof(app->shazam_candidate), "%s — %s", artist, title);
                                app->shazam_confirms = 1;
                                app->shazam_confidence = shazam_confidence;
                                pthread_mutex_unlock(&app->db_mu);
                                atomic_store_explicit(&app->shazam_state, SHAZAM_CONFIRMING, memory_order_release);
                                
                                /* Check if we should fall back to CDJ after many unconfirmed attempts */
                                if (app->prolink && shazam_attempts >= 5) {
                                    char cdj_title[256] = {0}, cdj_artist[256] = {0};
                                    int cdj_deck = 0;
                                    if (prolink_get_playing_track(app->prolink,
                                                                  cdj_title, sizeof(cdj_title),
                                                                  cdj_artist, sizeof(cdj_artist),
                                                                  &cdj_deck) == 0 && cdj_title[0]) {
                                        /* CDJ has a track - use it instead of unreliable Shazam */
                                        vlogmsg("id", "Shazam unreliable after %d attempts, using CDJ: %s — %s", shazam_attempts, cdj_artist, cdj_title);
                                        pending.valid = 1;
                                        snprintf(pending.artist, sizeof(pending.artist), "%s", cdj_artist);
                                        snprintf(pending.title, sizeof(pending.title), "%s", cdj_title);
                                        pending_confirms = 1;
                                        pending_confidence = CDJ_ONLY_CONFIDENCE;
                                        /* Update UI to show CDJ candidate */
                                        pthread_mutex_lock(&app->db_mu);
                                        snprintf(app->shazam_candidate, sizeof(app->shazam_candidate), "%s — %s", cdj_artist, cdj_title);
                                        app->shazam_confirms = 1;
                                        app->shazam_confirms_needed = 2;
                                        app->shazam_confidence = CDJ_ONLY_CONFIDENCE;
                                        app->shazam_cdj_confirmed = 1;
                                        pthread_mutex_unlock(&app->db_mu);
                                    }
                                }
                            }
                        }
                    } else {
                        shazam_attempts++;
                        pthread_mutex_lock(&app->db_mu);
                        app->shazam_no_match_count = shazam_attempts;
                        pthread_mutex_unlock(&app->db_mu);
                        logmsg("id", "no track in response (attempt %d/5)", shazam_attempts);
                        int cdj_handled = 0;
                        /* Try CDJ fallback after several Shazam attempts fail */
                        if (app->prolink && shazam_attempts >= 5) {
                            char cdj_title[256] = {0}, cdj_artist[256] = {0};
                            int cdj_deck = 0;
                            if (prolink_get_playing_track(app->prolink,
                                                          cdj_title, sizeof(cdj_title),
                                                          cdj_artist, sizeof(cdj_artist),
                                                          &cdj_deck) == 0 && cdj_title[0]) {
                                cdj_handled = 1;
                                /* Use CDJ info as fallback */
                                TrackID cdj_match = {0};
                                cdj_match.valid = 1;
                                snprintf(cdj_match.artist, sizeof(cdj_match.artist), "%s", cdj_artist);
                                snprintf(cdj_match.title, sizeof(cdj_match.title), "%s", cdj_title);
                                
                                if (!current.valid || !same_track(&cdj_match, &current)) {
                                    /* New track from CDJ */
                                    if (pending.valid && same_track(&cdj_match, &pending)) {
                                        pending_confirms++;
                                        vlogmsg("id", "CDJ confirming: %s — %s (%d/2)", cdj_artist, cdj_title, pending_confirms);
                                        if (pending_confirms >= 2) {  /* CDJ-only needs fewer confirms */
                                            current = cdj_match;
                                            last_good_match = time(NULL);
                                            char tsbuf[64];
                                            now_timestamp(tsbuf, sizeof(tsbuf));
                                            logmsg("id", "%s MATCH: %s — %s (%d%%, cdj)", tsbuf, cdj_artist, cdj_title, CDJ_ONLY_CONFIDENCE);
                                            db_insert_play(app, tsbuf, cdj_artist, cdj_title, "", CDJ_ONLY_CONFIDENCE, "cdj");
                                            pthread_mutex_lock(&app->db_mu);
                                            snprintf(app->last_artist, sizeof(app->last_artist), "%s", cdj_artist);
                                            snprintf(app->last_title, sizeof(app->last_title), "%s", cdj_title);
                                            snprintf(app->last_source, sizeof(app->last_source), "cdj");
                                            app->last_confidence = CDJ_ONLY_CONFIDENCE;
                                            app->last_isrc[0] = '\0';
                                            app->shazam_candidate[0] = '\0';
                                            app->shazam_confirms = 0;
                                            pthread_mutex_unlock(&app->db_mu);
                                            atomic_store_explicit(&app->shazam_state, SHAZAM_MATCHED, memory_order_release);
                                            atomic_fetch_add_explicit(&app->track_seq, 1, memory_order_release);
                                            pending.valid = 0;
                                            pending_confirms = 0;
                                            pending_confidence = 0;
                                            shazam_attempts = 0;
                                        }
                                    } else {
                                        pending = cdj_match;
                                        pending_confirms = 1;
                                        pending_confidence = CDJ_ONLY_CONFIDENCE;
                                        vlogmsg("id", "CDJ candidate: %s — %s (deck %d)", cdj_artist, cdj_title, cdj_deck);
                                        /* Show as confirming state */
                                        pthread_mutex_lock(&app->db_mu);
                                        snprintf(app->shazam_candidate, sizeof(app->shazam_candidate), "%s — %s", cdj_artist, cdj_title);
                                        app->shazam_confirms = 1;
                                        app->shazam_confirms_needed = 2;
                                        app->shazam_confidence = CDJ_ONLY_CONFIDENCE;
                                        app->shazam_cdj_confirmed = 1;
                                        pthread_mutex_unlock(&app->db_mu);
                                        atomic_store_explicit(&app->shazam_state, SHAZAM_CONFIRMING, memory_order_release);
                                    }
                                } else {
                                    /* Same track still playing */
                                    last_good_match = time(NULL);
                                    vlogmsg("id", "CDJ still playing: %s — %s", cdj_artist, cdj_title);
                                }
                            }
                        }
                        /* Show NO_MATCH briefly if neither Shazam nor CDJ found anything */
                        if (!cdj_handled) {
                            atomic_store_explicit(&app->shazam_state, SHAZAM_NO_MATCH, memory_order_release);
                        }
                    }
                } else {
                    shazam_attempts++;
                    pthread_mutex_lock(&app->db_mu);
                    app->shazam_no_match_count = shazam_attempts;
                    pthread_mutex_unlock(&app->db_mu);
                    logmsg("id", "recognize: empty (attempt %d/5)", shazam_attempts);
                    int cdj_handled = 0;
                    /* Try CDJ fallback after several Shazam attempts fail */
                    if (app->prolink && shazam_attempts >= 5) {
                        char cdj_title[256] = {0}, cdj_artist[256] = {0};
                        int cdj_deck = 0;
                        if (prolink_get_playing_track(app->prolink,
                                                      cdj_title, sizeof(cdj_title),
                                                      cdj_artist, sizeof(cdj_artist),
                                                      &cdj_deck) == 0 && cdj_title[0]) {
                            cdj_handled = 1;
                            TrackID cdj_match = {0};
                            cdj_match.valid = 1;
                            snprintf(cdj_match.artist, sizeof(cdj_match.artist), "%s", cdj_artist);
                            snprintf(cdj_match.title, sizeof(cdj_match.title), "%s", cdj_title);
                            
                            if (!current.valid || !same_track(&cdj_match, &current)) {
                                if (pending.valid && same_track(&cdj_match, &pending)) {
                                    pending_confirms++;
                                    vlogmsg("id", "CDJ confirming (API fail): %s — %s (%d/2)", cdj_artist, cdj_title, pending_confirms);
                                    if (pending_confirms >= 2) {
                                        current = cdj_match;
                                        last_good_match = time(NULL);
                                        char tsbuf[64];
                                        now_timestamp(tsbuf, sizeof(tsbuf));
                                        logmsg("id", "%s MATCH: %s — %s (%d%%, cdj)", tsbuf, cdj_artist, cdj_title, CDJ_ONLY_CONFIDENCE);
                                        db_insert_play(app, tsbuf, cdj_artist, cdj_title, "", CDJ_ONLY_CONFIDENCE, "cdj");
                                        pthread_mutex_lock(&app->db_mu);
                                        snprintf(app->last_artist, sizeof(app->last_artist), "%s", cdj_artist);
                                        snprintf(app->last_title, sizeof(app->last_title), "%s", cdj_title);
                                        snprintf(app->last_source, sizeof(app->last_source), "cdj");
                                        app->last_confidence = CDJ_ONLY_CONFIDENCE;
                                        app->last_isrc[0] = '\0';
                                        app->shazam_candidate[0] = '\0';
                                        app->shazam_confirms = 0;
                                        pthread_mutex_unlock(&app->db_mu);
                                        atomic_store_explicit(&app->shazam_state, SHAZAM_MATCHED, memory_order_release);
                                        atomic_fetch_add_explicit(&app->track_seq, 1, memory_order_release);
                                        pending.valid = 0;
                                        pending_confirms = 0;
                                        pending_confidence = 0;
                                        shazam_attempts = 0;
                                        app->shazam_no_match_count = 0;
                                    }
                                } else {
                                    pending = cdj_match;
                                    pending_confirms = 1;
                                    pending_confidence = CDJ_ONLY_CONFIDENCE;
                                    vlogmsg("id", "CDJ candidate (API fail): %s — %s (deck %d)", cdj_artist, cdj_title, cdj_deck);
                                    pthread_mutex_lock(&app->db_mu);
                                    snprintf(app->shazam_candidate, sizeof(app->shazam_candidate), "%s — %s", cdj_artist, cdj_title);
                                    app->shazam_confirms = 1;
                                    app->shazam_confirms_needed = 2;
                                    app->shazam_confidence = CDJ_ONLY_CONFIDENCE;
                                    app->shazam_cdj_confirmed = 1;
                                    pthread_mutex_unlock(&app->db_mu);
                                    atomic_store_explicit(&app->shazam_state, SHAZAM_CONFIRMING, memory_order_release);
                                }
                            } else {
                                last_good_match = time(NULL);
                            }
                        }
                    }
                    /* Show ERROR briefly if neither Shazam nor CDJ found anything */
                    if (!cdj_handled) {
                        atomic_store_explicit(&app->shazam_state, SHAZAM_ERROR, memory_order_release);
                    }
                }
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
