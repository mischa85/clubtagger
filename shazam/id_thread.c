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
#include "../confidence.h"
#include "../prolink/cdj_types.h"

#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
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
    unsigned shazam_backoff = 0;  /* Extra seconds to wait after API errors */

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

        /* CDJ track stability and duration are now handled by confidence_tick() */

        /* Use same threshold as writer for "is there music" detection */
        if (got > 0 && r >= cfg->threshold && got >= (size_t)(cfg->rate * cfg->fingerprint_sec * 3 / 4)) {
            time_t nowt = time(NULL);

            /* If the best deck (or audio-only) is already accepted, skip Shazam */
            {
                int best = confidence_best_deck();
                deck_confidence_t best_state;
                if (best >= 0) confidence_get_deck(best, &best_state);
                else confidence_get_audio(&best_state);
                if (best_state.accepted &&
                    (unsigned)(nowt - best_state.accepted_at) < cfg->same_track_hold_sec) {
                    vlogmsg("id", "hold: track accepted, skipping Shazam (%us)",
                            cfg->same_track_hold_sec);
                    goto sleep_loop;
                }
            }
            unsigned effective_gap = cfg->shazam_gap_sec + shazam_backoff;
            if (last_lookup && (unsigned)(nowt - last_lookup) < effective_gap) {
                vlogmsg("id", "throttle: waiting %us between lookups%s",
                        effective_gap, shazam_backoff ? " (backoff)" : "");
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

                struct timeval t_start, t_end;
                gettimeofday(&t_start, NULL);
                logmsg("id", "Querying Shazam...%s",
                       have_cdj ? " (CDJ has track, will compare)" : "");
                int post_ok = shazam_post(url, ua, body, json, sizeof(json));
                gettimeofday(&t_end, NULL);
                int query_ms = (int)((t_end.tv_sec - t_start.tv_sec) * 1000 +
                                     (t_end.tv_usec - t_start.tv_usec) / 1000);

                if (post_ok == 0) {
                    vlogmsg("id", "shazam response (%dms): %.500s", query_ms, json);

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
                        logmsg("id", "Shazam result (%dms): %s — %s (%d%%)",
                               query_ms, artist, title, shazam_confidence);
                        shazam_backoff = 0;

                        /* Find the best matching CDJ deck for this Shazam result */
                        int matched_deck = -1;
                        for (int di = 0; di < MAX_DEVICES; di++) {
                            cdj_device_t *dd = &devices[di];
                            if (!dd->active || dd->device_type != DEVICE_TYPE_CDJ) continue;
                            if (!dd->playing || dd->track_title[0] == '\0') continue;

                            if (prolink_isrc_matches(dd->track_isrc, isrc)) {
                                confidence_signal(di, SIG_ISRC_MATCH, 0,
                                                  artist, title, isrc, 0);
                                matched_deck = di;
                                break;
                            }
                            if (prolink_matches_fingerprint(dd->track_title, dd->track_artist,
                                                            title, artist)) {
                                confidence_signal(di, SIG_FUZZY_MATCH, 0,
                                                  NULL, NULL, NULL, 0);
                                matched_deck = di;
                                break;
                            }
                        }

                        if (matched_deck >= 0) {
                            /* Shazam confirmed a CDJ deck — boost that deck */
                            confidence_signal(matched_deck, SIG_SHAZAM_MATCH, shazam_confidence,
                                              artist, title, isrc, 0);
                        } else if (!have_cdj) {
                            /* Audio-only mode — Shazam is our only source */
                            /* Check if this is a repeat (confirm) or new candidate */
                            deck_confidence_t audio_state;
                            confidence_get_audio(&audio_state);
                            if (audio_state.title[0] &&
                                prolink_matches_fingerprint(audio_state.title, audio_state.artist,
                                                            title, artist)) {
                                confidence_signal(-1, SIG_SHAZAM_CONFIRM, shazam_confidence,
                                                  artist, title, isrc, 0);
                            } else {
                                confidence_signal(-1, SIG_SHAZAM_MATCH, shazam_confidence,
                                                  artist, title, isrc, 0);
                            }
                        } else {
                            /* Shazam disagrees with all CDJ decks.
                             * Only penalize CDJ if Shazam is being consistent
                             * (same track returned twice = audio-only has confirms).
                             * Random different tracks each time = Shazam doesn't
                             * know the track, don't punish CDJ for that. */
                            deck_confidence_t audio_state;
                            confidence_get_audio(&audio_state);
                            int shazam_is_consistent = audio_state.title[0] &&
                                prolink_matches_fingerprint(audio_state.title, audio_state.artist,
                                                            title, artist);

                            if (shazam_is_consistent && shazam_confidence >= 60) {
                                /* Shazam keeps saying the same different track with
                                 * decent confidence — penalize CDJ deck */
                                int best = confidence_best_deck();
                                if (best >= 0) {
                                    confidence_signal(best, SIG_SHAZAM_DISAGREE,
                                                      shazam_confidence,
                                                      NULL, NULL, NULL, 0);
                                }
                            }

                            /* Feed Shazam result to audio-only slot */
                            if (shazam_is_consistent) {
                                confidence_signal(-1, SIG_SHAZAM_CONFIRM, shazam_confidence,
                                                  artist, title, isrc, 0);
                            } else {
                                confidence_signal(-1, SIG_SHAZAM_MATCH, shazam_confidence,
                                                  artist, title, isrc, 0);
                            }
                        }
                    } else {
                        /* Shazam returned no track — don't penalize CDJ decks
                         * for this; Shazam often doesn't know niche/underground
                         * tracks. Only penalize the audio-only slot. */
                        if (shazam_backoff < 10) shazam_backoff += 5;
                        logmsg("id", "Shazam: no match (%dms)", query_ms);
                        confidence_signal(-1, SIG_SHAZAM_NO_MATCH, 0, NULL, NULL, NULL, 0);
                    }
                } else {
                    /* Shazam API error */
                    shazam_backoff = (shazam_backoff < 30) ? shazam_backoff + 30 :
                                    (shazam_backoff < 120) ? shazam_backoff * 2 : 300;
                    logmsg("id", "Shazam error (%dms, backoff %us)",
                           query_ms, shazam_backoff);
                }

                vibra_free_fingerprint(fp);
            }
        }
    sleep_loop:
        atomic_store_explicit(&app->shazam_state, SHAZAM_LISTENING, memory_order_release);

        for (unsigned s = 0; s < cfg->identify_interval_sec && g_running; ++s) {
            struct timespec ts = {.tv_sec = 0, .tv_nsec = 200 * 1000 * 1000};
            nanosleep(&ts, NULL);
        }
    }

    logmsg("id", "exit");
    return NULL;
#endif /* HAVE_VIBRA */
}
