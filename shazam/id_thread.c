/*
 * id_thread.c - Audio fingerprint identification thread
 *
 * Monitors all configured SLink channels independently.
 * Fingerprints whichever channel(s) have music above threshold.
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

/* Get CDJ track info if available */
static int get_cdj_track(App *app, char *title, size_t tsz, char *artist, size_t asz,
                         char *isrc, size_t isz, int *deck) {
    if (!app->prolink) return -1;
    return prolink_get_playing_track(app->prolink, title, tsz, artist, asz, isrc, isz, deck);
}

/* Fingerprint one channel and process the result */
static void id_process_channel(App *app, ChannelState *cs, int ch_idx, const char *ch_name,
                               time_t *last_lookup, unsigned *shazam_backoff) {
    Config *cfg = &app->cfg;
    const size_t look_frames = cs->id_buf_frames;
    const size_t fb = cfg->channels * cfg->bytes_per_sample;
    uint8_t *window = cs->id_buf;
    int16_t *window_s16 = cs->id_buf_s16;

    size_t got = asyncwr_copy_last(&cs->aw, window, look_frames);

    /* Convert to 16-bit for RMS and vibra */
    if (cfg->bytes_per_sample == 2) {
        memcpy(window_s16, window, got * fb);
    } else if (cfg->bytes_per_sample == 3) {
        for (size_t i = 0; i < got * cfg->channels; ++i) {
            int32_t s = ((int32_t)window[i * 3 + 2] << 16) | ((int32_t)window[i * 3 + 1] << 8) | (int32_t)window[i * 3];
            if (s & 0x800000) s |= 0xFF000000;
            window_s16[i] = (int16_t)(s >> 8);
        }
    }

    unsigned r = rms_s16_interleaved(window_s16, got, cfg->channels);
    vlogmsg("id", "[%s] peek=%zu frames, rms=%u (threshold=%u)", ch_name, got, r, cfg->threshold);

    if (got == 0 || r < cfg->threshold || got < (size_t)(cfg->rate * cfg->fingerprint_sec * 3 / 4))
        return;

    time_t nowt = time(NULL);
    unsigned effective_gap = cfg->shazam_gap_sec + *shazam_backoff;
    if (*last_lookup && (unsigned)(nowt - *last_lookup) < effective_gap) {
        vlogmsg("id", "[%s] throttle: waiting %us between lookups%s",
                ch_name, effective_gap, *shazam_backoff ? " (backoff)" : "");
        return;
    }
    *last_lookup = nowt;

    atomic_store_explicit(&app->shazam_state, SHAZAM_FINGERPRINTING, memory_order_release);

    const int bytes = (int)(got * cfg->channels * sizeof(int16_t));
    Fingerprint *fp = vibra_get_fingerprint_from_signed_pcm(
        (const char *)window_s16, bytes, (int)cfg->rate, 16, (int)cfg->channels);
    if (!fp) {
        logmsg("vibra", "[%s] fingerprint failed", ch_name);
        return;
    }

    const char *uri = vibra_get_uri_from_fingerprint(fp);
    unsigned sample_ms = vibra_get_sample_ms_from_fingerprint(fp);
    char url[512];
    char body[32768];
    char json[65536];
    build_shazam_request(uri, sample_ms, cfg->timezone, url, body, sizeof(body));
    const char *ua = cfg->user_agent ? cfg->user_agent : "Dalvik/2.1.0 (Linux; U; Android 5.0.2; VS980 4G Build/LRX22G)";

    atomic_store_explicit(&app->shazam_state, SHAZAM_QUERYING, memory_order_release);

    /* Always get CDJ track info for comparison */
    char cdj_title[256] = {0}, cdj_artist[256] = {0}, cdj_isrc[64] = {0};
    int cdj_deck = 0;
    int have_cdj = (get_cdj_track(app, cdj_title, sizeof(cdj_title),
                                  cdj_artist, sizeof(cdj_artist),
                                  cdj_isrc, sizeof(cdj_isrc), &cdj_deck) == 0 && cdj_title[0]);

    struct timeval t_start, t_end;
    gettimeofday(&t_start, NULL);
    logmsg("id", "[%s] Querying Shazam...%s",
           ch_name, have_cdj ? " (CDJ has track, will compare)" : "");
    atomic_fetch_add(&app->shazam_queries, 1);
    int post_ok = shazam_post(url, ua, body, json, sizeof(json));
    gettimeofday(&t_end, NULL);
    int query_ms = (int)((t_end.tv_sec - t_start.tv_sec) * 1000 +
                         (t_end.tv_usec - t_start.tv_usec) / 1000);

    if (post_ok == 0) {
        vlogmsg("id", "[%s] shazam response (%dms): %.500s", ch_name, query_ms, json);

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

        double max_skew = ts_abs > fs_abs ? ts_abs : fs_abs;
        int shazam_confidence = (int)(100.0 - max_skew * 1500.0);
        if (shazam_confidence < 40) shazam_confidence = 40;
        if (shazam_confidence > 100) shazam_confidence = 100;
        vlogmsg("id", "[%s] shazam skew: ts=%.4f fs=%.4f → %d%%",
                ch_name, timeskew, freqskew, shazam_confidence);

        if (title[0] || artist[0]) {
            logmsg("id", "[%s] Shazam result (%dms): %s — %s (%d%%)",
                   ch_name, query_ms, artist, title, shazam_confidence);
            atomic_fetch_add(&app->shazam_matches, 1);
            *shazam_backoff = 0;

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
                                      artist, title, isrc, 0);
                    matched_deck = di;
                    break;
                }
            }

            if (matched_deck >= 0) {
                deck_confidence_t ds;
                confidence_get_deck(matched_deck, &ds);
                if (ds.signals_seen & SIG_SHAZAM_MATCH) {
                    confidence_signal(matched_deck, SIG_SHAZAM_CONFIRM, shazam_confidence,
                                      artist, title, isrc, 0);
                } else {
                    confidence_signal(matched_deck, SIG_SHAZAM_MATCH, shazam_confidence,
                                      artist, title, isrc, 0);
                }
            } else if (!have_cdj) {
                /* Audio-only mode */
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
                deck_confidence_t audio_state;
                confidence_get_audio(&audio_state);
                int shazam_is_consistent = audio_state.title[0] &&
                    prolink_matches_fingerprint(audio_state.title, audio_state.artist,
                                                title, artist);

                if (shazam_is_consistent) {
                    int best = confidence_best_deck();
                    if (best >= 0) {
                        confidence_signal(best, SIG_SHAZAM_DISAGREE,
                                          shazam_confidence,
                                          NULL, NULL, NULL, 0);
                    }
                }

                if (shazam_is_consistent) {
                    confidence_signal(-1, SIG_SHAZAM_CONFIRM, shazam_confidence,
                                      artist, title, isrc, 0);
                } else {
                    confidence_signal(-1, SIG_SHAZAM_MATCH, shazam_confidence,
                                      artist, title, isrc, 0);
                }
            }
        } else {
            if (*shazam_backoff < 10) *shazam_backoff += 5;
            logmsg("id", "[%s] Shazam: no match (%dms)", ch_name, query_ms);
            confidence_signal(-1, SIG_SHAZAM_NO_MATCH, 0, NULL, NULL, NULL, 0);
        }
    } else {
        *shazam_backoff = (*shazam_backoff < 30) ? *shazam_backoff + 30 :
                          (*shazam_backoff < 120) ? *shazam_backoff * 2 : 300;
        logmsg("id", "[%s] Shazam error (%dms, backoff %us)",
               ch_name, query_ms, *shazam_backoff);
    }

    vibra_free_fingerprint(fp);
}
#endif /* HAVE_VIBRA */

void *id_main(void *arg) {
    App *app = (App *)arg;
    Config *cfg = &app->cfg;

#ifndef HAVE_VIBRA
    logmsg("id", "WARNING: libvibra not available, audio fingerprinting disabled");
    logmsg("id", "Use --cdj-tag for CDJ-only track identification");
    atomic_store_explicit(&app->shazam_state, SHAZAM_DISABLED, memory_order_release);
    while (g_running) {
        struct timespec ts = {.tv_sec = 1, .tv_nsec = 0};
        nanosleep(&ts, NULL);
    }
    return NULL;
#else
    const int nch = cfg->slink_channel_count;

    logmsg("id", "started: fingerprint=%us interval=%us threshold=%u channels=%d",
           cfg->fingerprint_sec, cfg->identify_interval_sec, cfg->threshold, nch);

    /* Per-channel Shazam state */
    time_t last_lookup[SLINK_MAX_CHANNELS] = {0};
    unsigned shazam_backoff[SLINK_MAX_CHANNELS] = {0};

    atomic_store_explicit(&app->shazam_state, SHAZAM_LISTENING, memory_order_release);

    while (g_running) {
        /* Check each channel — fingerprint whichever has music */
        for (int c = 0; c < nch; c++) {
            if (!app->ch[c].id_buf) continue;
            id_process_channel(app, &app->ch[c], c, cfg->slink_channels[c].name,
                               &last_lookup[c], &shazam_backoff[c]);
        }

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
