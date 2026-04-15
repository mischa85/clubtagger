/*
 * confidence.c - Track Confidence Accumulation Model
 *
 * Unified track identification model. Signals from CDJ, Shazam, and
 * cross-correlation accumulate into a per-deck confidence score.
 * Tracks are accepted when confidence crosses a threshold.
 */

#include "confidence.h"
#include "common.h"
#include "prolink/cdj_types.h"
#include "prolink/prolink_thread.h"

#include <string.h>
#include <stdio.h>

confidence_state_t g_confidence;

/*
 * ============================================================================
 * Init
 * ============================================================================
 */

void confidence_init(int accept_threshold, int decay_rate, int cooldown_sec)
{
    memset(&g_confidence, 0, sizeof(g_confidence));
    pthread_mutex_init(&g_confidence.mu, NULL);
    g_confidence.accept_threshold = accept_threshold > 0 ? accept_threshold : CONF_DEFAULT_ACCEPT;
    g_confidence.decay_rate = decay_rate > 0 ? decay_rate : CONF_DEFAULT_DECAY;
    g_confidence.cooldown_sec = cooldown_sec > 0 ? cooldown_sec : CONF_DEFAULT_COOLDOWN;
}

/*
 * ============================================================================
 * Internal helpers
 * ============================================================================
 */

static deck_confidence_t *get_slot(int deck_idx)
{
    if (deck_idx < 0) return &g_confidence.audio_only;
    if (deck_idx >= CONF_MAX_DECKS) return NULL;
    return &g_confidence.decks[deck_idx];
}

/* Check if a new track identity differs from what's already in the slot */
static int is_different_track(const deck_confidence_t *d,
                              const char *artist, const char *title,
                              uint32_t rekordbox_id)
{
    if (rekordbox_id > 0 && d->rekordbox_id > 0)
        return rekordbox_id != d->rekordbox_id;
    if (title && title[0] && d->title[0])
        return !prolink_matches_fingerprint(d->title, d->artist, title, artist);
    return 0; /* Can't tell — treat as same */
}

static void apply_decay(deck_confidence_t *d, time_t now)
{
    if (d->last_signal > 0 && now > d->last_signal) {
        int elapsed = (int)(now - d->last_signal);
        int decay = elapsed * g_confidence.decay_rate;
        d->score -= decay;
        if (d->score < 0) d->score = 0;
        /* Advance last_signal so decay isn't re-applied on next call */
        d->last_signal = now;
    }
}

/*
 * ============================================================================
 * Signal
 * ============================================================================
 */

void confidence_signal(int deck_idx, signal_flag_t sig, int value,
                       const char *artist, const char *title,
                       const char *isrc, uint32_t rekordbox_id)
{
    pthread_mutex_lock(&g_confidence.mu);

    deck_confidence_t *d = get_slot(deck_idx);
    if (!d) { pthread_mutex_unlock(&g_confidence.mu); return; }

    time_t now = time(NULL);
    apply_decay(d, now);

    /* If this signal brings a track identity, check for track change */
    if (title && title[0]) {
        if (d->title[0] && is_different_track(d, artist, title, rekordbox_id)) {
            if (deck_idx < 0) {
                /* Audio slot: penalize instead of hard reset.
                 * Survives brief interruptions during transitions. */
                int conf = (value > 0 && value <= 100) ? value : 70;
                int penalty = W_SHAZAM_DISAGREE * conf / 100;
                d->score += penalty; /* penalty is negative */
                if (d->score < 0) d->score = 0;
                d->shazam_flips++;
                d->last_signal = now;
                /* If score decayed to zero, clear slot for replacement */
                if (d->score == 0) {
                    uint8_t dn = d->deck_num;
                    memset(d, 0, sizeof(*d));
                    d->deck_num = dn;
                }
                pthread_mutex_unlock(&g_confidence.mu);
                return;
            }
            /* CDJ deck: hard reset — CDJ track changes are authoritative */
            uint8_t deck_num = d->deck_num;
            int flips = d->shazam_flips + 1;
            memset(d, 0, sizeof(*d));
            d->deck_num = deck_num;
            d->shazam_flips = flips;
            d->first_seen = now;
        }
        /* Update identity */
        if (artist && artist[0])
            snprintf(d->artist, sizeof(d->artist), "%s", artist);
        if (title[0])
            snprintf(d->title, sizeof(d->title), "%s", title);
        if (isrc && isrc[0])
            snprintf(d->isrc, sizeof(d->isrc), "%s", isrc);
        if (rekordbox_id > 0)
            d->rekordbox_id = rekordbox_id;
        if (d->first_seen == 0)
            d->first_seen = now;
    }

    /* Apply signal weight */
    int weight = 0;
    switch (sig) {
    case SIG_CDJ_LOADED:
        if (!(d->signals_seen & SIG_CDJ_LOADED)) {
            weight = W_CDJ_LOADED;
            if (deck_idx >= 0) {
                d->deck_num = devices[deck_idx].device_num;
                /* Reset duration clock — start counting from when we know
                 * the track identity, not from earlier unnamed playback */
                d->duration_ticks = 0;
                devices[deck_idx].play_started = devices[deck_idx].playing ? now : 0;
            }
        }
        break;
    case SIG_CDJ_PLAYING:
        if (!(d->signals_seen & SIG_CDJ_PLAYING))
            weight = W_CDJ_PLAYING;
        break;
    case SIG_CDJ_DURATION:
        /* value = play seconds; handled by tick, but can also be called directly */
        if (d->duration_ticks < DURATION_MAX_TICKS) {
            weight = W_CDJ_DURATION;
            d->duration_ticks++;
        }
        break;
    case SIG_CDJ_ON_AIR:
        if (!(d->signals_active & SIG_CDJ_ON_AIR))
            weight = W_CDJ_ON_AIR;
        break;
    case SIG_CDJ_ON_AIR_EDGE:
        if (!(d->signals_seen & SIG_CDJ_ON_AIR_EDGE))
            weight = W_CDJ_ON_AIR_EDGE;
        break;
    case SIG_SHAZAM_MATCH:
        if (!(d->signals_seen & SIG_SHAZAM_MATCH)) {
            /* Scale by Shazam confidence: 100%→full, 40%→40% of weight.
             * Also dampen by flip count — flaky Shazam results trusted less. */
            int conf = (value > 0 && value <= 100) ? value : 70;
            int flip_penalty = d->shazam_flips * 20;  /* Lose 20% per flip */
            if (flip_penalty > 80) flip_penalty = 80;  /* Never fully zero */
            weight = W_SHAZAM_MATCH * conf / 100 * (100 - flip_penalty) / 100;
            d->shazam_confidence = conf;
        }
        break;
    case SIG_SHAZAM_CONFIRM:
        {
            int conf = (value > 0 && value <= 100) ? value : 70;
            weight = W_SHAZAM_CONFIRM * conf / 100;
            d->shazam_confirms++;
            d->shazam_confidence = conf;
        }
        break;
    case SIG_ISRC_MATCH:
        if (!(d->signals_seen & SIG_ISRC_MATCH))
            weight = W_ISRC_MATCH;
        break;
    case SIG_FUZZY_MATCH:
        if (!(d->signals_seen & SIG_FUZZY_MATCH))
            weight = W_FUZZY_MATCH;
        break;
    case SIG_SHAZAM_DISAGREE:
        {
            /* Scale by Shazam confidence — low confidence disagree barely matters */
            int conf = (value > 0 && value <= 100) ? value : 70;
            weight = W_SHAZAM_DISAGREE * conf / 100;
        }
        break;
    case SIG_SHAZAM_NO_MATCH:
        weight = W_SHAZAM_NO_MATCH;
        break;
    case SIG_CDJ_OFF_AIR:
        weight = W_CDJ_OFF_AIR;
        d->signals_active &= ~(SIG_CDJ_ON_AIR | SIG_CDJ_ON_AIR_EDGE);
        break;
    default:
        break;
    }

    d->score += weight;
    if (d->score < 0) d->score = 0;
    if (d->score > CONF_MAX_SCORE) d->score = CONF_MAX_SCORE;
    if (d->score > d->peak_score) d->peak_score = d->score;

    d->signals_seen |= sig;
    if (weight > 0) d->signals_active |= sig;
    if (weight != 0) d->last_signal = now;

    /* Log significant signals to activity log */
    if (weight != 0 && d->title[0]) {
        const char *sig_name = "";
        switch (sig) {
        case SIG_CDJ_LOADED:      sig_name = "CDJ loaded"; break;
        case SIG_CDJ_PLAYING:     sig_name = "playing"; break;
        case SIG_CDJ_ON_AIR_EDGE: sig_name = "ON AIR"; break;
        case SIG_SHAZAM_MATCH:    sig_name = "Shazam match"; break;
        case SIG_SHAZAM_CONFIRM:  sig_name = "Shazam confirm"; break;
        case SIG_ISRC_MATCH:      sig_name = "ISRC match"; break;
        case SIG_FUZZY_MATCH:     sig_name = "CDJ+Shazam match"; break;
        case SIG_SHAZAM_DISAGREE: sig_name = "Shazam disagrees"; break;
        case SIG_CDJ_OFF_AIR:     sig_name = "off air"; break;
        default: break;
        }
        if (sig_name[0]) {
            logmsg("conf", "Deck %d: %s (%+d) → %d%% | %s — %s",
                   d->deck_num, sig_name, weight, d->score / 10,
                   d->artist, d->title);
        }
    }

    pthread_mutex_unlock(&g_confidence.mu);
}

/*
 * ============================================================================
 * Tick (called ~1Hz)
 * ============================================================================
 */

uint32_t confidence_tick(time_t now)
{
    uint32_t accepted_mask = 0;
    pthread_mutex_lock(&g_confidence.mu);

    for (int i = 0; i < CONF_MAX_DECKS + 1; i++) {
        deck_confidence_t *d = (i < CONF_MAX_DECKS)
            ? &g_confidence.decks[i]
            : &g_confidence.audio_only;

        if (d->score == 0 && d->title[0] == '\0') continue;

        /* Apply decay */
        apply_decay(d, now);

        /* Award duration ticks for playing CDJ decks */
        if (i < CONF_MAX_DECKS && d->title[0]) {
            cdj_device_t *dev = &devices[i];
            if (dev->active && dev->playing && !dev->playhead_stalled && dev->play_started > 0) {
                int play_secs = (int)(now - dev->play_started);
                int ticks_expected = play_secs / DURATION_TICK_SEC;
                if (ticks_expected > DURATION_MAX_TICKS)
                    ticks_expected = DURATION_MAX_TICKS;

                while (d->duration_ticks < ticks_expected) {
                    d->score += W_CDJ_DURATION;
                    if (d->score > CONF_MAX_SCORE) d->score = CONF_MAX_SCORE;
                    d->signals_seen |= SIG_CDJ_DURATION;
                    d->last_signal = now;
                    d->duration_ticks++;
                }
                if (d->score > d->peak_score) d->peak_score = d->score;
            }

            /* Clear active playing signal if deck stopped */
            if (!dev->playing && (d->signals_active & SIG_CDJ_PLAYING)) {
                d->signals_active &= ~SIG_CDJ_PLAYING;
            }
            /* Clear active on-air if deck went off-air */
            if (!dev->on_air && (d->signals_active & SIG_CDJ_ON_AIR)) {
                d->signals_active &= ~SIG_CDJ_ON_AIR;
            }
        }

        /* Check acceptance threshold — score alone decides */
        if (!d->accepted && d->score >= g_confidence.accept_threshold && d->title[0]) {
            /* Dedup: check if same track already accepted on another slot */
            int is_dup = 0;
            for (int j = 0; j < CONF_MAX_DECKS + 1; j++) {
                if (j == i) continue;
                deck_confidence_t *other = (j < CONF_MAX_DECKS)
                    ? &g_confidence.decks[j] : &g_confidence.audio_only;
                if (!other->accepted || !other->title[0]) continue;
                if (!is_different_track(other, d->artist, d->title, d->rekordbox_id)) {
                    is_dup = 1;
                    break;
                }
            }

            /* Audio slot: also check re-acceptance of same track */
            if (!is_dup && i == CONF_MAX_DECKS) {
                if (g_confidence.audio_last_title[0] &&
                    now - g_confidence.audio_last_accepted_at < 300 &&
                    !is_different_track(d, NULL, g_confidence.audio_last_title, 0)) {
                    is_dup = 1;
                }
                if (!is_dup) {
                    snprintf(g_confidence.audio_last_title,
                             sizeof(g_confidence.audio_last_title), "%s", d->title);
                    g_confidence.audio_last_accepted_at = now;
                }
            }

            d->accepted = 1;
            d->accepted_at = now;

            if (is_dup) {
                logmsg("conf", "⏭ DEDUP %s %d: %s — %s (%d%%, %s)",
                       d->deck_num == 0 ? "Audio" : "Deck",
                       d->deck_num, d->artist, d->title,
                       d->score / 10, confidence_source_string(d->signals_seen));
            } else {
                accepted_mask |= (1u << i);
                logmsg("conf", "✅ ACCEPTED %s %d: %s — %s (%d%%, %s)",
                       d->deck_num == 0 ? "Audio" : "Deck",
                       d->deck_num, d->artist, d->title,
                       d->score / 10, confidence_source_string(d->signals_seen));
            }
        }
    }

    pthread_mutex_unlock(&g_confidence.mu);
    return accepted_mask;
}

/*
 * ============================================================================
 * Queries
 * ============================================================================
 */

void confidence_get_deck(int deck_idx, deck_confidence_t *out)
{
    pthread_mutex_lock(&g_confidence.mu);
    deck_confidence_t *d = get_slot(deck_idx);
    if (d) {
        apply_decay(d, time(NULL));
        *out = *d;
    } else {
        memset(out, 0, sizeof(*out));
    }
    pthread_mutex_unlock(&g_confidence.mu);
}

void confidence_get_audio(deck_confidence_t *out)
{
    confidence_get_deck(-1, out);
}

int confidence_best_deck(void)
{
    int best = -1;
    int best_score = 0;
    pthread_mutex_lock(&g_confidence.mu);
    for (int i = 0; i < CONF_MAX_DECKS; i++) {
        deck_confidence_t *d = &g_confidence.decks[i];
        if (d->title[0] && d->score > best_score &&
            (d->signals_active & SIG_CDJ_PLAYING)) {
            best_score = d->score;
            best = i;
        }
    }
    pthread_mutex_unlock(&g_confidence.mu);
    return best;
}

void confidence_reset_deck(int deck_idx)
{
    pthread_mutex_lock(&g_confidence.mu);
    deck_confidence_t *d = get_slot(deck_idx);
    if (d) {
        uint8_t deck_num = d->deck_num;
        memset(d, 0, sizeof(*d));
        d->deck_num = deck_num;
    }
    pthread_mutex_unlock(&g_confidence.mu);
}

const char *confidence_source_string(uint32_t signals_seen)
{
    int has_cdj = signals_seen & (SIG_CDJ_LOADED | SIG_CDJ_PLAYING |
                                  SIG_CDJ_ON_AIR | SIG_CDJ_ON_AIR_EDGE |
                                  SIG_CDJ_DURATION);
    int has_audio = signals_seen & (SIG_SHAZAM_MATCH | SIG_SHAZAM_CONFIRM);
    int has_cross = signals_seen & (SIG_ISRC_MATCH | SIG_FUZZY_MATCH);

    if (has_cross || (has_cdj && has_audio))     return "both";
    if (has_audio && !has_cdj)                   return "audio";
    if (signals_seen & SIG_CDJ_ON_AIR_EDGE)      return "cdj/on-air";
    if (signals_seen & SIG_CDJ_DURATION)          return "cdj/duration";
    if (has_cdj)                                  return "cdj";
    return "unknown";
}
