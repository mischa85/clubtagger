/*
 * audio_analysis.c - RMS and peak calculation
 */
#include "audio_analysis.h"
#include "../common.h"
#include <math.h>

unsigned rms_s16_interleaved(const int16_t *x, size_t frames, size_t channels) {
    if (!frames || !channels) return 0;
    const size_t N = frames * channels;
    double acc = 0.0;
    for (size_t i = 0; i < N; ++i) {
        double s = (double)x[i];
        acc += s * s;
    }
    double r = sqrt(acc / (double)N);
    if (r > 32767.0) r = 32767.0;
    return (unsigned)(r + 0.5);
}

unsigned analyze_samples(const void *data, size_t frames, size_t channels,
                         int bytes_per_sample, unsigned *peak_out) {
    if (!frames || !channels) {
        if (peak_out) *peak_out = 0;
        return 0;
    }
    const size_t N = frames * channels;
    unsigned long long acc = 0;
    unsigned peak = 0;

    if (bytes_per_sample == 2) {
        const int16_t *s16 = (const int16_t *)data;
        for (size_t i = 0; i < N; ++i) {
            unsigned v = (unsigned)(s16[i] < 0 ? -s16[i] : s16[i]);
            acc += v;
            if (v > peak) peak = v;
        }
    } else if (bytes_per_sample == 3) {
        const uint8_t *p = (const uint8_t *)data;
        for (size_t i = 0; i < N; ++i) {
            /* Little-endian 24-bit */
            int32_t s = ((int32_t)p[i * 3 + 2] << 16) | ((int32_t)p[i * 3 + 1] << 8) | (int32_t)p[i * 3];
            if (s & 0x800000) s |= 0xFF000000;
            int16_t s16 = (int16_t)(s >> 8);
            unsigned v = (unsigned)(s16 < 0 ? -s16 : s16);
            acc += v;
            if (v > peak) peak = v;
        }
    }
    if (peak_out) *peak_out = peak;
    return (unsigned)(acc / N);
}

void analyze_peaks_stereo(const void *data, size_t frames, int bytes_per_sample,
                          uint16_t *peak_left, uint16_t *peak_right) {
    if (!frames) {
        *peak_left = *peak_right = 0;
        return;
    }
    unsigned pl = 0, pr = 0;

    if (bytes_per_sample == 2) {
        const int16_t *s16 = (const int16_t *)data;
        for (size_t i = 0; i < frames; ++i) {
            unsigned vl = (unsigned)(s16[i * 2] < 0 ? -s16[i * 2] : s16[i * 2]);
            unsigned vr = (unsigned)(s16[i * 2 + 1] < 0 ? -s16[i * 2 + 1] : s16[i * 2 + 1]);
            if (vl > pl) pl = vl;
            if (vr > pr) pr = vr;
        }
    } else if (bytes_per_sample == 3) {
        const uint8_t *p = (const uint8_t *)data;
        for (size_t i = 0; i < frames; ++i) {
            /* Left channel - little-endian 24-bit */
            int32_t sl = ((int32_t)p[i * 6 + 2] << 16) | ((int32_t)p[i * 6 + 1] << 8) | (int32_t)p[i * 6];
            if (sl & 0x800000) sl |= 0xFF000000;
            /* Right channel */
            int32_t sr = ((int32_t)p[i * 6 + 5] << 16) | ((int32_t)p[i * 6 + 4] << 8) | (int32_t)p[i * 6 + 3];
            if (sr & 0x800000) sr |= 0xFF000000;
            /* Convert to 16-bit magnitude */
            unsigned vl = (unsigned)((sl < 0 ? -sl : sl) >> 8);
            unsigned vr = (unsigned)((sr < 0 ? -sr : sr) >> 8);
            if (vl > pl) pl = vl;
            if (vr > pr) pr = vr;
        }
    }
    *peak_left = (uint16_t)(pl > 32767 ? 32767 : pl);
    *peak_right = (uint16_t)(pr > 32767 ? 32767 : pr);
}
