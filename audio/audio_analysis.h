/*
 * audio_analysis.h - RMS and peak calculation
 */
#ifndef CLUBTAGGER_AUDIO_ANALYSIS_H
#define CLUBTAGGER_AUDIO_ANALYSIS_H

#include <stddef.h>
#include <stdint.h>

/* Calculate RMS of interleaved 16-bit samples */
unsigned rms_s16_interleaved(const int16_t *x, size_t frames, size_t channels);

/* Analyze samples: returns avg absolute value, and optionally peak value
 * All samples are little-endian (converted at capture time for SLink) */
unsigned analyze_samples(const void *data, size_t frames, size_t channels,
                         int bytes_per_sample, unsigned *peak_out);

/* Compute per-channel peak values for VU meter (stereo) */
void analyze_peaks_stereo(const void *data, size_t frames, int bytes_per_sample,
                          uint16_t *peak_left, uint16_t *peak_right);

#endif /* CLUBTAGGER_AUDIO_ANALYSIS_H */
