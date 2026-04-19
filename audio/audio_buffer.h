/*
 * audio_buffer.h - Audio buffer management and file I/O
 */
#ifndef CLUBTAGGER_AUDIO_BUFFER_H
#define CLUBTAGGER_AUDIO_BUFFER_H

#include "types.h"
#include <time.h>

/* Ensure directory exists (mkdir -p style, single level only) */
void ensure_dir(const char *path);

/* Build a filename for audio output.
 * channel: if non-NULL and non-empty, inserted as {prefix}_{channel}_{date}_{time}.{ext} */
void build_audio_filename(char *out, size_t out_sz, const char *outdir,
                          const char *prefix, const char *channel,
                          const char *ext, time_t ts);

/* Write AudioBuffer to WAV file atomically. Returns file size in bytes, or -1 on error. */
int64_t audiobuf_write_wav(const AudioBuffer *ab, const char *outdir, const char *prefix);

#ifdef HAVE_FLAC
/* Write AudioBuffer to FLAC file atomically. Returns file size in bytes, or -1 on error. */
int64_t audiobuf_write_flac(const AudioBuffer *ab, const char *outdir, const char *prefix);
#endif

/* Write AudioBuffer to file (WAV or FLAC based on format). Returns file size in bytes, or -1 on error. */
int64_t audiobuf_write(const AudioBuffer *ab, const char *outdir, const char *prefix, const char *format);

/* ─────────────────────────────────────────────────────────────────────────────
 * Ring-buffer-aware writing (no intermediate copy)
 * ───────────────────────────────────────────────────────────────────────────── */

/* Write directly from a ring buffer to WAV file. Returns file size or -1. */
int64_t audiobuf_write_wav_ring(const uint8_t *ring, size_t ring_capacity,
                                size_t ring_start, size_t nframes,
                                unsigned channels, unsigned rate, int bytes_per_sample,
                                const char *outdir, const char *prefix, time_t start_time);

#ifdef HAVE_FLAC
/* Write directly from a ring buffer to FLAC file.
 * flac_buf/flac_buf_samples: pre-allocated int32 conversion buffer.
 * Returns file size or -1. */
int64_t audiobuf_write_flac_ring(const uint8_t *ring, size_t ring_capacity,
                                 size_t ring_start, size_t nframes,
                                 unsigned channels, unsigned rate, int bytes_per_sample,
                                 int32_t *flac_buf, size_t flac_buf_samples,
                                 const char *outdir, const char *prefix, time_t start_time);
#endif

/* Write from ring buffer (WAV or FLAC based on format). Returns file size or -1. */
int64_t audiobuf_write_ring(const uint8_t *ring, size_t ring_capacity,
                            size_t ring_start, size_t nframes,
                            unsigned channels, unsigned rate, int bytes_per_sample,
                            int32_t *flac_buf, size_t flac_buf_samples,
                            const char *outdir, const char *prefix, const char *format,
                            time_t start_time);

#endif /* CLUBTAGGER_AUDIO_BUFFER_H */
