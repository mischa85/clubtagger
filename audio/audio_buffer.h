/*
 * audio_buffer.h - Audio buffer management and file I/O
 */
#ifndef CLUBTAGGER_AUDIO_BUFFER_H
#define CLUBTAGGER_AUDIO_BUFFER_H

#include "types.h"
#include <time.h>

/* Ensure directory exists (mkdir -p style, single level only) */
void ensure_dir(const char *path);

/* Build a filename for audio output */
void build_audio_filename(char *out, size_t out_sz, const char *outdir,
                          const char *prefix, const char *ext, time_t ts);

/* Write AudioBuffer to WAV file atomically */
int audiobuf_write_wav(const AudioBuffer *ab, const char *outdir, const char *prefix);

#ifdef HAVE_FLAC
/* Write AudioBuffer to FLAC file atomically */
int audiobuf_write_flac(const AudioBuffer *ab, const char *outdir, const char *prefix);
#endif

/* Write AudioBuffer to file (WAV or FLAC based on format) */
int audiobuf_write(const AudioBuffer *ab, const char *outdir, const char *prefix, const char *format);

#endif /* CLUBTAGGER_AUDIO_BUFFER_H */
