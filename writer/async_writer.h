/*
 * async_writer.h - Ring buffer with async disk writes
 */
#ifndef CLUBTAGGER_ASYNC_WRITER_H
#define CLUBTAGGER_ASYNC_WRITER_H

#include "../types.h"
#include <stdint.h>
#include <time.h>

/* Initialize the async writer with ring buffer */
int asyncwr_init(AsyncWriter *aw, unsigned channels, unsigned rate,
                 int bytes_per_sample, size_t capacity_frames,
                 const char *outdir, const char *prefix, const char *format);

/* Free resources */
void asyncwr_free(AsyncWriter *aw);

/* Append samples to ring buffer (called by capture thread - LOCK-FREE) */
int asyncwr_append(AsyncWriter *aw, const uint8_t *samples, size_t nframes);

/* Get total frames ever written (monotonic position) */
size_t asyncwr_position(AsyncWriter *aw);

/* Copy last N frames for level detection / fingerprinting (LOCK-FREE) */
size_t asyncwr_copy_last(AsyncWriter *aw, void *dst, size_t nframes);

/* Write frames [from, to) to disk asynchronously.
 * channel: SLink channel name for filename (NULL = no channel suffix) */
void asyncwr_write_range(AsyncWriter *aw, size_t from, size_t to, time_t start_time,
                         const char *channel);

/* Wait for any pending async write to complete */
void asyncwr_wait_pending(AsyncWriter *aw);

#endif /* CLUBTAGGER_ASYNC_WRITER_H */
