/*
 * async_writer.c - Ring buffer with async disk writes
 *
 * Writer thread encodes directly from the ring buffer — no intermediate
 * memcpy.  The ring data is safe for (ring_sec - max_file_sec) seconds
 * after a SPLIT, which gives ~60s of headroom vs ~10-15s encoding time.
 */
#include "async_writer.h"
#include "../audio/audio_buffer.h"
#include "../common.h"

#include <stdlib.h>
#include <string.h>

/* ─────────────────────────────────────────────────────────────────────────────
 * Internal helper — encode directly from ring
 * ───────────────────────────────────────────────────────────────────────────── */

static int64_t asyncwr_do_write(AsyncWriter *aw, size_t from, size_t to,
                                int64_t start_ms, const char *channel) {
    size_t nframes = to - from;
    size_t ring_start = from % aw->capacity;

    /* Build effective prefix with channel name */
    char eff_prefix[128];
    if (channel && channel[0]) {
        snprintf(eff_prefix, sizeof(eff_prefix), "%s_%s", aw->prefix, channel);
    } else {
        snprintf(eff_prefix, sizeof(eff_prefix), "%s", aw->prefix);
    }

    SegmentMeta meta = {
        .cursor = (uint64_t)from,
        .start_unix_ms = start_ms,
        .run_id = aw->run_id,
    };
    time_t start_time = (time_t)(start_ms / 1000);

    int64_t file_size = audiobuf_write_ring(
        aw->data, aw->capacity, ring_start, nframes,
        aw->channels, aw->rate, aw->bytes_per_sample,
        aw->flac_buf, aw->flac_buf_samples, &aw->flac_out,
        aw->outdir, eff_prefix, aw->format, start_time,
        aw->peaks.minmax ? &aw->peaks : NULL, &meta);

    logmsg("wrt", "wrote frames %zu-%zu (%zu frames, %.1f sec)",
           from, to, nframes, (double)nframes / aw->rate);
    return file_size > 0 ? file_size : 0;
}

static void *asyncwr_thread_main(void *arg) {
    AsyncWriter *aw = (AsyncWriter *)arg;

    pthread_mutex_lock(&aw->mu);
    while (!aw->shutdown) {
        while (!aw->write_pending && !aw->shutdown) {
            pthread_cond_wait(&aw->cv, &aw->mu);
        }
        if (aw->shutdown && !aw->write_pending) break;

        size_t from = aw->write_from;
        size_t to = aw->write_to;
        int64_t start_ms = aw->write_start_ms;
        char channel[32];
        memcpy(channel, aw->write_channel, sizeof(channel));
        pthread_mutex_unlock(&aw->mu);

        size_t nframes = to - from;
        if (nframes > 0) {
            /* Verify data is still in ring before encoding */
            size_t tw = atomic_load_explicit(&aw->total_written, memory_order_acquire);
            size_t oldest = (tw > aw->capacity) ? (tw - aw->capacity) : 0;
            if (from >= oldest) {
                int64_t written = asyncwr_do_write(aw, from, to, start_ms, channel);
                atomic_fetch_add_explicit(&aw->bytes_on_disk, (uint64_t)written, memory_order_relaxed);
            } else {
                logmsg("wrt", "ERROR: ring overwritten before encode (from=%zu oldest=%zu, lost %.1f sec)",
                       from, oldest, (double)(oldest - from) / aw->rate);
            }
        }

        pthread_mutex_lock(&aw->mu);
        aw->write_pending = 0;
        pthread_cond_broadcast(&aw->cv);
    }
    pthread_mutex_unlock(&aw->mu);

    logmsg("wrt", "writer thread exit");
    return NULL;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * Public API
 * ───────────────────────────────────────────────────────────────────────────── */

int asyncwr_init(AsyncWriter *aw, unsigned channels, unsigned rate,
                 int bytes_per_sample, size_t capacity_frames,
                 size_t max_write_frames,
                 const char *outdir, const char *prefix, const char *format) {
    memset(aw, 0, sizeof(*aw));

    aw->frame_bytes = channels * bytes_per_sample;
    aw->channels = channels;
    aw->rate = rate;
    aw->bytes_per_sample = bytes_per_sample;
    aw->capacity = capacity_frames;
    aw->max_write_frames = max_write_frames;
    atomic_init(&aw->total_written, 0);
    atomic_init(&aw->bytes_on_disk, 0);

    aw->data = (uint8_t *)malloc(capacity_frames * aw->frame_bytes);
    if (!aw->data) {
        logmsg("ring", "asyncwr_init: OOM for ring (%zu frames * %u bytes = %zu bytes)",
               capacity_frames, aw->frame_bytes, capacity_frames * aw->frame_bytes);
        return -1;
    }

    /* FLAC conversion buffer sized to max_write_frames (not ring capacity).
     * With 6 channels this saves gigabytes vs the old ring-sized allocation. */
    aw->flac_buf_samples = max_write_frames * channels;
    aw->flac_buf = (int32_t *)malloc(aw->flac_buf_samples * sizeof(int32_t));
    if (!aw->flac_buf) {
        logmsg("ring", "asyncwr_init: OOM for FLAC buffer (%zu samples * 4 bytes = %zu bytes)",
               aw->flac_buf_samples, aw->flac_buf_samples * sizeof(int32_t));
        free(aw->data);
        return -1;
    }

    /* In-memory FLAC output. A 24-bit stereo segment compresses to roughly
     * half its PCM size; start at 3/4 and let the encoder grow it if needed. */
    if (format && strcmp(format, "flac") == 0) {
        aw->flac_out.cap = max_write_frames * aw->frame_bytes * 3 / 4;
        if (aw->flac_out.cap < ((size_t)1 << 20)) aw->flac_out.cap = (size_t)1 << 20;
        aw->flac_out.buf = (uint8_t *)malloc(aw->flac_out.cap);
        if (!aw->flac_out.buf) {
            logmsg("ring", "asyncwr_init: OOM for FLAC output buffer (%zu MB)", aw->flac_out.cap >> 20);
            free(aw->data);
            free(aw->flac_buf);
            return -1;
        }
    }

    if (peaks_init(&aw->peaks, rate, channels, (unsigned)bytes_per_sample * 8,
                   PEAKS_DEFAULT_PPS, max_write_frames) != 0) {
        /* Not fatal: recording works without sidecars, peaks_init logged why. */
        memset(&aw->peaks, 0, sizeof(aw->peaks));
    }

    aw->write_pending = 0;
    aw->outdir = outdir;
    aw->prefix = prefix;
    aw->format = format;
    aw->shutdown = 0;

    pthread_mutex_init(&aw->mu, NULL);
    pthread_cond_init(&aw->cv, NULL);

    int prc = pthread_create(&aw->thread, NULL, asyncwr_thread_main, aw);
    if (prc != 0) {
        logmsg("ring", "asyncwr_init: pthread_create failed: %s (errno=%d)",
               strerror(prc), prc);
        peaks_free(&aw->peaks);
        free(aw->data);
        free(aw->flac_buf);
        free(aw->flac_out.buf);
        pthread_mutex_destroy(&aw->mu);
        pthread_cond_destroy(&aw->cv);
        return -1;
    }
    aw->initialized = 1;

    logmsg("ring", "initialized: %.1f sec capacity (%zu frames), max write %.1f sec (%zu frames), flac out %zu MB",
           (double)capacity_frames / rate, capacity_frames,
           (double)max_write_frames / rate, max_write_frames, aw->flac_out.cap >> 20);
    return 0;
}

void asyncwr_free(AsyncWriter *aw) {
    if (!aw->initialized) return;

    pthread_mutex_lock(&aw->mu);
    aw->shutdown = 1;
    pthread_cond_signal(&aw->cv);
    pthread_mutex_unlock(&aw->mu);

    pthread_join(aw->thread, NULL);

    peaks_free(&aw->peaks);
    free(aw->data);
    free(aw->flac_buf);
    free(aw->flac_out.buf);
    pthread_mutex_destroy(&aw->mu);
    pthread_cond_destroy(&aw->cv);
    aw->initialized = 0;
}

int asyncwr_append(AsyncWriter *aw, const uint8_t *samples, size_t nframes) {
    const size_t fb = aw->frame_bytes;
    size_t tw = atomic_load_explicit(&aw->total_written, memory_order_relaxed);
    size_t remaining = nframes;
    const uint8_t *src = samples;

    while (remaining > 0) {
        size_t head = tw % aw->capacity;
        size_t space_to_end = aw->capacity - head;
        size_t chunk = (remaining < space_to_end) ? remaining : space_to_end;

        memcpy(aw->data + head * fb, src, chunk * fb);

        tw += chunk;
        src += chunk * fb;
        remaining -= chunk;
    }

    /* Release: ensure writes visible before updating total_written */
    atomic_store_explicit(&aw->total_written, tw, memory_order_release);
    return 0;
}

size_t asyncwr_position(AsyncWriter *aw) {
    return atomic_load_explicit(&aw->total_written, memory_order_acquire);
}

size_t asyncwr_copy_last(AsyncWriter *aw, void *dst, size_t nframes) {
    /* Acquire: see all writes before this total_written */
    size_t tw = atomic_load_explicit(&aw->total_written, memory_order_acquire);
    size_t head = tw % aw->capacity;

    size_t avail = (tw < aw->capacity) ? tw : aw->capacity;
    size_t take = (avail < nframes) ? avail : nframes;

    if (take > 0) {
        const size_t fb = aw->frame_bytes;
        uint8_t *d = (uint8_t *)dst;

        /* Start position in ring: head - take (with wraparound) */
        size_t start = (head + aw->capacity - take) % aw->capacity;

        if (start + take <= aw->capacity) {
            /* No wrap */
            memcpy(d, aw->data + start * fb, take * fb);
        } else {
            /* Wrap around */
            size_t first_part = aw->capacity - start;
            memcpy(d, aw->data + start * fb, first_part * fb);
            memcpy(d + first_part * fb, aw->data, (take - first_part) * fb);
        }
    }

    return take;
}

void asyncwr_write_range(AsyncWriter *aw, size_t from, size_t to, int64_t start_ms,
                         const char *channel) {
    /* Read total_written atomically first */
    size_t tw = atomic_load_explicit(&aw->total_written, memory_order_acquire);

    pthread_mutex_lock(&aw->mu);

    /* Wait for previous write to complete */
    while (aw->write_pending && !aw->shutdown) {
        pthread_cond_wait(&aw->cv, &aw->mu);
    }
    if (aw->shutdown) {
        pthread_mutex_unlock(&aw->mu);
        return;
    }

    /* Oldest frame still in ring */
    size_t oldest = (tw > aw->capacity) ? (tw - aw->capacity) : 0;

    if (from < oldest) {
        logmsg("wrt", "WARNING: requested frames %zu-%zu but oldest is %zu (lost %zu frames)",
               from, to, oldest, oldest - from);
        from = oldest;
    }
    if (to > tw) to = tw;
    if (to <= from) {
        pthread_mutex_unlock(&aw->mu);
        return;
    }

    /* Store range for writer thread — no data copy */
    aw->write_from = from;
    aw->write_to = to;
    aw->write_start_ms = start_ms;
    if (channel && channel[0]) {
        strncpy(aw->write_channel, channel, sizeof(aw->write_channel) - 1);
        aw->write_channel[sizeof(aw->write_channel) - 1] = '\0';
    } else {
        aw->write_channel[0] = '\0';
    }
    aw->write_pending = 1;

    pthread_cond_signal(&aw->cv);
    pthread_mutex_unlock(&aw->mu);
}

void asyncwr_wait_pending(AsyncWriter *aw) {
    pthread_mutex_lock(&aw->mu);
    while (aw->write_pending) {
        pthread_cond_wait(&aw->cv, &aw->mu);
    }
    pthread_mutex_unlock(&aw->mu);
}
