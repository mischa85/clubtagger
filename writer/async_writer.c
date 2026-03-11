/*
 * async_writer.c - Ring buffer with async disk writes
 */
#include "async_writer.h"
#include "../audio/audio_buffer.h"
#include "../common.h"

#include <stdlib.h>
#include <string.h>

/* ─────────────────────────────────────────────────────────────────────────────
 * Internal helper
 * ───────────────────────────────────────────────────────────────────────────── */

static void asyncwr_do_write(AsyncWriter *aw, const uint8_t *data, size_t nframes,
                             size_t from, size_t to, time_t start_time) {
    AudioBuffer ab = {
        .data = (uint8_t *)data,
        .frames = nframes,
        .capacity_frames = nframes,
        .frame_bytes = aw->frame_bytes,
        .channels = aw->channels,
        .rate = aw->rate,
        .bytes_per_sample = aw->bytes_per_sample,
        .start_time = start_time,
        .flac_buf = aw->flac_buf,
        .flac_buf_samples = aw->flac_buf_samples};

    audiobuf_write(&ab, aw->outdir, aw->prefix, aw->format);
    logmsg("wrt", "wrote frames %zu-%zu (%zu frames, %.1f sec)",
           from, to, nframes, (double)nframes / aw->rate);
}

static void *asyncwr_thread_main(void *arg) {
    AsyncWriter *aw = (AsyncWriter *)arg;

    pthread_mutex_lock(&aw->mu);
    while (!aw->shutdown) {
        while (!aw->write_pending && !aw->shutdown) {
            pthread_cond_wait(&aw->cv, &aw->mu);
        }
        if (aw->shutdown && !aw->write_pending) break;

        uint8_t *data = aw->write_buf;
        size_t nframes = aw->write_frames;
        size_t from = aw->write_from;
        size_t to = aw->write_to;
        time_t start_time = aw->write_start_time;
        pthread_mutex_unlock(&aw->mu);

        if (nframes > 0) {
            asyncwr_do_write(aw, data, nframes, from, to, start_time);
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
                 const char *outdir, const char *prefix, const char *format) {
    memset(aw, 0, sizeof(*aw));

    aw->frame_bytes = channels * bytes_per_sample;
    aw->channels = channels;
    aw->rate = rate;
    aw->bytes_per_sample = bytes_per_sample;
    aw->capacity = capacity_frames;
    atomic_init(&aw->total_written, 0);

    aw->data = (uint8_t *)malloc(capacity_frames * aw->frame_bytes);
    if (!aw->data) return -1;

    /* Write buffer sized for max_file_sec worth of data */
    aw->write_buf = (uint8_t *)malloc(capacity_frames * aw->frame_bytes);
    aw->write_capacity = capacity_frames;
    if (!aw->write_buf) {
        free(aw->data);
        return -1;
    }

    /* Pre-allocate FLAC conversion buffer (capacity_frames * channels samples) */
    aw->flac_buf_samples = capacity_frames * channels;
    aw->flac_buf = (int32_t *)malloc(aw->flac_buf_samples * sizeof(int32_t));
    if (!aw->flac_buf) {
        free(aw->write_buf);
        free(aw->data);
        return -1;
    }

    aw->write_pending = 0;
    aw->outdir = outdir;
    aw->prefix = prefix;
    aw->format = format;
    aw->shutdown = 0;

    pthread_mutex_init(&aw->mu, NULL);
    pthread_cond_init(&aw->cv, NULL);

    if (pthread_create(&aw->thread, NULL, asyncwr_thread_main, aw) != 0) {
        free(aw->data);
        free(aw->write_buf);
        free(aw->flac_buf);
        pthread_mutex_destroy(&aw->mu);
        pthread_cond_destroy(&aw->cv);
        return -1;
    }
    aw->initialized = 1;

    logmsg("ring", "initialized: %.1f sec capacity (%zu frames)",
           (double)capacity_frames / rate, capacity_frames);
    return 0;
}

void asyncwr_free(AsyncWriter *aw) {
    if (!aw->initialized) return;

    pthread_mutex_lock(&aw->mu);
    aw->shutdown = 1;
    pthread_cond_signal(&aw->cv);
    pthread_mutex_unlock(&aw->mu);

    pthread_join(aw->thread, NULL);

    free(aw->data);
    free(aw->write_buf);
    free(aw->flac_buf);
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

void asyncwr_write_range(AsyncWriter *aw, size_t from, size_t to, time_t start_time) {
    /* Read total_written atomically first */
    size_t tw = atomic_load_explicit(&aw->total_written, memory_order_acquire);
    size_t head = tw % aw->capacity;

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

    size_t nframes = to - from;
    const size_t fb = aw->frame_bytes;

    /* Resize write buffer if needed */
    if (nframes > aw->write_capacity) {
        uint8_t *new_buf = (uint8_t *)realloc(aw->write_buf, nframes * fb);
        if (new_buf) {
            aw->write_buf = new_buf;
            aw->write_capacity = nframes;
        } else {
            logmsg("wrt", "ERROR: can't allocate %zu bytes for write buffer", nframes * fb);
            pthread_mutex_unlock(&aw->mu);
            return;
        }
    }

    /* Copy from ring to write buffer - safe because capture thread only writes ahead */
    size_t offset_from_head = tw - from;
    size_t start = (head + aw->capacity - offset_from_head) % aw->capacity;

    if (start + nframes <= aw->capacity) {
        memcpy(aw->write_buf, aw->data + start * fb, nframes * fb);
    } else {
        size_t first_part = aw->capacity - start;
        memcpy(aw->write_buf, aw->data + start * fb, first_part * fb);
        memcpy(aw->write_buf + first_part * fb, aw->data, (nframes - first_part) * fb);
    }

    aw->write_frames = nframes;
    aw->write_from = from;
    aw->write_to = to;
    aw->write_start_time = start_time;
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
