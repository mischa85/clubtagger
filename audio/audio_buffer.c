/*
 * audio_buffer.c - Audio buffer management and file I/O
 */
#include "audio_buffer.h"
#include "common.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifdef HAVE_FLAC
#include <FLAC/stream_encoder.h>
#endif

/* ─────────────────────────────────────────────────────────────────────────────
 * Helper functions
 * ───────────────────────────────────────────────────────────────────────────── */

static void le16_write(uint16_t v, FILE *f) {
    uint8_t b[2] = {v & 0xff, (v >> 8) & 0xff};
    fwrite(b, 1, 2, f);
}

static void le32_write(uint32_t v, FILE *f) {
    uint8_t b[4] = {v & 0xff, (v >> 8) & 0xff, (v >> 16) & 0xff, (v >> 24) & 0xff};
    fwrite(b, 1, 4, f);
}

/* ─────────────────────────────────────────────────────────────────────────────
 * Directory and filename utilities
 * ───────────────────────────────────────────────────────────────────────────── */

void ensure_dir(const char *path) {
    if (!path || !path[0]) return;
    struct stat st;
    if (stat(path, &st) == 0) return; /* already exists */
    if (mkdir(path, 0755) != 0 && errno != EEXIST) {
        logmsg("wrt", "mkdir %s: %s", path, strerror(errno));
    }
}

void build_audio_filename(char *out, size_t out_sz, const char *outdir,
                          const char *prefix, const char *channel,
                          const char *ext, time_t ts) {
    struct tm tm;
    localtime_r(&ts, &tm);
    /* Build effective prefix: "{prefix}_{channel}" or just "{prefix}" */
    char eff[128];
    if (channel && channel[0]) {
        snprintf(eff, sizeof(eff), "%s_%s", prefix, channel);
    } else {
        snprintf(eff, sizeof(eff), "%s", prefix);
    }
    if (outdir && outdir[0]) {
        snprintf(out, out_sz, "%s/%04d%02d%02d_%02d%02d%02d_%s.%s",
                 outdir, tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                 tm.tm_hour, tm.tm_min, tm.tm_sec, eff, ext);
    } else {
        snprintf(out, out_sz, "%04d%02d%02d_%02d%02d%02d_%s.%s",
                 tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                 tm.tm_hour, tm.tm_min, tm.tm_sec, eff, ext);
    }
}

/* ─────────────────────────────────────────────────────────────────────────────
 * WAV writing
 * ───────────────────────────────────────────────────────────────────────────── */

int64_t audiobuf_write_wav(const AudioBuffer *ab, const char *outdir, const char *prefix) {
    if (!ab->data || ab->frames == 0) return -1;

    ensure_dir(outdir);

    char final_name[512], tmp_name[520];
    build_audio_filename(final_name, sizeof(final_name), outdir, prefix, NULL, "wav", ab->start_time);
    snprintf(tmp_name, sizeof(tmp_name), "%s.tmp", final_name);

    FILE *fp = fopen(tmp_name, "wb");
    if (!fp) {
        logmsg("wav", "open %s: %s", tmp_name, strerror(errno));
        return -1;
    }

    unsigned bits = ab->bytes_per_sample * 8;
    uint32_t data_bytes = (uint32_t)(ab->frames * ab->frame_bytes);
    uint16_t block_align = (uint16_t)(ab->channels * ab->bytes_per_sample);
    uint32_t byte_rate = ab->rate * block_align;

    /* Write header */
    fwrite("RIFF", 1, 4, fp);
    le32_write(36 + data_bytes, fp);
    fwrite("WAVE", 1, 4, fp);
    fwrite("fmt ", 1, 4, fp);
    le32_write(16, fp);
    le16_write(1, fp); /* PCM */
    le16_write((uint16_t)ab->channels, fp);
    le32_write(ab->rate, fp);
    le32_write(byte_rate, fp);
    le16_write(block_align, fp);
    le16_write((uint16_t)bits, fp);
    fwrite("data", 1, 4, fp);
    le32_write(data_bytes, fp);

    /* Write samples - data is already little-endian */
    fwrite(ab->data, ab->frame_bytes, ab->frames, fp);

    fflush(fp);
    int fd = fileno(fp);
    if (fd >= 0) fsync(fd);
    fclose(fp);

    if (rename(tmp_name, final_name) != 0) {
        logmsg("wav", "rename %s -> %s: %s", tmp_name, final_name, strerror(errno));
        unlink(tmp_name);
        return -1;
    }

    struct stat st;
    int64_t file_size = (stat(final_name, &st) == 0) ? (int64_t)st.st_size : (int64_t)(36 + data_bytes);

    logmsg("wav", "wrote %s (%.1f sec, %.1f MB)", final_name,
           (double)ab->frames / ab->rate, (double)file_size / (1024 * 1024));
    return file_size;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * FLAC writing
 * ───────────────────────────────────────────────────────────────────────────── */

#ifdef HAVE_FLAC
int64_t audiobuf_write_flac(const AudioBuffer *ab, const char *outdir, const char *prefix) {
    if (!ab->data || ab->frames == 0) return -1;

    ensure_dir(outdir);

    char final_name[512], tmp_name[520];
    build_audio_filename(final_name, sizeof(final_name), outdir, prefix, NULL, "flac", ab->start_time);
    snprintf(tmp_name, sizeof(tmp_name), "%s.tmp", final_name);

    FLAC__StreamEncoder *encoder = FLAC__stream_encoder_new();
    if (!encoder) {
        logmsg("flac", "encoder_new failed");
        return -1;
    }

    unsigned bits = ab->bytes_per_sample * 8;
    FLAC__stream_encoder_set_channels(encoder, ab->channels);
    FLAC__stream_encoder_set_bits_per_sample(encoder, bits);
    FLAC__stream_encoder_set_sample_rate(encoder, ab->rate);
    FLAC__stream_encoder_set_compression_level(encoder, 5); /* balanced speed/size */
    FLAC__stream_encoder_set_total_samples_estimate(encoder, ab->frames);

    FLAC__StreamEncoderInitStatus init_status =
        FLAC__stream_encoder_init_file(encoder, tmp_name, NULL, NULL);
    if (init_status != FLAC__STREAM_ENCODER_INIT_STATUS_OK) {
        logmsg("flac", "init failed: %s", FLAC__StreamEncoderInitStatusString[init_status]);
        FLAC__stream_encoder_delete(encoder);
        return -1;
    }

    /* FLAC needs samples as int32_t array - use pre-allocated buffer if available */
    size_t total_samples = ab->frames * ab->channels;
    FLAC__int32 *buffer;
    int buffer_allocated = 0;
    if (ab->flac_buf && ab->flac_buf_samples >= total_samples) {
        buffer = (FLAC__int32 *)ab->flac_buf;
    } else {
        buffer = (FLAC__int32 *)malloc(total_samples * sizeof(FLAC__int32));
        if (!buffer) {
            logmsg("flac", "oom for sample buffer");
            FLAC__stream_encoder_finish(encoder);
            FLAC__stream_encoder_delete(encoder);
            unlink(tmp_name);
            return -1;
        }
        buffer_allocated = 1;
    }

    const uint8_t *src = ab->data;
    if (ab->bytes_per_sample == 2) {
        const int16_t *s16 = (const int16_t *)src;
        for (size_t i = 0; i < total_samples; ++i) {
            buffer[i] = s16[i];
        }
    } else if (ab->bytes_per_sample == 3) {
        for (size_t i = 0; i < total_samples; ++i) {
            /* Little-endian 24-bit */
            int32_t s = ((int32_t)src[i * 3 + 2] << 16) | ((int32_t)src[i * 3 + 1] << 8) | (int32_t)src[i * 3];
            if (s & 0x800000) s |= 0xFF000000; /* sign extend */
            buffer[i] = s;
        }
    }

    /* Encode in chunks to avoid huge stack usage */
    const size_t chunk_frames = 4096;
    FLAC__bool ok = true;
    for (size_t pos = 0; pos < ab->frames && ok; pos += chunk_frames) {
        size_t frames_to_encode = (ab->frames - pos < chunk_frames) ? (ab->frames - pos) : chunk_frames;
        ok = FLAC__stream_encoder_process_interleaved(encoder, buffer + pos * ab->channels, (unsigned)frames_to_encode);
    }

    if (buffer_allocated) free(buffer);

    if (!ok) {
        logmsg("flac", "encode failed: %s", FLAC__StreamEncoderStateString[FLAC__stream_encoder_get_state(encoder)]);
        FLAC__stream_encoder_finish(encoder);
        FLAC__stream_encoder_delete(encoder);
        unlink(tmp_name);
        return -1;
    }

    FLAC__stream_encoder_finish(encoder);
    FLAC__stream_encoder_delete(encoder);

    /* Atomic rename */
    if (rename(tmp_name, final_name) != 0) {
        logmsg("flac", "rename %s -> %s: %s", tmp_name, final_name, strerror(errno));
        unlink(tmp_name);
        return -1;
    }

    /* Get actual file size */
    struct stat st;
    int64_t file_size = 0;
    if (stat(final_name, &st) == 0) file_size = (int64_t)st.st_size;

    logmsg("flac", "wrote %s (%.1f sec, %.1f MB)", final_name,
           (double)ab->frames / ab->rate, (double)file_size / (1024 * 1024));
    return file_size;
}
#endif /* HAVE_FLAC */

/* ─────────────────────────────────────────────────────────────────────────────
 * Format-agnostic writing
 * ───────────────────────────────────────────────────────────────────────────── */

int64_t audiobuf_write(const AudioBuffer *ab, const char *outdir, const char *prefix, const char *format) {
#ifdef HAVE_FLAC
    if (format && strcmp(format, "flac") == 0) {
        return audiobuf_write_flac(ab, outdir, prefix);
    }
#else
    if (format && strcmp(format, "flac") == 0) {
        logmsg("wrt", "FLAC not available, falling back to WAV");
    }
#endif
    return audiobuf_write_wav(ab, outdir, prefix);
}

/* ─────────────────────────────────────────────────────────────────────────────
 * Ring-buffer-aware writing (zero-copy from ring)
 * ───────────────────────────────────────────────────────────────────────────── */

/* Helper: write PCM data from ring buffer to FILE, handling wrap */
static void fwrite_ring(const uint8_t *ring, size_t ring_capacity, size_t frame_bytes,
                        size_t ring_start, size_t nframes, FILE *fp) {
    if (ring_start + nframes <= ring_capacity) {
        fwrite(ring + ring_start * frame_bytes, frame_bytes, nframes, fp);
    } else {
        size_t first = ring_capacity - ring_start;
        fwrite(ring + ring_start * frame_bytes, frame_bytes, first, fp);
        fwrite(ring, frame_bytes, nframes - first, fp);
    }
}

int64_t audiobuf_write_wav_ring(const uint8_t *ring, size_t ring_capacity,
                                size_t ring_start, size_t nframes,
                                unsigned channels, unsigned rate, int bytes_per_sample,
                                const char *outdir, const char *prefix, time_t start_time) {
    if (!ring || nframes == 0) return -1;

    ensure_dir(outdir);

    size_t frame_bytes = channels * bytes_per_sample;
    unsigned bits = bytes_per_sample * 8;

    char final_name[512], tmp_name[520];
    build_audio_filename(final_name, sizeof(final_name), outdir, prefix, NULL, "wav", start_time);
    snprintf(tmp_name, sizeof(tmp_name), "%s.tmp", final_name);

    FILE *fp = fopen(tmp_name, "wb");
    if (!fp) {
        logmsg("wav", "open %s: %s", tmp_name, strerror(errno));
        return -1;
    }

    uint32_t data_bytes = (uint32_t)(nframes * frame_bytes);
    uint16_t block_align = (uint16_t)(channels * bytes_per_sample);
    uint32_t byte_rate = rate * block_align;

    /* Write header */
    fwrite("RIFF", 1, 4, fp);
    le32_write(36 + data_bytes, fp);
    fwrite("WAVE", 1, 4, fp);
    fwrite("fmt ", 1, 4, fp);
    le32_write(16, fp);
    le16_write(1, fp); /* PCM */
    le16_write((uint16_t)channels, fp);
    le32_write(rate, fp);
    le32_write(byte_rate, fp);
    le16_write(block_align, fp);
    le16_write((uint16_t)bits, fp);
    fwrite("data", 1, 4, fp);
    le32_write(data_bytes, fp);

    /* Write samples directly from ring */
    fwrite_ring(ring, ring_capacity, frame_bytes, ring_start, nframes, fp);

    fflush(fp);
    int fd = fileno(fp);
    if (fd >= 0) fsync(fd);
    fclose(fp);

    if (rename(tmp_name, final_name) != 0) {
        logmsg("wav", "rename %s -> %s: %s", tmp_name, final_name, strerror(errno));
        unlink(tmp_name);
        return -1;
    }

    struct stat st;
    int64_t file_size = (stat(final_name, &st) == 0) ? (int64_t)st.st_size : (int64_t)(36 + data_bytes);

    logmsg("wav", "wrote %s (%.1f sec, %.1f MB)", final_name,
           (double)nframes / rate, (double)file_size / (1024 * 1024));
    return file_size;
}

#ifdef HAVE_FLAC
int64_t audiobuf_write_flac_ring(const uint8_t *ring, size_t ring_capacity,
                                 size_t ring_start, size_t nframes,
                                 unsigned channels, unsigned rate, int bytes_per_sample,
                                 int32_t *flac_buf, size_t flac_buf_samples,
                                 const char *outdir, const char *prefix, time_t start_time) {
    if (!ring || nframes == 0) return -1;

    size_t total_samples = nframes * channels;
    if (!flac_buf || flac_buf_samples < total_samples) {
        logmsg("flac", "flac_buf too small: need %zu, have %zu", total_samples, flac_buf_samples);
        return -1;
    }

    ensure_dir(outdir);

    size_t frame_bytes = channels * bytes_per_sample;

    char final_name[512], tmp_name[520];
    build_audio_filename(final_name, sizeof(final_name), outdir, prefix, NULL, "flac", start_time);
    snprintf(tmp_name, sizeof(tmp_name), "%s.tmp", final_name);

    FLAC__StreamEncoder *encoder = FLAC__stream_encoder_new();
    if (!encoder) {
        logmsg("flac", "encoder_new failed");
        return -1;
    }

    unsigned bits = bytes_per_sample * 8;
    FLAC__stream_encoder_set_channels(encoder, channels);
    FLAC__stream_encoder_set_bits_per_sample(encoder, bits);
    FLAC__stream_encoder_set_sample_rate(encoder, rate);
    FLAC__stream_encoder_set_compression_level(encoder, 5);
    FLAC__stream_encoder_set_total_samples_estimate(encoder, nframes);

    FLAC__StreamEncoderInitStatus init_status =
        FLAC__stream_encoder_init_file(encoder, tmp_name, NULL, NULL);
    if (init_status != FLAC__STREAM_ENCODER_INIT_STATUS_OK) {
        logmsg("flac", "init failed: %s", FLAC__StreamEncoderInitStatusString[init_status]);
        FLAC__stream_encoder_delete(encoder);
        return -1;
    }

    /* Convert ring samples to int32 — one pass, handling wrap */
    size_t rpos = ring_start;
    if (bytes_per_sample == 2) {
        for (size_t f = 0; f < nframes; f++) {
            const int16_t *s16 = (const int16_t *)(ring + rpos * frame_bytes);
            for (unsigned ch = 0; ch < channels; ch++)
                flac_buf[f * channels + ch] = s16[ch];
            if (++rpos >= ring_capacity) rpos = 0;
        }
    } else if (bytes_per_sample == 3) {
        for (size_t f = 0; f < nframes; f++) {
            const uint8_t *src = ring + rpos * frame_bytes;
            for (unsigned ch = 0; ch < channels; ch++) {
                const uint8_t *s = src + ch * 3;
                int32_t v = ((int32_t)s[2] << 16) | ((int32_t)s[1] << 8) | (int32_t)s[0];
                if (v & 0x800000) v |= (int32_t)0xFF000000;
                flac_buf[f * channels + ch] = v;
            }
            if (++rpos >= ring_capacity) rpos = 0;
        }
    }

    /* Encode in chunks */
    const size_t chunk_frames = 4096;
    FLAC__bool ok = true;
    for (size_t pos = 0; pos < nframes && ok; pos += chunk_frames) {
        size_t n = (nframes - pos < chunk_frames) ? (nframes - pos) : chunk_frames;
        ok = FLAC__stream_encoder_process_interleaved(encoder, flac_buf + pos * channels, (unsigned)n);
    }

    if (!ok) {
        logmsg("flac", "encode failed: %s", FLAC__StreamEncoderStateString[FLAC__stream_encoder_get_state(encoder)]);
        FLAC__stream_encoder_finish(encoder);
        FLAC__stream_encoder_delete(encoder);
        unlink(tmp_name);
        return -1;
    }

    FLAC__stream_encoder_finish(encoder);
    FLAC__stream_encoder_delete(encoder);

    if (rename(tmp_name, final_name) != 0) {
        logmsg("flac", "rename %s -> %s: %s", tmp_name, final_name, strerror(errno));
        unlink(tmp_name);
        return -1;
    }

    struct stat st;
    int64_t file_size = 0;
    if (stat(final_name, &st) == 0) file_size = (int64_t)st.st_size;

    logmsg("flac", "wrote %s (%.1f sec, %.1f MB)", final_name,
           (double)nframes / rate, (double)file_size / (1024 * 1024));
    return file_size;
}
#endif /* HAVE_FLAC */

int64_t audiobuf_write_ring(const uint8_t *ring, size_t ring_capacity,
                            size_t ring_start, size_t nframes,
                            unsigned channels, unsigned rate, int bytes_per_sample,
                            int32_t *flac_buf, size_t flac_buf_samples,
                            const char *outdir, const char *prefix, const char *format,
                            time_t start_time) {
#ifdef HAVE_FLAC
    if (format && strcmp(format, "flac") == 0) {
        return audiobuf_write_flac_ring(ring, ring_capacity, ring_start, nframes,
                                        channels, rate, bytes_per_sample,
                                        flac_buf, flac_buf_samples,
                                        outdir, prefix, start_time);
    }
#else
    (void)flac_buf; (void)flac_buf_samples;
    if (format && strcmp(format, "flac") == 0) {
        logmsg("wrt", "FLAC not available, falling back to WAV");
    }
#endif
    return audiobuf_write_wav_ring(ring, ring_capacity, ring_start, nframes,
                                   channels, rate, bytes_per_sample,
                                   outdir, prefix, start_time);
}
