/*
 * audio_buffer.c - Audio buffer management and file I/O
 */
#include "audio_buffer.h"
#include "common.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifdef HAVE_FLAC
#include <FLAC/metadata.h>
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

/* Path for a file that is still being produced: <outdir>/.incoming/<basename>.
 * A dot-directory is skipped by nginx autoindex, so half-written files are
 * never visible to readers; same filesystem as the final path, so rename()
 * is atomic. Returns 0 or -errno. */
static int staging_path(char *out, size_t out_sz, const char *outdir, const char *final_name) {
    const char *base = strrchr(final_name, '/');
    base = base ? base + 1 : final_name;
    char dir[520];
    if (outdir && outdir[0]) snprintf(dir, sizeof(dir), "%s/.incoming", outdir);
    else snprintf(dir, sizeof(dir), ".incoming");
    ensure_dir(dir);
    int n = snprintf(out, out_sz, "%s/%s", dir, base);
    if (n < 0 || (size_t)n >= out_sz) return -ENAMETOOLONG;
    return 0;
}

/* Publish an in-memory file: staging file, write, fsync, rename to final_name.
 * Returns 0 or -errno; every failure is logged under `tag`. */
static int publish_file(const char *tag, const char *outdir, const char *final_name,
                        const uint8_t *buf, size_t len) {
    char tmp[600];
    int rc = staging_path(tmp, sizeof(tmp), outdir, final_name);
    if (rc < 0) {
        logmsg(tag, "staging path too long for %s", final_name);
        return rc;
    }
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        rc = -errno;
        logmsg(tag, "open %s: %s", tmp, strerror(errno));
        return rc;
    }
    size_t off = 0;
    while (off < len) {
        ssize_t w = write(fd, buf + off, len - off);
        if (w < 0) {
            if (errno == EINTR) continue;
            rc = -errno;
            logmsg(tag, "write %s: %s", tmp, strerror(errno));
            close(fd);
            unlink(tmp);
            return rc;
        }
        off += (size_t)w;
    }
    if (fsync(fd) != 0) {
        rc = -errno;
        logmsg(tag, "fsync %s: %s", tmp, strerror(errno));
        close(fd);
        unlink(tmp);
        return rc;
    }
    if (close(fd) != 0) {
        rc = -errno;
        logmsg(tag, "close %s: %s", tmp, strerror(errno));
        unlink(tmp);
        return rc;
    }
    if (rename(tmp, final_name) != 0) {
        rc = -errno;
        logmsg(tag, "rename %s -> %s: %s", tmp, final_name, strerror(errno));
        unlink(tmp);
        return rc;
    }
    return 0;
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
    if (!ab->data || ab->frames == 0) {
        logmsg("wav", "audiobuf_write_wav: invalid input data=%p frames=%zu prefix=%s",
               (void *)ab->data, ab->frames, prefix ? prefix : "(null)");
        return -1;
    }

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
    if (!ab->data || ab->frames == 0) {
        logmsg("flac", "audiobuf_write_flac: invalid input data=%p frames=%zu prefix=%s",
               (void *)ab->data, ab->frames, prefix ? prefix : "(null)");
        return -1;
    }

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
    if (!ring || nframes == 0) {
        logmsg("wav", "audiobuf_write_wav_ring: invalid input ring=%p nframes=%zu prefix=%s",
               (const void *)ring, nframes, prefix ? prefix : "(null)");
        return -1;
    }

    ensure_dir(outdir);

    size_t frame_bytes = channels * bytes_per_sample;
    unsigned bits = bytes_per_sample * 8;

    char final_name[512], tmp_name[600];
    build_audio_filename(final_name, sizeof(final_name), outdir, prefix, NULL, "wav", start_time);
    if (staging_path(tmp_name, sizeof(tmp_name), outdir, final_name) < 0) {
        logmsg("wav", "staging path too long for %s", final_name);
        return -ENAMETOOLONG;
    }

    FILE *fp = fopen(tmp_name, "wb");
    if (!fp) {
        int err = errno;
        logmsg("wav", "open %s: %s", tmp_name, strerror(err));
        return -err;
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
        int err = errno;
        logmsg("wav", "rename %s -> %s: %s", tmp_name, final_name, strerror(err));
        unlink(tmp_name);
        return -err;
    }

    struct stat st;
    int64_t file_size = (stat(final_name, &st) == 0) ? (int64_t)st.st_size : (int64_t)(36 + data_bytes);

    logmsg("wav", "wrote %s (%.1f sec, %.1f MB)", final_name,
           (double)nframes / rate, (double)file_size / (1024 * 1024));
    return file_size;
}

#ifdef HAVE_FLAC
/* libFLAC stream callbacks over a FlacOutBuf. The encoder seeks back to
 * patch STREAMINFO after finish(), hence pos separate from len. */
static FLAC__StreamEncoderWriteStatus flac_mem_write(const FLAC__StreamEncoder *enc,
                                                     const FLAC__byte buffer[], size_t bytes,
                                                     uint32_t samples, uint32_t current_frame,
                                                     void *client_data) {
    (void)enc; (void)samples; (void)current_frame;
    FlacOutBuf *o = (FlacOutBuf *)client_data;
    if (o->pos + bytes > o->cap) {
        size_t ncap = o->cap ? o->cap : (size_t)1 << 20;
        while (ncap < o->pos + bytes) ncap *= 2;
        uint8_t *nb = (uint8_t *)realloc(o->buf, ncap);
        if (!nb) {
            logmsg("flac", "OOM growing output buffer %zu -> %zu MB", o->cap >> 20, ncap >> 20);
            return FLAC__STREAM_ENCODER_WRITE_STATUS_FATAL_ERROR;
        }
        logmsg("flac", "output buffer grown %zu -> %zu MB", o->cap >> 20, ncap >> 20);
        o->buf = nb;
        o->cap = ncap;
    }
    memcpy(o->buf + o->pos, buffer, bytes);
    o->pos += bytes;
    if (o->pos > o->len) o->len = o->pos;
    return FLAC__STREAM_ENCODER_WRITE_STATUS_OK;
}

static FLAC__StreamEncoderSeekStatus flac_mem_seek(const FLAC__StreamEncoder *enc,
                                                   FLAC__uint64 absolute_byte_offset,
                                                   void *client_data) {
    (void)enc;
    FlacOutBuf *o = (FlacOutBuf *)client_data;
    if (absolute_byte_offset > o->len) return FLAC__STREAM_ENCODER_SEEK_STATUS_ERROR;
    o->pos = (size_t)absolute_byte_offset;
    return FLAC__STREAM_ENCODER_SEEK_STATUS_OK;
}

static FLAC__StreamEncoderTellStatus flac_mem_tell(const FLAC__StreamEncoder *enc,
                                                   FLAC__uint64 *absolute_byte_offset,
                                                   void *client_data) {
    (void)enc;
    FlacOutBuf *o = (FlacOutBuf *)client_data;
    *absolute_byte_offset = o->pos;
    return FLAC__STREAM_ENCODER_TELL_STATUS_OK;
}

unsigned audiobuf_flac_blocksize(size_t segment_frames) {
    /* 4608 divides 120 s at both 48 and 96 kHz; 4096 is libFLAC's default. */
    static const unsigned candidates[] = { 4608, 4096 };
    if (segment_frames == 0) return 0;
    for (size_t i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++) {
        if (segment_frames % candidates[i] == 0) return candidates[i];
    }
    return 0;
}

size_t audiobuf_flac_chunk_frames(unsigned blocksize) {
    return blocksize ? blocksize : 4096;
}

/* Convert nframes frames starting at *rpos in the ring to int32, advancing *rpos. */
static void ring_to_int32(const uint8_t *ring, size_t ring_capacity, size_t *rpos,
                          size_t nframes, unsigned channels, int bytes_per_sample,
                          int32_t *dst) {
    size_t frame_bytes = channels * bytes_per_sample;
    size_t r = *rpos;
    if (bytes_per_sample == 2) {
        for (size_t f = 0; f < nframes; f++) {
            const int16_t *s16 = (const int16_t *)(ring + r * frame_bytes);
            for (unsigned ch = 0; ch < channels; ch++)
                dst[f * channels + ch] = s16[ch];
            if (++r >= ring_capacity) r = 0;
        }
    } else if (bytes_per_sample == 3) {
        for (size_t f = 0; f < nframes; f++) {
            const uint8_t *src = ring + r * frame_bytes;
            for (unsigned ch = 0; ch < channels; ch++) {
                const uint8_t *s = src + ch * 3;
                int32_t v = ((int32_t)s[2] << 16) | ((int32_t)s[1] << 8) | (int32_t)s[0];
                if (v & 0x800000) v |= (int32_t)0xFF000000;
                dst[f * channels + ch] = v;
            }
            if (++r >= ring_capacity) r = 0;
        }
    }
    *rpos = r;
}

/* VORBIS_COMMENT with the segment's provenance, so the information in the
 * filename and the sidecar also travels inside the file (and into exports). */
static FLAC__StreamMetadata *segment_tags(const SegmentMeta *meta) {
    FLAC__StreamMetadata *vc = FLAC__metadata_object_new(FLAC__METADATA_TYPE_VORBIS_COMMENT);
    if (!vc) {
        logmsg("flac", "metadata_object_new failed");
        return NULL;
    }
    char start_ms[32], cursor[32], run_id[32];
    snprintf(start_ms, sizeof(start_ms), "%lld", (long long)meta->start_unix_ms);
    snprintf(cursor, sizeof(cursor), "%llu", (unsigned long long)meta->cursor);
    snprintf(run_id, sizeof(run_id), "%u", meta->run_id);
    const char *names[4];
    const char *values[4];
    int n = 0;
    if (meta->channel[0]) { names[n] = "CLUBTAGGER_CHANNEL"; values[n++] = meta->channel; }
    names[n] = "CLUBTAGGER_START_MS"; values[n++] = start_ms;
    names[n] = "CLUBTAGGER_CURSOR";   values[n++] = cursor;
    names[n] = "CLUBTAGGER_RUN_ID";   values[n++] = run_id;
    for (int i = 0; i < n; i++) {
        FLAC__StreamMetadata_VorbisComment_Entry e;
        if (!FLAC__metadata_object_vorbiscomment_entry_from_name_value_pair(&e, names[i], values[i]) ||
            !FLAC__metadata_object_vorbiscomment_append_comment(vc, e, /*copy=*/false)) {
            logmsg("flac", "vorbis comment %s failed", names[i]);
            FLAC__metadata_object_delete(vc);
            return NULL;
        }
    }
    return vc;
}

int64_t audiobuf_write_flac_ring(const uint8_t *ring, size_t ring_capacity,
                                 size_t ring_start, size_t nframes,
                                 unsigned channels, unsigned rate, int bytes_per_sample,
                                 unsigned blocksize,
                                 int32_t *flac_buf, size_t flac_buf_samples,
                                 FlacOutBuf *out,
                                 const char *outdir, const char *prefix, time_t start_time,
                                 Peaks *peaks, const SegmentMeta *meta) {
    if (!ring || nframes == 0 || !out) {
        logmsg("flac", "audiobuf_write_flac_ring: invalid input ring=%p nframes=%zu out=%p prefix=%s",
               (const void *)ring, nframes, (const void *)out, prefix ? prefix : "(null)");
        return -EINVAL;
    }

    const size_t chunk_frames = audiobuf_flac_chunk_frames(blocksize);
    if (!flac_buf || flac_buf_samples < chunk_frames * channels) {
        logmsg("flac", "flac_buf too small: need %zu, have %zu", chunk_frames * channels, flac_buf_samples);
        return -EINVAL;
    }

    ensure_dir(outdir);

    char final_name[512];
    build_audio_filename(final_name, sizeof(final_name), outdir, prefix, NULL, "flac", start_time);

    FLAC__StreamEncoder *encoder = FLAC__stream_encoder_new();
    if (!encoder) {
        logmsg("flac", "encoder_new failed");
        return -ENOMEM;
    }

    unsigned bits = bytes_per_sample * 8;
    FLAC__stream_encoder_set_channels(encoder, channels);
    FLAC__stream_encoder_set_bits_per_sample(encoder, bits);
    FLAC__stream_encoder_set_sample_rate(encoder, rate);
    FLAC__stream_encoder_set_compression_level(encoder, 5);
    if (blocksize) FLAC__stream_encoder_set_blocksize(encoder, blocksize);
    FLAC__stream_encoder_set_total_samples_estimate(encoder, nframes);

    FLAC__StreamMetadata *tags = meta ? segment_tags(meta) : NULL;
    if (tags) FLAC__stream_encoder_set_metadata(encoder, &tags, 1);

    out->len = 0;
    out->pos = 0;
    FLAC__StreamEncoderInitStatus init_status =
        FLAC__stream_encoder_init_stream(encoder, flac_mem_write, flac_mem_seek, flac_mem_tell,
                                         NULL, out);
    if (init_status != FLAC__STREAM_ENCODER_INIT_STATUS_OK) {
        logmsg("flac", "init failed: %s", FLAC__StreamEncoderInitStatusString[init_status]);
        FLAC__stream_encoder_delete(encoder);
        if (tags) FLAC__metadata_object_delete(tags);
        return -EIO;
    }

    /* Convert, measure and encode one chunk at a time straight from the ring;
     * no whole-segment int32 copy (that was ~90 MB per channel at 96 kHz). */
    if (peaks) peaks_reset(peaks);
    size_t rpos = ring_start;
    FLAC__bool ok = true;
    for (size_t pos = 0; pos < nframes && ok; pos += chunk_frames) {
        size_t n = (nframes - pos < chunk_frames) ? (nframes - pos) : chunk_frames;
        ring_to_int32(ring, ring_capacity, &rpos, n, channels, bytes_per_sample, flac_buf);
        if (peaks) peaks_feed(peaks, flac_buf, n);
        ok = FLAC__stream_encoder_process_interleaved(encoder, flac_buf, (unsigned)n);
    }
    if (ok) ok = FLAC__stream_encoder_finish(encoder);

    if (!ok) {
        logmsg("flac", "encode failed: %s", FLAC__StreamEncoderStateString[FLAC__stream_encoder_get_state(encoder)]);
        FLAC__stream_encoder_delete(encoder);
        if (tags) FLAC__metadata_object_delete(tags);
        return -EIO;
    }
    FLAC__stream_encoder_delete(encoder);
    if (tags) FLAC__metadata_object_delete(tags);

    int rc = publish_file("flac", outdir, final_name, out->buf, out->len);
    if (rc < 0) return rc;

    int64_t file_size = (int64_t)out->len;
    logmsg("flac", "wrote %s (%.1f sec, %.1f MB)", final_name,
           (double)nframes / rate, (double)file_size / (1024 * 1024));

    /* Sidecar goes last: its existence tells readers the FLAC is complete. */
    if (peaks && meta) {
        if (peaks_write(peaks, final_name, nframes, meta) == 0) {
            logmsg("peaks", "wrote %zu points for %s", peaks_count(peaks), final_name);
        }
    }
    return file_size;
}
#endif /* HAVE_FLAC */

int64_t audiobuf_write_ring(const uint8_t *ring, size_t ring_capacity,
                            size_t ring_start, size_t nframes,
                            unsigned channels, unsigned rate, int bytes_per_sample,
                            unsigned blocksize,
                            int32_t *flac_buf, size_t flac_buf_samples,
                            FlacOutBuf *out,
                            const char *outdir, const char *prefix, const char *format,
                            time_t start_time, Peaks *peaks, const SegmentMeta *meta) {
#ifdef HAVE_FLAC
    if (format && strcmp(format, "flac") == 0) {
        return audiobuf_write_flac_ring(ring, ring_capacity, ring_start, nframes,
                                        channels, rate, bytes_per_sample, blocksize,
                                        flac_buf, flac_buf_samples, out,
                                        outdir, prefix, start_time, peaks, meta);
    }
#else
    (void)blocksize; (void)flac_buf; (void)flac_buf_samples; (void)out; (void)peaks; (void)meta;
    if (format && strcmp(format, "flac") == 0) {
        logmsg("wrt", "FLAC not available, falling back to WAV");
    }
#endif
    return audiobuf_write_wav_ring(ring, ring_capacity, ring_start, nframes,
                                   channels, rate, bytes_per_sample,
                                   outdir, prefix, start_time);
}
