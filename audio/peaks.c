/*
 * peaks.c - Waveform peaks sidecar for recorded segments
 */
#include "peaks.h"
#include "../common.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PEAKS_MAGIC       "CTPK"
#define PEAKS_VERSION     1u
#define PEAKS_HEADER_SIZE 56u

int peaks_init(Peaks *p, unsigned rate, unsigned channels, unsigned bps,
               unsigned pps, size_t max_frames) {
    memset(p, 0, sizeof(*p));
    if (rate == 0 || channels == 0 || pps == 0 || pps > rate) {
        logmsg("peaks", "peaks_init: invalid rate=%u channels=%u pps=%u", rate, channels, pps);
        return -EINVAL;
    }
    p->rate = rate;
    p->channels = channels;
    p->bps = bps;
    p->pps = pps;
    p->bucket_frames = rate / pps;
    /* +2: one partial bucket at the end, one for rounding of max_frames */
    p->cap_points = max_frames / p->bucket_frames + 2;
    p->minmax = (int16_t *)malloc(p->cap_points * channels * 2 * sizeof(int16_t));
    if (!p->minmax) {
        logmsg("peaks", "peaks_init: OOM for %zu points x %u channels", p->cap_points, channels);
        return -ENOMEM;
    }
    peaks_reset(p);
    return 0;
}

void peaks_free(Peaks *p) {
    free(p->minmax);
    p->minmax = NULL;
    p->cap_points = 0;
}

static void bucket_clear(Peaks *p, size_t idx) {
    int16_t *b = p->minmax + idx * p->channels * 2;
    for (unsigned c = 0; c < p->channels; c++) {
        b[c * 2 + 0] = INT16_MAX;
        b[c * 2 + 1] = INT16_MIN;
    }
}

void peaks_reset(Peaks *p) {
    p->done_points = 0;
    p->frames_in_bucket = 0;
    if (p->minmax && p->cap_points > 0) bucket_clear(p, 0);
}

/* Scale a sample of p->bps bits to 16 bit. */
static inline int16_t scale16(int32_t v, unsigned bps) {
    if (bps > 16) v >>= (bps - 16);
    else if (bps < 16) v <<= (16 - bps);
    if (v > INT16_MAX) v = INT16_MAX;
    if (v < INT16_MIN) v = INT16_MIN;
    return (int16_t)v;
}

void peaks_feed(Peaks *p, const int32_t *interleaved, size_t nframes) {
    if (!p->minmax) return;
    const unsigned ch = p->channels;

    for (size_t f = 0; f < nframes; f++) {
        if (p->done_points >= p->cap_points) {
            /* Segment longer than the allocation; keep the first cap_points.
             * Logged once per segment by peaks_write() via the count mismatch. */
            return;
        }
        int16_t *b = p->minmax + p->done_points * ch * 2;
        const int32_t *s = interleaved + f * ch;
        for (unsigned c = 0; c < ch; c++) {
            int16_t v = scale16(s[c], p->bps);
            if (v < b[c * 2 + 0]) b[c * 2 + 0] = v;
            if (v > b[c * 2 + 1]) b[c * 2 + 1] = v;
        }
        if (++p->frames_in_bucket >= p->bucket_frames) {
            p->frames_in_bucket = 0;
            p->done_points++;
            if (p->done_points < p->cap_points) bucket_clear(p, p->done_points);
        }
    }
}

size_t peaks_count(const Peaks *p) {
    size_t n = p->done_points;
    if (p->frames_in_bucket > 0 && n < p->cap_points) n++;
    return n;
}

static void put_u16(uint8_t *b, uint16_t v) { b[0] = v & 0xff; b[1] = (v >> 8) & 0xff; }
static void put_u32(uint8_t *b, uint32_t v) { for (int i = 0; i < 4; i++) b[i] = (v >> (8 * i)) & 0xff; }
static void put_u64(uint8_t *b, uint64_t v) { for (int i = 0; i < 8; i++) b[i] = (v >> (8 * i)) & 0xff; }

/* Replace the extension of flac_path with ext into out. */
static int sidecar_path(char *out, size_t out_sz, const char *flac_path, const char *ext) {
    const char *slash = strrchr(flac_path, '/');
    const char *dot = strrchr(flac_path, '.');
    size_t base_len = (dot && (!slash || dot > slash)) ? (size_t)(dot - flac_path) : strlen(flac_path);
    if (base_len + strlen(ext) + 1 > out_sz) return -ENAMETOOLONG;
    memcpy(out, flac_path, base_len);
    strcpy(out + base_len, ext);
    return 0;
}

int peaks_write(const Peaks *p, const char *flac_path, uint64_t total_samples,
                const SegmentMeta *meta) {
    if (!p->minmax) {
        logmsg("peaks", "peaks_write: not initialized");
        return -EINVAL;
    }
    size_t npoints = peaks_count(p);
    size_t expected = (size_t)((total_samples + p->bucket_frames - 1) / p->bucket_frames);
    if (npoints != expected) {
        logmsg("peaks", "peaks_write: %zu points for %llu samples, expected %zu (segment longer than allocation?)",
               npoints, (unsigned long long)total_samples, expected);
    }

    char final_name[600], tmp_name[608];
    int rc = sidecar_path(final_name, sizeof(final_name), flac_path, ".peaks");
    if (rc < 0) {
        logmsg("peaks", "peaks_write: path too long: %s", flac_path);
        return rc;
    }
    snprintf(tmp_name, sizeof(tmp_name), "%s.tmp", final_name);

    uint8_t hdr[PEAKS_HEADER_SIZE];
    memset(hdr, 0, sizeof(hdr));
    memcpy(hdr, PEAKS_MAGIC, 4);
    put_u16(hdr + 4, PEAKS_VERSION);
    put_u16(hdr + 6, PEAKS_HEADER_SIZE);
    put_u32(hdr + 8, p->rate);
    put_u16(hdr + 12, (uint16_t)p->channels);
    put_u16(hdr + 14, (uint16_t)p->bps);
    put_u64(hdr + 16, total_samples);
    put_u64(hdr + 24, meta ? meta->cursor : 0);
    put_u64(hdr + 32, (uint64_t)(meta ? meta->start_unix_ms : 0));
    put_u32(hdr + 40, meta ? meta->run_id : 0);
    put_u32(hdr + 44, p->pps);
    put_u32(hdr + 48, (uint32_t)npoints);
    put_u32(hdr + 52, 0);

    FILE *f = fopen(tmp_name, "wb");
    if (!f) {
        int err = errno;
        logmsg("peaks", "fopen %s: %s", tmp_name, strerror(err));
        return -err;
    }

    size_t nvals = npoints * p->channels * 2;
    int ok = fwrite(hdr, 1, sizeof(hdr), f) == sizeof(hdr);
    if (ok) {
        /* Values are written little-endian regardless of host order. */
        uint8_t buf[512];
        size_t i = 0;
        while (ok && i < nvals) {
            size_t n = 0;
            while (n + 2 <= sizeof(buf) && i < nvals) {
                put_u16(buf + n, (uint16_t)p->minmax[i++]);
                n += 2;
            }
            ok = fwrite(buf, 1, n, f) == n;
        }
    }
    if (ok) ok = fflush(f) == 0 && fsync(fileno(f)) == 0;
    int err = ok ? 0 : errno;
    if (fclose(f) != 0 && !err) err = errno;
    if (err) {
        logmsg("peaks", "write %s: %s", tmp_name, strerror(err));
        unlink(tmp_name);
        return -err;
    }
    if (rename(tmp_name, final_name) != 0) {
        err = errno;
        logmsg("peaks", "rename %s -> %s: %s", tmp_name, final_name, strerror(err));
        unlink(tmp_name);
        return -err;
    }
    return 0;
}
