/*
 * peaks.h - Waveform peaks sidecar for recorded segments
 *
 * The writer already holds every PCM sample of a segment in memory while
 * encoding it. peaks_feed() accumulates per-bucket min/max (10 buckets per
 * second by default) at no measurable cost, and peaks_write() stores them in
 * a small binary sidecar next to the FLAC (same basename, ".peaks"), so the
 * web UI can draw a waveform for a whole date without touching the audio.
 *
 * Sidecar layout, little-endian, 56-byte header:
 *   0  char[4] magic "CTPK"
 *   4  u16     version (1)
 *   6  u16     header_size (56)
 *   8  u32     sample_rate
 *  12  u16     channels
 *  14  u16     bits_per_sample
 *  16  u64     total_samples   (frames in the FLAC)
 *  24  u64     cursor          (first frame index in the recorder's monotonic counter)
 *  32  i64     start_unix_ms   (wall clock of the first frame)
 *  40  u32     run_id          (recorder process start, unix s; cursor only comparable within a run)
 *  44  u32     points_per_sec
 *  48  u32     npoints
 *  52  u32     reserved (0)
 *  56  i16[npoints][channels][2]  min, max per point per channel, scaled to 16 bit
 */
#ifndef CLUBTAGGER_PEAKS_H
#define CLUBTAGGER_PEAKS_H

#include <stddef.h>
#include <stdint.h>

#define PEAKS_DEFAULT_PPS 10u

/* Per-segment metadata that only the writer knows; stored in the sidecar
 * (and, later, in the FLAC's VORBIS_COMMENT). */
typedef struct {
    uint64_t cursor;        /* first frame index (monotonic ring counter) */
    int64_t  start_unix_ms; /* wall clock of the first frame */
    uint32_t run_id;        /* recorder process start time (unix seconds) */
    char     channel[32];   /* SLink channel name ("" for ALSA) */
} SegmentMeta;

typedef struct {
    unsigned rate;
    unsigned channels;
    unsigned bps;
    unsigned pps;
    size_t   bucket_frames;    /* frames per point = rate / pps */
    size_t   cap_points;
    size_t   done_points;      /* completed buckets */
    size_t   frames_in_bucket; /* frames accumulated in the current bucket */
    int16_t *minmax;           /* [cap_points][channels][2] */
} Peaks;

/* Allocate for segments of up to max_frames frames. Returns 0 or -errno. */
int  peaks_init(Peaks *p, unsigned rate, unsigned channels, unsigned bps,
                unsigned pps, size_t max_frames);
void peaks_free(Peaks *p);

/* Start a new segment (keeps the allocation). */
void peaks_reset(Peaks *p);

/* Accumulate nframes interleaved samples (already sign-extended to int32). */
void peaks_feed(Peaks *p, const int32_t *interleaved, size_t nframes);

/* Number of points that peaks_write() would emit (completed + partial bucket). */
size_t peaks_count(const Peaks *p);

/* Write the sidecar next to flac_path (extension replaced by ".peaks"),
 * atomically via a ".peaks.tmp" + rename. Returns 0 or -errno. */
int  peaks_write(const Peaks *p, const char *flac_path, uint64_t total_samples,
                 const SegmentMeta *meta);

#endif /* CLUBTAGGER_PEAKS_H */
