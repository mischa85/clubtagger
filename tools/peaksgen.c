/*
 * peaksgen - backfill ".peaks" waveform sidecars for existing FLAC segments
 *
 * The recorder writes a sidecar for every new segment (audio/peaks.c). This
 * tool produces the same file for recordings made before that existed:
 *
 *   peaksgen [--pps N] [--force] [--tz ZONE] <file.flac | directory> ...
 *
 * Each FLAC is decoded once (about a second of CPU per 2-minute segment; run
 * under `nice -n 19` on the recorder). Segment provenance comes from the
 * CLUBTAGGER_* Vorbis comments when the file has them, otherwise the start
 * time is parsed from the filename (local time in ZONE, default
 * Europe/Amsterdam) and cursor/run_id are 0 = "continuity unknown".
 */
#include "audio/peaks.h"
#include "common.h"

#include <FLAC/stream_decoder.h>

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>


typedef struct {
    Peaks       peaks;
    int         peaks_ready;
    unsigned    pps;
    unsigned    rate, channels, bps;
    uint64_t    total_samples;   /* from STREAMINFO (0 = unknown) */
    uint64_t    decoded;
    SegmentMeta meta;
    int         meta_from_tags;
    int32_t    *inter;           /* interleave buffer */
    size_t      inter_frames;
    int         error;
} Job;

/* YYYYMMDD_HHMMSS_<prefix>_<channel>.flac -> local time -> unix ms. */
static int start_ms_from_name(const char *path, int64_t *out_ms, char *channel, size_t ch_sz) {
    const char *name = strrchr(path, '/');
    name = name ? name + 1 : path;
    int Y, M, D, h, m, s;
    if (sscanf(name, "%4d%2d%2d_%2d%2d%2d_", &Y, &M, &D, &h, &m, &s) != 6) return -EINVAL;
    struct tm tm = {0};
    tm.tm_year = Y - 1900; tm.tm_mon = M - 1; tm.tm_mday = D;
    tm.tm_hour = h; tm.tm_min = m; tm.tm_sec = s; tm.tm_isdst = -1;
    time_t t = mktime(&tm);
    if (t == (time_t)-1) return -EINVAL;
    *out_ms = (int64_t)t * 1000;
    /* channel = text after the last '_' up to the extension */
    const char *us = strrchr(name, '_');
    const char *dot = strrchr(name, '.');
    if (us && dot && dot > us + 1) {
        size_t n = (size_t)(dot - us - 1);
        if (n >= ch_sz) n = ch_sz - 1;
        memcpy(channel, us + 1, n);
        channel[n] = '\0';
    }
    return 0;
}

static void on_metadata(const FLAC__StreamDecoder *dec, const FLAC__StreamMetadata *md, void *cd) {
    (void)dec;
    Job *j = (Job *)cd;
    if (md->type == FLAC__METADATA_TYPE_STREAMINFO) {
        j->rate = md->data.stream_info.sample_rate;
        j->channels = md->data.stream_info.channels;
        j->bps = md->data.stream_info.bits_per_sample;
        j->total_samples = md->data.stream_info.total_samples;
    } else if (md->type == FLAC__METADATA_TYPE_VORBIS_COMMENT) {
        const FLAC__StreamMetadata_VorbisComment *vc = &md->data.vorbis_comment;
        for (uint32_t i = 0; i < vc->num_comments; i++) {
            const char *e = (const char *)vc->comments[i].entry;
            uint32_t len = vc->comments[i].length;
            char buf[256];
            if (len >= sizeof(buf)) continue;
            memcpy(buf, e, len);
            buf[len] = '\0';
            if (!strncmp(buf, "CLUBTAGGER_START_MS=", 20)) {
                j->meta.start_unix_ms = strtoll(buf + 20, NULL, 10);
                j->meta_from_tags = 1;
            } else if (!strncmp(buf, "CLUBTAGGER_CURSOR=", 18)) {
                j->meta.cursor = strtoull(buf + 18, NULL, 10);
            } else if (!strncmp(buf, "CLUBTAGGER_RUN_ID=", 18)) {
                j->meta.run_id = (uint32_t)strtoul(buf + 18, NULL, 10);
            } else if (!strncmp(buf, "CLUBTAGGER_CHANNEL=", 19)) {
                snprintf(j->meta.channel, sizeof(j->meta.channel), "%s", buf + 19);
            }
        }
    }
}

static FLAC__StreamDecoderWriteStatus on_write(const FLAC__StreamDecoder *dec,
                                               const FLAC__Frame *frame,
                                               const FLAC__int32 *const buffer[], void *cd) {
    (void)dec;
    Job *j = (Job *)cd;
    if (!j->peaks_ready) {
        /* First frame: STREAMINFO is known now. Size for the whole file, or
         * for an hour if the header does not say. */
        size_t max_frames = j->total_samples ? (size_t)j->total_samples : (size_t)j->rate * 3600;
        if (peaks_init(&j->peaks, j->rate, j->channels, j->bps, j->pps, max_frames) != 0) {
            j->error = -ENOMEM;
            return FLAC__STREAM_DECODER_WRITE_STATUS_ABORT;
        }
        j->peaks_ready = 1;
    }
    unsigned n = frame->header.blocksize;
    if (j->inter_frames < n) {
        int32_t *nb = (int32_t *)realloc(j->inter, (size_t)n * j->channels * sizeof(int32_t));
        if (!nb) {
            logmsg("peaksgen", "OOM for %u-frame interleave buffer", n);
            j->error = -ENOMEM;
            return FLAC__STREAM_DECODER_WRITE_STATUS_ABORT;
        }
        j->inter = nb;
        j->inter_frames = n;
    }
    for (unsigned f = 0; f < n; f++)
        for (unsigned c = 0; c < j->channels; c++)
            j->inter[f * j->channels + c] = buffer[c][f];
    peaks_feed(&j->peaks, j->inter, n);
    j->decoded += n;
    return FLAC__STREAM_DECODER_WRITE_STATUS_CONTINUE;
}

static void on_error(const FLAC__StreamDecoder *dec, FLAC__StreamDecoderErrorStatus st, void *cd) {
    (void)dec;
    Job *j = (Job *)cd;
    logmsg("peaksgen", "decode error: %s", FLAC__StreamDecoderErrorStatusString[st]);
    j->error = -EIO;
}

static int has_sidecar(const char *flac_path) {
    char p[1024];
    size_t n = strlen(flac_path);
    if (n < 5 || n + 2 >= sizeof(p)) return 0;
    memcpy(p, flac_path, n - 5);          /* strip ".flac" */
    strcpy(p + n - 5, ".peaks");
    struct stat st;
    return stat(p, &st) == 0;
}

static int process_file(const char *path, unsigned pps, int force) {
    if (!force && has_sidecar(path)) return 1; /* skipped */

    Job j = {0};
    j.pps = pps;

    FLAC__StreamDecoder *dec = FLAC__stream_decoder_new();
    if (!dec) {
        logmsg("peaksgen", "decoder_new failed");
        return -ENOMEM;
    }
    FLAC__stream_decoder_set_metadata_respond(dec, FLAC__METADATA_TYPE_VORBIS_COMMENT);
    FLAC__StreamDecoderInitStatus is =
        FLAC__stream_decoder_init_file(dec, path, on_write, on_metadata, on_error, &j);
    if (is != FLAC__STREAM_DECODER_INIT_STATUS_OK) {
        logmsg("peaksgen", "%s: init failed: %s", path, FLAC__StreamDecoderInitStatusString[is]);
        FLAC__stream_decoder_delete(dec);
        return -EIO;
    }
    FLAC__bool ok = FLAC__stream_decoder_process_until_end_of_stream(dec);
    if (!ok && !j.error) {
        logmsg("peaksgen", "%s: decode failed: %s", path,
               FLAC__StreamDecoderStateString[FLAC__stream_decoder_get_state(dec)]);
        j.error = -EIO;
    }
    FLAC__stream_decoder_finish(dec);
    FLAC__stream_decoder_delete(dec);

    int rc = j.error;
    if (rc == 0 && !j.peaks_ready) {
        logmsg("peaksgen", "%s: no audio frames", path);
        rc = -EINVAL;
    }
    if (rc == 0 && j.total_samples && j.decoded != j.total_samples) {
        logmsg("peaksgen", "%s: decoded %llu of %llu samples (truncated?)", path,
               (unsigned long long)j.decoded, (unsigned long long)j.total_samples);
    }
    if (rc == 0 && !j.meta_from_tags) {
        if (start_ms_from_name(path, &j.meta.start_unix_ms, j.meta.channel, sizeof(j.meta.channel)) != 0) {
            logmsg("peaksgen", "%s: no CLUBTAGGER tags and unparseable name, start time unknown", path);
        }
    }
    if (rc == 0) {
        rc = peaks_write(&j.peaks, path, j.decoded, &j.meta);
        if (rc == 0) {
            logmsg("peaksgen", "%s: %zu points, %.1f s%s", path, peaks_count(&j.peaks),
                   (double)j.decoded / j.rate, j.meta_from_tags ? "" : " (start from filename)");
        }
    }
    if (j.peaks_ready) peaks_free(&j.peaks);
    free(j.inter);
    return rc;
}

static int cmp_names(const void *a, const void *b) {
    return strcmp(*(char *const *)a, *(char *const *)b);
}

static int ends_with(const char *s, const char *suffix) {
    size_t n = strlen(s), m = strlen(suffix);
    return n >= m && strcmp(s + n - m, suffix) == 0;
}

static int process_path(const char *path, unsigned pps, int force, int *done, int *skipped, int *failed) {
    struct stat st;
    if (stat(path, &st) != 0) {
        logmsg("peaksgen", "%s: %s", path, strerror(errno));
        (*failed)++;
        return -errno;
    }
    if (S_ISDIR(st.st_mode)) {
        DIR *d = opendir(path);
        if (!d) {
            logmsg("peaksgen", "opendir %s: %s", path, strerror(errno));
            (*failed)++;
            return -errno;
        }
        /* Sort for a predictable order in the log */
        char **names = NULL;
        size_t n = 0, cap = 0;
        struct dirent *de;
        while ((de = readdir(d)) != NULL) {
            if (de->d_name[0] == '.' || !ends_with(de->d_name, ".flac")) continue;
            if (n == cap) {
                cap = cap ? cap * 2 : 256;
                char **nn = (char **)realloc(names, cap * sizeof(char *));
                if (!nn) { logmsg("peaksgen", "OOM listing %s", path); break; }
                names = nn;
            }
            names[n++] = strdup(de->d_name);
        }
        closedir(d);
        qsort(names, n, sizeof(char *), cmp_names);
        for (size_t i = 0; i < n && g_running; i++) {
            char full[1024];
            snprintf(full, sizeof(full), "%s/%s", path, names[i]);
            int rc = process_file(full, pps, force);
            if (rc == 1) (*skipped)++;
            else if (rc == 0) (*done)++;
            else (*failed)++;
            free(names[i]);
        }
        free(names);
        return 0;
    }
    int rc = process_file(path, pps, force);
    if (rc == 1) (*skipped)++;
    else if (rc == 0) (*done)++;
    else (*failed)++;
    return rc == 1 ? 0 : rc;
}

int main(int argc, char **argv) {
    unsigned pps = PEAKS_DEFAULT_PPS;
    int force = 0;
    const char *tz = "Europe/Amsterdam";
    int i = 1;
    for (; i < argc && argv[i][0] == '-'; i++) {
        if (!strcmp(argv[i], "--pps") && i + 1 < argc) pps = (unsigned)atoi(argv[++i]);
        else if (!strcmp(argv[i], "--force")) force = 1;
        else if (!strcmp(argv[i], "--tz") && i + 1 < argc) tz = argv[++i];
        else {
            fprintf(stderr, "usage: peaksgen [--pps N] [--force] [--tz ZONE] <file.flac|dir> ...\n");
            return 2;
        }
    }
    if (i >= argc) {
        fprintf(stderr, "usage: peaksgen [--pps N] [--force] [--tz ZONE] <file.flac|dir> ...\n");
        return 2;
    }
    setenv("TZ", tz, 1);
    tzset();

    int done = 0, skipped = 0, failed = 0;
    for (; i < argc; i++) process_path(argv[i], pps, force, &done, &skipped, &failed);
    logmsg("peaksgen", "done: %d written, %d already had a sidecar, %d failed", done, skipped, failed);
    return failed ? 1 : 0;
}
