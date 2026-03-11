/*
 * writer_thread.c - Async audio file writer thread
 */
#include "writer_thread.h"
#include "async_writer.h"
#include "../audio/audio_analysis.h"
#include "../audio/audio_buffer.h"
#include "../common.h"

#include <stdbool.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

void *writer_main(void *arg) {
    App *app = (App *)arg;
    Config *cfg = &app->cfg;

    const size_t FR = cfg->frames_per_read;
    uint8_t *chunk = app->wrt_buf;

    const unsigned silence_chunks_needed = (unsigned)((cfg->silence_sec * cfg->rate + (FR - 1)) / FR);

    /* Sliding window for trigger detection - require 60% of chunks above threshold */
    unsigned window_size = app->wrt_window_size;
    unsigned *window = app->wrt_window;
    unsigned window_pos = 0;
    unsigned window_above = 0;
    bool window_full = false;
    const unsigned trigger_pct = 60;

    unsigned below_cnt = 0;
    bool recording = false;

    /* Position-based tracking */
    size_t write_cursor = 0;       /* absolute frame we've written up to */
    time_t segment_start_time = 0; /* timestamp of write_cursor */

    const size_t max_file_frames = cfg->max_file_sec > 0 ? (size_t)cfg->max_file_sec * cfg->rate : 0;

    const char *fmt_str = cfg->format ? cfg->format : "wav";
    logmsg("wrt", "started: thr=%u sustain=%.2fs silence=%.2fs format=%s outdir=%s",
           cfg->threshold, cfg->sustain_sec, cfg->silence_sec,
           fmt_str, cfg->outdir ? cfg->outdir : ".");

    while (g_running) {
        size_t peek = asyncwr_copy_last(&app->aw, chunk, FR);
        unsigned peak = 0;
        unsigned avg = analyze_samples(chunk, peek, cfg->channels, cfg->bytes_per_sample, &peak);

        /* Update VU meter values for SSE server */
        if (cfg->channels == 2 && peek > 0) {
            uint16_t vu_l, vu_r;
            analyze_peaks_stereo(chunk, peek, cfg->bytes_per_sample, &vu_l, &vu_r);
            atomic_store_explicit(&app->vu_left, vu_l, memory_order_relaxed);
            atomic_store_explicit(&app->vu_right, vu_r, memory_order_relaxed);
        }

        /* Music detection */
        const unsigned min_peak = 400;
        const unsigned min_avg = 60;
        int is_musical = (peak >= min_peak) && (avg >= min_avg) && (avg >= cfg->threshold);

        vlogmsg("wrt", "avg=%u peak=%u musical=%d recording=%d", avg, peak, is_musical, (int)recording);

        if (!recording) {
            /* Update sliding window */
            unsigned is_above = is_musical ? 1 : 0;
            if (window_full) {
                window_above -= window[window_pos];
            }
            window[window_pos] = is_above;
            window_above += is_above;
            window_pos = (window_pos + 1) % window_size;
            if (window_pos == 0) window_full = true;

            unsigned effective_size = window_full ? window_size : window_pos;
            unsigned required = (effective_size * trigger_pct) / 100;

            /* Log progress towards trigger */
            static unsigned last_pct = 0;
            unsigned current_pct = effective_size > 0 ? (window_above * 100) / effective_size : 0;
            if (current_pct >= 50 && (current_pct / 10 != last_pct / 10)) {
                logmsg("wrt", "trigger progress: %u%% above threshold (%u/%u) avg=%u",
                       current_pct, window_above, effective_size, avg);
                last_pct = current_pct;
            }
            if (current_pct < 50) last_pct = 0;

            if (window_full && window_above >= required && peek > 0) {
                /* TRIGGER: start recording from oldest available data (prebuffer) */
                size_t current_pos = asyncwr_position(&app->aw);

                /* Oldest frame still in ring buffer */
                pthread_mutex_lock(&app->aw.mu);
                size_t oldest = (app->aw.total_written > app->aw.capacity)
                                    ? (app->aw.total_written - app->aw.capacity)
                                    : 0;

                /* Continue gapless if write_cursor still valid, else start from oldest */
                if (write_cursor < oldest) {
                    if (write_cursor > 0) {
                        logmsg("wrt", "WARNING: lost %zu frames (%.1f sec), resuming from oldest",
                               oldest - write_cursor, (double)(oldest - write_cursor) / cfg->rate);
                    }
                    write_cursor = oldest;
                }
                /* else: continuing gapless from write_cursor */

                size_t prebuffer_frames = current_pos - write_cursor;
                segment_start_time = time(NULL) - (time_t)(prebuffer_frames / cfg->rate);
                pthread_mutex_unlock(&app->aw.mu);

                const char *ext = (cfg->format && strcmp(cfg->format, "flac") == 0) ? "flac" : "wav";
                build_audio_filename(app->current_wav, sizeof(app->current_wav),
                                     cfg->outdir, cfg->prefix, ext, segment_start_time);

                recording = true;
                below_cnt = 0;
                atomic_store_explicit(&app->is_recording, 1, memory_order_relaxed);

                logmsg("wrt", "TRIGGER avg=%u (prebuffer %.1f sec, cursor=%zu)",
                       avg, (double)prebuffer_frames / cfg->rate, write_cursor);

                /* Reset sliding window */
                memset(window, 0, window_size * sizeof(unsigned));
                window_pos = 0;
                window_above = 0;
                window_full = false;
            }
        } else {
            /* Recording: check for split or silence */
            size_t current_pos = asyncwr_position(&app->aw);
            size_t frames_since_cursor = current_pos - write_cursor;

            /* Check if we need to split */
            if (max_file_frames > 0 && frames_since_cursor >= max_file_frames) {
                logmsg("wrt", "SPLIT: writing frames %zu-%zu (%.1f min)",
                       write_cursor, current_pos, (double)frames_since_cursor / cfg->rate / 60.0);

                asyncwr_write_range(&app->aw, write_cursor, current_pos, segment_start_time);

                /* Advance cursor */
                write_cursor = current_pos;
                segment_start_time = time(NULL);

                const char *ext = (cfg->format && strcmp(cfg->format, "flac") == 0) ? "flac" : "wav";
                build_audio_filename(app->current_wav, sizeof(app->current_wav),
                                     cfg->outdir, cfg->prefix, ext, segment_start_time);
            }

            /* Check for silence */
            const unsigned silence_peak_thr = 150;
            const unsigned silence_avg_thr = 25;
            int is_silence = (peak < silence_peak_thr) && (avg < silence_avg_thr);
            if (is_silence) {
                if (below_cnt < 0x7fffffff) below_cnt++;
            } else {
                below_cnt = 0;
            }

            if (below_cnt >= silence_chunks_needed) {
                /* STOP: write remaining audio */
                size_t final_pos = asyncwr_position(&app->aw);
                if (final_pos > write_cursor) {
                    logmsg("wrt", "STOP: writing frames %zu-%zu", write_cursor, final_pos);
                    asyncwr_write_range(&app->aw, write_cursor, final_pos, segment_start_time);
                    write_cursor = final_pos;
                }
                recording = false;
                below_cnt = 0;
                atomic_store_explicit(&app->is_recording, 0, memory_order_relaxed);
                app->current_wav[0] = '\0';
                logmsg("wrt", "STOP (silence)");
            }
        }

        struct timespec ts = {.tv_sec = 0, .tv_nsec = 30 * 1000 * 1000};
        nanosleep(&ts, NULL);
    }

    /* Flush any remaining audio on shutdown */
    if (recording) {
        size_t final_pos = asyncwr_position(&app->aw);
        if (final_pos > write_cursor) {
            logmsg("wrt", "SHUTDOWN: writing frames %zu-%zu", write_cursor, final_pos);
            asyncwr_write_range(&app->aw, write_cursor, final_pos, segment_start_time);
        }
        /* Wait for async write to complete */
        asyncwr_wait_pending(&app->aw);
    }
    logmsg("wrt", "exit");
    return NULL;
}
