/*
 * writer_thread.c - Async audio file writer thread
 *
 * Monitors all configured SLink channels independently.
 * Each channel has its own ring buffer, recording state, and output files.
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

/* Per-channel writer state (stack-allocated in writer_main) */
typedef struct {
    bool     recording;
    unsigned below_cnt;
    size_t   write_cursor;
    time_t   segment_start_time;
    unsigned window_pos;
    unsigned window_above;
    bool     window_full;
    unsigned last_trigger_pct;
} WriterChState;

void *writer_main(void *arg) {
    App *app = (App *)arg;
    Config *cfg = &app->cfg;

    const size_t FR = cfg->frames_per_read;
    const int nch = cfg->slink_channel_count;
    const unsigned silence_chunks_needed = (unsigned)((cfg->silence_sec * cfg->rate + (FR - 1)) / FR);
    const unsigned trigger_pct = 60;
    const size_t max_file_frames = cfg->max_file_sec > 0 ? (size_t)cfg->max_file_sec * cfg->rate : 0;

    const char *fmt_str = cfg->format ? cfg->format : "wav";
    logmsg("wrt", "started: thr=%u sustain=%.2fs silence=%.2fs format=%s outdir=%s channels=%d",
           cfg->threshold, cfg->sustain_sec, cfg->silence_sec,
           fmt_str, cfg->outdir ? cfg->outdir : ".", nch);

    /* Initialize per-channel state */
    WriterChState chs[SLINK_MAX_CHANNELS] = {{0}};

    while (g_running) {
        for (int c = 0; c < nch; c++) {
            ChannelState *cs = &app->ch[c];
            WriterChState *ws = &chs[c];
            const char *ch_name = cfg->slink_channels[c].name;

            size_t peek = asyncwr_copy_last(&cs->aw, cs->wrt_buf, FR);
            unsigned peak = 0;
            unsigned avg = analyze_samples(cs->wrt_buf, peek, cfg->channels, cfg->bytes_per_sample, &peak);

            /* Update VU meter values */
            if (cfg->channels == 2 && peek > 0) {
                uint16_t vu_l, vu_r;
                analyze_peaks_stereo(cs->wrt_buf, peek, cfg->bytes_per_sample, &vu_l, &vu_r);
                atomic_store_explicit(&cs->vu_l, vu_l, memory_order_relaxed);
                atomic_store_explicit(&cs->vu_r, vu_r, memory_order_relaxed);
            }

            /* Music detection */
            const unsigned min_peak = 400;
            const unsigned min_avg = 60;
            int is_musical = (peak >= min_peak) && (avg >= min_avg) && (avg >= cfg->threshold);

            if (!ws->recording) {
                /* Update sliding window */
                unsigned is_above = is_musical ? 1 : 0;
                unsigned window_size = cs->wrt_window_size;
                unsigned *window = cs->wrt_window;

                if (ws->window_full) {
                    ws->window_above -= window[ws->window_pos];
                }
                window[ws->window_pos] = is_above;
                ws->window_above += is_above;
                ws->window_pos = (ws->window_pos + 1) % window_size;
                if (ws->window_pos == 0) ws->window_full = true;

                unsigned effective_size = ws->window_full ? window_size : ws->window_pos;
                unsigned required = (effective_size * trigger_pct) / 100;

                /* Log progress towards trigger */
                unsigned current_pct = effective_size > 0 ? (ws->window_above * 100) / effective_size : 0;
                if (current_pct >= 50 && (current_pct / 10 != ws->last_trigger_pct / 10)) {
                    logmsg("wrt", "[%s] trigger progress: %u%% above threshold (%u/%u) avg=%u",
                           ch_name, current_pct, ws->window_above, effective_size, avg);
                    ws->last_trigger_pct = current_pct;
                }
                if (current_pct < 50) ws->last_trigger_pct = 0;

                if (ws->window_full && ws->window_above >= required && peek > 0) {
                    /* TRIGGER: start recording from oldest available data (prebuffer) */
                    size_t current_pos = asyncwr_position(&cs->aw);

                    pthread_mutex_lock(&cs->aw.mu);
                    size_t oldest = (cs->aw.total_written > cs->aw.capacity)
                                        ? (cs->aw.total_written - cs->aw.capacity)
                                        : 0;

                    if (ws->write_cursor < oldest) {
                        if (ws->write_cursor > 0) {
                            logmsg("wrt", "[%s] WARNING: lost %zu frames (%.1f sec), resuming from oldest",
                                   ch_name, oldest - ws->write_cursor,
                                   (double)(oldest - ws->write_cursor) / cfg->rate);
                        }
                        ws->write_cursor = oldest;
                    }

                    size_t prebuffer_frames = current_pos - ws->write_cursor;
                    ws->segment_start_time = time(NULL) - (time_t)(prebuffer_frames / cfg->rate);
                    pthread_mutex_unlock(&cs->aw.mu);

                    const char *ext = (cfg->format && strcmp(cfg->format, "flac") == 0) ? "flac" : "wav";
                    build_audio_filename(cs->current_wav, sizeof(cs->current_wav),
                                         cfg->outdir, cfg->prefix, ch_name, ext,
                                         ws->segment_start_time);

                    ws->recording = true;
                    ws->below_cnt = 0;
                    atomic_store_explicit(&cs->is_recording, 1, memory_order_relaxed);

                    logmsg("wrt", "[%s] TRIGGER avg=%u (prebuffer %.1f sec, cursor=%zu)",
                           ch_name, avg,
                           (double)prebuffer_frames / cfg->rate, ws->write_cursor);

                    /* Reset sliding window */
                    memset(cs->wrt_window, 0, cs->wrt_window_size * sizeof(unsigned));
                    ws->window_pos = 0;
                    ws->window_above = 0;
                    ws->window_full = false;
                }
            } else {
                /* Recording: check for file split or silence */
                size_t current_pos = asyncwr_position(&cs->aw);
                size_t frames_since_cursor = current_pos - ws->write_cursor;

                /* Check if we need to split (max file size).
                 * Write exactly max_file_frames to stay within flac_buf bounds. */
                if (max_file_frames > 0 && frames_since_cursor >= max_file_frames) {
                    size_t split_end = ws->write_cursor + max_file_frames;
                    logmsg("wrt", "[%s] SPLIT: writing frames %zu-%zu (%.1f min)",
                           ch_name, ws->write_cursor, split_end,
                           (double)max_file_frames / cfg->rate / 60.0);

                    asyncwr_write_range(&cs->aw, ws->write_cursor, split_end,
                                        ws->segment_start_time, ch_name);

                    ws->write_cursor = split_end;
                    ws->segment_start_time = time(NULL);

                    const char *ext = (cfg->format && strcmp(cfg->format, "flac") == 0) ? "flac" : "wav";
                    build_audio_filename(cs->current_wav, sizeof(cs->current_wav),
                                         cfg->outdir, cfg->prefix, ch_name, ext,
                                         ws->segment_start_time);
                }

                /* Check for silence */
                const unsigned silence_peak_thr = 150;
                const unsigned silence_avg_thr = 25;
                int is_silence = (peak < silence_peak_thr) && (avg < silence_avg_thr);
                if (is_silence) {
                    if (ws->below_cnt < 0x7fffffff) ws->below_cnt++;
                } else {
                    ws->below_cnt = 0;
                }

                if (ws->below_cnt >= silence_chunks_needed) {
                    /* STOP: write remaining audio */
                    size_t final_pos = asyncwr_position(&cs->aw);
                    if (final_pos > ws->write_cursor) {
                        logmsg("wrt", "[%s] STOP: writing frames %zu-%zu",
                               ch_name, ws->write_cursor, final_pos);
                        asyncwr_write_range(&cs->aw, ws->write_cursor, final_pos,
                                            ws->segment_start_time, ch_name);
                        ws->write_cursor = final_pos;
                    }
                    ws->recording = false;
                    ws->below_cnt = 0;
                    atomic_store_explicit(&cs->is_recording, 0, memory_order_relaxed);
                    cs->current_wav[0] = '\0';
                    logmsg("wrt", "[%s] STOP (silence)", ch_name);
                }
            }
        }

        struct timespec ts = {.tv_sec = 0, .tv_nsec = 30 * 1000 * 1000};
        nanosleep(&ts, NULL);
    }

    /* Flush any remaining audio on shutdown */
    for (int c = 0; c < nch; c++) {
        WriterChState *ws = &chs[c];
        if (!ws->recording) continue;
        ChannelState *cs = &app->ch[c];
        const char *ch_name = cfg->slink_channels[c].name;

        size_t final_pos = asyncwr_position(&cs->aw);
        if (final_pos > ws->write_cursor) {
            logmsg("wrt", "[%s] SHUTDOWN: writing frames %zu-%zu",
                   ch_name, ws->write_cursor, final_pos);
            asyncwr_write_range(&cs->aw, ws->write_cursor, final_pos,
                                ws->segment_start_time, ch_name);
        }
        asyncwr_wait_pending(&cs->aw);
    }
    logmsg("wrt", "exit");
    return NULL;
}
