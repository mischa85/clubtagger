/*
 * main.c - clubtagger entry point
 */
#include "writer/async_writer.h"
#include "audio/capture.h"
#include "common.h"
#include "db/database.h"
#include "shazam/id_thread.h"
#include "server/sse_server.h"
#include "types.h"
#include "writer/writer_thread.h"
#include "prolink/prolink_thread.h"

#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* ─────────────────────────────────────────────────────────────────────────────
 * CLI parsing
 * ───────────────────────────────────────────────────────────────────────────── */

static void usage(const char *argv0) {
    fprintf(stderr,
            "Usage: %s [features] [options]\n"
            "\n"
            "Features (at least one required):\n"
            "  --record               Enable audio recording\n"
#ifdef HAVE_VIBRA
            "  --audio-tag            Enable Shazam audio fingerprint tagging\n"
#endif
            "  --cdj-tag              Enable CDJ/Pro DJ Link track tagging\n"
            "\n"
#ifdef HAVE_VIBRA
            "Audio source (required for --record or --audio-tag):\n"
#else
            "Audio source (required for --record):\n"
#endif
            "  --device DEV           ALSA device or network interface\n"
#if defined(HAVE_ALSA) && (defined(HAVE_PCAP) || defined(HAVE_AF_XDP))
            "  --source TYPE          Audio source: 'alsa' or 'slink'\n"
#elif defined(HAVE_ALSA)
            "  --source TYPE          Audio source: 'alsa'\n"
#elif defined(HAVE_PCAP) || defined(HAVE_AF_XDP)
            "  --source TYPE          Audio source: 'slink'\n"
#else
            "  --source TYPE          No audio sources compiled in!\n"
#endif
#if defined(HAVE_PCAP) && defined(HAVE_AF_XDP)
            "  --slink-backend TYPE   Slink capture backend: 'pcap' or 'afxdp' (default: pcap)\n"
#endif
            "\n"
#ifdef HAVE_VIBRA
            "Audio parameters (for --record / --audio-tag):\n"
#else
            "Audio parameters (for --record):\n"
#endif
            "  --rate 48000           Sample rate\n"
            "  --channels 2           Channel count\n"
            "  --frames 1024          Frames per read\n"
            "  --bits 16              Sample bit depth (16 or 24)\n"
            "\n"
            "Recording options (for --record):\n"
            "  --threshold 50         Avg abs amplitude trigger for recording\n"
            "  --sustain-sec 1.0      Seconds above threshold to start recording\n"
            "  --silence-sec 15       Seconds below threshold to stop recording\n"
            "  --prefix capture       Filename prefix\n"
            "  --outdir ./            Output directory for audio files\n"
            "  --format wav           Output format: 'wav' or 'flac'\n"
            "  --max-file-sec 600     Max seconds per file (0 = no limit)\n"
            "  --ring-sec N           Ring buffer size (default = max-file-sec + 60)\n"
            "\n"
#ifdef HAVE_VIBRA
            "Audio tagging options (for --audio-tag):\n"
            "  --fingerprint-sec 12   Seconds of audio to send to Shazam\n"
            "  --min-rms 300          Minimum RMS to attempt recognition\n"
            "  --interval 2           Seconds between recognition attempts\n"
            "  --user-agent UA        Override User-Agent header\n"
            "  --shazam-gap-sec 10    Min seconds between Shazam lookups\n"
            "  --same-track-hold-sec 90  Suppress lookups after a good match\n"
            "\n"
#endif
            "CDJ tagging options (for --cdj-tag):\n"
            "  --prolink-interface IF CDJ network interface (e.g., en0) - REQUIRED\n"
            "\n"
#ifdef HAVE_VIBRA
            "Matching options (for combined --audio-tag + --cdj-tag):\n"
            "  --match-threshold 60   Fuzzy match similarity %% (0-100, default 60)\n"
            "\n"
#endif
            "Database and output:\n"
            "  --db tracks.db         SQLite database for track logging\n"
            "  --timezone TZ          Override timezone (default Europe/Amsterdam)\n"
            "  --sse-socket PATH      Unix socket path for SSE server (VU meter/tracks)\n"
#ifdef HAVE_PCAP
            "  --pcap-buffer-mb N     Pcap kernel buffer size in MB (default: OS default)\n"
#endif
            "  --verbose              Enable detailed logging\n"
            "\n"
            "Examples:\n"
#ifdef HAVE_VIBRA
            "  %s --record --audio-tag --source alsa --device hw:2,1 --db tracks.db\n"
#endif
            "  %s --cdj-tag --prolink-interface en7 --db tracks.db\n"
            "  %s --record --cdj-tag --source slink --device en7 --prolink-interface en7 --db tracks.db\n",
#ifdef HAVE_VIBRA
            argv0, argv0, argv0, argv0);
#else
            argv0, argv0, argv0);
#endif
}

static int parse_cli(int argc, char **argv, Config *cfg) {
    for (int i = 1; i < argc; ++i) {
        const char *a = argv[i];
        if (!strcmp(a, "--device") && i + 1 < argc)
            cfg->device = argv[++i];
        else if (!strcmp(a, "--rate") && i + 1 < argc)
            cfg->rate = (unsigned)strtoul(argv[++i], NULL, 10);
        else if (!strcmp(a, "--channels") && i + 1 < argc)
            cfg->channels = (unsigned)strtoul(argv[++i], NULL, 10);
        else if (!strcmp(a, "--frames") && i + 1 < argc)
            cfg->frames_per_read = (unsigned)strtoul(argv[++i], NULL, 10);
        else if (!strcmp(a, "--fingerprint-sec") && i + 1 < argc)
            cfg->fingerprint_sec = (unsigned)strtoul(argv[++i], NULL, 10);
        else if (!strcmp(a, "--min-rms") && i + 1 < argc)
            cfg->min_rms = (unsigned)strtoul(argv[++i], NULL, 10);
        else if (!strcmp(a, "--interval") && i + 1 < argc)
            cfg->identify_interval_sec = (unsigned)strtoul(argv[++i], NULL, 10);
        else if (!strcmp(a, "--user-agent") && i + 1 < argc)
            cfg->user_agent = argv[++i];
        else if (!strcmp(a, "--timezone") && i + 1 < argc)
            cfg->timezone = argv[++i];
        else if (!strcmp(a, "--shazam-gap-sec") && i + 1 < argc)
            cfg->shazam_gap_sec = (unsigned)strtoul(argv[++i], NULL, 10);
        else if (!strcmp(a, "--same-track-hold-sec") && i + 1 < argc)
            cfg->same_track_hold_sec = (unsigned)strtoul(argv[++i], NULL, 10);
        else if (!strcmp(a, "--threshold") && i + 1 < argc)
            cfg->threshold = (unsigned)strtoul(argv[++i], NULL, 10);
        else if (!strcmp(a, "--sustain-sec") && i + 1 < argc)
            cfg->sustain_sec = (float)atof(argv[++i]);
        else if (!strcmp(a, "--silence-sec") && i + 1 < argc)
            cfg->silence_sec = (float)atof(argv[++i]);
        else if (!strcmp(a, "--prefix") && i + 1 < argc)
            cfg->prefix = argv[++i];
        else if (!strcmp(a, "--source") && i + 1 < argc)
            cfg->source = argv[++i];
        else if (!strcmp(a, "--slink-backend") && i + 1 < argc)
            cfg->slink_backend = argv[++i];
        else if (!strcmp(a, "--bits") && i + 1 < argc) {
            unsigned b = (unsigned)strtoul(argv[++i], NULL, 10);
            cfg->bytes_per_sample = (b == 24) ? 3 : 2;
        } else if (!strcmp(a, "--max-file-sec") && i + 1 < argc)
            cfg->max_file_sec = (unsigned)strtoul(argv[++i], NULL, 10);
        else if (!strcmp(a, "--ring-sec") && i + 1 < argc)
            cfg->ring_sec = (unsigned)strtoul(argv[++i], NULL, 10);
        else if (!strcmp(a, "--outdir") && i + 1 < argc)
            cfg->outdir = argv[++i];
        else if (!strcmp(a, "--format") && i + 1 < argc)
            cfg->format = argv[++i];
        else if (!strcmp(a, "--db") && i + 1 < argc)
            cfg->db_path = argv[++i];
        else if (!strcmp(a, "--pcap-buffer-mb") && i + 1 < argc)
            cfg->pcap_buffer_mb = (unsigned)strtoul(argv[++i], NULL, 10);
        else if (!strcmp(a, "--sse-socket") && i + 1 < argc)
            cfg->sse_socket = argv[++i];
        else if (!strcmp(a, "--prolink-interface") && i + 1 < argc)
            cfg->prolink_interface = argv[++i];
        else if (!strcmp(a, "--match-threshold") && i + 1 < argc)
            cfg->match_threshold = (unsigned)strtoul(argv[++i], NULL, 10);
        /* Feature enable flags */
        else if (!strcmp(a, "--record"))
            cfg->enable_record = 1;
        else if (!strcmp(a, "--audio-tag"))
            cfg->enable_audio_tag = 1;
        else if (!strcmp(a, "--cdj-tag"))
            cfg->enable_cdj_tag = 1;
        else if (!strcmp(a, "--verbose"))
            g_verbose = verbose = 1;
        else {
            usage(argv[0]);
            return -1;
        }
    }
    return 0;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * Signal handling
 * ───────────────────────────────────────────────────────────────────────────── */

static void on_signal(int sig) {
    (void)sig;
    g_running = 0;
#ifdef HAVE_PCAP
    if (g_pcap_handle) pcap_breakloop(g_pcap_handle);
#endif
#ifdef HAVE_ALSA
    if (g_alsa_handle) snd_pcm_abort(g_alsa_handle);
#endif
    /* AF_XDP capture exits on g_running = 0, no special cleanup needed */
}

/* ─────────────────────────────────────────────────────────────────────────────
 * CDJ-only Tagging Callback
 * ───────────────────────────────────────────────────────────────────────────── */

static void cdj_tag_callback(void *user_data, int deck,
                             const char *artist, const char *title,
                             int confidence, const char *source) {
    App *app = (App *)user_data;
    if (!app) return;
    
    /* Generate timestamp */
    char tsbuf[64];
    time_t now = time(NULL);
    struct tm tm;
    localtime_r(&now, &tm);
    strftime(tsbuf, sizeof(tsbuf), "%Y-%m-%d %H:%M:%S", &tm);
    
    /* Log to database */
    db_insert_play(app, tsbuf, artist, title, "", confidence, source);
    
    /* Update last track (for SSE/UI) */
    pthread_mutex_lock(&app->db_mu);
    snprintf(app->last_artist, sizeof(app->last_artist), "%s", artist ? artist : "");
    snprintf(app->last_title, sizeof(app->last_title), "%s", title ? title : "");
    snprintf(app->last_source, sizeof(app->last_source), "%s", source ? source : "cdj");
    app->last_confidence = confidence;
    app->last_isrc[0] = '\0';
    pthread_mutex_unlock(&app->db_mu);
    
    /* Bump track sequence for UI updates */
    atomic_fetch_add_explicit(&app->track_seq, 1, memory_order_release);
    
    (void)deck;  /* Unused but informational */
}

/* ─────────────────────────────────────────────────────────────────────────────
 * Main
 * ───────────────────────────────────────────────────────────────────────────── */

int main(int argc, char **argv) {
    setvbuf(stderr, NULL, _IONBF, 0);
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    srand((unsigned)(ts.tv_nsec ^ ts.tv_sec));

    Config cfg = {
        .device = "default",
        .rate = 48000,
        .channels = 2,
        .frames_per_read = 1024,
        .fingerprint_sec = 12,
        .min_rms = 300,
        .identify_interval_sec = 2,
        .user_agent = NULL,
        .timezone = NULL,
        .shazam_gap_sec = 10,
        .same_track_hold_sec = 90,
        .threshold = 50,
        .sustain_sec = 1.0f,
        .silence_sec = 15.0f,
        .prefix = "capture",
        .source = NULL,         /* must be specified unless CDJ-only mode */
        .bytes_per_sample = 2,
        .max_file_sec = 600,    /* 10 minutes */
        .ring_sec = 0,          /* 0 = auto-size to max_file_sec */
        .outdir = NULL,         /* current directory */
        .format = "wav",        /* default to WAV */
        .pcap_buffer_mb = 0,    /* 0 = OS default */
        .slink_backend = NULL,  /* auto-select based on what's compiled in */
        .match_threshold = 60,  /* 60% similarity for fuzzy matching */
        /* Mode flags - all disabled by default, must explicitly enable */
        .enable_record = 0,
        .enable_audio_tag = 0,
        .enable_cdj_tag = 0,
    };
    if (parse_cli(argc, argv, &cfg) != 0) return 2;

    /* Sync globals with config */
    match_threshold = cfg.match_threshold;

    /* Validate: at least one feature must be enabled */
    if (!cfg.enable_record && !cfg.enable_audio_tag && !cfg.enable_cdj_tag) {
        logmsg("main", "no features enabled - use --record, --audio-tag, and/or --cdj-tag");
        usage(argv[0]);
        return 2;
    }

    /* Determine if we need audio capture */
    int need_audio = cfg.enable_record || cfg.enable_audio_tag;
    
    /* CDJ tagging validation */
    if (cfg.enable_cdj_tag) {
        if (!cfg.prolink_interface) {
            logmsg("main", "--cdj-tag requires --prolink-interface");
            return 2;
        }
        if (!cfg.db_path) {
            logmsg("main", "--cdj-tag requires --db for track logging");
            return 2;
        }
    }
    
    /* Audio tagging validation */
#ifndef HAVE_VIBRA
    if (cfg.enable_audio_tag) {
        logmsg("main", "--audio-tag requires libvibra (not found at build time)");
        logmsg("main", "use --cdj-tag for CDJ-only track identification");
        return 2;
    }
#endif
    
    /* Validate audio source if needed */
    int source_valid = 0;
    if (need_audio) {
#ifdef HAVE_ALSA
        if (cfg.source && strcmp(cfg.source, "alsa") == 0) source_valid = 1;
#endif
#if defined(HAVE_PCAP) || defined(HAVE_AF_XDP)
        if (cfg.source && strcmp(cfg.source, "slink") == 0) source_valid = 1;
#endif
        if (!source_valid) {
#if defined(HAVE_ALSA) && (defined(HAVE_PCAP) || defined(HAVE_AF_XDP))
            logmsg("main", "--source is required: 'alsa' or 'slink'");
#elif defined(HAVE_ALSA)
            logmsg("main", "--source is required: 'alsa'");
#elif defined(HAVE_PCAP) || defined(HAVE_AF_XDP)
            logmsg("main", "--source is required: 'slink'");
#else
            logmsg("main", "no audio sources compiled in");
#endif
            return 2;
        }
    }

    /* SLink is always 24-bit */
    if (cfg.source && !strcmp(cfg.source, "slink")) {
        cfg.bytes_per_sample = 3;

        /* Set default backend based on what's compiled in */
        if (!cfg.slink_backend) {
#ifdef HAVE_PCAP
            cfg.slink_backend = "pcap";
#elif defined(HAVE_AF_XDP)
            cfg.slink_backend = "afxdp";
#endif
        }

        /* Validate slink backend */
        if (cfg.slink_backend && strcmp(cfg.slink_backend, "pcap") != 0 && strcmp(cfg.slink_backend, "afxdp") != 0) {
            logmsg("main", "--slink-backend must be 'pcap' or 'afxdp'");
            return 2;
        }
#ifndef HAVE_PCAP
        if (cfg.slink_backend && !strcmp(cfg.slink_backend, "pcap")) {
            logmsg("main", "pcap backend not compiled in (build with libpcap)");
            return 2;
        }
#endif
#ifndef HAVE_AF_XDP
        if (cfg.slink_backend && !strcmp(cfg.slink_backend, "afxdp")) {
            logmsg("main", "AF_XDP backend not compiled in (build with ENABLE_AF_XDP=1)");
            return 2;
        }
#endif
    }

    /* Ring buffer sizing */
    if (need_audio) {
        if (cfg.enable_record) {
            /* Recording needs headroom for async file writes */
            unsigned min_ring_sec = cfg.max_file_sec > 0 ? cfg.max_file_sec + 60 : 600;
            if (cfg.ring_sec == 0) {
                cfg.ring_sec = min_ring_sec;
            } else if (cfg.max_file_sec > 0 && cfg.ring_sec <= cfg.max_file_sec) {
                logmsg("main", "--ring-sec (%u) must be > --max-file-sec (%u) to allow headroom for writes",
                       cfg.ring_sec, cfg.max_file_sec);
                return 2;
            }
        } else if (cfg.enable_audio_tag && cfg.ring_sec == 0) {
            /* Audio tagging needs at least fingerprint_sec * 2 for buffering */
            cfg.ring_sec = cfg.fingerprint_sec * 2;
        }
    }

    App app = {0};
    app.cfg = cfg;

    /* Initialize ring buffer (only if recording or audio tagging) */
    if (need_audio) {
        size_t ring_frames = (size_t)cfg.ring_sec * cfg.rate;
        if (asyncwr_init(&app.aw, cfg.channels, cfg.rate, cfg.bytes_per_sample,
                         ring_frames, cfg.outdir, cfg.prefix, cfg.format) != 0) {
            logmsg("main", "audio buffer alloc failed");
            return 1;
        }
    }
    
    if (db_init(&app) != 0) {
        logmsg("main", "database init failed");
        if (need_audio) asyncwr_free(&app.aw);
        return 1;
    }

    /* Pre-allocate capture buffer (only if audio capture needed) */
    if (need_audio) {
        app.cap_buf_size = cfg.frames_per_read * cfg.channels * cfg.bytes_per_sample;
        app.cap_buf = (uint8_t *)malloc(app.cap_buf_size);
        if (!app.cap_buf) {
            logmsg("main", "capture buffer alloc failed");
            db_close(&app);
            asyncwr_free(&app.aw);
            return 1;
        }
    }

    /* Pre-allocate writer buffers (only if recording) */
    if (cfg.enable_record && need_audio) {
        app.wrt_buf = (uint8_t *)malloc(app.cap_buf_size);
        if (!app.wrt_buf) {
            logmsg("main", "writer buffer alloc failed");
            free(app.cap_buf);
            db_close(&app);
            asyncwr_free(&app.aw);
            return 1;
        }
        app.wrt_window_size = (unsigned)((cfg.sustain_sec * cfg.rate + (cfg.frames_per_read - 1)) / cfg.frames_per_read);
        app.wrt_window = (unsigned *)calloc(app.wrt_window_size, sizeof(unsigned));
        if (!app.wrt_window) {
            logmsg("main", "writer window alloc failed");
            free(app.wrt_buf);
            free(app.cap_buf);
            db_close(&app);
            asyncwr_free(&app.aw);
            return 1;
        }
    }

    /* Pre-allocate id_main buffers (only if audio tagging) */
    if (cfg.enable_audio_tag && need_audio) {
        app.id_buf_frames = (size_t)cfg.fingerprint_sec * cfg.rate;
        size_t id_fb = cfg.channels * cfg.bytes_per_sample;
        app.id_buf = (uint8_t *)malloc(app.id_buf_frames * id_fb);
        if (!app.id_buf) {
            logmsg("main", "id buffer alloc failed");
            free(app.wrt_window);
            free(app.wrt_buf);
            free(app.cap_buf);
            db_close(&app);
            asyncwr_free(&app.aw);
            return 1;
        }
        app.id_buf_s16 = (int16_t *)malloc(sizeof(int16_t) * app.id_buf_frames * cfg.channels);
        if (!app.id_buf_s16) {
            logmsg("main", "id s16 buffer alloc failed");
            free(app.id_buf);
            free(app.wrt_window);
            free(app.wrt_buf);
            free(app.cap_buf);
            db_close(&app);
            asyncwr_free(&app.aw);
            return 1;
        }
    }

    struct sigaction sa = {0};
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    /* Log mode information */
    logmsg("main", "mode: record=%s audio-tag=%s cdj-tag=%s",
           cfg.enable_record ? "on" : "off",
           cfg.enable_audio_tag ? "on" : "off",
           cfg.enable_cdj_tag ? "on" : "off");
    
    if (need_audio) {
        logmsg("main", "audio: dev=%s rate=%u ch=%u frames=%u fingerprint=%us interval=%us thr=%u sustain=%.2fs silence=%.2fs split=%us ring=%us",
               app.cfg.device, app.cfg.rate, app.cfg.channels, app.cfg.frames_per_read,
               app.cfg.fingerprint_sec, app.cfg.identify_interval_sec,
               app.cfg.threshold, app.cfg.sustain_sec, app.cfg.silence_sec, app.cfg.max_file_sec,
               app.cfg.ring_sec);
    }

    /* Track which threads are running */
    int cap_running = 0, id_running = 0, wrt_running = 0, sse_running = 0;

    /* Start capture thread (only if audio needed) */
    if (need_audio) {
        if (pthread_create(&app.th_cap, NULL, capture_main, &app) != 0) {
            logmsg("main", "pthread cap failed");
            goto cleanup;
        }
        cap_running = 1;
    }
    
    /* Start identification thread (only if audio tagging enabled) */
    if (cfg.enable_audio_tag && need_audio) {
        if (pthread_create(&app.th_id, NULL, id_main, &app) != 0) {
            logmsg("main", "pthread id failed");
            g_running = 0;
            goto cleanup;
        }
        id_running = 1;
    }
    
    /* Start writer thread (only if recording enabled) */
    if (cfg.enable_record && need_audio) {
        if (pthread_create(&app.th_wrt, NULL, writer_main, &app) != 0) {
            logmsg("main", "pthread wrt failed");
            g_running = 0;
            goto cleanup;
        }
        wrt_running = 1;
    }
    
    /* Start SSE server thread (if configured) */
    if (app.cfg.sse_socket) {
        if (pthread_create(&app.th_sse, NULL, sse_main, &app) != 0) {
            logmsg("main", "pthread sse failed");
            g_running = 0;
            goto cleanup;
        }
        sse_running = 1;
    }

    /* Start Pro DJ Link CDJ sniffer thread (if CDJ tagging enabled) */
    if (cfg.enable_cdj_tag && app.cfg.prolink_interface) {
        app.prolink = (ProlinkThread *)malloc(sizeof(ProlinkThread));
        if (app.prolink) {
            if (prolink_init(app.prolink, app.cfg.prolink_interface, g_verbose) != 0) {
                logmsg("main", "prolink init failed (continuing without CDJ support)");
                free(app.prolink);
                app.prolink = NULL;
            } else {
                logmsg("main", "CDJ sniffer started on %s", app.cfg.prolink_interface);
                
                /* Enable CDJ-only tagging if no audio tagging (pure CDJ mode) */
                if (!cfg.enable_audio_tag) {
                    prolink_enable_tagging(app.prolink, cdj_tag_callback, &app);
                }
            }
        }
    }

    while (g_running) {
        /* Check for CDJ tracks to log (if in CDJ-only tagging mode) */
        if (app.prolink && !cfg.enable_audio_tag) {
            prolink_check_tagging(app.prolink);
        }
        
        struct timespec snooze = {.tv_sec = 1, .tv_nsec = 0};
        nanosleep(&snooze, NULL);
    }

cleanup:
    /* Join threads that were started */
    if (cap_running) pthread_join(app.th_cap, NULL);
    if (id_running) pthread_join(app.th_id, NULL);
    if (wrt_running) pthread_join(app.th_wrt, NULL);
    if (sse_running) pthread_join(app.th_sse, NULL);
    
    if (app.prolink) {
        prolink_shutdown(app.prolink);
        free(app.prolink);
    }
    db_close(&app);
    
    /* Free buffers that were allocated */
    if (app.id_buf_s16) free(app.id_buf_s16);
    if (app.id_buf) free(app.id_buf);
    if (app.wrt_window) free(app.wrt_window);
    if (app.wrt_buf) free(app.wrt_buf);
    if (app.cap_buf) free(app.cap_buf);
    if (need_audio) asyncwr_free(&app.aw);
    
    logmsg("main", "bye");
    return 0;
}
