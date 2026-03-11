/*
 * sse_server.c - Server-Sent Events for VU meter and track updates
 */
#include "sse_server.h"
#include "../common.h"
#include "../prolink/cdj_types.h"
#include "../db/database.h"

#include <errno.h>
#include <fcntl.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#ifdef __APPLE__
#include <mach/mach.h>
#include <sys/sysctl.h>
#else
#include <sys/sysinfo.h>
#endif

/* Number of recent tracks to send when a client connects */
#define SSE_INITIAL_TRACKS 5

static const char *SSE_HEADERS =
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: text/event-stream\r\n"
    "Cache-Control: no-cache\r\n"
    "Connection: keep-alive\r\n"
    "Access-Control-Allow-Origin: *\r\n"
    "\r\n";

void *sse_main(void *arg) {
    App *app = (App *)arg;
    const char *socket_path = app->cfg.sse_socket;

    /* Create Unix socket */
    int server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_fd < 0) {
        logmsg("sse", "socket() failed: %s", strerror(errno));
        return NULL;
    }

    /* Remove existing socket file */
    unlink(socket_path);

    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", socket_path);

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        logmsg("sse", "bind() failed: %s", strerror(errno));
        close(server_fd);
        return NULL;
    }

    /* Make socket world-readable/writable for nginx */
    chmod(socket_path, 0666);

    if (listen(server_fd, 8) < 0) {
        logmsg("sse", "listen() failed: %s", strerror(errno));
        close(server_fd);
        return NULL;
    }

    /* Set non-blocking for accept */
    fcntl(server_fd, F_SETFL, O_NONBLOCK);

    logmsg("sse", "started: socket=%s", socket_path);

    /* Simple client tracking - max 8 concurrent clients */
#define SSE_MAX_CLIENTS 8
    int clients[SSE_MAX_CLIENTS];
    int client_needs_init[SSE_MAX_CLIENTS];  /* Flag for sending initial data */
    for (int i = 0; i < SSE_MAX_CLIENTS; i++) {
        clients[i] = -1;
        client_needs_init[i] = 0;
    }

    uint32_t last_track_seq = 0;
    int last_shazam_state = -1;
    int last_shazam_confirms = 0;

    while (g_running) {
        /* Accept new connections */
        int client_fd = accept(server_fd, NULL, NULL);
        if (client_fd >= 0) {
            /* Skip HTTP request (nginx proxies clean) */
            char buf[1024];
            ssize_t n = recv(client_fd, buf, sizeof(buf), MSG_DONTWAIT);
            (void)n;

            /* Send SSE headers */
            if (send(client_fd, SSE_HEADERS, strlen(SSE_HEADERS), MSG_NOSIGNAL) < 0) {
                close(client_fd);
            } else {
                /* Find slot for new client */
                int added = 0;
                for (int i = 0; i < SSE_MAX_CLIENTS; i++) {
                    if (clients[i] < 0) {
                        clients[i] = client_fd;
                        client_needs_init[i] = 1;  /* Mark for initial data send */
                        fcntl(client_fd, F_SETFL, O_NONBLOCK);
                        logmsg("sse", "client connected (slot %d)", i);
                        added = 1;
                        break;
                    }
                }
                if (!added) {
                    logmsg("sse", "max clients reached, rejecting");
                    close(client_fd);
                }
            }
        }

        /* Send initial history and shazam state to new clients */
        for (int i = 0; i < SSE_MAX_CLIENTS; i++) {
            if (clients[i] >= 0 && client_needs_init[i]) {
                client_needs_init[i] = 0;

                /* Send recent tracks */
                char timestamps[SSE_INITIAL_TRACKS][32];
                char artists[SSE_INITIAL_TRACKS][256];
                char titles[SSE_INITIAL_TRACKS][256];
                char sources[SSE_INITIAL_TRACKS][16];
                int confidences[SSE_INITIAL_TRACKS];
                int count = db_get_recent_tracks(app, SSE_INITIAL_TRACKS, timestamps, artists, titles, sources, confidences);

                if (count > 0) {
                    char history_msg[4096];
                    int history_len = snprintf(history_msg, sizeof(history_msg), "event: history\ndata: [");
                    for (int t = 0; t < count; t++) {
                        char esc_artist[512], esc_title[512];
                        json_escape(artists[t], esc_artist, sizeof(esc_artist));
                        json_escape(titles[t], esc_title, sizeof(esc_title));
                        if (t > 0) history_len += snprintf(history_msg + history_len, sizeof(history_msg) - history_len, ",");
                        history_len += snprintf(history_msg + history_len, sizeof(history_msg) - history_len,
                            "{\"ts\":\"%s\",\"a\":\"%s\",\"t\":\"%s\",\"src\":\"%s\",\"conf\":%d}",
                            timestamps[t], esc_artist, esc_title, sources[t], confidences[t]);
                    }
                    history_len += snprintf(history_msg + history_len, sizeof(history_msg) - history_len, "]\n\n");
                    send(clients[i], history_msg, history_len, MSG_NOSIGNAL);
                }

                /* Send current shazam state */
                int state = atomic_load_explicit(&app->shazam_state, memory_order_relaxed);
                char shazam_msg[1024];
                int shazam_len;
                if (state == SHAZAM_CONFIRMING) {
                    pthread_mutex_lock(&app->db_mu);
                    char esc_cand[1024];
                    json_escape(app->shazam_candidate, esc_cand, sizeof(esc_cand));
                    shazam_len = snprintf(shazam_msg, sizeof(shazam_msg),
                        "event: shazam\ndata: {\"state\":%d,\"candidate\":\"%s\",\"confirms\":%d,\"needed\":%d,\"conf\":%d,\"cdj\":%s}\n\n",
                        state, esc_cand, app->shazam_confirms, app->shazam_confirms_needed, 
                        app->shazam_confidence, app->shazam_cdj_confirmed ? "true" : "false");
                    pthread_mutex_unlock(&app->db_mu);
                } else {
                    pthread_mutex_lock(&app->db_mu);
                    shazam_len = snprintf(shazam_msg, sizeof(shazam_msg),
                        "event: shazam\ndata: {\"state\":%d,\"attempts\":%d}\n\n", state, app->shazam_no_match_count);
                    pthread_mutex_unlock(&app->db_mu);
                }
                send(clients[i], shazam_msg, shazam_len, MSG_NOSIGNAL);
            }
        }

        /* Build VU message with audio stats */
        uint16_t vu_l = atomic_load_explicit(&app->vu_left, memory_order_relaxed);
        uint16_t vu_r = atomic_load_explicit(&app->vu_right, memory_order_relaxed);
        uint64_t lost = atomic_load_explicit(&app->audio_lost, memory_order_relaxed);
        uint64_t frames = atomic_load_explicit(&app->aw.total_written, memory_order_relaxed);
        uint64_t disk_bytes = atomic_load_explicit(&app->aw.bytes_on_disk, memory_order_relaxed);
        int is_rec = atomic_load_explicit(&app->is_recording, memory_order_relaxed);
        
        /* Get system load average */
        double loadavg[1] = {0};
        getloadavg(loadavg, 1);
        
        /* Get memory stats */
        uint64_t mem_used = 0, mem_total = 0;
#ifdef __APPLE__
        struct task_basic_info info;
        mach_msg_type_number_t count = TASK_BASIC_INFO_COUNT;
        if (task_info(mach_task_self(), TASK_BASIC_INFO, (task_info_t)&info, &count) == KERN_SUCCESS) {
            mem_used = info.resident_size;
        }
        int mib[2] = {CTL_HW, HW_MEMSIZE};
        size_t len = sizeof(mem_total);
        sysctl(mib, 2, &mem_total, &len, NULL, 0);
#else
        struct sysinfo si;
        if (sysinfo(&si) == 0) {
            mem_total = si.totalram * si.mem_unit;
            mem_used = (si.totalram - si.freeram) * si.mem_unit;
        }
#endif
        
        /* Get disk space */
        uint64_t disk_free = 0, disk_total = 0;
        const char *outdir = app->cfg.outdir ? app->cfg.outdir : ".";
        struct statvfs svfs;
        if (statvfs(outdir, &svfs) == 0) {
            disk_free = (uint64_t)svfs.f_bavail * svfs.f_frsize;
            disk_total = (uint64_t)svfs.f_blocks * svfs.f_frsize;
        }
        
        char vu_msg[512];
        int vu_len = snprintf(vu_msg, sizeof(vu_msg), 
            "data: {\"l\":%u,\"r\":%u,\"lost\":%llu,\"frames\":%llu,\"rate\":%u,\"ch\":%u,"
            "\"rec\":%d,\"load\":%.2f,\"written\":%llu,\"mem\":%llu,\"memtot\":%llu,"
            "\"diskfree\":%llu,\"disktot\":%llu,\"fmt\":\"%s\"}\n\n", 
            vu_l, vu_r, (unsigned long long)lost, (unsigned long long)frames,
            app->cfg.rate, app->cfg.channels, is_rec, loadavg[0],
            (unsigned long long)disk_bytes, (unsigned long long)mem_used,
            (unsigned long long)mem_total, (unsigned long long)disk_free,
            (unsigned long long)disk_total, app->cfg.format ? app->cfg.format : "wav");

        /* Check for track change */
        uint32_t track_seq = atomic_load_explicit(&app->track_seq, memory_order_acquire);
        char track_msg[1536];
        int track_len = 0;
        if (track_seq != last_track_seq) {
            last_track_seq = track_seq;
            pthread_mutex_lock(&app->db_mu);
            /* Escape strings for safe JSON output */
            char escaped_artist[256];
            char escaped_title[256];
            char escaped_isrc[128];
            json_escape(app->last_artist, escaped_artist, sizeof(escaped_artist));
            json_escape(app->last_title, escaped_title, sizeof(escaped_title));
            json_escape(app->last_isrc, escaped_isrc, sizeof(escaped_isrc));
            track_len = snprintf(track_msg, sizeof(track_msg),
                                 "event: track\ndata: {\"a\":\"%s\",\"t\":\"%s\",\"src\":\"%s\",\"conf\":%d,\"isrc\":\"%s\"}\n\n",
                                 escaped_artist, escaped_title, app->last_source, app->last_confidence, escaped_isrc);
            pthread_mutex_unlock(&app->db_mu);
        }

        /* Send to all connected clients */
        for (int i = 0; i < SSE_MAX_CLIENTS; i++) {
            if (clients[i] < 0) continue;

            ssize_t sent = send(clients[i], vu_msg, vu_len, MSG_NOSIGNAL);
            if (sent < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                logmsg("sse", "client disconnected (slot %d)", i);
                close(clients[i]);
                clients[i] = -1;
                continue;
            }

            if (track_len > 0) {
                send(clients[i], track_msg, track_len, MSG_NOSIGNAL);
            }
        }

        /* Build deck status message (every ~500ms) */
        static int deck_counter = 0;
        if (++deck_counter >= 30) {  /* 30 * 16.7ms = ~500ms */
            deck_counter = 0;
            char deck_msg[2048];
            int deck_len = 0;
            deck_len += snprintf(deck_msg + deck_len, sizeof(deck_msg) - deck_len,
                                 "event: decks\ndata: [");
            int first = 1;
            time_t now = time(NULL);
            for (int d = 0; d < MAX_DEVICES; d++) {
                cdj_device_t *dev = &devices[d];
                if (!dev->active) continue;
                if (dev->device_type != DEVICE_TYPE_CDJ) continue;
                if (now - dev->last_seen > 10) continue;  /* Stale */
                
                char escaped_title[256], escaped_artist[256], escaped_name[64];
                json_escape(dev->track_title, escaped_title, sizeof(escaped_title));
                json_escape(dev->track_artist, escaped_artist, sizeof(escaped_artist));
                json_escape(dev->name, escaped_name, sizeof(escaped_name));
                
                if (!first) deck_len += snprintf(deck_msg + deck_len, sizeof(deck_msg) - deck_len, ",");
                first = 0;
                deck_len += snprintf(deck_msg + deck_len, sizeof(deck_msg) - deck_len,
                    "{\"n\":%d,\"name\":\"%s\",\"playing\":%d,\"on_air\":%d,"
                    "\"title\":\"%s\",\"artist\":\"%s\",\"bpm\":%d,\"slot\":%d}",
                    dev->device_num, escaped_name, dev->playing ? 1 : 0, dev->on_air ? 1 : 0,
                    escaped_title, escaped_artist, dev->bpm_raw / 100, dev->track_slot);
            }
            deck_len += snprintf(deck_msg + deck_len, sizeof(deck_msg) - deck_len, "]\n\n");
            
            /* Send deck status to all clients */
            for (int i = 0; i < SSE_MAX_CLIENTS; i++) {
                if (clients[i] >= 0) {
                    send(clients[i], deck_msg, deck_len, MSG_NOSIGNAL);
                }
            }

            /* Check for shazam state change and send update */
            int cur_shazam_state = atomic_load_explicit(&app->shazam_state, memory_order_relaxed);
            int cur_confirms = (cur_shazam_state == SHAZAM_CONFIRMING) ? app->shazam_confirms : 0;
            if (cur_shazam_state != last_shazam_state || 
                (cur_shazam_state == SHAZAM_CONFIRMING && cur_confirms != last_shazam_confirms)) {
                last_shazam_state = cur_shazam_state;
                last_shazam_confirms = cur_confirms;
                char shazam_msg[1024];
                int shazam_len;
                if (cur_shazam_state == SHAZAM_CONFIRMING) {
                    pthread_mutex_lock(&app->db_mu);
                    char esc_cand[1024];
                    json_escape(app->shazam_candidate, esc_cand, sizeof(esc_cand));
                    shazam_len = snprintf(shazam_msg, sizeof(shazam_msg),
                        "event: shazam\ndata: {\"state\":%d,\"candidate\":\"%s\",\"confirms\":%d,\"needed\":%d,\"conf\":%d,\"cdj\":%s}\n\n",
                        cur_shazam_state, esc_cand, app->shazam_confirms, app->shazam_confirms_needed,
                        app->shazam_confidence, app->shazam_cdj_confirmed ? "true" : "false");
                    pthread_mutex_unlock(&app->db_mu);
                } else {
                    pthread_mutex_lock(&app->db_mu);
                    shazam_len = snprintf(shazam_msg, sizeof(shazam_msg),
                        "event: shazam\ndata: {\"state\":%d,\"attempts\":%d}\n\n", cur_shazam_state, app->shazam_no_match_count);
                    pthread_mutex_unlock(&app->db_mu);
                }
                for (int i = 0; i < SSE_MAX_CLIENTS; i++) {
                    if (clients[i] >= 0) {
                        send(clients[i], shazam_msg, shazam_len, MSG_NOSIGNAL);
                    }
                }
            }
        }

        /* 60 Hz update rate */
        struct timespec ts = {.tv_sec = 0, .tv_nsec = 16666666}; /* ~16.7ms */
        nanosleep(&ts, NULL);
    }

    /* Cleanup */
    for (int i = 0; i < SSE_MAX_CLIENTS; i++) {
        if (clients[i] >= 0) close(clients[i]);
    }
    close(server_fd);
    unlink(socket_path);
    logmsg("sse", "exit");
    return NULL;
}
