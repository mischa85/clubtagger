/*
 * sse_server.c - Server-Sent Events for VU meter and track updates
 */
#include "sse_server.h"
#include "../common.h"
#include "../prolink/cdj_types.h"

#include <errno.h>
#include <fcntl.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

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
    for (int i = 0; i < SSE_MAX_CLIENTS; i++) clients[i] = -1;

    uint32_t last_track_seq = 0;

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

        /* Build VU message */
        uint16_t vu_l = atomic_load_explicit(&app->vu_left, memory_order_relaxed);
        uint16_t vu_r = atomic_load_explicit(&app->vu_right, memory_order_relaxed);
        char vu_msg[64];
        int vu_len = snprintf(vu_msg, sizeof(vu_msg), "data: {\"l\":%u,\"r\":%u}\n\n", vu_l, vu_r);

        /* Check for track change */
        uint32_t track_seq = atomic_load_explicit(&app->track_seq, memory_order_acquire);
        char track_msg[1024];
        int track_len = 0;
        if (track_seq != last_track_seq) {
            last_track_seq = track_seq;
            pthread_mutex_lock(&app->db_mu);
            /* Escape strings for safe JSON output */
            char escaped_artist[256];
            char escaped_title[256];
            json_escape(app->last_artist, escaped_artist, sizeof(escaped_artist));
            json_escape(app->last_title, escaped_title, sizeof(escaped_title));
            track_len = snprintf(track_msg, sizeof(track_msg),
                                 "event: track\ndata: {\"a\":\"%s\",\"t\":\"%s\"}\n\n",
                                 escaped_artist, escaped_title);
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
