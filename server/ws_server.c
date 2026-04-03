/*
 * ws_server.c - WebSocket server for real-time CDJ data and track updates
 *
 * Single WebSocket connection per client:
 * - Binary frames: raw Pro DJ Link packets (forwarded from prolink thread)
 * - Text frames: JSON events (track, history, log, shazam, VU meters)
 */
#include "ws_server.h"
#include "../common.h"
#include "../prolink/cdj_types.h"
#include "../prolink/onelibrary.h"
#include "../confidence.h"
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
#include <openssl/sha.h>
#include <openssl/evp.h>

#ifdef __APPLE__
#include <mach/mach.h>
#include <sys/sysctl.h>
#else
#include <sys/sysinfo.h>
#endif

#define WS_MAX_CLIENTS 8
#define WS_INITIAL_TRACKS 5
#define WS_MAGIC_GUID "258EAFA5-E914-47DA-95CA-5AB0141B3CF2"

/* Auth token — set from config before thread starts */
static const char *ws_token = NULL;

/* Shared client array — prolink thread sends binary, ws thread sends text.
 * Writes to ws_clients[i] are only done by ws thread (accept/close).
 * Reads + send() can happen from any thread (non-blocking, atomic FDs).
 * ws_client_ready: set after first successful text frame send.
 * Binary broadcasts only go to ready clients (prevents race with handshake). */
static _Atomic int ws_clients[WS_MAX_CLIENTS];
static _Atomic int ws_client_ready[WS_MAX_CLIENTS];

static void ws_clients_init(void) {
    for (int i = 0; i < WS_MAX_CLIENTS; i++) {
        atomic_store(&ws_clients[i], -1);
        atomic_store(&ws_client_ready[i], 0);
    }
}

/*
 * ============================================================================
 * WebSocket Frame Encoding (RFC 6455)
 * ============================================================================
 */

/* Send a WebSocket frame. Server→client frames are NOT masked.
 * opcode: 0x01=text, 0x02=binary, 0x09=ping, 0x0A=pong, 0x08=close
 * Returns bytes sent or -1 on error. */
static ssize_t ws_send_frame(int fd, uint8_t opcode, const void *data, size_t len) {
    uint8_t header[10];
    int hlen = 0;

    header[0] = 0x80 | opcode;  /* FIN + opcode */

    if (len < 126) {
        header[1] = (uint8_t)len;
        hlen = 2;
    } else if (len < 65536) {
        header[1] = 126;
        header[2] = (uint8_t)(len >> 8);
        header[3] = (uint8_t)(len & 0xFF);
        hlen = 4;
    } else {
        header[1] = 127;
        header[2] = 0; header[3] = 0; header[4] = 0; header[5] = 0;
        header[6] = (uint8_t)(len >> 24);
        header[7] = (uint8_t)(len >> 16);
        header[8] = (uint8_t)(len >> 8);
        header[9] = (uint8_t)(len & 0xFF);
        hlen = 10;
    }

    /* Send header + payload with writev-style gather (or two sends) */
    struct iovec iov[2] = {
        { .iov_base = header, .iov_len = hlen },
        { .iov_base = (void *)data, .iov_len = len }
    };
    struct msghdr msg = {0};
    msg.msg_iov = iov;
    msg.msg_iovlen = 2;
    return sendmsg(fd, &msg, MSG_NOSIGNAL | MSG_DONTWAIT);
}

/* Send a text frame (JSON event) */
static ssize_t ws_send_text(int fd, const char *data, size_t len) {
    return ws_send_frame(fd, 0x01, data, len);
}

/* Send a binary frame (raw packet) */
static ssize_t ws_send_binary(int fd, const void *data, size_t len) {
    return ws_send_frame(fd, 0x02, data, len);
}

/* Send text to all connected and ready clients, remove dead ones */
static void ws_broadcast_text(const char *data, size_t len) {
    for (int i = 0; i < WS_MAX_CLIENTS; i++) {
        int fd = atomic_load(&ws_clients[i]);
        if (fd < 0 || !atomic_load(&ws_client_ready[i])) continue;
        ssize_t sent = ws_send_text(fd, data, len);
        if (sent < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
            logmsg("ws", "client send failed (slot %d): errno=%d %s", i, errno, strerror(errno));
            atomic_store(&ws_client_ready[i], 0);
            close(fd);
            atomic_store(&ws_clients[i], -1);
        }
    }
}

/*
 * ============================================================================
 * WebSocket Handshake (RFC 6455)
 * ============================================================================
 */

/* Extract Sec-WebSocket-Key from HTTP request headers */
static int ws_extract_key(const char *request, char *key_out, size_t key_sz) {
    const char *needle = "Sec-WebSocket-Key:";
    const char *p = strcasestr(request, needle);
    if (!p) return -1;
    p += strlen(needle);
    while (*p == ' ') p++;
    size_t i = 0;
    while (*p && *p != '\r' && *p != '\n' && i < key_sz - 1)
        key_out[i++] = *p++;
    key_out[i] = '\0';
    return 0;
}

/* Perform WebSocket handshake on a new connection.
 * Returns 0 on success (connection upgraded), -1 on failure. */
static int ws_handshake(int fd) {
    char request[2048];
    ssize_t n = recv(fd, request, sizeof(request) - 1, 0);
    if (n <= 0) return -1;
    request[n] = '\0';

    /* Check for WebSocket upgrade request */
    if (!strcasestr(request, "Upgrade: websocket")) {
        const char *http_resp = "HTTP/1.1 426 Upgrade Required\r\n"
                                "Content-Type: text/plain\r\n"
                                "Connection: close\r\n\r\n"
                                "WebSocket connection required\n";
        send(fd, http_resp, strlen(http_resp), MSG_NOSIGNAL);
        return -1;
    }

    /* Validate auth token from query string: GET /ws?token=xxx */
    if (ws_token && ws_token[0]) {
        char expected[256];
        snprintf(expected, sizeof(expected), "token=%s", ws_token);
        if (!strstr(request, expected)) {
            const char *http_resp = "HTTP/1.1 403 Forbidden\r\n"
                                    "Content-Type: text/plain\r\n"
                                    "Connection: close\r\n\r\n"
                                    "Invalid token\n";
            send(fd, http_resp, strlen(http_resp), MSG_NOSIGNAL);
            return -1;
        }
    }

    /* Extract Sec-WebSocket-Key */
    char ws_key[128];
    if (ws_extract_key(request, ws_key, sizeof(ws_key)) != 0) return -1;

    /* Compute accept hash: SHA1(key + GUID), then base64 encode */
    char concat[256];
    snprintf(concat, sizeof(concat), "%s%s", ws_key, WS_MAGIC_GUID);

    unsigned char sha1_hash[SHA_DIGEST_LENGTH];
    SHA1((unsigned char *)concat, strlen(concat), sha1_hash);

    char accept_b64[64];
    EVP_EncodeBlock((unsigned char *)accept_b64, sha1_hash, SHA_DIGEST_LENGTH);

    /* Send 101 Switching Protocols response */
    char response[512];
    int resp_len = snprintf(response, sizeof(response),
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Accept: %s\r\n"
        "\r\n", accept_b64);

    if (send(fd, response, resp_len, MSG_NOSIGNAL) != resp_len) return -1;

    return 0;
}

/*
 * ============================================================================
 * Packet Broadcast (called from prolink thread)
 * ============================================================================
 */

/* Broadcast raw Pro DJ Link packet to all WebSocket clients.
 * Thread-safe: uses atomic client FD reads + non-blocking send.
 * Prepends 7-byte header: [port_id:1][src_ip:4][length:2] */
void ws_broadcast_packet(uint8_t port_id, uint32_t src_ip,
                         const uint8_t *payload, size_t len) {
    if (len == 0 || len > 4096) return;

    /* Build header + payload in one buffer to send as single binary frame */
    uint8_t buf[4096 + 7];
    buf[0] = port_id;
    memcpy(buf + 1, &src_ip, 4);  /* Network byte order (as received) */
    buf[5] = (uint8_t)(len >> 8);
    buf[6] = (uint8_t)(len & 0xFF);
    memcpy(buf + 7, payload, len);

    for (int i = 0; i < WS_MAX_CLIENTS; i++) {
        int fd = atomic_load(&ws_clients[i]);
        if (fd < 0 || !atomic_load(&ws_client_ready[i])) continue;
        /* Non-blocking send — drop if client can't keep up */
        ws_send_binary(fd, buf, len + 7);
    }
}

/*
 * ============================================================================
 * WebSocket Client Management (read incoming frames)
 * ============================================================================
 */

/* Read and handle one WebSocket frame from client (ping/pong/close).
 * Returns 0 on success, -1 if connection should be closed. */
static int ws_handle_client_frame(int fd) {
    uint8_t header[2];
    ssize_t n = recv(fd, header, 2, MSG_DONTWAIT | MSG_PEEK);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
        return -1;  /* Error */
    }
    if (n == 0) return -1;  /* Peer closed */
    if (n < 2) return 0;  /* Partial header, wait for more */
    /* Now actually consume the 2 bytes */
    recv(fd, header, 2, MSG_DONTWAIT);

    uint8_t opcode = header[0] & 0x0F;
    int masked = (header[1] & 0x80) != 0;
    uint64_t payload_len = header[1] & 0x7F;

    if (payload_len == 126) {
        uint8_t ext[2];
        if (recv(fd, ext, 2, 0) != 2) return -1;
        payload_len = (ext[0] << 8) | ext[1];
    } else if (payload_len == 127) {
        uint8_t ext[8];
        if (recv(fd, ext, 8, 0) != 8) return -1;
        payload_len = 0;
        for (int i = 0; i < 8; i++) payload_len = (payload_len << 8) | ext[i];
    }

    uint8_t mask[4] = {0};
    if (masked) {
        if (recv(fd, mask, 4, 0) != 4) return -1;
    }

    /* Read and unmask payload (limit to 4KB to prevent abuse) */
    if (payload_len > 4096) return -1;
    uint8_t payload[4096];
    size_t total = 0;
    while (total < payload_len) {
        n = recv(fd, payload + total, payload_len - total, 0);
        if (n <= 0) return -1;
        total += n;
    }
    if (masked) {
        for (size_t i = 0; i < payload_len; i++)
            payload[i] ^= mask[i % 4];
    }

    switch (opcode) {
    case 0x08: /* Close */
        ws_send_frame(fd, 0x08, payload, payload_len > 2 ? 2 : payload_len);
        return -1;
    case 0x09: /* Ping → Pong */
        ws_send_frame(fd, 0x0A, payload, payload_len);
        return 0;
    case 0x0A: /* Pong — ignore */
        return 0;
    default:
        return 0;  /* Text/binary from client — ignore for now */
    }
}

/*
 * ============================================================================
 * Main WebSocket Server Thread
 * ============================================================================
 */

void *ws_main(void *arg) {
    App *app = (App *)arg;
    const char *socket_path = app->cfg.ws_socket;
    ws_token = app->cfg.ws_token;

    /* Create Unix socket */
    int server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_fd < 0) {
        logmsg("ws", "socket() failed: %s", strerror(errno));
        return NULL;
    }

    unlink(socket_path);
    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", socket_path);

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        logmsg("ws", "bind() failed: %s", strerror(errno));
        close(server_fd);
        return NULL;
    }
    chmod(socket_path, 0666);

    if (listen(server_fd, 8) < 0) {
        logmsg("ws", "listen() failed: %s", strerror(errno));
        close(server_fd);
        return NULL;
    }
    fcntl(server_fd, F_SETFL, O_NONBLOCK);

    ws_clients_init();

    int client_needs_init[WS_MAX_CLIENTS];
    uint32_t client_log_seq[WS_MAX_CLIENTS];
    for (int i = 0; i < WS_MAX_CLIENTS; i++) {
        client_needs_init[i] = 0;
        client_log_seq[i] = 0;
    }

    logmsg("ws", "started: socket=%s (WebSocket)", socket_path);

    uint32_t last_track_seq = 0;
    int last_shazam_state = -1;
    int last_shazam_confirms = 0;

    while (g_running) {
        /* Accept new connections */
        int client_fd = accept(server_fd, NULL, NULL);
        if (client_fd >= 0) {
            /* Perform WebSocket handshake */
            if (ws_handshake(client_fd) != 0) {
                close(client_fd);
            } else {
                int added = 0;
                for (int i = 0; i < WS_MAX_CLIENTS; i++) {
                    if (atomic_load(&ws_clients[i]) < 0) {
                        fcntl(client_fd, F_SETFL, O_NONBLOCK);
                        atomic_store(&ws_clients[i], client_fd);
                        client_needs_init[i] = 1;
                        client_log_seq[i] = 0;
                        atomic_store(&ws_client_ready[i], 0);
                        logmsg("ws", "client connected (slot %d)", i);
                        added = 1;
                        break;
                    }
                }
                if (!added) {
                    logmsg("ws", "max clients reached, rejecting");
                    close(client_fd);
                }
            }
        }

        /* Handle incoming client frames (ping/pong/close).
         * Skip clients that haven't been initialized yet — recv on a
         * fresh connection can return 0 on some systems. */
        for (int i = 0; i < WS_MAX_CLIENTS; i++) {
            int fd = atomic_load(&ws_clients[i]);
            if (fd < 0 || !atomic_load(&ws_client_ready[i])) continue;
            if (ws_handle_client_frame(fd) < 0) {
                logmsg("ws", "client disconnected (slot %d)", i);
                atomic_store(&ws_client_ready[i], 0);
                close(fd);
                atomic_store(&ws_clients[i], -1);
            }
        }

        /* Send initial history to new clients */
        for (int i = 0; i < WS_MAX_CLIENTS; i++) {
            int fd = atomic_load(&ws_clients[i]);
            if (fd < 0 || !client_needs_init[i]) continue;
            client_needs_init[i] = 0;

            /* Send recent tracks */
            char timestamps[WS_INITIAL_TRACKS][32];
            char artists[WS_INITIAL_TRACKS][256];
            char titles[WS_INITIAL_TRACKS][256];
            char sources[WS_INITIAL_TRACKS][16];
            int confidences[WS_INITIAL_TRACKS];
            char isrcs[WS_INITIAL_TRACKS][64];
            int count = db_get_recent_tracks(app, WS_INITIAL_TRACKS, timestamps, artists, titles, sources, confidences, isrcs);

            if (count > 0) {
                char msg[4096];
                int len = snprintf(msg, sizeof(msg), "{\"event\":\"history\",\"data\":[");
                for (int t = 0; t < count; t++) {
                    char ea[512], et[512], ei[128];
                    json_escape(artists[t], ea, sizeof(ea));
                    json_escape(titles[t], et, sizeof(et));
                    json_escape(isrcs[t], ei, sizeof(ei));
                    if (t > 0) len += snprintf(msg + len, sizeof(msg) - len, ",");
                    len += snprintf(msg + len, sizeof(msg) - len,
                        "{\"ts\":\"%s\",\"a\":\"%s\",\"t\":\"%s\",\"src\":\"%s\",\"conf\":%d,\"isrc\":\"%s\"}",
                        timestamps[t], ea, et, sources[t], confidences[t], ei);
                }
                len += snprintf(msg + len, sizeof(msg) - len, "]}");
                ssize_t sent = ws_send_text(fd, msg, len);
                logmsg("ws", "init send: %zd bytes (payload %d)", sent, len);
            }

            /* Mark client ready for broadcasts */
            atomic_store(&ws_client_ready[i], 1);
            logmsg("ws", "client ready (slot %d)", i);
        }

        /* Build VU/stats message */
        uint16_t vu_l = atomic_load_explicit(&app->vu_left, memory_order_relaxed);
        uint16_t vu_r = atomic_load_explicit(&app->vu_right, memory_order_relaxed);
        uint64_t lost = atomic_load_explicit(&app->audio_lost, memory_order_relaxed);
        uint64_t frames = atomic_load_explicit(&app->aw.total_written, memory_order_relaxed);
        uint64_t disk_bytes = atomic_load_explicit(&app->aw.bytes_on_disk, memory_order_relaxed);
        int is_rec = atomic_load_explicit(&app->is_recording, memory_order_relaxed);

        double loadavg[1] = {0};
        getloadavg(loadavg, 1);

        uint64_t mem_used = 0, mem_total = 0;
#ifdef __APPLE__
        struct task_basic_info info;
        mach_msg_type_number_t mcount = TASK_BASIC_INFO_COUNT;
        if (task_info(mach_task_self(), TASK_BASIC_INFO, (task_info_t)&info, &mcount) == KERN_SUCCESS)
            mem_used = info.resident_size;
        int mib[2] = {CTL_HW, HW_MEMSIZE};
        size_t mlen = sizeof(mem_total);
        sysctl(mib, 2, &mem_total, &mlen, NULL, 0);
#else
        FILE *sf = fopen("/proc/self/status", "r");
        if (sf) {
            char line[128];
            while (fgets(line, sizeof(line), sf)) {
                if (strncmp(line, "VmRSS:", 6) == 0)
                    mem_used = (uint64_t)atoll(line + 6) * 1024;
            }
            fclose(sf);
        }
        struct sysinfo si;
        if (sysinfo(&si) == 0)
            mem_total = si.totalram * si.mem_unit;
#endif

        uint64_t disk_free = 0, disk_total = 0;
        const char *outdir = app->cfg.outdir ? app->cfg.outdir : ".";
        struct statvfs svfs;
        if (statvfs(outdir, &svfs) == 0) {
            disk_free = (uint64_t)svfs.f_bavail * svfs.f_frsize;
            disk_total = (uint64_t)svfs.f_blocks * svfs.f_frsize;
        }

        char vu_msg[512];
        int vu_len = snprintf(vu_msg, sizeof(vu_msg),
            "{\"event\":\"vu\",\"l\":%u,\"r\":%u,\"lost\":%llu,\"frames\":%llu,\"rate\":%u,\"ch\":%u,"
            "\"rec\":%d,\"load\":%.2f,\"written\":%llu,\"mem\":%llu,\"memtot\":%llu,"
            "\"diskfree\":%llu,\"disktot\":%llu,\"fmt\":\"%s\"}",
            vu_l, vu_r, (unsigned long long)lost, (unsigned long long)frames,
            app->cfg.rate, app->cfg.channels, is_rec, loadavg[0],
            (unsigned long long)disk_bytes, (unsigned long long)mem_used,
            (unsigned long long)mem_total, (unsigned long long)disk_free,
            (unsigned long long)disk_total, app->cfg.format ? app->cfg.format : "wav");

        ws_broadcast_text(vu_msg, vu_len);

        /* Check for track change */
        uint32_t track_seq = atomic_load_explicit(&app->track_seq, memory_order_acquire);
        if (track_seq != last_track_seq) {
            last_track_seq = track_seq;
            pthread_mutex_lock(&app->db_mu);
            char ea[256], et[256], ei[128];
            json_escape(app->last_artist, ea, sizeof(ea));
            json_escape(app->last_title, et, sizeof(et));
            json_escape(app->last_isrc, ei, sizeof(ei));
            char msg[1536];
            int len = snprintf(msg, sizeof(msg),
                "{\"event\":\"track\",\"a\":\"%s\",\"t\":\"%s\",\"src\":\"%s\",\"conf\":%d,\"isrc\":\"%s\"}",
                ea, et, app->last_source, app->last_confidence, ei);
            pthread_mutex_unlock(&app->db_mu);
            ws_broadcast_text(msg, len);
        }

        /* Deck status (every ~500ms) — still needed for confidence/track name data
         * that requires C-side logic. Raw packets handle display-only fields. */
        static int deck_counter = 0;
        if (++deck_counter >= 30) {
            deck_counter = 0;

            char deck_msg[4096];
            int deck_len = snprintf(deck_msg, sizeof(deck_msg), "{\"event\":\"decks\",\"data\":[");
            int first = 1;
            time_t now = time(NULL);
            for (int d = 0; d < MAX_DEVICES; d++) {
                cdj_device_t *dev = &devices[d];
                if (!dev->active || dev->device_type != DEVICE_TYPE_CDJ) continue;
                if (now - dev->last_seen > 10) continue;

                char et[256], ea[256], en[64], ei[128];
                json_escape(dev->track_title, et, sizeof(et));
                json_escape(dev->track_artist, ea, sizeof(ea));
                json_escape(dev->name, en, sizeof(en));
                json_escape(dev->track_isrc, ei, sizeof(ei));

                if (!first) deck_len += snprintf(deck_msg + deck_len, sizeof(deck_msg) - deck_len, ",");
                first = 0;

                deck_confidence_t dc;
                confidence_get_deck(d, &dc);

                deck_len += snprintf(deck_msg + deck_len, sizeof(deck_msg) - deck_len,
                    "{\"n\":%d,\"name\":\"%s\","
                    "\"title\":\"%s\",\"artist\":\"%s\",\"isrc\":\"%s\","
                    "\"rekordbox_id\":%u,"
                    "\"conf\":%d,\"conf_ok\":%d,\"conf_src\":\"%s\"}",
                    dev->device_num, en, et, ea, ei,
                    dev->rekordbox_id,
                    dc.score / 10, dc.accepted,
                    confidence_source_string(dc.signals_seen));
            }

            /* Audio-only confidence */
            deck_confidence_t audio_dc;
            confidence_get_audio(&audio_dc);
            if (audio_dc.title[0]) {
                char at[256], aa[256];
                json_escape(audio_dc.title, at, sizeof(at));
                json_escape(audio_dc.artist, aa, sizeof(aa));
                if (!first) deck_len += snprintf(deck_msg + deck_len, sizeof(deck_msg) - deck_len, ",");
                deck_len += snprintf(deck_msg + deck_len, sizeof(deck_msg) - deck_len,
                    "{\"n\":0,\"name\":\"Audio\",\"audio_only\":1,"
                    "\"title\":\"%s\",\"artist\":\"%s\","
                    "\"conf\":%d,\"conf_ok\":%d,\"conf_src\":\"%s\"}",
                    at, aa, audio_dc.score / 10, audio_dc.accepted,
                    confidence_source_string(audio_dc.signals_seen));
            }

            deck_len += snprintf(deck_msg + deck_len, sizeof(deck_msg) - deck_len, "]}");
            ws_broadcast_text(deck_msg, deck_len);

            /* Shazam state */
            int cur_shazam_state = atomic_load_explicit(&app->shazam_state, memory_order_relaxed);
            int cur_confirms = (cur_shazam_state == SHAZAM_CONFIRMING) ? app->shazam_confirms : 0;
            if (cur_shazam_state != last_shazam_state ||
                (cur_shazam_state == SHAZAM_CONFIRMING && cur_confirms != last_shazam_confirms)) {
                last_shazam_state = cur_shazam_state;
                last_shazam_confirms = cur_confirms;
                char msg[1024];
                int len;
                if (cur_shazam_state == SHAZAM_CONFIRMING) {
                    pthread_mutex_lock(&app->db_mu);
                    char ec[1024];
                    json_escape(app->shazam_candidate, ec, sizeof(ec));
                    len = snprintf(msg, sizeof(msg),
                        "{\"event\":\"shazam\",\"state\":%d,\"candidate\":\"%s\","
                        "\"confirms\":%d,\"needed\":%d,\"conf\":%d,\"cdj\":%s}",
                        cur_shazam_state, ec, app->shazam_confirms,
                        app->shazam_confirms_needed, app->shazam_confidence,
                        app->shazam_cdj_confirmed ? "true" : "false");
                    pthread_mutex_unlock(&app->db_mu);
                } else {
                    pthread_mutex_lock(&app->db_mu);
                    len = snprintf(msg, sizeof(msg),
                        "{\"event\":\"shazam\",\"state\":%d,\"attempts\":%d}",
                        cur_shazam_state, app->shazam_no_match_count);
                    pthread_mutex_unlock(&app->db_mu);
                }
                ws_broadcast_text(msg, len);
            }

            /* Activity log */
            uint32_t cur_log_seq = atomic_load(&g_activity_log.sequence);
            for (int i = 0; i < WS_MAX_CLIENTS; i++) {
                int fd = atomic_load(&ws_clients[i]);
                if (fd < 0) continue;
                if (client_log_seq[i] >= cur_log_seq) continue;

                char log_data[4096];
                int log_count = activity_log_since(client_log_seq[i], log_data, sizeof(log_data));
                client_log_seq[i] = cur_log_seq;
                if (log_count > 0) {
                    char msg[4200];
                    int len = snprintf(msg, sizeof(msg),
                        "{\"event\":\"log\",\"data\":%s}", log_data);
                    ws_send_text(fd, msg, len);
                }
            }
        }

        /* 60 Hz update rate */
        struct timespec ts = {.tv_sec = 0, .tv_nsec = 16666666};
        nanosleep(&ts, NULL);
    }

    /* Cleanup */
    for (int i = 0; i < WS_MAX_CLIENTS; i++) {
        int fd = atomic_load(&ws_clients[i]);
        if (fd >= 0) close(fd);
    }
    close(server_fd);
    unlink(socket_path);
    logmsg("ws", "exit");
    return NULL;
}
