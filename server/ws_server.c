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
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <time.h>
#include <unistd.h>
#include <poll.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

#ifdef __APPLE__
#include <mach/mach.h>
#include <sys/sysctl.h>
#else
#include <sys/sysinfo.h>
#endif

#define WS_MAX_CLIENTS  8
#define WS_HISTORY_SIZE 5
#define WS_MAGIC_GUID   "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

static _Atomic int ws_fds[WS_MAX_CLIENTS];

/* ── WebSocket framing (RFC 6455) ───────────────────────────────────────── */

static ssize_t ws_send_frame(int fd, uint8_t opcode, const void *data, size_t len) {
    uint8_t header[10];
    int hlen;
    header[0] = 0x80 | opcode;
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
    struct iovec iov[2] = {
        { .iov_base = header, .iov_len = hlen },
        { .iov_base = (void *)data, .iov_len = len }
    };
    struct msghdr msg = { .msg_iov = iov, .msg_iovlen = 2 };
    return sendmsg(fd, &msg, MSG_NOSIGNAL | MSG_DONTWAIT);
}

static ssize_t ws_text(int fd, const char *data, size_t len) {
    return ws_send_frame(fd, 0x01, data, len);
}

static void ws_broadcast_text(const char *data, size_t len) {
    for (int i = 0; i < WS_MAX_CLIENTS; i++) {
        int fd = atomic_load(&ws_fds[i]);
        if (fd < 0) continue;
        ssize_t s = ws_send_frame(fd, 0x01, data, len);
        if (s < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
            close(fd);
            atomic_store(&ws_fds[i], -1);
        }
    }
}

/* ── Pro DJ Link binary broadcast (called from prolink thread) ──────────── */

void ws_broadcast_packet(uint8_t port_id, uint32_t src_ip,
                         const uint8_t *payload, size_t len) {
    if (len == 0 || len > 4096) return;

    uint8_t buf[4096 + 7];
    buf[0] = port_id;
    memcpy(buf + 1, &src_ip, 4);
    buf[5] = (uint8_t)(len >> 8);
    buf[6] = (uint8_t)(len & 0xFF);
    memcpy(buf + 7, payload, len);

    for (int i = 0; i < WS_MAX_CLIENTS; i++) {
        int fd = atomic_load(&ws_fds[i]);
        if (fd < 0) continue;
        ws_send_frame(fd, 0x02, buf, len + 7);
    }
}

/* ── Handshake ──────────────────────────────────────────────────────────── */

static int do_handshake(int fd) {
    char buf[4096];
    ssize_t n = recv(fd, buf, sizeof(buf)-1, 0);
    if (n <= 0) return -1;
    buf[n] = '\0';

    char *kp = strcasestr(buf, "sec-websocket-key:");
    if (!kp) return -1;
    kp += 18;
    while (*kp == ' ' || *kp == '\t') kp++;
    char key[64] = {0};
    int ki = 0;
    while (ki < 60 && kp[ki] && kp[ki] != '\r' && kp[ki] != '\n')
        { key[ki] = kp[ki]; ki++; }
    while (ki > 0 && (key[ki-1] == ' ' || key[ki-1] == '\t')) ki--;
    key[ki] = '\0';

    char cat[256];
    snprintf(cat, sizeof(cat), "%s%s", key, WS_MAGIC_GUID);
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1((unsigned char *)cat, strlen(cat), hash);
    char b64[64];
    EVP_EncodeBlock((unsigned char *)b64, hash, SHA_DIGEST_LENGTH);

    char resp[256];
    int rn = snprintf(resp, sizeof(resp),
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Accept: %s\r\n\r\n", b64);

    return (send(fd, resp, rn, 0) == rn) ? 0 : -1;
}

/* ── Client frame handler (ping/pong/close) ─────────────────────────────── */

static int ws_handle_client_frame(int fd) {
    uint8_t header[2];
    ssize_t n = recv(fd, header, 2, MSG_DONTWAIT);
    if (n == 0) return -1;
    if (n < 0) return (errno == EAGAIN || errno == EWOULDBLOCK) ? 0 : -1;
    if (n < 2) return -1;

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
    if (masked && recv(fd, mask, 4, 0) != 4) return -1;

    if (payload_len > 4096) return -1;
    uint8_t payload[4096];
    size_t total = 0;
    while (total < payload_len) {
        n = recv(fd, payload + total, payload_len - total, 0);
        if (n <= 0) return -1;
        total += n;
    }
    if (masked)
        for (size_t i = 0; i < payload_len; i++) payload[i] ^= mask[i % 4];

    if (opcode == 0x08) { /* Close */
        ws_send_frame(fd, 0x08, payload, payload_len > 2 ? 2 : payload_len);
        return -1;
    }
    if (opcode == 0x09) /* Ping → Pong */
        ws_send_frame(fd, 0x0A, payload, payload_len);
    return 0;
}

/* ── Main server thread ─────────────────────────────────────────────────── */

void *ws_main(void *arg) {
    App *app = (App *)arg;
    const char *path = app->cfg.ws_socket;
    if (!path) return NULL;

    int server_fd;
    int port = atoi(path);

    if (port > 0) {
        server_fd = socket(AF_INET, SOCK_STREAM, 0);
        int opt = 1;
        setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        struct sockaddr_in a = {0};
        a.sin_family = AF_INET;
        a.sin_port = htons(port);
        if (bind(server_fd, (struct sockaddr *)&a, sizeof(a)) < 0) {
            logmsg("ws", "bind %d: %s", port, strerror(errno));
            close(server_fd);
            return NULL;
        }
    } else {
        server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
        unlink(path);
        struct sockaddr_un a = {0};
        a.sun_family = AF_UNIX;
        snprintf(a.sun_path, sizeof(a.sun_path), "%s", path);
        if (bind(server_fd, (struct sockaddr *)&a, sizeof(a)) < 0) {
            logmsg("ws", "bind: %s", strerror(errno));
            close(server_fd);
            return NULL;
        }
        chmod(path, 0666);
    }

    listen(server_fd, 4);
    logmsg("ws", "listening on %s", path);

    for (int i = 0; i < WS_MAX_CLIENTS; i++)
        atomic_store(&ws_fds[i], -1);

    int client_needs_init[WS_MAX_CLIENTS];
    uint32_t client_log_seq[WS_MAX_CLIENTS];
    for (int i = 0; i < WS_MAX_CLIENTS; i++) {
        client_needs_init[i] = 0;
        client_log_seq[i] = 0;
    }

    uint32_t last_track_seq = 0;
    int last_shazam_state = -1;
    int last_shazam_confirms = 0;
    int tick = 0;

    while (g_running) {
        struct pollfd pfd = { .fd = server_fd, .events = POLLIN };
        poll(&pfd, 1, 16); /* ~60 Hz */

        /* ── Accept new connections ─────────────────────────────────────── */
        if (pfd.revents & POLLIN) {
            int cfd = accept(server_fd, NULL, NULL);
            if (cfd >= 0) {
                int one = 1;
                setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
                fcntl(cfd, F_SETFL, O_NONBLOCK);

                if (do_handshake(cfd) != 0) {
                    close(cfd);
                } else {
                    int added = 0;
                    for (int i = 0; i < WS_MAX_CLIENTS; i++) {
                        if (atomic_load(&ws_fds[i]) < 0) {
                            atomic_store(&ws_fds[i], cfd);
                            client_needs_init[i] = 1;
                            client_log_seq[i] = 0;
                            logmsg("ws", "client connected (slot %d)", i);
                            added = 1;
                            break;
                        }
                    }
                    if (!added) {
                        logmsg("ws", "max clients, rejecting");
                        close(cfd);
                    }
                }
            }
        }

        /* ── Handle incoming client frames ──────────────────────────────── */
        for (int i = 0; i < WS_MAX_CLIENTS; i++) {
            int fd = atomic_load(&ws_fds[i]);
            if (fd < 0) continue;
            if (ws_handle_client_frame(fd) < 0) {
                logmsg("ws", "client disconnected (slot %d)", i);
                close(fd);
                atomic_store(&ws_fds[i], -1);
            }
        }

        /* ── Send history to new clients ────────────────────────────────── */
        for (int i = 0; i < WS_MAX_CLIENTS; i++) {
            int fd = atomic_load(&ws_fds[i]);
            if (fd < 0 || !client_needs_init[i]) continue;
            client_needs_init[i] = 0;

            char ts[WS_HISTORY_SIZE][32], art[WS_HISTORY_SIZE][256],
                 ttl[WS_HISTORY_SIZE][256], src[WS_HISTORY_SIZE][16],
                 isrc[WS_HISTORY_SIZE][64];
            int conf[WS_HISTORY_SIZE];
            int count = db_get_recent_tracks(app, WS_HISTORY_SIZE,
                                             ts, art, ttl, src, conf, isrc);
            if (count > 0) {
                char msg[4096];
                int len = snprintf(msg, sizeof(msg), "{\"event\":\"history\",\"data\":[");
                for (int t = 0; t < count; t++) {
                    char ea[512], et[512], ei[128];
                    json_escape(art[t], ea, sizeof(ea));
                    json_escape(ttl[t], et, sizeof(et));
                    json_escape(isrc[t], ei, sizeof(ei));
                    if (t > 0) len += snprintf(msg + len, sizeof(msg) - len, ",");
                    len += snprintf(msg + len, sizeof(msg) - len,
                        "{\"ts\":\"%s\",\"a\":\"%s\",\"t\":\"%s\","
                        "\"src\":\"%s\",\"conf\":%d,\"isrc\":\"%s\"}",
                        ts[t], ea, et, src[t], conf[t], ei);
                }
                len += snprintf(msg + len, sizeof(msg) - len, "]}");
                ws_text(fd, msg, len);
            }
        }

        /* ── VU meter + audio stats (every cycle, ~60 Hz) ──────────────── */
        {
            uint16_t vu_l = atomic_load_explicit(&app->vu_left, memory_order_relaxed);
            uint16_t vu_r = atomic_load_explicit(&app->vu_right, memory_order_relaxed);
            uint64_t lost = atomic_load_explicit(&app->audio_lost, memory_order_relaxed);
            uint64_t frames = atomic_load_explicit(&app->aw.total_written, memory_order_relaxed);
            int is_rec = atomic_load_explicit(&app->is_recording, memory_order_relaxed);

            char msg[512];
            int len = snprintf(msg, sizeof(msg),
                "{\"event\":\"vu\",\"l\":%u,\"r\":%u,"
                "\"lost\":%llu,\"frames\":%llu,"
                "\"rate\":%u,\"ch\":%u,\"rec\":%d,"
                "\"fmt\":\"%s\",\"src\":\"%s\"}",
                vu_l, vu_r,
                (unsigned long long)lost, (unsigned long long)frames,
                app->aw.rate, app->aw.channels, is_rec,
                app->cfg.format ? app->cfg.format : "wav",
                app->cfg.source ? app->cfg.source : "unknown");
            ws_broadcast_text(msg, len);
        }

        /* ── Track change notification ──────────────────────────────────── */
        {
            uint32_t seq = atomic_load_explicit(&app->track_seq, memory_order_acquire);
            if (seq != last_track_seq) {
                last_track_seq = seq;
                pthread_mutex_lock(&app->db_mu);
                char ea[256], et[256], ei[128];
                json_escape(app->last_artist, ea, sizeof(ea));
                json_escape(app->last_title, et, sizeof(et));
                json_escape(app->last_isrc, ei, sizeof(ei));
                char msg[1536];
                int len = snprintf(msg, sizeof(msg),
                    "{\"event\":\"track\",\"a\":\"%s\",\"t\":\"%s\","
                    "\"src\":\"%s\",\"conf\":%d,\"isrc\":\"%s\"}",
                    ea, et, app->last_source, app->last_confidence, ei);
                pthread_mutex_unlock(&app->db_mu);
                ws_broadcast_text(msg, len);
            }
        }

        /* ── Event-driven updates (cheap atomic checks, send on change) ── */

        /* Shazam state */
        {
            int ss = atomic_load_explicit(&app->shazam_state, memory_order_relaxed);
            int sc = (ss == SHAZAM_CONFIRMING) ? app->shazam_confirms : 0;
            if (ss != last_shazam_state ||
                (ss == SHAZAM_CONFIRMING && sc != last_shazam_confirms)) {
                last_shazam_state = ss;
                last_shazam_confirms = sc;
                char msg[1024];
                int len;
                pthread_mutex_lock(&app->db_mu);
                if (ss == SHAZAM_CONFIRMING) {
                    char ec[1024];
                    json_escape(app->shazam_candidate, ec, sizeof(ec));
                    len = snprintf(msg, sizeof(msg),
                        "{\"event\":\"shazam\",\"state\":%d,\"candidate\":\"%s\","
                        "\"confirms\":%d,\"needed\":%d,\"conf\":%d,\"cdj\":%s}",
                        ss, ec, app->shazam_confirms,
                        app->shazam_confirms_needed, app->shazam_confidence,
                        app->shazam_cdj_confirmed ? "true" : "false");
                } else {
                    len = snprintf(msg, sizeof(msg),
                        "{\"event\":\"shazam\",\"state\":%d,\"attempts\":%d}",
                        ss, app->shazam_no_match_count);
                }
                pthread_mutex_unlock(&app->db_mu);
                ws_broadcast_text(msg, len);
            }
        }

        /* Activity log — send immediately on new messages */
        {
            uint32_t cur_log_seq = atomic_load(&g_activity_log.sequence);
            for (int i = 0; i < WS_MAX_CLIENTS; i++) {
                int fd = atomic_load(&ws_fds[i]);
                if (fd < 0 || client_log_seq[i] >= cur_log_seq) continue;

                char log_data[4096];
                int log_count = activity_log_since(client_log_seq[i],
                                                   log_data, sizeof(log_data));
                client_log_seq[i] = cur_log_seq;
                if (log_count > 0) {
                    char msg[4200];
                    int len = snprintf(msg, sizeof(msg),
                        "{\"event\":\"log\",\"data\":%s}", log_data);
                    ws_text(fd, msg, len);
                }
            }
        }

        /* ── Slow updates (~1 Hz): decks metadata, system stats ─────────── */
        if (++tick >= 60) {
            tick = 0;

            /* Deck metadata + confidence */
            char dmsg[4096];
            int dlen = snprintf(dmsg, sizeof(dmsg), "{\"event\":\"decks\",\"data\":[");
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

                deck_confidence_t dc;
                confidence_get_deck(d, &dc);

                if (!first) dlen += snprintf(dmsg + dlen, sizeof(dmsg) - dlen, ",");
                first = 0;
                static const char *db_src_names[] = {
                    "", "OneLibrary", "PDB", "DBServer"
                };
                const char *db_src = dev->track_db_src < 4
                    ? db_src_names[dev->track_db_src] : "";

                static const char *fmt_names[] = {
                    [0] = "", [1] = "MP3", [4] = "M4A",
                    [5] = "FLAC", [11] = "WAV", [12] = "AIFF"
                };
                const char *fmt = dev->track_format < 13
                    ? fmt_names[dev->track_format] : "";

                dlen += snprintf(dmsg + dlen, sizeof(dmsg) - dlen,
                    "{\"n\":%d,\"name\":\"%s\","
                    "\"title\":\"%s\",\"artist\":\"%s\",\"isrc\":\"%s\","
                    "\"rekordbox_id\":%u,\"db_src\":\"%s\","
                    "\"bitrate\":%u,\"format\":\"%s\","
                    "\"conf\":%d,\"conf_ok\":%d,\"conf_src\":\"%s\"}",
                    dev->device_num, en, et, ea, ei,
                    dev->rekordbox_id, db_src,
                    dev->track_bitrate, fmt ? fmt : "",
                    dc.score / 10, dc.accepted,
                    confidence_source_string(dc.signals_seen));
            }

            /* Audio-only confidence */
            deck_confidence_t adc;
            confidence_get_audio(&adc);
            if (adc.title[0]) {
                char at[256], aa[256];
                json_escape(adc.title, at, sizeof(at));
                json_escape(adc.artist, aa, sizeof(aa));
                if (!first) dlen += snprintf(dmsg + dlen, sizeof(dmsg) - dlen, ",");
                dlen += snprintf(dmsg + dlen, sizeof(dmsg) - dlen,
                    "{\"n\":0,\"name\":\"Audio\",\"audio_only\":1,"
                    "\"title\":\"%s\",\"artist\":\"%s\","
                    "\"conf\":%d,\"conf_ok\":%d,\"conf_src\":\"%s\"}",
                    at, aa, adc.score / 10, adc.accepted,
                    confidence_source_string(adc.signals_seen));
            }

            dlen += snprintf(dmsg + dlen, sizeof(dmsg) - dlen, "]}");
            ws_broadcast_text(dmsg, dlen);

            /* System stats (load, mem, disk) */
            {
                double loadavg[1] = {0};
                getloadavg(loadavg, 1);

                uint64_t mem_used = 0, mem_total = 0;
#ifdef __APPLE__
                struct task_basic_info info;
                mach_msg_type_number_t mc = TASK_BASIC_INFO_COUNT;
                if (task_info(mach_task_self(), TASK_BASIC_INFO,
                              (task_info_t)&info, &mc) == KERN_SUCCESS)
                    mem_used = info.resident_size;
                int mib[2] = {CTL_HW, HW_MEMSIZE};
                size_t mlen = sizeof(mem_total);
                sysctl(mib, 2, &mem_total, &mlen, NULL, 0);
#else
                FILE *sf = fopen("/proc/self/status", "r");
                if (sf) {
                    char line[128];
                    while (fgets(line, sizeof(line), sf))
                        if (strncmp(line, "VmRSS:", 6) == 0)
                            mem_used = (uint64_t)atoll(line + 6) * 1024;
                    fclose(sf);
                }
                struct sysinfo si;
                if (sysinfo(&si) == 0) mem_total = si.totalram * si.mem_unit;
#endif

                uint64_t disk_free = 0, disk_total = 0;
                const char *outdir = app->cfg.outdir ? app->cfg.outdir : ".";
                struct statvfs svfs;
                if (statvfs(outdir, &svfs) == 0) {
                    disk_free = (uint64_t)svfs.f_bavail * svfs.f_frsize;
                    disk_total = (uint64_t)svfs.f_blocks * svfs.f_frsize;
                }

                /* Count active CDJs */
                int cdj_count = 0;
                for (int d = 0; d < MAX_DEVICES; d++)
                    if (devices[d].active && devices[d].device_type == DEVICE_TYPE_CDJ
                        && now - devices[d].last_seen < 10)
                        cdj_count++;

                /* Count WS clients */
                int ws_clients = 0;
                for (int c = 0; c < WS_MAX_CLIENTS; c++)
                    if (atomic_load(&ws_fds[c]) >= 0) ws_clients++;

                /* Packets/sec (delta since last tick) */
                static uint64_t prev_pkt_count = 0;
                extern uint64_t prolink_packet_count;
                uint64_t cur_pkt = prolink_packet_count;
                uint64_t pkt_sec = cur_pkt - prev_pkt_count;
                prev_pkt_count = cur_pkt;

                /* DB track count (cheap: just use track_seq) */
                uint32_t tracks_tagged = atomic_load(&app->track_seq);

                /* Shazam stats */
                uint32_t sz_queries = atomic_load(&app->shazam_queries);
                uint32_t sz_matches = atomic_load(&app->shazam_matches);

                /* Uptime */
                int uptime = (int)(now - app->start_time);

                /* Ring buffer usage (seconds buffered) */
                uint64_t ring_written = atomic_load_explicit(&app->aw.total_written, memory_order_relaxed);
                unsigned ring_cap = app->aw.capacity;
                unsigned ring_rate = app->aw.rate;
                int ring_sec = ring_rate > 0 ? (int)(ring_cap / ring_rate) : 0;
                int ring_filled = (ring_rate > 0 && ring_cap > 0)
                    ? (int)((ring_written % ring_cap) * 100 / ring_cap) : 0;

                char msg[512];
                int len = snprintf(msg, sizeof(msg),
                    "{\"event\":\"stats\",\"load\":%.2f,"
                    "\"mem\":%llu,\"memtot\":%llu,"
                    "\"diskfree\":%llu,\"disktot\":%llu,"
                    "\"uptime\":%d,\"cdjs\":%d,\"ws_clients\":%d,"
                    "\"tracks_tagged\":%u,\"pkt_sec\":%llu,"
                    "\"sz_queries\":%u,\"sz_matches\":%u,"
                    "\"ring_sec\":%d,\"ring_pct\":%d}",
                    loadavg[0],
                    (unsigned long long)mem_used, (unsigned long long)mem_total,
                    (unsigned long long)disk_free, (unsigned long long)disk_total,
                    uptime, cdj_count, ws_clients,
                    tracks_tagged, (unsigned long long)pkt_sec,
                    sz_queries, sz_matches,
                    ring_sec, ring_filled);
                ws_broadcast_text(msg, len);
            }
        }
    }

    for (int i = 0; i < WS_MAX_CLIENTS; i++) {
        int fd = atomic_load(&ws_fds[i]);
        if (fd >= 0) close(fd);
    }
    close(server_fd);
    if (port <= 0) unlink(path);
    logmsg("ws", "exit");
    return NULL;
}
