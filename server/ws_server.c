/*
 * ws_server.c - Minimal WebSocket server (step-by-step build)
 */
#include "ws_server.h"
#include "../common.h"
#include "../prolink/cdj_types.h"
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
#include <sys/un.h>
#include <netinet/in.h>
#include <time.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

#define WS_MAX_CLIENTS 8
#define WS_MAGIC_GUID "258EAFA5-E914-47DA-95CA-5AB0141B3CF2"

static const char *ws_token = NULL;
static _Atomic int ws_clients[WS_MAX_CLIENTS];

/* ============================================================================
 * WebSocket frame send (server→client, no masking)
 * ============================================================================ */

static ssize_t ws_send_frame(int fd, uint8_t opcode, const void *data, size_t len) {
    uint8_t hdr[4];
    int hlen;
    hdr[0] = 0x80 | opcode;
    if (len < 126) {
        hdr[1] = (uint8_t)len;
        hlen = 2;
    } else {
        hdr[1] = 126;
        hdr[2] = (uint8_t)(len >> 8);
        hdr[3] = (uint8_t)(len & 0xFF);
        hlen = 4;
    }
    /* Two separate sends — simple and portable */
    ssize_t s1 = send(fd, hdr, hlen, MSG_NOSIGNAL);
    if (s1 < 0) return s1;
    ssize_t s2 = send(fd, data, len, MSG_NOSIGNAL);
    return s2;
}

static ssize_t ws_send_text(int fd, const char *data, size_t len) {
    return ws_send_frame(fd, 0x01, data, len);
}

/* ============================================================================
 * WebSocket handshake
 * ============================================================================ */

static int ws_handshake(int fd) {
    char req[2048];
    ssize_t n = recv(fd, req, sizeof(req) - 1, 0);
    if (n <= 0) {
        logmsg("ws", "handshake: recv failed n=%zd errno=%d", n, errno);
        return -1;
    }
    req[n] = '\0';
    logmsg("ws", "handshake: received %zd bytes: %.200s", n, req);

    if (!strcasestr(req, "Upgrade: websocket")) {
        logmsg("ws", "handshake: no Upgrade header found");
        return -1;
    }

    /* Validate token if configured */
    if (ws_token && ws_token[0]) {
        char expect[256];
        snprintf(expect, sizeof(expect), "token=%s", ws_token);
        if (!strstr(req, expect)) return -1;
    }

    /* Extract Sec-WebSocket-Key */
    const char *kp = strcasestr(req, "Sec-WebSocket-Key:");
    if (!kp) return -1;
    kp += 18;
    while (*kp == ' ') kp++;
    char key[128];
    int ki = 0;
    while (*kp && *kp != '\r' && *kp != '\n' && ki < 126)
        key[ki++] = *kp++;
    key[ki] = '\0';

    /* SHA1(key + GUID) → base64 */
    char cat[256];
    snprintf(cat, sizeof(cat), "%s%s", key, WS_MAGIC_GUID);
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1((unsigned char *)cat, strlen(cat), hash);
    char accept[64];
    EVP_EncodeBlock((unsigned char *)accept, hash, SHA_DIGEST_LENGTH);

    /* 101 response */
    char resp[512];
    int rlen = snprintf(resp, sizeof(resp),
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Accept: %s\r\n\r\n", accept);
    return (send(fd, resp, rlen, MSG_NOSIGNAL) == rlen) ? 0 : -1;
}

/* ============================================================================
 * Broadcast packet stub (called from prolink thread)
 * ============================================================================ */

void ws_broadcast_packet(uint8_t port_id, uint32_t src_ip,
                         const uint8_t *payload, size_t len) {
    (void)port_id; (void)src_ip; (void)payload; (void)len;
    /* Disabled until basic connection works */
}

/* ============================================================================
 * Main thread
 * ============================================================================ */

void *ws_main(void *arg) {
    App *app = (App *)arg;
    const char *socket_path = app->cfg.ws_socket;
    ws_token = app->cfg.ws_token;

    for (int i = 0; i < WS_MAX_CLIENTS; i++)
        atomic_store(&ws_clients[i], -1);

    /* Create server socket — TCP if path looks like a port number */
    int server_fd, is_tcp = 0;
    int port = atoi(socket_path);
    if (port > 0 && port < 65536) {
        is_tcp = 1;
        server_fd = socket(AF_INET, SOCK_STREAM, 0);
        int opt = 1;
        setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        struct sockaddr_in a = {0};
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = INADDR_ANY;
        a.sin_port = htons((uint16_t)port);
        if (bind(server_fd, (struct sockaddr *)&a, sizeof(a)) < 0) {
            logmsg("ws", "TCP bind(%d) failed: %s", port, strerror(errno));
            return NULL;
        }
        logmsg("ws", "started: TCP port %d (WebSocket)", port);
    } else {
        server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
        unlink(socket_path);
        struct sockaddr_un a = {0};
        a.sun_family = AF_UNIX;
        snprintf(a.sun_path, sizeof(a.sun_path), "%s", socket_path);
        if (bind(server_fd, (struct sockaddr *)&a, sizeof(a)) < 0) {
            logmsg("ws", "bind() failed: %s", strerror(errno));
            return NULL;
        }
        chmod(socket_path, 0666);
        logmsg("ws", "started: socket=%s (WebSocket)", socket_path);
    }

    listen(server_fd, 8);
    fcntl(server_fd, F_SETFL, O_NONBLOCK);

    while (g_running) {
        /* Accept */
        int cfd = accept(server_fd, NULL, NULL);
        if (cfd >= 0) {
            if (ws_handshake(cfd) != 0) {
                close(cfd);
            } else {
                /* Find slot */
                int added = 0;
                for (int i = 0; i < WS_MAX_CLIENTS; i++) {
                    if (atomic_load(&ws_clients[i]) < 0) {
                        fcntl(cfd, F_SETFL, O_NONBLOCK);
                        atomic_store(&ws_clients[i], cfd);
                        logmsg("ws", "client connected (slot %d)", i);
                        added = 1;
                        break;
                    }
                }
                if (!added) close(cfd);
            }
        }

        /* Send a heartbeat text frame to all clients every loop (~60Hz) */
        static int counter = 0;
        if (++counter >= 60) {  /* ~1 second */
            counter = 0;
            char msg[128];
            int len = snprintf(msg, sizeof(msg),
                "{\"event\":\"ping\",\"t\":%ld}", (long)time(NULL));
            for (int i = 0; i < WS_MAX_CLIENTS; i++) {
                int fd = atomic_load(&ws_clients[i]);
                if (fd < 0) continue;
                ssize_t sent = ws_send_text(fd, msg, len);
                if (sent < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                    logmsg("ws", "client disconnected (slot %d, errno=%d)", i, errno);
                    close(fd);
                    atomic_store(&ws_clients[i], -1);
                }
            }
        }

        struct timespec ts = {0, 16666666};
        nanosleep(&ts, NULL);
    }

    for (int i = 0; i < WS_MAX_CLIENTS; i++) {
        int fd = atomic_load(&ws_clients[i]);
        if (fd >= 0) close(fd);
    }
    close(server_fd);
    if (!is_tcp) unlink(socket_path);
    return NULL;
}
