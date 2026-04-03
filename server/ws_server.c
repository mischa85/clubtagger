/*
 * ws_server.c - WebSocket server for real-time CDJ data
 */
#include "ws_server.h"
#include "../common.h"

#include <errno.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <poll.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

#define WS_MAX_CLIENTS 4

static _Atomic int ws_fds[WS_MAX_CLIENTS];

void ws_broadcast_packet(uint8_t port_id, uint32_t src_ip,
                         const uint8_t *payload, size_t len) {
    (void)port_id; (void)src_ip; (void)payload; (void)len;
}

static int do_handshake(int fd) {
    char buf[4096];
    ssize_t n = recv(fd, buf, sizeof(buf)-1, 0);
    if (n <= 0) return -1;
    buf[n] = '\0';

    /* Find Sec-WebSocket-Key */
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

    /* SHA1(key + RFC 6455 GUID) → base64 */
    char cat[256];
    snprintf(cat, sizeof(cat), "%s258EAFA5-E914-47DA-95CA-C5AB0DC85B11", key);
    unsigned char hash[20];
    SHA1((unsigned char*)cat, strlen(cat), hash);
    char b64[64];
    EVP_EncodeBlock((unsigned char*)b64, hash, 20);

    char resp[256];
    int rn = snprintf(resp, sizeof(resp),
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Accept: %s\r\n\r\n", b64);

    ssize_t sent = send(fd, resp, rn, 0);
    return (sent == rn) ? 0 : -1;
}

static ssize_t ws_text(int fd, const char *msg, int len) {
    uint8_t buf[4200];
    int hlen;
    buf[0] = 0x81; /* FIN + text */
    if (len < 126) {
        buf[1] = (uint8_t)len;
        hlen = 2;
    } else {
        buf[1] = 126;
        buf[2] = (uint8_t)(len >> 8);
        buf[3] = (uint8_t)(len & 0xff);
        hlen = 4;
    }
    if (hlen + len > (int)sizeof(buf)) return -1;
    memcpy(buf + hlen, msg, len);
    return send(fd, buf, hlen + len, MSG_NOSIGNAL);
}

void *ws_main(void *arg) {
    (void)arg;
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
        if (bind(server_fd, (struct sockaddr*)&a, sizeof(a)) < 0) {
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
        if (bind(server_fd, (struct sockaddr*)&a, sizeof(a)) < 0) {
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

    while (g_running) {
        struct pollfd pfd = { .fd = server_fd, .events = POLLIN };
        int pr = poll(&pfd, 1, 1000);
        if (pr <= 0) {
            /* Timeout — check clients and send keepalive */
            for (int i = 0; i < WS_MAX_CLIENTS; i++) {
                int fd = atomic_load(&ws_fds[i]);
                if (fd < 0) continue;

                uint8_t peek[16];
                ssize_t pn = recv(fd, peek, sizeof(peek), MSG_PEEK | MSG_DONTWAIT);
                if (pn == 0) {
                    close(fd);
                    atomic_store(&ws_fds[i], -1);
                    continue;
                } else if (pn < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                    close(fd);
                    atomic_store(&ws_fds[i], -1);
                    continue;
                }

                char ping[64];
                int plen = snprintf(ping, sizeof(ping), "{\"t\":%ld}", (long)time(NULL));
                if (ws_text(fd, ping, plen) < 0) {
                    close(fd);
                    atomic_store(&ws_fds[i], -1);
                }
            }
            continue;
        }

        int cfd = accept(server_fd, NULL, NULL);
        if (cfd < 0) continue;

        /* TCP_NODELAY for low-latency framing */
        int one = 1;
        setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

        if (do_handshake(cfd) != 0) {
            close(cfd);
            continue;
        }

        logmsg("ws", "client connected fd=%d", cfd);

        /* Store in slot */
        int stored = 0;
        for (int i = 0; i < WS_MAX_CLIENTS; i++) {
            if (atomic_load(&ws_fds[i]) < 0) {
                atomic_store(&ws_fds[i], cfd);
                stored = 1;
                break;
            }
        }
        if (!stored) {
            logmsg("ws", "no slot, closing fd=%d", cfd);
            close(cfd);
        }
    }

    close(server_fd);
    return NULL;
}
