/*
 * ws_server.c - Bare minimum WebSocket server
 */
#include "ws_server.h"
#include "../common.h"

#include <errno.h>
#include <fcntl.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
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
    logmsg("ws", "recv returned %zd", n);
    if (n <= 0) return -1;
    buf[n] = '\0';

    /* Find key */
    char *kp = strstr(buf, "Sec-WebSocket-Key: ");
    if (!kp) kp = strstr(buf, "sec-websocket-key: ");
    if (!kp) {
        logmsg("ws", "no key found in: %.100s", buf);
        return -1;
    }
    kp += 19;
    char key[64] = {0};
    for (int i = 0; i < 60 && kp[i] && kp[i] != '\r' && kp[i] != '\n'; i++)
        key[i] = kp[i];

    /* SHA1(key + guid) */
    char cat[256];
    snprintf(cat, sizeof(cat), "%s258EAFA5-E914-47DA-95CA-5AB0141B3CF2", key);
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
    logmsg("ws", "sent 101 response: %zd bytes", sent);
    return (sent == rn) ? 0 : -1;
}

static ssize_t ws_text(int fd, const char *msg, int len) {
    uint8_t hdr[4];
    hdr[0] = 0x81; /* FIN + text */
    if (len < 126) {
        hdr[1] = (uint8_t)len;
        send(fd, hdr, 2, MSG_NOSIGNAL | MSG_DONTWAIT);
    } else {
        hdr[1] = 126;
        hdr[2] = (uint8_t)(len >> 8);
        hdr[3] = (uint8_t)(len & 0xff);
        send(fd, hdr, 4, MSG_NOSIGNAL | MSG_DONTWAIT);
    }
    return send(fd, msg, len, MSG_NOSIGNAL | MSG_DONTWAIT);
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

    /* BLOCKING accept loop — simple and correct */
    while (g_running) {
        /* Use poll to avoid blocking forever */
        struct pollfd pfd = { .fd = server_fd, .events = POLLIN };
        int pr = poll(&pfd, 1, 1000); /* 1 second timeout */
        if (pr <= 0) {
            /* Timeout or error — send pings to existing clients */
            char ping[64];
            int plen = snprintf(ping, sizeof(ping), "{\"t\":%ld}", (long)time(NULL));
            for (int i = 0; i < WS_MAX_CLIENTS; i++) {
                int fd = atomic_load(&ws_fds[i]);
                if (fd < 0) continue;
                if (ws_text(fd, ping, plen) < 0) {
                    logmsg("ws", "slot %d dead", i);
                    close(fd);
                    atomic_store(&ws_fds[i], -1);
                }
            }
            continue;
        }

        int cfd = accept(server_fd, NULL, NULL);
        if (cfd < 0) continue;

        logmsg("ws", "accepted fd=%d", cfd);

        if (do_handshake(cfd) != 0) {
            logmsg("ws", "handshake failed");
            close(cfd);
            continue;
        }

        logmsg("ws", "handshake OK");

        /* Send a hello */
        const char *hello = "{\"event\":\"hello\"}";
        ws_text(cfd, hello, strlen(hello));

        /* Store in slot */
        int stored = 0;
        for (int i = 0; i < WS_MAX_CLIENTS; i++) {
            if (atomic_load(&ws_fds[i]) < 0) {
                atomic_store(&ws_fds[i], cfd);
                logmsg("ws", "client in slot %d", i);
                stored = 1;
                break;
            }
        }
        if (!stored) {
            logmsg("ws", "no slot, closing");
            close(cfd);
        }
    }

    close(server_fd);
    return NULL;
}
