/*
 * ws_test.c - Minimal standalone WebSocket test server
 * Build: cc -o ws_test ws_test.c -lcrypto
 * Run:   ./ws_test 9999
 * Test:  open browser console, type: new WebSocket("ws://YOURIP:9999")
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <time.h>
#include <strings.h>

static int do_handshake(int fd) {
    char buf[4096];
    ssize_t n = recv(fd, buf, sizeof(buf) - 1, 0);
    if (n <= 0) return -1;
    buf[n] = '\0';

    printf("=== REQUEST ===\n%s\n===============\n", buf);

    /* Find Sec-WebSocket-Key */
    char *kp = strcasestr(buf, "sec-websocket-key:");
    if (!kp) { printf("no key\n"); return -1; }
    kp += 18;
    while (*kp == ' ' || *kp == '\t') kp++;
    char key[64] = {0};
    int ki = 0;
    while (ki < 60 && kp[ki] && kp[ki] != '\r' && kp[ki] != '\n')
        { key[ki] = kp[ki]; ki++; }
    while (ki > 0 && (key[ki-1] == ' ' || key[ki-1] == '\t')) ki--;
    key[ki] = '\0';

    /* SHA1(key + magic) -> base64 */
    char cat[256];
    snprintf(cat, sizeof(cat), "%s258EAFA5-E914-47DA-95CA-C5AB0DC85B11", key);
    unsigned char hash[20];
    SHA1((unsigned char *)cat, strlen(cat), hash);
    char b64[64];
    EVP_EncodeBlock((unsigned char *)b64, hash, 20);

    printf("key=[%s] accept=[%s]\n", key, b64);

    char resp[512];
    int rn = snprintf(resp, sizeof(resp),
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Accept: %s\r\n\r\n", b64);

    printf("=== RESPONSE ===\n%s================\n", resp);

    ssize_t sent = send(fd, resp, rn, 0);
    return (sent == rn) ? 0 : -1;
}

static ssize_t ws_send_text(int fd, const char *msg, int len) {
    unsigned char frame[4096];
    int hlen;
    frame[0] = 0x81; /* FIN + text opcode */
    if (len < 126) {
        frame[1] = (unsigned char)len;
        hlen = 2;
    } else {
        frame[1] = 126;
        frame[2] = (unsigned char)(len >> 8);
        frame[3] = (unsigned char)(len & 0xff);
        hlen = 4;
    }
    memcpy(frame + hlen, msg, len);
    return send(fd, frame, hlen + len, 0);
}

int main(int argc, char **argv) {
    int port = argc > 1 ? atoi(argv[1]) : 9999;

    int sfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sfd < 0) { perror("socket"); return 1; }
    printf("socket fd=%d\n", sfd);

    int opt = 1;
    setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);
    if (bind(sfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        return 1;
    }
    printf("bind ok\n");

    if (listen(sfd, 4) < 0) {
        perror("listen");
        return 1;
    }

    /* Verify what we're actually listening on */
    struct sockaddr_in bound = {0};
    socklen_t blen = sizeof(bound);
    getsockname(sfd, (struct sockaddr *)&bound, &blen);
    printf("listening on %d.%d.%d.%d:%d\n",
        (ntohl(bound.sin_addr.s_addr) >> 24) & 0xff,
        (ntohl(bound.sin_addr.s_addr) >> 16) & 0xff,
        (ntohl(bound.sin_addr.s_addr) >> 8) & 0xff,
        ntohl(bound.sin_addr.s_addr) & 0xff,
        ntohs(bound.sin_port));

    for (;;) {
        int cfd = accept(sfd, NULL, NULL);
        if (cfd < 0) continue;
        printf("accepted fd=%d\n", cfd);

        if (do_handshake(cfd) != 0) {
            printf("handshake FAILED\n");
            close(cfd);
            continue;
        }
        printf("handshake OK — sending test messages\n");

        /* Send 3 test messages, 1 per second */
        for (int i = 1; i <= 3; i++) {
            char msg[128];
            int mlen = snprintf(msg, sizeof(msg),
                "{\"event\":\"test\",\"n\":%d,\"t\":%ld}", i, (long)time(NULL));
            ssize_t sent = ws_send_text(cfd, msg, mlen);
            printf("sent msg %d: %zd bytes\n", i, sent);
            sleep(1);
        }

        /* Send close frame */
        unsigned char close_frame[4] = {0x88, 0x02, 0x03, 0xe8}; /* 1000 normal */
        send(cfd, close_frame, 4, 0);
        printf("sent close frame\n");

        close(cfd);
        printf("done\n\n");
    }
}
