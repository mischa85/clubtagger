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

static void serve_debug_page(int fd) {
    static const char page[] =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html\r\n"
        "Connection: close\r\n\r\n"
        "<!DOCTYPE html><html><body style='background:#111;color:#eee;font:16px monospace'>"
        "<h2>WS Debug</h2><pre id=log></pre>"
        "<script>\n"
        "var L=document.getElementById('log');\n"
        "function log(s){L.textContent+=s+'\\n';console.log(s);}\n"
        "var host=location.host;\n"
        "\n"
        "/* Step 1: raw fetch with upgrade headers to see the 101 response */\n"
        "log('--- RAW FETCH TEST ---');\n"
        "var key='dGhlIHNhbXBsZSBub25jZQ==';\n"
        "fetch('http://'+host+'/',{headers:{\n"
        "  'Upgrade':'websocket','Connection':'Upgrade',\n"
        "  'Sec-WebSocket-Key':key,'Sec-WebSocket-Version':'13'\n"
        "}}).then(function(r){\n"
        "  log('fetch status='+r.status+' statusText='+r.statusText);\n"
        "  log('fetch headers:');\n"
        "  r.headers.forEach(function(v,k){log('  '+k+': '+v);});\n"
        "  return r.text();\n"
        "}).then(function(t){\n"
        "  if(t.length>0) log('fetch body('+t.length+'): '+t.substring(0,200));\n"
        "  log('');\n"
        "  startWS();\n"
        "}).catch(function(e){\n"
        "  log('fetch error: '+e);\n"
        "  startWS();\n"
        "});\n"
        "\n"
        "/* Step 2: actual WebSocket */\n"
        "function startWS(){\n"
        "  log('--- WEBSOCKET TEST ---');\n"
        "  var url='ws://'+host;\n"
        "  log('connecting to '+url);\n"
        "  var ws=new WebSocket(url);\n"
        "  ws.binaryType='arraybuffer';\n"
        "  log('readyState after new: '+ws.readyState);\n"
        "  ws.onopen=function(){log('OPEN readyState='+ws.readyState);};\n"
        "  ws.onmessage=function(e){\n"
        "    if(typeof e.data==='string') log('MSG: '+e.data);\n"
        "    else log('BIN: '+e.data.byteLength+' bytes');\n"
        "  };\n"
        "  ws.onclose=function(e){log('CLOSE code='+e.code+' reason=['+e.reason+'] clean='+e.wasClean+' readyState='+ws.readyState);};\n"
        "  ws.onerror=function(){log('ERROR readyState='+ws.readyState);};\n"
        "}\n"
        "</script></body></html>";
    send(fd, page, sizeof(page) - 1, 0);
}

static int do_handshake(int fd) {
    char buf[4096];
    ssize_t n = recv(fd, buf, sizeof(buf)-1, 0);
    logmsg("ws", "recv returned %zd", n);
    if (n <= 0) return -1;
    buf[n] = '\0';

    logmsg("ws", "request: %.200s", buf);

    /* Find key — case-insensitive, handle variable spacing */
    char *kp = strcasestr(buf, "sec-websocket-key:");
    if (!kp) {
        logmsg("ws", "no WS key — serving debug page");
        serve_debug_page(fd);
        return -2; /* not a WS request */
    }
    kp += 18; /* skip "sec-websocket-key:" */
    while (*kp == ' ' || *kp == '\t') kp++; /* skip whitespace */
    char key[64] = {0};
    int ki = 0;
    while (ki < 60 && kp[ki] && kp[ki] != '\r' && kp[ki] != '\n')
        { key[ki] = kp[ki]; ki++; }
    /* Trim trailing whitespace */
    while (ki > 0 && (key[ki-1] == ' ' || key[ki-1] == '\t')) ki--;
    key[ki] = '\0';

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

    logmsg("ws", "keylen=%d acceptlen=%zu accept=[%s]", ki, strlen(b64), b64);

    /* Dump full request + response to file for hex inspection */
    FILE *dbg = fopen("/tmp/ws_handshake.log", "w");
    if (dbg) {
        fprintf(dbg, "=== REQUEST (%zd bytes) ===\n%s\n", n, buf);
        fprintf(dbg, "=== PARSED ===\nkey=[%s]\ncat=[%s]\naccept=[%s]\n", key, cat, b64);
        fprintf(dbg, "=== RESPONSE (%d bytes) ===\n%s\n", rn, resp);
        fprintf(dbg, "=== RESPONSE HEX ===\n");
        for (int i = 0; i < rn; i++)
            fprintf(dbg, "%02x ", (unsigned char)resp[i]);
        fprintf(dbg, "\n");
        fclose(dbg);
    }
    ssize_t sent = send(fd, resp, rn, 0);
    logmsg("ws", "sent 101 response: %zd/%d bytes", sent, rn);
    return (sent == rn) ? 0 : -1;
}

static ssize_t ws_text(int fd, const char *msg, int len) {
    /* Build frame in one buffer to send atomically */
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

    /* BLOCKING accept loop — simple and correct */
    while (g_running) {
        /* Use poll to avoid blocking forever */
        struct pollfd pfd = { .fd = server_fd, .events = POLLIN };
        int pr = poll(&pfd, 1, 1000); /* 1 second timeout */
        if (pr <= 0) {
            /* Timeout — check clients and send pings */
            for (int i = 0; i < WS_MAX_CLIENTS; i++) {
                int fd = atomic_load(&ws_fds[i]);
                if (fd < 0) continue;

                /* Check if client sent anything (close frame?) */
                uint8_t peek[16];
                ssize_t pn = recv(fd, peek, sizeof(peek), MSG_PEEK | MSG_DONTWAIT);
                if (pn > 0) {
                    logmsg("ws", "slot %d has %zd bytes from client: %02x %02x %02x %02x",
                           i, pn, peek[0], pn>1?peek[1]:0, pn>2?peek[2]:0, pn>3?peek[3]:0);
                } else if (pn == 0) {
                    logmsg("ws", "slot %d: peer closed (recv=0)", i);
                    close(fd);
                    atomic_store(&ws_fds[i], -1);
                    continue;
                }

                char ping[64];
                int plen = snprintf(ping, sizeof(ping), "{\"t\":%ld}", (long)time(NULL));
                ssize_t sent = ws_text(fd, ping, plen);
                if (sent < 0) {
                    logmsg("ws", "slot %d send failed: errno=%d (%s)", i, errno, strerror(errno));
                    close(fd);
                    atomic_store(&ws_fds[i], -1);
                }
            }
            continue;
        }

        int cfd = accept(server_fd, NULL, NULL);
        if (cfd < 0) continue;

        logmsg("ws", "accepted fd=%d", cfd);

        int hs = do_handshake(cfd);
        if (hs == -2) {
            /* Debug page served, close */
            close(cfd);
            continue;
        }
        if (hs != 0) {
            logmsg("ws", "handshake failed");
            close(cfd);
            continue;
        }

        logmsg("ws", "handshake OK");

        /* Store in slot — don't send data yet, let poll timeout send first ping */
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
