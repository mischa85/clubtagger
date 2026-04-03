/*
 * ws_server.c - Bare minimum WebSocket server (DEBUG BUILD)
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
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

#define WS_MAX_CLIENTS 4

static _Atomic int ws_fds[WS_MAX_CLIENTS];
static int debug_seq = 0; /* global connection sequence counter */

void ws_broadcast_packet(uint8_t port_id, uint32_t src_ip,
                         const uint8_t *payload, size_t len) {
    (void)port_id; (void)src_ip; (void)payload; (void)len;
}

/* Log peer address for a socket fd */
static void log_peer(int fd, int seq) {
    struct sockaddr_in peer = {0};
    socklen_t plen = sizeof(peer);
    if (getpeername(fd, (struct sockaddr *)&peer, &plen) == 0) {
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &peer.sin_addr, ip, sizeof(ip));
        logmsg("ws", "[#%d] peer=%s:%d", seq, ip, ntohs(peer.sin_port));
    } else {
        logmsg("ws", "[#%d] getpeername failed: %s", seq, strerror(errno));
    }
}

/* Log socket state */
static void log_socket_state(int fd, int seq, const char *label) {
    int err = 0;
    socklen_t elen = sizeof(err);
    getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen);

    int sndbuf = 0, rcvbuf = 0, nodelay = 0;
    socklen_t optlen = sizeof(sndbuf);
    getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, &optlen);
    optlen = sizeof(rcvbuf);
    getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, &optlen);
    optlen = sizeof(nodelay);
    getsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &nodelay, &optlen);

    int flags = fcntl(fd, F_GETFL, 0);

    logmsg("ws", "[#%d] %s: SO_ERROR=%d sndbuf=%d rcvbuf=%d nodelay=%d flags=0x%x",
           seq, label, err, sndbuf, rcvbuf, nodelay, flags);
}

/* Check if fd is still connected */
static int check_alive(int fd, int seq) {
    /* getsockopt SO_ERROR */
    int err = 0;
    socklen_t elen = sizeof(err);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen) < 0) {
        logmsg("ws", "[#%d] getsockopt failed: %s", seq, strerror(errno));
        return 0;
    }
    if (err != 0) {
        logmsg("ws", "[#%d] SO_ERROR=%d (%s)", seq, err, strerror(err));
        return 0;
    }

    /* poll for POLLHUP / POLLERR */
    struct pollfd pfd = { .fd = fd, .events = POLLOUT };
    int pr = poll(&pfd, 1, 0);
    logmsg("ws", "[#%d] poll check: ret=%d revents=0x%x (HUP=%d ERR=%d OUT=%d)",
           seq, pr, pfd.revents,
           !!(pfd.revents & POLLHUP), !!(pfd.revents & POLLERR),
           !!(pfd.revents & POLLOUT));

    return (pr >= 0 && !(pfd.revents & (POLLHUP | POLLERR)));
}

static void serve_debug_page(int fd) {
    static const char page[] =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html\r\n"
        "Connection: close\r\n\r\n"
        "<!DOCTYPE html><html><head><title>WS Debug</title></head>"
        "<body style='background:#111;color:#eee;font:14px monospace;padding:20px'>"
        "<h2>WS Debug</h2>"
        "<div style='margin-bottom:10px'>"
        "<button onclick='startWS()'>Retry WebSocket</button> "
        "<button onclick='startRaw()'>Retry Raw Test</button> "
        "<button onclick='L.textContent=\"\"'>Clear</button>"
        "</div>"
        "<pre id=log style='white-space:pre-wrap'></pre>"
        "<script>\n"
        "var L=document.getElementById('log');\n"
        "var t0=Date.now();\n"
        "function log(s){var ms=Date.now()-t0;L.textContent+='['+ms+'ms] '+s+'\\n';console.log(s);}\n"
        "var host=location.host;\n"
        "log('UA: '+navigator.userAgent);\n"
        "log('host: '+host);\n"
        "log('');\n"
        "\n"
        "/* --- RAW TCP TEST via fetch --- */\n"
        "function startRaw(){\n"
        "  log('=== RAW FETCH TEST ===');\n"
        "  log('(Note: browsers strip Upgrade/Connection headers from fetch)');\n"
        "  fetch('http://'+host+'/rawtest').then(function(r){\n"
        "    log('fetch status='+r.status+' '+r.statusText);\n"
        "    log('fetch headers:');\n"
        "    r.headers.forEach(function(v,k){log('  '+k+': '+v);});\n"
        "    return r.text();\n"
        "  }).then(function(t){\n"
        "    log('fetch body('+t.length+'): '+t.substring(0,100));\n"
        "  }).catch(function(e){ log('fetch error: '+e); });\n"
        "}\n"
        "startRaw();\n"
        "\n"
        "/* --- WebSocket tests --- */\n"
        "function startWS(){\n"
        "  log('');\n"
        "  log('=== WEBSOCKET TEST ===');\n"
        "  var url='ws://'+host;\n"
        "  log('url: '+url);\n"
        "  try{\n"
        "    var ws=new WebSocket(url);\n"
        "  }catch(e){\n"
        "    log('CONSTRUCTOR THREW: '+e);\n"
        "    return;\n"
        "  }\n"
        "  ws.binaryType='arraybuffer';\n"
        "  log('created, readyState='+ws.readyState+' (0=CONNECTING)');\n"
        "  log('url='+ws.url+' protocol='+ws.protocol+' extensions='+ws.extensions);\n"
        "\n"
        "  /* Poll readyState rapidly for the first 2 seconds */\n"
        "  var pollCount=0;\n"
        "  var poller=setInterval(function(){\n"
        "    pollCount++;\n"
        "    if(ws.readyState!==0||pollCount>40){\n"
        "      log('readyState poll: '+ws.readyState+' after '+pollCount+' checks');\n"
        "      clearInterval(poller);\n"
        "    }\n"
        "  },50);\n"
        "\n"
        "  ws.onopen=function(e){\n"
        "    log('*** OPEN *** readyState='+ws.readyState);\n"
        "    log('  protocol='+ws.protocol+' extensions='+ws.extensions);\n"
        "    log('  bufferedAmount='+ws.bufferedAmount);\n"
        "  };\n"
        "  ws.onmessage=function(e){\n"
        "    if(typeof e.data==='string'){\n"
        "      log('MSG(text,'+e.data.length+'): '+e.data.substring(0,200));\n"
        "    } else {\n"
        "      var a=new Uint8Array(e.data);\n"
        "      var hex=Array.from(a.slice(0,16)).map(function(b){return ('0'+b.toString(16)).slice(-2);}).join(' ');\n"
        "      log('MSG(bin,'+e.data.byteLength+'): '+hex);\n"
        "    }\n"
        "  };\n"
        "  ws.onclose=function(e){\n"
        "    log('*** CLOSE *** code='+e.code+' reason=['+e.reason+'] clean='+e.wasClean+' readyState='+ws.readyState);\n"
        "    log('  (1000=normal 1001=going_away 1002=protocol_err 1003=unsupported 1005=no_status 1006=abnormal 1007=invalid_data 1008=policy 1009=too_big 1010=ext_required 1011=internal 1015=tls)');\n"
        "  };\n"
        "  ws.onerror=function(e){\n"
        "    log('*** ERROR *** readyState='+ws.readyState+' type='+e.type);\n"
        "    log('  (Note: browser gives no details on WS errors for security)');\n"
        "  };\n"
        "\n"
        "  /* Timeout: if still CONNECTING after 5s, something is stuck */\n"
        "  setTimeout(function(){\n"
        "    if(ws.readyState===0){\n"
        "      log('TIMEOUT: still CONNECTING after 5s — server may not be responding');\n"
        "    }\n"
        "  },5000);\n"
        "}\n"
        "\n"
        "/* Start WS test after a delay to let fetch finish cleanly */\n"
        "setTimeout(startWS, 1500);\n"
        "\n"
        "/* Test 2: try with explicit subprotocol after 5s */\n"
        "setTimeout(function(){\n"
        "  log('');\n"
        "  log('=== WEBSOCKET TEST 2 (with subprotocol) ===');\n"
        "  var url='ws://'+host;\n"
        "  try{\n"
        "    var ws2=new WebSocket(url, 'clubtagger');\n"
        "    ws2.binaryType='arraybuffer';\n"
        "    ws2.onopen=function(){log('WS2 OPEN');};\n"
        "    ws2.onclose=function(e){log('WS2 CLOSE code='+e.code+' clean='+e.wasClean);};\n"
        "    ws2.onerror=function(){log('WS2 ERROR readyState='+ws2.readyState);};\n"
        "    ws2.onmessage=function(e){log('WS2 MSG: '+(typeof e.data==='string'?e.data:e.data.byteLength+'B'));};\n"
        "  }catch(e){log('WS2 constructor error: '+e);}\n"
        "}, 6000);\n"
        "\n"
        "/* Test 3: try with /ws path after 10s */\n"
        "setTimeout(function(){\n"
        "  log('');\n"
        "  log('=== WEBSOCKET TEST 3 (with /ws path) ===');\n"
        "  var url='ws://'+host+'/ws';\n"
        "  try{\n"
        "    var ws3=new WebSocket(url);\n"
        "    ws3.binaryType='arraybuffer';\n"
        "    ws3.onopen=function(){log('WS3 OPEN');};\n"
        "    ws3.onclose=function(e){log('WS3 CLOSE code='+e.code+' clean='+e.wasClean);};\n"
        "    ws3.onerror=function(){log('WS3 ERROR readyState='+ws3.readyState);};\n"
        "    ws3.onmessage=function(e){log('WS3 MSG: '+(typeof e.data==='string'?e.data:e.data.byteLength+'B'));};\n"
        "  }catch(e){log('WS3 constructor error: '+e);}\n"
        "}, 10000);\n"
        "</script></body></html>";
    send(fd, page, sizeof(page) - 1, 0);
}

static int do_handshake(int fd, int seq) {
    char buf[4096];
    ssize_t n = recv(fd, buf, sizeof(buf)-1, 0);
    logmsg("ws", "[#%d] recv returned %zd (errno=%d)", seq, n, n <= 0 ? errno : 0);
    if (n <= 0) return -1;
    buf[n] = '\0';

    /* Log full request to file */
    {
        char fname[64];
        snprintf(fname, sizeof(fname), "/tmp/ws_req_%d.txt", seq);
        FILE *f = fopen(fname, "w");
        if (f) {
            fprintf(f, "fd=%d seq=%d len=%zd\n---\n%s\n---\nhex:\n", fd, seq, n, buf);
            for (ssize_t i = 0; i < n; i++)
                fprintf(f, "%02x ", (unsigned char)buf[i]);
            fprintf(f, "\n");
            fclose(f);
        }
    }

    logmsg("ws", "[#%d] request (%zd bytes): %.120s", seq, n, buf);

    /* Find key — case-insensitive, handle variable spacing */
    char *kp = strcasestr(buf, "sec-websocket-key:");
    if (!kp) {
        logmsg("ws", "[#%d] no WS key — serving debug page", seq);
        serve_debug_page(fd);
        return -2; /* not a WS request */
    }

    logmsg("ws", "[#%d] WS upgrade request detected", seq);

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
    snprintf(cat, sizeof(cat), "%s258EAFA5-E914-47DA-95CA-C5AB0DC85B11", key);
    unsigned char hash[20];
    unsigned char *sha_ret = SHA1((unsigned char*)cat, strlen(cat), hash);
    logmsg("ws", "[#%d] SHA1 returned %p (hash=%p)", seq, (void*)sha_ret, (void*)hash);

    char b64[64];
    int b64len = EVP_EncodeBlock((unsigned char*)b64, hash, 20);
    logmsg("ws", "[#%d] key=[%s] accept=[%s] (b64len=%d)", seq, key, b64, b64len);

    /* Log hash bytes for verification */
    logmsg("ws", "[#%d] sha1=%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
           seq, hash[0],hash[1],hash[2],hash[3],hash[4],hash[5],hash[6],hash[7],
           hash[8],hash[9],hash[10],hash[11],hash[12],hash[13],hash[14],hash[15],
           hash[16],hash[17],hash[18],hash[19]);

    char resp[512];
    int rn = snprintf(resp, sizeof(resp),
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Accept: %s\r\n\r\n", b64);

    logmsg("ws", "[#%d] response (%d bytes): [%s]", seq, rn, resp);

    /* Dump full handshake to file */
    FILE *dbg = fopen("/tmp/ws_handshake.log", "w");
    if (dbg) {
        fprintf(dbg, "=== CONNECTION #%d fd=%d ===\n", seq, fd);
        fprintf(dbg, "=== REQUEST (%zd bytes) ===\n%s\n", n, buf);
        fprintf(dbg, "=== PARSED ===\nkey=[%s] (len=%d)\ncat=[%s]\nsha1=", key, ki, cat);
        for (int i = 0; i < 20; i++) fprintf(dbg, "%02x", hash[i]);
        fprintf(dbg, "\naccept=[%s] (len=%d)\n", b64, b64len);
        fprintf(dbg, "=== RESPONSE (%d bytes) ===\n%s", rn, resp);
        fprintf(dbg, "=== RESPONSE HEX (%d bytes) ===\n", rn);
        for (int i = 0; i < rn; i++)
            fprintf(dbg, "%02x ", (unsigned char)resp[i]);
        fprintf(dbg, "\n");
        fclose(dbg);
    }

    /* Check socket is still good before sending */
    log_socket_state(fd, seq, "pre-send");

    ssize_t sent = send(fd, resp, rn, 0);
    logmsg("ws", "[#%d] send 101: %zd/%d bytes (errno=%d)", seq, sent, rn, sent < 0 ? errno : 0);

    if (sent != rn) return -1;

    /* Check how much data is still in the kernel send buffer */
    int outq = 0;
    ioctl(fd, TIOCOUTQ, &outq);
    logmsg("ws", "[#%d] TIOCOUTQ after 101: %d bytes pending in kernel", seq, outq);

    /* Check socket after sending 101 */
    log_socket_state(fd, seq, "post-send");
    check_alive(fd, seq);

    /* Append post-send state to handshake log */
    dbg = fopen("/tmp/ws_handshake.log", "a");
    if (dbg) {
        int err = 0;
        socklen_t elen = sizeof(err);
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen);
        fprintf(dbg, "=== POST-SEND ===\nsent=%zd/%d SO_ERROR=%d TIOCOUTQ=%d\n", sent, rn, err, outq);
        fclose(dbg);
    }

    return 0;
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
    logmsg("ws", "listening on %s (fd=%d)", path, server_fd);

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

                /* Check socket health */
                int err = 0;
                socklen_t elen = sizeof(err);
                getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen);

                /* Check if client sent anything (close frame?) */
                uint8_t peek[16];
                ssize_t pn = recv(fd, peek, sizeof(peek), MSG_PEEK | MSG_DONTWAIT);
                if (pn > 0) {
                    logmsg("ws", "slot %d fd=%d has %zd bytes: %02x %02x %02x %02x",
                           i, fd, pn, peek[0], pn>1?peek[1]:0, pn>2?peek[2]:0, pn>3?peek[3]:0);
                } else if (pn == 0) {
                    logmsg("ws", "slot %d fd=%d: peer closed (recv=0)", i, fd);
                    close(fd);
                    atomic_store(&ws_fds[i], -1);
                    continue;
                } else {
                    /* pn < 0: EAGAIN/EWOULDBLOCK is normal, anything else is bad */
                    if (errno != EAGAIN && errno != EWOULDBLOCK) {
                        logmsg("ws", "slot %d fd=%d: recv peek error: %s (SO_ERROR=%d)",
                               i, fd, strerror(errno), err);
                        close(fd);
                        atomic_store(&ws_fds[i], -1);
                        continue;
                    }
                }

                if (err != 0) {
                    logmsg("ws", "slot %d fd=%d: SO_ERROR=%d (%s)", i, fd, err, strerror(err));
                    close(fd);
                    atomic_store(&ws_fds[i], -1);
                    continue;
                }

                char ping[64];
                int plen = snprintf(ping, sizeof(ping), "{\"t\":%ld}", (long)time(NULL));
                ssize_t sent = ws_text(fd, ping, plen);
                if (sent < 0) {
                    logmsg("ws", "slot %d fd=%d send failed: errno=%d (%s)", i, fd, errno, strerror(errno));
                    close(fd);
                    atomic_store(&ws_fds[i], -1);
                } else {
                    logmsg("ws", "slot %d fd=%d: sent ping (%zd bytes)", i, fd, sent);
                }
            }
            continue;
        }

        int seq = ++debug_seq;
        int cfd = accept(server_fd, NULL, NULL);
        if (cfd < 0) {
            logmsg("ws", "[#%d] accept failed: %s", seq, strerror(errno));
            continue;
        }

        logmsg("ws", "[#%d] accepted fd=%d (revents=0x%x)", seq, cfd, pfd.revents);
        log_peer(cfd, seq);

        /* TCP_NODELAY: send 101 response immediately, no Nagle buffering */
        {
            int one = 1;
            setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
        }

        log_socket_state(cfd, seq, "after-accept");

        int hs = do_handshake(cfd, seq);
        if (hs == -2) {
            logmsg("ws", "[#%d] debug page served, closing fd=%d", seq, cfd);
            close(cfd);
            continue;
        }
        if (hs != 0) {
            logmsg("ws", "[#%d] handshake FAILED (ret=%d), closing fd=%d", seq, hs, cfd);
            close(cfd);
            continue;
        }

        logmsg("ws", "[#%d] *** HANDSHAKE OK *** fd=%d", seq, cfd);

        /* Verify connection is still alive after handshake */
        if (!check_alive(cfd, seq)) {
            logmsg("ws", "[#%d] connection DEAD right after handshake!", seq);
            close(cfd);
            continue;
        }

        /* Send a test frame immediately */
        {
            const char hello[] = "{\"event\":\"hello\"}";
            ssize_t hs_sent = ws_text(cfd, hello, sizeof(hello) - 1);
            logmsg("ws", "[#%d] immediate test frame: %zd bytes (errno=%d)", seq, hs_sent,
                   hs_sent < 0 ? errno : 0);
        }

        /* Verify still alive after test frame */
        check_alive(cfd, seq);

        /* Store in slot */
        int stored = 0;
        for (int i = 0; i < WS_MAX_CLIENTS; i++) {
            if (atomic_load(&ws_fds[i]) < 0) {
                atomic_store(&ws_fds[i], cfd);
                logmsg("ws", "[#%d] stored in slot %d (fd=%d)", seq, i, cfd);
                stored = 1;
                break;
            }
        }
        if (!stored) {
            logmsg("ws", "[#%d] NO SLOT AVAILABLE, closing fd=%d", seq, cfd);
            /* Log what's in all slots */
            for (int i = 0; i < WS_MAX_CLIENTS; i++)
                logmsg("ws", "  slot %d: fd=%d", i, atomic_load(&ws_fds[i]));
            close(cfd);
        }
    }

    close(server_fd);
    return NULL;
}
