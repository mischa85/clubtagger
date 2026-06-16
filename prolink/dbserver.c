/*
 * dbserver.c - CDJ DBServer Client Implementation
 *
 * Query track metadata from CDJ's built-in database server (port 1051).
 */

#include "dbserver.h"
#include "dbserver_protocol.h"
#include "cdj_types.h"
#include "registration.h"
#include "../common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <poll.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>

/*
 * ============================================================================
 * Module State
 * ============================================================================
 */

static uint32_t db_txid = 1;
extern uint32_t our_ip;  /* From registration module */
extern const char *capture_interface;  /* From registration module */

/* Forward declaration — discovers dynamic DBServer port via RemoteDB (port 12523) */
int dbserver_query_port(uint32_t server_ip);

/*
 * ============================================================================
 * Message Building Helpers
 * ============================================================================
 */

/* Check if buffer at position has DBServer message magic (int32 field with magic value) */
static inline int is_dbserver_magic(const uint8_t *buf) {
    return buf[0] == DBFIELD_INT32 &&
           buf[1] == ((DBSERVER_MAGIC >> 24) & 0xFF) &&
           buf[2] == ((DBSERVER_MAGIC >> 16) & 0xFF) &&
           buf[3] == ((DBSERVER_MAGIC >> 8) & 0xFF) &&
           buf[4] == (DBSERVER_MAGIC & 0xFF);
}

/* Extract message type from response at given position. */
static inline uint16_t get_msg_type(const uint8_t *buf, size_t msg_start) {
    return (buf[msg_start + DBMSG_OFF_MSG_TYPE_VALUE] << 8) |
            buf[msg_start + DBMSG_OFF_MSG_TYPE_VALUE + 1];
}

/* Is `v` one of the known rekordbox menu-item attribute types? */
static inline int is_menu_item_type(uint32_t v) {
    switch (v) {
        case MENU_FOLDER: case MENU_ALBUM: case MENU_DISC: case MENU_TRACK_TITLE:
        case MENU_GENRE: case MENU_ARTIST: case MENU_PLAYLIST: case MENU_RATING:
        case MENU_DURATION: case MENU_TEMPO: case MENU_LABEL: case MENU_KEY:
        case MENU_BITRATE: case MENU_YEAR: case MENU_COMMENT: case MENU_DATE_ADDED:
            return 1;
        default:
            return 0;
    }
}

/*
 * Read one menu-item row at msg_start (a DBMSG_MENU_ITEM): its value string
 * (label1) into `label`, and its attribute type into *out_type. The row args
 * are laid out as id1, id2, label1(string), label2(string), itemType(int32),…
 * so the type is the first recognized menu-type int32 *after* the label (the
 * leading id1/id2 ints precede it and can't be mistaken for it). Returns 1 if
 * a label was read.
 */
static int read_menu_item(const uint8_t *resp, size_t len, size_t msg_start,
                          char *label, size_t label_sz, uint32_t *out_type) {
    label[0] = '\0';
    *out_type = 0xffffffff;

    int args_off = dbmsg_args_offset(resp, len, msg_start);
    if (args_off < 0) return 0;

    int have_label = 0;
    size_t p = (size_t)args_off;
    while (p + 5 <= len && !is_dbserver_magic(&resp[p])) {
        uint8_t f = resp[p];
        if (f == DBFIELD_INT32) {
            uint32_t v = ((uint32_t)resp[p+1] << 24) | ((uint32_t)resp[p+2] << 16) |
                         ((uint32_t)resp[p+3] << 8)  |  (uint32_t)resp[p+4];
            if (have_label && *out_type == 0xffffffff && is_menu_item_type(v))
                *out_type = v;
            p += 5;
        } else if (f == DBFIELD_STRING) {
            uint32_t sl = ((uint32_t)resp[p+1] << 24) | ((uint32_t)resp[p+2] << 16) |
                          ((uint32_t)resp[p+3] << 8)  |  (uint32_t)resp[p+4];
            if (sl >= 256 || p + 5 + (size_t)sl * 2 > len) break;
            if (!have_label) {
                char text[256] = {0};
                if (utf16be_to_utf8(resp + p + 5, sl * 2, text, sizeof(text)) >= 1) {
                    utf8_safe_copy(label, text, label_sz);
                    have_label = 1;
                }
            }
            p += 5 + (size_t)sl * 2;
        } else if (f == DBFIELD_INT8)  { p += 2; }
        else if (f == DBFIELD_INT16)   { p += 3; }
        else if (f == DBFIELD_BINARY)  {
            uint32_t bl = ((uint32_t)resp[p+1] << 24) | ((uint32_t)resp[p+2] << 16) |
                          ((uint32_t)resp[p+3] << 8)  |  (uint32_t)resp[p+4];
            p += 5 + (size_t)bl;
        } else break;  /* unknown field — stop this item */
    }
    return have_label;
}

/*
 * Parse a rekordbox menu response and assign each row's label to title/artist
 * BY ITS ITEM TYPE, not by position. The old "first string = title, second
 * string = artist" heuristic mis-assigned the musical-key row to the artist
 * whenever a track had no artist tag — the empty artist row was skipped and
 * the key row's string fell into the artist slot. Routing by MENU_TRACK_TITLE
 * / MENU_ARTIST makes key/genre/etc. rows incapable of landing in the artist
 * field. Returns 1 if title or artist was found.
 */
static int parse_menu_items_typed(const uint8_t *resp, size_t len,
                                  char *title, size_t title_len,
                                  char *artist, size_t artist_len) {
    int found_title = 0, found_artist = 0;

    for (size_t i = 0; i + DBMSG_MIN_HEADER_BYTES < len; i++) {
        if (!is_dbserver_magic(&resp[i])) continue;
        if (get_msg_type(resp, i) != DBMSG_MENU_ITEM) continue;

        char     label[256];
        uint32_t item_type;
        if (!read_menu_item(resp, len, i, label, sizeof(label), &item_type)) continue;
        if (!label[0]) continue;

        if (item_type == MENU_TRACK_TITLE && !found_title) {
            utf8_safe_copy(title, label, title_len);
            found_title = 1;
        } else if (item_type == MENU_ARTIST && !found_artist) {
            utf8_safe_copy(artist, label, artist_len);
            found_artist = 1;
        }
    }

    /* Safety net: if no row carried a recognized type (e.g. an unexpected
     * firmware layout where the type int32 isn't where we expect), fall back
     * to the first menu item's string as the title so tracks still resolve.
     * We deliberately do NOT guess the artist — mis-guessing it (the key) is
     * the exact bug this function exists to prevent. */
    if (!found_title) {
        for (size_t i = 0; i + DBMSG_MIN_HEADER_BYTES < len; i++) {
            if (!is_dbserver_magic(&resp[i])) continue;
            if (get_msg_type(resp, i) != DBMSG_MENU_ITEM) continue;
            char label[256]; uint32_t t;
            if (read_menu_item(resp, len, i, label, sizeof(label), &t) && label[0]) {
                utf8_safe_copy(title, label, title_len);
                found_title = 1;
                break;
            }
        }
    }

    return found_title || found_artist;
}

static int add_int32_field(uint8_t *buf, uint32_t value) {
    buf[0] = DBFIELD_INT32;
    buf[1] = (value >> 24) & 0xFF;
    buf[2] = (value >> 16) & 0xFF;
    buf[3] = (value >> 8) & 0xFF;
    buf[4] = value & 0xFF;
    return 5;
}

static int add_int16_field(uint8_t *buf, uint16_t value) {
    buf[0] = DBFIELD_INT16;
    buf[1] = (value >> 8) & 0xFF;
    buf[2] = value & 0xFF;
    return 3;
}

static int add_int8_field(uint8_t *buf, uint8_t value) {
    buf[0] = DBFIELD_INT8;
    buf[1] = value;
    return 2;
}

static int add_arg_tags(uint8_t *buf, const uint8_t *tags, int num_tags) {
    buf[0] = DBFIELD_BINARY;
    buf[1] = 0x00; buf[2] = 0x00; buf[3] = 0x00; buf[4] = DBFIELD_TAGS_LEN;
    memset(buf + 5, 0, DBFIELD_TAGS_LEN);
    for (int i = 0; i < num_tags && i < DBFIELD_TAGS_LEN; i++) {
        buf[5 + i] = tags[i];
    }
    return 1 + 4 + DBFIELD_TAGS_LEN;
}

int build_message_header(uint8_t *buf, uint32_t txid, uint16_t msg_type,
                        uint8_t arg_count, const uint8_t *arg_tags) {
    int pos = 0;
    
    pos += add_int32_field(buf + pos, DBSERVER_MAGIC);
    pos += add_int32_field(buf + pos, txid);
    pos += add_int16_field(buf + pos, msg_type);
    pos += add_int8_field(buf + pos, arg_count);
    pos += add_arg_tags(buf + pos, arg_tags, arg_count);
    
    return pos;
}

/*
 * ============================================================================
 * Transaction Helper
 * ============================================================================
 */

int dbserver_transact(int sock, const uint8_t *msg, size_t msg_len,
                      uint8_t *resp, size_t resp_max) {
    ssize_t sent = send(sock, msg, msg_len, 0);
    if (sent != (ssize_t)msg_len) {
        logmsg("dbsrv", "Send failed: sent=%zd errno=%d (%s)", sent, errno, strerror(errno));
        return -1;
    }
    
    ssize_t total = 0;
    int wait_count = 0;
    
    while (total < (ssize_t)resp_max - 256 && wait_count < 10) {
        ssize_t received = recv(sock, resp + total, resp_max - total, 0);
        if (received < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                wait_count++;
                usleep(100000);  /* 100ms wait */
                continue;
            }
            logmsg("dbsrv", "recv error errno=%d (%s)", errno, strerror(errno));
            break;
        }
        if (received == 0) break;
        total += received;
        wait_count = 0;
        
        /* Check for complete message */
        if (total >= 12) {
            for (size_t i = 0; i < (size_t)total - 10; i++) {
                if (is_dbserver_magic(&resp[i])) {
                    if (i + 13 <= (size_t)total) {
                        uint16_t rtype = get_msg_type(resp, i);
                        /* Terminal message types - we have a complete response */
                        if (rtype == DBMSG_SUCCESS || rtype == DBMSG_MENU_FOOTER || 
                            rtype == DBMSG_ARTWORK_RESP || rtype == DBMSG_BEAT_GRID_RESP || 
                            rtype == DBMSG_CUE_RESP || rtype == DBMSG_WAVEFORM_RESP || 
                            rtype == DBMSG_ANALYSIS_RESP) {
                            goto done_recv;
                        }
                    }
                }
            }
        }
    }
    
done_recv:
    if (verbose) {
        vlogmsg("dbsrv", "Received %zd bytes", total);
    }
    
    return (int)total;
}

/*
 * ============================================================================
 * Connection Management
 * ============================================================================
 */

int dbserver_connect(uint32_t server_ip) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        logmsg("dbsrv", "socket() failed for connect to %s: %s",
               ip_to_str(server_ip), strerror(errno));
        return -1;
    }
    
    vlogmsg("dbsrv", "our_ip=0x%08x (%s)", our_ip, ip_to_str(our_ip));
    
    /* Bind to our Pro DJ Link interface for link-local routing */
    if (capture_interface) {
        if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, capture_interface, 
                       strlen(capture_interface) + 1) < 0) {
            logmsg("dbsrv", "SO_BINDTODEVICE(%s) failed: %s", capture_interface, strerror(errno));
            /* Continue anyway - might work without it */
        } else {
            if (verbose) vlogmsg("dbsrv", "Bound to interface %s", capture_interface);
        }
    } else {
        logmsg("dbsrv", "Warning: capture_interface not set");
    }
    
    /* Bind to our Pro DJ Link IP */
    struct sockaddr_in bind_addr;
    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_addr.s_addr = our_ip;
    bind_addr.sin_port = 0;
    if (bind(sock, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0) {
        logmsg("dbsrv", "DBServer: bind to %s failed: %s", ip_to_str(our_ip), strerror(errno));
        close(sock);
        return -1;
    }
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    int db_port = dbserver_query_port(server_ip);
    addr.sin_port = htons((uint16_t)db_port);
    addr.sin_addr.s_addr = server_ip;

    /* Non-blocking connect with timeout */
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    
    int ret = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
    if (ret < 0 && errno != EINPROGRESS) {
        logmsg("dbsrv", "DBServer: connect to %s:%d failed: %s", ip_to_str(server_ip), db_port, strerror(errno));
        close(sock);
        return -1;
    }
    
    struct pollfd pfd;
    pfd.fd = sock;
    pfd.events = POLLOUT;
    
    if (poll(&pfd, 1, 3000) <= 0) {
        logmsg("dbsrv", "DBServer: connect timeout to %s:%d", ip_to_str(server_ip), db_port);
        close(sock);
        return -1;
    }
    
    int error = 0;
    socklen_t len = sizeof(error);
    if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &error, &len) != 0 || error != 0) {
        logmsg("dbsrv", "DBServer: connect to %s:%d: %s", ip_to_str(server_ip), db_port, strerror(error));
        close(sock);
        return -1;
    }
    
    fcntl(sock, F_SETFL, flags);
    struct timeval tv = {1, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    
    if (verbose) vlogmsg("dbsrv", "Connected to %s", ip_to_str(server_ip));
    
    return sock;
}

int dbserver_setup(int sock, uint8_t device_num) {
    uint8_t msg[64];
    uint8_t resp[64];
    int pos = 0;
    
    /* Step 1: Send initial greeting (int32 value of 1) */
    pos = add_int32_field(msg, 1);
    
    if (send(sock, msg, pos, 0) != pos) {
        logmsg("dbsrv", "Setup step 1 send failed: %s", strerror(errno));
        return -1;
    }
    
    ssize_t received = recv(sock, resp, sizeof(resp), 0);
    if (received < 5) {
        logmsg("dbsrv", "Setup step 1 recv failed (%zd bytes, errno=%d %s)", received, errno, strerror(errno));
        return -1;
    }
    
    /* Step 2: Send setup message using build_message_header */
    uint8_t tags[DBFIELD_TAGS_LEN] = {FIELD_INT32};  /* One int32 argument */
    pos = build_message_header(msg, DB_SETUP_TXID, DBMSG_SETUP, 1, tags);
    pos += add_int32_field(msg + pos, device_num);
    
    if (send(sock, msg, pos, 0) != pos) {
        logmsg("dbsrv", "Setup step 2 send failed: %s", strerror(errno));
        return -1;
    }
    
    received = recv(sock, resp, sizeof(resp), 0);
    if (received < 12) {
        logmsg("dbsrv", "Setup step 2 recv failed (%zd bytes, errno=%d %s)", received, errno, strerror(errno));
        return -1;
    }
    
    /* Check magic - expect int32 field with magic value */
    if (resp[0] != DBFIELD_INT32 || 
        resp[1] != ((DBSERVER_MAGIC >> 24) & 0xFF) ||
        resp[2] != ((DBSERVER_MAGIC >> 16) & 0xFF) ||
        resp[3] != ((DBSERVER_MAGIC >> 8) & 0xFF) ||
        resp[4] != (DBSERVER_MAGIC & 0xFF)) {
        logmsg("dbsrv", "Setup bad magic: %02x %02x %02x %02x %02x", resp[0], resp[1], resp[2], resp[3], resp[4]);
        return -1;
    }
    
    return 0;
}

int dbserver_disconnect(int sock) {
    uint8_t msg[64];
    uint8_t tags[12] = {0};
    int pos = build_message_header(msg, DB_SETUP_TXID, DBMSG_DISCONNECT, 0, tags);
    
    send(sock, msg, pos, 0);
    
    if (verbose) vlogmsg("dbsrv", "Sent disconnect");
    return 0;
}

/*
 * ============================================================================
 * Metadata Queries
 * ============================================================================
 */

int dbserver_request_metadata_rekordbox(int sock, uint8_t device, uint8_t slot,
                                        uint32_t rekordbox_id,
                                        char *title, size_t title_len,
                                        char *artist, size_t artist_len) {
    uint8_t msg[128];
    uint8_t resp[8192];
    int pos = 0;
    
    /* Step 1: Send metadata setup request (0x2002) */
    uint8_t tags1[DBFIELD_TAGS_LEN] = {FIELD_INT32, FIELD_INT32};
    pos = build_message_header(msg, db_txid++, DBMSG_METADATA_REQ, 2, tags1);
    
    uint32_t dmst = build_dmst(device, MENU_LOC_DATA, slot, TRACK_REKORDBOX);
    pos += add_int32_field(msg + pos, dmst);
    pos += add_int32_field(msg + pos, rekordbox_id);
    
    /* Always dump the outgoing request */
    {
        char hex[256];
        int hlen = 0;
        for (int i = 0; i < pos && i < 60; i++) {
            hlen += snprintf(hex + hlen, sizeof(hex) - hlen, "%02x ", msg[i]);
        }
        vlogmsg("dbsrv", "Query msg (%d bytes): %s", pos, hex);
    }
    
    if (verbose) {
        vlogmsg("dbsrv", "Request: device=%d slot=%d rekordbox_id=%u DMST=0x%08x", 
                   device, slot, rekordbox_id, dmst);
    }
    
    int received = dbserver_transact(sock, msg, pos, resp, sizeof(resp));
    
    /* Always dump first 50 bytes of response */
    char rb_resp_hex[200] = {0};
    if (received > 0) {
        int hlen = 0;
        for (int i = 0; i < received && i < 50; i++) {
            hlen += snprintf(rb_resp_hex + hlen, sizeof(rb_resp_hex) - hlen, "%02x ", resp[i]);
        }
        if (verbose) vlogmsg("dbsrv", "Rekordbox resp (%d bytes): %s", received, rb_resp_hex);
    }

    if (received < 20) {
        logmsg("dbsrv", "Rekordbox response too short (id=%u %d bytes): %s",
               rekordbox_id, received, rb_resp_hex);
        return -1;
    }
    
    /* Parse response: locate the DBMSG_SUCCESS frame and read arg index 1
     * (num_items). Argtags blob is variable-length on CDJ-3000X replies, so
     * never hardcode the argument offset — use dbmsg_args_offset(). */
    uint32_t num_items = 0;
    for (int i = 0; (size_t)i + DBMSG_MIN_HEADER_BYTES < (size_t)received; i++) {
        if (!is_dbserver_magic(&resp[i])) continue;
        if ((size_t)i + DBMSG_OFF_ARGC_VALUE >= (size_t)received) break;
        uint16_t rtype = get_msg_type(resp, i);
        if (verbose > 1) vlogmsg("dbsrv", "Found msg at %d, type=0x%04x", i, rtype);
        if (rtype != DBMSG_SUCCESS) continue;
        int args_off = dbmsg_args_offset(resp, (size_t)received, (size_t)i);
        (void)dbmsg_read_int32_arg(resp, (size_t)received, args_off, 1, &num_items);
        break;
    }
    
    if (verbose) vlogmsg("dbsrv", "num_items=%u", num_items);
    if (num_items == 0 || num_items == 0xffffffffu) {
        logmsg("dbsrv", "Rekordbox no items (id=%u num_items=%u resp=%s)",
               rekordbox_id, num_items, rb_resp_hex);
        return -1;
    }

    /* Step 2: Render menu to get items */
    pos = 0;
    uint8_t tags2[DBFIELD_TAGS_LEN] = {FIELD_INT32, FIELD_INT32, FIELD_INT32, FIELD_INT32, FIELD_INT32, FIELD_INT32};
    pos = build_message_header(msg, db_txid++, DBMSG_RENDER_MENU, 6, tags2);

    pos += add_int32_field(msg + pos, build_dmst(device, MENU_LOC_DATA, slot, TRACK_REKORDBOX));
    pos += add_int32_field(msg + pos, 0);
    pos += add_int32_field(msg + pos, num_items);
    pos += add_int32_field(msg + pos, 0);
    pos += add_int32_field(msg + pos, num_items);
    pos += add_int32_field(msg + pos, 0);
    
    received = dbserver_transact(sock, msg, pos, resp, sizeof(resp));
    char rb_menu_hex[200] = {0};
    if (received > 0) {
        int hlen = 0;
        for (int i = 0; i < received && i < 50; i++) {
            hlen += snprintf(rb_menu_hex + hlen, sizeof(rb_menu_hex) - hlen, "%02x ", resp[i]);
        }
    }
    if (received < 50) {
        logmsg("dbsrv", "Rekordbox menu response too short (id=%u %d bytes): %s",
               rekordbox_id, received, rb_menu_hex);
        return -1;
    }

    /* Parse menu items, routing each row to title/artist by its item type. */
    parse_menu_items_typed(resp, (size_t)received, title, title_len, artist, artist_len);
    int found_title  = (title[0]  != '\0');
    int found_artist = (artist[0] != '\0');

    if (verbose) {
        vlogmsg("dbsrv", "Parse result: found_title=%d found_artist=%d", found_title, found_artist);
        if (found_title) vlogmsg("dbsrv", "Title: %s", title);
        if (found_artist) vlogmsg("dbsrv", "Artist: %s", artist);
    }

    if (!found_title && !found_artist) {
        logmsg("dbsrv", "Rekordbox parse found no strings (id=%u %d bytes num_items=%u): %s",
               rekordbox_id, received, num_items, rb_menu_hex);
        return -1;
    }
    return 0;
}

int dbserver_request_metadata_unanalyzed(int sock, uint8_t device, uint8_t slot,
                                         uint32_t track_id,
                                         char *title, size_t title_len,
                                         char *artist, size_t artist_len) {
    uint8_t msg[128];
    uint8_t resp[8192];
    int pos = 0;
    
    /* Send unanalyzed metadata request (0x2202) */
    uint8_t tags1[DBFIELD_TAGS_LEN] = {FIELD_INT32, FIELD_INT32};
    pos = build_message_header(msg, db_txid++, DBMSG_UNANALYZED_REQ, 2, tags1);
    
    pos += add_int32_field(msg + pos, build_dmst(device, MENU_LOC_DATA, slot, TRACK_UNANALYZED));
    pos += add_int32_field(msg + pos, track_id);
    
    int received = dbserver_transact(sock, msg, pos, resp, sizeof(resp));

    /* Capture response hex for both diagnostic and failure logs */
    char un_resp_hex[200] = {0};
    if (received > 0) {
        int hlen = 0;
        for (int i = 0; i < received && i < 60; i++) {
            hlen += snprintf(un_resp_hex + hlen, sizeof(un_resp_hex) - hlen, "%02x ", resp[i]);
        }
        if (verbose) vlogmsg("dbsrv", "Unanalyzed resp (%d bytes): %s", received, un_resp_hex);
    }

    if (received < 20) {
        logmsg("dbsrv", "Unanalyzed response too short (id=%u %d bytes): %s",
               track_id, received, un_resp_hex);
        return -1;
    }
    
    /* Parse response for item count. The success frame begins at offset 0;
     * arg index 1 is num_items. Argtags blob length is variable on
     * CDJ-3000X — dbmsg_args_offset() handles that. */
    uint32_t num_items = 0;
    if (get_msg_type(resp, 0) == DBMSG_SUCCESS) {
        int args_off = dbmsg_args_offset(resp, (size_t)received, 0);
        (void)dbmsg_read_int32_arg(resp, (size_t)received, args_off, 1, &num_items);
    }
    vlogmsg("dbsrv", "Unanalyzed: %u items available", num_items);

    if (num_items == 0 || num_items == 0xffffffffu || num_items == DBMSG_UNANALYZED_REQ) {
        logmsg("dbsrv", "Unanalyzed no items (id=%u num_items=%u resp=%s)",
               track_id, num_items, un_resp_hex);
        return -1;
    }

    /* Render menu */
    pos = 0;
    uint8_t tags2[DBFIELD_TAGS_LEN] = {FIELD_INT32, FIELD_INT32, FIELD_INT32, FIELD_INT32, FIELD_INT32, FIELD_INT32};
    pos = build_message_header(msg, db_txid++, DBMSG_RENDER_MENU, 6, tags2);

    pos += add_int32_field(msg + pos, build_dmst(device, MENU_LOC_DATA, slot, TRACK_UNANALYZED));
    pos += add_int32_field(msg + pos, 0);
    pos += add_int32_field(msg + pos, num_items);
    pos += add_int32_field(msg + pos, 0);
    pos += add_int32_field(msg + pos, num_items);
    pos += add_int32_field(msg + pos, 0);
    
    received = dbserver_transact(sock, msg, pos, resp, sizeof(resp));
    char un_menu_hex[200] = {0};
    if (received > 0) {
        int hlen = 0;
        for (int i = 0; i < received && i < 50; i++) {
            hlen += snprintf(un_menu_hex + hlen, sizeof(un_menu_hex) - hlen, "%02x ", resp[i]);
        }
    }
    if (received < 50) {
        logmsg("dbsrv", "Unanalyzed menu response too short (id=%u %d bytes): %s",
               track_id, received, un_menu_hex);
        return -1;
    }

    /* Parse menu items, routing each row to title/artist by its item type. */
    parse_menu_items_typed(resp, (size_t)received, title, title_len, artist, artist_len);
    int found_title  = (title[0]  != '\0');
    int found_artist = (artist[0] != '\0');

    if (!found_title && !found_artist) {
        logmsg("dbsrv", "Unanalyzed parse found no strings (id=%u %d bytes num_items=%u): %s",
               track_id, received, num_items, un_menu_hex);
        return -1;
    }
    return 0;
}

/*
 * ============================================================================
 * High-Level Query Wrapper
 * ============================================================================
 */

int dbserver_query_metadata(uint32_t device_ip, uint8_t our_device_param, uint8_t target_device,
                            uint8_t slot, uint8_t track_type, uint32_t track_id,
                            char *title, size_t title_len,
                            char *artist, size_t artist_len) {
    /* Ensure we're registered on the network before querying */
    if (!ensure_registration_active()) {
        logmsg("dbsrv", "Cannot query id=%u - no network slot available", track_id);
        return CDJ_ERR_CONNECT;
    }
    
    /* Use actual device number from registration (ignore passed parameter) */
    uint8_t our_device = get_our_device_num();
    (void)our_device_param;  /* Suppress unused warning */
    
    
    int sock = dbserver_connect(device_ip);
    if (sock < 0)
        return CDJ_ERR_CONNECT;

    if (dbserver_setup(sock, our_device) != 0) {
        logmsg("dbsrv", "DBServer: setup failed on %s (device %d)", ip_to_str(device_ip), our_device);
        close(sock);
        return CDJ_ERR_CONNECT;
    }
    vlogmsg("dbsrv", "Setup OK, querying target=%d slot=%d id=%u type=%d", 
               target_device, slot, track_id, track_type);
    
    int result;
    if (track_type == TRACK_REKORDBOX) {
        result = dbserver_request_metadata_rekordbox(sock, our_device, slot, track_id,
                                                     title, title_len, artist, artist_len);
    } else {
        /* Unanalyzed and CD-text both use 0x2202 */
        result = dbserver_request_metadata_unanalyzed(sock, our_device, slot, track_id,
                                                      title, title_len, artist, artist_len);
    }
    
    dbserver_disconnect(sock);
    close(sock);
    
    return result;
}

int dbserver_query_port(uint32_t server_ip) {
    /* Try RemoteDB port discovery first (CDJ-3000X uses dynamic port) */
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return DBSERVER_PORT;

    /* Bind to our Pro DJ Link IP */
    struct sockaddr_in bind_addr = {0};
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_addr.s_addr = our_ip;
    if (bind(sock, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0) {
        close(sock);
        return DBSERVER_PORT;
    }

    /* Bind to interface for link-local routing */
    if (capture_interface) {
        setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, capture_interface,
                   strlen(capture_interface) + 1);
    }

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(12523);
    addr.sin_addr.s_addr = server_ip;

    /* Non-blocking connect with 2s timeout */
    fcntl(sock, F_SETFL, fcntl(sock, F_GETFL, 0) | O_NONBLOCK);
    int ret = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
    if (ret < 0 && errno != EINPROGRESS) {
        close(sock);
        logmsg("dbsrv", "RemoteDB 12523 connect failed to %s: %s, using default port %d",
               ip_to_str(server_ip), strerror(errno), DBSERVER_PORT);
        return DBSERVER_PORT;
    }

    struct pollfd pfd = { .fd = sock, .events = POLLOUT };
    if (poll(&pfd, 1, 2000) <= 0 || !(pfd.revents & POLLOUT)) {
        close(sock);
        return DBSERVER_PORT;
    }

    /* Check connect result */
    int err = 0;
    socklen_t errlen = sizeof(err);
    getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &errlen);
    if (err != 0) {
        close(sock);
        return DBSERVER_PORT;
    }

    /* Connected! Switch back to blocking */
    fcntl(sock, F_SETFL, fcntl(sock, F_GETFL, 0) & ~O_NONBLOCK);

    /* Set timeout */
    struct timeval tv = {2, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    /* Send: [4B length] "RemoteDBServer\0" */
    uint8_t req[19];
    uint32_t len = htonl(15);
    memcpy(req, &len, 4);
    memcpy(req + 4, "RemoteDBServer", 15);  /* includes \0 */
    if (send(sock, req, 19, 0) != 19) {
        close(sock);
        return DBSERVER_PORT;
    }

    /* Read: [2B port big-endian] */
    uint8_t resp[2];
    if (recv(sock, resp, 2, 0) == 2) {
        int port = (resp[0] << 8) | resp[1];
        close(sock);
        if (port > 0 && port < 65536) {
            logmsg("dbsrv", "RemoteDB: CDJ at %s → DBServer on port %d", ip_to_str(server_ip), port);
            return port;
        }
    }

    close(sock);
    return DBSERVER_PORT;
}

int dbserver_request_all_tracks_count(int sock, uint8_t device, uint8_t slot) {
    (void)sock; (void)device; (void)slot;
    logmsg("dbsrv", "dbserver_request_all_tracks_count: stub not implemented");
    return -1;
}

int dbserver_find_unanalyzed_filename(uint32_t device_ip, uint8_t our_device,
                                      uint8_t slot, uint32_t track_id,
                                      char *filename, size_t filename_len) {
    (void)our_device; (void)filename; (void)filename_len;
    logmsg("dbsrv", "dbserver_find_unanalyzed_filename: stub not implemented (ip=%s slot=%u id=%u)",
           ip_to_str(device_ip), slot, track_id);
    return -1;
}

/*
 * ============================================================================
 * DBServer Traffic Parsing (Passive Eavesdropping)
 * ============================================================================
 *
 * When connected to a SPAN port, we can observe DBServer TCP traffic between
 * CDJs and extract track metadata without making active queries.
 *
 * DBServer messages:
 * - 0x2002 (METADATA_REQ): Query for rekordbox track metadata
 * - 0x2202 (UNANALYZED_REQ): Query for non-rekordbox track metadata
 * - 0x4101 (MENU_ITEM): Response containing title/artist strings
 * - 0x4000 (SUCCESS): Indicates data available
 */

#include "track_cache.h"

/*
 * Track pending metadata requests by transaction ID so we can correlate
 * responses with their requests.
 */
#define MAX_PENDING_DB_QUERIES 32

typedef struct {
    uint32_t txid;
    uint32_t client_ip;
    uint32_t server_ip;
    uint32_t rekordbox_id;
    uint8_t  device;
    uint8_t  slot;
    uint8_t  track_type;
    time_t   timestamp;
} pending_db_query_t;

static pending_db_query_t pending_db_queries[MAX_PENDING_DB_QUERIES];
static int pending_db_query_count = 0;

/* Add pending query */
static void add_pending_db_query(uint32_t txid, uint32_t client_ip, uint32_t server_ip,
                                  uint32_t rekordbox_id, uint8_t device, uint8_t slot,
                                  uint8_t track_type) {
    /* Evict old entries (>10 seconds) */
    time_t now = time(NULL);
    for (int i = 0; i < pending_db_query_count; ) {
        if (now - pending_db_queries[i].timestamp > 10) {
            pending_db_queries[i] = pending_db_queries[--pending_db_query_count];
        } else {
            i++;
        }
    }
    
    if (pending_db_query_count < MAX_PENDING_DB_QUERIES) {
        pending_db_query_t *q = &pending_db_queries[pending_db_query_count++];
        q->txid = txid;
        q->client_ip = client_ip;
        q->server_ip = server_ip;
        q->rekordbox_id = rekordbox_id;
        q->device = device;
        q->slot = slot;
        q->track_type = track_type;
        q->timestamp = now;
    }
}

/* Find pending query */
static pending_db_query_t *find_pending_db_query(uint32_t client_ip, uint32_t server_ip) {
    /* Find most recent query between these two IPs */
    time_t newest = 0;
    pending_db_query_t *result = NULL;
    
    for (int i = 0; i < pending_db_query_count; i++) {
        if (pending_db_queries[i].client_ip == client_ip &&
            pending_db_queries[i].server_ip == server_ip &&
            pending_db_queries[i].timestamp > newest) {
            newest = pending_db_queries[i].timestamp;
            result = &pending_db_queries[i];
        }
    }
    return result;
}

void parse_dbserver_traffic(const uint8_t *data, size_t len,
                            uint32_t src_ip, uint32_t dst_ip) {
    /*
     * DBServer traffic is TCP, so we may see partial messages.
     * Look for message magic (0x11 + DBSERVER_MAGIC bytes) and parse what we find.
     */
    
    for (size_t i = 0; i + 20 < len; i++) {
        /* Look for message start: 0x11 (int32 field) + magic bytes */
        if (!is_dbserver_magic(&data[i])) continue;
        
        size_t msg_start = i;
        
        /* Minimum header: magic(5) + txid(5) + type(3) + argcnt(2) + tags(17) = 32 */
        if (msg_start + 32 > len) continue;
        
        /* Extract transaction ID (int32 field at offset 5) */
        uint32_t txid = 0;
        if (data[msg_start + 5] == DBFIELD_INT32) {
            txid = (data[msg_start + 6] << 24) | (data[msg_start + 7] << 16) |
                   (data[msg_start + 8] << 8) | data[msg_start + 9];
        }
        
        /* Extract message type (int16 field at offset 10) */
        uint16_t msg_type = get_msg_type(data, msg_start);
        
        if (verbose > 1) {
            vlogmsg("dbsrv", "sniffed: msg_type=0x%04x txid=%u from %s -> %s",
                       msg_type, txid, ip_to_str(src_ip), ip_to_str(dst_ip));
        }
        
        /* Handle metadata request messages */
        if (msg_type == DBMSG_METADATA_REQ || msg_type == DBMSG_UNANALYZED_REQ) {
            /*
             * Request format after header (32 bytes):
             * - DMST (int32 at +32): device/menu/slot/type
             * - rekordbox_id (int32 at +37)
             */
            if (msg_start + 42 > len) continue;
            
            uint8_t track_type = (msg_type == DBMSG_METADATA_REQ) ? 
                                 TRACK_REKORDBOX : TRACK_UNANALYZED;
            
            /* Find DMST field */
            size_t pos = msg_start + 32;
            if (data[pos] != DBFIELD_INT32) continue;
            
            uint32_t dmst = (data[pos + 1] << 24) | (data[pos + 2] << 16) |
                            (data[pos + 3] << 8) | data[pos + 4];
            uint8_t device = (dmst >> 24) & 0xFF;
            uint8_t slot = (dmst >> 8) & 0xFF;
            
            /* Find rekordbox_id */
            pos += 5;
            if (pos + 5 > len || data[pos] != DBFIELD_INT32) continue;
            
            uint32_t rekordbox_id = (data[pos + 1] << 24) | (data[pos + 2] << 16) |
                                    (data[pos + 3] << 8) | data[pos + 4];
            
            if (verbose) {
                vlogmsg("dbsrv", "sniffed metadata query: %s -> %s device=%d slot=%d id=%u type=%s",
                           ip_to_str(src_ip), ip_to_str(dst_ip),
                           device, slot, rekordbox_id,
                           track_type == TRACK_REKORDBOX ? "rekordbox" : "unanalyzed");
            }
            
            /* Record pending query */
            add_pending_db_query(txid, src_ip, dst_ip, rekordbox_id, device, slot, track_type);
        }
        
        /* Handle menu item responses (contain title/artist) */
        else if (msg_type == DBMSG_MENU_ITEM) {
            /*
             * Each MENU_ITEM is one attribute row. Route its value to title or
             * artist by item type (not position) so key/genre/etc. rows can't
             * be learned as the artist. A given menu item carries either the
             * title or the artist; the cache merges them across messages.
             */
            char title[128] = {0};
            char artist[128] = {0};
            int found_title = 0, found_artist = 0;

            char     label[256];
            uint32_t item_type;
            if (read_menu_item(data, len, msg_start, label, sizeof(label), &item_type)
                && label[0]) {
                if (item_type == MENU_TRACK_TITLE) {
                    utf8_safe_copy(title, label, sizeof(title));
                    found_title = 1;
                } else if (item_type == MENU_ARTIST) {
                    utf8_safe_copy(artist, label, sizeof(artist));
                    found_artist = 1;
                }
            }
            
            /* If we found metadata, try to associate with a pending query */
            if (found_title || found_artist) {
                pending_db_query_t *query = find_pending_db_query(dst_ip, src_ip);
                
                if (query && query->rekordbox_id != 0) {
                    vlogmsg("dbsrv", "sniffed learn: id=%u title='%s' artist='%s'",
                               query->rekordbox_id, title, artist);
                    
                    /* Add to track cache */
                    track_cache_entry_t *entry = add_track_cache(query->rekordbox_id,
                                                                  query->device);
                    if (entry) {
                        if (title[0]) {
                            strncpy(entry->title, title, sizeof(entry->title) - 1);
                        }
                        if (artist[0]) {
                            strncpy(entry->artist, artist, sizeof(entry->artist) - 1);
                        }
                        entry->last_seen = time(NULL);
                    }
                } else if (verbose) {
                    vlogmsg("dbsrv", "sniffed menu item: title='%s' artist='%s' (no pending query)",
                               title, artist);
                }
            }
        }
        
        /* Handle SUCCESS response (indicates query completed) */
        else if (msg_type == DBMSG_SUCCESS) {
            if (verbose > 1) {
                vlogmsg("dbsrv", "sniffed SUCCESS response from %s", ip_to_str(src_ip));
            }
        }
    }
}
