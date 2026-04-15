/*
 * common.c - Shared utilities and globals for clubtagger
 */
#include "common.h"

#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ─────────────────────────────────────────────────────────────────────────────
 * Global state
 * ───────────────────────────────────────────────────────────────────────────── */
volatile sig_atomic_t g_running = 1;
int g_verbose = 0;
int verbose = 0;  /* Alias for prolink modules (synced with g_verbose) */
int match_threshold = 60;  /* Default 60% similarity for fuzzy matching */
#ifdef HAVE_PCAP
pcap_t *g_pcap_handle = NULL;
#endif
#ifdef HAVE_ALSA
snd_pcm_t *g_alsa_handle = NULL;
#endif
#ifdef HAVE_AF_XDP
struct xsk_socket *g_xsk = NULL;
#endif

/* ─────────────────────────────────────────────────────────────────────────────
 * Logging functions
 * ───────────────────────────────────────────────────────────────────────────── */

/* Activity log ring buffer */
activity_log_t g_activity_log = {0};

static void activity_log_push(const char *tag, const char *fmt, va_list ap) {
    char msg[ACTIVITY_MSG_LEN];
    int off = snprintf(msg, sizeof(msg), "[%s] ", tag);
    if (off > 0 && (size_t)off < sizeof(msg)) {
        vsnprintf(msg + off, sizeof(msg) - off, fmt, ap);
    }
    int idx = g_activity_log.head % ACTIVITY_LOG_SIZE;
    memcpy(g_activity_log.messages[idx], msg, ACTIVITY_MSG_LEN - 1);
    g_activity_log.messages[idx][ACTIVITY_MSG_LEN - 1] = '\0';
    g_activity_log.head = (idx + 1) % ACTIVITY_LOG_SIZE;
    atomic_fetch_add(&g_activity_log.sequence, 1);
}

int activity_log_since(uint32_t since_seq, char *buf, size_t buf_len) {
    uint32_t cur_seq = atomic_load(&g_activity_log.sequence);
    if (cur_seq <= since_seq) return 0;

    uint32_t count = cur_seq - since_seq;
    if (count > ACTIVITY_LOG_SIZE) count = ACTIVITY_LOG_SIZE;

    int pos = 0;
    pos += snprintf(buf + pos, buf_len - pos, "[");
    for (uint32_t i = 0; i < count && (size_t)pos < buf_len - 10; i++) {
        int idx = ((int)g_activity_log.head - (int)count + (int)i + ACTIVITY_LOG_SIZE) % ACTIVITY_LOG_SIZE;
        /* JSON-escape the message inline (simple: replace " and \ and control chars) */
        if (i > 0) pos += snprintf(buf + pos, buf_len - pos, ",");
        pos += snprintf(buf + pos, buf_len - pos, "\"");
        const char *s = g_activity_log.messages[idx];
        for (; *s && (size_t)pos < buf_len - 5; s++) {
            if (*s == '"' || *s == '\\') { buf[pos++] = '\\'; buf[pos++] = *s; }
            else if ((unsigned char)*s < 0x20) { buf[pos++] = ' '; }
            else { buf[pos++] = *s; }
        }
        pos += snprintf(buf + pos, buf_len - pos, "\"");
    }
    pos += snprintf(buf + pos, buf_len - pos, "]");
    return (int)count;
}

void logmsg(const char *tag, const char *fmt, ...) {
    va_list ap, ap2;
    va_start(ap, fmt);
    va_copy(ap2, ap);
    fprintf(stderr, "[%s] ", tag);
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    fflush(stderr);
    va_end(ap);
    /* Push to activity log for web UI */
    activity_log_push(tag, fmt, ap2);
    va_end(ap2);
}

void vlogmsg(const char *tag, const char *fmt, ...) {
    if (!g_verbose) return;
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "[%s] ", tag);
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    fflush(stderr);
    va_end(ap);
}

void now_timestamp(char *out, size_t out_sz) {
    (void)out_sz;
    time_t t = time(NULL);
    struct tm tm;
    localtime_r(&t, &tm);
    snprintf(out, out_sz, "%04d-%02d-%02d %02d:%02d:%02d",
             tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
             tm.tm_hour, tm.tm_min, tm.tm_sec);
}

/* ─────────────────────────────────────────────────────────────────────────────
 * String utilities
 * ───────────────────────────────────────────────────────────────────────────── */

void normalize_str(char *s) {
    if (!s) return;
    size_t n = strlen(s), w = 0;
    int inspace = 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c == '(' || c == ')' || c == '[' || c == ']' || c == '{' || c == '}') continue;
        if (c == '.' || c == ',' || c == '!' || c == '?' || c == '\'' || c == '"' || c == '`' || c == '~' || c == '_') continue;
        if (c == '-' || c == '/' || c == '\\' || c == ':') c = ' ';
        if (c < 32) c = ' ';
        if (c == ' ') {
            if (inspace) continue;
            inspace = 1;
            s[w++] = ' ';
            continue;
        }
        inspace = 0;
        if (c >= 'A' && c <= 'Z') c = (unsigned char)(c - 'A' + 'a');
        s[w++] = (char)c;
    }
    if (w > 0 && s[w - 1] == ' ') w--;
    s[w] = 0;
}

int same_track(const TrackID *a, const TrackID *b) {
    if (!a->valid || !b->valid) return 0;
    if (a->has_isrc && b->has_isrc) return strcmp(a->isrc, b->isrc) == 0;
    char aa[256], bb[256];
    snprintf(aa, sizeof(aa), "%s", a->artist);
    normalize_str(aa);
    snprintf(bb, sizeof(bb), "%s", b->artist);
    normalize_str(bb);
    if (strcmp(aa, bb) != 0) return 0;
    snprintf(aa, sizeof(aa), "%s", a->title);
    normalize_str(aa);
    snprintf(bb, sizeof(bb), "%s", b->title);
    normalize_str(bb);
    return strcmp(aa, bb) == 0;
}

/* Transliterate common UTF-8 diacritical characters to ASCII equivalents */
static int utf8_to_ascii(const unsigned char *src, size_t *consumed) {
    unsigned char c1 = src[0];
    
    /* ASCII passthrough */
    if (c1 < 0x80) {
        *consumed = 1;
        return c1;
    }
    
    /* 2-byte UTF-8 sequences (Latin Extended characters) */
    if ((c1 & 0xE0) == 0xC0 && src[1]) {
        unsigned char c2 = src[1];
        *consumed = 2;
        
        /* C3 8x-9x range: À-ß */
        if (c1 == 0xC3) {
            /* À Á Â Ã Ä Å → a */
            if (c2 >= 0x80 && c2 <= 0x85) return 'a';
            if (c2 == 0x86) return 'a'; /* Æ → a (or could be "ae") */
            if (c2 == 0x87) return 'c'; /* Ç → c */
            /* È É Ê Ë → e */
            if (c2 >= 0x88 && c2 <= 0x8B) return 'e';
            /* Ì Í Î Ï → i */
            if (c2 >= 0x8C && c2 <= 0x8F) return 'i';
            if (c2 == 0x90) return 'd'; /* Ð → d */
            if (c2 == 0x91) return 'n'; /* Ñ → n */
            /* Ò Ó Ô Õ Ö → o */
            if (c2 >= 0x92 && c2 <= 0x96) return 'o';
            if (c2 == 0x98) return 'o'; /* Ø → o */
            /* Ù Ú Û Ü → u */
            if (c2 >= 0x99 && c2 <= 0x9C) return 'u';
            if (c2 == 0x9D) return 'y'; /* Ý → y */
            if (c2 == 0x9F) return 's'; /* ß → s */
            /* à á â ã ä å → a */
            if (c2 >= 0xA0 && c2 <= 0xA5) return 'a';
            if (c2 == 0xA6) return 'a'; /* æ → a */
            if (c2 == 0xA7) return 'c'; /* ç → c */
            /* è é ê ë → e */
            if (c2 >= 0xA8 && c2 <= 0xAB) return 'e';
            /* ì í î ï → i */
            if (c2 >= 0xAC && c2 <= 0xAF) return 'i';
            if (c2 == 0xB0) return 'd'; /* ð → d */
            if (c2 == 0xB1) return 'n'; /* ñ → n */
            /* ò ó ô õ ö → o */
            if (c2 >= 0xB2 && c2 <= 0xB6) return 'o';
            if (c2 == 0xB8) return 'o'; /* ø → o */
            /* ù ú û ü → u */
            if (c2 >= 0xB9 && c2 <= 0xBC) return 'u';
            if (c2 == 0xBD) return 'y'; /* ý → y */
            if (c2 == 0xBF) return 'y'; /* ÿ → y */
        }
        /* Skip unknown 2-byte sequences */
        return -1;
    }
    
    /* 3-byte UTF-8 sequences */
    if ((c1 & 0xF0) == 0xE0 && src[1] && src[2]) {
        *consumed = 3;
        return -1; /* Skip 3-byte chars (CJK, etc.) */
    }
    
    /* 4-byte UTF-8 sequences */
    if ((c1 & 0xF8) == 0xF0 && src[1] && src[2] && src[3]) {
        *consumed = 4;
        return -1; /* Skip 4-byte chars (emoji, etc.) */
    }
    
    /* Invalid UTF-8, skip byte */
    *consumed = 1;
    return -1;
}

/* Normalize for fuzzy matching: transliterate UTF-8, lowercase, keep alphanumeric + space */
static void normalize_for_match(const char *src, char *dst, size_t dst_sz) {
    size_t j = 0;
    const unsigned char *p = (const unsigned char *)src;
    
    while (*p && j < dst_sz - 1) {
        size_t consumed = 1;
        int c = utf8_to_ascii(p, &consumed);
        p += consumed;
        
        if (c < 0) continue; /* Skip unmapped characters */
        
        /* Lowercase */
        if (c >= 'A' && c <= 'Z') c = c - 'A' + 'a';
        
        /* Keep only alphanumeric and space */
        if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == ' ') {
            dst[j++] = (char)c;
        }
    }
    dst[j] = '\0';
}

int levenshtein_distance(const char *s1, const char *s2) {
    size_t len1 = strlen(s1), len2 = strlen(s2);
    if (len1 == 0) return (int)len2;
    if (len2 == 0) return (int)len1;
    
    /* Ensure s1 is shorter for space optimization */
    if (len1 > len2) {
        const char *tmp = s1; s1 = s2; s2 = tmp;
        size_t t = len1; len1 = len2; len2 = t;
    }
    
    /* Use single row + prev value - O(min(n,m)) space */
    int *row = malloc((len1 + 1) * sizeof(int));
    if (!row) return (int)(len1 > len2 ? len1 : len2);  /* Fallback */
    
    for (size_t i = 0; i <= len1; i++) row[i] = (int)i;
    
    for (size_t j = 1; j <= len2; j++) {
        int prev = row[0];
        row[0] = (int)j;
        for (size_t i = 1; i <= len1; i++) {
            unsigned char c1 = (unsigned char)s1[i-1];
            unsigned char c2 = (unsigned char)s2[j-1];
            /* Case-insensitive comparison */
            if (c1 >= 'A' && c1 <= 'Z') c1 = c1 - 'A' + 'a';
            if (c2 >= 'A' && c2 <= 'Z') c2 = c2 - 'A' + 'a';
            int cost = (c1 != c2) ? 1 : 0;
            int del = row[i] + 1;
            int ins = row[i-1] + 1;
            int sub = prev + cost;
            prev = row[i];
            row[i] = (del < ins) ? (del < sub ? del : sub) : (ins < sub ? ins : sub);
        }
    }
    
    int result = row[len1];
    free(row);
    return result;
}

/* Strip trailing parenthetical mix descriptors for fuzzy matching.
 * "(Original Mix)", "(12" Version)", "(Extended Mix)", "(Remix)", etc. */
static void strip_mix_suffix(char *s) {
    size_t len = strlen(s);
    /* Find last '(' */
    for (int i = (int)len - 1; i >= 0; i--) {
        if (s[i] == '(') {
            /* Check if the parenthetical looks like a mix descriptor */
            const char *suffixes[] = {
                "mix", "remix", "version", "edit", "dub", "acapella",
                "a cappella", "instrumental", "remaster", "rework",
                "bootleg", "rework", "vip", NULL
            };
            char lower[128] = {0};
            size_t k = 0;
            for (int j = i + 1; j < (int)len && k < sizeof(lower) - 1; j++)
                lower[k++] = (s[j] >= 'A' && s[j] <= 'Z') ? s[j] - 'A' + 'a' : s[j];
            lower[k] = '\0';
            for (int si = 0; suffixes[si]; si++) {
                if (strstr(lower, suffixes[si])) {
                    /* Trim at the '(' and trailing whitespace */
                    s[i] = '\0';
                    while (i > 0 && s[i-1] == ' ') s[--i] = '\0';
                    return;
                }
            }
            break; /* Only check the last parenthetical */
        }
    }
}

int str_similarity(const char *s1, const char *s2) {
    char n1[256], n2[256];
    normalize_for_match(s1, n1, sizeof(n1));
    normalize_for_match(s2, n2, sizeof(n2));
    strip_mix_suffix(n1);
    strip_mix_suffix(n2);
    
    size_t len1 = strlen(n1), len2 = strlen(n2);
    size_t max_len = len1 > len2 ? len1 : len2;
    if (max_len == 0) return 100;
    
    int dist = levenshtein_distance(n1, n2);
    return 100 - (dist * 100 / (int)max_len);
}

int str_contains(const char *haystack, const char *needle) {
    char h[256], n[256];
    normalize_for_match(haystack, h, sizeof(h));
    normalize_for_match(needle, n, sizeof(n));

    if (n[0] == '\0') return 0;  /* Empty needle */
    return strcasestr(h, n) != NULL;
}

/* Core title match: compare normalized strings by common prefix.
 * Handles "Re-Rewind (Original Mix)" vs "Re-Rewind (The Crowd Say Bo Selecta)"
 * where the base title matches but the remix/version suffix differs. */
int str_core_match(const char *s1, const char *s2) {
    char n1[256], n2[256];
    normalize_for_match(s1, n1, sizeof(n1));
    normalize_for_match(s2, n2, sizeof(n2));

    size_t len1 = strlen(n1), len2 = strlen(n2);
    size_t min_len = len1 < len2 ? len1 : len2;
    if (min_len < 3) return 0;

    /* Count matching prefix */
    size_t match = 0;
    for (size_t i = 0; i < min_len; i++) {
        if (n1[i] == n2[i]) match++;
        else break;
    }

    /* Prefix must cover at least 80% of the shorter string and be >= 5 chars */
    return match >= 5 && (match * 100 / min_len) >= 80;
}

/* Artist match with separator normalization.
 * "Artful Dodger ft. Craig David" matches "Artful Dodger & Craig David" */
int str_artist_match(const char *a1, const char *a2) {
    if (!a1 || !a2 || !a1[0] || !a2[0]) return 1; /* No artist = match */

    char n1[256], n2[256];
    normalize_for_match(a1, n1, sizeof(n1));
    normalize_for_match(a2, n2, sizeof(n2));

    /* Strip "feat", "ft" — already alphanumeric after normalize */
    char *p;
    while ((p = strstr(n1, " feat ")) != NULL)
        memmove(p + 1, p + 6, strlen(p + 6) + 1);
    while ((p = strstr(n1, " ft ")) != NULL)
        memmove(p + 1, p + 4, strlen(p + 4) + 1);
    while ((p = strstr(n2, " feat ")) != NULL)
        memmove(p + 1, p + 6, strlen(p + 6) + 1);
    while ((p = strstr(n2, " ft ")) != NULL)
        memmove(p + 1, p + 4, strlen(p + 4) + 1);

    if (strcasestr(n1, n2) || strcasestr(n2, n1)) return 1;

    size_t len1 = strlen(n1), len2 = strlen(n2);
    size_t max_len = len1 > len2 ? len1 : len2;
    if (max_len == 0) return 1;

    int dist = levenshtein_distance(n1, n2);
    return (100 - (dist * 100 / (int)max_len)) >= 50;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * Misc utilities
 * ───────────────────────────────────────────────────────────────────────────── */

void random_bytes(void *dst, size_t n) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (f) {
        fread(dst, 1, n, f);
        fclose(f);
    } else {
        for (size_t i = 0; i < n; i++)
            ((unsigned char *)dst)[i] = (unsigned char)(rand() & 0xFF);
    }
}

void uuid4(char out[37]) {
    unsigned char b[16];
    random_bytes(b, sizeof(b));
    b[6] = (b[6] & 0x0F) | 0x40;
    b[8] = (b[8] & 0x3F) | 0x80;
    snprintf(out, 37,
             "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9],
             b[10], b[11], b[12], b[13], b[14], b[15]);
}

/* ─────────────────────────────────────────────────────────────────────────────
 * UTF-8 utilities
 * ───────────────────────────────────────────────────────────────────────────── */

void utf8_safe_copy(char *dst, const char *src, size_t dst_sz) {
    if (!dst || !src || dst_sz == 0) return;
    
    size_t src_len = strlen(src);
    size_t copy_len = (src_len < dst_sz - 1) ? src_len : dst_sz - 1;
    
    /* Walk back to find valid UTF-8 boundary */
    while (copy_len > 0 && (src[copy_len] & 0xC0) == 0x80) {
        copy_len--;
    }
    /* Check if we're in the middle of a multi-byte sequence */
    if (copy_len > 0) {
        unsigned char c = (unsigned char)src[copy_len - 1];
        /* If previous byte starts a multi-byte seq that extends past copy_len */
        if ((c & 0xE0) == 0xC0 && copy_len < src_len) {
            /* 2-byte seq needs 1 more byte */
            if (copy_len + 1 > src_len || (src[copy_len] & 0xC0) != 0x80) copy_len--;
        } else if ((c & 0xF0) == 0xE0 && copy_len + 1 < src_len) {
            /* 3-byte seq, check if complete */
            copy_len--;
        } else if ((c & 0xF8) == 0xF0 && copy_len + 2 < src_len) {
            /* 4-byte seq, check if complete */
            copy_len--;
        }
    }
    
    memcpy(dst, src, copy_len);
    dst[copy_len] = '\0';
}

void json_escape(const char *in, char *out, size_t out_max) {
    if (!in || !out || out_max == 0) return;
    
    size_t j = 0;
    for (size_t i = 0; in[i] && j < out_max - 2; i++) {
        unsigned char c = (unsigned char)in[i];
        
        /* Escape special JSON characters */
        if (c == '"' || c == '\\') {
            if (j + 2 >= out_max) break;
            out[j++] = '\\';
            out[j++] = c;
        } else if (c == '\n') {
            if (j + 2 >= out_max) break;
            out[j++] = '\\';
            out[j++] = 'n';
        } else if (c == '\r') {
            if (j + 2 >= out_max) break;
            out[j++] = '\\';
            out[j++] = 'r';
        } else if (c == '\t') {
            if (j + 2 >= out_max) break;
            out[j++] = '\\';
            out[j++] = 't';
        } else if (c < 0x20) {
            /* Other control chars - encode as \uXXXX */
            if (j + 6 >= out_max) break;
            j += snprintf(out + j, out_max - j, "\\u%04x", c);
        } else {
            out[j++] = c;
        }
    }
    out[j] = '\0';
}

/* Helper to encode a Unicode codepoint as UTF-8 */
static size_t encode_utf8(uint32_t cp, char *out, size_t out_max) {
    if (cp < 0x80) {
        if (out_max < 1) return 0;
        if (cp >= 0x20) { out[0] = (char)cp; return 1; }
        return 0;  /* Skip control chars */
    } else if (cp < 0x800) {
        if (out_max < 2) return 0;
        out[0] = 0xC0 | (cp >> 6);
        out[1] = 0x80 | (cp & 0x3F);
        return 2;
    } else if (cp < 0x10000) {
        if (out_max < 3) return 0;
        out[0] = 0xE0 | (cp >> 12);
        out[1] = 0x80 | ((cp >> 6) & 0x3F);
        out[2] = 0x80 | (cp & 0x3F);
        return 3;
    } else if (cp < 0x110000) {
        if (out_max < 4) return 0;
        out[0] = 0xF0 | (cp >> 18);
        out[1] = 0x80 | ((cp >> 12) & 0x3F);
        out[2] = 0x80 | ((cp >> 6) & 0x3F);
        out[3] = 0x80 | (cp & 0x3F);
        return 4;
    }
    return 0;  /* Invalid codepoint */
}

size_t utf16le_to_utf8(const uint8_t *data, size_t byte_len, char *out, size_t out_max) {
    size_t out_pos = 0;
    
    for (size_t i = 0; i + 1 < byte_len && out_pos < out_max - 4; i += 2) {
        uint16_t cp = data[i] | (data[i + 1] << 8);  /* Little-endian */
        
        if (cp == 0) break;
        
        /* Check for surrogate pair (emoji, rare CJK, etc.) */
        if (cp >= 0xD800 && cp <= 0xDBFF && i + 3 < byte_len) {
            uint16_t low = data[i + 2] | (data[i + 3] << 8);
            if (low >= 0xDC00 && low <= 0xDFFF) {
                /* Valid surrogate pair - decode to full codepoint */
                uint32_t full = 0x10000 + ((cp - 0xD800) << 10) + (low - 0xDC00);
                out_pos += encode_utf8(full, out + out_pos, out_max - out_pos);
                i += 2;  /* Skip low surrogate */
                continue;
            }
        }
        
        out_pos += encode_utf8(cp, out + out_pos, out_max - out_pos);
    }
    
    out[out_pos] = '\0';
    return out_pos;
}

size_t utf16be_to_utf8(const uint8_t *data, size_t byte_len, char *out, size_t out_max) {
    size_t out_pos = 0;
    
    for (size_t i = 0; i + 1 < byte_len && out_pos < out_max - 4; i += 2) {
        uint16_t cp = (data[i] << 8) | data[i + 1];  /* Big-endian */
        
        if (cp == 0) break;
        
        /* Check for surrogate pair (emoji, rare CJK, etc.) */
        if (cp >= 0xD800 && cp <= 0xDBFF && i + 3 < byte_len) {
            uint16_t low = (data[i + 2] << 8) | data[i + 3];
            if (low >= 0xDC00 && low <= 0xDFFF) {
                /* Valid surrogate pair - decode to full codepoint */
                uint32_t full = 0x10000 + ((cp - 0xD800) << 10) + (low - 0xDC00);
                out_pos += encode_utf8(full, out + out_pos, out_max - out_pos);
                i += 2;  /* Skip low surrogate */
                continue;
            }
        }
        
        out_pos += encode_utf8(cp, out + out_pos, out_max - out_pos);
    }
    
    out[out_pos] = '\0';
    return out_pos;
}

size_t latin1_to_utf8(const uint8_t *data, size_t len, char *out, size_t out_max) {
    size_t out_pos = 0;
    
    for (size_t i = 0; i < len && out_pos < out_max - 2; i++) {
        uint8_t c = data[i];
        
        if (c == 0) break;
        
        if (c < 0x80) {
            /* ASCII - copy directly (skip control chars except space) */
            if (c >= 0x20) out[out_pos++] = c;
        } else {
            /* Latin-1 extended (0x80-0xFF) -> 2-byte UTF-8 */
            if (out_pos + 2 >= out_max) break;
            out[out_pos++] = 0xC0 | (c >> 6);
            out[out_pos++] = 0x80 | (c & 0x3F);
        }
    }
    
    out[out_pos] = '\0';
    return out_pos;
}
