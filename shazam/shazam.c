/*
 * shazam.c - Shazam API communication
 */
#include "shazam.h"
#include "../common.h"

#include <curl/curl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ─────────────────────────────────────────────────────────────────────────────
 * CURL helpers
 * ───────────────────────────────────────────────────────────────────────────── */

struct Buf {
    char *s;
    size_t n;
    size_t cap;
    int owned; /* owned=1 if we allocated s */
};

static size_t curl_write_cb(void *ptr, size_t size, size_t nmemb, void *userdata) {
    size_t realsize = size * nmemb;
    struct Buf *b = (struct Buf *)userdata;
    if (b->n + realsize + 1 > b->cap) {
        if (!b->owned) {
            /* Fixed buffer, truncate */
            if (b->n < b->cap - 1) {
                size_t space = b->cap - 1 - b->n;
                memcpy(b->s + b->n, ptr, space);
                b->n += space;
                b->s[b->n] = 0;
            }
            return realsize; /* pretend success to avoid curl error */
        }
        size_t newcap = (b->cap ? b->cap * 2 : 4096);
        while (newcap < b->n + realsize + 1) newcap *= 2;
        char *ns = (char *)realloc(b->s, newcap);
        if (!ns) return 0;
        b->s = ns;
        b->cap = newcap;
    }
    memcpy(b->s + b->n, ptr, realsize);
    b->n += realsize;
    b->s[b->n] = 0;
    return realsize;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * JSON extraction (simple pattern matching)
 * ───────────────────────────────────────────────────────────────────────────── */

void json_extract_field(const char *j, const char *key, char *out, size_t out_sz) {
    if (!j || !key || !out || out_sz == 0) return;
    out[0] = 0;
    char pat[128];
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char *k = strstr(j, pat);
    if (!k) return;
    const char *q = strchr(k + strlen(pat), ':');
    if (!q) return;
    q++;
    while (*q == ' ' || *q == '\t') q++;
    if (*q == '\"') {
        const char *q2 = q + 1;
        while (*q2) {
            if (*q2 == '\"' && *(q2 - 1) != '\\') break;
            q2++;
        }
        if (!*q2) return;
        size_t n = (size_t)(q2 - (q + 1));
        if (n >= out_sz) n = out_sz - 1;
        memcpy(out, q + 1, n);
        out[n] = 0;
    } else {
        const char *q2 = q;
        while (*q2 && *q2 != ',' && *q2 != '}' && (size_t)(q2 - q) < out_sz - 1) q2++;
        size_t n = (size_t)(q2 - q);
        memcpy(out, q, n);
        out[n] = 0;
    }
}

/* ─────────────────────────────────────────────────────────────────────────────
 * Shazam request building
 * ───────────────────────────────────────────────────────────────────────────── */

void build_shazam_request(const char *uri, unsigned sample_ms,
                          const char *timezone_opt,
                          char url_out[512], char *body_out, size_t body_sz) {
    char u1[37], u2[37];
    uuid4(u1);
    uuid4(u2);
    snprintf(url_out, 512,
             "https://amp.shazam.com/discovery/v5/fr/FR/android/-/tag/%s/%s"
             "?sync=true&webv3=true&sampling=true&connected=&shazamapiversion=v3&sharehub=true&video=v3",
             u1, u2);
    double r1 = (double)rand() / (double)RAND_MAX;
    double r2 = (double)rand() / (double)RAND_MAX;
    double r3 = (double)rand() / (double)RAND_MAX;
    double fuzz = r1 * 15.3 - 7.65;
    double altitude = r2 * 400.0 + 100.0 + fuzz;
    double latitude = r3 * 180.0 - 90.0 + fuzz;
    double longitude = ((double)rand() / (double)RAND_MAX) * 360.0 - 180.0 + fuzz;

    const char *tz = timezone_opt && *timezone_opt ? timezone_opt : "Europe/Amsterdam";
    unsigned long long now_ms = (unsigned long long)time(NULL) * 1000ULL;

    snprintf(body_out, body_sz,
             "{"
             "\"geolocation\":{"
             "\"altitude\":%.3f,"
             "\"latitude\":%.6f,"
             "\"longitude\":%.6f"
             "},"
             "\"signature\":{"
             "\"samplems\":%u,"
             "\"timestamp\":%llu,"
             "\"uri\":\"%s\""
             "},"
             "\"timestamp\":%llu,"
             "\"timezone\":\"%s\""
             "}",
             altitude, latitude, longitude,
             sample_ms, now_ms, uri ? uri : "",
             now_ms, tz);
}

/* ─────────────────────────────────────────────────────────────────────────────
 * Shazam POST
 * ───────────────────────────────────────────────────────────────────────────── */

int shazam_post(const char *url, const char *user_agent, const char *json_body,
                char *response_buf, size_t response_sz) {
    CURL *curl = curl_easy_init();
    if (!curl) return -1;
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Accept-Encoding: gzip, deflate, br");
    headers = curl_slist_append(headers, "Accept: */*");
    headers = curl_slist_append(headers, "Connection: keep-alive");
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, "Content-Language: en_US");

    struct Buf buf = {.s = response_buf, .n = 0, .cap = response_sz, .owned = 0};

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, user_agent && *user_agent
                                                  ? user_agent
                                                  : "Dalvik/2.1.0 (Linux; U; Android 5.0; Nexus Build/LRX21M)");
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_body ? json_body : "");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buf);
    curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "gzip, deflate, br");
    curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);

    CURLcode res = curl_easy_perform(curl);
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        logmsg("curl", "perform failed: %s (code %d)", curl_easy_strerror(res), (int)res);
        return -1;
    }
    if (http_code != 200) {
        logmsg("curl", "HTTP %ld", http_code);
        return -1;
    }

    return (buf.n > 0) ? 0 : -1;
}
