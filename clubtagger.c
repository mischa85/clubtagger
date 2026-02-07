#ifdef HAVE_ALSA
#include <alsa/asoundlib.h>
#endif
#include <curl/curl.h>
#include <errno.h>
#include <inttypes.h>
#include <math.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <pcap.h>
#include <sqlite3.h>

typedef struct Fingerprint Fingerprint;
extern Fingerprint *vibra_get_fingerprint_from_signed_pcm(const char *raw_pcm, int pcm_data_size,
                                                          int sample_rate, int sample_width_bits,
                                                          int channel_count);
extern const char *vibra_get_uri_from_fingerprint(Fingerprint *fingerprint);
extern unsigned int vibra_get_sample_ms_from_fingerprint(Fingerprint *fingerprint);
extern void vibra_free_fingerprint(Fingerprint *fingerprint);

static volatile sig_atomic_t g_running = 1;
static int g_verbose = 0;

static void logmsg(const char *tag, const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    fprintf(stderr, "[%s] ", tag);
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    fflush(stderr);
    va_end(ap);
}
static void vlogmsg(const char *tag, const char *fmt, ...) {
    if (!g_verbose) return;
    va_list ap; va_start(ap, fmt);
    fprintf(stderr, "[%s] ", tag);
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    fflush(stderr);
    va_end(ap);
}

static void now_timestamp(char *out, size_t out_sz) {
    (void)out_sz;
    time_t t = time(NULL);
    struct tm tm; localtime_r(&t, &tm);
    snprintf(out, out_sz, "%04d-%02d-%02d %02d:%02d:%02d",
             tm.tm_year+1900, tm.tm_mon+1, tm.tm_mday,
             tm.tm_hour, tm.tm_min, tm.tm_sec);
}

typedef struct {
    char isrc[64];
    char artist[256];
    char title[256];
    time_t t;
    int valid;
} Vote;

typedef struct {
    char isrc[64];
    char artist[256];
    char title[256];
    int has_isrc;
    int valid;
} TrackID;

static void normalize_str(char *s) {
    if (!s) return;
    size_t n = strlen(s), w = 0; int inspace = 0;
    for (size_t i=0;i<n;i++) {
        unsigned char c = (unsigned char)s[i];
        if (c=='(' || c==')' || c=='[' || c==']' || c=='{' || c=='}') continue;
        if (c=='.' || c==',' || c=='!' || c=='?' || c=='\'' || c=='"' || c=='`' || c=='~' || c=='_') continue;
        if (c=='-' || c=='/' || c=='\\' || c==':') c=' ';
        if (c<32) c=' ';
        if (c==' ') { if (inspace) continue; inspace=1; s[w++]=' '; continue; }
        inspace=0;
        if (c>='A' && c<='Z') c = (unsigned char)(c - 'A' + 'a');
        s[w++] = (char)c;
    }
    if (w>0 && s[w-1]==' ') w--;
    s[w]=0;
}
static int same_track(const TrackID *a, const TrackID *b) {
    if (!a->valid || !b->valid) return 0;
    if (a->has_isrc && b->has_isrc) return strcmp(a->isrc,b->isrc)==0;
    char aa[256], bb[256];
    snprintf(aa, sizeof(aa), "%s", a->artist); normalize_str(aa);
    snprintf(bb, sizeof(bb), "%s", b->artist); normalize_str(bb);
    if (strcmp(aa,bb)!=0) return 0;
    snprintf(aa, sizeof(aa), "%s", a->title); normalize_str(aa);
    snprintf(bb, sizeof(bb), "%s", b->title); normalize_str(bb);
    return strcmp(aa,bb)==0;
}
static TrackID majority_vote(Vote v[5]) {
    TrackID r = {0};
    TrackID tracks[5] = {0};
    for (int i = 0; i < 5; i++) {
        if (v[i].valid) {
            tracks[i].valid = 1;
            snprintf(tracks[i].isrc, sizeof(tracks[i].isrc), "%s", v[i].isrc);
            snprintf(tracks[i].artist, sizeof(tracks[i].artist), "%s", v[i].artist);
            snprintf(tracks[i].title, sizeof(tracks[i].title), "%s", v[i].title);
            tracks[i].has_isrc = tracks[i].isrc[0] != 0;
        }
    }
    /* Count matches for each track, require 3 matching */
    for (int i = 0; i < 5; i++) {
        if (!tracks[i].valid) continue;
        int count = 1;
        for (int j = i + 1; j < 5; j++) {
            if (same_track(&tracks[i], &tracks[j])) count++;
        }
        if (count >= 3) return tracks[i];
    }
    return r;
}

typedef struct {
    const char *device;
    unsigned    rate;
    unsigned    channels;
    unsigned    frames_per_read;
    unsigned    ring_sec;
    unsigned    fingerprint_sec;
    unsigned    min_rms;
    unsigned    identify_interval_sec;
    const char *user_agent;
    const char *timezone;
    unsigned    shazam_gap_sec;
    unsigned    same_track_hold_sec;
    unsigned    threshold;
    float       sustain_sec;
    unsigned    prebuffer_sec;
    float       silence_sec;
    const char *prefix;
    const char *source;        /* "alsa" or "slink" */
    int         bytes_per_sample;  /* 2 for 16-bit, 3 for 24-bit */
    int         source_big_endian; /* 1 if source is big-endian (slink), 0 for little-endian (alsa) */
    unsigned    max_file_sec;      /* max seconds per WAV file (0 = no limit) */
    const char *db_path;       /* SQLite database path for track logging */
} Config;

typedef struct {
    uint8_t        *data;
    size_t          frames_capacity;
    size_t          channels;
    int             bytes_per_sample;
    size_t          frame_bytes;     /* channels * bytes_per_sample */
    size_t          write_pos;
    size_t          read_pos;
    size_t          total_written;
    pthread_mutex_t mu;
} Ring;

static int ring_init(Ring *r, size_t frames_capacity, size_t channels, int bytes_per_sample) {
    r->bytes_per_sample = bytes_per_sample;
    r->frame_bytes = channels * bytes_per_sample;
    r->data = (uint8_t*)calloc(frames_capacity, r->frame_bytes);
    if (!r->data) return -1;
    r->frames_capacity = frames_capacity;
    r->channels = channels;
    r->write_pos = 0;
    r->read_pos  = 0;
    r->total_written = 0;
    pthread_mutex_init(&r->mu, NULL);
    return 0;
}
static void ring_free(Ring *r) {
    if (r->data) free(r->data);
    pthread_mutex_destroy(&r->mu);
}
static void ring_write(Ring *r, const void *frames, size_t nframes) {
    pthread_mutex_lock(&r->mu);
    const size_t fb = r->frame_bytes;
    const uint8_t *src = (const uint8_t*)frames;
    size_t wp = r->write_pos;
    for (size_t i=0; i<nframes; ++i) {
        size_t idx = (wp % r->frames_capacity) * fb;
        memcpy(&r->data[idx], &src[i * fb], fb);
        wp = (wp + 1) % r->frames_capacity;
        if (wp == r->read_pos) r->read_pos = (r->read_pos + 1) % r->frames_capacity;
    }
    r->write_pos = wp;
    r->total_written += nframes;
    pthread_mutex_unlock(&r->mu);
}
static size_t ring_available_locked(const Ring *r) {
    if (r->write_pos >= r->read_pos) return r->write_pos - r->read_pos;
    return r->frames_capacity - (r->read_pos - r->write_pos);
}
static size_t ring_read(Ring *r, void *dst, size_t max_frames) {
    pthread_mutex_lock(&r->mu);
    size_t avail = ring_available_locked(r);
    if (avail == 0) { pthread_mutex_unlock(&r->mu); return 0; }
    size_t take = (avail < max_frames) ? avail : max_frames;
    const size_t fb = r->frame_bytes;
    uint8_t *d = (uint8_t*)dst;
    for (size_t i=0; i<take; ++i) {
        size_t idx = (r->read_pos % r->frames_capacity) * fb;
        memcpy(&d[i * fb], &r->data[idx], fb);
        r->read_pos = (r->read_pos + 1) % r->frames_capacity;
    }
    pthread_mutex_unlock(&r->mu);
    return take;
}
static size_t ring_copy_last(Ring *r, void *dst, size_t nframes) {
    pthread_mutex_lock(&r->mu);
    const size_t cap = r->frames_capacity;
    const size_t fb  = r->frame_bytes;
    size_t have = (r->total_written < cap) ? r->total_written : cap;
    size_t take = (have < nframes) ? have : nframes;
    if (take > cap) take = cap;  /* safety: never exceed buffer capacity */
    size_t start;
    if (r->write_pos >= take) {
        start = r->write_pos - take;
    } else {
        start = cap - (take - r->write_pos);
    }
    uint8_t *d = (uint8_t*)dst;
    for (size_t i=0; i<take; ++i) {
        size_t idx = ((start + i) % cap) * fb;
        memcpy(&d[i * fb], &r->data[idx], fb);
    }
    pthread_mutex_unlock(&r->mu);
    return take;
}

static unsigned rms_s16_interleaved(const int16_t *x, size_t frames, size_t channels) {
    if (!frames || !channels) return 0;
    const size_t N = frames * channels;
    double acc = 0.0;
    for (size_t i=0; i<N; ++i) { double s = (double)x[i]; acc += s * s; }
    double r = sqrt(acc / (double)N);
    if (r > 32767.0) r = 32767.0;
    return (unsigned)(r + 0.5);
}
static unsigned avg_abs_s16(const int16_t *x, size_t frames, size_t channels) {
    if (!frames || !channels) return 0;
    const size_t N = frames * channels;
    unsigned long long acc = 0;
    for (size_t i=0; i<N; ++i) acc += (unsigned)(x[i] < 0 ? -x[i] : x[i]);
    return (unsigned)(acc / N);
}

/* Analyze samples: returns avg absolute value, and optionally peak value */
static unsigned analyze_samples(const void *data, size_t frames, size_t channels, int bytes_per_sample, int source_big_endian, unsigned *peak_out) {
    if (!frames || !channels) { if (peak_out) *peak_out = 0; return 0; }
    const size_t N = frames * channels;
    unsigned long long acc = 0;
    unsigned peak = 0;
    
    if (bytes_per_sample == 2) {
        const int16_t *s16 = (const int16_t*)data;
        for (size_t i=0; i<N; ++i) {
            unsigned v = (unsigned)(s16[i] < 0 ? -s16[i] : s16[i]);
            acc += v;
            if (v > peak) peak = v;
        }
    } else if (bytes_per_sample == 3) {
        const uint8_t *p = (const uint8_t*)data;
        for (size_t i=0; i<N; ++i) {
            int32_t s;
            if (source_big_endian) {
                s = ((int32_t)p[i*3] << 16) | ((int32_t)p[i*3+1] << 8) | (int32_t)p[i*3+2];
            } else {
                s = ((int32_t)p[i*3+2] << 16) | ((int32_t)p[i*3+1] << 8) | (int32_t)p[i*3];
            }
            if (s & 0x800000) s |= 0xFF000000;
            int16_t s16 = (int16_t)(s >> 8);
            unsigned v = (unsigned)(s16 < 0 ? -s16 : s16);
            acc += v;
            if (v > peak) peak = v;
        }
    }
    if (peak_out) *peak_out = peak;
    return (unsigned)(acc / N);
}

/* Write samples to WAV file, optionally swapping bytes for big-endian 24-bit sources */
static void wav_write_samples(FILE *fp, const uint8_t *data, size_t frames, size_t channels, int bytes_per_sample, int source_big_endian) {
    if (bytes_per_sample == 2) {
        fwrite(data, channels * 2, frames, fp);
    } else if (bytes_per_sample == 3) {
        if (source_big_endian) {
            /* SLink is big-endian, WAV needs little-endian - swap byte order */
            for (size_t i = 0; i < frames * channels; ++i) {
                uint8_t le[3];
                le[0] = data[i*3 + 2];  /* LSB */
                le[1] = data[i*3 + 1];  /* middle */
                le[2] = data[i*3 + 0];  /* MSB */
                fwrite(le, 3, 1, fp);
            }
        } else {
            /* ALSA S24_3LE is already little-endian */
            fwrite(data, channels * 3, frames, fp);
        }
    }
}

static void random_bytes(void *dst, size_t n) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (f) { fread(dst, 1, n, f); fclose(f); }
    else { for (size_t i=0;i<n;i++) ((unsigned char*)dst)[i] = (unsigned char)(rand() & 0xFF); }
}
static void uuid4(char out[37]) {
    unsigned char b[16];
    random_bytes(b, sizeof(b));
    b[6] = (b[6] & 0x0F) | 0x40;
    b[8] = (b[8] & 0x3F) | 0x80;
    snprintf(out, 37,
             "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             b[0],b[1],b[2],b[3], b[4],b[5], b[6],b[7], b[8],b[9],
             b[10],b[11],b[12],b[13],b[14],b[15]);
}

struct Buf { char *s; size_t n; size_t cap; };
static size_t curl_write_cb(void *ptr, size_t size, size_t nmemb, void *userdata) {
    size_t realsize = size * nmemb;
    struct Buf *b = (struct Buf*)userdata;
    if (b->n + realsize + 1 > b->cap) {
        size_t newcap = (b->cap ? b->cap * 2 : 4096);
        while (newcap < b->n + realsize + 1) newcap *= 2;
        char *ns = (char*)realloc(b->s, newcap);
        if (!ns) return 0;
        b->s = ns; b->cap = newcap;
    }
    memcpy(b->s + b->n, ptr, realsize);
    b->n += realsize;
    b->s[b->n] = 0;
    return realsize;
}
static void json_extract_field(const char *j, const char *key, char *out, size_t out_sz) {
    if (!j || !key || !out || out_sz == 0) return;
    out[0] = 0;
    char pat[128];
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char *k = strstr(j, pat);
    if (!k) return;
    const char *q = strchr(k + strlen(pat), ':');
    if (!q) return;
    q++;
    while (*q==' '||*q=='\t') q++;
    if (*q=='\"') {
        const char *q2 = q+1;
        while (*q2) { if (*q2=='\"' && *(q2-1)!='\\') break; q2++; }
        if (!*q2) return;
        size_t n = (size_t)(q2 - (q+1));
        if (n >= out_sz) n = out_sz-1;
        memcpy(out, q+1, n);
        out[n] = 0;
    } else {
        const char *q2 = q;
        while (*q2 && *q2!=',' && *q2!='}' && (size_t)(q2-q)<out_sz-1) q2++;
        size_t n = (size_t)(q2 - q);
        memcpy(out, q, n);
        out[n] = 0;
    }
}

static void build_shazam_request(const char *uri, unsigned sample_ms,
                                 const char *timezone_opt,
                                 char url_out[512], char **json_body_out) {
    char u1[37], u2[37]; uuid4(u1); uuid4(u2);
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
    double longitude = ((double)rand()/(double)RAND_MAX) * 360.0 - 180.0 + fuzz;

    const char *tz = timezone_opt && *timezone_opt ? timezone_opt : "Europe/Amsterdam";
    unsigned long long now_ms = (unsigned long long)time(NULL) * 1000ULL;

    char *buf = (char*)malloc(1024 + (uri ? strlen(uri) : 0));
    if (!buf) { *json_body_out = NULL; return; }
    int n = snprintf(buf, 1024 + (uri ? (int)strlen(uri) : 0),
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
        now_ms, tz
    );
    if (n < 0) { free(buf); buf = NULL; }
    *json_body_out = buf;
}

static char *shazam_post(const char *url, const char *user_agent, const char *json_body) {
    CURL *curl = curl_easy_init();
    if (!curl) return NULL;
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Accept-Encoding: gzip, deflate, br");
    headers = curl_slist_append(headers, "Accept: */*");
    headers = curl_slist_append(headers, "Connection: keep-alive");
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, "Content-Language: en_US");

    struct Buf buf = {0};

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

    if (res != CURLE_OK) logmsg("curl","perform failed: %s", curl_easy_strerror(res));
    if (http_code != 200) logmsg("curl","HTTP %ld", http_code);

    if (buf.s && buf.n > 0) return buf.s;
    free(buf.s);
    return NULL;
}

static void le16_write(uint16_t v, FILE *f){ uint8_t b[2]={v&0xff,(v>>8)&0xff}; fwrite(b,1,2,f); }
static void le32_write(uint32_t v, FILE *f){ uint8_t b[4]={v&0xff,(v>>8)&0xff,(v>>16)&0xff,(v>>24)&0xff}; fwrite(b,1,4,f); }

typedef struct { FILE *fp; char tmp_name[512]; } WavFile;
static void build_wav_name(char *out, size_t out_sz, const char *prefix, time_t ts) {
    struct tm tm; localtime_r(&ts, &tm);
    snprintf(out, out_sz, "%s_%04d%02d%02d_%02d%02d%02d.wav",
             prefix, tm.tm_year+1900, tm.tm_mon+1, tm.tm_mday,
             tm.tm_hour, tm.tm_min, tm.tm_sec);
}

static int wav_open_at(WavFile *wf, const char *prefix, unsigned channels, unsigned rate, time_t ts) {
    (void)channels; (void)rate;
    char final[512]; build_wav_name(final, sizeof(final), prefix, ts);

    snprintf(wf->tmp_name, sizeof(wf->tmp_name), "%s", final);
    size_t len = strlen(wf->tmp_name);
    if (len + 5 < sizeof(wf->tmp_name)) { memcpy(wf->tmp_name + len, ".part", 6); }
    else { wf->tmp_name[sizeof(wf->tmp_name)-1] = '\0'; }

    wf->fp = fopen(wf->tmp_name, "wb");
    if (!wf->fp) { logmsg("wav","open %s: %s", wf->tmp_name, strerror(errno)); return -1; }
    uint8_t zero[44] = {0};
    if (fwrite(zero,1,44,wf->fp)!=44){ logmsg("wav","header write failed"); fclose(wf->fp); wf->fp=NULL; return -1; }
    logmsg("wav","opened %s", final);
    return 0;
}

static int wav_finalize(WavFile *wf, unsigned channels, unsigned rate, unsigned bits_per_sample) {
    if (!wf->fp) return 0;
    long file_size = ftell(wf->fp);
    if (file_size < 44) { fclose(wf->fp); wf->fp=NULL; unlink(wf->tmp_name); return -1; }

    uint32_t data_bytes = (uint32_t)(file_size - 44);
    uint16_t audio_format = 1;
    uint16_t num_channels = (uint16_t)channels;
    uint32_t sample_rate  = rate;
    uint16_t block_align = num_channels * (bits_per_sample/8);
    uint32_t byte_rate = sample_rate * block_align;

    fseek(wf->fp, 0, SEEK_SET);
    fwrite("RIFF",1,4,wf->fp);
    le32_write(36 + data_bytes, wf->fp);
    fwrite("WAVE",1,4,wf->fp);
    fwrite("fmt ",1,4,wf->fp);
    le32_write(16, wf->fp);
    le16_write(audio_format, wf->fp);
    le16_write(num_channels, wf->fp);
    le32_write(sample_rate,  wf->fp);
    le32_write(byte_rate,    wf->fp);
    le16_write(block_align,  wf->fp);
    le16_write((uint16_t)bits_per_sample, wf->fp);
    fwrite("data",1,4,wf->fp);
    le32_write(data_bytes, wf->fp);

    fflush(wf->fp);
    int fd = fileno(wf->fp); if (fd>=0) fsync(fd);
    fclose(wf->fp); wf->fp=NULL;

    char final_name[512]; snprintf(final_name, sizeof(final_name), "%s", wf->tmp_name);
    size_t n = strlen(final_name); if (n>5) final_name[n-5]='\0';
    if (rename(wf->tmp_name, final_name)!=0) {
        logmsg("wav","rename -> %s failed: %s", final_name, strerror(errno));
        return -1;
    }
    logmsg("wav","finalized data=%u bytes", data_bytes);
    return 0;
}

typedef struct {
    Config    cfg;
    Ring      ring;
    pthread_t th_cap;
    pthread_t th_id;
    pthread_t th_wrt;
    sqlite3  *db;
    pthread_mutex_t db_mu;
    char      current_wav[512];  /* current WAV file being recorded */
} App;

/* ─────────────────────────────────────────────────────────────────────────────
 * SQLite database for track logging
 * ───────────────────────────────────────────────────────────────────────────── */
static int db_init(App *app) {
    if (!app->cfg.db_path) return 0;  /* no database configured */
    
    pthread_mutex_init(&app->db_mu, NULL);
    
    int rc = sqlite3_open(app->cfg.db_path, &app->db);
    if (rc != SQLITE_OK) {
        logmsg("db", "failed to open %s: %s", app->cfg.db_path, sqlite3_errmsg(app->db));
        return -1;
    }
    
    const char *sql = 
        "CREATE TABLE IF NOT EXISTS plays ("
        "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  timestamp TEXT NOT NULL,"
        "  artist TEXT,"
        "  title TEXT,"
        "  isrc TEXT,"
        "  wav_file TEXT,"
        "  quality TEXT"
        ");"
        "CREATE INDEX IF NOT EXISTS idx_plays_timestamp ON plays(timestamp);"
        "CREATE INDEX IF NOT EXISTS idx_plays_isrc ON plays(isrc);";
    
    char *errmsg = NULL;
    rc = sqlite3_exec(app->db, sql, NULL, NULL, &errmsg);
    if (rc != SQLITE_OK) {
        logmsg("db", "failed to create tables: %s", errmsg);
        sqlite3_free(errmsg);
        sqlite3_close(app->db);
        app->db = NULL;
        return -1;
    }
    
    logmsg("db", "opened %s", app->cfg.db_path);
    return 0;
}

static void db_close(App *app) {
    if (app->db) {
        sqlite3_close(app->db);
        app->db = NULL;
        pthread_mutex_destroy(&app->db_mu);
    }
}

static void db_insert_play(App *app, const char *timestamp, const char *artist, 
                           const char *title, const char *isrc, const char *quality) {
    if (!app->db) return;
    
    pthread_mutex_lock(&app->db_mu);
    
    const char *sql = "INSERT INTO plays (timestamp, artist, title, isrc, wav_file, quality) "
                      "VALUES (?, ?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(app->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        logmsg("db", "prepare failed: %s", sqlite3_errmsg(app->db));
        pthread_mutex_unlock(&app->db_mu);
        return;
    }
    
    sqlite3_bind_text(stmt, 1, timestamp, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, artist, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, title, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, isrc[0] ? isrc : NULL, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 5, app->current_wav[0] ? app->current_wav : NULL, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 6, quality, -1, SQLITE_STATIC);
    
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        logmsg("db", "insert failed: %s", sqlite3_errmsg(app->db));
    }
    
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&app->db_mu);
}

static void *capture_slink(void *arg) {
    App *app = (App*)arg;
    Config *cfg = &app->cfg;
    
    vlogmsg("cap","opening SLink on %s", cfg->device);
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(cfg->device, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        logmsg("cap","pcap_open_live %s: %s", cfg->device, errbuf);
        g_running = 0;
        return NULL;
    }

    logmsg("cap","started: rate=%u ch=%u (SLink source, 24-bit)", cfg->rate, cfg->channels);

    const size_t fb = cfg->channels * cfg->bytes_per_sample;
    uint8_t *buf = (uint8_t*)malloc(cfg->frames_per_read * fb);
    if (!buf) { 
        logmsg("cap","oom"); 
        pcap_close(handle); 
        g_running=0; 
        return NULL; 
    }

    struct pcap_pkthdr hdr;
    const u_char *pkt;
    uint32_t buf_idx = 0;

    while (g_running) {
        pkt = pcap_next(handle, &hdr);
        if (!pkt) continue;

        if (hdr.caplen >= 30 && pkt[12] == 0x04 && pkt[13] == 0xee) {
            /* Store 24-bit samples directly (3 bytes per channel) */
            memcpy(&buf[buf_idx * fb + 0], &pkt[24], 3);  /* Ch 0 */
            memcpy(&buf[buf_idx * fb + 3], &pkt[27], 3);  /* Ch 1 */

            buf_idx++;
            if (buf_idx >= cfg->frames_per_read) {
                ring_write(&app->ring, buf, cfg->frames_per_read);
                buf_idx = 0;
            }
        }
    }

    free(buf);
    pcap_close(handle);
    logmsg("cap","exit");
    return NULL;
}

static void *capture_main(void *arg) {
    App *app = (App*)arg;
    Config *cfg = &app->cfg;

    if (cfg->source && !strcmp(cfg->source, "slink")) {
        return capture_slink(arg);
    }

#ifdef HAVE_ALSA
    vlogmsg("cap","opening ALSA on %s", cfg->device);
    snd_pcm_t *pcm = NULL;
    int err = snd_pcm_open(&pcm, cfg->device, SND_PCM_STREAM_CAPTURE, 0);
    if (err < 0) { logmsg("cap","open %s: %s", cfg->device, snd_strerror(err)); g_running=0; return NULL; }

    snd_pcm_hw_params_t *p = NULL;
    snd_pcm_hw_params_malloc(&p);
    snd_pcm_hw_params_any(pcm, p);
    snd_pcm_hw_params_set_access(pcm, p, SND_PCM_ACCESS_RW_INTERLEAVED);
    snd_pcm_format_t fmt = (cfg->bytes_per_sample == 3) ? SND_PCM_FORMAT_S24_3LE : SND_PCM_FORMAT_S16_LE;
    snd_pcm_hw_params_set_format(pcm, p, fmt);
    snd_pcm_hw_params_set_channels(pcm, p, cfg->channels);
    unsigned rate = cfg->rate; snd_pcm_hw_params_set_rate_near(pcm, p, &rate, 0);
    snd_pcm_uframes_t period = cfg->frames_per_read;
    snd_pcm_uframes_t buffer = period * 4;
    snd_pcm_hw_params_set_period_size_near(pcm, p, &period, 0);
    snd_pcm_hw_params_set_buffer_size_near(pcm, p, &buffer);
    err = snd_pcm_hw_params(pcm, p);
    snd_pcm_hw_params_free(p);
    if (err < 0) { logmsg("cap","hw_params: %s", snd_strerror(err)); snd_pcm_close(pcm); g_running=0; return NULL; }
    snd_pcm_prepare(pcm);

    cfg->rate = rate;
    const size_t FR = cfg->frames_per_read;
    const size_t fb = cfg->channels * cfg->bytes_per_sample;
    uint8_t *buf = (uint8_t*)malloc(fb * FR);
    if (!buf) { logmsg("cap","oom"); snd_pcm_close(pcm); g_running=0; return NULL; }

    logmsg("cap","started: rate=%u ch=%u period=%lu bits=%d", cfg->rate, cfg->channels, (unsigned long)period, cfg->bytes_per_sample * 8);
    while (g_running) {
        snd_pcm_sframes_t got = snd_pcm_readi(pcm, buf, FR);
        if (got < 0) {
            got = snd_pcm_recover(pcm, (int)got, 1);
            if (got < 0) {
                struct timespec _ts={.tv_sec=0,.tv_nsec=100*1000*1000};
                nanosleep(&_ts,NULL);
                continue;
            }
            continue;
        }
        if (got > 0) ring_write(&app->ring, buf, (size_t)got);
    }

    free(buf);
    snd_pcm_close(pcm);
#else
    logmsg("cap","ALSA not available, use --source slink");
    g_running = 0;
#endif
    logmsg("cap","exit");
    return NULL;
}

static void *id_main(void *arg) {
    App *app = (App*)arg;
    Config *cfg = &app->cfg;

    const size_t look_frames = (size_t)cfg->fingerprint_sec * cfg->rate;
    const size_t fb = cfg->channels * cfg->bytes_per_sample;
    uint8_t *window = (uint8_t*)malloc(look_frames * fb);
    int16_t *window_s16 = (int16_t*)malloc(sizeof(int16_t) * look_frames * cfg->channels);
    if (!window || !window_s16) { logmsg("id","oom"); return NULL; }

    logmsg("id","started: fingerprint=%us interval=%us min_rms=%u",
           cfg->fingerprint_sec, cfg->identify_interval_sec, cfg->min_rms);

    time_t last_lookup = 0;
    time_t last_good_match = 0;
    TrackID current = {0};
    TrackID pending = {0};
    int pending_confirms = 0;

    while (g_running) {
        size_t got = ring_copy_last(&app->ring, window, look_frames);
        
        /* Convert to 16-bit for RMS and vibra */
        if (cfg->bytes_per_sample == 2) {
            memcpy(window_s16, window, got * fb);
        } else if (cfg->bytes_per_sample == 3) {
            for (size_t i = 0; i < got * cfg->channels; ++i) {
                int32_t s;
                if (cfg->source_big_endian) {
                    s = ((int32_t)window[i*3] << 16) | ((int32_t)window[i*3+1] << 8) | (int32_t)window[i*3+2];
                } else {
                    s = ((int32_t)window[i*3+2] << 16) | ((int32_t)window[i*3+1] << 8) | (int32_t)window[i*3];
                }
                if (s & 0x800000) s |= 0xFF000000;
                window_s16[i] = (int16_t)(s >> 8);
            }
        }
        
        unsigned r = rms_s16_interleaved(window_s16, got, cfg->channels);
        vlogmsg("id","peek=%zu frames, rms=%u (min_rms=%u)", got, r, cfg->min_rms);

        if (got > 0 && r >= cfg->min_rms && got >= (size_t)(cfg->rate * cfg->fingerprint_sec * 3 / 4)) {
            time_t nowt = time(NULL);
            if (current.valid && (unsigned)(nowt - last_good_match) < cfg->same_track_hold_sec) {
                vlogmsg("id","hold: same-track window active (%us)", cfg->same_track_hold_sec);
                goto sleep_loop;
            }
            if (last_lookup && (unsigned)(nowt - last_lookup) < cfg->shazam_gap_sec) {
                vlogmsg("id","throttle: waiting %us between lookups", cfg->shazam_gap_sec);
                goto sleep_loop;
            }
            last_lookup = nowt;

            const int bytes = (int)(got * cfg->channels * sizeof(int16_t));
            Fingerprint *fp = vibra_get_fingerprint_from_signed_pcm(
                (const char*)window_s16, bytes, (int)cfg->rate, 16, (int)cfg->channels);
            if (!fp) {
                logmsg("vibra","fingerprint failed");
            } else {
                const char *uri = vibra_get_uri_from_fingerprint(fp);
                unsigned sample_ms = vibra_get_sample_ms_from_fingerprint(fp);
                char url[512]; char *body = NULL;
                build_shazam_request(uri, sample_ms, cfg->timezone, url, &body);
                if (body) {
                    const char *ua = cfg->user_agent ? cfg->user_agent :
                        "Dalvik/2.1.0 (Linux; U; Android 5.0.2; VS980 4G Build/LRX22G)";
                    char *json = shazam_post(url, ua, body);
                    if (json) {
                        vlogmsg("id","shazam response: %.500s", json);
                        
                        /* Count number of matches - more matches = more ambiguous */
                        int match_count = 0;
                        const char *mp = json;
                        while ((mp = strstr(mp, "\"id\":\"")) != NULL) {
                            match_count++;
                            mp += 6;
                        }
                        
                        /* Check match quality via skew values */
                        char timeskew_str[64]={0}, freqskew_str[64]={0};
                        json_extract_field(json, "timeskew", timeskew_str, sizeof(timeskew_str));
                        json_extract_field(json, "frequencyskew", freqskew_str, sizeof(freqskew_str));
                        double timeskew = timeskew_str[0] ? atof(timeskew_str) : 999;
                        double freqskew = freqskew_str[0] ? atof(freqskew_str) : 999;
                        double ts_abs = timeskew < 0 ? -timeskew : timeskew;
                        double fs_abs = freqskew < 0 ? -freqskew : freqskew;
                        
                        /* Classify match quality - consider both skew and match count
                         * Multiple matches means ambiguous fingerprint - require tighter skew
                         * Single match with good skew = high confidence
                         * Multiple matches with loose skew = likely wrong track */
                        int quality = 0;  /* 0=reject, 1=needs confirm, 2=excellent */
                        if (match_count <= 2) {
                            /* Few matches - use vinyl-friendly thresholds */
                            if (ts_abs < 0.01 && fs_abs < 0.01) quality = 2;       /* <1% skew = excellent */
                            else if (ts_abs < 0.05 && fs_abs < 0.05) quality = 1;  /* <5% skew = needs confirm */
                        } else {
                            /* Many matches - fingerprint is ambiguous, require tighter skew */
                            if (ts_abs < 0.005 && fs_abs < 0.005) quality = 2;     /* <0.5% = still excellent */
                            else if (ts_abs < 0.01 && fs_abs < 0.01) quality = 1;  /* <1% = needs confirm */
                            /* >1% with multiple matches = too ambiguous, reject */
                        }
                        
                        if (quality == 0) {
                            vlogmsg("id","rejecting: %d matches, ts=%.6f fs=%.6f (too ambiguous)", match_count, timeskew, freqskew);
                            free(json);
                            free(body);
                            vibra_free_fingerprint(fp);
                            goto sleep_loop;
                        }
                        
                        char title[256]={0}, artist[256]={0}, isrc[64]={0};
                        json_extract_field(json, "title", title, sizeof(title));
                        json_extract_field(json, "subtitle", artist, sizeof(artist));
                        if (!artist[0]) json_extract_field(json, "artist", artist, sizeof(artist));
                        json_extract_field(json, "isrc", isrc, sizeof(isrc));

                        if (title[0] || artist[0] || isrc[0]) {
                            TrackID match = {0};
                            match.valid = 1;
                            snprintf(match.isrc, sizeof(match.isrc), "%s", isrc);
                            snprintf(match.artist, sizeof(match.artist), "%s", artist);
                            snprintf(match.title, sizeof(match.title), "%s", title);
                            match.has_isrc = isrc[0] != 0;
                            
                            if (current.valid && same_track(&match, &current)) {
                                /* Same track still playing */
                                last_good_match = time(NULL);
                                vlogmsg("id","still playing: %s — %s (q=%d)", artist, title, quality);
                            } else {
                                /* All matches require confirmation to reduce false positives
                                 * This is especially important for vinyl where Shazam may return
                                 * multiple candidate matches and pick the wrong one */
                                if (pending.valid && same_track(&match, &pending)) {
                                    pending_confirms++;
                                    vlogmsg("id","confirming: %s — %s (%d/3, q=%d)", artist, title, pending_confirms, quality);
                                    if (pending_confirms >= 3) {
                                        current = match;
                                        last_good_match = time(NULL);
                                        char tsbuf[64]; now_timestamp(tsbuf, sizeof(tsbuf));
                                        const char *qstr = (quality == 2) ? "excellent" : "confirmed";
                                        if (match.has_isrc) logmsg("id","%s MATCH: %s — %s [ISRC %s] (%s)", tsbuf, artist, title, isrc, qstr);
                                        else                logmsg("id","%s MATCH: %s — %s (%s)", tsbuf, artist, title, qstr);
                                        db_insert_play(app, tsbuf, artist, title, isrc, qstr);
                                        pending.valid = 0; pending_confirms = 0;
                                    }
                                } else {
                                    pending = match;
                                    pending_confirms = 1;  /* first sighting counts as 1 */
                                    vlogmsg("id","candidate: %s — %s (need 3 confirms, %d matches, ts=%.6f fs=%.6f)", artist, title, match_count, timeskew, freqskew);
                                }
                            }
                        } else {
                            vlogmsg("id","no track in response");
                        }
                        free(json);
                    } else {
                        logmsg("id","recognize: empty");
                    }
                    free(body);
                }
                vibra_free_fingerprint(fp);
            }
        }
sleep_loop:
        for (unsigned s=0; s<cfg->identify_interval_sec && g_running; ++s) {
            struct timespec ts = {.tv_sec=0,.tv_nsec=200*1000*1000};
            nanosleep(&ts, NULL);
        }
    }

    free(window);
    logmsg("id","exit");
    return NULL;
}

static void *writer_main(void *arg) {
    App *app = (App*)arg;
    Config *cfg = &app->cfg;

    const size_t FR = cfg->frames_per_read;
    const size_t fb = cfg->channels * cfg->bytes_per_sample;
    uint8_t *chunk = (uint8_t*)malloc(FR * fb);
    if (!chunk) { logmsg("wrt","oom"); return NULL; }

    const unsigned sustain_chunks_needed = (unsigned)((cfg->sustain_sec * cfg->rate + (FR-1)) / FR);
    const unsigned silence_chunks_needed = (unsigned)((cfg->silence_sec * cfg->rate + (FR-1)) / FR);
    const size_t prebuffer_frames = (size_t)cfg->prebuffer_sec * cfg->rate;

    /* Sliding window for trigger detection - require 60% of chunks above threshold */
    unsigned window_size = sustain_chunks_needed;
    unsigned *window = (unsigned*)calloc(window_size, sizeof(unsigned));
    unsigned window_pos = 0;
    unsigned window_above = 0;  /* count of above-threshold in window */
    bool window_full = false;
    const unsigned trigger_pct = 60;  /* require 60% above threshold */

    unsigned below_cnt = 0;
    bool recording = false;
    WavFile wf = {0};
    size_t file_frames_written = 0;
    const size_t max_file_frames = cfg->max_file_sec > 0 ? (size_t)cfg->max_file_sec * cfg->rate : 0;

    logmsg("wrt","started: thr=%u sustain=%.2fs prebuffer=%us silence=%.2fs",
           cfg->threshold, cfg->sustain_sec, cfg->prebuffer_sec, cfg->silence_sec);

    while (g_running) {
        size_t peek = ring_copy_last(&app->ring, chunk, FR);
        unsigned peak = 0;
        unsigned avg = analyze_samples(chunk, peek, cfg->channels, cfg->bytes_per_sample, cfg->source_big_endian, &peak);
        
        /* Music detection: require minimum peak AND average above threshold
         * Pure silence/noise floor: peak ~100-200, avg ~20-40
         * Quiet music/vinyl: peak ~300-800, avg ~50-150
         * Loud music with bass: peak ~1000+, avg ~300+ */
        const unsigned min_peak = 400;   /* minimum peak to filter out noise floor */
        const unsigned min_avg = 60;     /* minimum average regardless of threshold setting */
        float crest = (avg > 0) ? (float)peak / (float)avg : 0;
        int is_musical = (peak >= min_peak) && (avg >= min_avg) && (avg >= cfg->threshold);
        
        vlogmsg("wrt","avg=%u peak=%u crest=%.1f musical=%d thr=%u recording=%d", avg, peak, crest, is_musical, cfg->threshold, (int)recording);

        if (!recording) {
            /* Update sliding window - require musical content */
            unsigned is_above = is_musical ? 1 : 0;
            if (window_full) {
                /* Remove oldest entry from count before replacing */
                window_above -= window[window_pos];
            }
            window[window_pos] = is_above;
            window_above += is_above;
            window_pos = (window_pos + 1) % window_size;
            if (window_pos == 0) window_full = true;

            /* Calculate required threshold (70% of window, or 70% of filled portion) */
            unsigned effective_size = window_full ? window_size : window_pos;
            unsigned required = (effective_size * trigger_pct) / 100;
            
            /* Log progress towards trigger */
            static unsigned last_pct = 0;
            unsigned current_pct = effective_size > 0 ? (window_above * 100) / effective_size : 0;
            if (current_pct >= 50 && (current_pct / 10 != last_pct / 10)) {
                logmsg("wrt","trigger progress: %u%% above threshold (%u/%u) avg=%u crest=%.1f", current_pct, window_above, effective_size, avg, crest);
                last_pct = current_pct;
            }
            if (current_pct < 50) last_pct = 0;

            if (window_full && window_above >= required && peek > 0) {
                /* Copy prebuffer while holding lock to avoid race with capture thread */
                pthread_mutex_lock(&app->ring.mu);
                size_t wp = app->ring.write_pos;
                size_t cap = app->ring.frames_capacity;
                size_t avail = (app->ring.total_written < cap) ? app->ring.total_written : cap;
                size_t want_pre = prebuffer_frames;
                if (want_pre > avail) want_pre = avail;
                if (want_pre > cap) want_pre = cap;  /* never request more than buffer can hold */
                size_t start;
                if (wp >= want_pre) {
                    start = wp - want_pre;
                } else {
                    start = cap - (want_pre - wp);
                }
                
                /* Copy prebuffer data to local buffer while holding lock */
                uint8_t *prebuf = malloc(want_pre * fb);
                size_t copied_frames = 0;
                if (prebuf) {
                    for (size_t i = 0; i < want_pre; i++) {
                        size_t cursor = (start + i) % cap;
                        if (cursor == wp) break;
                        memcpy(&prebuf[i * fb], &app->ring.data[cursor * fb], fb);
                        copied_frames++;
                    }
                    app->ring.read_pos = wp;
                }
                pthread_mutex_unlock(&app->ring.mu);

                time_t trigger_ts = time(NULL);
                if (prebuf && copied_frames > 0 && wav_open_at(&wf, cfg->prefix, cfg->channels, cfg->rate, trigger_ts - (time_t)(copied_frames / cfg->rate)) == 0) {
                    /* Track current WAV file for database logging */
                    snprintf(app->current_wav, sizeof(app->current_wav), "%s", wf.tmp_name);
                    size_t len = strlen(app->current_wav);
                    if (len > 5 && !strcmp(app->current_wav + len - 5, ".part")) {
                        app->current_wav[len - 5] = '\0';  /* strip .part suffix */
                    }
                    /* Write prebuffer from local copy - no lock needed */
                    wav_write_samples(wf.fp, prebuf, copied_frames, cfg->channels, cfg->bytes_per_sample, cfg->source_big_endian);
                    fflush(wf.fp);
                    recording = true;
                    below_cnt = 0;
                    file_frames_written = copied_frames;
                    logmsg("wrt","TRIGGER avg=%u (prebuffer %zu frames)", avg, copied_frames);
                } else {
                    logmsg("wrt","failed to open wav%s", prebuf ? "" : " (malloc failed)");
                }
                free(prebuf);
                /* Reset sliding window */
                memset(window, 0, window_size * sizeof(unsigned));
                window_pos = 0;
                window_above = 0;
                window_full = false;
            }
        } else {
            /* Read all available data to keep up with capture thread */
            size_t total_got = 0;
            size_t got;
            while ((got = ring_read(&app->ring, chunk, FR)) > 0 && wf.fp) {
                wav_write_samples(wf.fp, chunk, got, cfg->channels, cfg->bytes_per_sample, cfg->source_big_endian);
                total_got += got;
                file_frames_written += got;
                
                /* Check if we need to split to a new file (seamless) */
                if (max_file_frames > 0 && file_frames_written >= max_file_frames) {
                    unsigned bits = cfg->bytes_per_sample * 8;
                    fflush(wf.fp);
                    wav_finalize(&wf, cfg->channels, cfg->rate, bits);
                    logmsg("wrt","SPLIT at %zu frames (%.1f min)", file_frames_written, (double)file_frames_written / cfg->rate / 60.0);
                    
                    /* Open new file immediately - seamless transition */
                    time_t now_ts = time(NULL);
                    if (wav_open_at(&wf, cfg->prefix, cfg->channels, cfg->rate, now_ts) != 0) {
                        logmsg("wrt","failed to open continuation file, stopping");
                        app->current_wav[0] = '\0';
                        recording = false;
                        break;
                    }
                    /* Update current WAV file for database logging */
                    snprintf(app->current_wav, sizeof(app->current_wav), "%s", wf.tmp_name);
                    size_t clen = strlen(app->current_wav);
                    if (clen > 5 && !strcmp(app->current_wav + clen - 5, ".part")) {
                        app->current_wav[clen - 5] = '\0';
                    }
                    file_frames_written = 0;
                }
            }
            if (total_got > 0) {
                static unsigned cnt = 0; if ((++cnt & 0x1F)==0) { fflush(wf.fp); int fd=fileno(wf.fp); if (fd>=0) fsync(fd); }
            } else {
                struct timespec ts = {.tv_sec=0,.tv_nsec=50*1000*1000};
                nanosleep(&ts, NULL);
            }

            size_t p2 = ring_copy_last(&app->ring, chunk, FR);
            unsigned peak2 = 0;
            unsigned avg2 = analyze_samples(chunk, p2, cfg->channels, cfg->bytes_per_sample, cfg->source_big_endian, &peak2);
            /* Silence detection uses very low thresholds - only stop on true silence
             * Ambient music can have very quiet passages - don't stop on those
             * Vinyl surface noise alone: peak ~200-400, avg ~50-80
             * True silence (needle lifted): peak <100, avg <20 */
            const unsigned silence_peak_thr = 150;  /* below this = likely silence */
            const unsigned silence_avg_thr = 25;    /* below this = likely silence */
            int is_silence = (peak2 < silence_peak_thr) && (avg2 < silence_avg_thr);
            if (is_silence) { if (below_cnt < 0x7fffffff) below_cnt++; }
            else { below_cnt = 0; }

            if (below_cnt >= silence_chunks_needed) {
                unsigned bits = cfg->bytes_per_sample * 8;
                if (wf.fp) { fflush(wf.fp); wav_finalize(&wf, cfg->channels, cfg->rate, bits); }
                recording = false;
                below_cnt = 0;
                app->current_wav[0] = '\0';
                logmsg("wrt","STOP (silence)");
            }
        }
        struct timespec ts = {.tv_sec=0,.tv_nsec=30*1000*1000};
        nanosleep(&ts, NULL);
    }

    if (recording && wf.fp) { fflush(wf.fp); unsigned bits = cfg->bytes_per_sample * 8; wav_finalize(&wf, cfg->channels, cfg->rate, bits); }
    free(window);
    free(chunk);
    logmsg("wrt","exit");
    return NULL;
}

static void usage(const char *argv0) {
    fprintf(stderr,
        "Usage: %s [options]\n"
        "  --device hw:2,1        ALSA device\n"
        "  --rate 48000           sample rate\n"
        "  --channels 2           channel count\n"
        "  --frames 1024          frames per ALSA read\n"
        "  --ring-sec 20          ring buffer size in seconds\n"
        "  --fingerprint-sec 12   seconds of audio to send to vibra\n"
        "  --min-rms 300          minimum RMS to attempt recognition\n"
        "  --interval 2           seconds between recognition attempts (baseline loop)\n"
        "  --user-agent UA        override User-Agent header\n"
        "  --timezone TZ          override timezone (default Europe/Amsterdam)\n"
        "  --shazam-gap-sec 10    min seconds between Shazam lookups\n"
        "  --same-track-hold-sec 90  suppress lookups after a good match\n"
        "  --threshold 50         avg abs amplitude trigger for WAV writer\n"
        "  --sustain-sec 1.0      seconds above threshold to start recording\n"
        "  --prebuffer-sec 5      seconds of audio to include before trigger\n"
        "  --silence-sec 3.0      seconds below threshold to stop recording\n"
        "  --prefix capture       WAV filename prefix\n"
        "  --source alsa          audio source: 'alsa' or 'slink'\n"
        "  --bits 16              sample bit depth (16 or 24)\n"
        "  --max-file-sec 600     max seconds per WAV file (0 = no limit)\n"
        "  --db tracks.db         SQLite database for track logging\n"
        "  --verbose              enable heartbeat logging\n",
        argv0);
}
static int parse_cli(int argc, char **argv, Config *cfg) {
    for (int i=1; i<argc; ++i) {
        const char *a = argv[i];
        if (!strcmp(a,"--device") && i+1<argc) cfg->device = argv[++i];
        else if (!strcmp(a,"--rate") && i+1<argc) cfg->rate = (unsigned)strtoul(argv[++i], NULL, 10);
        else if (!strcmp(a,"--channels") && i+1<argc) cfg->channels = (unsigned)strtoul(argv[++i], NULL, 10);
        else if (!strcmp(a,"--frames") && i+1<argc) cfg->frames_per_read = (unsigned)strtoul(argv[++i], NULL, 10);
        else if (!strcmp(a,"--ring-sec") && i+1<argc) cfg->ring_sec = (unsigned)strtoul(argv[++i], NULL, 10);
        else if (!strcmp(a,"--fingerprint-sec") && i+1<argc) cfg->fingerprint_sec = (unsigned)strtoul(argv[++i], NULL, 10);
        else if (!strcmp(a,"--min-rms") && i+1<argc) cfg->min_rms = (unsigned)strtoul(argv[++i], NULL, 10);
        else if (!strcmp(a,"--interval") && i+1<argc) cfg->identify_interval_sec = (unsigned)strtoul(argv[++i], NULL, 10);
        else if (!strcmp(a,"--user-agent") && i+1<argc) cfg->user_agent = argv[++i];
        else if (!strcmp(a,"--timezone") && i+1<argc) cfg->timezone   = argv[++i];
        else if (!strcmp(a,"--shazam-gap-sec") && i+1<argc) cfg->shazam_gap_sec = (unsigned)strtoul(argv[++i], NULL, 10);
        else if (!strcmp(a,"--same-track-hold-sec") && i+1<argc) cfg->same_track_hold_sec = (unsigned)strtoul(argv[++i], NULL, 10);
        else if (!strcmp(a,"--threshold") && i+1<argc) cfg->threshold = (unsigned)strtoul(argv[++i], NULL, 10);
        else if (!strcmp(a,"--sustain-sec") && i+1<argc) cfg->sustain_sec = (float)atof(argv[++i]);
        else if (!strcmp(a,"--prebuffer-sec") && i+1<argc) cfg->prebuffer_sec = (unsigned)strtoul(argv[++i], NULL, 10);
        else if (!strcmp(a,"--silence-sec") && i+1<argc) cfg->silence_sec = (float)atof(argv[++i]);
        else if (!strcmp(a,"--prefix") && i+1<argc) cfg->prefix = argv[++i];
        else if (!strcmp(a,"--source") && i+1<argc) cfg->source = argv[++i];
        else if (!strcmp(a,"--bits") && i+1<argc) { unsigned b = (unsigned)strtoul(argv[++i], NULL, 10); cfg->bytes_per_sample = (b == 24) ? 3 : 2; }
        else if (!strcmp(a,"--max-file-sec") && i+1<argc) cfg->max_file_sec = (unsigned)strtoul(argv[++i], NULL, 10);
        else if (!strcmp(a,"--db") && i+1<argc) cfg->db_path = argv[++i];
        else if (!strcmp(a,"--verbose")) g_verbose = 1;
        else { usage(argv[0]); return -1; }
    }
    return 0;
}

static void on_signal(int sig) { (void)sig; g_running = 0; }

int main(int argc, char **argv) {
    setvbuf(stderr, NULL, _IONBF, 0);
    struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts);
    srand((unsigned)(ts.tv_nsec ^ ts.tv_sec));

    Config cfg = {
        .device = "default",
        .rate = 48000,
        .channels = 2,
        .frames_per_read = 1024,
        .ring_sec = 20,
        .fingerprint_sec = 12,
        .min_rms = 300,
        .identify_interval_sec = 2,
        .user_agent = NULL,
        .timezone = NULL,
        .shazam_gap_sec = 10,
        .same_track_hold_sec = 90,
        .threshold = 50,
        .sustain_sec = 1.0f,
        .prebuffer_sec = 5,
        .silence_sec = 15.0f,
        .prefix = "capture",
        .source = "alsa",
        .bytes_per_sample = 2,
        .max_file_sec = 600,  /* 10 minutes */
    };
    if (parse_cli(argc, argv, &cfg) != 0) return 2;

    /* SLink is big-endian, ALSA is little-endian */
    cfg.source_big_endian = (cfg.source && !strcmp(cfg.source, "slink")) ? 1 : 0;
    
    /* SLink is always 24-bit */
    if (cfg.source && !strcmp(cfg.source, "slink")) {
        cfg.bytes_per_sample = 3;
    }

    App app = {0};
    app.cfg = cfg;
    size_t ring_frames = (size_t)app.cfg.rate * app.cfg.ring_sec;
    if (ring_init(&app.ring, ring_frames, app.cfg.channels, app.cfg.bytes_per_sample) != 0) {
        logmsg("main","ring alloc failed"); return 1;
    }
    if (db_init(&app) != 0) {
        logmsg("main","database init failed"); ring_free(&app.ring); return 1;
    }

    struct sigaction sa = {0};
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    logmsg("main","starting: dev=%s rate=%u ch=%u frames=%u ring=%us fingerprint=%us interval=%us thr=%u sustain=%.2fs prebuffer=%us silence=%.2fs split=%us verbose=%d shazam-gap=%us same-hold=%us",
           app.cfg.device, app.cfg.rate, app.cfg.channels, app.cfg.frames_per_read,
           app.cfg.ring_sec, app.cfg.fingerprint_sec, app.cfg.identify_interval_sec,
           app.cfg.threshold, app.cfg.sustain_sec, app.cfg.prebuffer_sec, app.cfg.silence_sec, app.cfg.max_file_sec, g_verbose,
           app.cfg.shazam_gap_sec, app.cfg.same_track_hold_sec);

    if (pthread_create(&app.th_cap, NULL, capture_main, &app) != 0) {
        logmsg("main","pthread cap failed"); ring_free(&app.ring); return 1;
    }
    if (pthread_create(&app.th_id, NULL, id_main, &app) != 0) {
        logmsg("main","pthread id failed"); g_running=0; pthread_join(app.th_cap,NULL); ring_free(&app.ring); return 1;
    }
    if (pthread_create(&app.th_wrt, NULL, writer_main, &app) != 0) {
        logmsg("main","pthread wrt failed"); g_running=0; pthread_join(app.th_cap,NULL); pthread_join(app.th_id,NULL); ring_free(&app.ring); return 1;
    }

    while (g_running) {
        struct timespec snooze = {.tv_sec=1,.tv_nsec=0};
        nanosleep(&snooze, NULL);
    }

    pthread_join(app.th_cap, NULL);
    pthread_join(app.th_id, NULL);
    pthread_join(app.th_wrt, NULL);
    db_close(&app);
    ring_free(&app.ring);
    logmsg("main","bye");
    return 0;
}
