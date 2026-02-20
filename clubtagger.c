#ifdef HAVE_ALSA
#include <alsa/asoundlib.h>
#endif
#ifdef HAVE_FLAC
#include <FLAC/stream_encoder.h>
#endif
#ifdef HAVE_PCAP
#include <pcap.h>
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
#ifdef HAVE_PCAP
static pcap_t *g_pcap_handle = NULL;
#endif
#ifdef HAVE_ALSA
static snd_pcm_t *g_alsa_handle = NULL;
#endif

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

typedef struct {
    const char *device;
    unsigned    rate;
    unsigned    channels;
    unsigned    frames_per_read;
    unsigned    fingerprint_sec;
    unsigned    min_rms;
    unsigned    identify_interval_sec;
    const char *user_agent;
    const char *timezone;
    unsigned    shazam_gap_sec;
    unsigned    same_track_hold_sec;
    unsigned    threshold;
    float       sustain_sec;
    float       silence_sec;
    const char *prefix;
    const char *source;        /* "alsa" or "slink" */
    int         bytes_per_sample;  /* 2 for 16-bit, 3 for 24-bit */
    unsigned    max_file_sec;      /* max seconds per WAV file (0 = no limit) */
    unsigned    ring_sec;          /* ring buffer size in seconds */
    const char *db_path;       /* SQLite database path for track logging */
    const char *outdir;        /* output directory for audio files */
    const char *format;        /* output format: "wav" or "flac" */
} Config;

/* ─────────────────────────────────────────────────────────────────────────────
 * AudioBuffer - descriptor for atomic file writing (WAV/FLAC)
 * ───────────────────────────────────────────────────────────────────────────── */
typedef struct {
    uint8_t *data;
    size_t   frames;
    size_t   capacity_frames;
    size_t   frame_bytes;
    unsigned channels;
    unsigned rate;
    int      bytes_per_sample;
    time_t   start_time;
} AudioBuffer;

static int audiobuf_write(const AudioBuffer *ab, const char *outdir, const char *prefix, const char *format);

/* ─────────────────────────────────────────────────────────────────────────────
 * AsyncWriter - fixed-size ring buffer with async disk writes
 * 
 * Capture thread continuously writes samples (overwrites oldest when full).
 * Writer thread copies ranges from ring and writes to disk asynchronously.
 * ───────────────────────────────────────────────────────────────────────────── */
typedef struct {
    /* Ring buffer (fixed size) */
    uint8_t        *data;
    size_t          capacity;       /* fixed capacity in frames */
    size_t          head;           /* write position (wraps modulo capacity) */
    size_t          total_written;  /* monotonic counter: total frames ever written */
    size_t          frame_bytes;
    unsigned        channels;
    unsigned        rate;
    int             bytes_per_sample;
    
    /* Async write state */
    uint8_t        *write_buf;      /* snapshot buffer for async writes */
    size_t          write_capacity;
    size_t          write_frames;
    size_t          write_from;
    size_t          write_to;
    time_t          write_start_time;
    int             write_pending;
    
    /* Config */
    const char     *outdir;
    const char     *prefix;
    const char     *format;
    
    /* Threading */
    pthread_mutex_t mu;
    pthread_cond_t  cv;
    pthread_t       thread;
    int             shutdown;
    int             initialized;
} AsyncWriter;

static int asyncwr_init(AsyncWriter *aw, unsigned channels, unsigned rate,
                        int bytes_per_sample, size_t capacity_frames,
                        const char *outdir, const char *prefix, const char *format);
static void asyncwr_free(AsyncWriter *aw);
static int asyncwr_append(AsyncWriter *aw, const uint8_t *samples, size_t nframes);
static size_t asyncwr_position(AsyncWriter *aw);
static size_t asyncwr_copy_last(AsyncWriter *aw, void *dst, size_t nframes);
static void asyncwr_write_range(AsyncWriter *aw, size_t from, size_t to, time_t start_time);
static void asyncwr_wait_pending(AsyncWriter *aw);

/* Helper to write buffer to disk */
static void asyncwr_do_write(AsyncWriter *aw, const uint8_t *data, size_t nframes,
                             size_t from, size_t to, time_t start_time) {
    AudioBuffer ab = {
        .data = (uint8_t*)data,
        .frames = nframes,
        .capacity_frames = nframes,
        .frame_bytes = aw->frame_bytes,
        .channels = aw->channels,
        .rate = aw->rate,
        .bytes_per_sample = aw->bytes_per_sample,
        .start_time = start_time
    };
    
    audiobuf_write(&ab, aw->outdir, aw->prefix, aw->format);
    logmsg("wrt", "wrote frames %zu-%zu (%zu frames, %.1f sec)", 
           from, to, nframes, (double)nframes / aw->rate);
}

static void *asyncwr_thread_main(void *arg) {
    AsyncWriter *aw = (AsyncWriter*)arg;
    
    pthread_mutex_lock(&aw->mu);
    while (!aw->shutdown) {
        while (!aw->write_pending && !aw->shutdown) {
            pthread_cond_wait(&aw->cv, &aw->mu);
        }
        if (aw->shutdown && !aw->write_pending) break;
        
        uint8_t *data = aw->write_buf;
        size_t nframes = aw->write_frames;
        size_t from = aw->write_from;
        size_t to = aw->write_to;
        time_t start_time = aw->write_start_time;
        pthread_mutex_unlock(&aw->mu);
        
        if (nframes > 0) {
            asyncwr_do_write(aw, data, nframes, from, to, start_time);
        }
        
        pthread_mutex_lock(&aw->mu);
        aw->write_pending = 0;
        pthread_cond_broadcast(&aw->cv);
    }
    pthread_mutex_unlock(&aw->mu);
    
    logmsg("wrt", "writer thread exit");
    return NULL;
}

static int asyncwr_init(AsyncWriter *aw, unsigned channels, unsigned rate,
                        int bytes_per_sample, size_t capacity_frames,
                        const char *outdir, const char *prefix, const char *format) {
    memset(aw, 0, sizeof(*aw));
    
    aw->frame_bytes = channels * bytes_per_sample;
    aw->channels = channels;
    aw->rate = rate;
    aw->bytes_per_sample = bytes_per_sample;
    aw->capacity = capacity_frames;
    aw->head = 0;
    aw->total_written = 0;
    
    aw->data = (uint8_t*)malloc(capacity_frames * aw->frame_bytes);
    if (!aw->data) return -1;
    
    /* Write buffer sized for max_file_sec worth of data */
    aw->write_buf = (uint8_t*)malloc(capacity_frames * aw->frame_bytes);
    aw->write_capacity = capacity_frames;
    if (!aw->write_buf) {
        free(aw->data);
        return -1;
    }
    
    aw->write_pending = 0;
    aw->outdir = outdir;
    aw->prefix = prefix;
    aw->format = format;
    aw->shutdown = 0;
    
    pthread_mutex_init(&aw->mu, NULL);
    pthread_cond_init(&aw->cv, NULL);
    
    if (pthread_create(&aw->thread, NULL, asyncwr_thread_main, aw) != 0) {
        free(aw->data);
        free(aw->write_buf);
        pthread_mutex_destroy(&aw->mu);
        pthread_cond_destroy(&aw->cv);
        return -1;
    }
    aw->initialized = 1;
    
    logmsg("ring", "initialized: %.1f sec capacity (%zu frames)", 
           (double)capacity_frames / rate, capacity_frames);
    return 0;
}

static void asyncwr_free(AsyncWriter *aw) {
    if (!aw->initialized) return;
    
    pthread_mutex_lock(&aw->mu);
    aw->shutdown = 1;
    pthread_cond_signal(&aw->cv);
    pthread_mutex_unlock(&aw->mu);
    
    pthread_join(aw->thread, NULL);
    
    free(aw->data);
    free(aw->write_buf);
    pthread_mutex_destroy(&aw->mu);
    pthread_cond_destroy(&aw->cv);
    aw->initialized = 0;
}

/* Append samples to ring buffer (called by capture thread) */
static int asyncwr_append(AsyncWriter *aw, const uint8_t *samples, size_t nframes) {
    pthread_mutex_lock(&aw->mu);
    
    const size_t fb = aw->frame_bytes;
    size_t remaining = nframes;
    const uint8_t *src = samples;
    
    while (remaining > 0) {
        size_t space_to_end = aw->capacity - aw->head;
        size_t chunk = (remaining < space_to_end) ? remaining : space_to_end;
        
        memcpy(aw->data + aw->head * fb, src, chunk * fb);
        
        aw->head = (aw->head + chunk) % aw->capacity;
        aw->total_written += chunk;
        src += chunk * fb;
        remaining -= chunk;
    }
    
    pthread_mutex_unlock(&aw->mu);
    return 0;
}

/* Get total frames ever written (monotonic position) */
static size_t asyncwr_position(AsyncWriter *aw) {
    pthread_mutex_lock(&aw->mu);
    size_t pos = aw->total_written;
    pthread_mutex_unlock(&aw->mu);
    return pos;
}

/* Copy last N frames for level detection / fingerprinting */
static size_t asyncwr_copy_last(AsyncWriter *aw, void *dst, size_t nframes) {
    pthread_mutex_lock(&aw->mu);
    
    size_t avail = (aw->total_written < aw->capacity) ? aw->total_written : aw->capacity;
    size_t take = (avail < nframes) ? avail : nframes;
    
    if (take > 0) {
        const size_t fb = aw->frame_bytes;
        uint8_t *d = (uint8_t*)dst;
        
        /* Start position in ring: head - take (with wraparound) */
        size_t start = (aw->head + aw->capacity - take) % aw->capacity;
        
        if (start + take <= aw->capacity) {
            /* No wrap */
            memcpy(d, aw->data + start * fb, take * fb);
        } else {
            /* Wrap around */
            size_t first_part = aw->capacity - start;
            memcpy(d, aw->data + start * fb, first_part * fb);
            memcpy(d + first_part * fb, aw->data, (take - first_part) * fb);
        }
    }
    
    pthread_mutex_unlock(&aw->mu);
    return take;
}

/* Write frames [from, to) to disk asynchronously */
static void asyncwr_write_range(AsyncWriter *aw, size_t from, size_t to, time_t start_time) {
    pthread_mutex_lock(&aw->mu);
    
    /* Wait for previous write to complete */
    while (aw->write_pending && !aw->shutdown) {
        pthread_cond_wait(&aw->cv, &aw->mu);
    }
    if (aw->shutdown) {
        pthread_mutex_unlock(&aw->mu);
        return;
    }
    
    /* Oldest frame still in ring */
    size_t oldest = (aw->total_written > aw->capacity) 
                    ? (aw->total_written - aw->capacity) : 0;
    
    if (from < oldest) {
        logmsg("wrt", "WARNING: requested frames %zu-%zu but oldest is %zu (lost %zu frames)",
               from, to, oldest, oldest - from);
        from = oldest;
    }
    if (to > aw->total_written) to = aw->total_written;
    if (to <= from) {
        pthread_mutex_unlock(&aw->mu);
        return;
    }
    
    size_t nframes = to - from;
    const size_t fb = aw->frame_bytes;
    
    /* Resize write buffer if needed */
    if (nframes > aw->write_capacity) {
        uint8_t *new_buf = (uint8_t*)realloc(aw->write_buf, nframes * fb);
        if (new_buf) {
            aw->write_buf = new_buf;
            aw->write_capacity = nframes;
        } else {
            logmsg("wrt", "ERROR: can't allocate %zu bytes for write buffer", nframes * fb);
            pthread_mutex_unlock(&aw->mu);
            return;
        }
    }
    
    /* Copy from ring to write buffer */
    size_t offset_from_head = aw->total_written - from;
    size_t start = (aw->head + aw->capacity - offset_from_head) % aw->capacity;
    
    if (start + nframes <= aw->capacity) {
        memcpy(aw->write_buf, aw->data + start * fb, nframes * fb);
    } else {
        size_t first_part = aw->capacity - start;
        memcpy(aw->write_buf, aw->data + start * fb, first_part * fb);
        memcpy(aw->write_buf + first_part * fb, aw->data, (nframes - first_part) * fb);
    }
    
    aw->write_frames = nframes;
    aw->write_from = from;
    aw->write_to = to;
    aw->write_start_time = start_time;
    aw->write_pending = 1;
    
    pthread_cond_signal(&aw->cv);
    pthread_mutex_unlock(&aw->mu);
}

/* Wait for any pending async write to complete */
static void asyncwr_wait_pending(AsyncWriter *aw) {
    pthread_mutex_lock(&aw->mu);
    while (aw->write_pending) {
        pthread_cond_wait(&aw->cv, &aw->mu);
    }
    pthread_mutex_unlock(&aw->mu);
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

/* Analyze samples: returns avg absolute value, and optionally peak value
 * All samples are little-endian (converted at capture time for SLink) */
static unsigned analyze_samples(const void *data, size_t frames, size_t channels, int bytes_per_sample, unsigned *peak_out) {
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
            /* Little-endian 24-bit */
            int32_t s = ((int32_t)p[i*3+2] << 16) | ((int32_t)p[i*3+1] << 8) | (int32_t)p[i*3];
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

    if (res != CURLE_OK) logmsg("curl","perform failed: %s (code %d)", curl_easy_strerror(res), (int)res);
    else if (http_code != 200) logmsg("curl","HTTP %ld", http_code);

    if (buf.s && buf.n > 0) return buf.s;
    free(buf.s);
    return NULL;
}

static void le16_write(uint16_t v, FILE *f){ uint8_t b[2]={v&0xff,(v>>8)&0xff}; fwrite(b,1,2,f); }
static void le32_write(uint32_t v, FILE *f){ uint8_t b[4]={v&0xff,(v>>8)&0xff,(v>>16)&0xff,(v>>24)&0xff}; fwrite(b,1,4,f); }

/* ─────────────────────────────────────────────────────────────────────────────
 * Atomic file writing from AudioBuffer (WAV and FLAC)
 * ───────────────────────────────────────────────────────────────────────────── */

/* Ensure directory exists (mkdir -p style, single level only) */
static void ensure_dir(const char *path) {
    if (!path || !path[0]) return;
    struct stat st;
    if (stat(path, &st) == 0) return;  /* already exists */
    if (mkdir(path, 0755) != 0 && errno != EEXIST) {
        logmsg("wrt","mkdir %s: %s", path, strerror(errno));
    }
}

static void build_audio_filename(char *out, size_t out_sz, const char *outdir, 
                                  const char *prefix, const char *ext, time_t ts) {
    struct tm tm; localtime_r(&ts, &tm);
    if (outdir && outdir[0]) {
        snprintf(out, out_sz, "%s/%s_%04d%02d%02d_%02d%02d%02d.%s",
                 outdir, prefix, tm.tm_year+1900, tm.tm_mon+1, tm.tm_mday,
                 tm.tm_hour, tm.tm_min, tm.tm_sec, ext);
    } else {
        snprintf(out, out_sz, "%s_%04d%02d%02d_%02d%02d%02d.%s",
                 prefix, tm.tm_year+1900, tm.tm_mon+1, tm.tm_mday,
                 tm.tm_hour, tm.tm_min, tm.tm_sec, ext);
    }
}

/* Write AudioBuffer to WAV file atomically */
static int audiobuf_write_wav(const AudioBuffer *ab, const char *outdir, const char *prefix) {
    if (!ab->data || ab->frames == 0) return -1;
    
    ensure_dir(outdir);
    
    char final_name[512], tmp_name[520];
    build_audio_filename(final_name, sizeof(final_name), outdir, prefix, "wav", ab->start_time);
    snprintf(tmp_name, sizeof(tmp_name), "%s.tmp", final_name);
    
    FILE *fp = fopen(tmp_name, "wb");
    if (!fp) { logmsg("wav","open %s: %s", tmp_name, strerror(errno)); return -1; }
    
    unsigned bits = ab->bytes_per_sample * 8;
    uint32_t data_bytes = (uint32_t)(ab->frames * ab->frame_bytes);
    uint16_t block_align = (uint16_t)(ab->channels * ab->bytes_per_sample);
    uint32_t byte_rate = ab->rate * block_align;
    
    /* Write header */
    fwrite("RIFF", 1, 4, fp);
    le32_write(36 + data_bytes, fp);
    fwrite("WAVE", 1, 4, fp);
    fwrite("fmt ", 1, 4, fp);
    le32_write(16, fp);
    le16_write(1, fp);  /* PCM */
    le16_write((uint16_t)ab->channels, fp);
    le32_write(ab->rate, fp);
    le32_write(byte_rate, fp);
    le16_write(block_align, fp);
    le16_write((uint16_t)bits, fp);
    fwrite("data", 1, 4, fp);
    le32_write(data_bytes, fp);
    
    /* Write samples - data is already little-endian */
    fwrite(ab->data, ab->frame_bytes, ab->frames, fp);
    
    fflush(fp);
    int fd = fileno(fp); if (fd >= 0) fsync(fd);
    fclose(fp);
    
    if (rename(tmp_name, final_name) != 0) {
        logmsg("wav","rename %s -> %s: %s", tmp_name, final_name, strerror(errno));
        unlink(tmp_name);
        return -1;
    }
    
    logmsg("wav","wrote %s (%.1f sec, %.1f MB)", final_name, 
           (double)ab->frames / ab->rate, (double)data_bytes / (1024*1024));
    return 0;
}

#ifdef HAVE_FLAC
/* Write AudioBuffer to FLAC file atomically */
static int audiobuf_write_flac(const AudioBuffer *ab, const char *outdir, const char *prefix) {
    if (!ab->data || ab->frames == 0) return -1;
    
    ensure_dir(outdir);
    
    char final_name[512], tmp_name[520];
    build_audio_filename(final_name, sizeof(final_name), outdir, prefix, "flac", ab->start_time);
    snprintf(tmp_name, sizeof(tmp_name), "%s.tmp", final_name);
    
    FLAC__StreamEncoder *encoder = FLAC__stream_encoder_new();
    if (!encoder) { logmsg("flac","encoder_new failed"); return -1; }
    
    unsigned bits = ab->bytes_per_sample * 8;
    FLAC__stream_encoder_set_channels(encoder, ab->channels);
    FLAC__stream_encoder_set_bits_per_sample(encoder, bits);
    FLAC__stream_encoder_set_sample_rate(encoder, ab->rate);
    FLAC__stream_encoder_set_compression_level(encoder, 5);  /* balanced speed/size */
    FLAC__stream_encoder_set_total_samples_estimate(encoder, ab->frames);
    
    FLAC__StreamEncoderInitStatus init_status = 
        FLAC__stream_encoder_init_file(encoder, tmp_name, NULL, NULL);
    if (init_status != FLAC__STREAM_ENCODER_INIT_STATUS_OK) {
        logmsg("flac","init failed: %s", FLAC__StreamEncoderInitStatusString[init_status]);
        FLAC__stream_encoder_delete(encoder);
        return -1;
    }
    
    /* FLAC needs samples as int32_t array */
    size_t total_samples = ab->frames * ab->channels;
    FLAC__int32 *buffer = (FLAC__int32*)malloc(total_samples * sizeof(FLAC__int32));
    if (!buffer) {
        logmsg("flac","oom for sample buffer");
        FLAC__stream_encoder_finish(encoder);
        FLAC__stream_encoder_delete(encoder);
        unlink(tmp_name);
        return -1;
    }
    
    const uint8_t *src = ab->data;
    if (ab->bytes_per_sample == 2) {
        const int16_t *s16 = (const int16_t*)src;
        for (size_t i = 0; i < total_samples; ++i) {
            buffer[i] = s16[i];
        }
    } else if (ab->bytes_per_sample == 3) {
        for (size_t i = 0; i < total_samples; ++i) {
            /* Little-endian 24-bit */
            int32_t s = ((int32_t)src[i*3+2] << 16) | ((int32_t)src[i*3+1] << 8) | (int32_t)src[i*3];
            if (s & 0x800000) s |= 0xFF000000;  /* sign extend */
            buffer[i] = s;
        }
    }
    
    /* Encode in chunks to avoid huge stack usage */
    const size_t chunk_frames = 4096;
    FLAC__bool ok = true;
    for (size_t pos = 0; pos < ab->frames && ok; pos += chunk_frames) {
        size_t frames_to_encode = (ab->frames - pos < chunk_frames) ? (ab->frames - pos) : chunk_frames;
        ok = FLAC__stream_encoder_process_interleaved(encoder, buffer + pos * ab->channels, (unsigned)frames_to_encode);
    }
    
    free(buffer);
    
    if (!ok) {
        logmsg("flac","encode failed: %s", FLAC__StreamEncoderStateString[FLAC__stream_encoder_get_state(encoder)]);
        FLAC__stream_encoder_finish(encoder);
        FLAC__stream_encoder_delete(encoder);
        unlink(tmp_name);
        return -1;
    }
    
    FLAC__stream_encoder_finish(encoder);
    FLAC__stream_encoder_delete(encoder);
    
    /* Atomic rename */
    if (rename(tmp_name, final_name) != 0) {
        logmsg("flac","rename %s -> %s: %s", tmp_name, final_name, strerror(errno));
        unlink(tmp_name);
        return -1;
    }
    
    /* Get file size for logging */
    struct stat st;
    double file_mb = 0;
    if (stat(final_name, &st) == 0) file_mb = (double)st.st_size / (1024*1024);
    
    logmsg("flac","wrote %s (%.1f sec, %.1f MB)", final_name, 
           (double)ab->frames / ab->rate, file_mb);
    return 0;
}
#endif /* HAVE_FLAC */

/* Write AudioBuffer to file (WAV or FLAC based on format) */
static int audiobuf_write(const AudioBuffer *ab, const char *outdir, const char *prefix, const char *format) {
#ifdef HAVE_FLAC
    if (format && strcmp(format, "flac") == 0) {
        return audiobuf_write_flac(ab, outdir, prefix);
    }
#else
    if (format && strcmp(format, "flac") == 0) {
        logmsg("wrt","FLAC not available, falling back to WAV");
    }
#endif
    return audiobuf_write_wav(ab, outdir, prefix);
}

typedef struct {
    Config      cfg;
    AsyncWriter aw;            /* central audio buffer with async disk writes */
    pthread_t   th_cap;
    pthread_t   th_id;
    pthread_t   th_wrt;
    sqlite3    *db;
    pthread_mutex_t db_mu;
    char        current_wav[512];  /* current WAV file being recorded */
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

#ifdef HAVE_PCAP
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
    g_pcap_handle = handle;  /* allow signal handler to call breakloop */

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
            /* Convert 24-bit big-endian to little-endian as we copy */
            buf[buf_idx * fb + 0] = pkt[26];  /* Ch 0: swap bytes */
            buf[buf_idx * fb + 1] = pkt[25];
            buf[buf_idx * fb + 2] = pkt[24];
            buf[buf_idx * fb + 3] = pkt[29];  /* Ch 1: swap bytes */
            buf[buf_idx * fb + 4] = pkt[28];
            buf[buf_idx * fb + 5] = pkt[27];

            buf_idx++;
            if (buf_idx >= cfg->frames_per_read) {
                asyncwr_append(&app->aw, buf, cfg->frames_per_read);
                buf_idx = 0;
            }
        }
    }

    free(buf);
    g_pcap_handle = NULL;  /* prevent signal handler from using closed handle */
    pcap_close(handle);
    logmsg("cap","exit");
    return NULL;
}
#endif

#ifdef HAVE_ALSA
static void *capture_alsa(void *arg) {
    App *app = (App*)arg;
    Config *cfg = &app->cfg;

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
    g_alsa_handle = pcm;  /* allow signal handler to abort */

    cfg->rate = rate;
    const size_t FR = cfg->frames_per_read;
    const size_t fb = cfg->channels * cfg->bytes_per_sample;
    uint8_t *buf = (uint8_t*)malloc(fb * FR);
    if (!buf) { logmsg("cap","oom"); snd_pcm_close(pcm); g_running=0; return NULL; }

    logmsg("cap","started: rate=%u ch=%u period=%lu bits=%d (ALSA)", cfg->rate, cfg->channels, (unsigned long)period, cfg->bytes_per_sample * 8);
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
        if (got > 0) asyncwr_append(&app->aw, buf, (size_t)got);
    }

    free(buf);
    g_alsa_handle = NULL;  /* prevent signal handler from using closed handle */
    snd_pcm_close(pcm);
    logmsg("cap","exit");
    return NULL;
}
#endif

static void *capture_main(void *arg) {
    App *app = (App*)arg;
    Config *cfg = &app->cfg;

#ifdef HAVE_PCAP
    if (!strcmp(cfg->source, "slink")) {
        return capture_slink(arg);
    }
#endif

#ifdef HAVE_ALSA
    if (!strcmp(cfg->source, "alsa")) {
        return capture_alsa(arg);
    }
#endif

    logmsg("cap", "source '%s' not available (not compiled in)", cfg->source);
    g_running = 0;
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
        size_t got = asyncwr_copy_last(&app->aw, window, look_frames);
        
        /* Convert to 16-bit for RMS and vibra */
        if (cfg->bytes_per_sample == 2) {
            memcpy(window_s16, window, got * fb);
        } else if (cfg->bytes_per_sample == 3) {
            for (size_t i = 0; i < got * cfg->channels; ++i) {
                /* Little-endian 24-bit */
                int32_t s = ((int32_t)window[i*3+2] << 16) | ((int32_t)window[i*3+1] << 8) | (int32_t)window[i*3];
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

    /* Sliding window for trigger detection - require 60% of chunks above threshold */
    unsigned window_size = sustain_chunks_needed;
    unsigned *window = (unsigned*)calloc(window_size, sizeof(unsigned));
    unsigned window_pos = 0;
    unsigned window_above = 0;
    bool window_full = false;
    const unsigned trigger_pct = 60;

    unsigned below_cnt = 0;
    bool recording = false;
    
    /* Position-based tracking */
    size_t write_cursor = 0;      /* absolute frame we've written up to */
    time_t segment_start_time = 0; /* timestamp of write_cursor */
    
    const size_t max_file_frames = cfg->max_file_sec > 0 ? (size_t)cfg->max_file_sec * cfg->rate : 0;

    const char *fmt_str = cfg->format ? cfg->format : "wav";
    logmsg("wrt","started: thr=%u sustain=%.2fs silence=%.2fs format=%s outdir=%s",
           cfg->threshold, cfg->sustain_sec, cfg->silence_sec, 
           fmt_str, cfg->outdir ? cfg->outdir : ".");

    while (g_running) {
        size_t peek = asyncwr_copy_last(&app->aw, chunk, FR);
        unsigned peak = 0;
        unsigned avg = analyze_samples(chunk, peek, cfg->channels, cfg->bytes_per_sample, &peak);
        
        /* Music detection */
        const unsigned min_peak = 400;
        const unsigned min_avg = 60;
        int is_musical = (peak >= min_peak) && (avg >= min_avg) && (avg >= cfg->threshold);
        
        vlogmsg("wrt","avg=%u peak=%u musical=%d recording=%d", avg, peak, is_musical, (int)recording);

        if (!recording) {
            /* Update sliding window */
            unsigned is_above = is_musical ? 1 : 0;
            if (window_full) {
                window_above -= window[window_pos];
            }
            window[window_pos] = is_above;
            window_above += is_above;
            window_pos = (window_pos + 1) % window_size;
            if (window_pos == 0) window_full = true;

            unsigned effective_size = window_full ? window_size : window_pos;
            unsigned required = (effective_size * trigger_pct) / 100;
            
            /* Log progress towards trigger */
            static unsigned last_pct = 0;
            unsigned current_pct = effective_size > 0 ? (window_above * 100) / effective_size : 0;
            if (current_pct >= 50 && (current_pct / 10 != last_pct / 10)) {
                logmsg("wrt","trigger progress: %u%% above threshold (%u/%u) avg=%u", 
                       current_pct, window_above, effective_size, avg);
                last_pct = current_pct;
            }
            if (current_pct < 50) last_pct = 0;

            if (window_full && window_above >= required && peek > 0) {
                /* TRIGGER: start recording from oldest available data (prebuffer) */
                size_t current_pos = asyncwr_position(&app->aw);
                
                /* Oldest frame still in ring buffer */
                pthread_mutex_lock(&app->aw.mu);
                size_t oldest = (app->aw.total_written > app->aw.capacity) 
                                ? (app->aw.total_written - app->aw.capacity) : 0;
                
                /* Continue gapless if write_cursor still valid, else start from oldest */
                if (write_cursor < oldest) {
                    if (write_cursor > 0) {
                        logmsg("wrt","WARNING: lost %zu frames (%.1f sec), resuming from oldest",
                               oldest - write_cursor, (double)(oldest - write_cursor) / cfg->rate);
                    }
                    write_cursor = oldest;
                }
                /* else: continuing gapless from write_cursor */
                
                size_t prebuffer_frames = current_pos - write_cursor;
                segment_start_time = time(NULL) - (time_t)(prebuffer_frames / cfg->rate);
                pthread_mutex_unlock(&app->aw.mu);
                
                const char *ext = (cfg->format && strcmp(cfg->format, "flac") == 0) ? "flac" : "wav";
                build_audio_filename(app->current_wav, sizeof(app->current_wav), 
                                     cfg->outdir, cfg->prefix, ext, segment_start_time);
                
                recording = true;
                below_cnt = 0;
                
                logmsg("wrt","TRIGGER avg=%u (prebuffer %.1f sec, cursor=%zu)", 
                       avg, (double)prebuffer_frames / cfg->rate, write_cursor);
                
                /* Reset sliding window */
                memset(window, 0, window_size * sizeof(unsigned));
                window_pos = 0;
                window_above = 0;
                window_full = false;
            }
        } else {
            /* Recording: check for split or silence */
            size_t current_pos = asyncwr_position(&app->aw);
            size_t frames_since_cursor = current_pos - write_cursor;
            
            /* Check if we need to split */
            if (max_file_frames > 0 && frames_since_cursor >= max_file_frames) {
                logmsg("wrt","SPLIT: writing frames %zu-%zu (%.1f min)", 
                       write_cursor, current_pos, (double)frames_since_cursor / cfg->rate / 60.0);
                
                asyncwr_write_range(&app->aw, write_cursor, current_pos, segment_start_time);
                
                /* Advance cursor */
                write_cursor = current_pos;
                segment_start_time = time(NULL);
                
                const char *ext = (cfg->format && strcmp(cfg->format, "flac") == 0) ? "flac" : "wav";
                build_audio_filename(app->current_wav, sizeof(app->current_wav), 
                                     cfg->outdir, cfg->prefix, ext, segment_start_time);
            }

            /* Check for silence */
            const unsigned silence_peak_thr = 150;
            const unsigned silence_avg_thr = 25;
            int is_silence = (peak < silence_peak_thr) && (avg < silence_avg_thr);
            if (is_silence) { if (below_cnt < 0x7fffffff) below_cnt++; }
            else { below_cnt = 0; }

            if (below_cnt >= silence_chunks_needed) {
                /* STOP: write remaining audio */
                size_t final_pos = asyncwr_position(&app->aw);
                if (final_pos > write_cursor) {
                    logmsg("wrt","STOP: writing frames %zu-%zu", write_cursor, final_pos);
                    asyncwr_write_range(&app->aw, write_cursor, final_pos, segment_start_time);
                    write_cursor = final_pos;
                }
                recording = false;
                below_cnt = 0;
                app->current_wav[0] = '\0';
                logmsg("wrt","STOP (silence)");
            }
        }
        
        struct timespec ts = {.tv_sec=0,.tv_nsec=30*1000*1000};
        nanosleep(&ts, NULL);
    }

    /* Flush any remaining audio on shutdown */
    if (recording) {
        size_t final_pos = asyncwr_position(&app->aw);
        if (final_pos > write_cursor) {
            logmsg("wrt","SHUTDOWN: writing frames %zu-%zu", write_cursor, final_pos);
            asyncwr_write_range(&app->aw, write_cursor, final_pos, segment_start_time);
        }
        /* Wait for async write to complete */
        asyncwr_wait_pending(&app->aw);
    }
    free(window);
    free(chunk);
    logmsg("wrt","exit");
    return NULL;
}

static void usage(const char *argv0) {
    fprintf(stderr,
        "Usage: %s [options]\n"
        "  --device hw:2,1        ALSA device or network interface\n"
        "  --rate 48000           sample rate\n"
        "  --channels 2           channel count\n"
        "  --frames 1024          frames per read\n"
        "  --fingerprint-sec 12   seconds of audio to send to vibra\n"
        "  --min-rms 300          minimum RMS to attempt recognition\n"
        "  --interval 2           seconds between recognition attempts\n"
        "  --user-agent UA        override User-Agent header\n"
        "  --timezone TZ          override timezone (default Europe/Amsterdam)\n"
        "  --shazam-gap-sec 10    min seconds between Shazam lookups\n"
        "  --same-track-hold-sec 90  suppress lookups after a good match\n"
        "  --threshold 50         avg abs amplitude trigger for recording\n"
        "  --sustain-sec 1.0      seconds above threshold to start recording\n"
        "  --silence-sec 15       seconds below threshold to stop recording\n"
        "  --prefix capture       filename prefix\n"
        "  --outdir ./            output directory for audio files\n"
        "  --format wav           output format: 'wav' or 'flac'\n"
#if defined(HAVE_ALSA) && defined(HAVE_PCAP)
        "  --source TYPE          audio source: 'alsa' or 'slink' (required)\n"
#elif defined(HAVE_ALSA)
        "  --source TYPE          audio source: 'alsa' (required)\n"
#elif defined(HAVE_PCAP)
        "  --source TYPE          audio source: 'slink' (required)\n"
#else
        "  --source TYPE          no audio sources compiled in!\n"
#endif
        "  --bits 16              sample bit depth (16 or 24)\n"
        "  --max-file-sec 600     max seconds per file (0 = no limit)\n"
        "  --ring-sec N           ring buffer size (default = max-file-sec + 60)\n"
        "  --db tracks.db         SQLite database for track logging\n"
        "  --verbose              enable detailed logging\n",
        argv0);
}
static int parse_cli(int argc, char **argv, Config *cfg) {
    for (int i=1; i<argc; ++i) {
        const char *a = argv[i];
        if (!strcmp(a,"--device") && i+1<argc) cfg->device = argv[++i];
        else if (!strcmp(a,"--rate") && i+1<argc) cfg->rate = (unsigned)strtoul(argv[++i], NULL, 10);
        else if (!strcmp(a,"--channels") && i+1<argc) cfg->channels = (unsigned)strtoul(argv[++i], NULL, 10);
        else if (!strcmp(a,"--frames") && i+1<argc) cfg->frames_per_read = (unsigned)strtoul(argv[++i], NULL, 10);
        else if (!strcmp(a,"--fingerprint-sec") && i+1<argc) cfg->fingerprint_sec = (unsigned)strtoul(argv[++i], NULL, 10);
        else if (!strcmp(a,"--min-rms") && i+1<argc) cfg->min_rms = (unsigned)strtoul(argv[++i], NULL, 10);
        else if (!strcmp(a,"--interval") && i+1<argc) cfg->identify_interval_sec = (unsigned)strtoul(argv[++i], NULL, 10);
        else if (!strcmp(a,"--user-agent") && i+1<argc) cfg->user_agent = argv[++i];
        else if (!strcmp(a,"--timezone") && i+1<argc) cfg->timezone   = argv[++i];
        else if (!strcmp(a,"--shazam-gap-sec") && i+1<argc) cfg->shazam_gap_sec = (unsigned)strtoul(argv[++i], NULL, 10);
        else if (!strcmp(a,"--same-track-hold-sec") && i+1<argc) cfg->same_track_hold_sec = (unsigned)strtoul(argv[++i], NULL, 10);
        else if (!strcmp(a,"--threshold") && i+1<argc) cfg->threshold = (unsigned)strtoul(argv[++i], NULL, 10);
        else if (!strcmp(a,"--sustain-sec") && i+1<argc) cfg->sustain_sec = (float)atof(argv[++i]);
        else if (!strcmp(a,"--silence-sec") && i+1<argc) cfg->silence_sec = (float)atof(argv[++i]);
        else if (!strcmp(a,"--prefix") && i+1<argc) cfg->prefix = argv[++i];
        else if (!strcmp(a,"--source") && i+1<argc) cfg->source = argv[++i];
        else if (!strcmp(a,"--bits") && i+1<argc) { unsigned b = (unsigned)strtoul(argv[++i], NULL, 10); cfg->bytes_per_sample = (b == 24) ? 3 : 2; }
        else if (!strcmp(a,"--max-file-sec") && i+1<argc) cfg->max_file_sec = (unsigned)strtoul(argv[++i], NULL, 10);
        else if (!strcmp(a,"--ring-sec") && i+1<argc) cfg->ring_sec = (unsigned)strtoul(argv[++i], NULL, 10);
        else if (!strcmp(a,"--outdir") && i+1<argc) cfg->outdir = argv[++i];
        else if (!strcmp(a,"--format") && i+1<argc) cfg->format = argv[++i];
        else if (!strcmp(a,"--db") && i+1<argc) cfg->db_path = argv[++i];
        else if (!strcmp(a,"--verbose")) g_verbose = 1;
        else { usage(argv[0]); return -1; }
    }
    return 0;
}

static void on_signal(int sig) {
    (void)sig;
    g_running = 0;
#ifdef HAVE_PCAP
    if (g_pcap_handle) pcap_breakloop(g_pcap_handle);
#endif
#ifdef HAVE_ALSA
    if (g_alsa_handle) snd_pcm_abort(g_alsa_handle);
#endif
}

int main(int argc, char **argv) {
    setvbuf(stderr, NULL, _IONBF, 0);
    struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts);
    srand((unsigned)(ts.tv_nsec ^ ts.tv_sec));

    Config cfg = {
        .device = "default",
        .rate = 48000,
        .channels = 2,
        .frames_per_read = 1024,
        .fingerprint_sec = 12,
        .min_rms = 300,
        .identify_interval_sec = 2,
        .user_agent = NULL,
        .timezone = NULL,
        .shazam_gap_sec = 10,
        .same_track_hold_sec = 90,
        .threshold = 50,
        .sustain_sec = 1.0f,
        .silence_sec = 15.0f,
        .prefix = "capture",
        .source = NULL,           /* must be specified */
        .bytes_per_sample = 2,
        .max_file_sec = 600,  /* 10 minutes */
        .ring_sec = 0,        /* 0 = auto-size to max_file_sec */
        .outdir = NULL,       /* current directory */
        .format = "wav",      /* default to WAV */
    };
    if (parse_cli(argc, argv, &cfg) != 0) return 2;
    
    /* Validate required options */
    int source_valid = 0;
#ifdef HAVE_ALSA
    if (cfg.source && strcmp(cfg.source, "alsa") == 0) source_valid = 1;
#endif
#ifdef HAVE_PCAP
    if (cfg.source && strcmp(cfg.source, "slink") == 0) source_valid = 1;
#endif
    if (!source_valid) {
#if defined(HAVE_ALSA) && defined(HAVE_PCAP)
        logmsg("main", "--source is required: 'alsa' or 'slink'");
#elif defined(HAVE_ALSA)
        logmsg("main", "--source is required: 'alsa'");
#elif defined(HAVE_PCAP)
        logmsg("main", "--source is required: 'slink'");
#else
        logmsg("main", "no audio sources compiled in");
#endif
        return 2;
    }
    
    /* SLink is always 24-bit */
    if (cfg.source && !strcmp(cfg.source, "slink")) {
        cfg.bytes_per_sample = 3;
    }
    
    /* Ring buffer sizing - need headroom for async writes */
    unsigned min_ring_sec = cfg.max_file_sec > 0 ? cfg.max_file_sec + 60 : 600;
    if (cfg.ring_sec == 0) {
        cfg.ring_sec = min_ring_sec;
    } else if (cfg.max_file_sec > 0 && cfg.ring_sec <= cfg.max_file_sec) {
        logmsg("main", "--ring-sec (%u) must be > --max-file-sec (%u) to allow headroom for writes", 
               cfg.ring_sec, cfg.max_file_sec);
        return 2;
    }

    App app = {0};
    app.cfg = cfg;
    
    /* Initialize ring buffer */
    size_t ring_frames = (size_t)cfg.ring_sec * cfg.rate;
    if (asyncwr_init(&app.aw, cfg.channels, cfg.rate, cfg.bytes_per_sample,
                     ring_frames, cfg.outdir, cfg.prefix, cfg.format) != 0) {
        logmsg("main","audio buffer alloc failed"); return 1;
    }
    if (db_init(&app) != 0) {
        logmsg("main","database init failed"); asyncwr_free(&app.aw); return 1;
    }

    struct sigaction sa = {0};
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    logmsg("main","starting: dev=%s rate=%u ch=%u frames=%u fingerprint=%us interval=%us thr=%u sustain=%.2fs silence=%.2fs split=%us ring=%us verbose=%d shazam-gap=%us same-hold=%us",
           app.cfg.device, app.cfg.rate, app.cfg.channels, app.cfg.frames_per_read,
           app.cfg.fingerprint_sec, app.cfg.identify_interval_sec,
           app.cfg.threshold, app.cfg.sustain_sec, app.cfg.silence_sec, app.cfg.max_file_sec, 
           app.cfg.ring_sec, g_verbose,
           app.cfg.shazam_gap_sec, app.cfg.same_track_hold_sec);

    if (pthread_create(&app.th_cap, NULL, capture_main, &app) != 0) {
        logmsg("main","pthread cap failed"); asyncwr_free(&app.aw); return 1;
    }
    if (pthread_create(&app.th_id, NULL, id_main, &app) != 0) {
        logmsg("main","pthread id failed"); g_running=0; pthread_join(app.th_cap,NULL); asyncwr_free(&app.aw); return 1;
    }
    if (pthread_create(&app.th_wrt, NULL, writer_main, &app) != 0) {
        logmsg("main","pthread wrt failed"); g_running=0; pthread_join(app.th_cap,NULL); pthread_join(app.th_id,NULL); asyncwr_free(&app.aw); return 1;
    }

    while (g_running) {
        struct timespec snooze = {.tv_sec=1,.tv_nsec=0};
        nanosleep(&snooze, NULL);
    }

    pthread_join(app.th_cap, NULL);
    pthread_join(app.th_id, NULL);
    pthread_join(app.th_wrt, NULL);
    db_close(&app);
    asyncwr_free(&app.aw);
    logmsg("main","bye");
    return 0;
}
