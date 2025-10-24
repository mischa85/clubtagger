#include <alsa/asoundlib.h>
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
static TrackID majority_vote(Vote v[3]) {
    TrackID r = {0};
    TrackID a = {0}, b = {0}, c = {0};
    if (v[0].valid){ a.valid=1; snprintf(a.isrc, sizeof(a.isrc), "%s", v[0].isrc); snprintf(a.artist, sizeof(a.artist), "%s", v[0].artist); snprintf(a.title, sizeof(a.title), "%s", v[0].title); a.has_isrc = a.isrc[0]!=0; }
    if (v[1].valid){ b.valid=1; snprintf(b.isrc, sizeof(b.isrc), "%s", v[1].isrc); snprintf(b.artist, sizeof(b.artist), "%s", v[1].artist); snprintf(b.title, sizeof(b.title), "%s", v[1].title); b.has_isrc = b.isrc[0]!=0; }
    if (v[2].valid){ c.valid=1; snprintf(c.isrc, sizeof(c.isrc), "%s", v[2].isrc); snprintf(c.artist, sizeof(c.artist), "%s", v[2].artist); snprintf(c.title, sizeof(c.title), "%s", v[2].title); c.has_isrc = c.isrc[0]!=0; }
    if (same_track(&a,&b)) return a;
    if (same_track(&a,&c)) return a;
    if (same_track(&b,&c)) return b;
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
} Config;

typedef struct {
    int16_t        *data;
    size_t          frames_capacity;
    size_t          channels;
    size_t          write_pos;
    size_t          read_pos;
    size_t          total_written;
    pthread_mutex_t mu;
} Ring;

static int ring_init(Ring *r, size_t frames_capacity, size_t channels) {
    r->data = (int16_t*)calloc(frames_capacity * channels, sizeof(int16_t));
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
static void ring_write(Ring *r, const int16_t *frames, size_t nframes) {
    pthread_mutex_lock(&r->mu);
    const size_t ch = r->channels;
    size_t wp = r->write_pos;
    for (size_t i=0; i<nframes; ++i) {
        size_t idx = (wp % r->frames_capacity) * ch;
        memcpy(&r->data[idx], &frames[i * ch], ch * sizeof(int16_t));
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
static size_t ring_read(Ring *r, int16_t *dst, size_t max_frames) {
    pthread_mutex_lock(&r->mu);
    size_t avail = ring_available_locked(r);
    if (avail == 0) { pthread_mutex_unlock(&r->mu); return 0; }
    size_t take = (avail < max_frames) ? avail : max_frames;
    const size_t ch = r->channels;
    for (size_t i=0; i<take; ++i) {
        size_t idx = (r->read_pos % r->frames_capacity) * ch;
        memcpy(&dst[i * ch], &r->data[idx], ch * sizeof(int16_t));
        r->read_pos = (r->read_pos + 1) % r->frames_capacity;
    }
    pthread_mutex_unlock(&r->mu);
    return take;
}
static size_t ring_copy_last(Ring *r, int16_t *dst, size_t nframes) {
    pthread_mutex_lock(&r->mu);
    const size_t cap = r->frames_capacity;
    const size_t ch  = r->channels;
    size_t have = (r->total_written < cap) ? r->total_written : cap;
    size_t take = (have < nframes) ? have : nframes;
    size_t start = (r->write_pos >= take) ? (r->write_pos - take)
                                          : (cap - ((take - r->write_pos) % cap)) % cap;
    for (size_t i=0; i<take; ++i) {
        size_t idx = ((start + i) % cap) * ch;
        memcpy(&dst[i * ch], &r->data[idx], ch * sizeof(int16_t));
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

static int wav_finalize(WavFile *wf, unsigned channels, unsigned rate) {
    if (!wf->fp) return 0;
    long file_size = ftell(wf->fp);
    if (file_size < 44) { fclose(wf->fp); wf->fp=NULL; unlink(wf->tmp_name); return -1; }

    uint32_t data_bytes = (uint32_t)(file_size - 44);
    uint16_t audio_format = 1;
    uint16_t num_channels = (uint16_t)channels;
    uint32_t sample_rate  = rate;
    uint16_t bits_per_sample = 16;
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
    le16_write(bits_per_sample, wf->fp);
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
} App;

static void *capture_main(void *arg) {
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
    snd_pcm_hw_params_set_format(pcm, p, SND_PCM_FORMAT_S16_LE);
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
    int16_t *buf = (int16_t*)malloc(sizeof(int16_t) * FR * cfg->channels);
    if (!buf) { logmsg("cap","oom"); snd_pcm_close(pcm); g_running=0; return NULL; }

    logmsg("cap","started: rate=%u ch=%u period=%lu", cfg->rate, cfg->channels, (unsigned long)period);
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
    logmsg("cap","exit");
    return NULL;
}

static void *id_main(void *arg) {
    App *app = (App*)arg;
    Config *cfg = &app->cfg;

    const size_t look_frames = (size_t)cfg->fingerprint_sec * cfg->rate;
    int16_t *window = (int16_t*)malloc(sizeof(int16_t) * look_frames * cfg->channels);
    if (!window) { logmsg("id","oom"); return NULL; }

    logmsg("id","started: fingerprint=%us interval=%us min_rms=%u",
           cfg->fingerprint_sec, cfg->identify_interval_sec, cfg->min_rms);

    time_t last_lookup = 0;
    time_t last_good_match = 0;
    Vote votes[3] = {0}; int vpos = 0; TrackID current = {0};

    while (g_running) {
        size_t got = ring_copy_last(&app->ring, window, look_frames);
        unsigned r = rms_s16_interleaved(window, got, cfg->channels);
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
                (const char*)window, bytes, (int)cfg->rate, 16, (int)cfg->channels);
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
                        char title[256]={0}, artist[256]={0}, isrc[64]={0};
                        json_extract_field(json, "title", title, sizeof(title));
                        json_extract_field(json, "subtitle", artist, sizeof(artist));
                        if (!artist[0]) json_extract_field(json, "artist", artist, sizeof(artist));
                        json_extract_field(json, "isrc", isrc, sizeof(isrc));

                        if (title[0] || artist[0] || isrc[0]) {
                            votes[vpos].valid = 1;
                            snprintf(votes[vpos].isrc, sizeof(votes[vpos].isrc), "%s", isrc);
                            snprintf(votes[vpos].artist, sizeof(votes[vpos].artist), "%s", artist);
                            snprintf(votes[vpos].title, sizeof(votes[vpos].title), "%s", title);
                            votes[vpos].t = time(NULL);
                            vpos = (vpos + 1) % 3;
                            TrackID maj = majority_vote(votes);
                            if (maj.valid) {
                                if (!current.valid || !same_track(&maj, &current)) {
                                    static TrackID pending = {0}; static int pending_ok = 0;
                                    if (!pending.valid || !same_track(&pending, &maj)) {
                                        pending = maj; pending_ok = 1;
                                        vlogmsg("id","candidate: %s — %s", maj.artist, maj.title);
                                    } else if (pending_ok) {
                                        current = maj; pending.valid = 0; pending_ok = 0;
                                        last_good_match = time(NULL);
                                        char tsbuf[64]; now_timestamp(tsbuf, sizeof(tsbuf));
                                        if (current.has_isrc) logmsg("id","%s MATCH: %s — %s [ISRC %s]", tsbuf, current.artist, current.title, current.isrc);
                                        else                 logmsg("id","%s MATCH: %s — %s", tsbuf, current.artist, current.title);
                                    }
                                } else {
                                    last_good_match = time(NULL);
                                    vlogmsg("id","hold current: %s — %s", current.artist, current.title);
                                }
                            } else {
                                vlogmsg("id","no majority yet");
                            }
                        } else {
                            json[200] = 0;
                            logmsg("id","no match (json preview): %s", json);
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
    int16_t *chunk = (int16_t*)malloc(sizeof(int16_t) * FR * cfg->channels);
    if (!chunk) { logmsg("wrt","oom"); return NULL; }

    const unsigned sustain_chunks_needed = (unsigned)((cfg->sustain_sec * cfg->rate + (FR-1)) / FR);
    const unsigned silence_chunks_needed = (unsigned)((cfg->silence_sec * cfg->rate + (FR-1)) / FR);
    const size_t prebuffer_frames = (size_t)cfg->prebuffer_sec * cfg->rate;

    unsigned above_cnt = 0;
    unsigned below_cnt = 0;
    bool recording = false;
    WavFile wf = {0};

    logmsg("wrt","started: thr=%u sustain=%.2fs prebuffer=%us silence=%.2fs",
           cfg->threshold, cfg->sustain_sec, cfg->prebuffer_sec, cfg->silence_sec);

    while (g_running) {
        size_t peek = ring_copy_last(&app->ring, chunk, FR);
        unsigned avg = avg_abs_s16(chunk, peek, cfg->channels);
        vlogmsg("wrt","avg=%u thr=%u recording=%d above=%u below=%u", avg, cfg->threshold, (int)recording, above_cnt, below_cnt);

        if (!recording) {
            if (avg >= cfg->threshold) { if (above_cnt < 0x7fffffff) above_cnt++; }
            else { above_cnt = 0; }

            if (above_cnt >= sustain_chunks_needed && peek > 0) {
                pthread_mutex_lock(&app->ring.mu);
                size_t wp = app->ring.write_pos;
                size_t cap = app->ring.frames_capacity;
                size_t avail = (app->ring.total_written < cap) ? app->ring.total_written : cap;
                size_t want_pre = prebuffer_frames; if (want_pre > avail) want_pre = avail;
                size_t start = (wp >= want_pre) ? (wp - want_pre)
                                                : (cap - ((want_pre - wp) % cap)) % cap;
                pthread_mutex_unlock(&app->ring.mu);

                time_t trigger_ts = time(NULL);
                if (wav_open_at(&wf, cfg->prefix, cfg->channels, cfg->rate, trigger_ts - (time_t)(want_pre / cfg->rate)) == 0) {
                    pthread_mutex_lock(&app->ring.mu);
                    size_t cursor = start;
                    while (cursor != wp) {
                        size_t idx = (cursor % app->ring.frames_capacity) * app->ring.channels;
                        fwrite(&app->ring.data[idx], sizeof(int16_t), app->ring.channels, wf.fp);
                        cursor = (cursor + 1) % app->ring.frames_capacity;
                    }
                    app->ring.read_pos = wp;
                    pthread_mutex_unlock(&app->ring.mu);
                    fflush(wf.fp);
                    recording = true;
                    below_cnt = 0;
                    logmsg("wrt","TRIGGER avg=%u (prebuffer %zu frames)", avg, want_pre);
                } else {
                    logmsg("wrt","failed to open wav");
                }
                above_cnt = 0;
            }
        } else {
            size_t got = ring_read(&app->ring, chunk, FR);
            if (got > 0 && wf.fp) {
                fwrite(chunk, sizeof(int16_t) * cfg->channels, got, wf.fp);
                static unsigned cnt = 0; if ((++cnt & 0x1F)==0) { fflush(wf.fp); int fd=fileno(wf.fp); if (fd>=0) fsync(fd); }
            } else {
                struct timespec ts = {.tv_sec=0,.tv_nsec=50*1000*1000};
                nanosleep(&ts, NULL);
            }

            size_t p2 = ring_copy_last(&app->ring, chunk, FR);
            unsigned avg2 = avg_abs_s16(chunk, p2, cfg->channels);
            if (avg2 < cfg->threshold) { if (below_cnt < 0x7fffffff) below_cnt++; }
            else { below_cnt = 0; }

            if (below_cnt >= silence_chunks_needed) {
                if (wf.fp) { fflush(wf.fp); wav_finalize(&wf, cfg->channels, cfg->rate); }
                recording = false;
                below_cnt = 0;
                logmsg("wrt","STOP (silence)");
            }
        }
        struct timespec ts = {.tv_sec=0,.tv_nsec=30*1000*1000};
        nanosleep(&ts, NULL);
    }

    if (recording && wf.fp) { fflush(wf.fp); wav_finalize(&wf, cfg->channels, cfg->rate); }
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
        "  --threshold 200        avg abs amplitude trigger for WAV writer\n"
        "  --sustain-sec 2.0      seconds above threshold to start recording\n"
        "  --prebuffer-sec 5      seconds of audio to include before trigger\n"
        "  --silence-sec 3.0      seconds below threshold to stop recording\n"
        "  --prefix capture       WAV filename prefix\n"
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
        .threshold = 200,
        .sustain_sec = 2.0f,
        .prebuffer_sec = 5,
        .silence_sec = 3.0f,
        .prefix = "capture",
    };
    if (parse_cli(argc, argv, &cfg) != 0) return 2;

    App app = {0};
    app.cfg = cfg;
    size_t ring_frames = (size_t)app.cfg.rate * app.cfg.ring_sec;
    if (ring_init(&app.ring, ring_frames, app.cfg.channels) != 0) {
        logmsg("main","ring alloc failed"); return 1;
    }

    struct sigaction sa = {0};
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    logmsg("main","starting: dev=%s rate=%u ch=%u frames=%u ring=%us fingerprint=%us interval=%us thr=%u sustain=%.2fs prebuffer=%us silence=%.2fs verbose=%d shazam-gap=%us same-hold=%us",
           app.cfg.device, app.cfg.rate, app.cfg.channels, app.cfg.frames_per_read,
           app.cfg.ring_sec, app.cfg.fingerprint_sec, app.cfg.identify_interval_sec,
           app.cfg.threshold, app.cfg.sustain_sec, app.cfg.prebuffer_sec, app.cfg.silence_sec, g_verbose,
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
    ring_free(&app.ring);
    logmsg("main","bye");
    return 0;
}
