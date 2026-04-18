/*
 * capture_alsa.c - ALSA audio capture
 */
#include "capture.h"

#ifdef HAVE_ALSA

#include "../writer/async_writer.h"
#include "../common.h"

#include <alsa/asoundlib.h>
#include <time.h>

void *capture_alsa(void *arg) {
    App *app = (App *)arg;
    Config *cfg = &app->cfg;

    vlogmsg("cap", "opening ALSA on %s", cfg->device);
    snd_pcm_t *pcm = NULL;
    int err = snd_pcm_open(&pcm, cfg->device, SND_PCM_STREAM_CAPTURE, 0);
    if (err < 0) {
        logmsg("cap", "open %s: %s", cfg->device, snd_strerror(err));
        g_running = 0;
        return NULL;
    }

    snd_pcm_hw_params_t *p = NULL;
    snd_pcm_hw_params_malloc(&p);
    snd_pcm_hw_params_any(pcm, p);
    snd_pcm_hw_params_set_access(pcm, p, SND_PCM_ACCESS_RW_INTERLEAVED);
    snd_pcm_format_t fmt = (cfg->bytes_per_sample == 3) ? SND_PCM_FORMAT_S24_3LE : SND_PCM_FORMAT_S16_LE;
    snd_pcm_hw_params_set_format(pcm, p, fmt);
    snd_pcm_hw_params_set_channels(pcm, p, cfg->channels);
    unsigned rate = cfg->rate;
    snd_pcm_hw_params_set_rate_near(pcm, p, &rate, 0);
    snd_pcm_uframes_t period = cfg->frames_per_read;
    snd_pcm_uframes_t buffer = period * 4;
    snd_pcm_hw_params_set_period_size_near(pcm, p, &period, 0);
    snd_pcm_hw_params_set_buffer_size_near(pcm, p, &buffer);
    err = snd_pcm_hw_params(pcm, p);
    snd_pcm_hw_params_free(p);
    if (err < 0) {
        logmsg("cap", "hw_params: %s", snd_strerror(err));
        snd_pcm_close(pcm);
        g_running = 0;
        return NULL;
    }
    snd_pcm_prepare(pcm);
    g_alsa_handle = pcm; /* allow signal handler to abort */

    cfg->rate = rate;
    const size_t FR = cfg->frames_per_read;
    const size_t fb = cfg->channels * cfg->bytes_per_sample;
    (void)fb;
    uint8_t *buf = app->ch[0].cap_buf;

    logmsg("cap", "started: rate=%u ch=%u period=%lu bits=%d (ALSA)", cfg->rate, cfg->channels, (unsigned long)period, cfg->bytes_per_sample * 8);
    while (g_running) {
        snd_pcm_sframes_t got = snd_pcm_readi(pcm, buf, FR);
        if (got < 0) {
            got = snd_pcm_recover(pcm, (int)got, 1);
            if (got < 0) {
                struct timespec _ts = {.tv_sec = 0, .tv_nsec = 100 * 1000 * 1000};
                nanosleep(&_ts, NULL);
                continue;
            }
            continue;
        }
        if (got > 0) asyncwr_append(&app->ch[0].aw, buf, (size_t)got);
    }

    g_alsa_handle = NULL; /* prevent signal handler from using closed handle */
    snd_pcm_close(pcm);
    logmsg("cap", "exit");
    return NULL;
}

#endif /* HAVE_ALSA */
