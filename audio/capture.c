/*
 * capture.c - Audio capture thread (dispatcher)
 */
#include "capture.h"
#include "../writer/async_writer.h"
#include "../common.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef __linux__
#include <sched.h>
#endif

int capture_init_channel(ChannelState *cs, const Config *cfg) {
    size_t cap_buf_size = (size_t)cfg->frames_per_read * cfg->channels * cfg->bytes_per_sample;
    cs->cap_buf = (uint8_t *)malloc(cap_buf_size);
    if (!cs->cap_buf) {
        logmsg("cap", "cap_buf alloc failed (%zu bytes)", cap_buf_size);
        return -ENOMEM;
    }
    return 0;
}

void capture_free_channel(ChannelState *cs) {
    free(cs->cap_buf);
    cs->cap_buf = NULL;
}

void *capture_main(void *arg) {
    App *app = (App *)arg;
    Config *cfg = &app->cfg;

#ifdef __linux__
    /* Set real-time priority to prevent starvation during FLAC encoding */
    struct sched_param param = {.sched_priority = sched_get_priority_max(SCHED_FIFO)};
    if (pthread_setschedparam(pthread_self(), SCHED_FIFO, &param) == 0) {
        vlogmsg("cap", "using SCHED_FIFO priority %d", param.sched_priority);
    } else {
        vlogmsg("cap", "SCHED_FIFO failed (run as root or grant CAP_SYS_NICE)");
    }
#endif

#if defined(HAVE_PCAP) || defined(HAVE_AF_XDP)
    if (!strcmp(cfg->source, "slink")) {
#ifdef HAVE_AF_XDP
        if (cfg->slink_backend && !strcmp(cfg->slink_backend, "afxdp")) {
            return capture_afxdp(arg);
        }
#endif
#ifdef HAVE_PCAP
        return capture_pcap(arg);
#endif
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
