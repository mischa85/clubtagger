/*
 * capture.c - Audio capture thread (dispatcher)
 */
#include "capture.h"
#include "../writer/async_writer.h"
#include "../common.h"

#include <string.h>
#include <time.h>

#ifdef __linux__
#include <sched.h>
#endif

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
