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
#include <pthread.h>
#include <sched.h>
#include <unistd.h>
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
    /* Real-time priority so FLAC encoding, nginx and the like can never
     * starve capture. 80, not the maximum: high enough to beat every normal
     * process, low enough to stay below the kernel's own real-time threads
     * (migration, watchdog) that must keep running. */
    struct sched_param param = {.sched_priority = 80};
    if (param.sched_priority > sched_get_priority_max(SCHED_FIFO)) param.sched_priority = sched_get_priority_max(SCHED_FIFO);
    if (pthread_setschedparam(pthread_self(), SCHED_FIFO, &param) == 0) {
        vlogmsg("cap", "using SCHED_FIFO priority %d", param.sched_priority);
    } else {
        vlogmsg("cap", "SCHED_FIFO failed (run as root or grant CAP_SYS_NICE)");
    }

    /* Own core: main() pinned every other thread to CPU 0 and rt-tuning.sh
     * steers the SLink NIC interrupt to CPU 1, so the driver's receive path
     * and this thread share a core that nothing else uses. */
    if (sysconf(_SC_NPROCESSORS_ONLN) >= 2) {
        cpu_set_t set;
        CPU_ZERO(&set);
        CPU_SET(1, &set);
        if (pthread_setaffinity_np(pthread_self(), sizeof(set), &set) == 0) {
            vlogmsg("cap", "pinned to CPU 1");
        } else {
            logmsg("cap", "pthread_setaffinity_np(CPU 1) failed: %s", strerror(errno));
        }
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
