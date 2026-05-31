/*
 * capture.h - Audio capture thread interface
 */
#ifndef CLUBTAGGER_CAPTURE_H
#define CLUBTAGGER_CAPTURE_H

#include "../types.h"

/* Main capture thread entry point - dispatches to appropriate backend */
void *capture_main(void *arg);

/* Per-channel capture buffer lifecycle.
 * capture_init_channel allocates cs->cap_buf; returns 0 or -ENOMEM.
 * capture_free_channel is safe on a partially-/never-initialized channel. */
int  capture_init_channel(ChannelState *cs, const Config *cfg);
void capture_free_channel(ChannelState *cs);

#ifdef HAVE_PCAP
/* S/PDIF capture via libpcap */
void *capture_pcap(void *arg);
#endif

#ifdef HAVE_ALSA
/* ALSA audio capture */
void *capture_alsa(void *arg);
#endif

#ifdef HAVE_AF_XDP
/* AF_XDP high-performance capture */
void *capture_afxdp(void *arg);
#endif

#endif /* CLUBTAGGER_CAPTURE_H */
