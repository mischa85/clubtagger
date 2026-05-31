/*
 * shazam_thread.h - Shazam audio fingerprint identification thread
 */
#ifndef CLUBTAGGER_SHAZAM_THREAD_H
#define CLUBTAGGER_SHAZAM_THREAD_H

#include "../types.h"

/* Main Shazam thread entry point */
void *shazam_main(void *arg);

/* Per-channel Shazam buffer lifecycle.
 * shazam_init_channel allocates cs->id_buf and cs->id_buf_s16; returns 0 or -ENOMEM.
 * shazam_free_channel is safe on a partially-/never-initialized channel. */
int  shazam_init_channel(ChannelState *cs, const Config *cfg);
void shazam_free_channel(ChannelState *cs);

#endif /* CLUBTAGGER_SHAZAM_THREAD_H */
