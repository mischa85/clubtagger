/*
 * writer_thread.h - Async audio file writer thread
 */
#ifndef CLUBTAGGER_WRITER_THREAD_H
#define CLUBTAGGER_WRITER_THREAD_H

#include "../types.h"

/* Main writer thread entry point */
void *writer_main(void *arg);

/* Per-channel writer buffer lifecycle.
 * writer_init_channel allocates cs->wrt_buf and cs->wrt_window; returns 0 or -ENOMEM.
 * writer_free_channel is safe on a partially-/never-initialized channel. */
int  writer_init_channel(ChannelState *cs, const Config *cfg);
void writer_free_channel(ChannelState *cs);

#endif /* CLUBTAGGER_WRITER_THREAD_H */
