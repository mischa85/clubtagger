/*
 * writer_thread.h - Async audio file writer thread
 */
#ifndef CLUBTAGGER_WRITER_THREAD_H
#define CLUBTAGGER_WRITER_THREAD_H

#include "../types.h"

/* Main writer thread entry point */
void *writer_main(void *arg);

#endif /* CLUBTAGGER_WRITER_THREAD_H */
