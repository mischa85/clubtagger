/*
 * sse_server.h - Server-Sent Events for VU meter and track updates
 */
#ifndef CLUBTAGGER_SSE_SERVER_H
#define CLUBTAGGER_SSE_SERVER_H

#include "../types.h"

/* Main SSE server thread entry point */
void *sse_main(void *arg);

#endif /* CLUBTAGGER_SSE_SERVER_H */
