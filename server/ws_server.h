/*
 * ws_server.h - WebSocket server for real-time CDJ data and track updates
 */
#ifndef CLUBTAGGER_WS_SERVER_H
#define CLUBTAGGER_WS_SERVER_H

#include "../types.h"
#include <stdint.h>
#include <stddef.h>

/* Main WebSocket server thread entry point */
void *ws_main(void *arg);

/* Broadcast raw Pro DJ Link packet to all connected WebSocket clients.
 * Called from prolink thread — must be thread-safe and non-blocking.
 * port_id: 0=keepalive(50000), 1=beat(50001), 2=status(50002)
 * src_ip: sender IP in network byte order */
void ws_broadcast_packet(uint8_t port_id, uint32_t src_ip,
                         const uint8_t *payload, size_t len);

/* Broadcast ANLZ waveform data for a specific device.
 * Called from prolink thread after fetching ANLZ file.
 * Frame type 0xFF distinguishes from CDJ packet frames (0/1/2). */
void ws_broadcast_waveform(uint8_t device_num, const uint8_t *data, size_t len);

#endif /* CLUBTAGGER_WS_SERVER_H */
