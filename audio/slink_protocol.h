/*
 * slink_protocol.h - SLink Audio over Ethernet Protocol
 *
 * SLink packets carry a single stereo audio sample per Ethernet frame.
 * This protocol is used by Allen & Heath SQ series mixers to send audio
 * over Ethernet (via the SLink port).
 *
 * Packet structure (30 bytes minimum):
 *   [0-5]   Destination MAC (usually 01:60:78:00:00:02)
 *   [6-11]  Source MAC
 *   [12-13] EtherType: 0x04EE (SLink)
 *   [14-18] Header (unknown fields)
 *   [19]    Sequence counter (lower 5 bits, cycles 0x00-0x1F)
 *   [20-23] Unknown
 *   [24-26] Channel 0 audio sample (24-bit signed, big-endian)
 *   [27-29] Channel 1 audio sample (24-bit signed, big-endian)
 */

#ifndef SLINK_PROTOCOL_H
#define SLINK_PROTOCOL_H

#include <stdint.h>

/* SLink EtherType */
#define SLINK_ETHERTYPE_HI      0x04
#define SLINK_ETHERTYPE_LO      0xEE
#define SLINK_ETHERTYPE         0x04EE

/* Minimum packet length for valid audio */
#define SLINK_MIN_LEN           30

/* Sequence counter mask (lower 5 bits) */
#define SLINK_SEQ_MASK          0x1F

/* SLink packet header (packed for direct overlay on packet data) */
typedef struct __attribute__((packed)) {
    uint8_t  dst_mac[6];         /* [0-5]   Destination MAC */
    uint8_t  src_mac[6];         /* [6-11]  Source MAC */
    uint8_t  ethertype_hi;       /* [12]    EtherType high byte (0x04) */
    uint8_t  ethertype_lo;       /* [13]    EtherType low byte (0xEE) */
    uint8_t  header[5];          /* [14-18] Unknown header fields */
    uint8_t  seq;                /* [19]    Sequence counter (lower 5 bits valid) */
    uint8_t  reserved[4];        /* [20-23] Unknown */
    uint8_t  ch0[3];             /* [24-26] Channel 0: 24-bit signed BE */
    uint8_t  ch1[3];             /* [27-29] Channel 1: 24-bit signed BE */
} slink_packet_t;

/* Verify packet is valid SLink */
static inline int slink_is_valid(const uint8_t *pkt, uint32_t len) {
    if (len < SLINK_MIN_LEN) return 0;
    const slink_packet_t *s = (const slink_packet_t *)pkt;
    return s->ethertype_hi == SLINK_ETHERTYPE_HI && 
           s->ethertype_lo == SLINK_ETHERTYPE_LO;
}

/* Get sequence number (0-31) */
static inline uint8_t slink_get_seq(const slink_packet_t *pkt) {
    return pkt->seq & SLINK_SEQ_MASK;
}

/* Convert 24-bit big-endian to little-endian into output buffer
 * out must point to a 6-byte buffer for stereo frame */
static inline void slink_to_le24_stereo(const slink_packet_t *pkt, uint8_t *out) {
    /* Channel 0: swap byte order */
    out[0] = pkt->ch0[2];
    out[1] = pkt->ch0[1];
    out[2] = pkt->ch0[0];
    /* Channel 1: swap byte order */
    out[3] = pkt->ch1[2];
    out[4] = pkt->ch1[1];
    out[5] = pkt->ch1[0];
}

#endif /* SLINK_PROTOCOL_H */
