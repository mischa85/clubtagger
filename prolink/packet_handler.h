/*
 * packet_handler.h - Packet Capture Callback
 *
 * Main packet callback for dispatching packets to appropriate handlers.
 * Supports both pcap and AF_XDP capture backends.
 */

#ifndef PACKET_HANDLER_H
#define PACKET_HANDLER_H

#include <sys/types.h>
#include <sys/time.h>

/*
 * ============================================================================
 * Packet Header (pcap-compatible)
 * ============================================================================
 */

#ifdef HAVE_PCAP
#include <pcap/pcap.h>
#else
/* pcap_pkthdr-compatible struct for AF_XDP-only builds */
struct pcap_pkthdr {
    struct timeval ts;    /* timestamp */
    uint32_t caplen;      /* captured length */
    uint32_t len;         /* original length */
};
typedef unsigned char u_char;
#endif

/*
 * ============================================================================
 * Packet Handler
 * ============================================================================
 */

/* Main packet callback - dispatches to protocol handlers */
void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);

/*
 * ============================================================================
 * Pcap Filter (for pcap backend)
 * ============================================================================
 */

/* BPF filter for Pro DJ Link and NFS traffic */
#define PCAP_FILTER \
    "udp port 50000 or udp port 50001 or udp port 50002 " \
    "or udp port 2049 or tcp port 1051"

#endif /* PACKET_HANDLER_H */
