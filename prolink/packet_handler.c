/*
 * packet_handler.c - Packet Capture Callback
 *
 * Main pcap callback for dispatching packets to appropriate handlers.
 */

#include "packet_handler.h"
#include "prolink.h"
#include "prolink_protocol.h"
#include "dbserver_protocol.h"
#include "nfs_client.h"
#include "dbserver.h"
#include "cdj_types.h"
#include "../common.h"
#include <string.h>

/*
 * ============================================================================
 * Packet Handler
 * ============================================================================
 */

void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    (void)user;
    
    if (h->caplen < ETHER_HDR_LEN + IP_HDR_MIN_LEN + 8) {
        return;
    }
    
    /* Check for IPv4 (EtherType 0x0800) */
    if (bytes[12] != 0x08 || bytes[13] != 0x00) {
        return;
    }
    
    const uint8_t *ip_hdr = bytes + ETHER_HDR_LEN;
    
    /* Check IP version and get header length */
    uint8_t ip_version = (ip_hdr[0] >> 4) & 0x0F;
    uint8_t ip_hdr_len = (ip_hdr[0] & 0x0F) * 4;
    
    if (ip_version != 4 || ip_hdr_len < IP_HDR_MIN_LEN) {
        return;
    }
    
    /* Extract IP addresses */
    uint32_t src_ip, dst_ip;
    memcpy(&src_ip, ip_hdr + 12, 4);
    memcpy(&dst_ip, ip_hdr + 16, 4);
    
    /* Check protocol: UDP (17) or TCP (6) */
    uint8_t protocol = ip_hdr[9];
    
    if (protocol == 6) {
        /* TCP packet - check for dbserver port 1051 */
        const uint8_t *tcp_hdr = ip_hdr + ip_hdr_len;
        uint16_t src_port = (tcp_hdr[0] << 8) | tcp_hdr[1];
        uint16_t dst_port = (tcp_hdr[2] << 8) | tcp_hdr[3];
        uint8_t tcp_hdr_len = ((tcp_hdr[12] >> 4) & 0x0F) * 4;
        
        if (tcp_hdr_len < TCP_HDR_MIN_LEN) return;
        
        /* Only process dbserver traffic */
        if (src_port == DBSERVER_PORT || dst_port == DBSERVER_PORT) {
            const uint8_t *payload = tcp_hdr + tcp_hdr_len;
            size_t offset = ETHER_HDR_LEN + ip_hdr_len + tcp_hdr_len;
            if (offset >= h->caplen) return;
            size_t payload_len = h->caplen - offset;
            
            if (verbose) {
                log_message("[TCP] DBserver: %s:%d -> %s:%d, %zu bytes",
                           ip_to_str(src_ip), src_port, 
                           ip_to_str(dst_ip), dst_port, payload_len);
            }
            
            if (payload_len > 20) {
                parse_dbserver_traffic(payload, payload_len, src_ip, dst_ip);
            }
        }
        return;
    }
    
    if (protocol != 17) {
        return;  /* Not UDP or TCP */
    }
    
    /* UDP packet processing */
    const uint8_t *udp_hdr = ip_hdr + ip_hdr_len;
    uint16_t src_port = (udp_hdr[0] << 8) | udp_hdr[1];
    uint16_t dst_port = (udp_hdr[2] << 8) | udp_hdr[3];
    uint16_t udp_len = (udp_hdr[4] << 8) | udp_hdr[5];
    
    /* Get UDP payload */
    const uint8_t *payload = udp_hdr + UDP_HDR_LEN;
    size_t payload_len = udp_len - UDP_HDR_LEN;
    
    /* Sanity check */
    size_t offset = ETHER_HDR_LEN + ip_hdr_len + UDP_HDR_LEN;
    if (offset + payload_len > h->caplen) {
        payload_len = h->caplen - offset;
    }
    
    /* Check for Pro DJ Link packets */
    if (payload_len >= PROLINK_SIG_LEN && is_prolink_packet(payload, payload_len)) {
        uint8_t pkt_type = get_prolink_packet_type(payload);
        
        if (verbose > 1) {
            log_message("[PROLINK] %s:%d -> %s:%d type=0x%02x len=%zu",
                       ip_to_str(src_ip), src_port, 
                       ip_to_str(dst_ip), dst_port,
                       pkt_type, payload_len);
        }
        
        if (dst_port == PROLINK_KEEPALIVE_PORT || src_port == PROLINK_KEEPALIVE_PORT) {
            parse_keepalive(payload, payload_len, src_ip);
        }
        else if (dst_port == PROLINK_STATUS_PORT || src_port == PROLINK_STATUS_PORT) {
            parse_cdj_status(payload, payload_len, src_ip);
        }
        else if (dst_port == PROLINK_BEAT_PORT || src_port == PROLINK_BEAT_PORT) {
            if (pkt_type == PKT_TYPE_BEAT) {
                parse_beat(payload, payload_len, src_ip);
            } else if (pkt_type == PKT_TYPE_CDJ_STATUS) {
                parse_cdj_status(payload, payload_len, src_ip);
            } else {
                parse_beat(payload, payload_len, src_ip);
            }
        }
    }
    /* Check for NFS traffic */
    else if (dst_port == 2049 || src_port == 2049) {
        if (payload_len >= 8) {
            uint32_t msg_type = (payload[4] << 24) | (payload[5] << 16) |
                                (payload[6] << 8) | payload[7];
            if (msg_type == 0) {
                parse_nfs_request(payload, payload_len, src_ip, dst_ip);
            } else if (msg_type == 1) {
                parse_nfs_response(payload, payload_len, src_ip, dst_ip);
            }
        }
    }
}
