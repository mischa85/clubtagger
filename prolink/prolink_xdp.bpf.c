/* SPDX-License-Identifier: GPL-2.0 */
/*
 * XDP BPF program for Pro DJ Link packet capture
 * 
 * Filters packets for Pro DJ Link protocol and related traffic:
 * - UDP 50000-50002: Pro DJ Link keepalive, status, beat sync
 * - UDP 2049: NFS (CDJ database access)
 * - TCP 1051: dbserver (CDJ metadata queries)
 *
 * Designed for SPAN port capture where we observe CDJ-to-CDJ traffic.
 * All matching packets are redirected to AF_XDP socket for userspace processing.
 *
 * Compile with:
 *   clang -O2 -target bpf -c prolink_xdp.bpf.c -o prolink_xdp.bpf.o
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* Pro DJ Link ports */
#define PROLINK_KEEPALIVE_PORT  50000
#define PROLINK_STATUS_PORT     50001
#define PROLINK_BEAT_PORT       50002

/* NFS port (for passive eavesdropping on CDJ database access) */
#define NFS_PORT                2049

/* dbserver port (CDJ metadata query protocol) */
#define DBSERVER_PORT           1051

/* XSK map - AF_XDP sockets register here */
struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
    __uint(max_entries, 64);
} prolink_xsks_map SEC(".maps");

/* Check if UDP packet matches our filter */
static __always_inline int check_udp_ports(struct udphdr *udp)
{
    __u16 sport = bpf_ntohs(udp->source);
    __u16 dport = bpf_ntohs(udp->dest);
    
    /* Pro DJ Link traffic */
    if (dport == PROLINK_KEEPALIVE_PORT ||
        dport == PROLINK_STATUS_PORT ||
        dport == PROLINK_BEAT_PORT)
        return 1;
    
    /* NFS traffic (either direction) */
    if (sport == NFS_PORT || dport == NFS_PORT)
        return 1;
    
    return 0;
}

/* Check if TCP packet matches our filter */
static __always_inline int check_tcp_ports(struct tcphdr *tcp)
{
    __u16 sport = bpf_ntohs(tcp->source);
    __u16 dport = bpf_ntohs(tcp->dest);
    
    /* dbserver traffic (either direction) */
    if (sport == DBSERVER_PORT || dport == DBSERVER_PORT)
        return 1;
    
    return 0;
}

SEC("xdp")
int prolink_xdp_prog(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    
    /* Bounds check for ethernet header */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    
    /* Only process IPv4 */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;
    
    /* Bounds check for IP header */
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    
    /* Calculate IP header length (IHL is in 32-bit words) */
    unsigned int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(*ip))
        return XDP_PASS;
    
    /* Handle UDP */
    if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + ip_hdr_len;
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;
        
        if (check_udp_ports(udp))
            return bpf_redirect_map(&prolink_xsks_map, ctx->rx_queue_index, XDP_PASS);
    }
    /* Handle TCP */
    else if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + ip_hdr_len;
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
        
        if (check_tcp_ports(tcp))
            return bpf_redirect_map(&prolink_xsks_map, ctx->rx_queue_index, XDP_PASS);
    }
    
    /* Pass all other packets to kernel */
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
