/* SPDX-License-Identifier: GPL-2.0 */
/*
 * XDP BPF program for Pro DJ Link packet capture
 * 
 * Filters UDP packets for Pro DJ Link protocol:
 * - UDP 50000-50002: Pro DJ Link keepalive, status, beat sync
 *
 * NOTE: TCP (dbserver port 1051) is NOT filtered here!
 * The dbserver_client.c uses kernel TCP sockets for queries.
 * Redirecting TCP to AF_XDP would prevent kernel sockets from receiving responses.
 *
 * NOTE: NFS traffic (port 2049) is also NOT filtered here.
 * The nfs_client.c uses kernel UDP sockets for active NFS requests.
 *
 * This filter only handles PASSIVE UDP capture (announcements, status, beats).
 * All active connections (TCP dbserver, UDP NFS) use kernel sockets.
 *
 * Designed for SPAN port capture where we observe CDJ-to-CDJ traffic.
 *
 * Compile with:
 *   clang -O2 -target bpf -c prolink_xdp.bpf.c -o prolink_xdp.bpf.o
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* Pro DJ Link ports */
#define PROLINK_KEEPALIVE_PORT  50000
#define PROLINK_BEAT_PORT       50001
#define PROLINK_STATUS_PORT     50002

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
    
    /* Pro DJ Link traffic - check BOTH source and destination ports!
     * CDJs send status packets FROM port 50001, not TO port 50001.
     * Keepalives and beat packets have similar patterns. */
    if (dport == PROLINK_KEEPALIVE_PORT || sport == PROLINK_KEEPALIVE_PORT ||
        dport == PROLINK_STATUS_PORT || sport == PROLINK_STATUS_PORT ||
        dport == PROLINK_BEAT_PORT || sport == PROLINK_BEAT_PORT)
        return 1;
    
    /* NOTE: NFS traffic is NOT redirected to AF_XDP.
     * The nfs_client.c uses kernel UDP sockets for NFS requests.
     * If we redirect NFS responses here, they never reach the kernel
     * socket and nfs_rpc_call() times out.
     * CDJs also use non-standard NFS ports (not 2049), discovered via portmapper.
     */
    
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
    
    /* Only handle UDP - TCP uses kernel sockets for dbserver queries */
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;
    
    struct udphdr *udp = (void *)ip + ip_hdr_len;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;
    
    if (check_udp_ports(udp))
        return bpf_redirect_map(&prolink_xsks_map, ctx->rx_queue_index, XDP_PASS);
    
    /* Pass all other packets to kernel */
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
