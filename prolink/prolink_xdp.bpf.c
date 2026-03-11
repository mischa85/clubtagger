/* SPDX-License-Identifier: GPL-2.0 */
/*
 * XDP BPF program for Pro DJ Link packet capture
 * 
 * Filters UDP packets on ports 50000-50002 (Pro DJ Link) and redirects
 * them to an AF_XDP socket. All other packets are passed to the kernel.
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
#define PROLINK_STATUS_PORT     50001
#define PROLINK_BEAT_PORT       50002

/* XSK map - AF_XDP sockets register here */
struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
    __uint(max_entries, 64);
} prolink_xsks_map SEC(".maps");

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
    
    /* Only process UDP */
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;
    
    /* Calculate IP header length (IHL is in 32-bit words) */
    unsigned int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(*ip))
        return XDP_PASS;
    
    /* Bounds check for UDP header */
    struct udphdr *udp = (void *)ip + ip_hdr_len;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;
    
    /* Check destination port for Pro DJ Link */
    __u16 dport = bpf_ntohs(udp->dest);
    if (dport == PROLINK_KEEPALIVE_PORT ||
        dport == PROLINK_STATUS_PORT ||
        dport == PROLINK_BEAT_PORT) {
        /* Redirect to AF_XDP socket */
        return bpf_redirect_map(&prolink_xsks_map, ctx->rx_queue_index, XDP_PASS);
    }
    
    /* Pass all non-Pro DJ Link packets to kernel */
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
