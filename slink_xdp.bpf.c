/* SPDX-License-Identifier: GPL-2.0 */
/*
 * XDP BPF program for SLink packet capture
 * 
 * Filters ethernet frames with ethertype 0x04ee (SLink) and redirects
 * them to an AF_XDP socket. All other packets are passed to the kernel.
 *
 * Compile with:
 *   clang -O2 -target bpf -c slink_xdp.bpf.c -o slink_xdp.bpf.o
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define SLINK_ETHERTYPE 0x04ee

/* XSK map - AF_XDP sockets register here */
struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
    __uint(max_entries, 64);
} xsks_map SEC(".maps");

SEC("xdp")
int slink_xdp_prog(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    
    /* Bounds check for ethernet header */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    
    /* Check for SLink ethertype (0x04ee in big-endian) */
    if (eth->h_proto == bpf_htons(SLINK_ETHERTYPE)) {
        /* Redirect to AF_XDP socket on queue 0 */
        return bpf_redirect_map(&xsks_map, ctx->rx_queue_index, XDP_PASS);
    }
    
    /* Pass all non-SLink packets to kernel */
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
