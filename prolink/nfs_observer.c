/*
 * nfs_observer.c - Raw Socket NFS Traffic Observer
 *
 * Uses raw AF_PACKET socket with BPF filter to observe NFS traffic.
 * Alternative to pcap that avoids header conflicts with AF_XDP.
 */

#ifdef HAVE_AF_XDP

#include "nfs_observer.h"
#include "packet_handler.h"
#include "../common.h"

#include <errno.h>
#include <fcntl.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <linux/filter.h>
#include <linux/if_packet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <string.h>
#include <unistd.h>

/* NFS observer state */
static int nfs_sock = -1;
static uint8_t nfs_buf[2048];
static uint16_t observed_nfs_port = 2049;

/*
 * BPF filter for UDP port 2049 (NFS).
 * Generated using: tcpdump -dd 'udp port 2049'
 *
 * If CDJ uses a non-standard NFS port, we'll need to update this dynamically.
 */
static struct sock_filter nfs_bpf_code[] = {
    { 0x28, 0, 0, 0x0000000c },  /* ldh [12] - EtherType */
    { 0x15, 0, 8, 0x00000800 },  /* jeq #0x800 jt 2 jf 11 - IPv4? */
    { 0x30, 0, 0, 0x00000017 },  /* ldb [23] - IP protocol */
    { 0x15, 0, 6, 0x00000011 },  /* jeq #0x11 jt 4 jf 11 - UDP? */
    { 0x28, 0, 0, 0x00000014 },  /* ldh [20] - fragment offset */
    { 0x45, 4, 0, 0x00001fff },  /* jset #0x1fff jt 10 jf 6 - fragmented? */
    { 0xb1, 0, 0, 0x0000000e },  /* ldxb 4*([14]&0xf) - IP header len */
    { 0x48, 0, 0, 0x0000000e },  /* ldh [x+14] - src port */
    { 0x15, 1, 0, 0x00000801 },  /* jeq #2049 jt 10 jf 9 */
    { 0x48, 0, 0, 0x00000010 },  /* ldh [x+16] - dst port */
    { 0x15, 0, 1, 0x00000801 },  /* jeq #2049 jt 11 jf 12 */
    { 0x06, 0, 0, 0x00040000 },  /* ret #262144 - accept */
    { 0x06, 0, 0, 0x00000000 },  /* ret #0 - reject */
};

static struct sock_fprog nfs_bpf = {
    .len = sizeof(nfs_bpf_code) / sizeof(nfs_bpf_code[0]),
    .filter = nfs_bpf_code,
};

/*
 * Initialize NFS observer on the given interface.
 * Returns 0 on success, -1 on error.
 */
int nfs_observer_init(const char *interface) {
    if (nfs_sock >= 0) {
        return 0;  /* Already initialized */
    }

    /* Create raw packet socket */
    nfs_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (nfs_sock < 0) {
        vlogmsg("nfs", "Failed to create raw socket: %s", strerror(errno));
        return -1;
    }

    /* Bind to specific interface */
    struct sockaddr_ll sll = {0};
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = if_nametoindex(interface);
    if (sll.sll_ifindex == 0) {
        vlogmsg("nfs", "Interface '%s' not found", interface);
        close(nfs_sock);
        nfs_sock = -1;
        return -1;
    }

    if (bind(nfs_sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        vlogmsg("nfs", "Failed to bind to interface: %s", strerror(errno));
        close(nfs_sock);
        nfs_sock = -1;
        return -1;
    }

    /* Attach BPF filter for NFS traffic */
    if (setsockopt(nfs_sock, SOL_SOCKET, SO_ATTACH_FILTER, 
                   &nfs_bpf, sizeof(nfs_bpf)) < 0) {
        vlogmsg("nfs", "Failed to attach BPF filter: %s", strerror(errno));
        close(nfs_sock);
        nfs_sock = -1;
        return -1;
    }

    /* Set non-blocking */
    int flags = fcntl(nfs_sock, F_GETFL, 0);
    if (flags >= 0) {
        fcntl(nfs_sock, F_SETFL, flags | O_NONBLOCK);
    }

    vlogmsg("nfs", "NFS observer initialized on %s", interface);
    return 0;
}

/*
 * Update the NFS port filter (called after portmapper discovery).
 * Returns 0 on success, -1 on error.
 */
int nfs_observer_set_port(uint16_t port) {
    if (port == observed_nfs_port) {
        return 0;  /* No change needed */
    }

    observed_nfs_port = port;

    if (nfs_sock < 0) {
        return 0;  /* Not initialized yet */
    }

    /* Update BPF filter constants for new port.
     * The port appears in instructions 8 and 10 (0x801 = 2049 in the default). */
    nfs_bpf_code[8].k = port;
    nfs_bpf_code[10].k = port;

    /* Re-attach updated filter */
    if (setsockopt(nfs_sock, SOL_SOCKET, SO_ATTACH_FILTER,
                   &nfs_bpf, sizeof(nfs_bpf)) < 0) {
        vlogmsg("nfs", "Failed to update BPF filter: %s", strerror(errno));
        return -1;
    }

    vlogmsg("nfs", "NFS observer port updated to %u", port);
    return 0;
}

/*
 * Process pending NFS packets (non-blocking).
 * Call this periodically from the main loop.
 */
void nfs_observer_poll(void) {
    if (nfs_sock < 0) {
        return;
    }

    /* Process up to 10 packets per call */
    for (int i = 0; i < 10; i++) {
        ssize_t len = recv(nfs_sock, nfs_buf, sizeof(nfs_buf), MSG_DONTWAIT);
        if (len <= 0) {
            break;  /* No more packets or error */
        }

        /* Build pcap-compatible header and call packet_handler */
        struct pcap_pkthdr hdr = {0};
        gettimeofday(&hdr.ts, NULL);
        hdr.caplen = (uint32_t)len;
        hdr.len = (uint32_t)len;

        packet_handler(NULL, &hdr, nfs_buf);
    }
}

/*
 * Cleanup NFS observer.
 */
void nfs_observer_cleanup(void) {
    if (nfs_sock >= 0) {
        close(nfs_sock);
        nfs_sock = -1;
        vlogmsg("nfs", "NFS observer closed");
    }
}

#endif /* HAVE_AF_XDP */
