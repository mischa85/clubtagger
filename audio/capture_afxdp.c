/*
 * capture_afxdp.c - AF_XDP high-performance capture
 */
#include "capture.h"

#ifdef HAVE_AF_XDP

#include "../writer/async_writer.h"
#include "../common.h"
#include "slink_protocol.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/if_link.h>
#include <linux/if_xdp.h>
#include <net/if.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <xdp/xsk.h>

#define NUM_FRAMES 131072 /* ~1.37 sec at 96 Kpps */
#define FRAME_SIZE 2048   /* Power of 2 for fast indexing (SLink packets are 1276 bytes) */
#define BATCH_SIZE 64

struct xsk_umem_info {
    struct xsk_ring_prod fq;
    struct xsk_ring_cons cq;
    struct xsk_umem *umem;
    void *buffer;
};

struct xsk_socket_info {
    struct xsk_ring_cons rx;
    struct xsk_ring_prod tx;
    struct xsk_umem_info *umem;
    struct xsk_socket *xsk;
    uint32_t outstanding_tx;
};

static int xsk_configure_umem(struct xsk_umem_info *umem, void *buffer, uint64_t size) {
    memset(umem, 0, sizeof(*umem));

    struct xsk_umem_config cfg = {
        .fill_size = NUM_FRAMES,
        .comp_size = NUM_FRAMES,
        .frame_size = FRAME_SIZE,
        .frame_headroom = 0,
        .flags = 0,
    };

    int ret = xsk_umem__create(&umem->umem, buffer, size, &umem->fq, &umem->cq, &cfg);
    if (ret) {
        logmsg("cap", "xsk_umem__create failed: %s", strerror(-ret));
        return -1;
    }
    umem->buffer = buffer;
    return 0;
}

static int xsk_configure_socket(struct xsk_socket_info *xsk_info, struct xsk_umem_info *umem,
                                const char *ifname, int queue_id,
                                int prog_fd) {
    memset(xsk_info, 0, sizeof(*xsk_info));
    (void)prog_fd;

    struct xsk_socket_config cfg = {
        .rx_size = 16384, /* ~170ms at 96 Kpps - handles mutex contention */
        .tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
        .libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
        .xdp_flags = XDP_FLAGS_DRV_MODE,
        .bind_flags = XDP_USE_NEED_WAKEUP,
    };

    int ret = xsk_socket__create(&xsk_info->xsk, ifname, queue_id, umem->umem,
                                 &xsk_info->rx, &xsk_info->tx, &cfg);
    if (ret) {
        /* Try fallback to SKB mode */
        cfg.xdp_flags = XDP_FLAGS_SKB_MODE;
        ret = xsk_socket__create(&xsk_info->xsk, ifname, queue_id, umem->umem,
                                 &xsk_info->rx, &xsk_info->tx, &cfg);
        if (ret) {
            logmsg("cap", "xsk_socket__create failed: %s", strerror(-ret));
            return -1;
        }
        vlogmsg("cap", "using XDP SKB mode (fallback)");
    } else {
        vlogmsg("cap", "using XDP driver mode");
    }

    xsk_info->umem = umem;
    return 0;
}

static void xsk_populate_fill_ring(struct xsk_umem_info *umem) {
    uint32_t idx;
    int ret = xsk_ring_prod__reserve(&umem->fq, NUM_FRAMES, &idx);
    if (ret != NUM_FRAMES) {
        logmsg("cap", "xsk_ring_prod__reserve failed");
        return;
    }
    for (int i = 0; i < NUM_FRAMES; i++) {
        *xsk_ring_prod__fill_addr(&umem->fq, idx++) = i * FRAME_SIZE;
    }
    xsk_ring_prod__submit(&umem->fq, NUM_FRAMES);
}

void *capture_afxdp(void *arg) {
    App *app = (App *)arg;
    Config *cfg = &app->cfg;
    int ret;

    vlogmsg("cap", "opening SLink on %s (AF_XDP)", cfg->device);

    /* Get interface index */
    unsigned int ifindex = if_nametoindex(cfg->device);
    if (ifindex == 0) {
        logmsg("cap", "interface %s not found", cfg->device);
        g_running = 0;
        return NULL;
    }

    /* Load BPF program */
    char bpf_path[256];
    snprintf(bpf_path, sizeof(bpf_path), "%s/slink_xdp.bpf.o",
             getenv("BPF_PATH") ? getenv("BPF_PATH") : "/usr/share/clubtagger");

    struct bpf_object *obj = bpf_object__open(bpf_path);
    if (libbpf_get_error(obj)) {
        /* Try local path in audio/ subdirectory */
        obj = bpf_object__open("audio/slink_xdp.bpf.o");
        if (libbpf_get_error(obj)) {
            logmsg("cap", "failed to open BPF object: %s", bpf_path);
            g_running = 0;
            return NULL;
        }
    }

    ret = bpf_object__load(obj);
    if (ret) {
        logmsg("cap", "failed to load BPF object: %s", strerror(-ret));
        bpf_object__close(obj);
        g_running = 0;
        return NULL;
    }

    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "slink_xdp_prog");
    if (!prog) {
        logmsg("cap", "failed to find XDP program");
        bpf_object__close(obj);
        g_running = 0;
        return NULL;
    }

    int prog_fd = bpf_program__fd(prog);

    /* Attach XDP program to interface */
    ret = bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_DRV_MODE, NULL);
    if (ret) {
        /* Try SKB mode */
        ret = bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_SKB_MODE, NULL);
        if (ret) {
            logmsg("cap", "failed to attach XDP program: %s", strerror(-ret));
            bpf_object__close(obj);
            g_running = 0;
            return NULL;
        }
    }

    /* Allocate UMEM */
    void *buffer = aligned_alloc(getpagesize(), NUM_FRAMES * FRAME_SIZE);
    if (!buffer) {
        logmsg("cap", "failed to allocate UMEM buffer");
        bpf_xdp_detach(ifindex, 0, NULL);
        bpf_object__close(obj);
        g_running = 0;
        return NULL;
    }

    struct xsk_umem_info umem;
    if (xsk_configure_umem(&umem, buffer, NUM_FRAMES * FRAME_SIZE) < 0) {
        logmsg("cap", "failed to configure UMEM");
        free(buffer);
        bpf_xdp_detach(ifindex, 0, NULL);
        bpf_object__close(obj);
        g_running = 0;
        return NULL;
    }

    /* Create XSK socket */
    struct xsk_socket_info xsk;
    if (xsk_configure_socket(&xsk, &umem, cfg->device, 0, prog_fd) < 0) {
        xsk_umem__delete(umem.umem);
        free(buffer);
        bpf_xdp_detach(ifindex, 0, NULL);
        bpf_object__close(obj);
        g_running = 0;
        return NULL;
    }
    g_xsk = xsk.xsk;

    /* Get xsks_map and update it with our socket */
    struct bpf_map *xsks_map = bpf_object__find_map_by_name(obj, "xsks_map");
    if (xsks_map) {
        int xsks_map_fd = bpf_map__fd(xsks_map);
        int key = 0;
        int xsk_fd = xsk_socket__fd(xsk.xsk);
        ret = bpf_map_update_elem(xsks_map_fd, &key, &xsk_fd, 0);
        if (ret) {
            logmsg("cap", "failed to update xsks_map: %s", strerror(-ret));
        }
    }

    /* Populate fill ring */
    xsk_populate_fill_ring(&umem);

    logmsg("cap", "started: rate=%u ch=%u (AF_XDP source, 24-bit, %d channels configured)",
           cfg->rate, cfg->channels, cfg->slink_channel_count);

    const size_t fb = cfg->channels * cfg->bytes_per_sample;
    uint8_t *audio_buf = app->cap_buf;
    const int nch = cfg->slink_channel_count;
    uint32_t buf_idx = 0;
    int last_seq = -1; /* Sequence counter tracking */
    int prev_active = -1;
    uint32_t ch_peaks[SLINK_MAX_CHANNELS] = {0};

    /* Noise floor for channel activity detection (24-bit sample absolute value) */
    const int32_t noise_floor = 8000;

    struct pollfd fds = {
        .fd = xsk_socket__fd(xsk.xsk),
        .events = POLLIN,
    };

    while (g_running) {
        /* Check if we need to wakeup */
        if (xsk_ring_prod__needs_wakeup(&umem.fq)) {
            poll(&fds, 1, 100);
        }

        /* Process received packets */
        uint32_t idx_rx = 0;
        unsigned int rcvd = xsk_ring_cons__peek(&xsk.rx, BATCH_SIZE, &idx_rx);
        if (rcvd == 0) {
            poll(&fds, 1, 10);
            continue;
        }

        /* Save addresses before processing (needed for fill ring refill) */
        uint64_t addrs[BATCH_SIZE];
        for (unsigned int i = 0; i < rcvd; i++) {
            addrs[i] = xsk_ring_cons__rx_desc(&xsk.rx, idx_rx + i)->addr;
        }

        for (unsigned int i = 0; i < rcvd; i++) {
            uint32_t len = xsk_ring_cons__rx_desc(&xsk.rx, idx_rx++)->len;
            uint8_t *pkt = xsk_umem__get_data(umem.buffer, addrs[i]);

            /* Process SLink packet - ethertype already filtered by BPF */
            if (len >= SLINK_MIN_LEN) {
                const slink_packet_t *slink = (const slink_packet_t *)pkt;

                /* Check sequence counter (cycles 0x00-0x1F) */
                int seq = slink_get_seq(slink);
                if (last_seq >= 0) {
                    int expected = (last_seq + 1) & SLINK_SEQ_MASK;
                    if (seq != expected) {
                        int lost = (seq - expected) & SLINK_SEQ_MASK;
                        atomic_fetch_add_explicit(&app->audio_lost, lost, memory_order_relaxed);
                        logmsg("cap", "sequence discontinuity: expected %02X got %02X (%d lost)",
                               expected, seq, lost);
                    }
                }
                last_seq = seq;

                /* Monitor all configured channels, pick the one with audio */
                int active = -1;
                int32_t best_peak = 0;

                if (nch == 1) {
                    active = 0;
                    uint8_t tmp[6];
                    slink_to_le24_lr(pkt, cfg->slink_channels[0].left,
                                     cfg->slink_channels[0].right, tmp);
                    uint32_t p = abs(le24_to_int(tmp)) + abs(le24_to_int(tmp + 3));
                    if (p > ch_peaks[0]) ch_peaks[0] = p;
                } else {
                    for (int c = 0; c < nch; c++) {
                        int li = cfg->slink_channels[c].left;
                        int ri = cfg->slink_channels[c].right;
                        if (!slink_has_channel(len, li) || !slink_has_channel(len, ri))
                            continue;
                        uint8_t tmp[6];
                        slink_to_le24_lr(pkt, li, ri, tmp);
                        int32_t peak = abs(le24_to_int(tmp)) + abs(le24_to_int(tmp + 3));
                        if ((uint32_t)peak > ch_peaks[c]) ch_peaks[c] = (uint32_t)peak;
                        if (peak > best_peak && peak > noise_floor) {
                            best_peak = peak;
                            active = c;
                        }
                    }
                }

                if (active >= 0) {
                    slink_to_le24_lr(pkt, cfg->slink_channels[active].left,
                                     cfg->slink_channels[active].right, &audio_buf[buf_idx * fb]);
                } else {
                    memset(&audio_buf[buf_idx * fb], 0, fb);
                }

                if (active != prev_active) {
                    if (active >= 0)
                        vlogmsg("cap", "active channel: %s (L=%d R=%d)",
                                cfg->slink_channels[active].name,
                                cfg->slink_channels[active].left,
                                cfg->slink_channels[active].right);
                    else if (prev_active >= 0)
                        vlogmsg("cap", "all channels silent");
                    atomic_store_explicit(&app->slink_active_ch, active, memory_order_relaxed);
                    prev_active = active;
                }

                buf_idx++;
                atomic_fetch_add_explicit(&app->audio_frames, 1, memory_order_relaxed);
                if (buf_idx >= cfg->frames_per_read) {
                    asyncwr_append(&app->aw, audio_buf, cfg->frames_per_read);
                    for (int c = 0; c < nch; c++) {
                        uint16_t v = ch_peaks[c] > 0xFFFF ? 0xFFFF : (uint16_t)ch_peaks[c];
                        atomic_store_explicit(&app->slink_ch_peak[c], v, memory_order_relaxed);
                        ch_peaks[c] = 0;
                    }
                    buf_idx = 0;
                }
            }
        }
        xsk_ring_cons__release(&xsk.rx, rcvd);

        /* Refill fill queue with saved addresses - must not leak frames */
        uint32_t idx_fq = 0;
        while (xsk_ring_prod__reserve(&umem.fq, rcvd, &idx_fq) != rcvd) {
            /* Fill ring full, kernel hasn't consumed yet - brief spin */
            if (!g_running) break;
        }
        if (g_running) {
            for (unsigned int i = 0; i < rcvd; i++) {
                *xsk_ring_prod__fill_addr(&umem.fq, idx_fq++) = addrs[i];
            }
            xsk_ring_prod__submit(&umem.fq, rcvd);
        }
    }

    g_xsk = NULL;
    xsk_socket__delete(xsk.xsk);
    xsk_umem__delete(umem.umem);
    free(buffer);
    bpf_xdp_detach(ifindex, 0, NULL);
    bpf_object__close(obj);

    logmsg("cap", "exit");
    return NULL;
}

#endif /* HAVE_AF_XDP */
