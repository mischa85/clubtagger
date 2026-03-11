/*
 * prolink_thread.c - Pro DJ Link Integration for clubtagger
 *
 * Runs CDJ network sniffing in a background thread.
 * Supports both pcap (default) and AF_XDP (Linux, optional).
 */

#include "prolink_thread.h"
#include "../common.h"
#include "cdj_types.h"
#include "registration.h"
#include "packet_handler.h"
#include "track_cache.h"
#include "../common.h"

#ifdef HAVE_AF_XDP
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/if_link.h>
#include <linux/if_xdp.h>
#include <net/if.h>
#include <poll.h>
#include <stdlib.h>
#include <xdp/xsk.h>
#endif

#ifdef HAVE_PCAP
#include <pcap/pcap.h>
#endif

#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <unistd.h>

/* Global prolink thread pointer for callbacks */
static ProlinkThread *g_prolink = NULL;

#ifdef HAVE_AF_XDP
/*
 * ============================================================================
 * AF_XDP Capture (Linux high-performance, no libpcap dependency)
 * ============================================================================
 */

#define PROLINK_NUM_FRAMES 4096
#define PROLINK_FRAME_SIZE 2048
#define PROLINK_BATCH_SIZE 32

struct prolink_xsk_umem_info {
    struct xsk_ring_prod fq;
    struct xsk_ring_cons cq;
    struct xsk_umem *umem;
    void *buffer;
};

struct prolink_xsk_socket_info {
    struct xsk_ring_cons rx;
    struct xsk_ring_prod tx;
    struct prolink_xsk_umem_info *umem;
    struct xsk_socket *xsk;
};

static int prolink_xsk_configure_umem(struct prolink_xsk_umem_info *umem, void *buffer, uint64_t size) {
    memset(umem, 0, sizeof(*umem));

    struct xsk_umem_config cfg = {
        .fill_size = PROLINK_NUM_FRAMES,
        .comp_size = PROLINK_NUM_FRAMES,
        .frame_size = PROLINK_FRAME_SIZE,
        .frame_headroom = 0,
        .flags = 0,
    };

    int ret = xsk_umem__create(&umem->umem, buffer, size, &umem->fq, &umem->cq, &cfg);
    if (ret) {
        logmsg("cdj", "xsk_umem__create failed: %s", strerror(-ret));
        return -1;
    }
    umem->buffer = buffer;
    return 0;
}

static int prolink_xsk_configure_socket(struct prolink_xsk_socket_info *xsk_info, 
                                        struct prolink_xsk_umem_info *umem,
                                        const char *ifname, int queue_id) {
    memset(xsk_info, 0, sizeof(*xsk_info));

    struct xsk_socket_config cfg = {
        .rx_size = 2048,
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
            logmsg("cdj", "xsk_socket__create failed: %s", strerror(-ret));
            return -1;
        }
        vlogmsg("cdj", "using XDP SKB mode (fallback)");
    } else {
        vlogmsg("cdj", "using XDP driver mode");
    }

    xsk_info->umem = umem;
    return 0;
}

static void prolink_xsk_populate_fill_ring(struct prolink_xsk_umem_info *umem) {
    uint32_t idx;
    int ret = xsk_ring_prod__reserve(&umem->fq, PROLINK_NUM_FRAMES, &idx);
    if (ret != PROLINK_NUM_FRAMES) {
        logmsg("cdj", "xsk_ring_prod__reserve failed");
        return;
    }
    for (int i = 0; i < PROLINK_NUM_FRAMES; i++) {
        *xsk_ring_prod__fill_addr(&umem->fq, idx++) = i * PROLINK_FRAME_SIZE;
    }
    xsk_ring_prod__submit(&umem->fq, PROLINK_NUM_FRAMES);
}

static void *prolink_thread_afxdp(void *arg) {
    ProlinkThread *pt = (ProlinkThread *)arg;
    int ret;

    logmsg("cdj", "Prolink thread starting on interface %s (AF_XDP)", pt->interface);

    /* Get interface index */
    unsigned int ifindex = if_nametoindex(pt->interface);
    if (ifindex == 0) {
        logmsg("cdj", "interface %s not found", pt->interface);
        return NULL;
    }

    /* Load BPF program */
    char bpf_path[256];
    snprintf(bpf_path, sizeof(bpf_path), "%s/prolink_xdp.bpf.o",
             getenv("BPF_PATH") ? getenv("BPF_PATH") : "/usr/share/clubtagger");

    struct bpf_object *obj = bpf_object__open(bpf_path);
    if (libbpf_get_error(obj)) {
        /* Try local path in prolink/ subdirectory */
        obj = bpf_object__open("prolink/prolink_xdp.bpf.o");
        if (libbpf_get_error(obj)) {
            logmsg("cdj", "failed to open BPF object: %s (falling back to pcap)", bpf_path);
            return NULL;  /* Caller should fall back to pcap */
        }
    }

    ret = bpf_object__load(obj);
    if (ret) {
        logmsg("cdj", "failed to load BPF object: %s", strerror(-ret));
        bpf_object__close(obj);
        return NULL;
    }

    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "prolink_xdp_prog");
    if (!prog) {
        logmsg("cdj", "failed to find XDP program");
        bpf_object__close(obj);
        return NULL;
    }

    int prog_fd = bpf_program__fd(prog);

    /* Attach XDP program to interface */
    ret = bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_DRV_MODE, NULL);
    if (ret) {
        ret = bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_SKB_MODE, NULL);
        if (ret) {
            logmsg("cdj", "failed to attach XDP program: %s", strerror(-ret));
            bpf_object__close(obj);
            return NULL;
        }
    }

    /* Allocate UMEM */
    void *buffer = aligned_alloc(getpagesize(), PROLINK_NUM_FRAMES * PROLINK_FRAME_SIZE);
    if (!buffer) {
        logmsg("cdj", "failed to allocate UMEM buffer");
        bpf_xdp_detach(ifindex, 0, NULL);
        bpf_object__close(obj);
        return NULL;
    }

    struct prolink_xsk_umem_info umem;
    if (prolink_xsk_configure_umem(&umem, buffer, PROLINK_NUM_FRAMES * PROLINK_FRAME_SIZE) < 0) {
        free(buffer);
        bpf_xdp_detach(ifindex, 0, NULL);
        bpf_object__close(obj);
        return NULL;
    }

    struct prolink_xsk_socket_info xsk;
    if (prolink_xsk_configure_socket(&xsk, &umem, pt->interface, 0) < 0) {
        xsk_umem__delete(umem.umem);
        free(buffer);
        bpf_xdp_detach(ifindex, 0, NULL);
        bpf_object__close(obj);
        return NULL;
    }

    /* Get xsks_map and update it with our socket */
    struct bpf_map *xsks_map = bpf_object__find_map_by_name(obj, "prolink_xsks_map");
    if (xsks_map) {
        int xsks_map_fd = bpf_map__fd(xsks_map);
        int key = 0;
        int xsk_fd = xsk_socket__fd(xsk.xsk);
        bpf_map_update_elem(xsks_map_fd, &key, &xsk_fd, 0);
    }

    prolink_xsk_populate_fill_ring(&umem);

    /* Initialize device array and track cache */
    memset(devices, 0, sizeof(devices));
    clear_track_cache();
    capture_interface = pt->interface;
    passive_only = 0;

    /* Send initial keepalives */
    for (int i = 0; i < 3; i++) {
        do_full_registration(pt->interface);
        usleep(200000);
    }

    logmsg("cdj", "Prolink ready for metadata queries (AF_XDP)");

    struct pollfd fds = {
        .fd = xsk_socket__fd(xsk.xsk),
        .events = POLLIN,
    };

    time_t last_ka = 0;

    while (atomic_load(&pt->running)) {
        if (xsk_ring_prod__needs_wakeup(&umem.fq)) {
            poll(&fds, 1, 100);
        }

        uint32_t idx_rx = 0;
        unsigned int rcvd = xsk_ring_cons__peek(&xsk.rx, PROLINK_BATCH_SIZE, &idx_rx);
        if (rcvd == 0) {
            poll(&fds, 1, 10);
            goto keepalive_check;
        }

        /* Process received packets */
        for (unsigned int i = 0; i < rcvd; i++) {
            uint64_t addr = xsk_ring_cons__rx_desc(&xsk.rx, idx_rx + i)->addr;
            uint32_t len = xsk_ring_cons__rx_desc(&xsk.rx, idx_rx + i)->len;
            uint8_t *pkt = (uint8_t *)umem.buffer + addr;

            /* Create fake pcap header for packet_handler compatibility */
            struct pcap_pkthdr hdr;
            gettimeofday(&hdr.ts, NULL);
            hdr.caplen = len;
            hdr.len = len;

            packet_handler(NULL, &hdr, pkt);
        }

        xsk_ring_cons__release(&xsk.rx, rcvd);

        /* Refill fill ring */
        uint32_t idx_fq;
        ret = xsk_ring_prod__reserve(&umem.fq, rcvd, &idx_fq);
        if (ret == (int)rcvd) {
            for (unsigned int i = 0; i < rcvd; i++) {
                *xsk_ring_prod__fill_addr(&umem.fq, idx_fq + i) = 
                    xsk_ring_cons__rx_desc(&xsk.rx, idx_rx + i)->addr;
            }
            xsk_ring_prod__submit(&umem.fq, rcvd);
        }

keepalive_check:
        /* Drive registration state machine (handles observation + keepalives) */
        time_t now = time(NULL);
        if (now - last_ka >= 1) {
            do_full_registration(pt->interface);
            last_ka = now;
        }
    }

    /* Cleanup */
    xsk_socket__delete(xsk.xsk);
    xsk_umem__delete(umem.umem);
    free(buffer);
    bpf_xdp_detach(ifindex, 0, NULL);
    bpf_object__close(obj);

    logmsg("cdj", "Prolink thread exiting (AF_XDP)");
    return (void *)1;  /* Non-NULL indicates success */
}
#endif /* HAVE_AF_XDP */

#ifdef HAVE_PCAP
/*
 * ============================================================================
 * pcap Capture (portable, default)
 * ============================================================================
 */

static void *prolink_thread_pcap(void *arg) {
    ProlinkThread *pt = (ProlinkThread *)arg;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    logmsg("cdj", "Prolink thread starting on interface %s (pcap)", pt->interface);
    
    /* Open device for capture */
    pcap_t *handle = pcap_open_live(pt->interface, 65535, 1, 100, errbuf);
    if (!handle) {
        logmsg("cdj", "Error opening %s: %s", pt->interface, errbuf);
        return NULL;
    }
    
    pt->pcap_handle = handle;
    
    /* Set BPF filter for Pro DJ Link traffic */
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, PCAP_FILTER, 1, PCAP_NETMASK_UNKNOWN) == 0) {
        if (pcap_setfilter(handle, &fp) != 0) {
            logmsg("cdj", "Warning: Could not set filter: %s", pcap_geterr(handle));
        }
        pcap_freecode(&fp);
    }
    
    /* Initialize device array and track cache */
    memset(devices, 0, sizeof(devices));
    clear_track_cache();
    
    /* Store interface for registration */
    capture_interface = pt->interface;
    passive_only = 0;  /* We want active registration for metadata queries */
    
    /* Send initial keepalives */
    for (int i = 0; i < 3; i++) {
        do_full_registration(pt->interface);
        usleep(200000);
    }
    
    logmsg("cdj", "Prolink ready for metadata queries (pcap)");
    
    /* Main capture loop */
    while (atomic_load(&pt->running)) {
        int ret = pcap_dispatch(handle, 10, packet_handler, NULL);
        if (ret < 0) {
            if (ret == PCAP_ERROR_BREAK) break;
            logmsg("cdj", "pcap error: %s", pcap_geterr(handle));
            break;
        }
        
        /* Drive registration state machine (handles observation + keepalives) */
        static time_t last_ka = 0;
        time_t now = time(NULL);
        if (now - last_ka >= 1) {
            do_full_registration(pt->interface);
            last_ka = now;
        }
    }
    
    pcap_close(handle);
    pt->pcap_handle = NULL;
    
    logmsg("cdj", "Prolink thread exiting (pcap)");
    return (void *)1;
}
#endif /* HAVE_PCAP */

/*
 * ============================================================================
 * Thread Entry Point
 * ============================================================================
 */

static void *prolink_thread_main(void *arg) {
    ProlinkThread *pt = (ProlinkThread *)arg;
    void *result = NULL;

#ifdef HAVE_AF_XDP
    /* Try AF_XDP first (Linux, high-performance, no libpcap needed) */
    result = prolink_thread_afxdp(arg);
    if (result != NULL) {
        return result;  /* AF_XDP succeeded */
    }
    logmsg("cdj", "AF_XDP unavailable, falling back to pcap");
#endif

#ifdef HAVE_PCAP
    result = prolink_thread_pcap(arg);
    if (result != NULL) {
        return result;
    }
#endif

#if !defined(HAVE_AF_XDP) && !defined(HAVE_PCAP)
    logmsg("cdj", "No capture backend available (need pcap or AF_XDP)");
    (void)pt;
#endif

    return NULL;
}

/*
 * ============================================================================
 * Public API
 * ============================================================================
 */

int prolink_init(ProlinkThread *pt, const char *interface, int verbose_level) {
    if (!pt || !interface) return -1;
    
    memset(pt, 0, sizeof(*pt));
    pt->interface = interface;
    atomic_store(&pt->running, 1);
    
    /* Set CDJ verbose level */
    verbose = verbose_level;
    
    g_prolink = pt;
    
    /* Start thread */
    if (pthread_create(&pt->thread, NULL, prolink_thread_main, pt) != 0) {
        logmsg("cdj", "Failed to create prolink thread");
        return -1;
    }
    
    return 0;
}

void prolink_shutdown(ProlinkThread *pt) {
    if (!pt) return;
    
    atomic_store(&pt->running, 0);
    
    /* Break pcap loop if running */
    if (pt->pcap_handle) {
        pcap_breakloop((pcap_t *)pt->pcap_handle);
    }
    
    pthread_join(pt->thread, NULL);
    g_prolink = NULL;
}

int prolink_get_playing_track(ProlinkThread *pt,
                               char *title, size_t title_sz,
                               char *artist, size_t artist_sz,
                               int *deck_num) {
    if (!pt || !atomic_load(&pt->running)) return -1;
    
    /* Find first playing CDJ */
    time_t now = time(NULL);
    for (int i = 0; i < MAX_DEVICES; i++) {
        cdj_device_t *dev = &devices[i];
        if (!dev->active) continue;
        if (dev->device_type != DEVICE_TYPE_CDJ) continue;
        if (now - dev->last_seen > 10) continue;  /* Stale device */
        if (!dev->playing) continue;
        
        /* Found a playing deck */
        if (dev->track_title[0]) {
            if (title) utf8_safe_copy(title, dev->track_title, title_sz);
            if (artist) utf8_safe_copy(artist, dev->track_artist, artist_sz);
            if (deck_num) *deck_num = dev->device_num;
            return 0;
        }
    }
    
    return -1;  /* No playing track found */
}

/*
 * ============================================================================
 * Fuzzy Matching for Fingerprint Confirmation
 * ============================================================================
 */

int prolink_matches_fingerprint(const char *cdj_title, const char *cdj_artist,
                                 const char *fp_title, const char *fp_artist) {
    if (!cdj_title || !fp_title) return 0;
    if (cdj_title[0] == '\0' || fp_title[0] == '\0') return 0;
    
    /* Fast path: substring containment (handles "Song" vs "Song (Original Mix)") */
    int title_match = str_contains(cdj_title, fp_title) ||
                      str_contains(fp_title, cdj_title);
    
    /* Slow path: Levenshtein similarity (handles typos like "Tiësto" vs "Tiesto") */
    if (!title_match) {
        int sim = str_similarity(cdj_title, fp_title);
        title_match = (sim >= match_threshold);
        if (title_match) {
            vlogmsg("cdj", "Fuzzy title match: %d%% (\"%s\" vs \"%s\")", 
                   sim, cdj_title, fp_title);
        }
    }
    
    if (!title_match) return 0;
    
    /* Check artist match if both have artists */
    int artist_match = 1;  /* Default to match if no artist info */
    if (cdj_artist && fp_artist && cdj_artist[0] && fp_artist[0]) {
        artist_match = str_contains(cdj_artist, fp_artist) ||
                       str_contains(fp_artist, cdj_artist);
        if (!artist_match) {
            int sim = str_similarity(cdj_artist, fp_artist);
            artist_match = (sim >= match_threshold);
            if (artist_match) {
                vlogmsg("cdj", "Fuzzy artist match: %d%% (\"%s\" vs \"%s\")", 
                       sim, cdj_artist, fp_artist);
            }
        }
    }
    
    return title_match && artist_match;
}

/*
 * ============================================================================
 * CDJ-Only Tagging
 * ============================================================================
 */

void prolink_enable_tagging(ProlinkThread *pt, 
                            cdj_tag_callback_t callback, 
                            void *user_data) {
    if (!pt) return;
    pt->on_track_confirmed = callback;
    pt->callback_user_data = user_data;
    pt->tagging_enabled = 1;
    logmsg("cdj", "CDJ-only tagging enabled (on-air + %ds fallback)", 
           CDJ_TAG_MIN_PLAYTIME_SEC);
}

/* Check if any of the CDJs have ON_AIR capability (DJM present) */
static int any_device_has_on_air(void) {
    for (int i = 0; i < MAX_DEVICES; i++) {
        if (devices[i].active && devices[i].on_air_available) {
            return 1;
        }
    }
    return 0;
}

void prolink_check_tagging(ProlinkThread *pt) {
    if (!pt || !pt->tagging_enabled || !pt->on_track_confirmed) return;
    if (!atomic_load(&pt->running)) return;
    
    time_t now = time(NULL);
    int on_air_available = any_device_has_on_air();
    
    for (int i = 0; i < MAX_DEVICES; i++) {
        cdj_device_t *dev = &devices[i];
        
        if (!dev->active) continue;
        if (dev->device_type != DEVICE_TYPE_CDJ) continue;
        if (now - dev->last_seen > 10) continue;  /* Stale device */
        if (!dev->playing) continue;
        if (dev->rekordbox_id == 0) continue;
        if (dev->track_title[0] == '\0') continue;  /* No metadata yet */
        
        /* Already logged this track on this deck */
        if (dev->logged_rekordbox_id == dev->rekordbox_id) continue;
        
        int should_log = 0;
        const char *reason = NULL;
        
        if (on_air_available) {
            /* ON_AIR mode: log when deck goes on-air while playing */
            if (dev->on_air) {
                should_log = 1;
                reason = "cdj/on-air";
            }
        } else {
            /* Duration fallback: log after continuous playback */
            if (dev->play_started > 0) {
                time_t play_duration = now - dev->play_started;
                if (play_duration >= CDJ_TAG_MIN_PLAYTIME_SEC) {
                    should_log = 1;
                    reason = "cdj/duration";
                }
            }
        }
        
        if (should_log) {
            /* Mark as logged to prevent duplicate logging */
            dev->logged_rekordbox_id = dev->rekordbox_id;
            
            logmsg("cdj", "📝 DECK %d: Logging track - %s - %s (%s)",
                   dev->device_num, dev->track_artist, dev->track_title, reason);
            
            pt->on_track_confirmed(pt->callback_user_data, 
                                   dev->device_num,
                                   dev->track_artist,
                                   dev->track_title,
                                   CDJ_TAG_CONFIDENCE,
                                   reason);
        }
    }
}
