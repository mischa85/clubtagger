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
#include "nfs_observer.h"
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

    /* Get xsks_map and update it with our socket for ALL queues.
     * This ensures packets arriving on any RX queue (due to RSS hashing)
     * get redirected to our single XSK socket. */
    struct bpf_map *xsks_map = bpf_object__find_map_by_name(obj, "prolink_xsks_map");
    if (xsks_map) {
        int xsks_map_fd = bpf_map__fd(xsks_map);
        int xsk_fd = xsk_socket__fd(xsk.xsk);
        for (int key = 0; key < 64; key++) {
            bpf_map_update_elem(xsks_map_fd, &key, &xsk_fd, 0);
        }
    }

    prolink_xsk_populate_fill_ring(&umem);

    /* Initialize device array and track cache */
    memset(devices, 0, sizeof(devices));
    clear_track_cache();
    capture_interface = pt->interface;

    /* Initialize NFS observer for passive traffic sniffing.
     * NFS traffic is XDP_PASS'd to kernel, so we use a raw socket to observe it. */
    if (nfs_observer_init(pt->interface) == 0) {
        vlogmsg("cdj", "NFS observation enabled via raw socket");
    }

    if (!passive_only) {
        do_full_registration(pt->interface);
        logmsg("cdj", "Prolink observing network (AF_XDP) — will auto-detect active vs passive");
    } else {
        logmsg("cdj", "Prolink ready (forced passive/SPAN mode, AF_XDP) — eavesdrop only");
    }

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

            /* Watchdog: warn if no CDJ packets received recently */
            if (last_cdj_packet_time > 0) {
                int silent = (int)(now - last_cdj_packet_time);
                if (silent == 30) {
                    logmsg("cdj", "⚠ No CDJ packets for 30s (reg=%d slot=%d)",
                           registration_state, our_device_num);
                } else if (silent == 60) {
                    logmsg("cdj", "⚠ No CDJ packets for 60s — re-registering");
                    registration_state = REG_IDLE;
                    keepalives_sent_active = 0;
                    our_device_num = 0;
                }
            }
        }

        /* Poll for NFS traffic (passive observation) */
        nfs_observer_poll();
    }

    /* Cleanup */
    nfs_observer_cleanup();
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

    if (!passive_only) {
        /* Start observation phase — will auto-detect whether we need to register.
         * If status packets are already flowing (SPAN/multi-CDJ), stays passive.
         * If no status packets seen after 10s, registers as virtual CDJ. */
        do_full_registration(pt->interface);
        logmsg("cdj", "Prolink observing network (pcap) — will auto-detect active vs passive");
    } else {
        logmsg("cdj", "Prolink ready (forced passive/SPAN mode, pcap) — eavesdrop only");
    }
    
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
    ProlinkThread *pt __attribute__((unused)) = (ProlinkThread *)arg;
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
    
    /* Stay registered for continuous monitoring (don't release slot after timeout) */
    active_mode = 1;
    
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
#ifdef HAVE_PCAP
    if (pt->pcap_handle) {
        pcap_breakloop((pcap_t *)pt->pcap_handle);
    }
#endif
    
    pthread_join(pt->thread, NULL);
    g_prolink = NULL;
}

int prolink_get_playing_track(ProlinkThread *pt,
                               char *title, size_t title_sz,
                               char *artist, size_t artist_sz,
                               char *isrc, size_t isrc_sz,
                               int *deck_num) {
    if (!pt || !atomic_load(&pt->running)) return -1;
    
    time_t now = time(NULL);
    cdj_device_t *on_air_dev = NULL;
    cdj_device_t *longest_playing_dev = NULL;
    time_t longest_play_duration = 0;
    int playing_count = 0;
    
    /* Find best candidate: on-air deck, or deck with longest continuous playback */
    for (int i = 0; i < MAX_DEVICES; i++) {
        cdj_device_t *dev = &devices[i];
        if (!dev->active) continue;
        if (dev->device_type != DEVICE_TYPE_CDJ) continue;
        if (now - dev->last_seen > 10) continue;  /* Stale device */
        if (!dev->playing) continue;
        if (dev->track_title[0] == '\0') continue;  /* No metadata */
        
        playing_count++;
        
        /* Track on-air deck */
        if (dev->on_air && !on_air_dev) {
            on_air_dev = dev;
        }
        
        /* Track longest continuous playback */
        if (dev->play_started > 0) {
            time_t duration = now - dev->play_started;
            if (duration > longest_play_duration) {
                longest_play_duration = duration;
                longest_playing_dev = dev;
            }
        }
    }
    
    /* Decision logic:
     * 1. If only one deck is playing → that's definitely the live track
     * 2. If one deck has been playing 30+ seconds uninterrupted → likely live
     * 3. Otherwise, prefer on-air deck if available
     */
    cdj_device_t *best = NULL;
    
    if (playing_count == 1 && longest_playing_dev) {
        /* Only one deck playing - obvious choice */
        best = longest_playing_dev;
    } else if (longest_play_duration >= 30 && longest_playing_dev) {
        /* One deck has been playing 30+ seconds - likely the main track */
        best = longest_playing_dev;
    } else if (on_air_dev) {
        /* Fall back to on-air signal */
        best = on_air_dev;
    } else {
        /* Last resort: longest playing deck */
        best = longest_playing_dev;
    }
    
    if (best) {
        if (title) utf8_safe_copy(title, best->track_title, title_sz);
        if (artist) utf8_safe_copy(artist, best->track_artist, artist_sz);
        if (isrc) utf8_safe_copy(isrc, best->track_isrc, isrc_sz);
        if (deck_num) *deck_num = best->device_num;
        return 0;
    }
    
    return -1;  /* No playing track found */
}

/* ISRC match - the ultimate comparison when both sides have it */
int prolink_isrc_matches(const char *cdj_isrc, const char *fp_isrc) {
    /* Both must have ISRC */
    if (!cdj_isrc || !fp_isrc) return 0;
    if (cdj_isrc[0] == '\0' || fp_isrc[0] == '\0') return 0;
    
    /* ISRC format: 12 alphanumeric chars (e.g. USRC12345678)
     * May have hyphens in some formats - compare alphanumeric only */
    char cdj_norm[16] = {0}, fp_norm[16] = {0};
    int ci = 0, fi = 0;
    
    for (const char *p = cdj_isrc; *p && ci < 12; p++) {
        if ((*p >= 'A' && *p <= 'Z') || (*p >= '0' && *p <= '9')) {
            cdj_norm[ci++] = *p;
        } else if (*p >= 'a' && *p <= 'z') {
            cdj_norm[ci++] = *p - 32;  /* Uppercase */
        }
    }
    
    for (const char *p = fp_isrc; *p && fi < 12; p++) {
        if ((*p >= 'A' && *p <= 'Z') || (*p >= '0' && *p <= '9')) {
            fp_norm[fi++] = *p;
        } else if (*p >= 'a' && *p <= 'z') {
            fp_norm[fi++] = *p - 32;  /* Uppercase */
        }
    }
    
    /* Must have full 12-char ISRCs to compare */
    if (ci != 12 || fi != 12) return 0;
    
    return memcmp(cdj_norm, fp_norm, 12) == 0;
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

    /* Title matching — three strategies, any hit counts:
     * 1. Substring containment ("Song" vs "Song (Original Mix)")
     * 2. Core prefix match ("Re-Rewind ..." vs "Re-Rewind ...")
     * 3. Levenshtein similarity (typos like "Tiësto" vs "Tiesto") */
    int title_match = str_contains(cdj_title, fp_title) ||
                      str_contains(fp_title, cdj_title) ||
                      str_core_match(cdj_title, fp_title);

    if (!title_match) {
        int sim = str_similarity(cdj_title, fp_title);
        title_match = (sim >= match_threshold);
        if (title_match) {
            vlogmsg("cdj", "Fuzzy title match: %d%% (\"%s\" vs \"%s\")",
                   sim, cdj_title, fp_title);
        }
    }

    if (!title_match) return 0;

    /* Artist matching — handles "ft."/"feat."/"&" separator differences */
    int artist_match = str_artist_match(cdj_artist, fp_artist);

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
                } else if (play_duration > 0 && play_duration % 30 == 0) {
                    /* Log progress every 30s so UI shows we're waiting */
                    logmsg("cdj", "Deck %d: playing %lds/%ds before auto-tag",
                           dev->device_num, (long)play_duration, CDJ_TAG_MIN_PLAYTIME_SEC);
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

int prolink_any_deck_on_air(ProlinkThread *pt) {
    if (!pt || !atomic_load(&pt->running)) return -1;
    
    int has_on_air_info = 0;
    
    for (int i = 0; i < MAX_DEVICES; i++) {
        cdj_device_t *dev = &devices[i];
        if (!dev->active) continue;
        if (dev->device_type != DEVICE_TYPE_CDJ) continue;
        
        if (dev->on_air_available) {
            has_on_air_info = 1;
            if (dev->on_air && dev->playing) {
                return 1;  /* Found a deck that's on-air and playing */
            }
        }
    }
    
    /* Return -1 if no ON_AIR data available (no DJM), 0 if DJM present but no deck on-air */
    return has_on_air_info ? 0 : -1;
}

int prolink_active_deck_count(ProlinkThread *pt) {
    if (!pt || !atomic_load(&pt->running)) return 0;
    
    int count = 0;
    time_t now = time(NULL);
    
    for (int i = 0; i < MAX_DEVICES; i++) {
        cdj_device_t *dev = &devices[i];
        if (!dev->active) continue;
        if (dev->device_type != DEVICE_TYPE_CDJ) continue;
        if (now - dev->last_seen > 10) continue;  /* Stale */
        count++;
    }
    
    return count;
}
