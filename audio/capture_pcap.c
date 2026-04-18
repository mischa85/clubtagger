/*
 * capture_pcap.c - S/PDIF capture via libpcap
 */
#include "capture.h"

#ifdef HAVE_PCAP

#include "../writer/async_writer.h"
#include "../common.h"
#include "slink_protocol.h"

#include <pcap.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

void *capture_pcap(void *arg) {
    App *app = (App *)arg;
    Config *cfg = &app->cfg;

    vlogmsg("cap", "opening SLink on %s (pcap)", cfg->device);
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_create(cfg->device, errbuf);
    if (!handle) {
        logmsg("cap", "pcap_create %s: %s", cfg->device, errbuf);
        g_running = 0;
        return NULL;
    }
    pcap_set_snaplen(handle, BUFSIZ);
    pcap_set_promisc(handle, 1);
    pcap_set_timeout(handle, 100);  /* 100ms for responsive exit */
    pcap_set_immediate_mode(handle, 1);
    if (cfg->pcap_buffer_mb > 0) {
        pcap_set_buffer_size(handle, cfg->pcap_buffer_mb * 1024 * 1024);
        vlogmsg("cap", "pcap buffer size: %u MB", cfg->pcap_buffer_mb);
    }
    int rc = pcap_activate(handle);
    if (rc != 0) {
        logmsg("cap", "pcap_activate %s: %s", cfg->device, pcap_geterr(handle));
        pcap_close(handle);
        g_running = 0;
        return NULL;
    }
    g_pcap_handle = handle; /* allow signal handler to call breakloop */

    logmsg("cap", "started: rate=%u ch=%u (SLink source, 24-bit, %d channels configured)",
           cfg->rate, cfg->channels, cfg->slink_channel_count);

    const size_t fb = cfg->channels * cfg->bytes_per_sample;
    uint8_t *buf = app->cap_buf;
    const int nch = cfg->slink_channel_count;

    /* Noise floor for channel activity detection (24-bit sample absolute value) */
    const int32_t noise_floor = 8000;

    struct pcap_pkthdr hdr;
    const u_char *pkt;
    uint32_t buf_idx = 0;
    int last_seq = -1;
    int prev_active = -1;
    uint32_t ch_peak_l[SLINK_MAX_CHANNELS] = {0};
    uint32_t ch_peak_r[SLINK_MAX_CHANNELS] = {0};

    while (g_running) {
        pkt = pcap_next(handle, &hdr);
        if (!pkt) {
            if (!g_running) break;
            continue;
        }

        if (slink_is_valid(pkt, hdr.caplen)) {
            const slink_packet_t *slink = (const slink_packet_t *)pkt;

            /* Sequence counter check */
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
                uint32_t pl = abs(le24_to_int(tmp));
                uint32_t pr = abs(le24_to_int(tmp + 3));
                if (pl > ch_peak_l[0]) ch_peak_l[0] = pl;
                if (pr > ch_peak_r[0]) ch_peak_r[0] = pr;
            } else {
                for (int i = 0; i < nch; i++) {
                    int li = cfg->slink_channels[i].left;
                    int ri = cfg->slink_channels[i].right;
                    if (!slink_has_channel(hdr.caplen, li) || !slink_has_channel(hdr.caplen, ri))
                        continue;
                    uint8_t tmp[6];
                    slink_to_le24_lr(pkt, li, ri, tmp);
                    int32_t pl = abs(le24_to_int(tmp));
                    int32_t pr = abs(le24_to_int(tmp + 3));
                    if ((uint32_t)pl > ch_peak_l[i]) ch_peak_l[i] = (uint32_t)pl;
                    if ((uint32_t)pr > ch_peak_r[i]) ch_peak_r[i] = (uint32_t)pr;
                    int32_t peak = pl + pr;
                    if (peak > best_peak && peak > noise_floor) {
                        best_peak = peak;
                        active = i;
                    }
                }
            }

            if (active >= 0) {
                slink_to_le24_lr(pkt, cfg->slink_channels[active].left,
                                 cfg->slink_channels[active].right, &buf[buf_idx * fb]);
            } else {
                memset(&buf[buf_idx * fb], 0, fb);
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
                asyncwr_append(&app->aw, buf, cfg->frames_per_read);
                for (int c = 0; c < nch; c++) {
                    uint16_t vl = ch_peak_l[c] > 0xFFFF ? 0xFFFF : (uint16_t)ch_peak_l[c];
                    uint16_t vr = ch_peak_r[c] > 0xFFFF ? 0xFFFF : (uint16_t)ch_peak_r[c];
                    atomic_store_explicit(&app->slink_ch_peak_l[c], vl, memory_order_relaxed);
                    atomic_store_explicit(&app->slink_ch_peak_r[c], vr, memory_order_relaxed);
                    ch_peak_l[c] = 0;
                    ch_peak_r[c] = 0;
                }
                buf_idx = 0;
            }
        }
    }

    g_pcap_handle = NULL; /* prevent signal handler from using closed handle */
    pcap_close(handle);
    logmsg("cap", "exit");
    return NULL;
}

#endif /* HAVE_PCAP */
