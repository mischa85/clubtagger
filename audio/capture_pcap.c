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

    logmsg("cap", "started: rate=%u ch=%u (SLink source, 24-bit)", cfg->rate, cfg->channels);

    const size_t fb = cfg->channels * cfg->bytes_per_sample;
    uint8_t *buf = app->cap_buf;

    struct pcap_pkthdr hdr;
    const u_char *pkt;
    uint32_t buf_idx = 0;
    int last_seq = -1; /* Sequence counter tracking */

    while (g_running) {
        pkt = pcap_next(handle, &hdr);
        if (!pkt) {
            /* Check if broken by signal or just timeout */
            if (!g_running) break;
            continue;
        }

        if (slink_is_valid(pkt, hdr.caplen)) {
            const slink_packet_t *slink = (const slink_packet_t *)pkt;
            
            /* Check sequence counter (cycles 0x00-0x1F) */
            int seq = slink_get_seq(slink);
            if (last_seq >= 0) {
                int expected = (last_seq + 1) & SLINK_SEQ_MASK;
                if (seq != expected) {
                    /* Calculate how many packets were lost */
                    int lost = (seq - expected) & SLINK_SEQ_MASK;
                    atomic_fetch_add_explicit(&app->audio_lost, lost, memory_order_relaxed);
                    logmsg("cap", "sequence discontinuity: expected %02X got %02X (%d lost)",
                           expected, seq, lost);
                }
            }
            last_seq = seq;

            /* Convert 24-bit big-endian to little-endian */
            slink_to_le24_stereo(slink, &buf[buf_idx * fb]);

            buf_idx++;
            atomic_fetch_add_explicit(&app->audio_frames, 1, memory_order_relaxed);
            if (buf_idx >= cfg->frames_per_read) {
                asyncwr_append(&app->aw, buf, cfg->frames_per_read);
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
