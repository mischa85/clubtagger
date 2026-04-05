/*
 * prolink.c - Pro DJ Link Packet Parsing
 *
 * Parse keepalive, status, and beat packets from Pro DJ Link protocol.
 */

#include "prolink.h"
#include "prolink_protocol.h"
#include "cdj_types.h"
#include "track_cache.h"
#include "dbserver.h"
#include "pdb_parser.h"
#include "onelibrary.h"
#include "registration.h"
#include "../confidence.h"
#include "../common.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

/*
 * ============================================================================
 * Packet Validation
 * ============================================================================
 */

int is_prolink_packet(const uint8_t *data, size_t len) {
    if (len < PROLINK_SIG_LEN) return 0;
    return memcmp(data, PROLINK_SIGNATURE, PROLINK_SIG_LEN) == 0;
}

uint8_t get_prolink_packet_type(const uint8_t *data) {
    return data[10];
}

/*
 * ============================================================================
 * Keepalive Packet Parsing (Port 50000)
 * ============================================================================
 */

void parse_keepalive(const uint8_t *data, size_t len, uint32_t src_ip) {
    if (len < sizeof(prolink_header_t)) return;
    
    const prolink_header_t *hdr = (const prolink_header_t *)data;
    uint8_t subtype = hdr->subtype;
    
    if (subtype == PKT_TYPE_DEVICE_ANNOUNCE) {
        /* Device announcement packet - use struct for parsing */
        if (len < sizeof(prolink_announce_packet_t)) return;
        
        const prolink_announce_packet_t *pkt = (const prolink_announce_packet_t *)data;
        
        /* Extract and trim device name */
        char name[21];
        memcpy(name, pkt->device_name, 20);
        name[20] = '\0';
        for (int i = 19; i >= 0 && name[i] == ' '; i--) name[i] = '\0';
        
        uint8_t device_num = pkt->device_num;
        uint8_t device_type = pkt->device_type;
        
        /* Check for slot conflict with REAL devices (CDJ/DJM, not rekordbox) */
        if (device_num == our_device_num && our_device_num > 0 &&
            device_type != PROLINK_DEVICE_REKORDBOX) {
            /* Real hardware claiming our slot - must yield */
            handle_slot_conflict(device_num, name);
        }
        
        cdj_device_t *dev = find_device(device_num);
        if (dev) {
            uint8_t was_new = (dev->name[0] == '\0');
            strncpy(dev->name, name, sizeof(dev->name) - 1);
            dev->ip_addr = src_ip;
            
            /* Device type from packet, also auto-detect from name.
             * NXS-GW is a gateway device broadcast by CDJ-3000X, not a real CDJ */
            if (strstr(name, "NXS-GW") != NULL || strstr(name, "-GW") != NULL) {
                dev->device_type = DEVICE_TYPE_UNKNOWN;  /* Filter out gateway devices */
            } else if (device_type == PROLINK_DEVICE_CDJ || strstr(name, "CDJ") != NULL) {
                dev->device_type = DEVICE_TYPE_CDJ;
            } else if (device_type == PROLINK_DEVICE_DJM || strstr(name, "DJM") != NULL) {
                dev->device_type = DEVICE_TYPE_DJM;
            } else if (device_type == PROLINK_DEVICE_REKORDBOX || strstr(name, "rekordbox") != NULL) {
                dev->device_type = DEVICE_TYPE_REKORDBOX;
            } else if (device_num > 16) {
                /* High device numbers without CDJ/DJM in name are likely auxiliary devices */
                dev->device_type = DEVICE_TYPE_UNKNOWN;
            } else {
                dev->device_type = DEVICE_TYPE_CDJ;
            }
            dev->last_seen = time(NULL);
            
            /* Copy MAC address from packet */
            memcpy(dev->mac_addr, pkt->mac_addr, 6);
            
            if (was_new) {
                logmsg("cdj", "🔗 Device %d: %s connected @ %s",
                       device_num, name, ip_to_str(src_ip));
                
                /* Start registration when we see a new CDJ */
                if (dev->device_type == DEVICE_TYPE_CDJ && 
                    capture_interface && 
                    registration_state == REG_IDLE) {
                    vlogmsg("cdj", "[REG] Starting registration (CDJ detected)...");
                    do_full_registration(capture_interface);
                    last_keepalive_sent = time(NULL);
                }
            }
            
            if (verbose) {
                vlogmsg("cdj", "[ANNOUNCE] Device %d: %s (%s) at %s",
                           device_num, name, device_type_name(dev->device_type),
                           ip_to_str(src_ip));
            }
        }
    }
    else if (subtype == PKT_TYPE_KEEPALIVE) {
        /* Keep-alive packet - use struct for parsing */
        if (len < sizeof(prolink_keepalive_packet_t)) return;
        
        const prolink_keepalive_packet_t *pkt = (const prolink_keepalive_packet_t *)data;
        uint8_t device_num = pkt->device_num;
        
        cdj_device_t *dev = find_device(device_num);
        if (dev) {
            dev->ip_addr = src_ip;
            memcpy(dev->mac_addr, pkt->mac_addr, 6);
            dev->last_seen = time(NULL);
            
            /* Start registration if CDJ detected but no track info yet */
            if (dev->device_type == DEVICE_TYPE_CDJ && 
                capture_interface && 
                registration_state == REG_IDLE &&
                dev->track_title[0] == '\0') {
                vlogmsg("cdj", "[REG] Starting registration (CDJ keepalive, no track info)...");
                do_full_registration(capture_interface);
                last_keepalive_sent = time(NULL);
            }
            
            /* Check if a better slot became available (device went away) */
            try_optimize_slot();
        }
    }
    
    /* Handle registration keepalives - only if active */
    time_t now = time(NULL);
    if (registration_state == REG_ACTIVE && capture_interface) {
        int interval = (keepalives_sent_active < 3) ? 0 : 2;
        if (now - last_keepalive_sent >= interval) {
            do_full_registration(capture_interface);
            last_keepalive_sent = now;
        }
        check_go_passive();
    }
}

/*
 * ============================================================================
 * CDJ Status Packet Parsing (Port 50002)
 * ============================================================================
 */

/* Forward declaration — defined in Track Name Resolution section below */
void dbserver_reset_retry(void);

void parse_cdj_status(const uint8_t *data, size_t len, uint32_t src_ip) {
    if (len < sizeof(prolink_header_t)) return;
    
    const prolink_header_t *hdr = (const prolink_header_t *)data;
    uint8_t subtype = hdr->subtype;
    
    if (verbose) {
        vlogmsg("cdj", "[STATUS] Packet from %s: subtype=0x%02x len=%zu",
                   ip_to_str(src_ip), subtype, len);
    }
    
    /* Handle beat packets - use struct for parsing */
    if (subtype == PKT_TYPE_BEAT && len >= sizeof(cdj_beat_packet_t)) {
        const cdj_beat_packet_t *beat = (const cdj_beat_packet_t *)data;
        uint8_t device_num = beat->device_num;
        
        cdj_device_t *dev = find_device(device_num);
        if (!dev) return;
        
        dev->last_seen = time(NULL);
        dev->ip_addr = src_ip;
        
        /* Extract and trim device name */
        char name[21];
        memcpy(name, beat->device_name, 20);
        name[20] = '\0';
        for (int i = 19; i >= 0 && name[i] == ' '; i--) name[i] = '\0';
        if (name[0]) strncpy(dev->name, name, sizeof(dev->name) - 1);
        
        if (dev->device_type == 0 && strstr(name, "CDJ") != NULL) {
            dev->device_type = DEVICE_TYPE_CDJ;
        }
        
        /* BPM from beat packet */
        uint16_t bpm = BE16_TO_HOST(beat->bpm_be);
        if (bpm > 2000 && bpm < 25000) {
            dev->bpm_raw = bpm;
        }
        
        /* Don't infer playing from beat packets — DJM sends them as backup
         * metronome. F bit 6 in status packets is authoritative. */

        if (dev->track_slot == 0 && dev->device_type == DEVICE_TYPE_CDJ) {
            dev->track_slot = SLOT_USB;
        }
        
        check_media_change(dev);
        
        time_t now = time(NULL);
        static time_t last_beat_ui_update = 0;
        if (now != last_beat_ui_update) {
            last_beat_ui_update = now;
            
            /* Handle registration state machine - must register to receive 0x0a status packets! */
            if (capture_interface && registration_state != REG_PASSIVE) {
                /* During registration stages, send more frequently */
                int interval = (registration_state == REG_ACTIVE) ? 2 : 0;
                if (now - last_keepalive_sent >= interval) {
                    do_full_registration(capture_interface);
                    last_keepalive_sent = now;
                }
            }
            check_go_passive();
        }
        return;
    }
    
    if (subtype == PKT_TYPE_CDJ_STATUS) {
        /* Full CDJ status packet - use struct for parsing.
         * Increment counter for auto-passive detection during observation. */
        status_packets_seen++;

        if (verbose) {
            vlogmsg("cdj", "[STATUS] Got subtype 0x0a packet, len=%zu (need %zu)", len, sizeof(cdj_status_packet_t));
        }

        if (len < sizeof(cdj_status_packet_t)) {
            if (verbose) {
                vlogmsg("cdj", "[STATUS] Short status packet (%zu < %zu bytes)", 
                           len, sizeof(cdj_status_packet_t));
            }
            return;
        }
        
        const cdj_status_packet_t *pkt = (const cdj_status_packet_t *)data;
        uint8_t device_num = pkt->device_num;
        uint8_t subtype2 = pkt->subtype2;

        if (verbose) {
            if (len > 300) {
                /* CDJ-3000X 1152-byte packet: dump bytes 0x70-0x9f to find real play state */
                char hex[256] = {0};
                int hlen = 0;
                for (size_t i = 0x70; i < 0xa0 && i < len && hlen < 240; i++)
                    hlen += snprintf(hex + hlen, sizeof(hex) - hlen, "%02x ", data[i]);
                vlogmsg("cdj", "[STATUS] Dev%d: sub2=0x%02x rbid=%u slot=0x%02x [70-9f]: %s",
                           device_num, subtype2,
                           BE32_TO_HOST(pkt->rekordbox_id_be), pkt->track_slot, hex);
            } else {
                vlogmsg("cdj", "[STATUS] Dev%d: subtype2=0x%02x len=%zu rekordbox_id=%u slot=0x%02x play_state=0x%02x",
                           device_num, subtype2, len,
                           BE32_TO_HOST(pkt->rekordbox_id_be), pkt->track_slot,
                           pkt->play_state);
            }
        }

        /* CDJ-3000X sends 1152-byte packets with alternating zero-data variants
         * (rekordbox_id=0, slot=0). Track fields are unreliable in these but
         * P1 (play_state at 0x7b) and on-air ARE consistent. Update play state,
         * on-air, and liveness. Skip track/USB fields. */
        uint32_t pkt_rekordbox_id = BE32_TO_HOST(pkt->rekordbox_id_be);
        uint8_t pkt_track_slot = pkt->track_slot;
        if (pkt_rekordbox_id == 0 && pkt_track_slot == 0 && len > 300) {
            cdj_device_t *dev2 = find_device(device_num);
            if (dev2) {
                dev2->last_seen = time(NULL);
                dev2->ip_addr = src_ip;

                /* DEBUG: dump media bytes from zero-data variant too */
                {
                    static time_t last_zd_dump[MAX_DEVICES] = {0};
                    static uint8_t prev_zd[MAX_DEVICES][16] = {{0}};
                    int zidx = (int)(dev2 - devices);
                    time_t now_zd = time(NULL);
                    uint8_t zc[16] = {0};
                    if (len > 0xb9) {
                        zc[0] = data[0x6a]; zc[1] = data[0x6b];
                        zc[2] = data[0x6f]; zc[3] = data[0x73];
                        zc[4] = data[0x75]; zc[5] = data[0xb7];
                        zc[6] = data[0xb8]; zc[7] = data[0xb9];
                        zc[8] = data[0x37]; zc[9] = data[0x29]; zc[10] = data[0x28];
                    }
                    /* Skip Ua/Sa (index 0,1) in comparison — they toggle every packet */
                    int zchanged = memcmp(zc + 2, prev_zd[zidx] + 2, sizeof(zc) - 2) != 0;
                    if (zchanged || (verbose && now_zd - last_zd_dump[zidx] >= 5)) {
                        vlogmsg("cdj", "Dev%d [media-zd] Ua=%02x Sa=%02x Ul=%02x Sl=%02x L=%02x "
                                "Mp=%02x Ue=%02x Se=%02x tsrc=%02x Dr=%d Sr=%02x%s",
                                device_num, zc[0], zc[1], zc[2], zc[3], zc[4],
                                zc[5], zc[6], zc[7], zc[8], zc[10], zc[9],
                                zchanged ? " *** CHANGED" : "");
                        memcpy(prev_zd[zidx], zc, sizeof(zc));
                        last_zd_dump[zidx] = now_zd;
                    }
                }

                /* USB/SD presence — read from usb_state at 0x6f */
                uint8_t old_usb2 = dev2->usb_present;
                uint8_t old_sd2 = dev2->sd_present;
                dev2->usb_present = (pkt->usb_state != MEDIA_STATE_NONE);
                dev2->sd_present = (pkt->sd_state != MEDIA_STATE_NONE);
                dev2->usb_local_raw = pkt->usb_state;
                dev2->sd_local_raw = pkt->sd_state;
                /* Log on change */
                if ((dev2->usb_present != old_usb2 || dev2->sd_present != old_sd2)) {
                    logmsg("cdj", "Dev%d media change: Ul=0x%02x Sl=0x%02x L=0x%02x Mp=0x%02x "
                           "Dr=%d Sr=0x%02x tsrc=0x%02x",
                           device_num,
                           pkt->usb_state, pkt->sd_state, pkt->link_available,
                           pkt->media_presence,
                           pkt->source_player, pkt->track_slot, pkt->track_menu);
                }
                if (dev2->usb_present && !old_usb2) {
                    logmsg("cdj", "💾 Device %d: USB inserted", device_num);
                    dev2->usb_db_fetched = 0;
                    dev2->usb_olib_fetched = 0;
                    dev2->usb_fetch_attempt = 0;
                    dev2->usb_fetch_fails = 0;
                    dbserver_reset_retry();
                }
                if (!dev2->usb_present && old_usb2) {
                    logmsg("cdj", "💾 Device %d: USB removed", device_num);
                    dev2->usb_db_fetched = 0;
                    dev2->usb_olib_fetched = 0;
                    dev2->usb_fetch_attempt = 0;
                    dev2->usb_fetch_fails = 0;
                    remove_pdb_database(dev2->ip_addr, SLOT_USB);
                    remove_onelibrary(dev2->ip_addr, SLOT_USB);
                }
                if (dev2->sd_present && !old_sd2) {
                    logmsg("cdj", "💾 Device %d: SD inserted", device_num);
                    dev2->sd_db_fetched = 0;
                    dev2->sd_olib_fetched = 0;
                    dev2->sd_fetch_attempt = 0;
                    dev2->sd_fetch_fails = 0;
                    dbserver_reset_retry();
                }
                if (!dev2->sd_present && old_sd2) {
                    logmsg("cdj", "💾 Device %d: SD removed", device_num);
                    dev2->sd_db_fetched = 0;
                    dev2->sd_olib_fetched = 0;
                    dev2->sd_fetch_attempt = 0;
                    dev2->sd_fetch_fails = 0;
                    remove_pdb_database(dev2->ip_addr, SLOT_SD);
                    remove_onelibrary(dev2->ip_addr, SLOT_SD);
                }
                /* P1 + P2 play state — same logic as main path */
                uint8_t old_playing = dev2->playing;
                uint8_t p2 = data[0x8b];
                int p1_playing = (pkt->play_state == PLAY_STATE_PLAYING ||
                                 pkt->play_state == PLAY_STATE_LOOPING);
                dev2->playing = p1_playing && !(p2 & 0x04);
                if (dev2->playing && !old_playing) {
                    dev2->play_started = time(NULL);
                    if (dev2->track_title[0])
                        logmsg("cdj", "▶ DECK %d: Playing - %s - %s",
                               device_num, dev2->track_artist, dev2->track_title);
                } else if (!dev2->playing && old_playing) {
                    dev2->play_started = 0;
                    if (dev2->track_title[0])
                        logmsg("cdj", "⏸ DECK %d: Paused", device_num);
                }
                uint8_t old_on_air = dev2->on_air;
                dev2->on_air = (pkt->status_flags & STATE_FLAG_ON_AIR) != 0;
                if (dev2->on_air != old_on_air) {
                    dev2->on_air_available = 1;
                }
                uint16_t bpm = BE16_TO_HOST(pkt->bpm_be);
                if (bpm > 2000 && bpm < 25000) dev2->bpm_raw = bpm;
                return;
            }
        }
        
        cdj_device_t *dev = find_device(device_num);
        if (!dev) return;
        
        dev->last_seen = time(NULL);
        dev->ip_addr = src_ip;
        
        /* Extract and trim device name */
        char name[21];
        memcpy(name, pkt->device_name, 20);
        name[20] = '\0';
        for (int i = 19; i >= 0 && name[i] == ' '; i--) name[i] = '\0';
        if (name[0]) strncpy(dev->name, name, sizeof(dev->name) - 1);
        
        /* Infer device type from name if not already set */
        if (dev->device_type == 0) {
            if (strstr(name, "CDJ") != NULL) {
                dev->device_type = DEVICE_TYPE_CDJ;
            } else if (strstr(name, "DJM") != NULL || strstr(name, "XDJ-XZ") != NULL) {
                dev->device_type = DEVICE_TYPE_DJM;
            } else if (strstr(name, "rekordbox") != NULL) {
                dev->device_type = DEVICE_TYPE_REKORDBOX;
            }
        }
        
        /* DEBUG: dump media-relevant bytes on change or every 5 seconds.
         * This helps us find which fields actually indicate USB insert/remove. */
        {
            static time_t last_media_dump[MAX_DEVICES] = {0};
            static uint8_t prev_bytes[MAX_DEVICES][16] = {{0}};
            int didx = (int)(dev - devices);
            time_t now_dbg = time(NULL);

            /* Collect key bytes: 0x6a-0x6b (activity), 0x6f (Ul), 0x73 (Sl),
             * 0x75 (L), 0xb7 (Mp), 0xb8-0xb9 (unsafe eject) */
            uint8_t cur[16] = {0};
            if (len > 0xb9) {
                cur[0] = data[0x6a]; cur[1] = data[0x6b];  /* Ua, Sa */
                cur[2] = data[0x6f]; cur[3] = data[0x73];  /* Ul, Sl */
                cur[4] = data[0x75];                         /* L */
                cur[5] = data[0xb7];                         /* Mp */
                cur[6] = data[0xb8]; cur[7] = data[0xb9];  /* Ue, Se */
                cur[8] = data[0x37];                         /* tsrc */
                cur[9] = data[0x29];                         /* Sr */
                cur[10] = data[0x28];                        /* Dr */
            }

            /* Skip Ua/Sa (index 0,1) in comparison — they toggle every packet */
            int changed = memcmp(cur + 2, prev_bytes[didx] + 2, sizeof(cur) - 2) != 0;
            if (changed || (verbose && now_dbg - last_media_dump[didx] >= 5)) {
                vlogmsg("cdj", "Dev%d [media] Ua=%02x Sa=%02x Ul=%02x Sl=%02x L=%02x "
                        "Mp=%02x Ue=%02x Se=%02x tsrc=%02x Dr=%d Sr=%02x%s",
                        device_num, cur[0], cur[1], cur[2], cur[3], cur[4],
                        cur[5], cur[6], cur[7], cur[8], cur[10], cur[9],
                        changed ? " *** CHANGED" : "");
                memcpy(prev_bytes[didx], cur, sizeof(cur));
                last_media_dump[didx] = now_dbg;
            }
        }

        /* Detect media insertion and proactively fetch databases */
        uint8_t old_usb = dev->usb_present;
        uint8_t old_sd = dev->sd_present;
        dev->usb_present = (pkt->usb_state != MEDIA_STATE_NONE);
        dev->sd_present = (pkt->sd_state != MEDIA_STATE_NONE);
        dev->usb_local_raw = pkt->usb_state;
        dev->sd_local_raw = pkt->sd_state;
        
        /* USB inserted */
        if (dev->usb_present && !old_usb) {
            logmsg("cdj", "💾 Device %d: USB inserted", device_num);
            dev->usb_db_fetched = 0;
            dev->usb_olib_fetched = 0;
            dev->usb_fetch_attempt = 0;
            dev->usb_fetch_fails = 0;
            dbserver_reset_retry();
        }
        /* USB removed */
        if (!dev->usb_present && old_usb) {
            logmsg("cdj", "💾 Device %d: USB removed", device_num);
            dev->usb_db_fetched = 0;
            dev->usb_olib_fetched = 0;
            dev->usb_fetch_attempt = 0;
            dev->usb_fetch_fails = 0;
            remove_pdb_database(dev->ip_addr, SLOT_USB);
            remove_onelibrary(dev->ip_addr, SLOT_USB);
        }
        /* SD inserted */
        if (dev->sd_present && !old_sd) {
            logmsg("cdj", "💾 Device %d: SD inserted", device_num);
            dev->sd_db_fetched = 0;
            dev->sd_olib_fetched = 0;
            dev->sd_fetch_attempt = 0;
            dev->sd_fetch_fails = 0;
            dbserver_reset_retry();
        }
        /* SD removed */
        if (!dev->sd_present && old_sd) {
            logmsg("cdj", "💾 Device %d: SD removed", device_num);
            dev->sd_db_fetched = 0;
            dev->sd_olib_fetched = 0;
            dev->sd_fetch_attempt = 0;
            dev->sd_fetch_fails = 0;
            remove_pdb_database(dev->ip_addr, SLOT_SD);
            remove_onelibrary(dev->ip_addr, SLOT_SD);
        }
        
        /* Proactively fetch databases when media is detected.
         * Must wait for registration to be ready (5 keepalives sent) or CDJ will refuse NFS.
         * On failure, retry after 10s (CDJ may still be indexing after media swap). */
        if (capture_interface && our_ip != 0 && dev->ip_addr != 0 &&
            keepalives_sent_active >= MIN_KEEPALIVES_BEFORE_NFS) {
            time_t fetch_now = time(NULL);

            /* Fetch USB databases if USB is present locally (not via Link).
             * Byte 0x3a == 0x01 indicates Link client — no local media.
             * usb_state 0x00 (MEDIA_STATE_LOADED) = real media present.
             * Give up after 3 NFS failures. */
            if (dev->usb_local_raw == MEDIA_STATE_LOADED &&
                dev->usb_fetch_fails < 3 &&
                (!dev->usb_olib_fetched || !dev->usb_db_fetched) &&
                fetch_now - dev->usb_fetch_attempt >= 10) {

                int usb_fetched_something = 0;
                if (!dev->usb_olib_fetched && onelibrary_key_available()) {
                    dev->usb_fetch_attempt = fetch_now;
                    logmsg("cdj", "📥 Device %d: Fetching USB OneLibrary...", device_num);
                    if (fetch_onelibrary_database(dev->ip_addr, SLOT_USB) == 0) {
                        dev->usb_olib_fetched = 1;
                        dev->usb_db_fetched = 1;
                        dev->usb_fetch_fails = 0;
                        usb_fetched_something = 1;
                        if (dev->track_slot == SLOT_USB && dev->track_title[0] == '\0')
                            dev->lookup_failed_id = 0;
                    }
                }
                if (!dev->usb_db_fetched) {
                    dev->usb_fetch_attempt = fetch_now;
                    logmsg("cdj", "📥 Device %d: Fetching USB PDB...", device_num);
                    pdb_database_t *db = create_pdb_database(dev->ip_addr, SLOT_USB);
                    if (db) {
                        if (fetch_rekordbox_database(dev->ip_addr, SLOT_USB, db) == 0) {
                            logmsg("cdj", "✅ Device %d: USB PDB loaded (%d tracks)",
                                   device_num, db->track_count);
                            dev->usb_db_fetched = 1;
                            dev->usb_olib_fetched = 1; /* PDB success → skip OneLibrary */
                            dev->usb_fetch_fails = 0;
                            usb_fetched_something = 1;
                            if (dev->track_slot == SLOT_USB && dev->track_title[0] == '\0')
                                dev->lookup_failed_id = 0;
                        }
                    }
                }
                if (!usb_fetched_something) {
                    dev->usb_fetch_fails++;
                    if (dev->usb_fetch_fails >= 3)
                        logmsg("cdj", "📥 Device %d: USB NFS failed 3x — no physical media?", device_num);
                }
            }

            /* Fetch SD databases - same strategy */
            if (dev->sd_local_raw == MEDIA_STATE_LOADED &&
                dev->sd_fetch_fails < 3 &&
                (!dev->sd_olib_fetched || !dev->sd_db_fetched) &&
                fetch_now - dev->sd_fetch_attempt >= 10) {

                int sd_fetched_something = 0;
                if (!dev->sd_olib_fetched && onelibrary_key_available()) {
                    dev->sd_fetch_attempt = fetch_now;
                    logmsg("cdj", "📥 Device %d: Fetching SD OneLibrary...", device_num);
                    if (fetch_onelibrary_database(dev->ip_addr, SLOT_SD) == 0) {
                        dev->sd_olib_fetched = 1;
                        dev->sd_db_fetched = 1;
                        dev->sd_fetch_fails = 0;
                        sd_fetched_something = 1;
                        if (dev->track_slot == SLOT_SD && dev->track_title[0] == '\0')
                            dev->lookup_failed_id = 0;
                    }
                }
                if (!dev->sd_db_fetched) {
                    dev->sd_fetch_attempt = fetch_now;
                    logmsg("cdj", "📥 Device %d: Fetching SD PDB...", device_num);
                    pdb_database_t *db = create_pdb_database(dev->ip_addr, SLOT_SD);
                    if (db) {
                        if (fetch_rekordbox_database(dev->ip_addr, SLOT_SD, db) == 0) {
                            logmsg("cdj", "✅ Device %d: SD PDB loaded (%d tracks)",
                                   device_num, db->track_count);
                            dev->sd_db_fetched = 1;
                            dev->sd_olib_fetched = 1; /* PDB success → skip OneLibrary */
                            dev->sd_fetch_fails = 0;
                            sd_fetched_something = 1;
                            if (dev->track_slot == SLOT_SD && dev->track_title[0] == '\0')
                                dev->lookup_failed_id = 0;
                        }
                    }
                }
                if (!sd_fetched_something) {
                    dev->sd_fetch_fails++;
                    if (dev->sd_fetch_fails >= 3)
                        logmsg("cdj", "📥 Device %d: SD NFS failed 3x — no physical media?", device_num);
                }
            }
        }
        
        uint8_t old_playing = dev->playing;
        uint16_t old_track = dev->track_id;
        uint8_t old_slot = dev->track_slot;
        uint32_t old_rekordbox = dev->rekordbox_id;
        
        dev->track_slot = pkt->track_slot;
        dev->track_source_player = pkt->source_player;
        dev->track_source_slot = pkt->track_slot;  /* Use track_slot, Tr is track type not slot */
        
        /* Determine track type from Tr field (byte 0x2a) */
        if (pkt->track_type == TRACK_CD_AUDIO || dev->track_slot == SLOT_CD) {
            dev->track_type = TRACK_UNANALYZED;
            if (verbose > 1) {
                vlogmsg("cdj", "[STATUS] CD/audio track detected, using UNANALYZED type");
            }
        } else if (pkt->track_type == TRACK_REKORDBOX) {
            dev->track_type = TRACK_REKORDBOX;
        } else if (pkt->track_type == TRACK_UNANALYZED) {
            dev->track_type = TRACK_UNANALYZED;
        } else {
            /* Default: try to determine from rekordbox_id presence */
            dev->track_type = TRACK_REKORDBOX;
        }
        if (verbose > 1) {
            vlogmsg("cdj", "[STATUS] Dev%d: Tr=%d slot=%d rekordbox_id=%u track_type=%s", 
                       device_num, pkt->track_type, dev->track_slot, 
                       BE32_TO_HOST(pkt->rekordbox_id_be),
                       dev->track_type == TRACK_REKORDBOX ? "REKORDBOX" : "UNANALYZED");
        }
        
        dev->rekordbox_id = BE32_TO_HOST(pkt->rekordbox_id_be);
        dev->track_number = BE16_TO_HOST(pkt->track_num_be);
        dev->track_id = (uint16_t)dev->track_number;
        
        if (verbose) {
            vlogmsg("cdj", "[STATUS] Parsed CDJ%d: rekordbox_id=%u track_num=%u slot=%s",
                       device_num, dev->rekordbox_id, dev->track_number, cdj_slot_name(dev->track_slot));
        }
        
        /* P1 (0x7b) for play state, P2 (0x8b) for jogwheel hold detection.
         * P1 says PLAYING during jogwheel hold — P2 distinguishes it:
         * P2=0xfa/0x7a/0x9a = actually playing, P2=0xfe/0x7e/0x9e = stopped/held.
         * Use P1 && (P2 low bit == 0) as the "truly playing" indicator. */
        uint8_t p2 = data[0x8b];
        int p1_playing = (pkt->play_state == PLAY_STATE_PLAYING ||
                         pkt->play_state == PLAY_STATE_LOOPING);
        dev->playing = p1_playing && !(p2 & 0x04);  /* P2 bit 2 clear = playing */
        dev->cued = (pkt->play_state == PLAY_STATE_PAUSED ||
                    pkt->play_state == PLAY_STATE_CUED);
        
        /* Parse on-air status from status flags */
        uint8_t old_on_air = dev->on_air;
        dev->on_air = (pkt->status_flags & STATE_FLAG_ON_AIR) != 0;
        if (dev->on_air != old_on_air) {
            dev->on_air_available = 1;  /* We've seen on_air change, so DJM is present */
            if (dev->on_air) {
                if (dev->track_title[0]) {
                    logmsg("cdj", "🔴 DECK %d ON AIR: %s — %s", device_num,
                           dev->track_artist, dev->track_title);
                } else {
                    logmsg("cdj", "🔴 DECK %d ON AIR", device_num);
                }
                /* Signal confidence: on-air edge (strong) + sustained on-air */
                int didx = (int)(dev - devices);
                confidence_signal(didx, SIG_CDJ_ON_AIR_EDGE, 0, NULL, NULL, NULL, 0);
                confidence_signal(didx, SIG_CDJ_ON_AIR, 0, NULL, NULL, NULL, 0);
            } else {
                logmsg("cdj", "⚪ DECK %d off air", device_num);
                int didx = (int)(dev - devices);
                confidence_signal(didx, SIG_CDJ_OFF_AIR, 0, NULL, NULL, NULL, 0);
            }
        }
        
        /* Track when playback started (for duration-based fallback) */
        if (dev->playing && !old_playing) {
            dev->play_started = time(NULL);
            /* Signal confidence: deck started playing */
            if (dev->track_title[0]) {
                confidence_signal((int)(dev - devices), SIG_CDJ_PLAYING, 0,
                                  NULL, NULL, NULL, 0);
            }
        } else if (!dev->playing) {
            dev->play_started = 0;
        }
        
        uint16_t bpm = BE16_TO_HOST(pkt->bpm_be);
        if (bpm > 0 && bpm < 50000) {
            dev->bpm_raw = bpm;
        }

        /* Pitch from status packet: 0x100000 = 0%, 0x000000 = -100%, 0x200000 = +100%
         * Store as percentage * 100 (e.g. +3.26% = 326) for easy UI display */
        uint32_t pitch_raw = BE32_TO_HOST(pkt->pitch1_be);
        dev->pitch_raw = (int32_t)(((int64_t)pitch_raw - 0x100000) * 10000 / 0x100000);

        dev->beat_number = BE32_TO_HOST(pkt->beat_num_be);
        dev->beat_in_bar = pkt->beat_in_bar;

        /* Loop detection from play state */
        dev->looping = (pkt->play_state == PLAY_STATE_LOOPING) ||
                       (pkt->emergency_loop != 0);
        dev->loop_beats = 0;

        /* CDJ-3000 extended fields (512-byte packets) */
        if (len >= 0x1ca) {
            uint32_t loop_start = BE32_TO_HOST(data + 0x1b6);
            uint32_t loop_end   = BE32_TO_HOST(data + 0x1be);
            if (loop_start > 0 && loop_end > loop_start) {
                dev->looping = 1;
                dev->loop_beats = (uint16_t)((data[0x1c8] << 8) | data[0x1c9]);
            }
        }
        if (len >= 0x15f) {
            dev->key_note = data[0x15c];
            dev->key_scale = data[0x15d];
            dev->key_accidental = data[0x15e];
            dev->master_tempo = data[0x158];
        }

        int track_changed = (dev->track_id != old_track) || 
                            (dev->rekordbox_id != old_rekordbox) ||
                            (dev->track_slot != old_slot);  /* Also trigger on slot change! */
        
        if (track_changed) {
            dev->track_title[0] = '\0';
            dev->track_artist[0] = '\0';
            dev->track_isrc[0] = '\0';
            dev->lookup_failed_id = 0;  /* Reset failed lookup marker */
            dev->last_lookup_time = 0;  /* Allow immediate lookup for new track */
            dev->logged_rekordbox_id = 0;  /* Allow new track to be logged */
            dev->play_started = dev->playing ? time(NULL) : 0;  /* Reset play timer on track change */
            /* Reset confidence for this deck — new track starts at 0 */
            confidence_reset_deck((int)(dev - devices));
        }
        
        /* Skip lookup if no track loaded, already failed for this ID, or already have title */
        time_t now_lookup = time(NULL);
        int need_lookup = (dev->rekordbox_id > 0) &&
                          (dev->track_title[0] == '\0') &&
                          (dev->lookup_failed_id != dev->rekordbox_id) &&
                          (now_lookup - dev->last_lookup_time >= 5);  /* Rate-limit: once per 5s */

        if ((track_changed && dev->rekordbox_id > 0) || need_lookup) {
            dev->last_lookup_time = now_lookup;
            /* Only log on track change to avoid spam during retry attempts */
            if (verbose && track_changed) {
                vlogmsg("cdj", "[LOOKUP] CDJ %d: Looking up rekordbox_id=%u (track_id=%d, slot=%s)",
                           device_num, dev->rekordbox_id, dev->track_id, cdj_slot_name(dev->track_slot));
            }
            
            int found = 0;
            int retry_later = 0;  /* 1 = temporary skip, will retry */
            
            if (dev->track_slot == SLOT_CD) {
                retry_later = try_resolve_track_name(dev);
                found = (dev->track_title[0] != '\0');
            } else if (dev->track_slot > 0) {
                /* Determine source device for database lookups.
                 * Link tracks come from a different device's media. */
                uint32_t src_ip = dev->ip_addr;
                uint8_t  src_slot = dev->track_slot;
                if (dev->track_source_player > 0 &&
                    dev->track_source_player != dev->device_num) {
                    cdj_device_t *src = get_device(dev->track_source_player);
                    if (src && src->ip_addr)
                        src_ip = src->ip_addr;
                }

                /* First try track cache (scoped to source device) */
                track_cache_entry_t *tc = find_track_cache(dev->rekordbox_id, src_ip);
                if (tc && tc->title[0]) {
                    utf8_safe_copy(dev->track_title, tc->title, sizeof(dev->track_title));
                    if (tc->artist[0]) {
                        utf8_safe_copy(dev->track_artist, tc->artist, sizeof(dev->track_artist));
                    }
                    if (tc->isrc[0]) {
                        utf8_safe_copy(dev->track_isrc, tc->isrc, sizeof(dev->track_isrc));
                    }
                    found = 1;
                } else {
                    /* Try OneLibrary first (scoped to source device) */
                    char ol_title[128] = {0}, ol_artist[128] = {0}, ol_isrc[64] = {0};
                    if (onelibrary_lookup(dev->rekordbox_id,
                                          src_ip, src_slot,
                                          ol_title, sizeof(ol_title),
                                          ol_artist, sizeof(ol_artist),
                                          ol_isrc, sizeof(ol_isrc)) == 0 &&
                        ol_title[0] != '\0' && ol_artist[0] != '\0') {
                        utf8_safe_copy(dev->track_title, ol_title, sizeof(dev->track_title));
                        utf8_safe_copy(dev->track_artist, ol_artist, sizeof(dev->track_artist));
                        if (ol_isrc[0]) {
                            utf8_safe_copy(dev->track_isrc, ol_isrc, sizeof(dev->track_isrc));
                        }
                        found = 1;
                        dev->track_db_src = DB_SRC_ONELIBRARY;
                        vlogmsg("cdj", "🎵 %s - %s (via OneLibrary)", ol_artist, ol_title);
                    }

                    /* Try DBServer (authoritative — queries CDJ's own database) */
                    if (!found) {
                        retry_later = try_resolve_track_name(dev);
                        found = (dev->track_title[0] != '\0');
                        if (found) dev->track_db_src = DB_SRC_DBSERVER;
                    }

                    /* Fall back to PDB (parsed export — may have version differences) */
                    if (!found) {
                        TrackID *pdb = lookup_pdb_track(dev->rekordbox_id, src_ip, src_slot);
                        if (pdb && pdb->title[0] && pdb->artist[0]) {
                            utf8_safe_copy(dev->track_title, pdb->title, sizeof(dev->track_title));
                            utf8_safe_copy(dev->track_artist, pdb->artist, sizeof(dev->track_artist));
                            if (pdb->has_isrc && pdb->isrc[0])
                                utf8_safe_copy(dev->track_isrc, pdb->isrc, sizeof(dev->track_isrc));
                            found = 1;
                            dev->track_db_src = DB_SRC_PDB;
                        }
                    } /* end if (!found) - OneLibrary/DBServer/PDB chain */
                }
            }
            
            /* Mark failed lookup to prevent retry spam - but not if temporary skip */
            if (!found && !retry_later && dev->rekordbox_id > 0) {
                dev->lookup_failed_id = dev->rekordbox_id;
            }

            /* Signal confidence model when metadata is resolved */
            if (found && dev->track_title[0]) {
                int didx = (int)(dev - devices);
                confidence_signal(didx, SIG_CDJ_LOADED, 0,
                                  dev->track_artist, dev->track_title,
                                  dev->track_isrc, dev->rekordbox_id);
            }
        }
        
        /* Log track and play state changes */
        if (dev->track_id != old_track || dev->track_slot != old_slot ||
            dev->rekordbox_id != old_rekordbox ||
            dev->playing != old_playing) {

            const char *title = dev->track_title[0] ? dev->track_title : "(unknown)";
            const char *artist = dev->track_artist[0] ? dev->track_artist : NULL;

            if (dev->playing && !old_playing) {
                if (artist) {
                    logmsg("cdj", "▶ DECK %d: Playing - %s - %s", device_num, artist, title);
                } else {
                    logmsg("cdj", "▶ DECK %d: Playing - %s", device_num, title);
                }
            } else if (dev->track_id != old_track || dev->rekordbox_id != old_rekordbox) {
                if (dev->track_id == 0 && dev->rekordbox_id == 0) {
                    logmsg("cdj", "⏏ DECK %d: Ejected", device_num);
                } else if (artist) {
                    logmsg("cdj", "📀 DECK %d: Loaded - %s - %s", device_num, artist, title);
                } else {
                    logmsg("cdj", "📀 DECK %d: Loaded - %s", device_num, title);
                }
            } else if (!dev->playing && old_playing) {
                logmsg("cdj", "⏸ DECK %d: Paused", device_num);
            }
        }
        
        if (verbose > 1) {
            vlogmsg("cdj", "[STATUS] CDJ #%d: track=%d slot=%s type=%d playing=%d bpm=%.2f",
                       device_num, dev->track_id, cdj_slot_name(dev->track_slot),
                       dev->track_type, dev->playing, dev->bpm_raw / 100.0f);
        }
    }
}

/*
 * ============================================================================
 * Beat Packet Parsing (Port 50001)
 * ============================================================================
 */

void parse_beat(const uint8_t *data, size_t len, uint32_t src_ip) {
    (void)src_ip;  /* Unused but kept for consistent callback signature */
    if (len < sizeof(cdj_beat_packet_t)) return;
    
    const cdj_beat_packet_t *pkt = (const cdj_beat_packet_t *)data;
    uint8_t device_num = pkt->device_num;
    uint8_t subtype = pkt->header.subtype;
    
    if (subtype != PKT_TYPE_BEAT && verbose) {
        vlogmsg("cdj", "[BEAT-PORT] type=0x%02x len=%zu from CDJ#%d", subtype, len, device_num);
    }
    
    /* Store beat position for UI visualization */
    cdj_device_t *bdev = find_device(device_num);
    if (bdev) {
        bdev->beat_in_bar = pkt->beat_in_bar;
        uint16_t bpm = BE16_TO_HOST(pkt->bpm_be);
        if (bpm > 2000 && bpm < 25000) bdev->bpm_raw = bpm;
    }

    if (verbose > 2) {
        uint32_t next_beat_ms = BE32_TO_HOST(pkt->next_beat_be);
        uint16_t bpm = BE16_TO_HOST(pkt->bpm_be);
        vlogmsg("cdj", "[BEAT] CDJ #%d next_beat=%u ms bpm=%.2f beat=%u/4",
                   device_num, next_beat_ms, bpm / 100.0f, pkt->beat_in_bar);
    }
}

/*
 * ============================================================================
 * CDJ-3000 Position Packet Parsing (Port 50001, subtype2=0x00)
 * ============================================================================
 * CDJ-3000 and newer send absolute position packets every ~30ms.
 * These provide track length, playhead position, pitch, and BPM.
 */

void parse_position(const uint8_t *data, size_t len, uint32_t src_ip) {
    if (len < sizeof(cdj_position_packet_t)) return;

    /* Debug: dump first position packet from each device to understand structure */
    static uint8_t dumped[MAX_DEVICES] = {0};
    if (verbose) {
        /* Try to identify device from typical offset */
        uint8_t maybe_dev = data[0x21];
        if (maybe_dev < MAX_DEVICES && !dumped[maybe_dev]) {
            dumped[maybe_dev] = 1;
            char hex[256] = {0};
            int hlen = 0;
            for (size_t i = 0; i < len && i < 64 && hlen < 240; i++)
                hlen += snprintf(hex + hlen, sizeof(hex) - hlen, "%02x ", data[i]);
            vlogmsg("cdj", "[POS] First position pkt (len=%zu) from %s: %s",
                       len, ip_to_str(src_ip), hex);
        }
    }

    const cdj_position_packet_t *pkt = (const cdj_position_packet_t *)data;
    uint8_t device_num = pkt->device_num;

    cdj_device_t *dev = find_device(device_num);
    if (!dev) return;

    dev->last_seen = time(NULL);
    dev->ip_addr = src_ip;

    /* Update position and track length */
    uint32_t playhead = BE32_TO_HOST(pkt->playhead_be);
    dev->position_ms = playhead;
    uint32_t track_len = BE32_TO_HOST(pkt->track_length_be);
    if (track_len > 0 && track_len < 100000)
        dev->track_length_sec = track_len;

    /* Track playhead for position display (not used for play detection —
     * P1+P2 from status packets handle that properly). */
    dev->last_position_ms = playhead;

    /* Update BPM if valid (0xffffffff means unknown) */
    uint32_t raw_bpm = BE32_TO_HOST(pkt->bpm_be);
    if (raw_bpm != 0xffffffff && raw_bpm > 0) {
        /* Position packet BPM is *10, our bpm_raw is *100 */
        dev->bpm_raw = (uint16_t)(raw_bpm * 10);
    }

    /* Pitch: status packet Pitch1 (0x8c) is the authoritative source using
     * the well-documented 0x100000 encoding, parsed in parse_cdj_status.
     * Works on all CDJ models. Position packet pitch at 0x2c uses a
     * different encoding — not used for display. */

    /* Don't set dev->playing from position packets — F bit 6 in status
     * packets is authoritative. Position packets arrive even when paused. */

    if (verbose > 2) {
        uint32_t track_len = BE32_TO_HOST(pkt->track_length_be);
        int32_t pitch_raw;
        memcpy(&pitch_raw, pkt->pitch_be, 4);
        pitch_raw = (int32_t)BE32_TO_HOST((const uint8_t *)&pitch_raw);
        vlogmsg("cdj", "[POSITION] CDJ #%d pos=%u ms len=%u s bpm=%.1f pitch=%.2f%%",
                   device_num, playhead, track_len,
                   raw_bpm == 0xffffffff ? 0.0f : raw_bpm / 10.0f,
                   pitch_raw / 6400.0f);
    }
}

/*
 * ============================================================================
 * Track Name Resolution
 * ============================================================================
 */

/* Rate limiting for dbserver queries */
static time_t last_query_time = 0;
static uint32_t last_query_id = 0;
static int query_fail_count = 0;

/* Reset DBServer retry state (call on media change).
 * Forward-declared before parse_cdj_status which calls it. */
void dbserver_reset_retry(void) {
    query_fail_count = 0;
    last_query_time = 0;
    last_query_id = 0;
}

/* Returns: 0 = done (success or permanent failure), 1 = temporary skip (retry later) */
int try_resolve_track_name(cdj_device_t *dev) {
    if (!dev || !dev->active) return 0;
    
    /* Rate limit: don't query same track more than once per 5 seconds */
    time_t now = time(NULL);
    if (dev->rekordbox_id == last_query_id && now - last_query_time < 5) {
        return 1;  /* Rate limited - will retry later, don't mark as failed */
    }
    
    /* Exponential backoff after failures: 5s, 10s, 20s, 40s, capped at 60s */
    {
        int backoff = 5;
        if (query_fail_count > 2) backoff = 10;
        if (query_fail_count > 5) backoff = 20;
        if (query_fail_count > 8) backoff = 40;
        if (query_fail_count > 12) backoff = 60;
        if (now - last_query_time < backoff) {
            return 1;  /* Backing off - will retry later */
        }
    }
    
    uint8_t target_device = dev->device_num;
    
    if (dev->track_slot == SLOT_CD && dev->track_id > 0) {
        char title[128] = {0};
        char artist[128] = {0};
        
        vlogmsg("cdj", "[CD] Querying CD-text for track %d on %s (target=%d)",
                   dev->track_id, ip_to_str(dev->ip_addr), target_device);
        
        int dbresult = dbserver_query_metadata(dev->ip_addr, 0, target_device,
                                               SLOT_CD, TRACK_UNANALYZED,
                                               dev->track_id, 
                                               title, sizeof(title), 
                                               artist, sizeof(artist));
        
        if (dbresult == 0 && title[0] != '\0') {
            utf8_safe_copy(dev->track_title, title, sizeof(dev->track_title));
            if (artist[0] != '\0') {
                utf8_safe_copy(dev->track_artist, artist, sizeof(dev->track_artist));
            }
            vlogmsg("cdj", "[CD] Got CD-text: %s - %s", artist, title);
        } else {
            snprintf(dev->track_title, sizeof(dev->track_title), 
                    "CD Track %d", dev->track_id);
            if (dbresult != 0) {
                vlogmsg("cdj", "[CD] CD-text query failed (result=%d)", dbresult);
            }
        }
        return 0;  /* CD done */
    }
    else if (dev->rekordbox_id > 0 && dev->track_slot > 0) {
        /* USB/SD/Link track - try dbserver query */
        char title[128] = {0};
        char artist[128] = {0};
        
        /* Use the track type from the status packet */
        uint8_t primary_type = dev->track_type;
        uint8_t fallback_type = (dev->track_type == TRACK_REKORDBOX) ? TRACK_UNANALYZED : TRACK_REKORDBOX;
        
        /* For Link tracks, query the source player's DBServer */
        uint32_t query_ip = dev->ip_addr;
        uint8_t query_slot = dev->track_slot;
        uint8_t query_target = target_device;  /* DMST target device */
        
        /* Detect Link: src_player is set and different from this device */
        if (dev->track_source_player > 0 && dev->track_source_player != dev->device_num) {
            cdj_device_t *src_dev = get_device(dev->track_source_player);
            if (src_dev && src_dev->ip_addr) {
                /* Check if device table shows us as the source - this means slot conflict */
                if (src_dev->ip_addr == our_ip) {
                    /* We don't have media, so we can't be the real source.
                     * This is a slot conflict - the real device hasn't announced yet.
                     * Rate-limit these retries to avoid spamming and causing emergency loop. */
                    last_query_time = now;  /* Prevent retry flood */
                    last_query_id = dev->rekordbox_id;
                    vlogmsg("cdj", "[DBSERVER] Link track src_player=%d shows our IP - slot conflict, will retry",
                               dev->track_source_player);
                    return 1;  /* Temporary - retry after slot conflict resolves */
                }
                query_ip = src_dev->ip_addr;
                query_slot = dev->track_slot;  /* Use track_slot which has the actual media type */
                query_target = dev->track_source_player;  /* DMST target = source player */
                vlogmsg("cdj", "[DBSERVER] Link track: src_player=%d src_slot=%s src_ip=%s",
                           dev->track_source_player, cdj_slot_name(query_slot), ip_to_str(query_ip));
            } else {
                /* Source device not discovered yet - rate-limit retries */
                last_query_time = now;  /* Prevent retry flood */
                last_query_id = dev->rekordbox_id;
                vlogmsg("cdj", "[DBSERVER] Link track src_player=%d not found yet, will retry", 
                           dev->track_source_player);
                return 1;  /* Temporary - retry later */
            }
        }
        
        /* Track query for rate limiting */
        last_query_time = now;
        last_query_id = dev->rekordbox_id;
        
        vlogmsg("cdj", "[DBSERVER] Query for slot=%s id=%u (target=%d)",
                   cdj_slot_name(query_slot), dev->rekordbox_id, query_target);
        
        /* Strategy 1: Try with detected track type first */
        int result = dbserver_query_metadata(query_ip, 0, query_target,
                                            query_slot, primary_type,
                                            dev->rekordbox_id,
                                            title, sizeof(title),
                                            artist, sizeof(artist));
        
        vlogmsg("cdj", "[DBSERVER] Result=%d title='%s'", result, title);
        
        /* Track failures for backoff */
        if (result != 0) {
            query_fail_count++;
            if (result == CDJ_ERR_CONNECT) {
                if (query_fail_count <= 3) {
                    logmsg("cdj", "DBServer connection failed for track %u (will retry)",
                           dev->rekordbox_id);
                } else if (query_fail_count == 5) {
                    logmsg("cdj", "DBServer giving up after %d failures", query_fail_count);
                    return 0;  /* Stop retrying */
                }
                return 1;  /* Temporary — retry later */
            }
            if (query_fail_count <= 3) {
                logmsg("cdj", "DBServer query failed for track %u (attempt %d)",
                       dev->rekordbox_id, query_fail_count);
            }
        } else {
            query_fail_count = 0;
        }
        
        if (result == 0 && title[0] != '\0') {
            utf8_safe_copy(dev->track_title, title, sizeof(dev->track_title));
            if (artist[0] != '\0') {
                utf8_safe_copy(dev->track_artist, artist, sizeof(dev->track_artist));
            }
            if (artist[0]) {
                logmsg("cdj", "🎵 %s - %s (via DBServer)", artist, title);
            } else {
                logmsg("cdj", "🎵 %s (via DBServer)", title);
            }
            
            track_cache_entry_t *tc = add_track_cache(dev->rekordbox_id, dev->ip_addr);
            if (tc) {
                utf8_safe_copy(tc->title, title, sizeof(tc->title));
                utf8_safe_copy(tc->artist, artist, sizeof(tc->artist));
                tc->track_num = dev->track_number;
            }
            return 0;  /* Success */
        }
        
        /* Strategy 2: Try with fallback track type */
        if (result != CDJ_ERR_CONNECT) {
            memset(title, 0, sizeof(title));
            memset(artist, 0, sizeof(artist));
            result = dbserver_query_metadata(query_ip, 0, query_target,
                                            query_slot, fallback_type,
                                            dev->rekordbox_id,
                                            title, sizeof(title),
                                            artist, sizeof(artist));
            if (result == 0 && title[0] != '\0') {
                utf8_safe_copy(dev->track_title, title, sizeof(dev->track_title));
                if (artist[0] != '\0') {
                    utf8_safe_copy(dev->track_artist, artist, sizeof(dev->track_artist));
                }
                if (artist[0]) {
                    logmsg("cdj", "🎵 %s - %s (via DBServer)", artist, title);
                } else {
                    logmsg("cdj", "🎵 %s (via DBServer)", title);
                }
                
                track_cache_entry_t *tc = add_track_cache(dev->rekordbox_id, dev->ip_addr);
                if (tc) {
                    utf8_safe_copy(tc->title, title, sizeof(tc->title));
                    utf8_safe_copy(tc->artist, artist, sizeof(tc->artist));
                    tc->track_num = dev->track_number;
                }
                return 0;
            }
        }
    }
    else if (dev->track_slot > 0) {
        /* No rekordbox_id available */
        vlogmsg("cdj", "[DBSERVER] Skip query - rekordbox_id=%u slot=%s", 
                   dev->rekordbox_id, cdj_slot_name(dev->track_slot));
    }
    return 0;
}

/*
 * ============================================================================
 * Media Change Detection
 * ============================================================================
 */

void check_media_change(cdj_device_t *dev) {
    if (!dev) return;
    
    if (dev->track_slot != dev->last_slot && dev->last_slot != 0) {
        vlogmsg("cdj", "[MEDIA] Device %d changed from %s to %s",
                   dev->device_num, cdj_slot_name(dev->last_slot), 
                   cdj_slot_name(dev->track_slot));
        
        dev->db_fetched = 0;
        dev->track_title[0] = '\0';
        dev->track_artist[0] = '\0';
        dev->track_isrc[0] = '\0';
    }
    
    dev->last_slot = dev->track_slot;
}
