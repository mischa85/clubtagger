/*
 * prolink.c - Pro DJ Link Packet Parsing
 *
 * Parse keepalive, status, and beat packets from Pro DJ Link protocol.
 */

#include "prolink.h"
#include "prolink_protocol.h"
#include "cdj_types.h"
#include "track_cache.h"
#include "dbserver_thread.h"
#include "pdb_thread.h"
#include "onelibrary_thread.h"
#include "waveform_thread.h"
#include "registration.h"
#include "nfs_client.h"
#include "nfs_protocol.h"
#include "track_registry.h"
#include "../confidence.h"
#include "../common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <pthread.h>

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
 * Shared Helpers (used by both main and zero-data status paths)
 * ============================================================================
 */

/* Dump media-relevant bytes (verbose debug). No change-suppression — keep simple
 * to avoid the static-array bookkeeping that crashed previously. */
static void dump_media_bytes(cdj_device_t *dev, const uint8_t *data,
                             size_t len, const char *tag)
{
    if (!verbose) return;
    if (!dev || !data) return;
    if (len <= 0xb9) return;

    vlogmsg("cdj", "Dev%u [%s] Ua=%02x Sa=%02x Ul=%02x Sl=%02x L=%02x "
            "Mp=%02x Ue=%02x Se=%02x tsrc=%02x Dr=%d Sr=%02x",
            dev->device_num, tag,
            data[0x6a], data[0x6b], data[0x6f], data[0x73], data[0x75],
            data[0xb7], data[0xb8], data[0xb9], data[0x37],
            data[0x28], data[0x29]);
}

/* PATCH(2026-04): source-device resolution boilerplate. Same pattern is repeated
 * inline at L700-703 (DBServer gate) and L772-775 (waveform slot_dead). Candidate
 * to consolidate into a single cdj_track_owner(dev) helper returning cdj_device_t*. */
/* Resolve the device that owns the media for a Link track.
 * Returns source IP and slot. For local tracks, returns dev's own IP/slot. */
static void resolve_source_device(const cdj_device_t *dev,
                                  uint32_t *out_ip, uint8_t *out_slot)
{
    *out_ip   = dev->ip_addr;
    *out_slot = dev->track_slot;
    if (dev->track_source_player > 0 &&
        dev->track_source_player != dev->device_num) {
        cdj_device_t *src = get_device(dev->track_source_player);
        if (src && src->ip_addr)
            *out_ip = src->ip_addr;
    }
}

/* Log everything the network told us about a freshly-loaded track. Fires
 * once per track-change so a subsequent offline backfill has a complete
 * baseline (rekordbox_id, source CDJ, BPM, key, length, type) to key on.
 * DB and Shazam resolution events that follow are enrichment on top of
 * this line, not a replacement for it. */
static void log_track_loaded(const cdj_device_t *dev)
{
    static const char *type_names[] = {
        [TRACK_REKORDBOX]  = "rekordbox",
        [TRACK_UNANALYZED] = "unanalyzed",
        [TRACK_CD_AUDIO]   = "cd-audio",
        [TRACK_STREAMING]  = "streaming",
    };
    const char *type_name = (dev->track_type < sizeof(type_names)/sizeof(type_names[0])
                             && type_names[dev->track_type])
                            ? type_names[dev->track_type] : "unknown";

    char key_buf[8] = "?";
    if (dev->key_note <= 11) {
        static const char *sharp[] = {"A","A#","B","C","C#","D","D#","E","F","F#","G","G#"};
        static const char *flat[]  = {"A","Bb","B","C","Db","D","Eb","E","F","Gb","G","Ab"};
        const char *n = (dev->key_accidental == 0xff) ? flat[dev->key_note] : sharp[dev->key_note];
        snprintf(key_buf, sizeof(key_buf), "%s%s", n, dev->key_scale == 0 ? "m" : "");
    }

    logmsg("cdj",
           "[%u@CDJ%u] 🆕 DECK %d NEW rb=%u tid=%u type=%s slot=%s "
           "src_slot=%s bpm=%.2f key=%s len=%us "
           "on_air=%d playing=%d cdj=\"%s\"",
           dev->rekordbox_id, dev->track_source_player,
           dev->device_num,
           dev->rekordbox_id, (unsigned)dev->track_id, type_name,
           cdj_slot_name(dev->track_slot),
           cdj_slot_name(dev->track_source_slot),
           dev->bpm_raw / 100.0,
           key_buf,
           dev->track_length_sec,
           dev->on_air, dev->playing,
           dev->name[0] ? dev->name : "?");
}

/* Update media presence for one slot (USB or SD). Spawns / stops the
 * per-slot OneLibrary and PDB workers on insert / remove and evicts
 * registry entries sourced from the slot. */
static void update_slot_media(cdj_device_t *dev, uint8_t new_state, uint8_t slot)
{
    uint8_t *present   = (slot == SLOT_USB) ? &dev->usb_present : &dev->sd_present;
    uint8_t *local_raw = (slot == SLOT_USB) ? &dev->usb_local_raw : &dev->sd_local_raw;
    const char *name   = (slot == SLOT_USB) ? "USB" : "SD";

    uint8_t old = *present;
    *present   = (new_state != MEDIA_STATE_NONE);
    *local_raw = new_state;

    if (*present && !old) {
        logmsg("cdj", "💾 Device %d: %s inserted", dev->device_num, name);
        if (prolink_olib_key && prolink_olib_key[0]) {
            int rc = onelibrary_thread_spawn(dev->device_num, slot, dev->ip_addr,
                                             dev->nfs_port, dev->mount_port,
                                             prolink_olib_key);
            if (rc != 0) {
                logmsg("cdj", "⚠ Device %d: %s OneLibrary worker spawn failed rc=%d",
                       dev->device_num, name, rc);
            }
        }
        int prc = pdb_thread_spawn(dev->device_num, slot, dev->ip_addr,
                                   dev->nfs_port, dev->mount_port);
        if (prc != 0) {
            logmsg("cdj", "⚠ Device %d: %s PDB worker spawn failed rc=%d",
                   dev->device_num, name, prc);
        }
    }
    if (!*present && old) {
        logmsg("cdj", "💾 Device %d: %s removed", dev->device_num, name);
        pdb_thread_stop(dev->device_num, slot);
        onelibrary_thread_stop(dev->device_num, slot);
        track_registry_evict_source_slot(dev->device_num, slot);
    }
}

/* Update media state for both USB and SD slots from a status packet. */
static void update_media_state(cdj_device_t *dev, const cdj_status_packet_t *pkt)
{
    update_slot_media(dev, pkt->usb_state, SLOT_USB);
    update_slot_media(dev, pkt->sd_state, SLOT_SD);
}

/* CDJs that haven't sent a keepalive in this many seconds are considered
 * disappeared. Longer than the 10s stale-skip threshold elsewhere so a
 * Wi-Fi blip doesn't thrash worker spawn/stop. */
#define CDJ_DISAPPEAR_TIMEOUT_SEC 30

void prolink_sweep_disappeared_cdjs(void) {
    time_t now = time(NULL);
    for (int i = 0; i < MAX_DEVICES; i++) {
        cdj_device_t *dev = &devices[i];
        if (dev->name[0] == '\0') continue;       /* never seen / already cleared */
        if (dev->last_seen == 0) continue;
        if (now - dev->last_seen <= CDJ_DISAPPEAR_TIMEOUT_SEC) continue;

        logmsg("cdj", "🔌 Device %d: %s disappeared (silent for %lds)",
               dev->device_num, dev->name,
               (long)(now - dev->last_seen));

        /* Leave the DBServer worker alive. CDJs only send announce packets
         * on boot — a transient hiccup (WiFi blip, brief stall) resumes via
         * status packets, which never re-trigger was_new and so never re-
         * spawn the worker. Keeping the worker means a returning CDJ stays
         * usable; on a true reboot the fresh announce re-fires was_new and
         * dbserver_thread_spawn is idempotent. Worker state is just dedup
         * hints that overwrite naturally. */
        dev->name[0]        = '\0';
        dev->supported_libs = 0;
        dev->last_seen      = 0;
    }
}

/* Update play state (P1+P2), on-air, and BPM from a status packet.
 * Handles transition logging and confidence signals. */
static void update_play_state(cdj_device_t *dev, const cdj_status_packet_t *pkt,
                               const uint8_t *data)
{
    uint8_t old_playing = dev->playing;
    uint8_t p2 = data[0x8b];
    int p1_playing = (pkt->play_state == PLAY_STATE_PLAYING ||
                     pkt->play_state == PLAY_STATE_LOOPING);
    dev->playing = p1_playing && !(p2 & 0x04);  /* P2 bit 2 clear = playing */

    if (dev->playing && !old_playing) {
        dev->play_started = time(NULL);
        if (dev->track_title[0]) {
            logmsg("cdj", "▶ DECK %d: Playing - %s - %s",
                   dev->device_num, dev->track_artist, dev->track_title);
            confidence_signal((int)(dev - devices), SIG_CDJ_PLAYING, 0,
                              NULL, NULL, NULL, 0);
        }
    } else if (!dev->playing && old_playing) {
        dev->play_started = 0;
        if (dev->track_title[0])
            logmsg("cdj", "⏸ DECK %d: Paused", dev->device_num);
    }

    uint8_t old_on_air = dev->on_air;
    dev->on_air = (pkt->status_flags & STATE_FLAG_ON_AIR) != 0;
    if (dev->on_air != old_on_air) {
        dev->on_air_available = 1;
        int didx = (int)(dev - devices);
        if (dev->on_air) {
            if (dev->track_title[0])
                logmsg("cdj", "🔴 DECK %d ON AIR: %s — %s", dev->device_num,
                       dev->track_artist, dev->track_title);
            else
                logmsg("cdj", "🔴 DECK %d ON AIR", dev->device_num);
            confidence_signal(didx, SIG_CDJ_ON_AIR_EDGE, 0, NULL, NULL, NULL, 0);
            confidence_signal(didx, SIG_CDJ_ON_AIR, 0, NULL, NULL, NULL, 0);
        } else {
            logmsg("cdj", "⚪ DECK %d off air", dev->device_num);
            confidence_signal(didx, SIG_CDJ_OFF_AIR, 0, NULL, NULL, NULL, 0);
        }
    }

    uint16_t bpm = BE16_TO_HOST(pkt->bpm_be);
    if (bpm > 0 && bpm < 50000) dev->bpm_raw = bpm;
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
            dev->supported_libs = cdj_libs_for_name(dev->name);
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

                /* Discover the device's NFS and MOUNT ports via portmap once
                 * at connect. RPC service ports are stable for the lifetime
                 * of the daemon (i.e., until the CDJ reboots); on reboot the
                 * stale-device logic clears dev->name, which re-fires was_new
                 * and re-runs this block. Held under nfs_fetch_mu because
                 * portmap reuses the shared NFS UDP socket. */
                if (dev->device_type == DEVICE_TYPE_CDJ) {
                    pthread_mutex_lock(&nfs_fetch_mu);
                    int np = rpc_portmap_getport(src_ip, NFS_PROGRAM, NFS_VERSION);
                    int mp = rpc_portmap_getport(src_ip, MOUNT_PROGRAM, MOUNT_VERSION);
                    pthread_mutex_unlock(&nfs_fetch_mu);
                    if (np > 0) {
                        dev->nfs_port = (uint16_t)np;
                    } else {
                        dev->nfs_port = 2049;
                        logmsg("cdj", "⚠ Device %d: portmap NFS query failed, defaulting to 2049",
                               device_num);
                    }
                    if (mp > 0) {
                        dev->mount_port = (uint16_t)mp;
                    } else {
                        /* No safe default — CDJ uses non-standard mount port.
                         * Leave 0; fetchers will refuse and retry next fetch. */
                        dev->mount_port = 0;
                        logmsg("cdj", "⚠ Device %d: portmap MOUNT query failed — mount port unknown",
                               device_num);
                    }
                    vlogmsg("cdj", "[%s] NFS port=%u, MOUNT port=%u",
                            name, dev->nfs_port, dev->mount_port);
                }

                /* Spawn DBServer worker — every CDJ hosts a DBServer; queries
                 * for any track on the network go to the playing deck. */
                if (dev->device_type == DEVICE_TYPE_CDJ) {
                    dbserver_thread_spawn(device_num);
                }

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
        if (name[0]) {
            strncpy(dev->name, name, sizeof(dev->name) - 1);
            dev->supported_libs = cdj_libs_for_name(dev->name);
        }

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
         * P1 (play_state at 0x7b) and on-air ARE consistent. */
        uint32_t pkt_rekordbox_id = BE32_TO_HOST(pkt->rekordbox_id_be);
        uint8_t pkt_track_slot = pkt->track_slot;
        if (pkt_rekordbox_id == 0 && pkt_track_slot == 0 && len > 300) {
            cdj_device_t *dev2 = find_device(device_num);
            if (dev2) {
                dev2->last_seen = time(NULL);
                dev2->ip_addr = src_ip;
                dump_media_bytes(dev2, data, len, "media-zd");
                update_media_state(dev2, pkt);
                update_play_state(dev2, pkt, data);
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
        if (name[0]) {
            strncpy(dev->name, name, sizeof(dev->name) - 1);
            dev->supported_libs = cdj_libs_for_name(dev->name);
        }

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
        
        dump_media_bytes(dev, data, len, "media");
        update_media_state(dev, pkt);

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

        /* Play state, on-air, BPM — shared with zero-data path */
        update_play_state(dev, pkt, data);
        dev->cued = (pkt->play_state == PLAY_STATE_PAUSED ||
                    pkt->play_state == PLAY_STATE_CUED);

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
            dev->track_bitrate = 0;
            dev->track_samplerate = 0;
            dev->track_depth = 0;
            dev->track_format = 0;
            dev->track_anlz_path[0] = '\0';
            waveform_thread_clear(dev->device_num);
            dev->waveform_last_attempt = 0;
            dev->waveform_backoff = 10;   /* Start fresh on track change */
            dev->enqueue_last_attempt = 0;
            dev->enqueue_backoff = 1;
            dev->track_db_src = DB_SRC_NONE;
            dev->logged_rekordbox_id = 0;  /* Allow new track to be logged */
            dev->play_started = dev->playing ? time(NULL) : 0;  /* Reset play timer on track change */
            /* Reset confidence for this deck — new track starts at 0 */
            confidence_reset_deck((int)(dev - devices));

            /* Baseline: dump everything the network told us. Resolution
             * results from cache/OneLibrary/DBServer/PDB/Shazam follow as
             * enrichment lines if/when they arrive. */
            if (dev->rekordbox_id != 0) {
                log_track_loaded(dev);
            }
        }
        
        /* Enqueue resolver lookups while we don't have a title yet. The
         * resolver workers dedupe via per-slot pending mailboxes, so re-
         * enqueueing on every status tick (10/sec) is cheap. As soon as
         * any resolver emits a winner, the registry projection below sets
         * dev->track_title and this gate stops further enqueues.
         *
         * reg_id is the per-slot identifier: rekordbox_id for USB/SD/Link,
         * track number for CD. They live in different namespaces but share
         * the same gate. */
        uint32_t reg_id = (dev->track_slot == SLOT_CD)
                          ? dev->track_id : dev->rekordbox_id;

        if (reg_id > 0 && dev->track_title[0] == '\0') {
            int found = 0;

            /* Producer-side backoff. Without it, the gate would re-fire the
             * full resolver-enqueue chain at every status tick (~10Hz) for as
             * long as track_title stays empty — which under any downstream
             * stall (registry full, workers stuck) is indefinite and saturates
             * the logs. Cap at 1→60s, doubling per attempt; reset on track
             * change. Projection below still runs every tick so winners get
             * picked up the moment they land. */
            time_t now_eq = time(NULL);
            uint16_t eq_backoff = dev->enqueue_backoff ? dev->enqueue_backoff : 1;
            int may_enqueue = (now_eq - dev->enqueue_last_attempt) >= eq_backoff;

            if (may_enqueue) {
                dev->enqueue_last_attempt = now_eq;
                uint16_t b = dev->enqueue_backoff ? dev->enqueue_backoff * 2 : 1;
                dev->enqueue_backoff = (b > 60) ? 60 : b;
            }

            if (may_enqueue && dev->track_slot == SLOT_CD) {
                /* CD-text: query the playing CDJ itself; the worker emits
                 * into the registry under (track_id, dev->device_num, SLOT_CD).
                 * Result is consumed by the readers below (confidence) and
                 * by ws_server / auto-tag via dev_track_key(dev). */
                int erc = dbserver_thread_enqueue(dev->device_num,
                                                  dev->track_id,
                                                  dev->ip_addr, dev->device_num,
                                                  SLOT_CD,
                                                  TRACK_UNANALYZED);
                if (erc != 0) {
                    logmsg("cdj", "[CD %u@CDJ%u] DBServer enqueue failed (rc=%d)",
                           dev->track_id, dev->device_num, erc);
                }
            } else if (may_enqueue && dev->track_slot > 0) {
                uint32_t src_ip;
                uint8_t  src_slot;
                resolve_source_device(dev, &src_ip, &src_slot);
                /* OneLibrary and PDB key on (source_player, slot) so they
                 * don't need src_ip; DBServer below dials src_ip directly so
                 * Link-loaded tracks reach the CDJ that actually holds them. */

                /* 1. Track cache */
                track_cache_entry_t *tc = find_track_cache(dev->rekordbox_id, dev->track_source_player);
                if (tc && tc->title[0]) {
                    utf8_safe_copy(dev->track_title, tc->title, sizeof(dev->track_title));
                    if (tc->artist[0])
                        utf8_safe_copy(dev->track_artist, tc->artist, sizeof(dev->track_artist));
                    if (tc->isrc[0])
                        utf8_safe_copy(dev->track_isrc, tc->isrc, sizeof(dev->track_isrc));
                    found = 1;
                    logmsg("cdj", "[%u@CDJ%u] DECK %d: Found in cache: %s - %s",
                           dev->rekordbox_id, dev->track_source_player,
                           device_num, dev->track_artist, dev->track_title);
                }

                /* 2. OneLibrary — async via per-(source_player, slot) worker.
                 * The worker emits to track_registry; the winner is folded
                 * into dev fields below. Only for rekordbox-analyzed tracks:
                 * the unanalyzed-id namespace can collide with rekordbox_id
                 * and produce a confident wrong answer. Library gate skips
                 * legacy PDB-only players — the numeric ID they send comes
                 * from PDB, so a DLP lookup returns a wrong-row answer. */
                if (!found && dev->track_type == TRACK_REKORDBOX &&
                    (dev->supported_libs & CDJ_LIB_DEVICE_LIBRARY_PLUS)) {
                    int ol_erc = onelibrary_thread_enqueue(dev->track_source_player,
                                                           src_slot,
                                                           dev->rekordbox_id);
                    if (ol_erc != 0 && ol_erc != -ENOENT) {
                        /* -ENOENT = no worker for this slot (key not set / wrong slot).
                         * Other errors are real and should be visible. */
                        logmsg("cdj", "[%u@CDJ%u] OneLibrary enqueue failed (src=CDJ%u slot=%s rc=%d)",
                               dev->rekordbox_id, dev->track_source_player,
                               dev->track_source_player, cdj_slot_name(src_slot), ol_erc);
                    }
                }

                /* 3. DBServer — async via per-playing-deck worker. The
                 * worker emits to track_registry; the registry winner is
                 * picked up on the next prolink tick. */
                if (!found) {
                    /* DMST byte = device holding the media. For self-mounted
                     * that's dev itself; for Link Export it's track_source_player. */
                    uint8_t query_target = (dev->track_source_player > 0)
                                         ? dev->track_source_player : dev->device_num;
                    logmsg("cdj", "[%u@CDJ%u] DECK %d: Enqueuing DBServer query (target=%u slot=%s)",
                           dev->rekordbox_id, dev->track_source_player, device_num,
                           query_target, cdj_slot_name(src_slot));
                    int erc = dbserver_thread_enqueue(dev->device_num,
                                                      dev->rekordbox_id,
                                                      src_ip, query_target,
                                                      src_slot, dev->track_type);
                    if (erc != 0) {
                        logmsg("cdj", "[%u@CDJ%u] DBServer enqueue failed (playing=CDJ%u rc=%d)",
                               dev->rekordbox_id, dev->track_source_player,
                               dev->device_num, erc);
                    }
                }

                /* 4. PDB — async via per-(source_player, slot) worker. The
                 * worker emits to track_registry; the registry winner is
                 * picked up on the next prolink tick. Rekordbox-only for the
                 * same reason as OneLibrary above. Library gate skips DLP
                 * players (CDJ-3000X et al.) — the numeric ID they send was
                 * resolved via the sqlite lib, so a PDB hit is a wrong row. */
                if (!found && dev->track_type == TRACK_REKORDBOX &&
                    (dev->supported_libs & CDJ_LIB_REKORDBOX_PDB)) {
                    int pdb_erc = pdb_thread_enqueue(dev->track_source_player,
                                                     src_slot,
                                                     dev->rekordbox_id);
                    if (pdb_erc != 0 && pdb_erc != -ENOENT) {
                        logmsg("cdj", "[%u@CDJ%u] PDB enqueue failed (src=CDJ%u slot=%s rc=%d)",
                               dev->rekordbox_id, dev->track_source_player,
                               dev->track_source_player, cdj_slot_name(src_slot), pdb_erc);
                    }
                }
            }

            /* Signal confidence model when metadata is resolved.
             * Identity comes from the registry winner (composed across
             * all resolvers) — DBServer wins title/artist when present,
             * OneLibrary/PDB enrich with ISRC when they agree. */
            track_key_t res_key = dev_track_key(dev);
            track_identity_t res_id;
            int have_id = track_registry_winner(res_key, &res_id);

            /* Project registry → dev fields. Async resolvers (DBServer worker
             * including CD-text) emit into the registry; this copy is what
             * makes log_track_loaded, the title gate, and dev-reading
             * consumers (ws_server) observe the result. */
            if (have_id && res_id.title[0]) {
                if (!dev->track_title[0])
                    utf8_safe_copy(dev->track_title, res_id.title, sizeof(dev->track_title));
                if (!dev->track_artist[0] && res_id.artist[0])
                    utf8_safe_copy(dev->track_artist, res_id.artist, sizeof(dev->track_artist));
                if (!dev->track_isrc[0] && res_id.isrc[0])
                    utf8_safe_copy(dev->track_isrc, res_id.isrc, sizeof(dev->track_isrc));
                if (!dev->track_anlz_path[0] && res_id.anlz_path[0])
                    utf8_safe_copy(dev->track_anlz_path, res_id.anlz_path, sizeof(dev->track_anlz_path));
                if (!dev->track_bitrate    && res_id.bitrate)      dev->track_bitrate    = res_id.bitrate;
                if (!dev->track_samplerate && res_id.sample_rate)  dev->track_samplerate = res_id.sample_rate;
                if (!dev->track_depth      && res_id.sample_depth) dev->track_depth      = res_id.sample_depth;
                if (!dev->track_format     && res_id.file_type)    dev->track_format     = res_id.file_type;
                if (!found) found = 1;
            }

            if (found && have_id && res_id.title[0]) {
                int didx = (int)(dev - devices);
                confidence_signal(didx, SIG_CDJ_LOADED, 0,
                                  res_id.artist, res_id.title,
                                  res_id.isrc, dev->rekordbox_id);
            }
        }

        /* Waveform: enqueue an async fetch via the worker thread. Producer-side
         * backoff (10s → 300s) gates re-enqueues so we don't flood the worker
         * mailbox on every status tick (10/sec) for tracks the CDJ hasn't
         * indexed yet. waveform_data being non-NULL is the "have data" flag;
         * worker installs it under waveform_mu (gated on rekordbox_id match).
         * The worker doesn't report failures back — we grow the backoff
         * optimistically and the next tick will re-enqueue if data is still
         * missing. */
        time_t now_wf = time(NULL);
        uint16_t wf_backoff = dev->waveform_backoff ? dev->waveform_backoff : 10;
        track_key_t wf_key = dev_track_key(dev);
        track_identity_t wf_id;
        int have_wf_id = track_registry_winner(wf_key, &wf_id);
        pthread_mutex_lock(&waveform_mu);
        int have_wf_data = (dev->waveform_data != NULL);
        pthread_mutex_unlock(&waveform_mu);
        if (have_wf_id && wf_id.anlz_path[0] && !have_wf_data
            && registration_state == REG_ACTIVE
            && now_wf - dev->waveform_last_attempt >= wf_backoff) {
            uint32_t wf_ip;
            uint8_t  wf_slot;
            resolve_source_device(dev, &wf_ip, &wf_slot);
            const cdj_device_t *wf_src = dev;
            if (dev->track_source_player > 0 &&
                dev->track_source_player != dev->device_num) {
                cdj_device_t *s = get_device(dev->track_source_player);
                if (s && s->ip_addr) wf_src = s;
            }
            uint16_t wf_nport = wf_src->nfs_port;
            uint16_t wf_mport = wf_src->mount_port;

            dev->waveform_last_attempt = now_wf;
            /* Grow backoff optimistically; the next tick will re-enqueue if the
             * worker found nothing. 10 → 20 → 40 → 80 → 160 → 300 cap. */
            uint16_t b = dev->waveform_backoff ? dev->waveform_backoff * 2 : 10;
            dev->waveform_backoff = (b > 300) ? 300 : b;

            int erc = waveform_thread_enqueue(dev->device_num, dev->rekordbox_id,
                                              wf_ip, wf_nport, wf_mport, wf_slot,
                                              wf_id.anlz_path);
            if (erc != 0) {
                logmsg("cdj", "[%u@CDJ%u] 🌊 waveform enqueue failed rc=%d",
                       dev->rekordbox_id, dev->device_num, erc);
            }
        }

        /* Eject is the only track-change variant the per-resolver and 🆕
         * baseline lines don't already cover — log it here. The "Loaded"
         * summary that used to live here was redundant with the 🎵 ... (via X)
         * enrichment lines, so it was removed. */
        if ((dev->track_id != old_track || dev->track_slot != old_slot ||
             dev->rekordbox_id != old_rekordbox) &&
            dev->track_id == 0 && dev->rekordbox_id == 0) {
            logmsg("cdj", "⏏ DECK %d: Ejected", device_num);
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

    /* BPM: status packet (0x92) is the authoritative track BPM.
     * Position packet BPM may differ (interpolated from beat timing)
     * and overwrites at 30Hz, causing display mismatches. Don't use it. */
    uint32_t raw_bpm = BE32_TO_HOST(pkt->bpm_be);

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

