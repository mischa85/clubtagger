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
                    log_message("[REG] Starting registration (CDJ detected)...");
                    do_full_registration(capture_interface);
                    last_keepalive_sent = time(NULL);
                }
            }
            
            if (verbose) {
                log_message("[ANNOUNCE] Device %d: %s (%s) at %s",
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
                log_message("[REG] Starting registration (CDJ keepalive, no track info)...");
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
        log_message("[STATUS] Packet from %s: subtype=0x%02x len=%zu",
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
        
        dev->playing = 1;
        
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
            log_message("[STATUS] Got subtype 0x0a packet, len=%zu (need %zu)", len, sizeof(cdj_status_packet_t));
        }

        if (len < sizeof(cdj_status_packet_t)) {
            if (verbose) {
                log_message("[STATUS] Short status packet (%zu < %zu bytes)", 
                           len, sizeof(cdj_status_packet_t));
            }
            return;
        }
        
        const cdj_status_packet_t *pkt = (const cdj_status_packet_t *)data;
        uint8_t device_num = pkt->device_num;
        uint8_t subtype2 = pkt->subtype2;

        if (verbose) {
            log_message("[STATUS] Dev%d: subtype2=0x%02x len=%zu rekordbox_id=%u slot=0x%02x",
                       device_num, subtype2, len,
                       BE32_TO_HOST(pkt->rekordbox_id_be), pkt->track_slot);
        }

        /* CDJ-3000X sends large packets (1152 bytes) with alternating subtype2 values.
         * Some variants don't carry track data at the standard offsets (read as zeros).
         * If this packet has rekordbox_id=0 AND slot=0 but we already have a valid track,
         * this is likely a non-track-data variant — skip the track fields to avoid
         * flipping between valid data and zeros. */
        uint32_t pkt_rekordbox_id = BE32_TO_HOST(pkt->rekordbox_id_be);
        uint8_t pkt_track_slot = pkt->track_slot;
        if (pkt_rekordbox_id == 0 && pkt_track_slot == 0) {
            cdj_device_t *dev2 = find_device(device_num);
            if (dev2 && dev2->rekordbox_id > 0 && dev2->track_slot > 0) {
                /* We have a valid track but this packet says zero — skip track fields.
                 * Still update liveness and non-track fields (on-air, play state, etc.) */
                dev2->last_seen = time(NULL);
                dev2->ip_addr = src_ip;
                dev2->playing = (pkt->play_state == PLAY_STATE_PLAYING ||
                                pkt->play_state == PLAY_STATE_LOOPING);
                dev2->cued = (pkt->play_state == PLAY_STATE_PAUSED ||
                             pkt->play_state == PLAY_STATE_CUED);
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
        
        /* Detect media insertion and proactively fetch databases */
        uint8_t old_usb = dev->usb_present;
        uint8_t old_sd = dev->sd_present;
        dev->usb_present = (pkt->usb_local != 0);
        dev->sd_present = (pkt->sd_local != 0);
        
        /* USB inserted */
        if (dev->usb_present && !old_usb) {
            logmsg("cdj", "💾 Device %d: USB inserted", device_num);
            dev->usb_db_fetched = 0;
            dev->usb_olib_fetched = 0;
        }
        /* USB removed */
        if (!dev->usb_present && old_usb) {
            logmsg("cdj", "💾 Device %d: USB removed", device_num);
            dev->usb_db_fetched = 0;
            dev->usb_olib_fetched = 0;
            remove_pdb_database(dev->ip_addr, SLOT_USB);
            remove_onelibrary(dev->ip_addr, SLOT_USB);
        }
        /* SD inserted */
        if (dev->sd_present && !old_sd) {
            logmsg("cdj", "💾 Device %d: SD inserted", device_num);
            dev->sd_db_fetched = 0;
            dev->sd_olib_fetched = 0;
        }
        /* SD removed */
        if (!dev->sd_present && old_sd) {
            logmsg("cdj", "💾 Device %d: SD removed", device_num);
            dev->sd_db_fetched = 0;
            dev->sd_olib_fetched = 0;
            remove_pdb_database(dev->ip_addr, SLOT_SD);
            remove_onelibrary(dev->ip_addr, SLOT_SD);
        }
        
        /* Proactively fetch databases when media is detected.
         * Must wait for registration to be ready (5 keepalives sent) or CDJ will refuse NFS. */
        if (capture_interface && our_ip != 0 && dev->ip_addr != 0 &&
            keepalives_sent_active >= MIN_KEEPALIVES_BEFORE_NFS) {
            /* Fetch USB databases if USB is present and not yet fetched.
             * Try OneLibrary first (CDJ-3000X), fall back to PDB. */
            if (dev->usb_present && !dev->usb_olib_fetched && onelibrary_key_available()) {
                logmsg("cdj", "📥 Device %d: Fetching USB OneLibrary...", device_num);
                if (fetch_onelibrary_database(dev->ip_addr, SLOT_USB) == 0) {
                    dev->usb_olib_fetched = 1;
                    dev->usb_db_fetched = 1;  /* Skip PDB if OneLibrary loaded */
                    if (dev->track_slot == SLOT_USB && dev->track_title[0] == '\0') {
                        dev->lookup_failed_id = 0;
                    }
                } else {
                    dev->usb_olib_fetched = 1;  /* Don't retry OneLibrary */
                }
            }
            if (dev->usb_present && !dev->usb_db_fetched) {
                logmsg("cdj", "📥 Device %d: Fetching USB PDB...", device_num);
                pdb_database_t *db = create_pdb_database(dev->ip_addr, SLOT_USB);
                if (db) {
                    if (fetch_rekordbox_database(dev->ip_addr, SLOT_USB, db) == 0) {
                        logmsg("cdj", "✅ Device %d: USB PDB loaded (%d tracks)",
                               device_num, db->track_count);
                        dev->usb_db_fetched = 1;
                        if (dev->track_slot == SLOT_USB && dev->track_title[0] == '\0') {
                            dev->lookup_failed_id = 0;
                        }
                    } else {
                        log_message("[FETCH] USB PDB fetch failed");
                        dev->usb_db_fetched = 1;
                    }
                }
            }
            /* Fetch SD databases - same OneLibrary-first strategy */
            if (dev->sd_present && !dev->sd_olib_fetched && onelibrary_key_available()) {
                logmsg("cdj", "📥 Device %d: Fetching SD OneLibrary...", device_num);
                if (fetch_onelibrary_database(dev->ip_addr, SLOT_SD) == 0) {
                    dev->sd_olib_fetched = 1;
                    dev->sd_db_fetched = 1;
                    if (dev->track_slot == SLOT_SD && dev->track_title[0] == '\0') {
                        dev->lookup_failed_id = 0;
                    }
                } else {
                    dev->sd_olib_fetched = 1;
                }
            }
            if (dev->sd_present && !dev->sd_db_fetched) {
                logmsg("cdj", "📥 Device %d: Fetching SD PDB...", device_num);
                pdb_database_t *db = create_pdb_database(dev->ip_addr, SLOT_SD);
                if (db) {
                    if (fetch_rekordbox_database(dev->ip_addr, SLOT_SD, db) == 0) {
                        logmsg("cdj", "✅ Device %d: SD PDB loaded (%d tracks)",
                               device_num, db->track_count);
                        dev->sd_db_fetched = 1;
                        if (dev->track_slot == SLOT_SD && dev->track_title[0] == '\0') {
                            dev->lookup_failed_id = 0;
                        }
                    } else {
                        log_message("[FETCH] SD PDB fetch failed");
                        dev->sd_db_fetched = 1;
                    }
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
                log_message("[STATUS] CD/audio track detected, using UNANALYZED type");
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
            log_message("[STATUS] Dev%d: Tr=%d slot=%d rekordbox_id=%u track_type=%s", 
                       device_num, pkt->track_type, dev->track_slot, 
                       BE32_TO_HOST(pkt->rekordbox_id_be),
                       dev->track_type == TRACK_REKORDBOX ? "REKORDBOX" : "UNANALYZED");
        }
        
        dev->rekordbox_id = BE32_TO_HOST(pkt->rekordbox_id_be);
        dev->track_number = BE16_TO_HOST(pkt->track_num_be);
        dev->track_id = (uint16_t)dev->track_number;
        
        if (verbose) {
            log_message("[STATUS] Parsed CDJ%d: rekordbox_id=%u track_num=%u slot=%s",
                       device_num, dev->rekordbox_id, dev->track_number, cdj_slot_name(dev->track_slot));
        }
        
        dev->playing = (pkt->play_state == PLAY_STATE_PLAYING || 
                       pkt->play_state == PLAY_STATE_LOOPING);
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
        
        dev->beat_number = BE32_TO_HOST(pkt->beat_num_be);
        
        int track_changed = (dev->track_id != old_track) || 
                            (dev->rekordbox_id != old_rekordbox) ||
                            (dev->track_slot != old_slot);  /* Also trigger on slot change! */
        
        if (track_changed) {
            dev->track_title[0] = '\0';
            dev->track_artist[0] = '\0';
            dev->track_isrc[0] = '\0';
            dev->lookup_failed_id = 0;  /* Reset failed lookup marker */
            dev->logged_rekordbox_id = 0;  /* Allow new track to be logged */
            dev->play_started = dev->playing ? time(NULL) : 0;  /* Reset play timer on track change */
            /* Reset confidence for this deck — new track starts at 0 */
            confidence_reset_deck((int)(dev - devices));
        }
        
        /* Skip lookup if no track loaded, already failed for this ID, or already have title */
        int need_lookup = (dev->rekordbox_id > 0) &&
                          (dev->track_title[0] == '\0') && 
                          (dev->lookup_failed_id != dev->rekordbox_id);
        
        if ((track_changed && dev->rekordbox_id > 0) || need_lookup) {
            /* Only log on track change to avoid spam during retry attempts */
            if (verbose && track_changed) {
                log_message("[LOOKUP] CDJ %d: Looking up rekordbox_id=%u (track_id=%d, slot=%s)",
                           device_num, dev->rekordbox_id, dev->track_id, cdj_slot_name(dev->track_slot));
            }
            
            int found = 0;
            int retry_later = 0;  /* 1 = temporary skip, will retry */
            
            if (dev->track_slot == SLOT_CD) {
                retry_later = try_resolve_track_name(dev);
                found = (dev->track_title[0] != '\0');
            } else if (dev->track_slot > 0) {
                /* First try track cache */
                track_cache_entry_t *tc = find_track_by_id(dev->rekordbox_id);
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
                    /* Try OneLibrary first (richer metadata from CDJ-3000X) */
                    char ol_title[128] = {0}, ol_artist[128] = {0}, ol_isrc[64] = {0};
                    if (onelibrary_lookup(dev->rekordbox_id,
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
                        log_message("🎵 %s - %s (via OneLibrary)", ol_artist, ol_title);
                    }

                    /* Try PDB database by rekordbox_id */
                    if (!found) {
                    TrackID *pdb = lookup_pdb_track(dev->rekordbox_id);
                    
                    if (pdb && pdb->title[0]) {
                        utf8_safe_copy(dev->track_title, pdb->title, sizeof(dev->track_title));
                        if (pdb->has_isrc && pdb->isrc[0]) {
                            utf8_safe_copy(dev->track_isrc, pdb->isrc, sizeof(dev->track_isrc));
                        }
                        if (pdb->artist[0]) {
                            utf8_safe_copy(dev->track_artist, pdb->artist, sizeof(dev->track_artist));
                            found = 1;  /* Only consider "found" if we have artist too */
                        } else {
                            /* PDB has title but no artist - try dbserver for better metadata */
                            log_message("[PDB] Track %u has title but no artist, trying dbserver", 
                                       dev->rekordbox_id);
                            retry_later = try_resolve_track_name(dev);
                            /* If dbserver also fails, use PDB title at least */
                            if (dev->track_title[0] == '\0') {
                                utf8_safe_copy(dev->track_title, pdb->title, sizeof(dev->track_title));
                            }
                            found = (dev->track_title[0] != '\0');
                        }
                    } else {
                        /* Fall back to DBServer query */
                        retry_later = try_resolve_track_name(dev);
                        found = (dev->track_title[0] != '\0');
                    }
                    } /* end if (!found) - OneLibrary/PDB/DBServer chain */
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
        
        if (dev->track_id != old_track || dev->track_slot != old_slot ||
            dev->playing != old_playing || dev->rekordbox_id != old_rekordbox) {
            
            const char *title = dev->track_title[0] ? dev->track_title : "(unknown)";
            const char *artist = dev->track_artist[0] ? dev->track_artist : NULL;
            
            if (dev->playing && !old_playing) {
                if (artist) {
                    logmsg("cdj", "▶ DECK %d: Playing - %s - %s", device_num, artist, title);
                } else {
                    logmsg("cdj", "▶ DECK %d: Playing - %s", device_num, title);
                }
            } else if (dev->track_id != old_track || dev->rekordbox_id != old_rekordbox) {
                /* Check if deck is now empty (track ejected) */
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
            log_message("[STATUS] CDJ #%d: track=%d slot=%s type=%d playing=%d bpm=%.2f",
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
        log_message("[BEAT-PORT] type=0x%02x len=%zu from CDJ#%d", subtype, len, device_num);
    }
    
    if (verbose > 2) {
        uint32_t next_beat_ms = BE32_TO_HOST(pkt->next_beat_be);
        uint16_t bpm = BE16_TO_HOST(pkt->bpm_be);
        log_message("[BEAT] CDJ #%d next_beat=%u ms bpm=%.2f beat=%u/4", 
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

    const cdj_position_packet_t *pkt = (const cdj_position_packet_t *)data;
    uint8_t device_num = pkt->device_num;

    cdj_device_t *dev = find_device(device_num);
    if (!dev) return;

    dev->last_seen = time(NULL);
    dev->ip_addr = src_ip;

    /* Update position from playhead (milliseconds) */
    uint32_t playhead = BE32_TO_HOST(pkt->playhead_be);
    dev->position_ms = playhead;

    /* Update BPM if valid (0xffffffff means unknown) */
    uint32_t raw_bpm = BE32_TO_HOST(pkt->bpm_be);
    if (raw_bpm != 0xffffffff && raw_bpm > 0) {
        /* Position packet BPM is *10, our bpm_raw is *100 */
        dev->bpm_raw = (uint16_t)(raw_bpm * 10);
    }

    /* Mark as playing if we're getting position updates with a moving playhead */
    if (playhead > 0) {
        dev->playing = 1;
    }

    if (verbose > 2) {
        uint32_t track_len = BE32_TO_HOST(pkt->track_length_be);
        int32_t pitch_raw;
        memcpy(&pitch_raw, pkt->pitch_be, 4);
        pitch_raw = (int32_t)BE32_TO_HOST((const uint8_t *)&pitch_raw);
        log_message("[POSITION] CDJ #%d pos=%u ms len=%u s bpm=%.1f pitch=%.2f%%",
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

/* Returns: 0 = done (success or permanent failure), 1 = temporary skip (retry later) */
int try_resolve_track_name(cdj_device_t *dev) {
    if (!dev || !dev->active) return 0;
    
    /* Rate limit: don't query same track more than once per 5 seconds */
    time_t now = time(NULL);
    if (dev->rekordbox_id == last_query_id && now - last_query_time < 5) {
        return 1;  /* Rate limited - will retry later, don't mark as failed */
    }
    
    /* Back off after failures */
    if (query_fail_count > 3 && now - last_query_time < 10) {
        return 1;  /* Too many failures - will retry later */
    }
    
    uint8_t target_device = dev->device_num;
    
    if (dev->track_slot == SLOT_CD && dev->track_id > 0) {
        char title[128] = {0};
        char artist[128] = {0};
        
        log_message("[CD] Querying CD-text for track %d on %s (target=%d)",
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
            log_message("[CD] Got CD-text: %s - %s", artist, title);
        } else {
            snprintf(dev->track_title, sizeof(dev->track_title), 
                    "CD Track %d", dev->track_id);
            if (dbresult != 0) {
                log_message("[CD] CD-text query failed (result=%d)", dbresult);
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
                    log_message("[DBSERVER] Link track src_player=%d shows our IP - slot conflict, will retry",
                               dev->track_source_player);
                    return 1;  /* Temporary - retry after slot conflict resolves */
                }
                query_ip = src_dev->ip_addr;
                query_slot = dev->track_slot;  /* Use track_slot which has the actual media type */
                query_target = dev->track_source_player;  /* DMST target = source player */
                log_message("[DBSERVER] Link track: src_player=%d src_slot=%s src_ip=%s",
                           dev->track_source_player, cdj_slot_name(query_slot), ip_to_str(query_ip));
            } else {
                /* Source device not discovered yet - rate-limit retries */
                last_query_time = now;  /* Prevent retry flood */
                last_query_id = dev->rekordbox_id;
                log_message("[DBSERVER] Link track src_player=%d not found yet, will retry", 
                           dev->track_source_player);
                return 1;  /* Temporary - retry later */
            }
        }
        
        /* Track query for rate limiting */
        last_query_time = now;
        last_query_id = dev->rekordbox_id;
        
        log_message("[DBSERVER] Query for slot=%s id=%u (target=%d)",
                   cdj_slot_name(query_slot), dev->rekordbox_id, query_target);
        
        /* Strategy 1: Try with detected track type first */
        int result = dbserver_query_metadata(query_ip, 0, query_target,
                                            query_slot, primary_type,
                                            dev->rekordbox_id,
                                            title, sizeof(title),
                                            artist, sizeof(artist));
        
        log_message("[DBSERVER] Result=%d title='%s'", result, title);
        
        /* Track failures for backoff */
        if (result != 0) {
            query_fail_count++;
            if (result == CDJ_ERR_CONNECT) {
                /* Connection failure is temporary — retry later */
                logmsg("cdj", "DBServer connection failed for track %u (will retry)",
                       dev->rekordbox_id);
                return 1;  /* Temporary — don't mark as permanently failed */
            }
            if (query_fail_count <= 2) {
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
        log_message("[DBSERVER] Skip query - rekordbox_id=%u slot=%s", 
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
        log_message("[MEDIA] Device %d changed from %s to %s",
                   dev->device_num, cdj_slot_name(dev->last_slot), 
                   cdj_slot_name(dev->track_slot));
        
        dev->db_fetched = 0;
        dev->track_title[0] = '\0';
        dev->track_artist[0] = '\0';
        dev->track_isrc[0] = '\0';
    }
    
    dev->last_slot = dev->track_slot;
}
