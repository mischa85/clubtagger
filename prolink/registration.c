/*
 * registration.c - Virtual CDJ Registration
 *
 * Handle Pro DJ Link network registration as a virtual CDJ device.
 */

#include "registration.h"
#include "prolink_protocol.h"
#include "cdj_types.h"
#include "../common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ifaddrs.h>

/*
 * ============================================================================
 * Module State
 * ============================================================================
 */

reg_state_t registration_state = REG_IDLE;
time_t registration_start = 0;
time_t observation_start = 0;  /* When we started observing the network */
time_t last_keepalive_sent = 0;
int registration_stage_count = 0;
int databases_pending = 0;
int keepalives_sent_active = 0;

/* Observation period before claiming a slot (seconds) */
#define OBSERVATION_PERIOD_SEC 3

/* Configuration */
int passive_only = 0;
int active_mode = 0;
int show_nfs = 1;
const char *capture_interface = NULL;

/* Sockets */
static int announce_socket = -1;
static int status_socket = -1;
static int beat_socket = -1;
uint32_t our_ip = 0;

/* Dynamic slot management */
uint8_t our_device_num = 0;  /* 0 = not registered, 1-6 = active slot */

/*
 * ============================================================================
 * Slot Management - Smart Network Participation
 * ============================================================================
 */

/* Log all detected Pro-Link devices on the network */
static void log_detected_devices(void) {
    time_t now = time(NULL);
    int device_count = 0;
    
    /* Count devices first */
    for (int i = 0; i < MAX_DEVICES; i++) {
        if (devices[i].active && (now - devices[i].last_seen) < DEVICE_TIMEOUT_SEC) {
            device_count++;
        }
    }
    
    log_message("[REG] Network scan complete. Detected devices:");
    
    for (int i = 0; i < MAX_DEVICES; i++) {
        if (devices[i].active && (now - devices[i].last_seen) < DEVICE_TIMEOUT_SEC) {
            const char *type_str;
            switch (devices[i].device_type) {
                case DEVICE_TYPE_CDJ:       type_str = "CDJ"; break;
                case DEVICE_TYPE_DJM:       type_str = "Mixer"; break;
                case DEVICE_TYPE_REKORDBOX: type_str = "rekordbox"; break;
                default:                    type_str = "Unknown"; break;
            }
            log_message("[REG]   #%d: %s (%s) @ %s", 
                        devices[i].device_num,
                        devices[i].name[0] ? devices[i].name : "unnamed",
                        type_str,
                        ip_to_str(devices[i].ip_addr));
        }
    }
    if (device_count == 0) {
        log_message("[REG]   (none)");
    }
    log_message("[REG] Max players for this network: %d", get_max_players());
}

/* Detect max players: 6 for CDJ-3000 only networks, 4 if any older model present */
int get_max_players(void) {
    int has_any_cdj = 0;
    int has_older_cdj = 0;
    
    for (int i = 0; i < MAX_DEVICES; i++) {
        if (devices[i].active && devices[i].device_type == DEVICE_TYPE_CDJ) {
            has_any_cdj = 1;
            /* Check if this is NOT a CDJ-3000 */
            if (strstr(devices[i].name, "CDJ-3000") == NULL &&
                strstr(devices[i].name, "CDJ3000") == NULL) {
                has_older_cdj = 1;
                break;  /* Found an older CDJ, limit to 4 */
            }
        }
    }
    
    /* If any older CDJ is present, limit to 4 slots */
    if (has_older_cdj) {
        return MAX_PLAYERS_NXS2;
    }
    
    /* Pure CDJ-3000 network or no CDJs yet - allow 6 slots */
    return has_any_cdj ? MAX_PLAYERS_CDJ3000 : MAX_PLAYERS_NXS2;
}

/* Find a free device slot, returns 0 if none available */
uint8_t find_free_slot(void) {
    int max_players = get_max_players();
    time_t now = time(NULL);
    
    /* Track which slots are occupied */
    uint8_t occupied[7] = {0};  /* Index 1-6 */
    
    for (int i = 0; i < MAX_DEVICES; i++) {
        if (devices[i].active && 
            (now - devices[i].last_seen) < DEVICE_TIMEOUT_SEC &&
            devices[i].device_num >= 1 && 
            devices[i].device_num <= MAX_PLAYERS_CDJ3000) {
            occupied[devices[i].device_num] = 1;
        }
    }
    
    /* Prefer highest available slot within the network's max player limit.
     * After observation period, we know which slots are actually occupied. */
    for (int slot = max_players; slot >= 1; slot--) {
        if (!occupied[slot]) {
            return slot;
        }
    }
    
    return 0;  /* No free slots */
}

/* Check if any device has a track that needs active query (DBServer) */
/* Since NFS/PDB fetching isn't implemented yet, we need DBServer for ALL tracks */
int needs_active_query(void) {
    time_t now = time(NULL);
    
    for (int i = 0; i < MAX_DEVICES; i++) {
        if (!devices[i].active || devices[i].device_type != DEVICE_TYPE_CDJ) continue;
        if ((now - devices[i].last_seen) > DEVICE_TIMEOUT_SEC) continue;
        
        /* Any track without a title needs a query */
        if (devices[i].track_slot > 0 && 
            devices[i].track_title[0] == '\0' &&
            (devices[i].rekordbox_id > 0 || devices[i].track_id > 0)) {
            return 1;
        }
    }
    
    return 0;
}

/* Check if we should release our slot (ONLY if network is full) */
int should_release_slot(void) {
    int max_players = get_max_players();
    time_t now = time(NULL);
    
    /* Count active CDJs (excluding us) */
    int cdj_count = 0;
    for (int i = 0; i < MAX_DEVICES; i++) {
        if (devices[i].active && 
            devices[i].device_type == DEVICE_TYPE_CDJ &&
            (now - devices[i].last_seen) < DEVICE_TIMEOUT_SEC &&
            devices[i].device_num != our_device_num) {
            cdj_count++;
        }
    }
    
    /* ONLY release if network is full (another CDJ needs this slot) */
    /* We must stay registered to receive PKT_TYPE_CDJ_STATUS packets! */
    if (cdj_count >= max_players - 1) {
        return 1;
    }
    
    return 0;
}

/* Get our current device number (0 if not registered) */
uint8_t get_our_device_num(void) {
    return our_device_num;
}

/* Handle slot conflict when another device claims our slot */
void handle_slot_conflict(uint8_t conflicting_device_num, const char *device_name) {
    /* Ignore if we're not registered or conflict is not with us */
    if (our_device_num == 0 || conflicting_device_num != our_device_num) {
        return;
    }
    
    /* Ignore our own keepalives */
    if (device_name && (strstr(device_name, "CLUBTAGGER") != NULL ||
                        strstr(device_name, "rekordbox") != NULL)) {
        return;
    }
    
    log_message("[REG] ⚠️  Slot %d conflict with %s - finding new slot...",
                our_device_num, device_name ? device_name : "unknown device");
    
    /* Mark our old slot as occupied (so find_free_slot won't pick it) */
    /* The device table should already be updated from the keepalive */
    
    /* Find a new free slot */
    uint8_t new_slot = find_free_slot();
    if (new_slot == 0) {
        log_message("[REG] No free slots available, going passive");
        our_device_num = 0;
        registration_state = REG_PASSIVE;
        return;
    }
    
    log_message("[REG] ✅ Switched from slot %d to slot %d",
                our_device_num, new_slot);
    our_device_num = new_slot;
    keepalives_sent_active = 0;  /* Reset keepalive counter for new slot */
    
    /* Send immediate keepalive on new slot */
    if (capture_interface) {
        send_prolink_keepalive(capture_interface);
    }
}

/*
 * ============================================================================
 * Network Utilities
 * ============================================================================
 */

uint32_t get_link_local_ip(const char *interface) {
    struct ifaddrs *ifaddr, *ifa;
    uint32_t result = 0;
    
    if (getifaddrs(&ifaddr) == -1) return 0;
    
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;
        if (ifa->ifa_addr->sa_family != AF_INET) continue;
        if (strcmp(ifa->ifa_name, interface) != 0) continue;
        
        struct sockaddr_in *sin = (struct sockaddr_in *)ifa->ifa_addr;
        result = sin->sin_addr.s_addr;
        break;
    }
    
    freeifaddrs(ifaddr);
    return result;
}

/*
 * ============================================================================
 * Keepalive Sending
 * ============================================================================
 */

int send_prolink_keepalive(const char *interface) {
    if (announce_socket < 0) {
        announce_socket = socket(AF_INET, SOCK_DGRAM, 0);
        if (announce_socket < 0) {
            log_message("[ANNOUNCE] Socket creation failed: %s", strerror(errno));
            return -1;
        }
        
        int broadcast = 1;
        setsockopt(announce_socket, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast));
        
        our_ip = get_link_local_ip(interface);
        if (our_ip == 0) {
            log_message("[ANNOUNCE] No IP address on interface %s", interface);
            close(announce_socket);
            announce_socket = -1;
            return -2;
        }
        
        struct sockaddr_in bind_addr;
        memset(&bind_addr, 0, sizeof(bind_addr));
        bind_addr.sin_family = AF_INET;
        bind_addr.sin_port = htons(PROLINK_KEEPALIVE_PORT);
        bind_addr.sin_addr.s_addr = our_ip;
        
        if (bind(announce_socket, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0) {
            log_message("[ANNOUNCE] Bind failed: %s", strerror(errno));
            close(announce_socket);
            announce_socket = -1;
            return -3;
        }
        
        log_message("[ANNOUNCE] Socket bound to %s:%d", ip_to_str(our_ip), PROLINK_KEEPALIVE_PORT);
        
        /* Also create status socket (50001) */
        status_socket = socket(AF_INET, SOCK_DGRAM, 0);
        if (status_socket >= 0) {
            bind_addr.sin_port = htons(PROLINK_STATUS_PORT);
            if (bind(status_socket, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0) {
                close(status_socket);
                status_socket = -1;
            }
        }
        
        /* Also create beat socket (50002) */
        beat_socket = socket(AF_INET, SOCK_DGRAM, 0);
        if (beat_socket >= 0) {
            bind_addr.sin_port = htons(PROLINK_BEAT_PORT);
            if (bind(beat_socket, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0) {
                close(beat_socket);
                beat_socket = -1;
            }
        }
    }
    
    /* Build keepalive packet using struct */
    keepalive_packet_t pkt = {0};
    
    /* Must have a valid device number */
    if (our_device_num == 0) {
        if (verbose) log_message("[ANNOUNCE] No device slot assigned, cannot send keepalive");
        return -4;
    }
    
    memcpy(pkt.magic, PROLINK_SIGNATURE, PROLINK_SIG_LEN);
    pkt.packet_type = PKT_TYPE_DEVICE_ANNOUNCE;
    pkt.subtype = KEEPALIVE_SUBTYPE_INITIAL;
    
    /* Device name (null-padded, already zeroed) */
    memcpy(pkt.device_name, VIRTUAL_CDJ_NAME, strlen(VIRTUAL_CDJ_NAME));
    
    /* Packet structure fields */
    pkt.struct_version = 0x01;
    pkt.device_type = PROLINK_DEVICE_REKORDBOX;  /* Safer - CDJs won't query our media */
    pkt.device_num = our_device_num;
    pkt._reserved3 = 0x01;
    
    /* MAC address left as zeros (works fine) */
    
    /* IP address */
    memcpy(pkt.ip_addr, &our_ip, sizeof(pkt.ip_addr));
    
    /* Presence flag */
    pkt.presence_flag = 0x01;
    
    /* Send to broadcast */
    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(PROLINK_KEEPALIVE_PORT);
    dest.sin_addr.s_addr = htonl(PROLINK_BROADCAST_IP);
    
    ssize_t sent = sendto(announce_socket, &pkt, sizeof(pkt), 0, 
                          (struct sockaddr *)&dest, sizeof(dest));
    
    if (sent != sizeof(pkt)) {
        if (verbose) log_message("[ANNOUNCE] Send failed: %s", strerror(errno));
        return -1;
    }
    
    if (verbose) {
        log_message("[ANNOUNCE] Sent keepalive from %s", ip_to_str(our_ip));
    }
    
    return 0;
}

/*
 * ============================================================================
 * Registration State Machine
 * ============================================================================
 */

int do_full_registration(const char *interface) {
    time_t now = time(NULL);
    
    if (announce_socket < 0) {
        announce_socket = socket(AF_INET, SOCK_DGRAM, 0);
        if (announce_socket < 0) return -1;
        
        int broadcast = 1;
        setsockopt(announce_socket, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast));
        
        our_ip = get_link_local_ip(interface);
        if (our_ip == 0) {
            close(announce_socket);
            announce_socket = -1;
            return -1;
        }
        
        struct sockaddr_in bind_addr;
        memset(&bind_addr, 0, sizeof(bind_addr));
        bind_addr.sin_family = AF_INET;
        bind_addr.sin_port = htons(PROLINK_KEEPALIVE_PORT);
        bind_addr.sin_addr.s_addr = our_ip;
        
        if (bind(announce_socket, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0) {
            close(announce_socket);
            announce_socket = -1;
            return -1;
        }
    }
    
    switch (registration_state) {
        case REG_IDLE:
            /* Start observation phase - listen to network before claiming slot */
            observation_start = now;
            registration_state = REG_OBSERVING;
            log_message("[REG] Observing network for %d seconds before joining...", OBSERVATION_PERIOD_SEC);
            return 0;  /* Don't send anything yet */
            
        case REG_OBSERVING:
            /* Wait for observation period to complete */
            if (now - observation_start < OBSERVATION_PERIOD_SEC) {
                return 0;  /* Still observing, don't send anything */
            }
            
            /* Observation complete - log what we found */
            log_detected_devices();
            
            /* Now claim a slot */
            our_device_num = find_free_slot();
            if (our_device_num == 0) {
                log_message("[REG] No free slot available (max %d players), staying passive", get_max_players());
                registration_state = REG_PASSIVE;
                return -1;
            }
            
            /* Go to active mode */
            registration_state = REG_ACTIVE;
            keepalives_sent_active = 0;
            registration_start = now;
            log_message("[REG] Acquired slot %d, starting keepalives...", our_device_num);
            /* Fall through */
            
        case REG_STAGE_0:
        case REG_STAGE_2:
        case REG_STAGE_4:
            registration_state = REG_ACTIVE;
            keepalives_sent_active = 0;
            /* Fall through */
            
        case REG_ACTIVE:
            /* Check if we should release the slot */
            if (should_release_slot()) {
                log_message("[REG] Releasing slot %d (network full or queries done)", our_device_num);
                our_device_num = 0;
                registration_state = REG_PASSIVE;
                if (announce_socket >= 0) {
                    close(announce_socket);
                    announce_socket = -1;
                }
                break;
            }
            
            send_prolink_keepalive(interface);
            keepalives_sent_active++;
            if (keepalives_sent_active == MIN_KEEPALIVES_BEFORE_NFS) {
                log_message("[REG] Ready for DBServer queries after %d keepalives", keepalives_sent_active);
            }
            break;
        
        case REG_PASSIVE:
            /* Do nothing */
            break;
    }
    
    return 0;
}

void check_go_passive(void) {
    if (registration_state != REG_ACTIVE) return;
    if (active_mode) return;
    
    /* We need to STAY registered to receive PKT_TYPE_CDJ_STATUS packets!
     * Without registration, CDJs only send PKT_TYPE_BEAT packets.
     * Only release if network is full OR truly timed out. */
    
    int max_players = get_max_players();
    time_t now = time(NULL);
    
    /* Count active CDJs (excluding us) */
    int cdj_count = 0;
    for (int i = 0; i < MAX_DEVICES; i++) {
        if (devices[i].active && 
            devices[i].device_type == DEVICE_TYPE_CDJ &&
            (now - devices[i].last_seen) < DEVICE_TIMEOUT_SEC &&
            devices[i].device_num != our_device_num) {
            cdj_count++;
        }
    }
    
    /* Only release if network is full (another CDJ might need our slot) */
    int network_full = (cdj_count >= max_players - 1);
    int timeout = (keepalives_sent_active > KEEPALIVE_TIMEOUT_COUNT);
    
    if (network_full || timeout) {
        log_message("[REG] Releasing slot %d - %s", 
                    our_device_num,
                    network_full ? "network full" : "timeout");
        our_device_num = 0;
        registration_state = REG_PASSIVE;
        if (announce_socket >= 0) {
            close(announce_socket);
            announce_socket = -1;
        }
    }
}

int ensure_registration_active(void) {
    if (passive_only || !capture_interface) {
        return 0;  /* Can't re-activate in passive-only mode */
    }
    
    /* Don't allow registration until observation period completes */
    if (registration_state == REG_IDLE || registration_state == REG_OBSERVING) {
        return 0;  /* Still observing - use NFS only for now */
    }
    
    if (registration_state == REG_ACTIVE && our_device_num > 0) {
        return 1;  /* Already active with a slot */
    }
    
    if (registration_state == REG_PASSIVE || our_device_num == 0) {
        /* Need to acquire a slot first */
        if (our_device_num == 0) {
            our_device_num = find_free_slot();
            if (our_device_num == 0) {
                log_message("[REG] No free slot for re-activation (max %d players)", get_max_players());
                return 0;  /* Network full, fall back to NFS-only */
            }
            log_message("[REG] Activating with slot %d for DBServer query...", our_device_num);
        } else {
            log_message("[REG] Re-activating slot %d for DBServer query...", our_device_num);
        }
        
        /* Send a burst of keepalives to re-establish presence */
        for (int i = 0; i < REACTIVATION_BURST_COUNT; i++) {
            if (send_prolink_keepalive(capture_interface) < 0) {
                log_message("[REG] Re-activation keepalive failed");
                our_device_num = 0;
                return 0;
            }
            usleep(REACTIVATION_DELAY_US);
        }
        
        registration_state = REG_ACTIVE;
        keepalives_sent_active = REACTIVATION_BURST_COUNT;
        log_message("[REG] Re-activated on slot %d", our_device_num);
        return 1;
    }
    
    return 0;  /* Not in a state we can re-activate from */
}
