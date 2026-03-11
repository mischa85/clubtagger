/*
 * cdj_types.c - Common Type Implementations
 *
 * Utility functions for device management and string conversion.
 */

#include "cdj_types.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

/*
 * ============================================================================
 * Global Device Array
 * ============================================================================
 */

cdj_device_t devices[MAX_DEVICES];

cdj_device_t *get_device(uint8_t device_num) {
    if (device_num == 0 || device_num > MAX_DEVICES) return NULL;
    for (int i = 0; i < MAX_DEVICES; i++) {
        if (devices[i].active && devices[i].device_num == device_num) {
            return &devices[i];
        }
    }
    return NULL;
}

/*
 * ============================================================================
 * String Conversion Utilities
 * ============================================================================
 */

const char *ip_to_str(uint32_t ip) {
    static char buf[4][16];
    static int idx = 0;
    idx = (idx + 1) % 4;
    uint8_t *b = (uint8_t *)&ip;
    snprintf(buf[idx], 16, "%d.%d.%d.%d", b[0], b[1], b[2], b[3]);
    return buf[idx];
}

const char *mac_to_str(const uint8_t *mac) {
    static char buf[4][18];
    static int idx = 0;
    idx = (idx + 1) % 4;
    snprintf(buf[idx], 18, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return buf[idx];
}

const char *slot_name(uint8_t slot) {
    switch (slot) {
        case SLOT_UNKNOWN:  return "----";
        case SLOT_CD:       return "CD";
        case SLOT_SD:       return "SD";
        case SLOT_USB:      return "USB";
        case SLOT_LINK:     return "LINK";
        default:            return "????";
    }
}

const char *device_type_name(uint8_t type) {
    switch (type) {
        case DEVICE_TYPE_CDJ:      return "CDJ";
        case DEVICE_TYPE_DJM:      return "DJM";
        case DEVICE_TYPE_REKORDBOX:return "rekordbox";
        default:                   return "Unknown";
    }
}

/*
 * ============================================================================
 * Device Management
 * ============================================================================
 */

cdj_device_t *find_device(uint8_t device_num) {
    for (int i = 0; i < MAX_DEVICES; i++) {
        if (devices[i].active && devices[i].device_num == device_num) {
            return &devices[i];
        }
    }
    /* Create new entry */
    for (int i = 0; i < MAX_DEVICES; i++) {
        if (!devices[i].active) {
            memset(&devices[i], 0, sizeof(cdj_device_t));
            devices[i].active = 1;
            devices[i].device_num = device_num;
            return &devices[i];
        }
    }
    return NULL;
}

uint8_t find_other_cdj_device_num(uint32_t exclude_ip) {
    time_t now = time(NULL);
    
    for (int i = 0; i < MAX_DEVICES; i++) {
        if (devices[i].active && 
            devices[i].ip_addr != exclude_ip &&
            devices[i].device_type == DEVICE_TYPE_CDJ &&
            devices[i].device_num >= 1 && devices[i].device_num <= 4 &&
            (now - devices[i].last_seen) < 10) {
            return devices[i].device_num;
        }
    }
    
    /* No other CDJ found - return 1 as fallback */
    return 1;
}
