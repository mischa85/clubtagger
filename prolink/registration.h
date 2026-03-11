/*
 * registration.h - Virtual CDJ Registration
 *
 * Handle Pro DJ Link network registration as a virtual CDJ device.
 */

#ifndef REGISTRATION_H
#define REGISTRATION_H

#include <stdint.h>
#include <time.h>
#include "cdj_types.h"

/*
 * ============================================================================
 * Registration Constants
 * ============================================================================
 */

/* Required keepalives before CDJ accepts our NFS requests */
#define MIN_KEEPALIVES_BEFORE_NFS 5

/*
 * ============================================================================
 * Registration State (extern)
 * ============================================================================
 */

extern reg_state_t registration_state;
extern time_t registration_start;
extern time_t last_keepalive_sent;
extern int registration_stage_count;
extern int databases_pending;
extern int keepalives_sent_active;
extern uint32_t our_ip;

/*
 * ============================================================================
 * Registration Functions
 * ============================================================================
 */

/* Perform full 4-stage registration */
int do_full_registration(const char *interface);

/* Send keepalive packet */
int send_prolink_keepalive(const char *interface);

/* Check if we can go passive (all databases fetched) */
void check_go_passive(void);

/* Ensure we're active for DBServer queries - re-activates if passive */
int ensure_registration_active(void);

/*
 * ============================================================================
 * Slot Management - Smart Network Participation
 * ============================================================================
 */

/* Get max players supported (4 for NXS2, 6 for CDJ-3000) */
int get_max_players(void);

/* Find a free device slot, returns 0 if none available */
uint8_t find_free_slot(void);

/* Check if any device needs active query (unanalyzed/CD) */
int needs_active_query(void);

/* Check if we should release our slot */
int should_release_slot(void);

/* Get our current device number (0 if not registered) */
uint8_t get_our_device_num(void);

/* Handle slot conflict when another device claims our slot */
void handle_slot_conflict(uint8_t conflicting_device_num, const char *device_name);

/* Dynamic device number (0 = not registered) */
extern uint8_t our_device_num;

/*
 * ============================================================================
 * Network Utilities
 * ============================================================================
 */

/* Get link-local IP address for interface */
uint32_t get_link_local_ip(const char *interface);

/*
 * ============================================================================
 * Global Configuration (extern)
 * ============================================================================
 */

extern int passive_only;      /* Pure passive mode - no registration */
extern int active_mode;       /* Stay active, never go passive */
extern int show_nfs;          /* Show NFS activity in log */
extern const char *capture_interface;

#endif /* REGISTRATION_H */
