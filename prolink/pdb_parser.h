/*
 * pdb_parser.h - Rekordbox PDB Database Parser
 *
 * Parse rekordbox export.pdb files to extract track metadata.
 */

#ifndef PDB_PARSER_H
#define PDB_PARSER_H

#include <stdint.h>
#include <stddef.h>
#include <time.h>
#include "../types.h"

/*
 * ============================================================================
 * PDB Constants
 * ============================================================================
 */

#define MAX_PDB_TRACKS 65536  /* 64K tracks per USB, ~64MB per database */

/*
 * ============================================================================
 * PDB Database Cache (uses unified TrackID from types.h)
 * ============================================================================
 */

typedef struct pdb_database_s {
    uint32_t device_ip;
    uint8_t  slot;           /* 1=CD, 2=SD, 3=USB */
    TrackID  tracks[MAX_PDB_TRACKS];
    int      track_count;
    time_t   fetched_at;
    uint8_t  fetch_in_progress;
    uint8_t  fetch_failed;
} pdb_database_t;

/* Support up to 6 CDJs * 2 slots (USB + SD) = 12 databases */
#define MAX_DATABASES 12

extern pdb_database_t pdb_databases[MAX_DATABASES];
extern int pdb_database_count;

/*
 * ============================================================================
 * Database Management
 * ============================================================================
 */

/* Find database for device/slot */
pdb_database_t *find_pdb_database(uint32_t device_ip, uint8_t slot);

/* Create new database entry */
pdb_database_t *create_pdb_database(uint32_t device_ip, uint8_t slot);

/* Remove database for device/slot (e.g., when media ejected) */
void remove_pdb_database(uint32_t device_ip, uint8_t slot);

/* Look up track by rekordbox ID in any loaded database */
TrackID *lookup_pdb_track(uint32_t rekordbox_id);

/*
 * ============================================================================
 * PDB Parsing
 * ============================================================================
 */

/* Parse PDB file data into database structure */
int parse_pdb_file(const uint8_t *data, size_t len, pdb_database_t *db);

/*
 * ============================================================================
 * Database Fetching
 * ============================================================================
 */

/* Fetch rekordbox database from CDJ via NFS */
int fetch_rekordbox_database(uint32_t device_ip, uint8_t slot, pdb_database_t *db);

/* Parse a passively captured PDB buffer (from NFS sniffing) */
void parse_pdb_buffer(const uint8_t *data, size_t len, uint32_t device_ip);

#endif /* PDB_PARSER_H */
