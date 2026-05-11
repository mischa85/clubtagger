/*
 * pdb.h - Rekordbox PDB database: fetch over NFS + parse pages.
 *
 * Data layer for pdb_thread workers (mirrors onelibrary.{c,h} ↔
 * onelibrary_thread.{c,h}). The worker owns the parsed pdb_database_t and
 * drives all lookups; this module just fetches and parses.
 */

#ifndef CLUBTAGGER_PDB_H
#define CLUBTAGGER_PDB_H

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

/* Fetch rekordbox database from CDJ via NFS.
 * `nfs_port` and `mount_port` are the device's ports discovered at announce
 * time (cdj_device_t::nfs_port, mount_port); the fetcher does not touch
 * portmap. Both must be non-zero. */
int fetch_rekordbox_database(uint32_t device_ip, uint8_t slot,
                             uint16_t nfs_port, uint16_t mount_port,
                             pdb_database_t *db);

/* Parse a passively captured PDB buffer (from NFS sniffing) */
void parse_pdb_buffer(const uint8_t *data, size_t len, uint32_t device_ip);

#endif /* CLUBTAGGER_PDB_H */
