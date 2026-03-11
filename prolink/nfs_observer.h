/*
 * nfs_observer.h - Raw Socket NFS Traffic Observer
 *
 * Uses raw AF_PACKET socket with BPF filter to observe NFS traffic.
 * Alternative to pcap that avoids header conflicts with AF_XDP.
 */

#ifndef NFS_OBSERVER_H
#define NFS_OBSERVER_H

#ifdef HAVE_AF_XDP

#include <stdint.h>

/*
 * Initialize NFS observer on the given interface.
 * Returns 0 on success, -1 on error.
 */
int nfs_observer_init(const char *interface);

/*
 * Update the NFS port filter (called after portmapper discovery).
 * Returns 0 on success, -1 on error.
 */
int nfs_observer_set_port(uint16_t port);

/*
 * Process pending NFS packets (non-blocking).
 * Call this periodically from the main loop.
 */
void nfs_observer_poll(void);

/*
 * Cleanup NFS observer.
 */
void nfs_observer_cleanup(void);

#endif /* HAVE_AF_XDP */

#endif /* NFS_OBSERVER_H */
