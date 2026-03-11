/*
 * nfs_protocol.h - NFS/RPC Protocol Constants
 *
 * Minimal NFS v2 constants for fetching rekordbox databases from CDJs.
 */

#ifndef NFS_PROTOCOL_H
#define NFS_PROTOCOL_H

#include <stdint.h>

/*
 * ============================================================================
 * Network Ports
 * ============================================================================
 */

#define NFS_PORT                2049
#define PORTMAPPER_PORT         111
#define MOUNT_PORT              635     /* Pioneer uses non-standard port */

/*
 * ============================================================================
 * RPC Program Numbers
 * ============================================================================
 */

#define NFS_PROGRAM             100003
#define MOUNT_PROGRAM           100005
#define PORTMAP_PROGRAM         100000

/*
 * ============================================================================
 * NFS Procedures
 * ============================================================================
 */

typedef enum {
    NFS_PROC_NULL       = 0,
    NFS_PROC_GETATTR    = 1,
    NFS_PROC_SETATTR    = 2,
    NFS_PROC_ROOT       = 3,
    NFS_PROC_LOOKUP     = 4,
    NFS_PROC_READLINK   = 5,
    NFS_PROC_READ       = 6,
    NFS_PROC_WRITECACHE = 7,
    NFS_PROC_WRITE      = 8,
    NFS_PROC_CREATE     = 9,
    NFS_PROC_REMOVE     = 10,
    NFS_PROC_RENAME     = 11,
    NFS_PROC_LINK       = 12,
    NFS_PROC_SYMLINK    = 13,
    NFS_PROC_MKDIR      = 14,
    NFS_PROC_RMDIR      = 15,
    NFS_PROC_READDIR    = 16,
    NFS_PROC_READDIRPLUS= 17,
    NFS_PROC_STATFS     = 18
} nfs_proc_t;

/*
 * ============================================================================
 * MOUNT Procedures
 * ============================================================================
 */

typedef enum {
    MOUNT_PROC_NULL     = 0,
    MOUNT_PROC_MNT      = 1,
    MOUNT_PROC_DUMP     = 2,
    MOUNT_PROC_UMNT     = 3,
    MOUNT_PROC_UMNTALL  = 4,
    MOUNT_PROC_EXPORT   = 5
} mount_proc_t;

/*
 * ============================================================================
 * Portmap Procedures
 * ============================================================================
 */

typedef enum {
    PORTMAP_PROC_NULL    = 0,
    PORTMAP_PROC_SET     = 1,
    PORTMAP_PROC_UNSET   = 2,
    PORTMAP_PROC_GETPORT = 3,
    PORTMAP_PROC_DUMP    = 4
} portmap_proc_t;

/*
 * ============================================================================
 * Protocol Constants
 * ============================================================================
 */

#define PORTMAP_PROT_UDP        17
#define PORTMAP_PROT_TCP        6

#define NFS_VERSION             2
#define MOUNT_VERSION           1

/*
 * ============================================================================
 * RPC Message Types
 * ============================================================================
 */

#define RPC_CALL                0
#define RPC_REPLY               1

#define RPC_MSG_ACCEPTED        0
#define RPC_MSG_DENIED          1

#define RPC_SUCCESS             0
#define RPC_PROG_UNAVAIL        1
#define RPC_PROG_MISMATCH       2
#define RPC_PROC_UNAVAIL        3
#define RPC_GARBAGE_ARGS        4

/*
 * ============================================================================
 * NFS Status Codes
 * ============================================================================
 */

typedef enum {
    NFS_OK          = 0,
    NFSERR_PERM     = 1,
    NFSERR_NOENT    = 2,
    NFSERR_IO       = 5,
    NFSERR_NXIO     = 6,
    NFSERR_ACCES    = 13,
    NFSERR_EXIST    = 17,
    NFSERR_NODEV    = 19,
    NFSERR_NOTDIR   = 20,
    NFSERR_ISDIR    = 21,
    NFSERR_INVAL    = 22,
    NFSERR_FBIG     = 27,
    NFSERR_NOSPC    = 28,
    NFSERR_ROFS     = 30,
    NFSERR_NAMETOOLONG = 63,
    NFSERR_NOTEMPTY = 66,
    NFSERR_DQUOT    = 69,
    NFSERR_STALE    = 70,
    NFSERR_WFLUSH   = 99
} nfs_status_t;

/*
 * ============================================================================
 * NFS File Handle Size
 * ============================================================================
 */

#define NFS_FHSIZE              32

/*
 * ============================================================================
 * RPC Auth Types
 * ============================================================================
 */

#define AUTH_NULL               0
#define AUTH_UNIX               1
#define AUTH_SHORT              2

/*
 * ============================================================================
 * RPC Packet Structures (Big-Endian / Network Byte Order)
 * ============================================================================
 * Use ntohl()/ntohs() when reading fields, htonl()/htons() when writing.
 */

/* RPC Call Header (24 bytes before credentials) */
typedef struct __attribute__((packed)) {
    uint32_t xid;           /* Transaction ID */
    uint32_t msg_type;      /* 0 = CALL, 1 = REPLY */
    uint32_t rpc_vers;      /* RPC version (always 2) */
    uint32_t prog;          /* Program number */
    uint32_t vers;          /* Program version */
    uint32_t proc;          /* Procedure number */
    /* Followed by credentials and verifier */
} rpc_call_header_t;

_Static_assert(sizeof(rpc_call_header_t) == 24, "rpc_call_header_t must be 24 bytes");

/* RPC Reply Header (24 bytes) */
typedef struct __attribute__((packed)) {
    uint32_t xid;           /* Transaction ID (echoed from call) */
    uint32_t msg_type;      /* 1 = REPLY */
    uint32_t reply_stat;    /* 0 = MSG_ACCEPTED, 1 = MSG_DENIED */
    uint32_t auth_flavor;   /* Verifier flavor (usually AUTH_NULL) */
    uint32_t auth_length;   /* Verifier length (usually 0) */
    uint32_t accept_stat;   /* 0 = SUCCESS */
    /* Followed by procedure-specific reply data */
} rpc_reply_header_t;

_Static_assert(sizeof(rpc_reply_header_t) == 24, "rpc_reply_header_t must be 24 bytes");

/* AUTH_UNIX credentials (28 bytes) - fixed format we use */
typedef struct __attribute__((packed)) {
    uint32_t flavor;        /* AUTH_UNIX = 1 */
    uint32_t length;        /* 20 bytes */
    uint32_t stamp;         /* Arbitrary (we use 0xdeadbeef) */
    uint32_t machine_len;   /* 0 = no machine name */
    uint32_t uid;           /* 0 */
    uint32_t gid;           /* 0 */
    uint32_t gids_len;      /* 0 = no aux gids */
} rpc_auth_unix_t;

_Static_assert(sizeof(rpc_auth_unix_t) == 28, "rpc_auth_unix_t must be 28 bytes");

/* AUTH_NULL verifier (8 bytes) */
typedef struct __attribute__((packed)) {
    uint32_t flavor;        /* AUTH_NULL = 0 */
    uint32_t length;        /* 0 */
} rpc_auth_null_t;

_Static_assert(sizeof(rpc_auth_null_t) == 8, "rpc_auth_null_t must be 8 bytes");

/* Portmapper GETPORT request arguments (16 bytes) */
typedef struct __attribute__((packed)) {
    uint32_t prog;          /* Program number to query */
    uint32_t vers;          /* Version number */
    uint32_t prot;          /* Protocol (UDP=17, TCP=6) */
    uint32_t port;          /* Port (0 for query) */
} portmap_getport_args_t;

_Static_assert(sizeof(portmap_getport_args_t) == 16, "portmap_getport_args_t must be 16 bytes");

/* Portmapper GETPORT reply (4 bytes after RPC header) */
typedef struct __attribute__((packed)) {
    uint32_t port;          /* Mapped port number */
} portmap_getport_reply_t;

/* NFS LOOKUP request (32-byte fhandle + XDR string) */
typedef struct __attribute__((packed)) {
    uint8_t  dir_fh[NFS_FHSIZE];  /* Directory file handle */
    uint32_t name_len;            /* Filename length (XDR string) */
    /* Followed by name bytes, padded to 4-byte boundary */
} nfs_lookup_args_t;

/* NFS LOOKUP reply (status + 32-byte fhandle + fattr) */
typedef struct __attribute__((packed)) {
    uint32_t status;              /* NFS status */
    uint8_t  fh[NFS_FHSIZE];      /* File handle (if status == 0) */
    /* Followed by fattr structure */
} nfs_lookup_reply_t;

/* NFS READ request arguments */
typedef struct __attribute__((packed)) {
    uint8_t  fh[NFS_FHSIZE];      /* File handle */
    uint32_t offset;              /* Byte offset (NFSv2: 32-bit) */
    uint32_t count;               /* Bytes to read */
    uint32_t totalcount;          /* Unused in NFSv2 */
} nfs_read_args_t;

_Static_assert(sizeof(nfs_read_args_t) == 44, "nfs_read_args_t must be 44 bytes");

/* NFS READ reply header (before data) */
typedef struct __attribute__((packed)) {
    uint32_t status;              /* NFS status */
    /* If status == 0, followed by fattr (68 bytes) then data */
} nfs_read_reply_t;

/* NFS file attributes (fattr) - NFSv2 (68 bytes) */
typedef struct __attribute__((packed)) {
    uint32_t type;          /* File type */
    uint32_t mode;          /* Protection mode bits */
    uint32_t nlink;         /* # hard links */
    uint32_t uid;           /* Owner user id */
    uint32_t gid;           /* Owner group id */
    uint32_t size;          /* File size in bytes */
    uint32_t blocksize;     /* Preferred block size */
    uint32_t rdev;          /* Device id for special files */
    uint32_t blocks;        /* Blocks used (1K units) */
    uint32_t fsid;          /* File system id */
    uint32_t fileid;        /* File id (inode) */
    uint32_t atime_sec;     /* Access time seconds */
    uint32_t atime_usec;    /* Access time microseconds */
    uint32_t mtime_sec;     /* Modify time seconds */
    uint32_t mtime_usec;    /* Modify time microseconds */
    uint32_t ctime_sec;     /* Change time seconds */
    uint32_t ctime_usec;    /* Change time microseconds */
} nfs_fattr_t;

_Static_assert(sizeof(nfs_fattr_t) == 68, "nfs_fattr_t must be 68 bytes");

/* MOUNT MNT reply */
typedef struct __attribute__((packed)) {
    uint32_t status;              /* Mount status (0 = success) */
    uint8_t  fh[NFS_FHSIZE];      /* Root file handle */
} mount_mnt_reply_t;

_Static_assert(sizeof(mount_mnt_reply_t) == 36, "mount_mnt_reply_t must be 36 bytes");

/*
 * ============================================================================
 * Helper Macros for Network Byte Order
 * ============================================================================
 */

/* Write big-endian uint32 to buffer */
#define RPC_PUT_U32(buf, val) do { \
    (buf)[0] = ((val) >> 24) & 0xFF; \
    (buf)[1] = ((val) >> 16) & 0xFF; \
    (buf)[2] = ((val) >> 8) & 0xFF; \
    (buf)[3] = (val) & 0xFF; \
} while(0)

/* Read big-endian uint32 from buffer */
#define RPC_GET_U32(buf) \
    (((uint32_t)(buf)[0] << 24) | ((uint32_t)(buf)[1] << 16) | \
     ((uint32_t)(buf)[2] << 8) | (uint32_t)(buf)[3])

#endif /* NFS_PROTOCOL_H */
