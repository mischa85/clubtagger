/*
 * common.h - Shared utilities and globals for clubtagger
 */
#ifndef CLUBTAGGER_COMMON_H
#define CLUBTAGGER_COMMON_H

#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/* AF_XDP and pcap have conflicting struct bpf_insn definitions.
 * When AF_XDP is enabled, we use raw sockets for NFS observation 
 * instead of pcap, avoiding the conflict entirely. */
#ifdef HAVE_AF_XDP
#include <xdp/xsk.h>
#elif defined(HAVE_PCAP)
#include <pcap.h>
#endif
#ifdef HAVE_ALSA
#include <alsa/asoundlib.h>
#endif

#include "types.h"

/* Maximum ANLZ waveform file size (1 MB — long tracks can exceed 300KB) */
#define ANLZ_MAX_SIZE 1048576

/* ─────────────────────────────────────────────────────────────────────────────
 * Global state
 * ───────────────────────────────────────────────────────────────────────────── */
extern volatile sig_atomic_t g_running;
extern int g_verbose;
extern int verbose;  /* Alias for prolink modules */
extern int match_threshold;  /* 0-100 similarity % for fuzzy matching (default 60) */
#if defined(HAVE_PCAP) && !defined(HAVE_AF_XDP)
extern pcap_t *g_pcap_handle;
#endif
#ifdef HAVE_ALSA
extern snd_pcm_t *g_alsa_handle;
#endif
#ifdef HAVE_AF_XDP
extern struct xsk_socket *g_xsk;
#endif

/* ─────────────────────────────────────────────────────────────────────────────
 * Logging functions
 * ───────────────────────────────────────────────────────────────────────────── */

/* Log a message with tag (always prints) */
void logmsg(const char *tag, const char *fmt, ...);

/* Log a message with tag (only if verbose enabled) */
void vlogmsg(const char *tag, const char *fmt, ...);

/* Format current time to a buffer */
void now_timestamp(char *out, size_t out_sz);

/* ─────────────────────────────────────────────────────────────────────────────
 * Activity log ring buffer (for web UI)
 * ───────────────────────────────────────────────────────────────────────────── */

#define ACTIVITY_LOG_SIZE 32
#define ACTIVITY_MSG_LEN 160

typedef struct {
    char messages[ACTIVITY_LOG_SIZE][ACTIVITY_MSG_LEN];
    int head;                  /* Next write position */
    _Atomic uint32_t sequence; /* Bumps on each new message */
} activity_log_t;

extern activity_log_t g_activity_log;

/* Get messages newer than `since_seq`. Returns count, fills buf with JSON array string. */
int activity_log_since(uint32_t since_seq, char *buf, size_t buf_len);

/* ─────────────────────────────────────────────────────────────────────────────
 * String utilities
 * ───────────────────────────────────────────────────────────────────────────── */

/* Normalize a string for comparison (lowercase, remove punctuation, collapse spaces) */
void normalize_str(char *s);

/* Check if two TrackID structs identify the same track */
int same_track(const TrackID *a, const TrackID *b);

/* Levenshtein edit distance between two strings (case-insensitive) */
int levenshtein_distance(const char *s1, const char *s2);

/* Similarity percentage (0-100) based on Levenshtein distance
 * Normalizes strings first (lowercase, alphanumeric only) */
int str_similarity(const char *s1, const char *s2);

/* Check if needle is a substring of haystack (normalized, case-insensitive) */
int str_contains(const char *haystack, const char *needle);

/* Core title match: compare prefix of normalized strings.
 * Handles different remix/version suffixes. */
int str_core_match(const char *s1, const char *s2);

/* Artist match with "ft."/"feat."/"&" normalization */
int str_artist_match(const char *a1, const char *a2);

/* ─────────────────────────────────────────────────────────────────────────────
 * UTF-8 utilities
 * ───────────────────────────────────────────────────────────────────────────── */

/* Copy string with UTF-8-safe truncation (won't split multi-byte sequences) */
void utf8_safe_copy(char *dst, const char *src, size_t dst_sz);

/* Escape string for JSON output (handles ", \, control chars) */
void json_escape(const char *in, char *out, size_t out_max);

/* Convert UTF-16LE to UTF-8 (handles surrogate pairs for emoji/CJK) */
size_t utf16le_to_utf8(const uint8_t *data, size_t byte_len, char *out, size_t out_max);

/* Convert UTF-16BE to UTF-8 (handles surrogate pairs for emoji/CJK) */
size_t utf16be_to_utf8(const uint8_t *data, size_t byte_len, char *out, size_t out_max);

/* Convert Latin-1 (ISO-8859-1) to UTF-8 */
size_t latin1_to_utf8(const uint8_t *data, size_t len, char *out, size_t out_max);

/* ─────────────────────────────────────────────────────────────────────────────
 * Misc utilities
 * ───────────────────────────────────────────────────────────────────────────── */

/* Fill buffer with random bytes */
void random_bytes(void *dst, size_t n);

/* Generate a UUID v4 string (37 chars including null) */
void uuid4(char out[37]);

#endif /* CLUBTAGGER_COMMON_H */
