/*
 * shazam.h - Shazam API communication
 */
#ifndef CLUBTAGGER_SHAZAM_H
#define CLUBTAGGER_SHAZAM_H

#include <stddef.h>

/* Build Shazam request URL and body */
void build_shazam_request(const char *uri, unsigned sample_ms,
                          const char *timezone_opt,
                          char url_out[512], char *body_out, size_t body_sz);

/* POST to Shazam and get response */
int shazam_post(const char *url, const char *user_agent, const char *json_body,
                char *response_buf, size_t response_sz);

/* Extract a string field from JSON (simple pattern matching) */
void json_extract_field(const char *j, const char *key, char *out, size_t out_sz);

#endif /* CLUBTAGGER_SHAZAM_H */
