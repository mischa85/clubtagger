/*
 * database.h - SQLite database operations
 */
#ifndef CLUBTAGGER_DATABASE_H
#define CLUBTAGGER_DATABASE_H

#include "../types.h"

/* Initialize database connection and create tables */
int db_init(App *app);

/* Close database connection */
void db_close(App *app);

/* Insert a play record
 * confidence: 0-100 percentage
 * source: "audio", "cdj", or "both" */
void db_insert_play(App *app, const char *timestamp, const char *artist,
                    const char *title, const char *isrc, int confidence, const char *source);

/* Get recent tracks from database
 * Returns number of tracks written to the output arrays (up to max_tracks)
 * Arrays must be pre-allocated with at least max_tracks elements */
int db_get_recent_tracks(App *app, int max_tracks,
                         char timestamps[][32], char artists[][256], char titles[][256]);

#endif /* CLUBTAGGER_DATABASE_H */
