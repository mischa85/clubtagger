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

#endif /* CLUBTAGGER_DATABASE_H */
