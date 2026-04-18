/*
 * database.c - SQLite database operations
 */
#include "database.h"
#include "../common.h"

#include <sqlite3.h>
#include <stdio.h>

int db_init(App *app) {
    if (!app->cfg.db_path) return 0; /* no database configured */

    pthread_mutex_init(&app->db_mu, NULL);

    int rc = sqlite3_open(app->cfg.db_path, &app->db);
    if (rc != SQLITE_OK) {
        logmsg("db", "failed to open %s: %s", app->cfg.db_path, sqlite3_errmsg(app->db));
        return -1;
    }

    const char *sql =
        "CREATE TABLE IF NOT EXISTS plays ("
        "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  timestamp TEXT NOT NULL,"
        "  artist TEXT,"
        "  title TEXT,"
        "  isrc TEXT,"
        "  wav_file TEXT,"
        "  confidence INTEGER,"
        "  source TEXT"
        ");"
        "CREATE INDEX IF NOT EXISTS idx_plays_timestamp ON plays(timestamp);"
        "CREATE INDEX IF NOT EXISTS idx_plays_isrc ON plays(isrc);";

    /* Migration: add confidence/source columns if they don't exist (for existing DBs) */
    sqlite3_exec(app->db, "ALTER TABLE plays ADD COLUMN confidence INTEGER", NULL, NULL, NULL);
    sqlite3_exec(app->db, "ALTER TABLE plays ADD COLUMN source TEXT", NULL, NULL, NULL);;

    char *errmsg = NULL;
    rc = sqlite3_exec(app->db, sql, NULL, NULL, &errmsg);
    if (rc != SQLITE_OK) {
        logmsg("db", "failed to create tables: %s", errmsg);
        sqlite3_free(errmsg);
        sqlite3_close(app->db);
        app->db = NULL;
        return -1;
    }

    logmsg("db", "opened %s", app->cfg.db_path);
    return 0;
}

void db_close(App *app) {
    if (app->db) {
        sqlite3_close(app->db);
        app->db = NULL;
        pthread_mutex_destroy(&app->db_mu);
    }
}

void db_insert_play(App *app, const char *timestamp, const char *artist,
                    const char *title, const char *isrc, int confidence, const char *source) {
    if (!app->db) return;

    pthread_mutex_lock(&app->db_mu);

    const char *sql = "INSERT INTO plays (timestamp, artist, title, isrc, wav_file, confidence, source) "
                      "VALUES (?, ?, ?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(app->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        logmsg("db", "prepare failed: %s", sqlite3_errmsg(app->db));
        pthread_mutex_unlock(&app->db_mu);
        return;
    }

    sqlite3_bind_text(stmt, 1, timestamp, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, artist, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, title, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, isrc[0] ? isrc : NULL, -1, SQLITE_STATIC);
    /* Find first channel currently recording for the filename */
    const char *wav = NULL;
    for (int c = 0; c < app->cfg.slink_channel_count; c++) {
        if (app->ch[c].current_wav[0]) { wav = app->ch[c].current_wav; break; }
    }
    sqlite3_bind_text(stmt, 5, wav, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 6, confidence);
    sqlite3_bind_text(stmt, 7, source, -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        logmsg("db", "insert failed: %s", sqlite3_errmsg(app->db));
    }

    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&app->db_mu);
}

void db_update_play_source(App *app, const char *artist, const char *title,
                           const char *new_source, const char *isrc) {
    if (!app->db) return;

    pthread_mutex_lock(&app->db_mu);

    const char *sql = "UPDATE plays SET source = ?, isrc = COALESCE(?, isrc) "
                      "WHERE id = (SELECT id FROM plays WHERE artist = ? AND title = ? "
                      "ORDER BY id DESC LIMIT 1)";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(app->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        logmsg("db", "update prepare failed: %s", sqlite3_errmsg(app->db));
        pthread_mutex_unlock(&app->db_mu);
        return;
    }

    sqlite3_bind_text(stmt, 1, new_source, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, (isrc && isrc[0]) ? isrc : NULL, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, artist, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, title, -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        logmsg("db", "update failed: %s", sqlite3_errmsg(app->db));
    } else if (sqlite3_changes(app->db) > 0) {
        logmsg("db", "enriched: %s — %s → source=%s%s",
               artist, title, new_source,
               (isrc && isrc[0]) ? " +ISRC" : "");
    }

    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&app->db_mu);
}

int db_get_recent_tracks(App *app, int max_tracks,
                         char timestamps[][32], char artists[][256], char titles[][256],
                         char sources[][16], int confidences[], char isrcs[][64]) {
    if (!app->db) return 0;

    pthread_mutex_lock(&app->db_mu);

    const char *sql = "SELECT timestamp, artist, title, source, confidence, isrc FROM plays "
                      "ORDER BY id DESC LIMIT ?";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(app->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        logmsg("db", "prepare failed: %s", sqlite3_errmsg(app->db));
        pthread_mutex_unlock(&app->db_mu);
        return 0;
    }

    sqlite3_bind_int(stmt, 1, max_tracks);

    int count = 0;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW && count < max_tracks) {
        const char *ts = (const char *)sqlite3_column_text(stmt, 0);
        const char *art = (const char *)sqlite3_column_text(stmt, 1);
        const char *ttl = (const char *)sqlite3_column_text(stmt, 2);
        const char *src = (const char *)sqlite3_column_text(stmt, 3);
        int conf = sqlite3_column_int(stmt, 4);
        const char *isrc = (const char *)sqlite3_column_text(stmt, 5);

        snprintf(timestamps[count], 32, "%s", ts ? ts : "");
        snprintf(artists[count], 256, "%s", art ? art : "");
        snprintf(titles[count], 256, "%s", ttl ? ttl : "");
        snprintf(sources[count], 16, "%s", src ? src : "audio");
        confidences[count] = conf;
        snprintf(isrcs[count], 64, "%s", isrc ? isrc : "");
        count++;
    }

    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&app->db_mu);
    return count;
}
