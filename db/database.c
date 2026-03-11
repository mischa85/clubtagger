/*
 * database.c - SQLite database operations
 */
#include "database.h"
#include "../common.h"

#include <sqlite3.h>

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
    sqlite3_bind_text(stmt, 5, app->current_wav[0] ? app->current_wav : NULL, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 6, confidence);
    sqlite3_bind_text(stmt, 7, source, -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        logmsg("db", "insert failed: %s", sqlite3_errmsg(app->db));
    }

    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&app->db_mu);
}
