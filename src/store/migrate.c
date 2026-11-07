/* OpenGDS - schema migrations. The SQL lives in migrations/NNN_*.sql and is
 * compiled in by CMake (migrations_sql.h).
 * SPDX-License-Identifier: MPL-2.0 */
#include "migrate.h"

#include <stdio.h>

#include "common/compiler.h"
#include "migrations_sql.h"
#include "common/banned.h"

static const struct {
    int version;
    const char *sql;
} migrations[] = {
    {1, (const char *)gds_sql_001_init},
    {2, (const char *)gds_sql_002_audit},
    {3, (const char *)gds_sql_003_record_ids},
};

int gds_migrate_latest(void) {
    return migrations[GDS_ARRAY_SIZE(migrations) - 1].version;
}

static int user_version(sqlite3 *db) {
    sqlite3_stmt *st = NULL;
    int v = -1;
    if(sqlite3_prepare_v2(db, "PRAGMA user_version", -1, &st, NULL) == SQLITE_OK &&
       sqlite3_step(st) == SQLITE_ROW)
        v = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return v;
}

gds_status gds_migrate(sqlite3 *db, int *version) {
    int v = user_version(db);
    *version = v;
    if(v < 0)
        return GDS_EIO;
    if(v > gds_migrate_latest()) {
        fprintf(stderr, "store: schema %d is newer than this OpenGDS (%d)\n", v,
                gds_migrate_latest());
        return GDS_ESTATE;
    }
    for(size_t i = 0; i < GDS_ARRAY_SIZE(migrations); i++) {
        if(migrations[i].version <= v)
            continue;
        char setv[64];
        (void)snprintf(setv, sizeof(setv), "PRAGMA user_version = %d", migrations[i].version);
        char *err = NULL;
        if(sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, &err) != SQLITE_OK ||
           sqlite3_exec(db, migrations[i].sql, NULL, NULL, &err) != SQLITE_OK ||
           sqlite3_exec(db, setv, NULL, NULL, &err) != SQLITE_OK ||
           sqlite3_exec(db, "COMMIT", NULL, NULL, &err) != SQLITE_OK) {
            fprintf(stderr, "store: migration %d failed: %s\n", migrations[i].version,
                    err ? err : "?");
            sqlite3_free(err);
            (void)sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
            return GDS_EIO;
        }
        *version = migrations[i].version;
    }
    return GDS_OK;
}
