/* OpenGDS - schema migrations (PRAGMA user_version, one transaction each).
 * SPDX-License-Identifier: MPL-2.0 */
#ifndef OPENGDS_STORE_MIGRATE_H
#define OPENGDS_STORE_MIGRATE_H

#include <sqlite3.h>

#include "common/compiler.h"
#include "common/errors.h"

/* Bring db to the newest schema. Refuses (GDS_ESTATE) a database written by
 * a newer OpenGDS. *version is the schema version afterwards. */
GDS_MUST_CHECK gds_status gds_migrate(sqlite3 *db, int *version);
int gds_migrate_latest(void);

#endif
