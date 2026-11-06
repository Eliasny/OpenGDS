/* OpenGDS - the built-in SQLite backend, for store.c only.
 * SPDX-License-Identifier: MPL-2.0 */
#ifndef OPENGDS_STORE_BACKEND_H
#define OPENGDS_STORE_BACKEND_H

#include <stdbool.h>

#include "store.h"

extern const gds_store_backend gds_store_sqlite_backend;
/* *ctx is NULL on failure. */
GDS_MUST_CHECK gds_status gds_store_sqlite_open(const char *path, bool readonly, void **ctx);

#endif
