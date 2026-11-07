/* gdsadm apps import: parse a file of application records (OpenGDS plan,
 * W1, cmd_import). Each record is later registered with the standard
 * RegisterApplication (OPC 10000-12 §6.5.5), one call per record.
 *
 * CSV (RFC 4180, UTF-8): a header row names the columns, in any order:
 *   ApplicationUri, ApplicationName, ApplicationType   required
 *   ApplicationNameLocale                             optional, default "en"
 *   ProductUri, DiscoveryUrls, ServerCapabilities     optional
 * ApplicationType is Server, Client or ClientAndServer. DiscoveryUrls and
 * ServerCapabilities hold several values separated by spaces.
 *
 * JSON: {"Applications": [ ... ]}, each element an ApplicationRecordDataType
 * in the OPC UA JSON encoding (OPC 10000-6 §5.4); ApplicationId is ignored.
 *
 * The format is JSON when the first non-blank character is '{', else CSV.
 * SPDX-License-Identifier: MPL-2.0 */
#ifndef OPENGDS_GDSADM_IMPORT_H
#define OPENGDS_GDSADM_IMPORT_H

#include <open62541/types.h>
#include <open62541/types_gds_generated.h>

#include "common/buf.h"
#include "common/compiler.h"

#define GDSADM_IMPORT_MAX_FILE ((size_t)16 * 1024 * 1024)
#define GDSADM_IMPORT_MAX_ROWS ((size_t)100000)

typedef struct {
    UA_ApplicationRecordDataType *recs;
    size_t *lines; /* the line (CSV) or element number (JSON, from 1) of each */
    size_t n;
} gdsadm_import;

/* Parse the file. On failure, err names the line and the problem. Records
 * are not validated here (gds_validate_record does that per record). */
GDS_MUST_CHECK gds_status gdsadm_import_parse(const gds_buf *file, gdsadm_import *out, char *err,
                                              size_t errLen);
void gdsadm_import_clear(gdsadm_import *im);

#endif
