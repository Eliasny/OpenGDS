/* OpenGDS - opengdsd configuration file.
 *
 * One `key = value` per line; '#' starts a comment line; unknown keys and
 * repeated keys are errors. Paths must be absolute.
 *
 *   application_uri  = urn:example:opengds          (required)
 *   application_name = OpenGDS                      (default)
 *   product_uri      = https://opengds.org/opengds  (default)
 *   port             = 58810                        (default; 0 = any)
 *   hostname         = gds.example.com              (endpoint host; default: all interfaces)
 *   loopback_only    = false                        (true: listen on 127.0.0.1 only)
 *   data_dir         = /var/lib/opengds             (required: store and own certificate)
 *   users_file       = /etc/opengds/users           (required)
 *   organization     = Example Oy                   (O= in issued certificates)
 *   ca_dir           = /var/lib/opengds-signer/ca   (required)
 *   signer           = /usr/libexec/opengds-signer  (default: the CA runs in opengdsd)
 *   ca_passphrase_file = /etc/opengds/ca-passphrase (default: $CREDENTIALS_DIRECTORY/ca-passphrase)
 *   auto_approve     = true                         (T1 default, decision G7)
 *
 * With `signer` set the CA key never enters opengdsd (decision G1); the
 * passphrase file path (not its content) is passed to the signer.
 * SPDX-License-Identifier: MPL-2.0 */
#ifndef OPENGDS_DAEMON_CONFIG_H
#define OPENGDS_DAEMON_CONFIG_H

#include <stdbool.h>
#include <stdint.h>

#include "common/compiler.h"
#include "common/errors.h"
#include "common/limits.h"

#define GDSD_MAX_VALUE 1024

typedef struct {
    char applicationUri[GDSD_MAX_VALUE];
    char applicationName[GDSD_MAX_VALUE];
    char productUri[GDSD_MAX_VALUE];
    char hostname[GDSD_MAX_VALUE];
    char dataDir[GDS_MAX_PATH];
    char usersFile[GDS_MAX_PATH];
    char organization[GDSD_MAX_VALUE];
    char caDir[GDS_MAX_PATH];
    char signer[GDS_MAX_PATH];
    char caPassphraseFile[GDS_MAX_PATH];
    uint16_t port;
    bool loopbackOnly;
    bool autoApprove;
} gdsd_config;

/* Parse a configuration text (len bytes, need not be NUL-terminated). On
 * error, *errLine is the 1-based line at fault. */
GDS_MUST_CHECK gds_status gdsd_config_parse(const char *text, size_t len, gdsd_config *out,
                                            unsigned *errLine);
GDS_MUST_CHECK gds_status gdsd_config_load(const char *path, gdsd_config *out,
                                           unsigned *errLine);

#endif
