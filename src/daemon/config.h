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
 *   signer           = /usr/libexec/opengds/opengds-signer  (opengdsd starts the signer itself)
 *   signer_socket    = /run/opengds/signer.sock     (connect to a signer started by systemd,
 *                                                    opengds-signer.socket; production)
 *   (neither: the CA runs in opengdsd, development only)
 *   ca_passphrase_file = /etc/opengds/ca-passphrase (default: $CREDENTIALS_DIRECTORY/ca-passphrase)
 *   approval         = renewals                     (default) which certificate requests
 *                      are approved on arrival: auto (all), renewals (an
 *                      application with a valid certificate in that group),
 *                      manual (none); the others wait for a
 *                      RegistrationAuthorityAdmin (Respond2 on their dialog)
 *   keycred_service  = mqtt urn:example:broker http://opcfoundation.org/UA/Profile/Transport/pubsub-mqtt-uadp
 *                      a KeyCredentialService (OPC 10000-12 §8.5): name,
 *                      ResourceUri and its ProfileUris (comma-separated);
 *                      may be repeated, up to GDSD_MAX_KC times. Requests
 *                      follow `approval` like certificate requests.
 *
 * With `signer` or `signer_socket` the CA key never enters opengdsd
 * (decision G1). With `signer` the passphrase file path (not its content)
 * is passed to the child; with `signer_socket` the signer's own unit holds
 * the passphrase and opengdsd never sees it. The two keys are exclusive.
 * SPDX-License-Identifier: MPL-2.0 */
#ifndef OPENGDS_DAEMON_CONFIG_H
#define OPENGDS_DAEMON_CONFIG_H

#include <stdbool.h>
#include <stdint.h>

#include "common/compiler.h"
#include "common/errors.h"
#include "common/limits.h"

#define GDSD_MAX_VALUE 1024
#define GDSD_MAX_KC 8          /* keycred_service lines */
#define GDSD_MAX_KC_PROFILES 8 /* ProfileUris per service */

/* One keycred_service line; the profile URIs are NUL-separated in
 * profiles, profile[i] their offsets. */
typedef struct {
    char name[65];
    char resourceUri[GDSD_MAX_VALUE];
    char profiles[GDSD_MAX_VALUE];
    uint16_t profile[GDSD_MAX_KC_PROFILES];
    uint8_t nProfiles;
} gdsd_keycred;

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
    char signerSocket[GDS_MAX_PATH];
    char caPassphraseFile[GDS_MAX_PATH];
    uint16_t port;
    bool loopbackOnly;
    uint8_t approval; /* GDSD_APPROVE_* */
    gdsd_keycred keycred[GDSD_MAX_KC];
    uint8_t nKeycred;
} gdsd_config;

/* The values of gds_approval_policy (gds_server.h). */
#define GDSD_APPROVE_AUTO 1
#define GDSD_APPROVE_RENEWALS 2
#define GDSD_APPROVE_MANUAL 3

/* Parse a configuration text (len bytes, need not be NUL-terminated). On
 * error, *errLine is the 1-based line at fault. */
GDS_MUST_CHECK gds_status gdsd_config_parse(const char *text, size_t len, gdsd_config *out,
                                            unsigned *errLine);
GDS_MUST_CHECK gds_status gdsd_config_load(const char *path, gdsd_config *out,
                                           unsigned *errLine);

#endif
