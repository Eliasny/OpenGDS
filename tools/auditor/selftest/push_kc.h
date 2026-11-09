/* OpenGDS Auditor self-test target: KeyCredential push (OPC 10000-12 §8.6)
 * in push_test_server, checked by the SRV-KC tests (srv_keycred.c).
 * SPDX-License-Identifier: MPL-2.0 */
#ifndef GDSAUDIT_PUSH_KC_H
#define GDSAUDIT_PUSH_KC_H

#include <open62541/server.h>

#include "push_mgmt.h"
#include "push_setup.h"

/* CreateCredential on the KeyCredentialConfiguration Object and the
 * methods of KeyCredentialConfigurationType. Call after pm_install. */
UA_StatusCode pk_install(UA_Server *server, ps_admin_fn isAdmin, pm_mode_fn modeOf);
void pk_clear(void);

#endif
