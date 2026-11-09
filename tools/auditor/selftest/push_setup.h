/* OpenGDS Auditor self-test target: the application setup state of
 * push_test_server --setup (OPC 10000-12 §7.5, Annex G.2, §7.10.13), written
 * to the catalogue's "Push setup" group (SRV-SET-01 to -06). TEST TARGET,
 * NOT A PRODUCT.
 *
 *   - InApplicationSetup is TRUE and ServerStatus.State is NoConfiguration
 *     until the SecurityAdmin Role has an identity (Part 18 AddIdentity on
 *     WellKnownRole_SecurityAdmin). Both are kept under <pki>/push.
 *   - In setup any client application certificate opens a SecureChannel
 *     (§7.5: the Server allows any Client with SecurityAdmin credentials);
 *     only the SecurityAdmin credentials of push_test_server's --admin and
 *     --admin-cert give SecurityAdmin. After setup the trust list decides.
 *   - The SecurityAdmin identities give SecurityAdmin: UserName (user name)
 *     and Application (the ApplicationUri of the client certificate, with
 *     an Anonymous token). Other criteria are Bad_NotSupported, Anonymous
 *     and AuthenticatedUser Bad_RequestNotAllowed (OPC 10000-18 §4.4.5).
 *   - ResetToServerDefaults (SecurityAdmin, encrypted channel) sets State to
 *     Shutdown with a ShutdownReason, then wipes what was pushed and set up,
 *     and push_test_server starts again in setup (ps_reset_requested).
 * SPDX-License-Identifier: MPL-2.0 */
#ifndef GDSAUDIT_PUSH_SETUP_H
#define GDSAUDIT_PUSH_SETUP_H

#include <open62541/server.h>

#include <stdbool.h>

#include "push_mgmt.h"

/* Does the Session have SecurityAdmin? */
typedef UA_Boolean (*ps_admin_fn)(const UA_NodeId *sessionId);

/* Install the setup state (push_test_server --setup). Call after pm_install. */
UA_StatusCode ps_install(UA_Server *server, const char *pki, ps_admin_fn isAdmin,
                         pm_mode_fn modeOf);
/* Do the SecurityAdmin identities match this user name (NULL: none) or,
 * for an Anonymous token, the ApplicationUri of this client certificate
 * (NULL or empty: none)? OPC 10000-18 §4.4.3. */
bool ps_identity_admin(const UA_String *userName, bool anonymous, const UA_ByteString *clientCert);
/* ResetToServerDefaults completed: the server stopped and must start again. */
bool ps_reset_requested(void);
void ps_clear(void);

#endif
