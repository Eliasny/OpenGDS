/* OpenGDS Auditor self-test target: the PushManagement methods of
 * push_test_server (OPC 10000-12 §7.8.2 TrustListType, §7.10
 * ServerConfigurationType), written to the catalogue in
 * docs/auditor/server-profile.md. TEST TARGET, NOT A PRODUCT.
 *
 * It replaces open62541 v1.5.10's method callbacks on the
 * DefaultApplicationGroup and ServerConfiguration, because the library's
 * transaction rules differ from the spec (for example a Session cannot
 * continue its own transaction, §7.8.2.2). Applying still goes through the
 * library's public API (UA_Server_updateCertificate, the CertificateGroup
 * plugin), so pushed state is persisted by the Annex F.1 file store.
 *
 * --break mutants live here too: each one is a single deliberate fault that
 * one catalogue test must catch.
 * SPDX-License-Identifier: MPL-2.0 */
#ifndef GDSAUDIT_PUSH_MGMT_H
#define GDSAUDIT_PUSH_MGMT_H

#include <open62541/server.h>

#include <stdbool.h>

/* The SecurityMode of a Session's channel (INVALID if unknown). */
typedef UA_MessageSecurityMode (*pm_mode_fn)(const UA_NodeId *sessionId);

/* Install the methods. mutant is NULL or a name from pm_mutant_known;
 * ownKey (the server's private key, DER or PEM) is copied: CreateSigningRequest
 * signs with it and UpdateCertificate checks certificates against it. */
UA_StatusCode pm_install(UA_Server *server, const char *mutant, const UA_ByteString *ownKey,
                         pm_mode_fn modeOf);
/* Where push_mgmt keeps what a restart must not lose (<pki>/push).
 * Call before pm_install. */
void pm_store(const char *pki);
/* --accept-keys: advertise SupportedPrivateKeyFormats ["PEM"] and take a
 * pushed private key (12 §7.10.5). Call before pm_install. */
void pm_accept_keys(bool on);
/* True if mutant `name` is active (push_test_server's own mutants). */
bool pm_breaking(const char *name);
/* A Session ended: its transaction and file handles are discarded (§7.10.2). */
void pm_session_closed(const UA_NodeId *sessionId);
/* Called after a trust list is put in use (ApplyChanges, AddCertificate,
 * RemoveCertificate), with the server lock held. */
void pm_on_list_installed(void (*fn)(void));
/* Called after an ApplyChanges that applied a transaction, with the server
 * lock held. */
void pm_on_applied(void (*fn)(void));
void pm_clear(void);
/* The private key of the certificate in use (DER), for KeyCredential
 * secrets encrypted to it (push_kc.c). Borrowed. */
const UA_ByteString *pm_own_key(void);

bool pm_mutant_known(const char *name);
void pm_mutant_list(void);

#endif
