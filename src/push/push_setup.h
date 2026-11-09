/* OpenGDS push engine - application setup with PushManagement (OPC 10000-12
 * v1.05.07 Annex G.2; OpenGDS plan W3, push_setup.c).
 * SPDX-License-Identifier: MPL-2.0
 *
 * A new device starts in the application setup state: ServerStatus.State is
 * NoConfiguration and ServerConfiguration.InApplicationSetup is TRUE (Annex
 * G.2; §7.10.3). push_setup_run takes it out of that state:
 *
 *   1. Connect with the setup credentials the device accepts (§7.5: "the
 *      Server should allow any Client that provides the proper
 *      SecurityAdmin credentials"). The device is trusted only through the
 *      certificate the installer registered for it beforehand (Annex G.2,
 *      last paragraph: the CertificateManager checks the device is one of
 *      the pre-authorized devices); no trust on first use. Check the state:
 *      State NoConfiguration, confirmed by InApplicationSetup TRUE (Annex
 *      G.2, "it is good practice for a Client to always check the
 *      ServerState after creating a Session").
 *   2. Register the device with the GDS from the ApplicationDescription it
 *      gives, and get its trust list (the enroll callback). Registration
 *      comes before the certificate because StartSigningRequest names the
 *      ApplicationId (§7.9.3) and the GDS builds the certificate from the
 *      registered record (decision G5).
 *   3. Push the trust list and the certificate, then ApplyChanges
 *      (push_run, §7.7.2).
 *   4. Connect again, now trusting the device through the GDS CA, and
 *      configure the SecurityAdmin Role: add our ApplicationUri
 *      (OPC 10000-18 §4.4.3 Application rule, AddIdentity §4.4.5) and remove
 *      an Anonymous rule if the device had one (Annex G.2 workflow: "Add
 *      Client ApplicationUri to SecurityAdmin Role, remove Anonymous from
 *      SecurityAdmin Role"). Annex G.2: "During the setup state the Client
 *      shall configure the SecurityAdmin Role. If the Client fails to do this
 *      Server shall stay in application setup state."
 *   5. Connect a third time with only our ApplicationInstance Certificate
 *      (Annex G.3) and check the device left the setup state: State Running,
 *      InApplicationSetup FALSE.
 *
 * Each connection may run over Reverse Connect (gdsc_session_cfg
 * reversePort), for a device behind a firewall. */
#ifndef OPENGDS_PUSH_SETUP_H
#define OPENGDS_PUSH_SETUP_H

#include <open62541/client.h>
#include <open62541/types_gds_generated.h>

#include <stdbool.h>

#include "client/gdsc_session.h"
#include "common/buf.h"
#include "common/compiler.h"
#include "push/push_workflows.h"

/* What a device says about its setup state */
typedef struct {
    UA_ServerState state;   /* ServerStatus.State */
    bool hasInSetup;        /* ServerConfiguration.InApplicationSetup exists */
    bool inSetup;           /* its value */
} push_setup_state;

/* State NoConfiguration confirmed by InApplicationSetup TRUE (Annex G.2) */
bool push_setup_in_setup(const push_setup_state *st);

/* Read ServerStatus.State and ServerConfiguration.InApplicationSetup on an
 * open session. An absent InApplicationSetup is not an error (the Property is
 * Optional, §7.10.3): hasInSetup is false. */
GDS_MUST_CHECK UA_StatusCode push_setup_probe(UA_Client *c, push_setup_state *out);

/* The SecurityAdmin Role's Identities (OPC 10000-18 §4.4.1), at most
 * PUSH_SETUP_MAX_RULES. *rules: UA_Array_delete with
 * UA_TYPES_IDENTITYMAPPINGRULETYPE. */
#define PUSH_SETUP_MAX_RULES 64
GDS_MUST_CHECK UA_StatusCode push_setup_admin_identities(UA_Client *c,
                                                         UA_IdentityMappingRuleType **rules,
                                                         size_t *n);

/* AddIdentity on the SecurityAdmin Role with an Application rule for
 * applicationUri (OPC 10000-18 §4.4.3, §4.4.5). Bad_AlreadyExists counts as
 * added: the rule is there. */
GDS_MUST_CHECK UA_StatusCode push_setup_add_admin(UA_Client *c, const char *applicationUri);

/* Remove every Anonymous rule from the SecurityAdmin Role (OPC 10000-18
 * §4.4.6 RemoveIdentity). *removed: how many there were. */
GDS_MUST_CHECK UA_StatusCode push_setup_remove_anonymous(UA_Client *c, size_t *removed);

/* Register the device with the GDS and return the trust list to push.
 * server: what the device says about itself on the setup session;
 * endpointUrl: where the setup session connected (NULL over Reverse
 * Connect); serverCert: the certificate it presented. The callback keeps
 * whatever the sign callback needs (the ApplicationId). */
typedef gds_status (*push_enroll_fn)(void *ctx, const UA_ApplicationDescription *server,
                                     const char *endpointUrl, const UA_ByteString *serverCert,
                                     UA_TrustListDataType *tlOut);

typedef struct {
    /* The connection: endpointUrl or Reverse Connect, our certificate and
     * key, timeouts. Its trust, identity and serverUri fields are ignored. */
    gdsc_session_cfg conn;
    const char *serverUri;    /* the device's ApplicationUri, as registered (required) */
    const gds_buf *deviceCert; /* the pre-authorized device certificate (DER, required) */
    /* The GDS CA chain the pushed certificate comes from (at most
     * GDS_MAX_CHAIN_LEN). Step 1 also trusts it, so that a device that
     * already has a certificate from the GDS is found configured. */
    const gds_buf *trust;
    size_t trustN;
    const gds_buf *crls;
    size_t crlN;
    /* The setup credentials the device maps to SecurityAdmin while in setup:
     * a user (GDSC_IDENTITY_USERNAME) or our certificate (APP_CERT, for a
     * device that gives SecurityAdmin to any secure Client in setup) */
    gdsc_identity setupIdentity;
    const char *setupUser;
    const gds_buf *setupPassword;
    /* Added to the SecurityAdmin Role; NULL = the SAN URI of conn.cert */
    const char *adminUri;
    push_enroll_fn enroll;
    void *enrollCtx;
    push_sign_fn sign;
    void *signCtx;
    UA_NodeId certificateGroup; /* e.g. GDSC_DEFAULT_APP_GROUP */
    UA_NodeId trustListNode;
    UA_NodeId certificateType;
    /* How long to keep reconnecting after ApplyChanges; 0 = 30 s */
    UA_UInt32 settleMs;
} push_setup_job;

typedef enum {
    PUSH_SETUP_STEP_NONE = 0,
    PUSH_SETUP_STEP_CONNECT,  /* the setup session */
    PUSH_SETUP_STEP_STATE,    /* not in the application setup state */
    PUSH_SETUP_STEP_ENROLL,   /* registration with the GDS */
    PUSH_SETUP_STEP_PUSH,     /* see report.push */
    PUSH_SETUP_STEP_RECONNECT, /* the session trusting the GDS CA */
    PUSH_SETUP_STEP_ROLE,     /* AddIdentity / RemoveIdentity */
    PUSH_SETUP_STEP_VERIFY    /* still in setup, or our certificate is not SecurityAdmin */
} push_setup_step;

typedef struct {
    push_setup_step failedStep;
    UA_StatusCode failedCode; /* Good when the failure was local (see the gds_status) */
    push_setup_state before;  /* step 1 */
    push_setup_state after;   /* step 5 */
    push_report push;         /* step 3; push_setup_report_clear frees it */
    bool adminAdded;
    size_t anonymousRemoved;
    bool done;                /* the device left the setup state */
} push_setup_report;

void push_setup_report_clear(push_setup_report *r);
const char *push_setup_step_name(push_setup_step s);

/* GDS_OK when the device is set up and out of the setup state. GDS_EREMOTE
 * when the device refused a step or is not in the setup state
 * (failedStep, failedCode); other codes for local failures. */
GDS_MUST_CHECK gds_status push_setup_run(const push_setup_job *job, push_setup_report *rep);

#endif
