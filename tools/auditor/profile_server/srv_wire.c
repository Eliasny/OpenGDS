/* OpenGDS Auditor server profile: on the wire (srv_wire.c).
 * ConformanceUnit: Push Model for Global Certificate and TrustList Management.
 * Catalogue: docs/auditor/server-profile.md, "On the wire".
 * SPDX-License-Identifier: MPL-2.0 */
#include <string.h>

#include <open62541/client_config_default.h>

#include "srv_target.h"
#include "srv_tests.h"
#include "common/banned.h"

static bool client_has_policy(UA_Client *c, const UA_String *uri) {
    const UA_ClientConfig *cfg = UA_Client_getConfig(c);
    for(size_t i = 0; i < cfg->securityPoliciesSize; i++)
        if(UA_String_equal(&cfg->securityPolicies[i].policyUri, uri))
            return true;
    return false;
}

typedef struct {
    size_t checked, stale, noChannel, other;
    char first[160];
} wire_tally;

static void first_problem(wire_tally *w, const char *pol, const char *mode, const char *what,
                          UA_StatusCode r) {
    if(w->first[0])
        return;
    if(gds_path(w->first, sizeof(w->first), "%s %s: %s%s%s", pol, mode, what,
                r != UA_STATUSCODE_GOOD ? " -> " : "",
                r != UA_STATUSCODE_GOOD ? UA_StatusCode_name(r) : "") != GDS_OK)
        w->first[0] = '\0';
}

/* One endpoint: GetEndpoints view, then a SecureChannel trusting only ca. */
static void check_endpoint(ga_ctx *ctx, const srv_target *t, const UA_EndpointDescription *e,
                           wire_tally *w) {
    UA_NodeId type = st_policy_cert_type(&e->securityPolicyUri);
    char pol[96];
    if(gds_path(pol, sizeof(pol), "%s", st_short_policy(&e->securityPolicyUri)) != GDS_OK)
        pol[0] = '\0';
    const char *mode = e->securityMode == UA_MESSAGESECURITYMODE_SIGN ? "Sign" : "SignAndEncrypt";
    if(!UA_NodeId_equal(&type, &t->certType)) {
        ga_note(ctx, "%s %s: another CertificateType, not checked", pol, mode);
        w->other++;
        return;
    }
    w->checked++;
    UA_ByteString good = {t->tGood.len, t->tGood.data};
    if(!UA_ByteString_equal(&e->serverCertificate, &good)) {
        w->stale++;
        first_problem(w, pol, mode, "GetEndpoints advertises another certificate",
                      UA_STATUSCODE_GOOD);
        return;
    }
    char polUri[256];
    if(e->securityPolicyUri.length >= sizeof(polUri))
        return;
    memcpy(polUri, e->securityPolicyUri.data, e->securityPolicyUri.length);
    polUri[e->securityPolicyUri.length] = '\0';
    UA_Client *c = st_new_client(t, ST_ADMIN, false, polUri, e->securityMode);
    if(!c) {
        w->noChannel++;
        first_problem(w, pol, mode, "no client", UA_STATUSCODE_BADOUTOFMEMORY);
        return;
    }
    if(!client_has_policy(c, &e->securityPolicyUri)) {
        ga_note(ctx, "%s %s: the Auditor has no such policy; GetEndpoints only", pol, mode);
        st_client_free(c);
        return;
    }
    UA_StatusCode r = UA_Client_connectSecureChannel(c, t->url);
    st_client_free(c);
    if(r != UA_STATUSCODE_GOOD) {
        w->noChannel++;
        first_problem(w, pol, mode, "OpenSecureChannel trusting only the test CA", r);
    }
}

/* SRV-WIRE-01 (12 §7.10.9, §7.8.4.8, §7.8.4.9): after SRV-TXN-03, every
 * endpoint whose SecurityPolicy uses the updated CertificateType advertises
 * t-good in GetEndpoints, and a SecureChannel opens on it with a client that
 * trusts only the test CA. Endpoints of other CertificateTypes use another
 * slot of the group and are listed as evidence. */
static void t_wire_new_cert(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    if(!t->applied) {
        ga_not_tested(ctx, "builds on SRV-TXN-03 (t-good applied)");
        return;
    }
    UA_EndpointDescription *eps = NULL;
    size_t n = 0;
    UA_StatusCode r = st_endpoints(t, &eps, &n);
    if(r != UA_STATUSCODE_GOOD) {
        ga_fail(ctx, "GetEndpoints -> %s", UA_StatusCode_name(r));
        return;
    }
    wire_tally w;
    memset(&w, 0, sizeof(w));
    for(size_t i = 0; i < n; i++)
        if(eps[i].securityMode == UA_MESSAGESECURITYMODE_SIGN ||
           eps[i].securityMode == UA_MESSAGESECURITYMODE_SIGNANDENCRYPT)
            check_endpoint(ctx, t, &eps[i], &w);
    UA_Array_delete(eps, n, &UA_TYPES[UA_TYPES_ENDPOINTDESCRIPTION]);
    if(w.checked == 0)
        ga_fail(ctx, "no endpoint uses the updated CertificateType (%zu of other types)", w.other);
    else if(w.stale || w.noChannel)
        ga_fail(ctx, "%zu of %zu endpoint(s) still on the old certificate, %zu without a channel; %s",
                w.stale, w.checked, w.noChannel, w.first);
    else
        ga_pass(ctx, "all %zu endpoint(s) of the updated CertificateType present t-good", w.checked);
}

const ga_test srv_wire_tests[] = {
    {"SRV-WIRE-01", "12 §7.10.9, §7.8.4.8, §7.8.4.9",
     "Every endpoint of the updated CertificateType presents the new certificate", true, false,
     t_wire_new_cert},
};
const size_t srv_wire_count = GDS_ARRAY_SIZE(srv_wire_tests);
