/* OpenGDS Auditor server profile: security (srv_security.c).
 * ConformanceUnit: Push Model for Global Certificate and TrustList Management.
 * Catalogue: docs/auditor/server-profile.md, "Security".
 *
 * The calls use valid arguments, so a refusal can only come from the access
 * or channel check. Anything accepted by mistake is undone: handles are
 * closed and the probing session is closed, which discards its transaction
 * (12 §7.10.2); the restore step covers the rest.
 * SPDX-License-Identifier: MPL-2.0 */
#include <open62541/client_highlevel.h>

#include <stdio.h>
#include <string.h>

#include "srv_target.h"
#include "srv_tests.h"
#include "common/banned.h"

#define SP "http://opcfoundation.org/UA/SecurityPolicy#"
#define MAX_PROBES 8

typedef enum {
    P_APPLY = 1u << 0,
    P_CANCEL = 1u << 1,
    P_REJECTED = 1u << 2,
    P_OPENMASKS = 1u << 3,
    P_OPENWRITE = 1u << 4,
    P_CSR = 1u << 5,
    P_UPDATE = 1u << 6,
} probe_set;

#define P_ALL (P_APPLY | P_CANCEL | P_REJECTED | P_OPENMASKS | P_OPENWRITE | P_CSR | P_UPDATE)

typedef struct {
    const char *name;
    UA_StatusCode r;
} probe;

typedef struct {
    probe p[MAX_PROBES];
    size_t n;
} probes;

static UA_NodeId ns0(UA_UInt32 id) {
    return UA_NODEID_NUMERIC(0, id);
}

static void add(probes *ps, const char *name, UA_StatusCode r) {
    if(ps->n < MAX_PROBES) {
        ps->p[ps->n].name = name;
        ps->p[ps->n].r = r;
        ps->n++;
    }
}

static UA_StatusCode call(UA_Client *c, UA_UInt32 obj, UA_UInt32 method, size_t inN,
                          const UA_Variant *in, UA_Variant **out, size_t *outN) {
    *out = NULL;
    *outN = 0;
    return UA_Client_call(c, ns0(obj), ns0(method), inN, in, outN, out);
}

static void free_out(UA_Variant *out, size_t n) {
    if(out)
        UA_Array_delete(out, n, &UA_TYPES[UA_TYPES_VARIANT]);
}

#define TLOBJ UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST
#define TLM(x) UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST_##x

/* An Open that returned a handle by mistake is closed again. */
static UA_StatusCode open_probe(UA_Client *c, UA_UInt32 method, const UA_Variant *arg) {
    UA_Variant *out;
    size_t outN;
    UA_StatusCode r = call(c, TLOBJ, method, 1, arg, &out, &outN);
    const UA_UInt32 *h = uac_out_scalar(out, outN, 0, &UA_TYPES[UA_TYPES_UINT32]);
    if(r == UA_STATUSCODE_GOOD && h) {
        UA_UInt32 hv = *h;
        UA_Variant cin;
        UA_Variant_setScalar(&cin, &hv, &UA_TYPES[UA_TYPES_UINT32]);
        UA_Variant *co;
        size_t coN;
        (void)call(c, TLOBJ, TLM(CLOSE), 1, &cin, &co, &coN);
        free_out(co, coN);
    }
    free_out(out, outN);
    return r;
}

static bool has_cancel(UA_Client *c) {
    UA_NodeId m;
    bool ok = uac_find_child(c, ns0(UA_NS0ID_SERVERCONFIGURATION), "CancelChanges", &m) ==
              UA_STATUSCODE_GOOD;
    UA_NodeId_clear(&m);
    return ok;
}

/* Call the methods in `which` with valid arguments; ApplyChanges first, so
 * nothing queued by a mistaken UpdateCertificate is ever applied. */
static void run_probes(const srv_target *t, UA_Client *c, unsigned which, probes *ps) {
    UA_Variant *out;
    size_t outN;
    UA_Variant in[6];
    if(which & P_APPLY) {
        add(ps, "ApplyChanges",
            call(c, UA_NS0ID_SERVERCONFIGURATION, UA_NS0ID_SERVERCONFIGURATION_APPLYCHANGES, 0,
                 NULL, &out, &outN));
        free_out(out, outN);
    }
    if((which & P_CANCEL) && has_cancel(c)) {
        add(ps, "CancelChanges",
            call(c, UA_NS0ID_SERVERCONFIGURATION, UA_NS0ID_SERVERCONFIGURATION_CANCELCHANGES, 0,
                 NULL, &out, &outN));
        free_out(out, outN);
    }
    if(which & P_REJECTED) {
        add(ps, "GetRejectedList",
            call(c, UA_NS0ID_SERVERCONFIGURATION, UA_NS0ID_SERVERCONFIGURATION_GETREJECTEDLIST, 0,
                 NULL, &out, &outN));
        free_out(out, outN);
    }
    if(which & P_OPENMASKS) {
        UA_UInt32 masks = ST_MASK_ALL;
        UA_Variant_setScalar(&in[0], &masks, &UA_TYPES[UA_TYPES_UINT32]);
        add(ps, "OpenWithMasks", open_probe(c, TLM(OPENWITHMASKS), in));
    }
    if(which & P_OPENWRITE) {
        UA_Byte mode = ST_OPEN_WRITE_ERASE;
        UA_Variant_setScalar(&in[0], &mode, &UA_TYPES[UA_TYPES_BYTE]);
        add(ps, "Open(Write|EraseExisting)", open_probe(c, TLM(OPEN), in));
    }
    UA_NodeId group = ns0(UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP);
    UA_NodeId type = UA_NodeId_isNull(&t->certType)
                         ? ns0(UA_NS0ID_RSASHA256APPLICATIONCERTIFICATETYPE)
                         : t->certType;
    if(which & P_CSR) {
        UA_String subject = UA_STRING_NULL;
        UA_Boolean regen = false;
        UA_ByteString nonce = UA_BYTESTRING_NULL;
        UA_Variant_setScalar(&in[0], &group, &UA_TYPES[UA_TYPES_NODEID]);
        UA_Variant_setScalar(&in[1], &type, &UA_TYPES[UA_TYPES_NODEID]);
        UA_Variant_setScalar(&in[2], &subject, &UA_TYPES[UA_TYPES_STRING]);
        UA_Variant_setScalar(&in[3], &regen, &UA_TYPES[UA_TYPES_BOOLEAN]);
        UA_Variant_setScalar(&in[4], &nonce, &UA_TYPES[UA_TYPES_BYTESTRING]);
        add(ps, "CreateSigningRequest",
            call(c, UA_NS0ID_SERVERCONFIGURATION,
                 UA_NS0ID_SERVERCONFIGURATION_CREATESIGNINGREQUEST, 5, in, &out, &outN));
        free_out(out, outN);
    }
    if(which & P_UPDATE) {
        /* the certificate the target already presents: valid, changes nothing */
        UA_ByteString cert = {t->pinned.len, t->pinned.data};
        UA_String fmt = UA_STRING_NULL;
        UA_ByteString key = UA_BYTESTRING_NULL;
        UA_Variant_setScalar(&in[0], &group, &UA_TYPES[UA_TYPES_NODEID]);
        UA_Variant_setScalar(&in[1], &type, &UA_TYPES[UA_TYPES_NODEID]);
        UA_Variant_setScalar(&in[2], &cert, &UA_TYPES[UA_TYPES_BYTESTRING]);
        UA_Variant_setArray(&in[3], UA_EMPTY_ARRAY_SENTINEL, 0, &UA_TYPES[UA_TYPES_BYTESTRING]);
        UA_Variant_setScalar(&in[4], &fmt, &UA_TYPES[UA_TYPES_STRING]);
        UA_Variant_setScalar(&in[5], &key, &UA_TYPES[UA_TYPES_BYTESTRING]);
        add(ps, "UpdateCertificate",
            call(c, UA_NS0ID_SERVERCONFIGURATION, UA_NS0ID_SERVERCONFIGURATION_UPDATECERTIFICATE,
                 6, in, &out, &outN));
        free_out(out, outN);
    }
}

/* The catalogue's verdict for "every call returns <want>": Fail on a Good,
 * Warn on another Bad code (README, "Bad code but the right outcome"). */
static void judge(ga_ctx *ctx, const probes *ps, UA_StatusCode want, const char *who) {
    size_t good = 0, other = 0;
    char goodList[200] = "", otherList[200] = "";
    for(size_t i = 0; i < ps->n; i++) {
        ga_note(ctx, "%s: %s -> %s", who, ps->p[i].name, UA_StatusCode_name(ps->p[i].r));
        char *l = NULL;
        size_t len = 0;
        if(ps->p[i].r == UA_STATUSCODE_GOOD) {
            good++;
            l = goodList;
            len = sizeof(goodList);
        } else if(ps->p[i].r != want) {
            other++;
            l = otherList;
            len = sizeof(otherList);
        }
        if(l) {
            size_t used = strlen(l);
            if(gds_path(l + used, len - used, "%s%s", used ? ", " : "", ps->p[i].name) != GDS_OK)
                l[used] = '\0';
        }
    }
    if(good)
        ga_fail(ctx, "%s: accepted %s", who, goodList);
    else if(other)
        ga_warn(ctx, "%s: refused, but not with %s: %s", who, UA_StatusCode_name(want), otherList);
    else
        ga_pass(ctx, "%s: all %zu calls refused with %s", who, ps->n, UA_StatusCode_name(want));
}

static bool learn(srv_target *t, ga_ctx *ctx) {
    UA_StatusCode r = st_learn(t, ctx);
    if(r != UA_STATUSCODE_GOOD)
        ga_not_tested(ctx, "setup: reading the target as SecurityAdmin -> %s", UA_StatusCode_name(r));
    return r == UA_STATUSCODE_GOOD;
}

/* SRV-SEC-01, -02: every method as anon or user over ch-enc */
static void refuse_role(ga_ctx *ctx, srv_target *t, st_role role, const char *who) {
    if(!learn(t, ctx))
        return;
    UA_Client *c = NULL;
    UA_StatusCode r = st_open(t, role, NULL, UA_MESSAGESECURITYMODE_SIGNANDENCRYPT, &c);
    if(r != UA_STATUSCODE_GOOD) {
        ga_not_tested(ctx, "%s session over SignAndEncrypt -> %s", who, UA_StatusCode_name(r));
        return;
    }
    probes ps = {0};
    run_probes(t, c, P_ALL, &ps);
    st_client_free(c);
    judge(ctx, &ps, UA_STATUSCODE_BADUSERACCESSDENIED, who);
}

static void t_sec_anon(ga_ctx *ctx, void *p) {
    refuse_role(ctx, p, ST_ANON, "anonymous");
}

static void t_sec_user(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    if(!t->userName) {
        ga_not_tested(ctx, "no user fixture given (--user)");
        return;
    }
    refuse_role(ctx, t, ST_USER, "user without SecurityAdmin");
}

/* Admin over a weaker channel: a refused session is a refused call. */
static void refuse_channel(ga_ctx *ctx, srv_target *t, const char *policy,
                           UA_MessageSecurityMode mode, unsigned which, const char *who) {
    if(!learn(t, ctx))
        return;
    UA_Client *c = NULL;
    UA_StatusCode r = st_open(t, ST_ADMIN, policy, mode, &c);
    if(r != UA_STATUSCODE_GOOD) {
        ga_pass(ctx, "no %s session is possible (%s); every call is refused", who,
                UA_StatusCode_name(r));
        return;
    }
    probes ps = {0};
    run_probes(t, c, which, &ps);
    st_client_free(c);
    judge(ctx, &ps, UA_STATUSCODE_BADSECURITYMODEINSUFFICIENT, who);
}

static void t_sec_none(ga_ctx *ctx, void *p) {
    refuse_channel(ctx, p, SP "None", UA_MESSAGESECURITYMODE_NONE, P_ALL, "admin over None");
}

static void t_sec_sign_encrypt_only(ga_ctx *ctx, void *p) {
    refuse_channel(ctx, p, NULL, UA_MESSAGESECURITYMODE_SIGN, P_CSR | P_UPDATE,
                   "admin over Sign");
}

/* SRV-SEC-05: only a Warn; ApplyChanges answering Bad_NothingToDo passed the
 * channel check, so it counts as accepted. */
static void t_sec_sign_auth_only(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    if(!learn(t, ctx))
        return;
    UA_Client *c = NULL;
    UA_StatusCode r = st_open(t, ST_ADMIN, NULL, UA_MESSAGESECURITYMODE_SIGN, &c);
    if(r != UA_STATUSCODE_GOOD) {
        ga_pass(ctx, "no admin session over Sign (%s)", UA_StatusCode_name(r));
        return;
    }
    probes ps = {0};
    run_probes(t, c, P_APPLY | P_REJECTED | P_OPENMASKS, &ps);
    st_client_free(c);
    size_t accepted = 0;
    for(size_t i = 0; i < ps.n; i++) {
        ga_note(ctx, "admin over Sign: %s -> %s", ps.p[i].name, UA_StatusCode_name(ps.p[i].r));
        if(ps.p[i].r == UA_STATUSCODE_GOOD || ps.p[i].r == UA_STATUSCODE_BADNOTHINGTODO)
            accepted++;
    }
    if(accepted)
        ga_warn(ctx, "%zu of %zu push methods accepted over Sign; §7.4 says push management "
                     "needs an encrypted channel", accepted, ps.n);
    else
        ga_pass(ctx, "all %zu refused over Sign", ps.n);
}

static const char *const diagChildren[] = {"StartTime", "EndTime", "Result",
                                           "AffectedTrustLists", "AffectedCertificateGroups",
                                           "Errors"};

/* SRV-SEC-06: TransactionDiagnostics hidden from user and anon */
static void t_sec_diag(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    UA_StatusCode r = st_admin(t);
    UA_NodeId diag = UA_NODEID_NULL;
    if(r == UA_STATUSCODE_GOOD &&
       uac_find_child(t->client, ns0(UA_NS0ID_SERVERCONFIGURATION), "TransactionDiagnostics",
                      &diag) != UA_STATUSCODE_GOOD) {
        ga_not_supported(ctx, "no TransactionDiagnostics Object");
        return;
    }
    if(r != UA_STATUSCODE_GOOD) {
        ga_not_tested(ctx, "setup: admin session -> %s", UA_StatusCode_name(r));
        return;
    }
    const st_role roles[2] = {ST_USER, ST_ANON};
    size_t readable = 0, tried = 0;
    for(size_t k = 0; k < 2; k++) {
        if(roles[k] == ST_USER && !t->userName)
            continue;
        const char *who = roles[k] == ST_USER ? "user" : "anonymous";
        UA_Client *c = NULL;
        r = st_open(t, roles[k], NULL, UA_MESSAGESECURITYMODE_SIGNANDENCRYPT, &c);
        if(r != UA_STATUSCODE_GOOD) {
            ga_note(ctx, "%s session -> %s", who, UA_StatusCode_name(r));
            continue;
        }
        tried++;
        for(size_t i = 0; i < GDS_ARRAY_SIZE(diagChildren); i++) {
            UA_NodeId v;
            if(uac_find_child(c, diag, diagChildren[i], &v) != UA_STATUSCODE_GOOD) {
                ga_note(ctx, "%s: %s not browsable", who, diagChildren[i]);
                continue;
            }
            UA_Variant val;
            UA_Variant_init(&val);
            r = UA_Client_readValueAttribute(c, v, &val);
            UA_Variant_clear(&val);
            UA_NodeId_clear(&v);
            ga_note(ctx, "%s: Read %s -> %s", who, diagChildren[i], UA_StatusCode_name(r));
            /* another code (Bad_OutOfService before any transaction, 12
             * §7.10.17) means the access check let the Read through */
            if(r != UA_STATUSCODE_BADUSERACCESSDENIED && r != UA_STATUSCODE_BADNOTREADABLE)
                readable++;
        }
        st_client_free(c);
    }
    UA_NodeId_clear(&diag);
    if(tried == 0)
        ga_not_tested(ctx, "no user or anonymous session could be opened");
    else if(readable)
        ga_fail(ctx, "%zu TransactionDiagnostics Read(s) without SecurityAdmin not refused with "
                     "Bad_UserAccessDenied or Bad_NotReadable",
                readable);
    else
        ga_pass(ctx, "TransactionDiagnostics not readable without SecurityAdmin");
}

/* SRV-SEC-07: OpenWithMasks(All) as user and anon */
static void t_sec_tl_read(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    const st_role roles[2] = {ST_USER, ST_ANON};
    size_t opened = 0, other = 0, tried = 0;
    for(size_t k = 0; k < 2; k++) {
        if(roles[k] == ST_USER && !t->userName)
            continue;
        const char *who = roles[k] == ST_USER ? "user" : "anonymous";
        UA_Client *c = NULL;
        UA_StatusCode r = st_open(t, roles[k], NULL, UA_MESSAGESECURITYMODE_SIGNANDENCRYPT, &c);
        if(r != UA_STATUSCODE_GOOD) {
            ga_note(ctx, "%s session -> %s", who, UA_StatusCode_name(r));
            continue;
        }
        tried++;
        UA_UInt32 masks = ST_MASK_ALL;
        UA_Variant in;
        UA_Variant_setScalar(&in, &masks, &UA_TYPES[UA_TYPES_UINT32]);
        r = open_probe(c, TLM(OPENWITHMASKS), &in);
        st_client_free(c);
        ga_note(ctx, "%s: OpenWithMasks(All) -> %s", who, UA_StatusCode_name(r));
        if(r == UA_STATUSCODE_GOOD)
            opened++;
        else if(r != UA_STATUSCODE_BADUSERACCESSDENIED)
            other++;
    }
    if(tried == 0)
        ga_not_tested(ctx, "no user or anonymous session could be opened");
    else if(opened)
        ga_fail(ctx, "a file handle was returned without SecurityAdmin");
    else if(other)
        ga_warn(ctx, "refused, but not with BadUserAccessDenied");
    else
        ga_pass(ctx, "OpenWithMasks refused with BadUserAccessDenied");
}

/* SRV-SEC-08: no deprecated SecurityPolicy (OPC 10000-7) */
static void t_sec_policies(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    UA_EndpointDescription *eps = NULL;
    size_t n = 0;
    UA_StatusCode r = st_endpoints(t, &eps, &n);
    if(r != UA_STATUSCODE_GOOD) {
        ga_fail(ctx, "GetEndpoints -> %s", UA_StatusCode_name(r));
        return;
    }
    const UA_String dep[2] = {UA_STRING_STATIC(SP "Basic128Rsa15"), UA_STRING_STATIC(SP "Basic256")};
    size_t deprecated = 0, encrypt = 0, encryptStrong = 0;
    for(size_t i = 0; i < n; i++) {
        bool d = UA_String_equal(&eps[i].securityPolicyUri, &dep[0]) ||
                 UA_String_equal(&eps[i].securityPolicyUri, &dep[1]);
        if(d) {
            deprecated++;
            ga_note(ctx, "deprecated: %s", st_short_policy(&eps[i].securityPolicyUri));
        }
        if(eps[i].securityMode == UA_MESSAGESECURITYMODE_SIGNANDENCRYPT) {
            encrypt++;
            encryptStrong += !d;
        }
    }
    UA_Array_delete(eps, n, &UA_TYPES[UA_TYPES_ENDPOINTDESCRIPTION]);
    if(encrypt && !encryptStrong)
        ga_fail(ctx, "SignAndEncrypt is only possible with a deprecated policy");
    else if(deprecated)
        ga_warn(ctx, "%zu endpoint(s) with a deprecated policy", deprecated);
    else
        ga_pass(ctx, "no deprecated policy among %zu endpoint(s)", n);
}

const ga_test srv_security_tests[] = {
    {"SRV-SEC-01", "12 §7.10.5, §7.10.10, §7.10.12, §7.8.2.3, §7.8.2.5",
     "An anonymous session cannot call any push method", true, false, t_sec_anon},
    {"SRV-SEC-02", "12 §7.10.5, §7.10.10, §7.10.12, §7.8.2.3, §7.8.2.5",
     "A user without SecurityAdmin cannot call any push method", true, false, t_sec_user},
    {"SRV-SEC-03", "12 §7.10.5, §7.10.9, §7.8.2.2",
     "Push methods are refused over a None channel", true, false, t_sec_none},
    {"SRV-SEC-04", "12 §7.10.5, §7.10.10, §8.6.3",
     "UpdateCertificate and CreateSigningRequest need an encrypted channel", true, false,
     t_sec_sign_encrypt_only},
    {"SRV-SEC-05", "12 §7.4, §7.10.9, §7.10.12, §7.8.2.3",
     "Push methods over a Sign-only channel (Warn only)", true, false, t_sec_sign_auth_only},
    {"SRV-SEC-06", "12 §7.10.3", "TransactionDiagnostics is not readable without SecurityAdmin",
     false, false, t_sec_diag},
    {"SRV-SEC-07", "12 §7.8.2.1, §7.8.2.3",
     "The trust list cannot be read without SecurityAdmin", false, false, t_sec_tl_read},
    {"SRV-SEC-08", "OPC 10000-7 (security policy facets)", "No deprecated SecurityPolicy",
     false, false, t_sec_policies},
};
const size_t srv_security_count = GDS_ARRAY_SIZE(srv_security_tests);
