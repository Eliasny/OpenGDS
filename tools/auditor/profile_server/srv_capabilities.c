/* OpenGDS Auditor server profile: capabilities (srv_capabilities.c).
 * ConformanceUnit: Push Model for Global Certificate and TrustList Management
 * (SRV-CAP-08: Server PushManagement Transactions).
 * Catalogue: docs/auditor/server-profile.md, "Capabilities".
 *
 * The read-only tests use the admin session. The tests that write (CAP-06,
 * CAP-07, CAP-09) use their own admin session and close it afterwards, so a
 * change accepted by mistake is cancelled (CancelChanges) or discarded with
 * the session (12 §7.10.2); the restore step covers the rest.
 * SPDX-License-Identifier: MPL-2.0 */
#include <open62541/client_highlevel.h>

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "srv_target.h"
#include "srv_tests.h"
#include "common/banned.h"

#define MAX_GROUPS 16
#define MAX_TYPES 16
#define MAX_DEPTH 8
#define LIST_LEN 384
/* Big-list filler certificates: nsComment padding range (bytes). Inside it a
 * certificate grows by exactly one byte per padding byte (all DER lengths
 * around the padding stay in the two-byte form). */
#define PAD_MIN 300
#define PAD_MAX ST_MAX_CERT_PAD
#define FILLER_TARGET 4000

static UA_NodeId ns0(UA_UInt32 id) {
    return UA_NODEID_NUMERIC(0, id);
}

/* Append ", item" (quoted if asked) to a bounded list. */
static void list_add(char *list, size_t len, const char *item, size_t itemLen, bool quote) {
    size_t off = strlen(list);
    if(off < len)
        (void)snprintf(list + off, len - off, quote ? "%s\"%.*s\"" : "%s%.*s", off ? ", " : "",
                       (int)(itemLen < 64 ? itemLen : 64), item);
}

static bool admin_or_not_tested(ga_ctx *ctx, srv_target *t) {
    UA_StatusCode r = st_admin(t);
    if(r != UA_STATUSCODE_GOOD)
        ga_not_tested(ctx, "setup: admin session -> %s", UA_StatusCode_name(r));
    return r == UA_STATUSCODE_GOOD;
}

/* ---------------- SRV-CAP-01 ---------------- */

static const char *const mandatoryMembers[] = {
    "ServerCapabilities", "SupportedPrivateKeyFormats", "MaxTrustListSize",
    "MulticastDnsEnabled", "UpdateCertificate",          "ApplyChanges",
    "CreateSigningRequest", "GetRejectedList",           "CertificateGroups"};

static void t_cap_members(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    if(!admin_or_not_tested(ctx, t))
        return;
    char missing[LIST_LEN] = "";
    size_t n = 0;
    for(size_t i = 0; i < GDS_ARRAY_SIZE(mandatoryMembers); i++) {
        UA_NodeId m;
        UA_StatusCode r =
            uac_find_child(t->client, ns0(UA_NS0ID_SERVERCONFIGURATION), mandatoryMembers[i], &m);
        UA_NodeId_clear(&m);
        if(r != UA_STATUSCODE_GOOD) {
            list_add(missing, sizeof(missing), mandatoryMembers[i], strlen(mandatoryMembers[i]),
                     false);
            ga_note(ctx, "ServerConfiguration/%s -> %s", mandatoryMembers[i],
                    UA_StatusCode_name(r));
            n++;
        }
    }
    if(n)
        ga_fail(ctx, "%zu Mandatory member(s) of ServerConfiguration missing: %s", n, missing);
    else
        ga_pass(ctx, "all %zu Mandatory members present",
                (size_t)GDS_ARRAY_SIZE(mandatoryMembers));
}

/* ---------------- CertificateGroups ---------------- */

typedef struct {
    UA_NodeId id[MAX_GROUPS];
    char name[MAX_GROUPS][64];
    size_t n;
} groups;

static void groups_clear(groups *g) {
    for(size_t i = 0; i < g->n; i++)
        UA_NodeId_clear(&g->id[i]);
    g->n = 0;
}

static UA_StatusCode browse_one(UA_Client *c, const UA_NodeId *node, UA_BrowseDirection dir,
                                UA_UInt32 refType, UA_UInt32 classMask,
                                UA_BrowseResponse *resp) {
    UA_BrowseDescription bd;
    UA_BrowseDescription_init(&bd);
    bd.nodeId = *node;
    bd.browseDirection = dir;
    bd.referenceTypeId = ns0(refType);
    bd.includeSubtypes = true;
    bd.nodeClassMask = classMask;
    bd.resultMask = UA_BROWSERESULTMASK_ALL;
    UA_BrowseRequest req;
    UA_BrowseRequest_init(&req);
    req.nodesToBrowse = &bd;
    req.nodesToBrowseSize = 1;
    *resp = UA_Client_Service_browse(c, req);
    UA_StatusCode r = resp->responseHeader.serviceResult;
    if(r == UA_STATUSCODE_GOOD && resp->resultsSize != 1)
        r = UA_STATUSCODE_BADUNEXPECTEDERROR;
    if(r == UA_STATUSCODE_GOOD)
        r = resp->results[0].statusCode;
    return r;
}

/* The CertificateGroup Objects in ServerConfiguration/CertificateGroups:
 * typed CertificateGroupType, or any Object child with a TrustList. */
static UA_StatusCode find_groups(UA_Client *c, groups *g) {
    g->n = 0;
    UA_NodeId folder;
    UA_StatusCode r =
        uac_find_child(c, ns0(UA_NS0ID_SERVERCONFIGURATION), "CertificateGroups", &folder);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    UA_BrowseResponse resp;
    r = browse_one(c, &folder, UA_BROWSEDIRECTION_FORWARD, UA_NS0ID_HIERARCHICALREFERENCES,
                   UA_NODECLASS_OBJECT, &resp);
    const UA_NodeId groupType = ns0(UA_NS0ID_CERTIFICATEGROUPTYPE);
    for(size_t i = 0; r == UA_STATUSCODE_GOOD && i < resp.results[0].referencesSize; i++) {
        const UA_ReferenceDescription *rd = &resp.results[0].references[i];
        if(g->n >= MAX_GROUPS || rd->nodeId.serverIndex != 0)
            continue;
        bool isGroup = UA_NodeId_equal(&rd->typeDefinition.nodeId, &groupType);
        if(!isGroup) {
            UA_NodeId tl;
            isGroup = uac_find_child(c, rd->nodeId.nodeId, "TrustList", &tl) == UA_STATUSCODE_GOOD;
            UA_NodeId_clear(&tl);
        }
        if(!isGroup || UA_NodeId_copy(&rd->nodeId.nodeId, &g->id[g->n]) != UA_STATUSCODE_GOOD)
            continue;
        const UA_String *bn = &rd->browseName.name;
        int len = bn->length < sizeof(g->name[0]) ? (int)bn->length : (int)sizeof(g->name[0]) - 1;
        (void)snprintf(g->name[g->n], sizeof(g->name[0]), "%.*s", len, (const char *)bn->data);
        g->n++;
    }
    UA_BrowseResponse_clear(&resp);
    UA_NodeId_clear(&folder);
    return r;
}

/* ---------------- SRV-CAP-02 ---------------- */

static void t_cap_default_group(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    if(!admin_or_not_tested(ctx, t))
        return;
    UA_NodeId folder, dag;
    UA_NodeId_init(&dag);
    UA_StatusCode r =
        uac_find_child(t->client, ns0(UA_NS0ID_SERVERCONFIGURATION), "CertificateGroups", &folder);
    if(r == UA_STATUSCODE_GOOD)
        r = uac_find_child(t->client, folder, "DefaultApplicationGroup", &dag);
    UA_NodeId_clear(&folder);
    UA_NodeId_clear(&dag);
    if(r == UA_STATUSCODE_GOOD)
        ga_pass(ctx, "CertificateGroups/DefaultApplicationGroup exists");
    else
        ga_fail(ctx, "CertificateGroups/DefaultApplicationGroup not found: %s",
                UA_StatusCode_name(r));
}

/* ---------------- SRV-CAP-03 ---------------- */

/* The CertificateTypes of a group; an empty value counts as empty (7.8.3.1:
 * the group then only holds a TrustList). */
static UA_StatusCode read_types(UA_Client *c, const UA_NodeId *group, UA_NodeId *types,
                                size_t *n) {
    *n = 0;
    UA_NodeId prop;
    UA_StatusCode r = uac_find_child(c, *group, "CertificateTypes", &prop);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    UA_Variant v;
    UA_Variant_init(&v);
    r = UA_Client_readValueAttribute(c, prop, &v);
    UA_NodeId_clear(&prop);
    if(r == UA_STATUSCODE_GOOD && !UA_Variant_isEmpty(&v)) {
        if(!UA_Variant_hasArrayType(&v, &UA_TYPES[UA_TYPES_NODEID]))
            r = UA_STATUSCODE_BADTYPEMISMATCH;
        else if(v.arrayLength > MAX_TYPES)
            r = UA_STATUSCODE_BADTOOMANYOPERATIONS;
        for(size_t i = 0; r == UA_STATUSCODE_GOOD && i < v.arrayLength; i++) {
            r = UA_NodeId_copy(&((const UA_NodeId *)v.data)[i], &types[i]);
            if(r == UA_STATUSCODE_GOOD)
                (*n)++;
        }
    }
    UA_Variant_clear(&v);
    return r;
}

static void types_clear(UA_NodeId *types, size_t n) {
    for(size_t i = 0; i < n; i++)
        UA_NodeId_clear(&types[i]);
}

/* The supertype of a type (inverse HasSubtype). */
static UA_StatusCode supertype(UA_Client *c, const UA_NodeId *type, UA_NodeId *parent) {
    UA_NodeId_init(parent);
    UA_BrowseResponse resp;
    UA_StatusCode r = browse_one(c, type, UA_BROWSEDIRECTION_INVERSE, UA_NS0ID_HASSUBTYPE,
                                 UA_NODECLASS_OBJECTTYPE, &resp);
    if(r == UA_STATUSCODE_GOOD)
        r = resp.results[0].referencesSize == 1
                ? UA_NodeId_copy(&resp.results[0].references[0].nodeId.nodeId, parent)
                : UA_STATUSCODE_BADNOTFOUND;
    UA_BrowseResponse_clear(&resp);
    return r;
}

/* The direct subtype of CertificateType that `type` derives from (the type
 * itself if it is one). Bad_NotFound if it is not a CertificateType. */
static UA_StatusCode family(UA_Client *c, const UA_NodeId *type, UA_NodeId *fam) {
    const UA_NodeId root = ns0(UA_NS0ID_CERTIFICATETYPE);
    UA_NodeId cur;
    UA_StatusCode r = UA_NodeId_copy(type, &cur);
    for(size_t d = 0; r == UA_STATUSCODE_GOOD && d < MAX_DEPTH; d++) {
        UA_NodeId par;
        r = supertype(c, &cur, &par);
        if(r != UA_STATUSCODE_GOOD)
            break;
        if(UA_NodeId_equal(&par, &root)) {
            UA_NodeId_clear(&par);
            *fam = cur;
            return UA_STATUSCODE_GOOD;
        }
        UA_NodeId_clear(&cur);
        cur = par;
    }
    UA_NodeId_clear(&cur);
    return r == UA_STATUSCODE_GOOD ? UA_STATUSCODE_BADNOTFOUND : r;
}

static void id_text(const UA_NodeId *id, char *out, size_t len) {
    UA_String s = UA_STRING_NULL;
    if(UA_NodeId_print(id, &s) == UA_STATUSCODE_GOOD)
        (void)snprintf(out, len, "%.*s", (int)(s.length < 200 ? s.length : 200),
                       (const char *)s.data);
    else
        (void)snprintf(out, len, "?");
    UA_String_clear(&s);
}

/* One group: problems are noted; the count is returned. */
static size_t check_group(ga_ctx *ctx, UA_Client *c, const UA_NodeId *g, const char *name) {
    size_t bad = 0;
    UA_NodeId x;
    if(uac_find_child(c, *g, "TrustList", &x) != UA_STATUSCODE_GOOD) {
        ga_note(ctx, "%s: no TrustList", name);
        bad++;
    }
    UA_NodeId_clear(&x);
    UA_NodeId types[MAX_TYPES];
    size_t n = 0;
    UA_StatusCode r = read_types(c, g, types, &n);
    if(r != UA_STATUSCODE_GOOD) {
        ga_note(ctx, "%s: CertificateTypes -> %s", name, UA_StatusCode_name(r));
        bad++;
    }
    UA_NodeId first;
    UA_NodeId_init(&first);
    for(size_t i = 0; i < n; i++) {
        char tx[224];
        id_text(&types[i], tx, sizeof(tx));
        UA_NodeId fam;
        if(family(c, &types[i], &fam) != UA_STATUSCODE_GOOD) {
            ga_note(ctx, "%s: CertificateType %s is not a subtype of CertificateType", name, tx);
            bad++;
            continue;
        }
        char fx[224];
        id_text(&fam, fx, sizeof(fx));
        ga_note(ctx, "%s: %s (under %s)", name, tx, fx);
        if(UA_NodeId_isNull(&first)) {
            first = fam;
            continue;
        }
        if(!UA_NodeId_equal(&first, &fam)) {
            ga_note(ctx, "%s: %s is not under the same type as the first CertificateType", name,
                    tx);
            bad++;
        }
        UA_NodeId_clear(&fam);
    }
    UA_NodeId_clear(&first);
    types_clear(types, n);
    /* Purpose (Optional): a direct subtype of CertificateType */
    if(uac_find_child(c, *g, "Purpose", &x) == UA_STATUSCODE_GOOD) {
        UA_Variant v;
        UA_Variant_init(&v);
        UA_NodeId par;
        UA_NodeId_init(&par);
        const UA_NodeId root = ns0(UA_NS0ID_CERTIFICATETYPE);
        bool ok = UA_Client_readValueAttribute(c, x, &v) == UA_STATUSCODE_GOOD &&
                  UA_Variant_hasScalarType(&v, &UA_TYPES[UA_TYPES_NODEID]) &&
                  supertype(c, v.data, &par) == UA_STATUSCODE_GOOD &&
                  UA_NodeId_equal(&par, &root);
        if(!ok) {
            ga_note(ctx, "%s: Purpose is not a direct subtype of CertificateType", name);
            bad++;
        }
        UA_NodeId_clear(&par);
        UA_Variant_clear(&v);
    }
    UA_NodeId_clear(&x);
    return bad;
}

static void t_cap_groups(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    if(!admin_or_not_tested(ctx, t))
        return;
    groups g;
    UA_StatusCode r = find_groups(t->client, &g);
    if(r != UA_STATUSCODE_GOOD || g.n == 0) {
        groups_clear(&g);
        ga_fail(ctx, "no CertificateGroup found: %s", UA_StatusCode_name(r));
        return;
    }
    size_t bad = 0;
    for(size_t i = 0; i < g.n; i++)
        bad += check_group(ctx, t->client, &g.id[i], g.name[i]);
    size_t n = g.n;
    groups_clear(&g);
    if(bad)
        ga_fail(ctx, "%zu problem(s) in %zu CertificateGroup(s)", bad, n);
    else
        ga_pass(ctx, "%zu CertificateGroup(s): TrustList and CertificateTypes present, one "
                     "common type per group",
                n);
}

/* ---------------- SRV-CAP-04 and -05 ---------------- */

/* Annex D Table D.1 (the normative set is the ServerCapabilities.csv the
 * annex links to; Table D.1 lists the same identifiers). */
static const char *const capabilityIds[] = {"NA",  "DA",  "HD",   "AC",  "HE",  "GDS",   "LDS",
                                            "DI",  "ADI", "FDI",  "FDIC", "PLC", "S95",  "RCP",
                                            "PUB", "PSC", "ALIAS", "SKS", "REG", "DCA"};
static const char *const keyFormats[] = {"PEM", "PFX", "PKCS8"};

static bool in_set(const UA_String *s, const char *const *set, size_t n) {
    for(size_t i = 0; i < n; i++)
        if(s->length == strlen(set[i]) && memcmp(s->data, set[i], s->length) == 0)
            return true;
    return false;
}

/* Read a String[] property of ServerConfiguration and list the entries not
 * in `set`. Returns the number of such entries, or -1 if it cannot be read. */
static long unknown_strings(ga_ctx *ctx, UA_Client *c, UA_UInt32 id, const char *const *set,
                            size_t setN, char *list, size_t listLen, size_t *total) {
    *total = 0;
    UA_Variant v;
    UA_Variant_init(&v);
    UA_StatusCode r = UA_Client_readValueAttribute(c, ns0(id), &v);
    long bad = -1;
    if(r != UA_STATUSCODE_GOOD)
        ga_note(ctx, "Read -> %s", UA_StatusCode_name(r));
    else if(!UA_Variant_isEmpty(&v) && !UA_Variant_hasArrayType(&v, &UA_TYPES[UA_TYPES_STRING]))
        ga_note(ctx, "the value is not a String[]");
    else {
        bad = 0;
        const UA_String *s = v.data;
        size_t n = UA_Variant_isEmpty(&v) ? 0 : v.arrayLength;
        *total = n;
        for(size_t i = 0; i < n; i++) {
            if(in_set(&s[i], set, setN))
                continue;
            bad++;
            list_add(list, listLen, (const char *)s[i].data, s[i].length, true);
        }
    }
    UA_Variant_clear(&v);
    return bad;
}

static void t_cap_capabilities(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    if(!admin_or_not_tested(ctx, t))
        return;
    char list[LIST_LEN] = "";
    size_t n = 0;
    long bad = unknown_strings(ctx, t->client, UA_NS0ID_SERVERCONFIGURATION_SERVERCAPABILITIES,
                               capabilityIds, GDS_ARRAY_SIZE(capabilityIds), list, sizeof(list),
                               &n);
    if(bad < 0)
        ga_warn(ctx, "ServerCapabilities cannot be read as a String[]");
    else if(bad)
        ga_warn(ctx, "%ld of %zu ServerCapabilities not in Annex D: %s", bad, n, list);
    else
        ga_pass(ctx, "%zu ServerCapabilities, all from Annex D", n);
}

static void t_cap_key_formats(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    if(!admin_or_not_tested(ctx, t))
        return;
    char list[LIST_LEN] = "";
    size_t n = 0;
    long bad = unknown_strings(ctx, t->client,
                               UA_NS0ID_SERVERCONFIGURATION_SUPPORTEDPRIVATEKEYFORMATS, keyFormats,
                               GDS_ARRAY_SIZE(keyFormats), list, sizeof(list), &n);
    if(bad < 0)
        ga_fail(ctx, "SupportedPrivateKeyFormats cannot be read as a String[]");
    else if(bad)
        ga_fail(ctx, "SupportedPrivateKeyFormats has a value other than PEM, PFX, PKCS8: %s",
                list);
    else
        ga_pass(ctx, "SupportedPrivateKeyFormats: %zu value(s), all PEM, PFX or PKCS8", n);
}

/* ---------------- SRV-CAP-06 ---------------- */

static void t_cap_key_unadvertised(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    if(!admin_or_not_tested(ctx, t))
        return;
    char list[LIST_LEN] = "";
    size_t n = 0;
    long bad = unknown_strings(ctx, t->client,
                               UA_NS0ID_SERVERCONFIGURATION_SUPPORTEDPRIVATEKEYFORMATS, keyFormats,
                               GDS_ARRAY_SIZE(keyFormats), list, sizeof(list), &n);
    if(bad < 0) {
        ga_not_tested(ctx, "SupportedPrivateKeyFormats cannot be read");
        return;
    }
    if(n) {
        ga_not_supported(ctx, "SupportedPrivateKeyFormats is not empty (SRV-UPD-09 covers it)");
        return;
    }
    UA_StatusCode r = st_snapshot(t, ctx);
    if(r == UA_STATUSCODE_GOOD)
        r = st_learn(t, ctx);
    if(r != UA_STATUSCODE_GOOD) {
        ga_not_tested(ctx, "setup: snapshot -> %s", UA_StatusCode_name(r));
        return;
    }
    gds_buf cert, pem;
    gds_status gs = st_withkey(t, &cert, &pem);
    if(gs != GDS_OK) {
        ga_not_tested(ctx, "setup: t-withkey -> %s", gds_status_name(gs));
        return;
    }
    UA_Client *c = NULL;
    r = st_admin_fresh(t, true, &c);
    bool acr = false;
    if(r == UA_STATUSCODE_GOOD) {
        r = st_update_cert_key(t, c, &cert, &t->caDer, 1, "PEM", &pem, &acr);
        st_discard(c);
    } else {
        ga_not_tested(ctx, "setup: second admin session -> %s", UA_StatusCode_name(r));
        gds_buf_free(&cert);
        gds_buf_free_secret(&pem);
        return;
    }
    gds_buf_free(&cert);
    gds_buf_free_secret(&pem);
    if(r == UA_STATUSCODE_BADNOTSUPPORTED)
        ga_pass(ctx, "UpdateCertificate with a PEM private key -> Bad_NotSupported");
    else if(r == UA_STATUSCODE_GOOD)
        ga_fail(ctx, "UpdateCertificate accepted a private key although "
                     "SupportedPrivateKeyFormats is empty");
    else
        ga_warn(ctx, "UpdateCertificate with a private key refused with %s, not Bad_NotSupported",
                UA_StatusCode_name(r));
}

/* ---------------- SRV-CAP-07 ---------------- */

static gds_status filler(const testca_t *ca, EVP_PKEY *key, unsigned idx, size_t pad,
                         gds_buf *out) {
    char cn[64];
    (void)snprintf(cn, sizeof(cn), "%s big list %u", TESTCA_ORG, idx);
    return st_make_cert(ca, key, cn, -3600, 86400L, false, pad, out);
}

/* A filler of exactly `want` bytes (base: the size at PAD_MIN). */
static gds_status filler_sized(const testca_t *ca, EVP_PKEY *key, unsigned idx, size_t base,
                               size_t want, gds_buf *out) {
    size_t pad = PAD_MIN + (want > base ? want - base : 0);
    gds_status s = GDS_ECRYPTO;
    for(int tries = 0; tries < 3 && pad >= PAD_MIN && pad <= PAD_MAX; tries++) {
        s = filler(ca, key, idx, pad, out);
        if(s != GDS_OK || out->len == want)
            return s;
        size_t got = out->len;
        gds_buf_free(out);
        pad = pad + want - got; /* unsigned wrap is caught by the range check */
        s = GDS_ECRYPTO;
    }
    return s;
}

/* The big list: the snapshot plus filler certificates in TrustedCertificates,
 * encoded one byte larger than max. If that size cannot be hit exactly the
 * list is the smallest one above max the fillers allow. */
static gds_status big_list(const srv_target *t, size_t max, UA_TrustListDataType *tl) {
    UA_TrustListDataType_init(tl);
    if(UA_TrustListDataType_copy(&t->snap, tl) != UA_STATUSCODE_GOOD)
        return GDS_ENOMEM;
    tl->specifiedLists = ST_MASK_ALL;
    size_t have = UA_calcSizeBinary(tl, &UA_TYPES[UA_TYPES_TRUSTLISTDATATYPE], NULL);
    EVP_PKEY *key = EVP_RSA_gen(2048);
    gds_buf b = {NULL, 0};
    gds_status s = key ? filler(&t->ca, key, 0, PAD_MIN, &b) : GDS_ECRYPTO;
    size_t base = b.len;
    gds_buf_free(&b);
    size_t need = max + 1 > have ? max + 1 - have : 0;     /* bytes still to add */
    size_t n = (need + FILLER_TARGET + 3) / (FILLER_TARGET + 4); /* 4: length prefix */
    if(n == 0 || need / n < base + 4)
        n = 1;
    for(size_t i = 0; s == GDS_OK && i < n; i++) {
        size_t share = need / n + (i < need % n ? 1 : 0);
        size_t want = share > base + 4 ? share - 4 : base;
        s = filler_sized(&t->ca, key, (unsigned)i + 1, base, want, &b);
        if(s == GDS_OK) {
            UA_ByteString bs = {b.len, b.data};
            if(UA_Array_appendCopy((void **)&tl->trustedCertificates,
                                   &tl->trustedCertificatesSize, &bs,
                                   &UA_TYPES[UA_TYPES_BYTESTRING]) != UA_STATUSCODE_GOOD)
                s = GDS_ENOMEM;
            gds_buf_free(&b);
        }
    }
    EVP_PKEY_free(key);
    ERR_clear_error();
    if(s != GDS_OK)
        UA_TrustListDataType_clear(tl);
    return s;
}

static void t_cap_max_size(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    if(!admin_or_not_tested(ctx, t))
        return;
    UA_Variant v;
    UA_Variant_init(&v);
    UA_StatusCode r = UA_Client_readValueAttribute(
        t->client, ns0(UA_NS0ID_SERVERCONFIGURATION_MAXTRUSTLISTSIZE), &v);
    if(r != UA_STATUSCODE_GOOD || !UA_Variant_hasScalarType(&v, &UA_TYPES[UA_TYPES_UINT32])) {
        UA_Variant_clear(&v);
        ga_not_tested(ctx, "MaxTrustListSize cannot be read as a UInt32: %s",
                      UA_StatusCode_name(r));
        return;
    }
    size_t max = *(UA_UInt32 *)v.data;
    UA_Variant_clear(&v);
    if(max == 0) {
        ga_not_supported(ctx, "MaxTrustListSize is 0 (no limit)");
        return;
    }
    if(max >= GDS_MAX_TRUSTLIST_SIZE) {
        ga_not_tested(ctx, "MaxTrustListSize %zu is above the %zu bytes the Auditor builds", max,
                      (size_t)GDS_MAX_TRUSTLIST_SIZE);
        return;
    }
    if((r = st_snapshot(t, ctx)) != UA_STATUSCODE_GOOD) {
        ga_not_tested(ctx, "setup: snapshot -> %s", UA_StatusCode_name(r));
        return;
    }
    UA_TrustListDataType big;
    gds_status gs = big_list(t, max, &big);
    if(gs != GDS_OK) {
        ga_not_tested(ctx, "setup: building the big list -> %s", gds_status_name(gs));
        return;
    }
    size_t size = UA_calcSizeBinary(&big, &UA_TYPES[UA_TYPES_TRUSTLISTDATATYPE], NULL);
    ga_note(ctx, "MaxTrustListSize %zu; big list %zu bytes (%zu trusted certificates)", max, size,
            big.trustedCertificatesSize);
    UA_Client *c = NULL;
    UA_TrustListDataType before, after;
    UA_TrustListDataType_init(&before);
    UA_TrustListDataType_init(&after);
    r = st_admin_fresh(t, true, &c);
    if(r == UA_STATUSCODE_GOOD)
        r = st_read_trustlist(c, ST_MASK_ALL, &before);
    if(r != UA_STATUSCODE_GOOD) {
        if(c)
            st_client_free(c);
        UA_TrustListDataType_clear(&big);
        ga_not_tested(ctx, "setup: reading the trust list -> %s", UA_StatusCode_name(r));
        return;
    }
    bool acr = false;
    UA_StatusCode w = st_write_trustlist(c, &big, 4096, &acr, ctx);
    UA_TrustListDataType_clear(&big);
    if(w == UA_STATUSCODE_GOOD)
        ga_note(ctx, "CloseAndUpdate -> Good, ApplyChangesRequired %s", acr ? "TRUE" : "FALSE");
    r = st_read_trustlist(c, ST_MASK_ALL, &after);
    st_discard(c);
    char why[160] = "";
    bool same = r == UA_STATUSCODE_GOOD && st_lists_equal(&before, &after, why, sizeof(why));
    if(r != UA_STATUSCODE_GOOD)
        ga_note(ctx, "read-back -> %s", UA_StatusCode_name(r));
    UA_TrustListDataType_clear(&before);
    UA_TrustListDataType_clear(&after);
    if(w == UA_STATUSCODE_GOOD)
        ga_fail(ctx, "a trust list of %zu bytes was accepted (MaxTrustListSize %zu)", size, max);
    else if(!same)
        ga_fail(ctx, "refused with %s, but the trust list changed: %s", UA_StatusCode_name(w),
                why[0] ? why : "read-back failed");
    else if(w == UA_STATUSCODE_BADREQUESTTOOLARGE)
        ga_pass(ctx, "%zu bytes refused with Bad_RequestTooLarge; trust list unchanged", size);
    else
        ga_warn(ctx, "refused with %s, not Bad_RequestTooLarge; trust list unchanged",
                UA_StatusCode_name(w));
}

/* ---------------- SRV-CAP-08 ---------------- */

static void t_cap_cancel(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    if(!admin_or_not_tested(ctx, t))
        return;
    bool present = false, txn = false;
    st_supports_transactions(t->client, &present, &txn);
    if(!present || !txn) {
        ga_not_supported(ctx, "SupportsTransactions is %s", present ? "FALSE" : "absent");
        return;
    }
    UA_NodeId m;
    UA_StatusCode r =
        uac_find_child(t->client, ns0(UA_NS0ID_SERVERCONFIGURATION), "CancelChanges", &m);
    UA_NodeId_clear(&m);
    if(r == UA_STATUSCODE_GOOD)
        ga_pass(ctx, "SupportsTransactions TRUE and CancelChanges exists");
    else
        ga_fail(ctx, "SupportsTransactions is TRUE but CancelChanges is missing: %s",
                UA_StatusCode_name(r));
}

/* ---------------- SRV-CAP-09 ---------------- */

static void t_cap_csr_types(ga_ctx *ctx, void *p) {
    srv_target *t = p;
    if(!admin_or_not_tested(ctx, t))
        return;
    groups g;
    UA_StatusCode r = find_groups(t->client, &g);
    if(r != UA_STATUSCODE_GOOD || g.n == 0) {
        groups_clear(&g);
        ga_not_tested(ctx, "no CertificateGroup found: %s", UA_StatusCode_name(r));
        return;
    }
    if((r = st_snapshot(t, ctx)) != UA_STATUSCODE_GOOD) {
        groups_clear(&g);
        ga_not_tested(ctx, "setup: snapshot -> %s", UA_StatusCode_name(r));
        return;
    }
    UA_Client *c = NULL;
    if((r = st_admin_fresh(t, true, &c)) != UA_STATUSCODE_GOOD) {
        groups_clear(&g);
        ga_not_tested(ctx, "setup: second admin session -> %s", UA_StatusCode_name(r));
        return;
    }
    size_t tried = 0, invalid = 0, other = 0;
    for(size_t i = 0; i < g.n; i++) {
        UA_NodeId types[MAX_TYPES];
        size_t n = 0;
        if(read_types(c, &g.id[i], types, &n) != UA_STATUSCODE_GOOD)
            continue; /* SRV-CAP-03 reports it */
        for(size_t k = 0; k < n; k++) {
            char tx[224];
            id_text(&types[k], tx, sizeof(tx));
            gds_buf csr = {NULL, 0};
            r = st_csr_for(c, g.id[i], types[k], false, NULL, &csr);
            gds_buf_free(&csr);
            ga_note(ctx, "%s / %s: CreateSigningRequest -> %s", g.name[i], tx,
                    UA_StatusCode_name(r));
            tried++;
            if(r == UA_STATUSCODE_BADINVALIDARGUMENT)
                invalid++;
            else if(r != UA_STATUSCODE_GOOD)
                other++;
        }
        types_clear(types, n);
    }
    st_discard(c);
    groups_clear(&g);
    if(invalid)
        ga_fail(ctx, "%zu advertised CertificateType(s) refused with Bad_InvalidArgument", invalid);
    else if(other)
        ga_warn(ctx, "%zu of %zu CreateSigningRequest calls refused", other, tried);
    else
        ga_pass(ctx, "CreateSigningRequest Good for all %zu advertised CertificateType(s)", tried);
}

const ga_test srv_capabilities_tests[] = {
    {"SRV-CAP-01", "12 §7.10.3", "ServerConfiguration has its Mandatory members", false, false,
     t_cap_members},
    {"SRV-CAP-02", "12 §7.10.3", "CertificateGroups has DefaultApplicationGroup", false, false,
     t_cap_default_group},
    {"SRV-CAP-03", "12 §7.8.3.1", "Each CertificateGroup has a TrustList and one family of types",
     false, false, t_cap_groups},
    {"SRV-CAP-04", "12 §7.10.3, Annex D", "ServerCapabilities are Annex D identifiers", false,
     false, t_cap_capabilities},
    {"SRV-CAP-05", "12 §7.10.3", "SupportedPrivateKeyFormats are PEM, PFX or PKCS8", false, false,
     t_cap_key_formats},
    {"SRV-CAP-06", "12 §7.10.3, §7.10.5",
     "No private key accepted when SupportedPrivateKeyFormats is empty", true, false,
     t_cap_key_unadvertised},
    {"SRV-CAP-07", "12 §7.10.3, §7.8.2.5", "A trust list above MaxTrustListSize is refused", true,
     false, t_cap_max_size},
    {"SRV-CAP-08", "12 §7.10.2, §7.10.3", "SupportsTransactions TRUE comes with CancelChanges",
     false, false, t_cap_cancel},
    {"SRV-CAP-09", "12 §7.10.3, §7.10.10", "CreateSigningRequest works for every advertised type",
     true, false, t_cap_csr_types},
};
const size_t srv_capabilities_count = GDS_ARRAY_SIZE(srv_capabilities_tests);
