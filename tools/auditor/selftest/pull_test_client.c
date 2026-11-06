/* OpenGDS Auditor self-test target: PULL test client
 * SPDX-License-Identifier: MPL-2.0
 *
 * A known-good OPC UA application that manages its own certificate and trust
 * list with Part 12 PullManagement against any GDS (OPC 10000-12 §6.4, §7.6,
 * Annex G.1). TEST TARGET, NOT A PRODUCT.
 *
 *   FindApplications -> RegisterApplication (first run only)
 *   GetCertificateGroups -> GetCertificateStatus
 *   StartSigningRequest (CSR from our own key) -> FinishRequest (polls while
 *   the GDS returns Bad_NothingToDo, i.e. awaiting approval)
 *   GetTrustList -> TrustList Open/Read/Close
 *
 * The result is written to a Part 12 Annex F.1 style PKI directory. The GDS
 * is trusted explicitly with --trust, never on first use (rogue GDS threat).
 *
 * Usage:
 *   pull_test_client --gds opc.tcp://localhost:4850 --pki ./pki-pull \
 *       --trust gds-ca.der [--crl gds-ca.crl] --user registrar \
 *       (--password-file FILE | --password P) [--app-uri urn:...] [--poll-seconds 60]
 */
#include <open62541/client_highlevel.h>
#include <open62541/nodeids_gds.h>
#include <open62541/plugin/create_certificate.h>
#include <open62541/plugin/log_stdout.h>
#include <open62541/types_gds_generated.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/crypto.h>

#include "common/limits.h"
#include "common/safeint.h"
#include "uaclient.h"
#include "common/banned.h"

#define GDS_NS_URI "http://opcfoundation.org/UA/GDS/"
#define MAX_TRUST 8
#define MAX_PASSWORD 256

static const char *appUri = "urn:opengds:test:pullclient";
static const char *appName = "OpenGDS Pull Test Client";

/* Register the GDS-namespace data types (ApplicationRecordDataType) */
static UA_DataTypeArray gdsTypes = {NULL, UA_TYPES_GDS_COUNT, UA_TYPES_GDS, false};

static int fail(const char *what, UA_StatusCode r) {
    fprintf(stderr, "\nFAILED: %s: %s\n", what, UA_StatusCode_name(r));
    return 1;
}

static int failg(const char *what, gds_status s) {
    fprintf(stderr, "\nFAILED: %s: %s\n", what, gds_status_name(s));
    return 1;
}

static gds_status ensureOwnIdentity(const char *pki, gds_buf *cert, gds_buf *key) {
    char cp[GDS_MAX_PATH], kp[GDS_MAX_PATH], d[GDS_MAX_PATH], sanUri[GDS_MAX_APPLICATION_URI + 8];
    gds_status r;
    if((r = gds_path(cp, sizeof(cp), "%s/own/cert.der", pki)) != GDS_OK ||
       (r = gds_path(kp, sizeof(kp), "%s/own/private/key.der", pki)) != GDS_OK ||
       (r = gds_path(d, sizeof(d), "%s/own/private", pki)) != GDS_OK ||
       (r = gds_path(sanUri, sizeof(sanUri), "URI:%s", appUri)) != GDS_OK)
        return r;
    if(gds_file_read(cp, GDS_MAX_CERT_SIZE, cert) == GDS_OK &&
       gds_file_read(kp, GDS_MAX_KEY_SIZE, key) == GDS_OK && x509_key_matches(cert, key)) {
        uac_info("Loaded own certificate from %s", cp);
        return GDS_OK;
    }
    gds_buf_free(cert);
    gds_buf_free_secret(key);
    /* First start: self-signed certificate, replaced by the GDS below */
    UA_String subject[2] = {UA_STRING_STATIC("O=OpenGDS Test"),
                            UA_STRING_STATIC("CN=OpenGDS Pull Test Client")};
    UA_String san[2] = {UA_STRING(sanUri), UA_STRING_STATIC("DNS:localhost")};
    UA_ByteString c = UA_BYTESTRING_NULL, k = UA_BYTESTRING_NULL;
    if(UA_CreateCertificate(UA_Log_Stdout, subject, 2, san, 2, UA_CERTIFICATEFORMAT_DER, NULL,
                            &k, &c) != UA_STATUSCODE_GOOD)
        return GDS_ECRYPTO;
    cert->data = c.data;
    cert->len = c.length;
    key->data = k.data;
    key->len = k.length;
    if((r = gds_mkdirs(d, 0700)) != GDS_OK ||
       (r = gds_file_write_atomic(kp, key->data, key->len, 0600)) != GDS_OK ||
       (r = gds_file_write_atomic(cp, cert->data, cert->len, 0644)) != GDS_OK) {
        gds_buf_free(cert);
        gds_buf_free_secret(key);
        return r;
    }
    uac_info("Created self-signed certificate (first start)");
    return GDS_OK;
}

static gds_status saveList(const char *pki, const char *sub, const char *ext,
                           const UA_ByteString *items, size_t n) {
    char dir[GDS_MAX_PATH];
    gds_status r;
    if((r = gds_path(dir, sizeof(dir), "%s/%s", pki, sub)) != GDS_OK ||
       (r = gds_mkdirs(dir, 0700)) != GDS_OK)
        return r;
    for(size_t i = 0; i < n; i++) {
        gds_buf b = {items[i].data, items[i].length};
        char tp[X509_THUMBPRINT_LEN], path[GDS_MAX_PATH];
        if(b.len == 0 || b.len > GDS_MAX_CRL_SIZE)
            return GDS_ETOOBIG;
        /* name by SHA-1 of the bytes; CRLs too (thumbprint() checks only size) */
        if(b.len > GDS_MAX_CERT_SIZE) {
            if((r = gds_path(path, sizeof(path), "%s/crl-%zu.%s", dir, i, ext)) != GDS_OK)
                return r;
        } else if((r = x509_thumbprint(&b, tp)) != GDS_OK ||
                  (r = gds_path(path, sizeof(path), "%s/%s.%s", dir, tp, ext)) != GDS_OK) {
            return r;
        }
        if((r = gds_file_write_atomic(path, b.data, b.len, 0644)) != GDS_OK)
            return r;
    }
    return GDS_OK;
}

static gds_status readPasswordFile(const char *path, char *out, size_t outLen) {
    gds_buf b = {0};
    gds_status r = gds_file_read(path, outLen - 1, &b);
    if(r != GDS_OK)
        return r;
    size_t n = b.len;
    while(n > 0 && (b.data[n - 1] == '\n' || b.data[n - 1] == '\r'))
        n--;
    if(memchr(b.data, '\0', n)) {
        gds_buf_free_secret(&b);
        return GDS_EINVAL;
    }
    memcpy(out, b.data, n);
    out[n] = '\0';
    gds_buf_free_secret(&b);
    return GDS_OK;
}

static void freeOut(UA_Variant **out, size_t *outN) {
    if(*out)
        UA_Array_delete(*out, *outN, &UA_TYPES[UA_TYPES_VARIANT]);
    *out = NULL;
    *outN = 0;
}

/* Self-test main: one linear script of steps, kept in one place on purpose. */
// NOLINTNEXTLINE(readability-function-cognitive-complexity)
int main(int argc, char **argv) {
    const char *gds = "opc.tcp://localhost:4850";
    const char *pki = "./pki-pull";
    const char *user = NULL, *passwordArg = NULL, *passwordFile = NULL;
    const char *trustFiles[MAX_TRUST], *crlFiles[MAX_TRUST];
    size_t trustN = 0, crlN = 0;
    long pollSeconds = 60;
    char password[MAX_PASSWORD] = "";

    for(int i = 1; i < argc; i++) {
        const char *a = argv[i];
        const char *v = i + 1 < argc ? argv[i + 1] : NULL;
        if(!v)
            goto usage;
        i++;
        if(!strcmp(a, "--gds")) gds = v;
        else if(!strcmp(a, "--pki")) pki = v;
        else if(!strcmp(a, "--user")) user = v;
        else if(!strcmp(a, "--password")) passwordArg = v;
        else if(!strcmp(a, "--password-file")) passwordFile = v;
        else if(!strcmp(a, "--app-uri") && strlen(v) < GDS_MAX_APPLICATION_URI) appUri = v;
        else if(!strcmp(a, "--trust") && trustN < MAX_TRUST) trustFiles[trustN++] = v;
        else if(!strcmp(a, "--crl") && crlN < MAX_TRUST) crlFiles[crlN++] = v;
        else if(!strcmp(a, "--poll-seconds") && gds_parse_long(v, 1, 3600, &pollSeconds)) {}
        else goto usage;
    }
    if(trustN == 0) {
        fprintf(stderr, "refusing to run without --trust: the GDS must be trusted explicitly\n");
        return 1;
    }
    if(passwordFile) {
        gds_status s = readPasswordFile(passwordFile, password, sizeof(password));
        if(s != GDS_OK)
            return failg("read --password-file", s);
    } else if(passwordArg) {
        fprintf(stderr, "warning: --password is visible to other local users; prefer --password-file\n");
        if(gds_path(password, sizeof(password), "%s", passwordArg) != GDS_OK)
            return failg("--password", GDS_ETOOBIG);
    }
    if(user && !password[0]) {
        fprintf(stderr, "--user needs --password-file or --password\n");
        return 2;
    }

    printf("OpenGDS pull test client (Auditor self-test target)  app=%s  gds=%s\n", appUri, gds);

    uac_step("Load identity and the explicitly trusted GDS issuer");
    gds_buf cert = {0}, key = {0};
    gds_status gs = ensureOwnIdentity(pki, &cert, &key);
    if(gs != GDS_OK)
        return failg("own identity", gs);
    gds_buf trust[MAX_TRUST] = {{0}}, crls[MAX_TRUST] = {{0}};
    for(size_t i = 0; i < trustN; i++)
        if((gs = gds_file_read(trustFiles[i], GDS_MAX_CERT_SIZE, &trust[i])) != GDS_OK)
            return failg(trustFiles[i], gs);
    for(size_t i = 0; i < crlN; i++)
        if((gs = gds_file_read(crlFiles[i], GDS_MAX_CRL_SIZE, &crls[i])) != GDS_OK)
            return failg(crlFiles[i], gs);
    {
        char d[512];
        x509_describe(&cert, d, sizeof(d));
        uac_info("own: %s", d);
    }

    uac_step("Connect to the GDS (SignAndEncrypt, %s)",
             user ? "user credentials" : "application identity");
    UA_Client *client = uac_new_secure(&cert, &key, trust, trustN, crls, crlN, appUri);
    if(!client)
        return 1;
    UA_Client_getConfig(client)->customDataTypes = &gdsTypes;
    UA_StatusCode r = user ? UA_Client_connectUsername(client, gds, user, password)
                           : UA_Client_connect(client, gds);
    OPENSSL_cleanse(password, sizeof(password));
    if(r != UA_STATUSCODE_GOOD)
        return fail("connect", r);
    uac_info("connected");

    /* Bind the GDS namespace index at runtime */
    UA_UInt16 ns = 0;
    r = UA_Client_getNamespaceIndex(client, UA_STRING(GDS_NS_URI), &ns);
    if(r != UA_STATUSCODE_GOOD)
        return fail("GDS namespace not found on server", r);
    for(size_t i = 0; i < UA_TYPES_GDS_COUNT; i++) {
        UA_TYPES_GDS[i].typeId.namespaceIndex = ns;
        UA_TYPES_GDS[i].binaryEncodingId.namespaceIndex = ns;
    }
    uac_info("GDS namespace index = %u", ns);
    const UA_NodeId dir = UA_NODEID_NUMERIC(ns, UA_GDSID_DIRECTORY);
    const UA_DataType *recType = &UA_TYPES_GDS[UA_TYPES_GDS_APPLICATIONRECORDDATATYPE];

    size_t outN = 0;
    UA_Variant *out = NULL;
    UA_Variant in[4];

    uac_step("FindApplications(\"%s\")", appUri);
    UA_String uri = UA_STRING((char *)(uintptr_t)appUri);
    UA_Variant_setScalar(&in[0], &uri, &UA_TYPES[UA_TYPES_STRING]);
    r = uac_call(client, "FindApplications", dir,
                 UA_NODEID_NUMERIC(ns, UA_GDSID_DIRECTORY_FINDAPPLICATIONS), 1, in, 1, &outN, &out);
    if(r != UA_STATUSCODE_GOOD)
        return fail("FindApplications", r);
    UA_NodeId appId = UA_NODEID_NULL;
    {
        const void *recs = NULL;
        size_t found = 0;
        r = gds_arg_array(&out[0], recType, GDS_MAX_QUERY_RECORDS, &recs, &found);
        if(r != UA_STATUSCODE_GOOD)
            return fail("FindApplications result", r);
        if(found > 1) {
            fprintf(stderr, "More than one record for this ApplicationUri - a DiscoveryAdmin must resolve this\n");
            return 1;
        }
        if(found == 1) {
            const UA_ApplicationRecordDataType *rec = recs;
            if(UA_NodeId_copy(&rec->applicationId, &appId) != UA_STATUSCODE_GOOD)
                return fail("copy", UA_STATUSCODE_BADOUTOFMEMORY);
            uac_info("already registered");
        }
    }
    freeOut(&out, &outN);

    if(UA_NodeId_isNull(&appId)) {
        uac_step("RegisterApplication");
        UA_ApplicationRecordDataType rec;
        UA_ApplicationRecordDataType_init(&rec);
        rec.applicationUri = UA_STRING((char *)(uintptr_t)appUri);
        rec.applicationType = UA_APPLICATIONTYPE_CLIENT;
        UA_LocalizedText name = UA_LOCALIZEDTEXT("en", (char *)(uintptr_t)appName);
        rec.applicationNames = &name;
        rec.applicationNamesSize = 1;
        rec.productUri = UA_STRING("urn:opengds:test");
        UA_Variant_setScalar(&in[0], &rec, recType);
        r = uac_call(client, "RegisterApplication", dir,
                     UA_NODEID_NUMERIC(ns, UA_GDSID_DIRECTORY_REGISTERAPPLICATION), 1, in, 1,
                     &outN, &out);
        if(r != UA_STATUSCODE_GOOD)
            return fail("RegisterApplication", r);
        const UA_NodeId *id = uac_out_scalar(out, outN, 0, &UA_TYPES[UA_TYPES_NODEID]);
        if(!id || UA_NodeId_isNull(id) || UA_NodeId_copy(id, &appId) != UA_STATUSCODE_GOOD)
            return fail("RegisterApplication result", UA_STATUSCODE_BADUNEXPECTEDERROR);
        freeOut(&out, &outN);
    }
    {
        UA_String s = UA_STRING_NULL;
        if(UA_NodeId_print(&appId, &s) == UA_STATUSCODE_GOOD)
            uac_info("ApplicationId = %.*s", (int)s.length, s.data);
        UA_String_clear(&s);
    }

    uac_step("GetCertificateGroups");
    UA_Variant_setScalar(&in[0], &appId, &UA_TYPES[UA_TYPES_NODEID]);
    r = uac_call(client, "GetCertificateGroups", dir,
                 UA_NODEID_NUMERIC(ns, UA_GDSID_DIRECTORY_GETCERTIFICATEGROUPS), 1, in, 1, &outN,
                 &out);
    if(r != UA_STATUSCODE_GOOD)
        return fail("GetCertificateGroups", r);
    UA_NodeId groupId;
    {
        const void *groups = NULL;
        size_t nGroups = 0;
        r = gds_arg_array(&out[0], &UA_TYPES[UA_TYPES_NODEID], GDS_MAX_ARRAY_FIELD, &groups,
                          &nGroups);
        if(r != UA_STATUSCODE_GOOD || nGroups == 0)
            return fail("GetCertificateGroups result", r ? r : UA_STATUSCODE_BADNOTFOUND);
        if(UA_NodeId_copy(&((const UA_NodeId *)groups)[0], &groupId) != UA_STATUSCODE_GOOD)
            return fail("copy", UA_STATUSCODE_BADOUTOFMEMORY);
        uac_info("%zu group(s); using the first (DefaultApplicationGroup)", nGroups);
    }
    freeOut(&out, &outN);

    uac_step("GetCertificateStatus");
    UA_NodeId certType = UA_NODEID_NUMERIC(0, UA_NS0ID_RSASHA256APPLICATIONCERTIFICATETYPE);
    UA_Variant_setScalar(&in[0], &appId, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&in[1], &groupId, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&in[2], &certType, &UA_TYPES[UA_TYPES_NODEID]);
    r = uac_call(client, "GetCertificateStatus", dir,
                 UA_NODEID_NUMERIC(ns, UA_GDSID_DIRECTORY_GETCERTIFICATESTATUS), 3, in, 1, &outN,
                 &out);
    if(r != UA_STATUSCODE_GOOD)
        return fail("GetCertificateStatus", r);
    const UA_Boolean *upd = uac_out_scalar(out, outN, 0, &UA_TYPES[UA_TYPES_BOOLEAN]);
    if(!upd)
        return fail("GetCertificateStatus result", UA_STATUSCODE_BADUNEXPECTEDERROR);
    UA_Boolean updateRequired = *upd;
    freeOut(&out, &outN);
    uac_info("updateRequired = %s", updateRequired ? "true" : "false");

    if(updateRequired) {
        uac_step("StartSigningRequest (CSR signed with our own key; the key never leaves us)");
        gds_buf csr = {0};
        if((gs = x509_make_csr(&key, appName, appUri, "localhost", &csr)) != GDS_OK)
            return failg("CSR creation", gs);
        uac_info("CSR: %zu bytes", csr.len);
        UA_ByteString csrBs = {csr.len, csr.data};
        UA_Variant_setScalar(&in[3], &csrBs, &UA_TYPES[UA_TYPES_BYTESTRING]);
        r = uac_call(client, "StartSigningRequest", dir,
                     UA_NODEID_NUMERIC(ns, UA_GDSID_DIRECTORY_STARTSIGNINGREQUEST), 4, in, 1,
                     &outN, &out);
        gds_buf_free(&csr);
        if(r != UA_STATUSCODE_GOOD)
            return fail("StartSigningRequest", r);
        UA_NodeId requestId;
        const UA_NodeId *rid = uac_out_scalar(out, outN, 0, &UA_TYPES[UA_TYPES_NODEID]);
        if(!rid || UA_NodeId_copy(rid, &requestId) != UA_STATUSCODE_GOOD)
            return fail("StartSigningRequest result", UA_STATUSCODE_BADUNEXPECTEDERROR);
        freeOut(&out, &outN);

        uac_step("FinishRequest (poll until approved and issued)");
        UA_Variant fin[2];
        UA_Variant_setScalar(&fin[0], &appId, &UA_TYPES[UA_TYPES_NODEID]);
        UA_Variant_setScalar(&fin[1], &requestId, &UA_TYPES[UA_TYPES_NODEID]);
        long waited = 0;
        for(;;) {
            r = UA_Client_call(client, dir, UA_NODEID_NUMERIC(ns, UA_GDSID_DIRECTORY_FINISHREQUEST),
                               2, fin, &outN, &out);
            if(r != UA_STATUSCODE_BADNOTHINGTODO)
                break;
            freeOut(&out, &outN);
            uac_info("FinishRequest              -> BadNothingToDo (pending approval), retry in 1 s");
            if(++waited > pollSeconds)
                return fail("FinishRequest timed out", r);
            sleep(1);
        }
        uac_info("FinishRequest              -> %s", UA_StatusCode_name(r));
        if(r != UA_STATUSCODE_GOOD)
            return fail("FinishRequest", r);
        const UA_ByteString *newCert = uac_out_scalar(out, outN, 0, &UA_TYPES[UA_TYPES_BYTESTRING]);
        const UA_ByteString *newKey = uac_out_scalar(out, outN, 1, &UA_TYPES[UA_TYPES_BYTESTRING]);
        const void *issuers = NULL;
        size_t nIssuers = 0;
        if(!newCert || newCert->length == 0 || newCert->length > GDS_MAX_CERT_SIZE || outN < 3 ||
           gds_arg_array(&out[2], &UA_TYPES[UA_TYPES_BYTESTRING], GDS_MAX_CHAIN_LEN, &issuers,
                         &nIssuers) != UA_STATUSCODE_GOOD)
            return fail("FinishRequest result", UA_STATUSCODE_BADUNEXPECTEDERROR);
        if(newKey && newKey->length > 0) {
            fprintf(stderr, "GDS returned a private key for a CSR request - refusing it\n");
            return 1;
        }
        gds_buf nc = {newCert->data, newCert->length};
        if(!x509_key_matches(&nc, &key)) {
            fprintf(stderr, "issued certificate does not match our key - refusing it\n");
            return 1;
        }
        char d[512], tp[X509_THUMBPRINT_LEN], cp[GDS_MAX_PATH];
        x509_describe(&nc, d, sizeof(d));
        if((gs = x509_thumbprint(&nc, tp)) != GDS_OK)
            return failg("thumbprint", gs);
        uac_info("issued: %s", d);
        uac_info("thumbprint %s", tp);
        if((gs = gds_path(cp, sizeof(cp), "%s/own/cert.der", pki)) != GDS_OK ||
           (gs = gds_file_write_atomic(cp, nc.data, nc.len, 0644)) != GDS_OK ||
           (gs = saveList(pki, "issuer/certs", "der", issuers, nIssuers)) != GDS_OK)
            return failg("save certificate", gs);
        uac_info("saved certificate + %zu issuer certificate(s)", nIssuers);
        freeOut(&out, &outN);
        UA_NodeId_clear(&requestId);
    }

    uac_step("GetTrustList -> read it through the standard FileType methods");
    UA_Variant_setScalar(&in[0], &appId, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&in[1], &groupId, &UA_TYPES[UA_TYPES_NODEID]);
    r = uac_call(client, "GetTrustList", dir, UA_NODEID_NUMERIC(ns, UA_GDSID_DIRECTORY_GETTRUSTLIST),
                 2, in, 1, &outN, &out);
    if(r != UA_STATUSCODE_GOOD)
        return fail("GetTrustList", r);
    UA_NodeId tlId;
    const UA_NodeId *tlp = uac_out_scalar(out, outN, 0, &UA_TYPES[UA_TYPES_NODEID]);
    if(!tlp || UA_NodeId_copy(tlp, &tlId) != UA_STATUSCODE_GOOD)
        return fail("GetTrustList result", UA_STATUSCODE_BADUNEXPECTEDERROR);
    freeOut(&out, &outN);
    UA_TrustListDataType tl;
    r = uac_read_trustlist(client, tlId, &tl);
    if(r != UA_STATUSCODE_GOOD)
        return fail("TrustList read", r);
    uac_info("trusted certs=%zu trusted CRLs=%zu issuer certs=%zu issuer CRLs=%zu",
             tl.trustedCertificatesSize, tl.trustedCrlsSize, tl.issuerCertificatesSize,
             tl.issuerCrlsSize);
    if((gs = saveList(pki, "trusted/certs", "der", tl.trustedCertificates, tl.trustedCertificatesSize)) != GDS_OK ||
       (gs = saveList(pki, "trusted/crl", "crl", tl.trustedCrls, tl.trustedCrlsSize)) != GDS_OK ||
       (gs = saveList(pki, "issuer/certs", "der", tl.issuerCertificates, tl.issuerCertificatesSize)) != GDS_OK ||
       (gs = saveList(pki, "issuer/crl", "crl", tl.issuerCrls, tl.issuerCrlsSize)) != GDS_OK)
        return failg("save trust list", gs);
    UA_TrustListDataType_clear(&tl);

    uac_step("Disconnect (Part 12 §6.3: stay connected to the GDS as briefly as possible)");
    UA_Client_disconnect(client);
    UA_Client_delete(client);
    UA_NodeId_clear(&appId);
    UA_NodeId_clear(&groupId);
    UA_NodeId_clear(&tlId);
    for(size_t i = 0; i < trustN; i++)
        gds_buf_free(&trust[i]);
    for(size_t i = 0; i < crlN; i++)
        gds_buf_free(&crls[i]);
    gds_buf_free(&cert);
    gds_buf_free_secret(&key);
    printf("\nPULL WORKFLOW COMPLETE - PKI written to %s\n", pki);
    return 0;

usage:
    fprintf(stderr,
            "usage: %s --gds URL --trust gds-ca.der [--crl x.crl] [--user U\n"
            "          (--password-file F | --password P)] [--pki DIR] [--app-uri URI]\n"
            "          [--poll-seconds N]\n",
            argv[0]);
    return 2;
}
