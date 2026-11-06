/* OpenGDS Auditor - push driver (seed of the server profile: plays the GDS
 * CertificateManager)
 * SPDX-License-Identifier: MPL-2.0
 *
 * Drives the Part 12 PushManagement workflow (Annex G.2) against a push
 * server, as a GDS would:
 *   1. Trust the server: its certificate from --server-cert, or on first use
 *      with --tofu (test setups only), and connect with a CA-issued
 *      certificate that the server maps to SecurityAdmin (Annex G.3).
 *   2. TrustList Open(Write|EraseExisting) -> Write -> CloseAndUpdate
 *   3. CreateSigningRequest -> sign with the test CA -> UpdateCertificate
 *   4. ApplyChanges
 *   5. Reconnect trusting only the CA and verify the server now presents the
 *      issued certificate and the pushed trust list.
 *
 * Usage: push_driver [--server opc.tcp://localhost:4841] [--ca-dir ./demo-ca]
 *                    [--server-uri urn:opengds:test:pushserver]
 *                    (--server-cert srv.der | --tofu) [--init-only]
 */
#include <open62541/client_highlevel.h>
#include <open62541/plugin/log_stdout.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "common/limits.h"
#include "test_ca.h"
#include "uaclient.h"
#include "common/banned.h"

#define DRIVER_URI "urn:opengds:test:pushdriver"

static int fail(const char *what, UA_StatusCode r) {
    fprintf(stderr, "\nFAILED: %s: %s\n", what, UA_StatusCode_name(r));
    return 1;
}

static int failg(const char *what, gds_status s) {
    fprintf(stderr, "\nFAILED: %s: %s\n", what, gds_status_name(s));
    return 1;
}

static UA_NodeId ns0(UA_UInt32 id) { return UA_NODEID_NUMERIC(0, id); }

static void freeOut(UA_Variant **out, size_t *outN) {
    if(*out)
        UA_Array_delete(*out, *outN, &UA_TYPES[UA_TYPES_VARIANT]);
    *out = NULL;
    *outN = 0;
}

/* Everything main() owns, freed by one atexit handler, so every exit path
 * (including the early `return fail(...)`s) releases it. */
static struct {
    testca_t ca;
    gds_buf caDer, crlDer, cert, key, newCert;
    UA_ByteString srvCert, now;
    UA_Client *client;
} R;

static void releaseAll(void) {
    if(R.client) {
        UA_Client_disconnect(R.client);
        UA_Client_delete(R.client);
    }
    UA_ByteString_clear(&R.srvCert);
    UA_ByteString_clear(&R.now);
    gds_buf_free(&R.newCert);
    gds_buf_free(&R.caDer);
    gds_buf_free(&R.crlDer);
    gds_buf_free(&R.cert);
    gds_buf_free_secret(&R.key);
    testca_free(&R.ca);
}

static int usage(const char *argv0) {
    fprintf(stderr,
            "usage: %s [--server URL] [--ca-dir DIR] [--server-uri URI]\n"
            "          (--server-cert srv.der | --tofu) [--init-only]\n",
            argv0);
    return 2;
}

/* Self-test main: one linear script of steps, kept in one place on purpose. */
// NOLINTNEXTLINE(readability-function-cognitive-complexity)
int main(int argc, char **argv) {
    const char *url = "opc.tcp://localhost:4841";
    const char *caDir = "./demo-ca";
    const char *serverUri = "urn:opengds:test:pushserver";
    const char *serverCertFile = NULL;
    bool tofu = false, initOnly = false;
    for(int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if(!strcmp(a, "--tofu")) { tofu = true; continue; }
        if(!strcmp(a, "--init-only")) { initOnly = true; continue; }
        const char *v = i + 1 < argc ? argv[++i] : NULL;
        if(!v) return usage(argv[0]);
        if(!strcmp(a, "--server")) url = v;
        else if(!strcmp(a, "--ca-dir")) caDir = v;
        else if(!strcmp(a, "--server-uri") && strlen(v) < GDS_MAX_APPLICATION_URI) serverUri = v;
        else if(!strcmp(a, "--server-cert")) serverCertFile = v;
        else return usage(argv[0]);
    }

    atexit(releaseAll);
#define ca R.ca
    gds_status gs = testca_load_or_create(&ca, caDir, "OpenGDS Auditor TEST CA");
    if(gs != GDS_OK)
        return failg("test CA", gs);
#define caDer R.caDer
#define crlDer R.crlDer
    if((gs = testca_cert_der(&ca, &caDer)) != GDS_OK || (gs = testca_crl_der(&ca, &crlDer)) != GDS_OK)
        return failg("test CA export", gs);

    /* Driver identity (the "GDS application certificate", Annex G.3) */
#define cert R.cert
#define key R.key
    if((gs = testca_identity(&ca, caDir, "pushdriver", "OpenGDS Push Driver", DRIVER_URI, &cert,
                             &key)) != GDS_OK)
        return failg("driver identity", gs);
    if(initOnly) {
        printf("push driver identity ready in %s\n", caDir);
        return 0;
    }
    if(!tofu && !serverCertFile) {
        fprintf(stderr, "refusing to run: pass --server-cert, or --tofu for test setups only\n");
        return 2;
    }
    printf("OpenGDS push driver  server=%s\n", url);

#define srvCert R.srvCert
    UA_StatusCode r;
    if(serverCertFile) {
        uac_step("Trust the server certificate given with --server-cert");
        gds_buf b = {0};
        if((gs = gds_file_read(serverCertFile, GDS_MAX_CERT_SIZE, &b)) != GDS_OK)
            return failg(serverCertFile, gs);
        srvCert.data = b.data;
        srvCert.length = b.len;
    } else {
        uac_step("Trust the server on first use (--tofu: test setup only, Annex G.2)");
        r = uac_fetch_server_cert(url, &srvCert);
        if(r != UA_STATUSCODE_GOOD)
            return fail("GetEndpoints", r);
    }
    gds_buf sc = {srvCert.data, srvCert.length};
    char d[512], oldTp[X509_THUMBPRINT_LEN], newTp[X509_THUMBPRINT_LEN];
    x509_describe(&sc, d, sizeof(d));
    if((gs = x509_thumbprint(&sc, oldTp)) != GDS_OK)
        return failg("server certificate", gs);
    uac_info("current: %s", d);
    uac_info("thumbprint %s", oldTp);

    uac_step("Connect as SecurityAdmin (CA-issued driver certificate)");
    gds_buf trust[2] = {caDer, sc};
#define client R.client
    client = uac_new_secure(&cert, &key, trust, 2, &crlDer, 1, DRIVER_URI);
    if(!client)
        return 1;
    r = UA_Client_connect(client, url);
    if(r != UA_STATUSCODE_GOOD)
        return fail("connect", r);
    uac_info("connected");

    size_t outN = 0;
    UA_Variant *out = NULL;
    UA_Variant in[6];
    const UA_NodeId tlNode =
        ns0(UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST);
    const UA_NodeId sc0 = ns0(UA_NS0ID_SERVERCONFIGURATION);

    uac_step("Push the trust list: Open(Write|EraseExisting) -> Write -> CloseAndUpdate");
    UA_TrustListDataType tl;
    UA_TrustListDataType_init(&tl);
    UA_ByteString caBs = {caDer.len, caDer.data}, crlBs = {crlDer.len, crlDer.data};
    tl.specifiedLists = UA_TRUSTLISTMASKS_ALL;
    tl.trustedCertificates = &caBs;
    tl.trustedCertificatesSize = 1;
    tl.trustedCrls = &crlBs;
    tl.trustedCrlsSize = 1;
    UA_ByteString file = UA_BYTESTRING_NULL;
    r = UA_encodeBinary(&tl, &UA_TYPES[UA_TYPES_TRUSTLISTDATATYPE], &file, NULL);
    if(r != UA_STATUSCODE_GOOD)
        return fail("encode trust list", r);

    UA_Byte mode = 0x02 | 0x04; /* Write | EraseExisting */
    UA_Variant_setScalar(&in[0], &mode, &UA_TYPES[UA_TYPES_BYTE]);
    r = uac_call(client, "TrustList.Open", tlNode,
                 ns0(UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST_OPEN),
                 1, in, 1, &outN, &out);
    if(r != UA_STATUSCODE_GOOD)
        return fail("TrustList.Open", r);
    const UA_UInt32 *hp = uac_out_scalar(out, outN, 0, &UA_TYPES[UA_TYPES_UINT32]);
    if(!hp)
        return fail("TrustList.Open result", UA_STATUSCODE_BADUNEXPECTEDERROR);
    UA_UInt32 handle = *hp;
    freeOut(&out, &outN);

    UA_Variant_setScalar(&in[0], &handle, &UA_TYPES[UA_TYPES_UINT32]);
    UA_Variant_setScalar(&in[1], &file, &UA_TYPES[UA_TYPES_BYTESTRING]);
    r = uac_call(client, "TrustList.Write", tlNode,
                 ns0(UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST_WRITE),
                 2, in, 0, &outN, &out);
    if(r != UA_STATUSCODE_GOOD)
        return fail("TrustList.Write", r);
    freeOut(&out, &outN);

    r = uac_call(client, "TrustList.CloseAndUpdate", tlNode,
                 ns0(UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST_CLOSEANDUPDATE),
                 1, in, 1, &outN, &out);
    if(r != UA_STATUSCODE_GOOD)
        return fail("TrustList.CloseAndUpdate", r);
    const UA_Boolean *acr = uac_out_scalar(out, outN, 0, &UA_TYPES[UA_TYPES_BOOLEAN]);
    uac_info("applyChangesRequired = %s", acr ? (*acr ? "true" : "false") : "<missing>");
    freeOut(&out, &outN);
    UA_ByteString_clear(&file);

    uac_step("CreateSigningRequest (server keeps its private key)");
    UA_NodeId group = ns0(UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP);
    UA_NodeId ctype = ns0(UA_NS0ID_RSASHA256APPLICATIONCERTIFICATETYPE);
    UA_String subject = UA_STRING_NULL;
    UA_Boolean regen = false;
    UA_ByteString nonce = UA_BYTESTRING_NULL;
    UA_Variant_setScalar(&in[0], &group, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&in[1], &ctype, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalar(&in[2], &subject, &UA_TYPES[UA_TYPES_STRING]);
    UA_Variant_setScalar(&in[3], &regen, &UA_TYPES[UA_TYPES_BOOLEAN]);
    UA_Variant_setScalar(&in[4], &nonce, &UA_TYPES[UA_TYPES_BYTESTRING]);
    r = uac_call(client, "CreateSigningRequest", sc0,
                 ns0(UA_NS0ID_SERVERCONFIGURATION_CREATESIGNINGREQUEST), 5, in, 1, &outN, &out);
    if(r != UA_STATUSCODE_GOOD)
        return fail("CreateSigningRequest", r);
    const UA_ByteString *csrBs = uac_out_scalar(out, outN, 0, &UA_TYPES[UA_TYPES_BYTESTRING]);
    if(!csrBs || csrBs->length == 0 || csrBs->length > GDS_MAX_CSR_SIZE)
        return fail("CreateSigningRequest result", UA_STATUSCODE_BADUNEXPECTEDERROR);
    gds_buf csr = {csrBs->data, csrBs->length};
    uac_info("CSR: %zu bytes", csr.len);

    uac_step("Sign the CSR with the CA (SAN URI forced to the registered ApplicationUri)");
#define newCert R.newCert
    gs = testca_sign_csr(&ca, &csr, serverUri, TESTCA_MAX_DAYS, &newCert);
    freeOut(&out, &outN);
    if(gs != GDS_OK)
        return failg("CA refused the CSR", gs);
    x509_describe(&newCert, d, sizeof(d));
    if((gs = x509_thumbprint(&newCert, newTp)) != GDS_OK)
        return failg("issued certificate", gs);
    uac_info("issued: %s", d);
    uac_info("thumbprint %s", newTp);

    uac_step("UpdateCertificate");
    UA_ByteString nc = {newCert.len, newCert.data};
    UA_String pkFormat = UA_STRING_NULL;
    UA_ByteString pk = UA_BYTESTRING_NULL;
    UA_Variant_setScalar(&in[2], &nc, &UA_TYPES[UA_TYPES_BYTESTRING]);
    UA_Variant_setArray(&in[3], &caBs, 1, &UA_TYPES[UA_TYPES_BYTESTRING]);
    UA_Variant_setScalar(&in[4], &pkFormat, &UA_TYPES[UA_TYPES_STRING]);
    UA_Variant_setScalar(&in[5], &pk, &UA_TYPES[UA_TYPES_BYTESTRING]);
    r = uac_call(client, "UpdateCertificate", sc0,
                 ns0(UA_NS0ID_SERVERCONFIGURATION_UPDATECERTIFICATE), 6, in, 1, &outN, &out);
    if(r != UA_STATUSCODE_GOOD)
        return fail("UpdateCertificate", r);
    acr = uac_out_scalar(out, outN, 0, &UA_TYPES[UA_TYPES_BOOLEAN]);
    uac_info("applyChangesRequired = %s", acr ? (*acr ? "true" : "false") : "<missing>");
    freeOut(&out, &outN);

    uac_step("ApplyChanges");
    r = uac_call(client, "ApplyChanges", sc0, ns0(UA_NS0ID_SERVERCONFIGURATION_APPLYCHANGES), 0,
                 NULL, 0, &outN, &out);
    if(r != UA_STATUSCODE_GOOD)
        return fail("ApplyChanges", r);
    freeOut(&out, &outN);
    UA_Client_disconnect(client);
    UA_Client_delete(client);
    client = NULL;

    uac_step("Verify: reconnect trusting ONLY the CA (no more trust on first use)");
    sleep(1);
#define now R.now
    r = uac_fetch_server_cert(url, &now);
    if(r != UA_STATUSCODE_GOOD)
        return fail("GetEndpoints after ApplyChanges", r);
    gds_buf nowB = {now.data, now.length};
    char nowTp[X509_THUMBPRINT_LEN];
    if((gs = x509_thumbprint(&nowB, nowTp)) != GDS_OK)
        return failg("server certificate after ApplyChanges", gs);
    uac_info("server now presents %s", nowTp);
    if(strcmp(nowTp, newTp) != 0) {
        fprintf(stderr, "\nFAILED: server does not present the issued certificate\n");
        return 1;
    }
    client = uac_new_secure(&cert, &key, &caDer, 1, &crlDer, 1, DRIVER_URI);
    if(!client)
        return 1;
    r = UA_Client_connect(client, url);
    if(r != UA_STATUSCODE_GOOD)
        return fail("reconnect with CA trust only", r);
    uac_info("connected; certificate chain validates against the CA");
    r = uac_read_trustlist(client, tlNode, &tl);
    if(r != UA_STATUSCODE_GOOD)
        return fail("TrustList read-back", r);
    uac_info("server trust list: trusted certs=%zu trusted CRLs=%zu issuer certs=%zu issuer CRLs=%zu",
             tl.trustedCertificatesSize, tl.trustedCrlsSize, tl.issuerCertificatesSize,
             tl.issuerCrlsSize);
    UA_TrustListDataType_clear(&tl);
    UA_Client_disconnect(client);
    UA_Client_delete(client);
    client = NULL;

    printf("\nPUSH WORKFLOW COMPLETE - %s -> %s\n", oldTp, newTp);
    return 0; /* releaseAll() frees the rest */
}
