/* OpenGDS Auditor client profile - Signing request (CLI-CSR-*).
 * Rows of docs/auditor/client-profile.md, "Signing request (cli_csr.c)".
 * SPDX-License-Identifier: MPL-2.0 */
#include <open62541/nodeids.h>

#include <openssl/evp.h>

#include <stdio.h>
#include <string.h>

#include "client_profile.h"
#include "csr_check.h"
#include "common/banned.h"

/* The first StartSigningRequest of the shared cycle, its CSR inspected.
 * NULL (verdict decided) when there is none. */
static const fg_event *base_sign(cli_profile *p, ga_ctx *ctx, csr_info *info) {
    const cli_cycle *c = cli_base_cycle(p, ctx);
    if(!c)
        return NULL;
    const fg_event *ev = cli_find(c, FG_M_SIGN, 0);
    if(!ev) {
        ga_not_tested(ctx, "the client made no StartSigningRequest in its first cycle (%zu calls)",
                      c->end - c->first);
        return NULL;
    }
    csr_inspect(&ev->csr, info);
    return ev;
}

static void t_csr_valid(ga_ctx *ctx, void *profile) {
    csr_info ci;
    if(!base_sign(profile, ctx, &ci))
        return;
    if(!ci.parsed)
        ga_fail(ctx, "the CertificateRequest is not a DER PKCS #10 request");
    else if(!ci.signatureOk)
        ga_fail(ctx, "the CSR signature does not verify with its own public key (no proof of possession)");
    else
        ga_pass(ctx, "DER PKCS #10, signature verifies (key type %d, %d bits)", ci.keyType, ci.bits);
    csr_info_clear(&ci);
}

static void t_csr_uri(ga_ctx *ctx, void *profile) {
    csr_info ci;
    const fg_event *ev = base_sign(profile, ctx, &ci);
    if(!ev)
        return;
    if(!ci.parsed)
        ga_fail(ctx, "the CSR does not parse, so it has no subjectAltName");
    else if(ci.uriN != 1)
        ga_fail(ctx, "subjectAltName has %zu URIs, Part 6 §6.2.2 needs exactly one", ci.uriN);
    else if(strcmp(ci.uris[0], ev->appUri) != 0)
        ga_fail(ctx, "CSR URI %s differs from the ApplicationUri %s", ci.uris[0], ev->appUri);
    else
        ga_pass(ctx, "one URI, equal to the ApplicationUri %s", ev->appUri);
    csr_info_clear(&ci);
}

/* 12 §7.8.4.9: RsaSha256ApplicationCertificateType keys are 2048, 3072 or 4096 bits */
static void t_csr_key(ga_ctx *ctx, void *profile) {
    csr_info ci;
    const fg_event *ev = base_sign(profile, ctx, &ci);
    if(!ev)
        return;
    UA_NodeId rsa256 = UA_NODEID_NUMERIC(0, UA_NS0ID_RSASHA256APPLICATIONCERTIFICATETYPE);
    if(!ci.parsed)
        ga_fail(ctx, "the CSR does not parse");
    else if(!UA_NodeId_equal(&ev->certType, &rsa256))
        ga_not_tested(ctx, "key rules for CertificateTypeId ns=%u;i=%u are not implemented yet",
                      ev->certType.namespaceIndex, ev->certType.identifier.numeric);
    else if(ci.keyType != EVP_PKEY_RSA)
        ga_fail(ctx, "RsaSha256ApplicationCertificateType with a non-RSA key (type %d)", ci.keyType);
    else if(ci.bits != 2048 && ci.bits != 3072 && ci.bits != 4096)
        ga_fail(ctx, "RSA key of %d bits; the type allows 2048, 3072 or 4096", ci.bits);
    else
        ga_pass(ctx, "RSA %d bits for RsaSha256ApplicationCertificateType", ci.bits);
    csr_info_clear(&ci);
}

static void t_csr_listed(ga_ctx *ctx, void *profile) {
    csr_info ci;
    const fg_event *ev = base_sign(profile, ctx, &ci);
    if(!ev)
        return;
    csr_info_clear(&ci);
    UA_NodeId g = fg_default_group(), t = fg_listed_cert_type();
    if(!UA_NodeId_equal(&ev->group, &g))
        ga_fail(ctx, "CertificateGroupId is not one GetCertificateGroups returned");
    else if(!UA_NodeId_equal(&ev->certType, &t))
        ga_fail(ctx, "CertificateTypeId ns=%u;i=%u is not in the group's CertificateTypes "
                     "(RsaSha256ApplicationCertificateType only)",
                ev->certType.namespaceIndex, ev->certType.identifier.numeric);
    else
        ga_pass(ctx, "DefaultApplicationGroup, RsaSha256ApplicationCertificateType: both listed");
}

/* "opc.tcp://host:port/path" -> host */
static void url_host(const char *url, char *out, size_t outLen) {
    const char *h = strstr(url, "://");
    h = h ? h + 3 : url;
    size_t n = strcspn(h, ":/");
    if(n >= outLen)
        n = outLen - 1;
    memcpy(out, h, n);
    out[n] = '\0';
}

static void t_csr_dns(ga_ctx *ctx, void *profile) {
    csr_info ci;
    const fg_event *ev = base_sign(profile, ctx, &ci);
    if(!ev)
        return;
    if(ev->appType == UA_APPLICATIONTYPE_CLIENT) {
        ga_not_supported(ctx, "the client is registered as a pure Client");
    } else if(ev->discoveryUrlsN == 0) {
        ga_pass(ctx, "no DiscoveryUrls registered, so no domain can be missing");
    } else {
        char host[FG_MAX_URI];
        url_host(ev->discoveryUrl0, host, sizeof(host));
        bool found = false;
        for(size_t i = 0; i < ci.dnsN && !found; i++)
            found = strcmp(ci.dns[i], host) == 0;
        if(found)
            ga_pass(ctx, "the CSR names %s from DiscoveryUrl %s", host, ev->discoveryUrl0);
        else
            ga_fail(ctx, "DiscoveryUrl %s: domain %s is not among the CSR's %zu DNS names",
                    ev->discoveryUrl0, host, ci.dnsN);
    }
    csr_info_clear(&ci);
}

static void t_csr_new_key(ga_ctx *ctx, void *profile) {
    cli_profile *p = profile;
    csr_info first;
    if(!base_sign(p, ctx, &first))
        return;
    const cli_cycle *c = cli_shared_cycle(p, CLI_SHARED_RENEW, ctx);
    if(!c) {
        csr_info_clear(&first);
        return;
    }
    const fg_event *ev = cli_find(c, FG_M_SIGN, 0);
    if(!ev) {
        ga_not_tested(ctx, "UpdateRequired was TRUE but the client made no second request");
    } else {
        csr_info second;
        csr_inspect(&ev->csr, &second);
        if(!second.parsed || second.pubDer.len == 0)
            ga_not_tested(ctx, "the second CSR does not parse");
        else if(second.pubDer.len == first.pubDer.len &&
                memcmp(second.pubDer.data, first.pubDer.data, first.pubDer.len) == 0)
            ga_warn(ctx, "the second signing request reuses the first key (12 §7.6 strongly "
                         "recommends a new key per request)");
        else
            ga_pass(ctx, "the second signing request carries a new key");
        csr_info_clear(&second);
    }
    csr_info_clear(&first);
}

static void t_csr_no_leak(ga_ctx *ctx, void *profile) {
    cli_profile *p = profile;
    csr_info ci;
    if(!base_sign(p, ctx, &ci))
        return;
    const cli_cycle *c = &p->shared[CLI_SHARED_BASE];
    size_t hit = SIZE_MAX;
    for(size_t i = c->first; i < c->end && hit == SIZE_MAX; i++)
        if(csr_blob_has_private_key(&fg_event_at(i)->args, &ci.pubDer))
            hit = i;
    if(hit != SIZE_MAX)
        ga_fail(ctx, "the private key of the CSR was sent in the arguments of %s",
                fg_method_name(fg_event_at(hit)->method));
    else
        ga_pass(ctx, "no argument of the %zu calls holds the CSR's private key",
                c->end - c->first);
    csr_info_clear(&ci);
}

static void t_csr_retry(ga_ctx *ctx, void *profile) {
    cli_cycle c;
    if(!cli_cycle_for(profile, FAULT_SIGN_URI_INVALID, ctx, &c))
        return;
    size_t n = cli_count(&c, FG_M_SIGN);
    if(n == 0)
        ga_not_tested(ctx, "the client made no StartSigningRequest in this cycle");
    else if(n <= 2)
        ga_pass(ctx, "%zu StartSigningRequest call(s) after Bad_CertificateUriInvalid", n);
    else
        ga_warn(ctx, "%zu StartSigningRequest calls in one cycle after Bad_CertificateUriInvalid", n);
}

static void t_csr_keypair(ga_ctx *ctx, void *profile) {
    const cli_cycle *c = cli_base_cycle(profile, ctx);
    if(!c)
        return;
    size_t nk = cli_count(c, FG_M_NEWKEYPAIR), ns = cli_count(c, FG_M_SIGN);
    if(nk)
        ga_warn(ctx, "StartNewKeyPairRequest called %zu time(s): the GDS would generate the "
                     "client's private key (12 §7.6 recommends client-generated keys)", nk);
    else if(ns)
        ga_pass(ctx, "StartSigningRequest only (the key is generated by the client)");
    else
        ga_not_supported(ctx, "neither StartSigningRequest nor StartNewKeyPairRequest was called");
}

const ga_test cli_csr_tests[] = {
    {"CLI-CSR-01", "12 §7.9.3", "CSR is DER PKCS #10 and its signature verifies", false, true, t_csr_valid},
    {"CLI-CSR-02", "12 §7.9.3; 6 §6.2.2", "CSR subjectAltName URI equals the ApplicationUri", false, true, t_csr_uri},
    {"CLI-CSR-03", "12 §7.9.3, §7.8.4.9", "Key type and length fit the CertificateType", false, true, t_csr_key},
    {"CLI-CSR-04", "12 §7.9.3, §7.9.7, §7.8.3.1", "Group and type are ones the GDS listed", false, true, t_csr_listed},
    {"CLI-CSR-05", "12 §7.9.3", "A server's CSR names its DiscoveryUrl domains", false, true, t_csr_dns},
    {"CLI-CSR-06", "12 §7.6", "A new key for each signing request", false, true, t_csr_new_key},
    {"CLI-CSR-07", "12 §7.9.3", "The private key never leaves the client", false, true, t_csr_no_leak},
    {"CLI-CSR-08", "12 §7.9.3", "No retry storm after Bad_CertificateUriInvalid", false, true, t_csr_retry},
    {"CLI-CSR-09", "12 §7.6, §7.9.4", "StartSigningRequest rather than StartNewKeyPairRequest", false, true, t_csr_keypair},
};
const size_t cli_csr_count = GDS_ARRAY_SIZE(cli_csr_tests);
