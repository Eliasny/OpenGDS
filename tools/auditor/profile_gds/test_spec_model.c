/* OpenGDS spec tests: the GDS address space has every Mandatory member of
 * DirectoryType (OPC 10000-12 §6.5.3), CertificateDirectoryType (§7.9.2),
 * CertificateGroupType (§7.8.3.1) and TrustListType (§7.8.2.1) on the
 * well-known Directory Object.
 * SPDX-License-Identifier: MPL-2.0 */
#include <open62541/client_highlevel.h>
#include <open62541/nodeids_gds.h>

#include <string.h>

#include "common/limits.h"
#include "gds_target.h"
#include "spec_tests.h"
#include "common/banned.h"

typedef struct {
    const char *name;
    bool ns0; /* BrowseName in namespace 0, else in the GDS namespace */
} member;

static size_t missing(gds_target *t, UA_NodeId parent, const member *m, size_t n, char *list,
                      size_t listLen) {
    size_t miss = 0;
    list[0] = '\0';
    for(size_t i = 0; i < n; i++) {
        UA_NodeId x;
        UA_StatusCode r = m[i].ns0 ? uac_find_child(t->client, parent, m[i].name, &x)
                                   : gt_find(t->client, parent, t->ns, m[i].name, &x);
        if(r == UA_STATUSCODE_GOOD) {
            UA_NodeId_clear(&x);
            continue;
        }
        miss++;
        size_t used = strlen(list);
        if(gds_path(list + used, listLen - used, "%s%s", used ? ", " : "", m[i].name) != GDS_OK)
            break;
    }
    return miss;
}

static void t_directory(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    UA_StatusCode r = gt_session(t);
    if(r != UA_STATUSCODE_GOOD) {
        ga_not_tested(ctx, "session -> %s", UA_StatusCode_name(r));
        return;
    }
    static const member m[] = {
        {"Applications", false},          {"FindApplications", false},
        {"RegisterApplication", false},   {"UpdateApplication", false},
        {"UnregisterApplication", false}, {"GetApplication", false},
        {"QueryApplications", false},     {"QueryServers", false},
        {"CertificateGroups", false},     {"StartSigningRequest", false},
        {"StartNewKeyPairRequest", false}, {"FinishRequest", false},
        {"GetCertificateGroups", false},  {"GetTrustList", false},
        {"GetCertificateStatus", false}};
    char list[512];
    size_t miss = missing(t, gt_node(t, UA_GDSID_DIRECTORY), m, GDS_ARRAY_SIZE(m), list, sizeof(list));
    if(miss)
        ga_fail(ctx, "Directory lacks %zu Mandatory member(s): %s", miss, list);
    else
        ga_pass(ctx, "Directory has every Mandatory member of DirectoryType and CertificateDirectoryType");
}

static void t_certificate_group(ga_ctx *ctx, void *p) {
    gds_target *t = p;
    UA_StatusCode r = gt_session(t);
    if(r != UA_STATUSCODE_GOOD) {
        ga_not_tested(ctx, "session -> %s", UA_StatusCode_name(r));
        return;
    }
    static const member g[] = {{"TrustList", true}, {"CertificateTypes", true}};
    static const member tl[] = {{"LastUpdateTime", true}, {"OpenWithMasks", true},
                                {"CloseAndUpdate", true}, {"AddCertificate", true},
                                {"RemoveCertificate", true}, {"Open", true},
                                {"Close", true},           {"Read", true},
                                {"Write", true},           {"GetPosition", true},
                                {"SetPosition", true}};
    char l1[512], l2[512];
    size_t m1 = missing(t, gt_default_group(t), g, GDS_ARRAY_SIZE(g), l1, sizeof(l1));
    size_t m2 = missing(t,
                        gt_node(t, UA_GDSID_DIRECTORY_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST),
                        tl, GDS_ARRAY_SIZE(tl), l2, sizeof(l2));
    if(m1 || m2) {
        ga_fail(ctx, "missing Mandatory members: group [%s] trust list [%s]", l1, l2);
        return;
    }
    /* CertificateTypes lists what StartSigningRequest accepts for the group */
    UA_NodeId ct;
    UA_Variant v;
    UA_Variant_init(&v);
    r = uac_find_child(t->client, gt_default_group(t), "CertificateTypes", &ct);
    if(r == UA_STATUSCODE_GOOD)
        r = UA_Client_readValueAttribute(t->client, ct, &v);
    UA_NodeId_clear(&ct);
    bool rsa = false;
    size_t n = 0;
    if(r == UA_STATUSCODE_GOOD && v.type == &UA_TYPES[UA_TYPES_NODEID]) {
        UA_NodeId want = gt_rsa_type();
        n = UA_Variant_isScalar(&v) ? 1 : v.arrayLength;
        for(size_t i = 0; i < n; i++)
            rsa |= UA_NodeId_equal(&((UA_NodeId *)v.data)[i], &want);
    }
    if(r != UA_STATUSCODE_GOOD || v.type != &UA_TYPES[UA_TYPES_NODEID])
        ga_fail(ctx, "DefaultApplicationGroup.CertificateTypes unreadable or not NodeIds (%s)",
                UA_StatusCode_name(r));
    else if(!rsa)
        ga_warn(ctx, "CertificateTypes (%zu entries) does not list "
                     "RsaSha256ApplicationCertificateType, which the signing tests request", n);
    else
        ga_pass(ctx, "DefaultApplicationGroup and its TrustList have every Mandatory member");
    UA_Variant_clear(&v);
}

const ga_test spec_model_tests[] = {
    {"gds.model.directory", "12 §6.5.3, §7.9.2", "The Directory Object has every Mandatory Method and Object",
     false, false, t_directory},
    {"gds.model.certificate_group", "12 §7.8.3.1, §7.8.2.1", "DefaultApplicationGroup and its TrustList have every Mandatory member",
     false, false, t_certificate_group},
};
const size_t spec_model_count = GDS_ARRAY_SIZE(spec_model_tests);
