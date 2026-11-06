/* OpenGDS Auditor client profile - Registration (CLI-REG-*).
 * Rows of docs/auditor/client-profile.md, "Registration (cli_register.c)".
 * CLI-REG-03 (GetEndpoints on the DiscoveryUrls) and CLI-REG-05 (prompted
 * credentials) come with the probe server and the operator hook.
 * SPDX-License-Identifier: MPL-2.0 */
#include <string.h>

#include "client_profile.h"
#include "common/banned.h"

/* The RegisterApplication call of the first cycle that created the record */
static const fg_event *base_register(cli_profile *p, ga_ctx *ctx) {
    const cli_cycle *c = cli_base_cycle(p, ctx);
    if(!c)
        return NULL;
    for(size_t n = 0;; n++) {
        const fg_event *ev = cli_find(c, FG_M_REGISTER, n);
        if(!ev)
            break;
        if(ev->result == UA_STATUSCODE_GOOD)
            return ev;
    }
    ga_not_tested(ctx, "the client registered no record in its first cycle");
    return NULL;
}

static void t_reg_uri(ga_ctx *ctx, void *profile) {
    const fg_event *ev = base_register(profile, ctx);
    if(!ev)
        return;
    const fg_session *s = fg_session_at(ev->session);
    if(!s || !s->certUri[0])
        ga_not_tested(ctx, "no client certificate with a URI on the channel of the call");
    else if(strcmp(s->certUri, ev->appUri) != 0)
        ga_fail(ctx, "record ApplicationUri %s, but the channel certificate says %s", ev->appUri,
                s->certUri);
    else
        ga_pass(ctx, "record and channel certificate both say %s", ev->appUri);
}

static const char *type_name(UA_ApplicationType t) {
    switch(t) {
    case UA_APPLICATIONTYPE_SERVER: return "Server";
    case UA_APPLICATIONTYPE_CLIENT: return "Client";
    case UA_APPLICATIONTYPE_CLIENTANDSERVER: return "ClientAndServer";
    case UA_APPLICATIONTYPE_DISCOVERYSERVER: return "DiscoveryServer";
    case __UA_APPLICATIONTYPE_FORCE32BIT:
    default: return "?";
    }
}

/* The client profile tests a pulling client, so the record has to say
 * Client, or ClientAndServer when it also serves (has DiscoveryUrls). */
static void t_reg_type(ga_ctx *ctx, void *profile) {
    const fg_event *ev = base_register(profile, ctx);
    if(!ev)
        return;
    const char *t = type_name(ev->appType);
    if(ev->appType != UA_APPLICATIONTYPE_CLIENT && ev->appType != UA_APPLICATIONTYPE_CLIENTANDSERVER)
        ga_warn(ctx, "a pulling client registered as %s", t);
    else if(ev->appType == UA_APPLICATIONTYPE_CLIENT && ev->discoveryUrlsN > 0)
        ga_warn(ctx, "registered as Client with %zu DiscoveryUrl(s): it also serves", ev->discoveryUrlsN);
    else if(ev->appType == UA_APPLICATIONTYPE_CLIENTANDSERVER && ev->discoveryUrlsN == 0)
        ga_warn(ctx, "registered as ClientAndServer without a DiscoveryUrl");
    else
        ga_pass(ctx, "%s with %zu DiscoveryUrl(s)", t, ev->discoveryUrlsN);
}

static void t_reg_again(ga_ctx *ctx, void *profile) {
    const cli_cycle *c = cli_shared_cycle(profile, CLI_SHARED_SECOND, ctx);
    if(!c)
        return;
    for(size_t i = c->first; i < c->end; i++) {
        const fg_event *ev = fg_event_at(i);
        if(ev->method != FG_M_REGISTER || ev->result != UA_STATUSCODE_BADENTRYEXISTS)
            continue;
        if(i + 1 < c->end)
            ga_pass(ctx, "Bad_EntryExists from RegisterApplication, and the cycle went on (%s)",
                    fg_method_name(fg_event_at(i + 1)->method));
        else
            ga_warn(ctx, "the cycle stopped on Bad_EntryExists from RegisterApplication");
        return;
    }
    if(cli_count(c, FG_M_REGISTER) == 0)
        ga_pass(ctx, "no second registration (%zu FindApplications)", cli_count(c, FG_M_FIND));
    else
        ga_pass(ctx, "registered again without an error");
}

const ga_test cli_register_tests[] = {
    {"CLI-REG-01", "12 §6.5.5, §6.5.6; 6 §6.2.2", "ApplicationUri of the record matches the certificate", false, true, t_reg_uri},
    {"CLI-REG-02", "12 §6.5.5", "ApplicationType matches what the application is", false, true, t_reg_type},
    {"CLI-REG-04", "12 §6.5.4, §6.5.6", "A second cycle copes with the existing record", false, true, t_reg_again},
};
const size_t cli_register_count = GDS_ARRAY_SIZE(cli_register_tests);
