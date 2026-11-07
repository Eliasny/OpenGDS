/* OpenGDS Auditor client profile - Registration (CLI-REG-*).
 * Rows of docs/auditor/client-profile.md, "Registration (cli_register.c)".
 * SPDX-License-Identifier: MPL-2.0 */
#define _GNU_SOURCE /* memmem */
#include <open62541/client.h>
#include <open62541/client_config_default.h>

#include <ftw.h>
#include <string.h>
#include <sys/stat.h>

#include "client_profile.h"
#include "common/buf.h"
#include "common/limits.h"
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

/* GetEndpoints on one DiscoveryUrl: the ApplicationUri the Server states
 * in its endpoints (copied to `uri`), or an error */
static UA_StatusCode endpoints_uri(const char *url, char *uri, size_t uriLen, size_t *mismatched,
                                   const char *want) {
    UA_Client *c = UA_Client_new();
    if(!c)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    UA_ClientConfig *cc = UA_Client_getConfig(c);
    cc->timeout = 5000;
    size_t n = 0;
    UA_EndpointDescription *eps = NULL;
    UA_StatusCode r = UA_Client_getEndpoints(c, url, &n, &eps);
    *mismatched = 0;
    uri[0] = '\0';
    for(size_t i = 0; r == UA_STATUSCODE_GOOD && i < n; i++) {
        const UA_String *u = &eps[i].server.applicationUri;
        bool same = u->length == strlen(want) && memcmp(u->data, want, u->length) == 0;
        if(!same && (*mismatched)++ == 0) {
            size_t k = u->length < uriLen - 1 ? u->length : uriLen - 1;
            if(k)
                memcpy(uri, u->data, k);
            uri[k] = '\0';
        }
    }
    if(r == UA_STATUSCODE_GOOD && n == 0)
        r = UA_STATUSCODE_BADNOTFOUND;
    UA_Array_delete(eps, n, &UA_TYPES[UA_TYPES_ENDPOINTDESCRIPTION]);
    UA_Client_delete(c);
    return r;
}

/* CLI-REG-03: every DiscoveryUrl of a ClientAndServer record answers
 * GetEndpoints with the record's ApplicationUri (12 §6.5.5) */
static void t_reg_urls(ga_ctx *ctx, void *profile) {
    const fg_event *ev = base_register(profile, ctx);
    if(!ev)
        return;
    if(ev->appType != UA_APPLICATIONTYPE_CLIENTANDSERVER || ev->discoveryUrlsN == 0) {
        ga_not_supported(ctx, "registered as %s without a DiscoveryUrl: nothing to call",
                         type_name(ev->appType));
        return;
    }
    size_t n = ev->discoveryUrlsN < FG_MAX_DURLS ? ev->discoveryUrlsN : FG_MAX_DURLS;
    if(n < ev->discoveryUrlsN)
        ga_note(ctx, "%zu DiscoveryUrls; the first %d are called", ev->discoveryUrlsN, FG_MAX_DURLS);
    size_t silent = 0;
    for(size_t i = 0; i < n; i++) {
        char other[FG_MAX_URI];
        size_t bad = 0;
        UA_StatusCode r = endpoints_uri(ev->discoveryUrls[i], other, sizeof(other), &bad, ev->appUri);
        if(r != UA_STATUSCODE_GOOD) {
            ga_note(ctx, "%s: GetEndpoints -> %s", ev->discoveryUrls[i], UA_StatusCode_name(r));
            silent++;
        } else if(bad) {
            ga_fail(ctx, "%s answers as %s, the record says %s", ev->discoveryUrls[i], other,
                    ev->appUri);
            return;
        }
    }
    if(silent)
        ga_warn(ctx, "%zu of %zu DiscoveryUrl(s) did not answer GetEndpoints", silent, n);
    else
        ga_pass(ctx, "%zu DiscoveryUrl(s) answer GetEndpoints as %s", n, ev->appUri);
}

/* Does any file below `dir` contain `needle`? (nftw walk, no links) */
static struct {
    const char *needle;
    char hit[GDS_MAX_PATH];
} scan;

/* memmem is not in every libc (MinGW) */
static bool find_bytes(const uint8_t *hay, size_t hayLen, const char *needle, size_t n) {
    for(size_t i = 0; n > 0 && i + n <= hayLen; i++)
        if(hay[i] == (uint8_t)needle[0] && memcmp(hay + i, needle, n) == 0)
            return true;
    return false;
}

static int scan_file(const char *path, const struct stat *st, int type, struct FTW *ftw) {
    (void)ftw;
    if(type != FTW_F || !S_ISREG(st->st_mode))
        return 0;
    gds_buf b = {0};
    size_t n = strlen(scan.needle);
    bool found = gds_file_read(path, (size_t)4 * 1024 * 1024, &b) == GDS_OK && b.len >= n &&
                 find_bytes(b.data, b.len, scan.needle, n);
    gds_buf_free_secret(&b);
    if(found && gds_path(scan.hit, sizeof(scan.hit), "%s", path) != GDS_OK)
        scan.hit[0] = '\0';
    return found ? 1 : 0;
}

static bool dir_contains(const char *dir, const char *needle, char *hit, size_t hitLen) {
    scan.needle = needle;
    scan.hit[0] = '\0';
    bool found = nftw(dir, scan_file, 16, FTW_PHYS) == 1;
    if(found && gds_path(hit, hitLen, "%s", scan.hit) != GDS_OK)
        hit[0] = '\0';
    return found;
}

/* CLI-REG-05: credentials an operator typed at the client's prompt in one
 * cycle are not used again in the next (Annex G.1). Anonymous is refused in
 * both cycles so that the client has to authenticate. */
static void t_reg_prompt(ga_ctx *ctx, void *profile) {
    cli_profile *p = profile;
    if(!cli_base_cycle(p, ctx))
        return;
    p->trig.promptUser = FG_OPERATOR_USER;
    p->trig.promptPasswordFile = fg_operator_password_path();
    cli_cycle a, b;
    bool ran = cli_cycle_for(p, FAULT_REFUSE_ANONYMOUS, ctx, &a);
    p->trig.promptUser = NULL;
    p->trig.promptPasswordFile = NULL;
    if(!ran)
        return;
    size_t first, end, used = 0;
    cli_sessions(&a, &first, &end);
    for(size_t i = first; i < end; i++)
        used += strcmp(fg_session_at(i)->user, FG_OPERATOR_USER) == 0;
    if(!used) {
        ga_not_tested(ctx, "the client did not use the credentials typed at its prompt");
        return;
    }
    if(!cli_cycle_for(p, FAULT_REFUSE_ANONYMOUS, ctx, &b))
        return;
    char hit[GDS_MAX_PATH] = "";
    cli_sessions(&b, &first, &end);
    for(size_t i = first; i < end; i++)
        if(strcmp(fg_session_at(i)->user, FG_OPERATOR_USER) == 0) {
            ga_fail(ctx, "the next cycle, without an operator, logged in as %s again: the "
                         "prompted credentials were kept", FG_OPERATOR_USER);
            return;
        }
    if(dir_contains(p->trig.clientDir, fg_operator_password(), hit, sizeof(hit)))
        ga_fail(ctx, "the prompted password is stored in %s", hit);
    else
        ga_pass(ctx, "the prompted credentials were used once, not again and not stored in the "
                     "client directory");
}

const ga_test cli_register_tests[] = {
    {"CLI-REG-01", "12 §6.5.5, §6.5.6; 6 §6.2.2", "ApplicationUri of the record matches the certificate", false, true, t_reg_uri},
    {"CLI-REG-02", "12 §6.5.5", "ApplicationType matches what the application is", false, true, t_reg_type},
    {"CLI-REG-03", "12 §6.5.5", "Every DiscoveryUrl answers with the record's ApplicationUri", false, true, t_reg_urls},
    {"CLI-REG-04", "12 §6.5.4, §6.5.6", "A second cycle copes with the existing record", false, true, t_reg_again},
    {"CLI-REG-05", "12 Annex G.1", "Credentials typed at the prompt are not kept", false, true, t_reg_prompt},
};
const size_t cli_register_count = GDS_ARRAY_SIZE(cli_register_tests);
