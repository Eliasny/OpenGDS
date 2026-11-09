/* OpenGDS example: an OPC UA application that gets and renews its own
 * certificate and trust list from a GDS with the libgdsclient pull agent
 * (OPC 10000-12 Annex G.1, §7.6; src/client/gdsc_pull_agent.h).
 *
 *   pull_agent --gds URL --trust CA.der [--crl CA.crl] [--gds-uri URI]
 *              --app-uri URI --name NAME --dir DIR
 *              [--user NAME --password-file FILE]
 *
 * One run, as an application would do at start and then every UpdateFrequency.
 * DIR keeps the state between runs, written all at once on change:
 *   cert.der, key.der        the ApplicationInstance Certificate and key (a
 *                            self-signed pair is made on the first run)
 *   issuer<N>.der            its issuer chain once the GDS issued it
 *   app-id, pending-id       the ApplicationId and a pending RequestId
 *   pending-key.der          the key pair of the pending request
 *   trustlist.bin, trustlist-time  the TrustList (binary TrustListDataType)
 * --user is for the first registration only (Annex G.1: ApplicationAdmin
 * rights); its password is read from a file and never stored.
 * SPDX-License-Identifier: MPL-2.0 */
#include <open62541/plugin/create_certificate.h>
#include <open62541/plugin/log_stdout.h>

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "client/gdsc_pull_agent.h"
#include "common/buf.h"
#include "common/limits.h"
#include "common/banned.h"

typedef struct {
    const char *gds, *trust, *crl, *gdsUri, *appUri, *name, *dir, *user, *passwordFile;
} args;

static gds_status file_path(const char *dir, const char *name, char *out, size_t len) {
    return gds_path(out, len, "%s/%s", dir, name);
}

static gds_status read_opt(const char *dir, const char *name, size_t max, gds_buf *out) {
    char p[GDS_MAX_PATH];
    memset(out, 0, sizeof(*out));
    gds_status s = file_path(dir, name, p, sizeof(p));
    if(s != GDS_OK || access(p, F_OK) != 0)
        return s;
    return gds_file_read(p, max, out);
}

static gds_status write_or_remove(const char *dir, const char *name, const void *data, size_t len,
                                  unsigned mode) {
    char p[GDS_MAX_PATH];
    gds_status s = file_path(dir, name, p, sizeof(p));
    if(s != GDS_OK)
        return s;
    if(len == 0)
        return (unlink(p) == 0 || access(p, F_OK) != 0) ? GDS_OK : GDS_EIO;
    return gds_file_write_atomic(p, data, len, mode);
}

static gds_status save_nodeid(const char *dir, const char *name, const UA_NodeId *id) {
    UA_String str = UA_STRING_NULL;
    if(!UA_NodeId_isNull(id) && UA_NodeId_print(id, &str) != UA_STATUSCODE_GOOD)
        return GDS_ENOMEM;
    gds_status s = write_or_remove(dir, name, str.data, str.length, 0600);
    UA_String_clear(&str);
    return s;
}

static gds_status load_nodeid(const char *dir, const char *name, UA_NodeId *id) {
    gds_buf b;
    UA_NodeId_init(id);
    gds_status s = read_opt(dir, name, 512, &b);
    if(s == GDS_OK && b.len > 0) {
        UA_String str = {b.len, b.data};
        s = UA_NodeId_parse(id, str) == UA_STATUSCODE_GOOD ? GDS_OK : GDS_EINVAL;
    }
    gds_buf_free(&b);
    return s;
}

/* The persist callback: every file, at once */
static gds_status persist(void *ctx, const gdsc_pull_state *st) {
    const char *dir = ctx;
    gds_status s = write_or_remove(dir, "cert.der", st->cert.data, st->cert.len, 0644);
    if(s == GDS_OK)
        s = write_or_remove(dir, "key.der", st->key.data, st->key.len, 0600);
    for(size_t i = 0; s == GDS_OK && i < GDS_MAX_CHAIN_LEN; i++) {
        char n[32];
        snprintf(n, sizeof(n), "issuer%zu.der", i);
        s = i < st->issuersN ? write_or_remove(dir, n, st->issuers[i].data, st->issuers[i].len, 0644)
                             : write_or_remove(dir, n, NULL, 0, 0);
    }
    if(s == GDS_OK)
        s = save_nodeid(dir, "app-id", &st->applicationId);
    if(s == GDS_OK)
        s = save_nodeid(dir, "pending-id", &st->pendingRequest);
    if(s == GDS_OK)
        s = write_or_remove(dir, "pending-key.der", st->pendingKey.data, st->pendingKey.len, 0600);
    UA_ByteString tl = UA_BYTESTRING_NULL;
    if(s == GDS_OK && st->trustList.specifiedLists != 0 &&
       UA_encodeBinary(&st->trustList, &UA_TYPES[UA_TYPES_TRUSTLISTDATATYPE], &tl, NULL) !=
           UA_STATUSCODE_GOOD)
        s = GDS_ENOMEM;
    if(s == GDS_OK)
        s = write_or_remove(dir, "trustlist.bin", tl.data, tl.length, 0644);
    UA_ByteString_clear(&tl);
    char t[32];
    int n = snprintf(t, sizeof(t), "%" PRId64, (int64_t)st->trustListTime);
    if(s == GDS_OK)
        s = write_or_remove(dir, "trustlist-time", t, (size_t)n, 0644);
    return s;
}

static gds_status load(const args *a, gdsc_pull_state *st) {
    memset(st, 0, sizeof(*st));
    gds_status s = read_opt(a->dir, "cert.der", GDS_MAX_CERT_SIZE, &st->cert);
    if(s == GDS_OK)
        s = read_opt(a->dir, "key.der", GDS_MAX_KEY_SIZE, &st->key);
    if(s == GDS_OK && st->cert.len == 0) {
        /* first run: the application's own self-signed certificate */
        char san[GDS_MAX_APPLICATION_URI + 8], cn[96];
        UA_ByteString key = UA_BYTESTRING_NULL, cert = UA_BYTESTRING_NULL;
        if(gds_path(san, sizeof(san), "URI:%s", a->appUri) != GDS_OK ||
           gds_path(cn, sizeof(cn), "CN=%.64s", a->name) != GDS_OK)
            return GDS_EINVAL;
        UA_String subject[1] = {UA_STRING(cn)}, sans[1] = {UA_STRING(san)};
        if(UA_CreateCertificate(UA_Log_Stdout, subject, 1, sans, 1, UA_CERTIFICATEFORMAT_DER,
                                NULL, &key, &cert) != UA_STATUSCODE_GOOD)
            return GDS_ECRYPTO;
        gds_buf_free_secret(&st->key);
        s = gds_buf_dup(cert.data, cert.length, &st->cert);
        if(s == GDS_OK)
            s = gds_buf_dup(key.data, key.length, &st->key);
        UA_ByteString_clear(&cert);
        UA_ByteString_clear(&key);
        printf("created a self-signed certificate for %s\n", a->appUri);
    }
    for(size_t i = 0; s == GDS_OK && i < GDS_MAX_CHAIN_LEN; i++) {
        char n[32];
        snprintf(n, sizeof(n), "issuer%zu.der", i);
        s = read_opt(a->dir, n, GDS_MAX_CERT_SIZE, &st->issuers[i]);
        if(s != GDS_OK || st->issuers[i].len == 0)
            break;
        st->issuersN = i + 1;
    }
    if(s == GDS_OK)
        s = load_nodeid(a->dir, "app-id", &st->applicationId);
    if(s == GDS_OK)
        s = load_nodeid(a->dir, "pending-id", &st->pendingRequest);
    if(s == GDS_OK)
        s = read_opt(a->dir, "pending-key.der", GDS_MAX_KEY_SIZE, &st->pendingKey);
    gds_buf b = {0};
    if(s == GDS_OK)
        s = read_opt(a->dir, "trustlist.bin", GDS_MAX_TRUSTLIST_SIZE, &b);
    if(s == GDS_OK && b.len > 0) {
        UA_ByteString bs = {b.len, b.data};
        s = UA_decodeBinary(&bs, &st->trustList, &UA_TYPES[UA_TYPES_TRUSTLISTDATATYPE], NULL) ==
                    UA_STATUSCODE_GOOD
                ? GDS_OK
                : GDS_EINVAL;
    }
    gds_buf_free(&b);
    if(s == GDS_OK)
        s = read_opt(a->dir, "trustlist-time", 32, &b);
    if(s == GDS_OK && b.len > 0) {
        char t[33];
        memcpy(t, b.data, b.len);
        t[b.len] = '\0';
        st->trustListTime = (UA_DateTime)strtoll(t, NULL, 10);
    }
    gds_buf_free(&b);
    return s;
}

static bool parse(int argc, char **argv, args *a) {
    memset(a, 0, sizeof(*a));
    for(int i = 1; i + 1 < argc; i += 2) {
        const struct {
            const char *opt;
            const char **v;
        } o[] = {{"--gds", &a->gds},       {"--trust", &a->trust},   {"--crl", &a->crl},
                 {"--gds-uri", &a->gdsUri}, {"--app-uri", &a->appUri}, {"--name", &a->name},
                 {"--dir", &a->dir},       {"--user", &a->user},
                 {"--password-file", &a->passwordFile}};
        size_t k = 0;
        while(k < GDS_ARRAY_SIZE(o) && strcmp(argv[i], o[k].opt) != 0)
            k++;
        if(k == GDS_ARRAY_SIZE(o) || *o[k].v)
            return false;
        *o[k].v = argv[i + 1];
    }
    return argc % 2 == 1 && a->gds && a->trust && a->appUri && a->name && a->dir &&
           !a->user == !a->passwordFile && strlen(a->appUri) < GDS_MAX_APPLICATION_URI;
}

int main(int argc, char **argv) {
    args a;
    if(!parse(argc, argv, &a)) {
        fprintf(stderr, "usage: pull_agent --gds URL --trust CA.der [--crl CA.crl] [--gds-uri URI]\n"
                        "                  --app-uri URI --name NAME --dir DIR\n"
                        "                  [--user NAME --password-file FILE]\n");
        return 2;
    }
    gds_buf trust = {0}, crl = {0}, password = {0};
    gdsc_pull_state st;
    memset(&st, 0, sizeof(st));
    gds_status s = gds_mkdirs(a.dir, 0700);
    if(s == GDS_OK)
        s = gds_file_read(a.trust, GDS_MAX_CERT_SIZE, &trust);
    if(s == GDS_OK && a.crl)
        s = gds_file_read(a.crl, GDS_MAX_CRL_SIZE, &crl);
    if(s == GDS_OK && a.passwordFile) {
        s = gds_file_read(a.passwordFile, GDS_MAX_STRING, &password);
        while(s == GDS_OK && password.len > 0 && password.data[password.len - 1] == '\n')
            password.len--;
    }
    if(s == GDS_OK)
        s = load(&a, &st);
    if(s != GDS_OK) {
        fprintf(stderr, "pull_agent: reading the files: %s\n", gds_status_name(s));
        return 1;
    }
    UA_String url = UA_STRING("opc.tcp://localhost:4840");
    UA_LocalizedText name = UA_LOCALIZEDTEXT("en", (char *)(uintptr_t)a.name);
    UA_ApplicationRecordDataType rec;
    UA_ApplicationRecordDataType_init(&rec);
    rec.applicationUri = UA_STRING((char *)(uintptr_t)a.appUri);
    rec.applicationType = UA_APPLICATIONTYPE_SERVER;
    rec.applicationNames = &name;
    rec.applicationNamesSize = 1;
    rec.productUri = UA_STRING("urn:opengds:example:pull-agent");
    rec.discoveryUrls = &url;
    rec.discoveryUrlsSize = 1;
    gdsc_pull_cfg c;
    memset(&c, 0, sizeof(c));
    c.gdsUrl = a.gds;
    c.gdsUri = a.gdsUri;
    c.trust = &trust;
    c.trustN = 1;
    c.crls = &crl;
    c.crlN = a.crl ? 1 : 0;
    c.record = &rec;
    c.userName = a.user;
    c.password = a.user ? &password : NULL;
    c.persist = persist;
    c.persistCtx = (void *)(uintptr_t)a.dir;
    gdsc_pull_result res;
    UA_StatusCode r = gdsc_pull_agent_run(&c, &st, &res);
    if(res.registered)
        printf("registered %s\n", a.appUri);
    printf("update required: %s\n", res.updateRequired ? "yes" : "no");
    if(res.certificateIssued)
        printf("certificate issued\n");
    if(res.pending)
        printf("signing request pending; run again later\n");
    if(res.trustListDownloaded)
        printf("trust list updated (%zu trusted certificates)\n",
               st.trustList.trustedCertificatesSize);
    if(res.nextRunMs > 0)
        printf("next run in %.0f ms (UpdateFrequency)\n", res.nextRunMs);
    gdsc_pull_state_clear(&st);
    gds_buf_free(&trust);
    gds_buf_free(&crl);
    gds_buf_free_secret(&password);
    if(r != UA_STATUSCODE_GOOD) {
        fprintf(stderr, "pull_agent: failed at %s: %s\n", gdsc_pull_step_name(res.failedStep),
                UA_StatusCode_name(r));
        return 1;
    }
    printf("PULL AGENT OK\n");
    return 0;
}
