/* OpenGDS Auditor view-model - targets: discovery output parsing, saved
 * targets, and (with ENGINE URL arguments) a live discovery through the
 * engine.
 * Usage: test_avm_target [ENGINE URL]
 * SPDX-License-Identifier: MPL-2.0 */
#include <glib/gstdio.h>
#include <string.h>

#include "avm_target.h"

static int failures;

#define CHECK(c)                                                                                   \
    do {                                                                                           \
        if(!(c)) {                                                                                 \
            g_printerr("%s:%d: check failed: %s\n", __FILE__, __LINE__, #c);                       \
            failures++;                                                                            \
        }                                                                                          \
    } while(0)

static gboolean eq(const char *a, const char *b) {
    return a && b && strcmp(a, b) == 0;
}

static const char sample[] =
    "server\turn:x\tPush Server\tserver\topc.tcp://h:4840\n"
    "error\tnetwork\topc.tcp://h:4840\tBadServiceUnsupported\n"
    "endpoint\topc.tcp://h:4840\thttp://opcfoundation.org/UA/SecurityPolicy#None\tnone\t0\tAB\t"
    "anonymous\t/c/AB.der\tsubject=/CN=x\n"
    "endpoint\topc.tcp://h:4840\thttp://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256\tsign"
    "\t20\tAB\tanonymous,username\t/c/AB.der\tsubject=/CN=x\n"
    "endpoint\topc.tcp://h:4840\thttp://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256\t"
    "signandencrypt\t20\tAB\tusername\t/c/AB.der\tsubject=/CN=x\n"
    /* the same endpoint again (a second DiscoveryUrl): left out */
    "endpoint\topc.tcp://h:4840\thttp://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256\t"
    "signandencrypt\t20\tAB\tusername\t/c/AB.der\tsubject=/CN=x\n"
    "endpoint\topc.tcp://h:4840\thttp://opcfoundation.org/UA/SecurityPolicy#Aes256_Sha256_RsaPss"
    "\tsignandencrypt\t999\tAB\t\t\t\n"           /* level out of range: 0 */
    "endpoint\tbad utf8 \xff\tp\tnone\t1\t\t\t\t\n" /* skipped */
    "endpoint\ttoo\tfew\n"                          /* skipped */
    "something else\n\n";

// NOLINTNEXTLINE(readability-function-cognitive-complexity): flat checks
static void parse(void) {
    AvmDiscovery *d = avm_discovery_parse(sample);
    CHECK(d->servers->len == 1 && d->errors->len == 1);
    CHECK(eq(g_ptr_array_index(d->servers, 0), "Push Server (urn:x), server"));
    CHECK(eq(g_ptr_array_index(d->errors, 0),
             "FindServersOnNetwork on opc.tcp://h:4840: BadServiceUnsupported"));
    CHECK(d->endpoints->len == 4);
    if(d->endpoints->len == 4) {
        const AvmEndpoint *e0 = g_ptr_array_index(d->endpoints, 0);
        const AvmEndpoint *e1 = g_ptr_array_index(d->endpoints, 1);
        const AvmEndpoint *e2 = g_ptr_array_index(d->endpoints, 2);
        const AvmEndpoint *e3 = g_ptr_array_index(d->endpoints, 3);
        /* strongest first: level 20 signandencrypt, then level 20 sign */
        CHECK(eq(e0->mode, "signandencrypt") && e0->level == 20);
        CHECK(eq(avm_policy_name(e0->policyUri), "Basic256Sha256"));
        CHECK(eq(e1->mode, "sign") && eq(e1->userTokens, "anonymous,username"));
        CHECK(eq(e2->mode, "signandencrypt") && e2->level == 0 && eq(e2->certFile, ""));
        CHECK(eq(e3->mode, "none"));
        CHECK(eq(e0->certFile, "/c/AB.der") && eq(e0->thumbprint, "AB"));

        AvmPlan p;
        avm_plan_init(&p);
        p.tofu = TRUE;
        avm_plan_use_endpoint(&p, e0);
        CHECK(eq(p.url, "opc.tcp://h:4840") && eq(p.serverCert, "/c/AB.der") && !p.tofu);
        avm_plan_clear(&p);
    }
    avm_discovery_free(d);

    d = avm_discovery_parse(NULL);
    CHECK(d->endpoints->len == 0 && d->servers->len == 0);
    avm_discovery_free(d);
    CHECK(eq(avm_policy_name("http://opcfoundation.org/UA/SecurityPolicy#None"), "None"));
    CHECK(eq(avm_policy_name("plain"), "plain"));
}

// NOLINTNEXTLINE(readability-function-cognitive-complexity): flat checks
static void saved(void) {
    CHECK(avm_target_name_ok("Line 3 PLC"));
    CHECK(avm_target_name_ok("Linja 3 – säädin"));
    CHECK(!avm_target_name_ok(""));
    CHECK(!avm_target_name_ok("a[b]"));
    CHECK(!avm_target_name_ok("tab\there"));
    CHECK(!avm_target_name_ok("bad \xff"));
    char longName[80];
    memset(longName, 'x', sizeof(longName) - 1);
    longName[sizeof(longName) - 1] = '\0';
    CHECK(!avm_target_name_ok(longName));

    char *dir = g_dir_make_tmp("avm-target-XXXXXX", NULL);
    CHECK(dir != NULL);
    if(!dir)
        return;
    char *path = g_build_filename(dir, "sub", "targets.ini", NULL);
    char **names = avm_targets_list(path); /* missing file: empty */
    CHECK(names && g_strv_length(names) == 0);
    g_strfreev(names);

    AvmPlan a, b;
    avm_plan_init(&a);
    avm_plan_set(&a.url, "opc.tcp://plc:4840");
    avm_plan_set(&a.serverCert, "/certs/plc.der");
    avm_plan_set(&a.passwordFile, "/secrets/pw");
    a.profile = AVM_PROFILE_SERVER;
    GError *e = NULL;
    CHECK(avm_target_save(path, "Line 3 PLC", &a, &e));
    g_clear_error(&e);
    avm_plan_set(&a.url, "opc.tcp://gds:4840");
    a.profile = AVM_PROFILE_GDS;
    CHECK(avm_target_save(path, "GDS", &a, NULL));
    CHECK(!avm_target_save(path, "a]b", &a, &e) && e);
    g_clear_error(&e);

    names = avm_targets_list(path);
    CHECK(names && g_strv_length(names) == 2 && eq(names[0], "Line 3 PLC") && eq(names[1], "GDS"));
    g_strfreev(names);

    avm_plan_init(&b);
    CHECK(avm_target_load(path, "Line 3 PLC", &b, NULL));
    CHECK(eq(b.url, "opc.tcp://plc:4840") && eq(b.serverCert, "/certs/plc.der"));
    CHECK(eq(b.passwordFile, "/secrets/pw") && b.profile == AVM_PROFILE_SERVER);
    CHECK(avm_target_load(path, "GDS", &b, NULL) && b.profile == AVM_PROFILE_GDS);
    CHECK(!avm_target_load(path, "nope", &b, &e) && e);
    g_clear_error(&e);

    /* saving again replaces the target */
    avm_plan_set(&a.url, "opc.tcp://gds2:4840");
    CHECK(avm_target_save(path, "GDS", &a, NULL));
    CHECK(avm_target_load(path, "GDS", &b, NULL) && eq(b.url, "opc.tcp://gds2:4840"));

    CHECK(avm_target_delete(path, "Line 3 PLC", NULL));
    names = avm_targets_list(path);
    CHECK(names && g_strv_length(names) == 1 && eq(names[0], "GDS"));
    g_strfreev(names);
    CHECK(!avm_target_delete(path, "Line 3 PLC", &e) && e);
    g_clear_error(&e);

    /* the file never holds a password, only paths */
    char *text = NULL;
    CHECK(g_file_get_contents(path, &text, NULL, NULL));
    CHECK(text && !strstr(text, "password=") && strstr(text, "password_file=/secrets/pw"));
    g_free(text);

    avm_plan_clear(&a);
    avm_plan_clear(&b);
    g_unlink(path);
    char *sub = g_path_get_dirname(path);
    g_rmdir(sub);
    g_free(sub);
    g_rmdir(dir);
    g_free(path);
    g_free(dir);
}

typedef struct {
    GMainLoop *loop;
    guint endpoints;
    gboolean pinned, failed;
} Live;

static void on_live(AvmDiscovery *d, const char *error, gpointer user) {
    Live *l = user;
    if(!d) {
        g_printerr("discovery failed: %s\n", error);
        l->failed = TRUE;
    } else {
        l->endpoints = d->endpoints->len;
        for(guint i = 0; i < d->endpoints->len; i++) {
            const AvmEndpoint *e = g_ptr_array_index(d->endpoints, i);
            if(!strcmp(e->mode, "signandencrypt") && *e->certFile &&
               g_file_test(e->certFile, G_FILE_TEST_IS_REGULAR))
                l->pinned = TRUE;
        }
    }
    g_main_loop_quit(l->loop);
}

/* Live discovery through the engine: endpoints come back and a server
 * certificate is written for pinning. */
static void live(const char *engine, const char *url) {
    char *dir = g_dir_make_tmp("avm-discover-XXXXXX", NULL);
    CHECK(dir != NULL);
    if(!dir)
        return;
    Live l = {g_main_loop_new(NULL, FALSE), 0, FALSE, FALSE};
    avm_discover(engine, url, dir, NULL, on_live, &l);
    g_main_loop_run(l.loop);
    g_main_loop_unref(l.loop);
    CHECK(!l.failed && l.endpoints > 0 && l.pinned);

    /* a URL the engine refuses comes back as an error, not as results */
    l.loop = g_main_loop_new(NULL, FALSE);
    l.failed = FALSE;
    avm_discover(engine, "http://not-opc", dir, NULL, on_live, &l);
    g_main_loop_run(l.loop);
    g_main_loop_unref(l.loop);
    CHECK(l.failed);

    GDir *gd = g_dir_open(dir, 0, NULL);
    const char *name;
    while(gd && (name = g_dir_read_name(gd))) {
        char *f = g_build_filename(dir, name, NULL);
        g_unlink(f);
        g_free(f);
    }
    if(gd)
        g_dir_close(gd);
    g_rmdir(dir);
    g_free(dir);
}

int main(int argc, char **argv) {
    parse();
    saved();
    if(argc == 3)
        live(argv[1], argv[2]);
    if(failures) {
        g_printerr("%d check(s) failed\n", failures);
        return 1;
    }
    g_print("avm target tests passed%s\n", argc == 3 ? " (with live discovery)" : "");
    return 0;
}
