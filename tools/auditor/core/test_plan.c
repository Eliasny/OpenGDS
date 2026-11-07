/* OpenGDS Auditor - tests of plan files (plan.h): parsing the TOML subset,
 * refusals with a line number, the per-profile keys, save and load round
 * trip, and the command line a plan stands for.
 * SPDX-License-Identifier: MPL-2.0 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "gdsaudit/plan.h"

#include "common/banned.h"

static int failures;

#define CHECK(cond)                                                            \
    do {                                                                       \
        if(!(cond)) {                                                          \
            fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__,   \
                    #cond);                                                    \
            failures++;                                                        \
        }                                                                      \
    } while(0)

static ga_plan *parse(const char *text, char *err, size_t errLen) {
    err[0] = '\0';
    return ga_plan_parse(text, strlen(text), "t.toml", err, errLen);
}

static bool eq(const char *a, const char *b) {
    return a && b && strcmp(a, b) == 0;
}

/* argv joined with single spaces */
static char *joined(char **argv) {
    size_t n = 1;
    for(char **a = argv; *a; a++)
        n += strlen(*a) + 1;
    char *s = calloc(1, n);
    if(!s)
        return NULL;
    size_t k = 0;
    for(char **a = argv; *a; a++) {
        size_t l = strlen(*a);
        if(k)
            s[k++] = ' ';
        memcpy(s + k, *a, l);
        k += l;
    }
    s[k] = '\0';
    return s;
}

static const char serverPlan[] =
    "# a server plan\n"
    "schema = \"gdsaudit-plan\"\n"
    "version = 1\n"
    "profile = \"server\"\n"
    "name = \"Line 3 PLC \\\"fw 2.1\\\" \\u00e4\"   # comment after a value\n"
    "preset = \"full\"\n"
    "\n"
    "[target]\n"
    "url = \"opc.tcp://plc:4840\"\n"
    "server_cert = 'certs/plc.der'\n"
    "trust = [\n"
    "  \"certs/gds-ca.der\",  # the GDS CA\n"
    "  \"/etc/ca2.der\",\n"
    "]\n"
    "crl = [\"certs/gds-ca.crl\"]\n"
    "\n"
    "[identity]\n"
    "work = \"work\"\n"
    "admin_user = \"sysadmin\"\n"
    "admin_password_file = \"secrets/admin.pw\"\n"
    "\n"
    "[tests]\n"
    "allow_changes = true\n"
    "only = \"SRV-TL\"\n"
    "settle_timeout = 30\n"
    "slow = false\n"
    "\n"
    "[report]\n"
    "dir = \"out\"\n"
    "events = \"out/events.jsonl\"\n";

// NOLINTNEXTLINE(readability-function-cognitive-complexity): flat checks
static void server_plan(void) {
    char err[256];
    ga_plan *p = parse(serverPlan, err, sizeof(err));
    if(!p) {
        fprintf(stderr, "server plan: %s\n", err);
        failures++;
        return;
    }
    CHECK(eq(ga_plan_profile(p), "server"));
    CHECK(eq(ga_plan_name(p), "Line 3 PLC \"fw 2.1\" \xc3\xa4"));
    CHECK(eq(ga_plan_preset(p), "full"));
    CHECK(eq(ga_plan_get(p, "target.url", 0), "opc.tcp://plc:4840"));
    CHECK(ga_plan_count(p, "target.trust") == 2);
    CHECK(eq(ga_plan_get(p, "target.trust", 1), "/etc/ca2.der"));
    CHECK(ga_plan_get(p, "target.trust", 2) == NULL);
    CHECK(eq(ga_plan_get(p, "tests.allow_changes", 0), "true"));
    CHECK(eq(ga_plan_get(p, "tests.settle_timeout", 0), "30"));
    CHECK(ga_plan_count(p, "tests.stop_after") == 0);

    /* the command line, paths joined to the plan's folder; false bools
     * give no option */
    int argc = 0;
    char **argv = ga_plan_argv(p, "/plans", &argc);
    char *s = argv ? joined(argv) : NULL;
    CHECK(eq(s, "server --url opc.tcp://plc:4840 --server-cert /plans/certs/plc.der "
                "--target-trust /plans/certs/gds-ca.der --target-trust /etc/ca2.der "
                "--target-crl /plans/certs/gds-ca.crl --work /plans/work "
                "--admin-user sysadmin --admin-password-file /plans/secrets/admin.pw "
                "--allow-changes --only SRV-TL --settle-timeout 30 "
                "--report /plans/out --events /plans/out/events.jsonl"));
    if(s && !strstr(s, "--allow-changes --only"))
        fprintf(stderr, "argv: %s\n", s);
    CHECK(argc == 26);
    free(s);
    free((void *)argv);
    argv = ga_plan_argv(p, NULL, &argc);
    s = argv ? joined(argv) : NULL;
    CHECK(s && strstr(s, " --server-cert certs/plc.der "));
    free(s);
    free((void *)argv);

    /* save and load give the same plan and the same command line */
    char path[] = "/tmp/gdsaudit-plan-XXXXXX";
    int fd = mkstemp(path);
    CHECK(fd >= 0);
    if(fd >= 0)
        close(fd);
    CHECK(ga_plan_save(p, path, err, sizeof(err)));
    ga_plan *q = ga_plan_load(path, err, sizeof(err));
    CHECK(q != NULL);
    if(q) {
        char **a1 = ga_plan_argv(p, "/x", &argc);
        char **a2 = ga_plan_argv(q, "/x", &argc);
        char *s1 = a1 ? joined(a1) : NULL, *s2 = a2 ? joined(a2) : NULL;
        CHECK(eq(s1, s2));
        CHECK(eq(ga_plan_name(q), ga_plan_name(p)));
        CHECK(eq(ga_plan_preset(q), "full"));
        free(s1);
        free(s2);
        free((void *)a1);
        free((void *)a2);
        ga_plan_free(q);
    }
    unlink(path);
    ga_plan_free(p);
}

// NOLINTNEXTLINE(readability-function-cognitive-complexity): flat checks
static void per_profile(void) {
    /* the same key gives the profile's own option */
    ga_plan_type t;
    CHECK(ga_plan_key_type("gds", "target.trust", &t) && t == GA_PLAN_PATHS);
    CHECK(eq(ga_plan_key_option("gds", "target.trust"), "--trust"));
    CHECK(eq(ga_plan_key_option("server", "target.trust"), "--target-trust"));
    CHECK(eq(ga_plan_key_option("gds", "identity.password_file"), "--password-file"));
    CHECK(eq(ga_plan_key_option("server", "identity.password_file"), "--user-password-file"));
    CHECK(eq(ga_plan_key_option("client", "identity.client_user"), "--user"));
    CHECK(eq(ga_plan_key_option("client", "hooks.trigger"), "--"));
    CHECK(!ga_plan_key_type("client", "tests.allow_changes", &t));
    CHECK(!ga_plan_key_type("gds", "target.server_cert", &t));
    CHECK(!ga_plan_key_type("server", "nope", &t));
    CHECK(ga_plan_new("printer") == NULL);

    /* a client plan built through the API, as the UI does */
    ga_plan *p = ga_plan_new("client");
    CHECK(p != NULL);
    if(!p)
        return;
    CHECK(ga_plan_set(p, "target.listen", "4850"));
    CHECK(!ga_plan_set(p, "target.listen", "48a"));       /* not an integer */
    CHECK(!ga_plan_set(p, "target.listen_any", "yes"));   /* not a bool */
    CHECK(!ga_plan_set(p, "tests.allow_changes", "true")); /* not for client */
    CHECK(!ga_plan_set(p, "target.url", "x"));
    CHECK(ga_plan_set(p, "identity.work", "w"));
    CHECK(ga_plan_set(p, "identity.client_user", "registrar"));
    CHECK(ga_plan_set(p, "hooks.trigger", "./pull.sh"));
    CHECK(ga_plan_add(p, "hooks.trigger", "--device"));
    CHECK(ga_plan_add(p, "hooks.trigger", "a b"));
    CHECK(!ga_plan_add(p, "identity.work", "w2")); /* not an array */
    CHECK(ga_plan_set(p, "tests.only", "CLI-CSR"));
    ga_plan_unset(p, "tests.only");
    CHECK(ga_plan_count(p, "tests.only") == 0);
    int argc = 0;
    char **argv = ga_plan_argv(p, "/d", &argc);
    char *s = argv ? joined(argv) : NULL;
    CHECK(eq(s, "client --listen 4850 --work /d/w --user registrar -- /d/./pull.sh --device a b"));
    CHECK(argc == 11 && argv && argv[argc] == NULL && eq(argv[10], "a b"));
    free(s);
    free((void *)argv);

    /* written TOML parses back; strings needing escapes survive */
    CHECK(ga_plan_set_name(p, "tab\there \"q\" back\\slash \x01"));
    char *buf = NULL;
    size_t len = 0;
    FILE *f = open_memstream(&buf, &len);
    CHECK(f && ga_plan_write(p, f));
    if(f)
        fclose(f);
    char err[256];
    ga_plan *q = buf ? ga_plan_parse(buf, len, "mem", err, sizeof(err)) : NULL;
    CHECK(q != NULL);
    if(!q)
        fprintf(stderr, "reparse: %s\n%s\n", err, buf ? buf : "");
    CHECK(q && eq(ga_plan_name(q), "tab\there \"q\" back\\slash \x01"));
    CHECK(q && ga_plan_count(q, "hooks.trigger") == 3 &&
          eq(ga_plan_get(q, "hooks.trigger", 2), "a b"));
    CHECK(buf && strstr(buf, "schema = \"gdsaudit-plan\"\nversion = 1\nprofile = \"client\"\n"));
    CHECK(buf && !strstr(buf, "password ="));
    ga_plan_free(q);
    free(buf);
    ga_plan_free(p);
}

// NOLINTNEXTLINE(readability-function-cognitive-complexity): flat checks
static void refusals(void) {
    static const struct {
        const char *text, *why;
    } bad[] = {
        {"profile = \"server\"\n[target]\nurl = \"a\"\nurl = \"b\"\n", "t.toml:4"}, /* duplicate */
        {"profile = \"server\"\n[target]\nnope = 1\n", "t.toml:3"},
        {"profile = \"server\"\n[target]\nlisten = 1\n", "t.toml:3"},         /* client only */
        {"profile = \"server\"\n[secrets]\n", "t.toml:2"},
        {"profile = \"server\"\n[identity]\npassword = \"x\"\n", "t.toml:3"},  /* never inline */
        {"[target]\nurl = \"a\"\n", "t.toml:1"},                               /* no profile */
        {"profile = \"server\"\nprofile = \"gds\"\n", "t.toml:2"},
        {"profile = \"printer\"\n", "t.toml:1"},
        {"schema = \"other\"\nprofile = \"server\"\n", "t.toml:1"},
        {"version = 2\nprofile = \"server\"\n", "t.toml:1"},
        {"profile = \"server\"\n[tests]\nallow_changes = yes\n", "t.toml:3"},
        {"profile = \"server\"\n[tests]\nsettle_timeout = 1.5\n", "t.toml:3"},
        {"profile = \"server\"\n[tests]\nsettle_timeout = 007\n", "t.toml:3"},
        {"profile = \"server\"\n[tests]\nonly = \"a\" \"b\"\n", "t.toml:3"},
        {"profile = \"server\"\n[tests]\nonly = \"unterminated\n", "t.toml:3"},
        {"profile = \"server\"\n[tests]\nonly = \"\\q\"\n", "t.toml:3"},
        {"profile = \"server\"\n[tests]\nonly = \"\\ud800\"\n", "t.toml:3"},
        {"profile = \"server\"\n[tests]\nonly = \"\"\"multi\"\"\"\n", "t.toml:3"},
        {"profile = \"server\"\n[tests]\nonly = [\"a\"]\n", "t.toml:3"},      /* not an array key */
        {"profile = \"server\"\n[target]\ntrust = \"a\"\n", "t.toml:3"},      /* must be an array */
        {"profile = \"server\"\n[target]\ntrust = [\"a\", 1]\n", "t.toml:3"},
        {"profile = \"server\"\n[target]\ntrust = [\"a\"\n", "t.toml:3"},
        {"profile = \"server\"\n[target.x]\n", "t.toml:2"},
        {"profile = \"server\"\n[[target]]\n", "t.toml:2"},
        {"profile = \"server\"\n[target]\nurl = { a = 1 }\n", "t.toml:3"},
        {"profile = \"server\"\n[target]\nurl = \"a\0b\"\n", "t.toml"},
        {"profile = \"client\"\n[hooks]\ntrigger = []\n", "t.toml:3"},        /* empty command */
        {"profile = \"server\"\n[target]\nurl\n", "t.toml:3"},
    };
    for(size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        char err[256];
        ga_plan *p = parse(bad[i].text, err, sizeof(err));
        if(p) {
            fprintf(stderr, "accepted bad plan %zu:\n%s\n", i, bad[i].text);
            ga_plan_free(p);
            failures++;
        } else if(!strstr(err, bad[i].why)) {
            fprintf(stderr, "plan %zu: error \"%s\" does not name %s\n", i, err, bad[i].why);
            failures++;
        }
    }
    /* an array with too many items, and a too long file */
    char big[4096];
    size_t k = (size_t)snprintf(big, sizeof(big), "profile = \"server\"\n[target]\ntrust = [");
    for(int i = 0; i <= GA_PLAN_MAX_ITEMS; i++)
        k += (size_t)snprintf(big + k, sizeof(big) - k, "\"c%d\",", i);
    snprintf(big + k, sizeof(big) - k, "]\n");
    char err[256];
    ga_plan *p = parse(big, err, sizeof(err));
    CHECK(p == NULL);
    ga_plan_free(p);
    p = ga_plan_parse("profile = \"gds\"\n", GA_PLAN_MAX_FILE + 1, "t.toml", err, sizeof(err));
    CHECK(p == NULL);
    CHECK(ga_plan_load("/nonexistent/plan.toml", err, sizeof(err)) == NULL &&
          strstr(err, "/nonexistent/plan.toml"));
}

int main(void) {
    server_plan();
    per_profile();
    refusals();
    if(failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    printf("plan file tests passed\n");
    return 0;
}
