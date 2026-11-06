/* OpenGDS Auditor view-model - tests of the plan: presets, checks and the
 * headless command line. No display needed.
 * SPDX-License-Identifier: MPL-2.0 */
#include <glib/gstdio.h>
#include <string.h>
#include <unistd.h>

#include "avm_plan.h"

#include "common/banned.h"

/* Comparisons as functions: keeps comparison operators out of macro
 * arguments, which cppcheck cannot parse without the GLib headers. */
static void eq_str(const char *got, const char *want) {
    if(g_strcmp0(got, want) != 0) {
        g_printerr("expected \"%s\"\n     got \"%s\"\n", want ? want : "(null)",
                   got ? got : "(null)");
        g_test_fail();
    }
}

static char *joined(const AvmPlan *p) {
    GError *e = NULL;
    char **argv = avm_plan_argv(p, "/bin/gdsaudit", "/dev/fd/3", "/r/report", &e);
    g_assert_no_error(e);
    char *s = g_strjoinv(" ", argv);
    g_strfreev(argv);
    return s;
}

// NOLINTNEXTLINE(readability-function-cognitive-complexity): flat checks
static void test_presets(void) {
    AvmPlan p;
    avm_plan_init(&p);
    g_assert_true(p.preset == AVM_PRESET_QUICK);
    g_assert_false(p.allowChanges); /* read-only is the default */
    avm_plan_apply_preset(&p, AVM_PRESET_FULL);
    g_assert_true(p.allowChanges);
    avm_plan_apply_preset(&p, AVM_PRESET_CERT);
    g_assert_true(p.allowChanges);
    eq_str(avm_preset_label(AVM_PRESET_CERT), "Preparation for certification");
    avm_plan_apply_preset(&p, AVM_PRESET_QUICK);
    g_assert_false(p.allowChanges);
    avm_plan_clear(&p);
}

// NOLINTNEXTLINE(readability-function-cognitive-complexity): flat checks
static void test_server(void) {
    AvmPlan p;
    avm_plan_init(&p);
    avm_plan_set(&p.workDir, "/w");
    avm_plan_set(&p.url, "opc.tcp://plc:4840");
    char *m = avm_plan_check(&p);
    g_assert_nonnull(m); /* neither pinned certificate nor trust on first use */
    g_free(m);
    p.tofu = TRUE;
    g_assert_null(avm_plan_check(&p));
    char *s = joined(&p);
    eq_str(s, "/bin/gdsaudit server --events /dev/fd/3 --report /r/report --work /w "
                           "--url opc.tcp://plc:4840 --tofu");
    g_free(s);
    p.tofu = FALSE;
    avm_plan_set(&p.serverCert, "/c/srv.der");
    avm_plan_set(&p.user, "admin");
    m = avm_plan_check(&p);
    g_assert_nonnull(m); /* user without password file */
    g_free(m);
    avm_plan_set(&p.passwordFile, "/c/pw");
    avm_plan_apply_preset(&p, AVM_PRESET_FULL);
    g_assert_null(avm_plan_check(&p));
    s = joined(&p);
    eq_str(s, "/bin/gdsaudit server --events /dev/fd/3 --report /r/report --work /w "
                           "--url opc.tcp://plc:4840 --user admin --password-file /c/pw "
                           "--allow-changes --server-cert /c/srv.der");
    g_free(s);
    avm_plan_set(&p.url, "http://plc");
    m = avm_plan_check(&p);
    g_assert_nonnull(m);
    g_free(m);
    avm_plan_clear(&p);
}

// NOLINTNEXTLINE(readability-function-cognitive-complexity): flat checks
static void test_gds(void) {
    AvmPlan p;
    avm_plan_init(&p);
    p.profile = AVM_PROFILE_GDS;
    avm_plan_set(&p.workDir, "/w");
    avm_plan_set(&p.url, "opc.tcp://gds:58810");
    char *m = avm_plan_check(&p);
    g_assert_nonnull(m); /* the GDS is trusted explicitly */
    g_free(m);
    avm_plan_set(&p.trustFiles, "/a/ca1.der; /a/ca2.der");
    avm_plan_set(&p.crlFile, "/a/ca.crl");
    g_assert_null(avm_plan_check(&p));
    char *s = joined(&p);
    eq_str(s, "/bin/gdsaudit gds --events /dev/fd/3 --report /r/report --work /w "
                           "--url opc.tcp://gds:58810 --trust /a/ca1.der --trust /a/ca2.der "
                           "--crl /a/ca.crl");
    g_free(s);
    avm_plan_clear(&p);
}

// NOLINTNEXTLINE(readability-function-cognitive-complexity): flat checks
static void test_client(void) {
    AvmPlan p;
    avm_plan_init(&p);
    p.profile = AVM_PROFILE_CLIENT;
    avm_plan_set(&p.workDir, "/w");
    g_assert_null(avm_plan_check(&p)); /* no trigger: every test Not tested, allowed */
    avm_plan_apply_preset(&p, AVM_PRESET_CERT);
    char *m = avm_plan_check(&p);
    g_assert_nonnull(m); /* certification preparation needs the hook */
    g_free(m);
    avm_plan_set(&p.triggerCmd, "./start-client.sh 'two words' --x");
    g_assert_null(avm_plan_check(&p));
    char *s = joined(&p);
    /* no --allow-changes: the client profile has no target to change */
    eq_str(s, "/bin/gdsaudit client --events /dev/fd/3 --report /r/report --work /w "
                           "--listen 4850 --user registrar -- ./start-client.sh two words --x");
    g_free(s);
    GError *e = NULL;
    char **argv = avm_plan_argv(&p, "/bin/gdsaudit", "/dev/fd/3", "/r", &e);
    eq_str(argv[14], "two words");
    g_strfreev(argv);
    avm_plan_set(&p.triggerCmd, "unbalanced 'quote");
    m = avm_plan_check(&p);
    g_assert_nonnull(m);
    g_free(m);
    argv = avm_plan_argv(&p, "/bin/gdsaudit", "/dev/fd/3", "/r", &e);
    g_assert_null(argv);
    g_assert_nonnull(e);
    g_error_free(e);
    avm_plan_clear(&p);
}

// NOLINTNEXTLINE(readability-function-cognitive-complexity): flat checks
static void test_thumbprint(void) {
    AvmPlan p;
    avm_plan_init(&p);
    char *path = NULL;
    int fd = g_file_open_tmp("avm-cert-XXXXXX", &path, NULL);
    g_assert_true(fd >= 0);
    close(fd);
    g_assert_true(g_file_set_contents(path, "abc", 3, NULL));
    avm_plan_set(&p.serverCert, path);
    char *t = avm_plan_thumbprint(&p);
    eq_str(t, "A9993E364706816ABA3E25717850C26C9CD0D89D"); /* SHA-1("abc") */
    g_free(t);
    p.tofu = TRUE;
    g_assert_null(avm_plan_thumbprint(&p));
    g_unlink(path);
    g_free(path);
    avm_plan_clear(&p);
}

int main(int argc, char **argv) {
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/avm/plan/presets", test_presets);
    g_test_add_func("/avm/plan/server", test_server);
    g_test_add_func("/avm/plan/gds", test_gds);
    g_test_add_func("/avm/plan/client", test_client);
    g_test_add_func("/avm/plan/thumbprint", test_thumbprint);
    return g_test_run();
}
