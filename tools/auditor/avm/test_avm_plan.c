/* OpenGDS Auditor view-model - tests of the plan: presets, checks and the
 * headless command line. No display needed.
 * SPDX-License-Identifier: MPL-2.0 */
#include <glib/gstdio.h>
#include <string.h>
#include <unistd.h>

#include <stdlib.h>

#include "avm_plan.h"
#include "avm_target.h"

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
    g_assert_false(p.slow);
    avm_plan_apply_preset(&p, AVM_PRESET_FULL);
    g_assert_true(p.allowChanges);
    g_assert_true(p.slow); /* a full run is every test */
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
    eq_str(s, "/bin/gdsaudit server --events /dev/fd/3 --report /r/report "
                           "--url opc.tcp://plc:4840 --tofu --work /w");
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
    eq_str(s, "/bin/gdsaudit server --events /dev/fd/3 --report /r/report "
                           "--url opc.tcp://plc:4840 --server-cert /c/srv.der --work /w "
                           "--user admin --user-password-file /c/pw --allow-changes --slow");
    g_free(s);
    avm_plan_set(&p.adminCert, "/c/a.der");
    m = avm_plan_check(&p);
    g_assert_nonnull(m); /* certificate without key */
    g_free(m);
    avm_plan_set(&p.adminKey, "/c/a.key");
    g_assert_null(avm_plan_check(&p));
    s = joined(&p);
    eq_str(s, "/bin/gdsaudit server --events /dev/fd/3 --report /r/report "
              "--url opc.tcp://plc:4840 --server-cert /c/srv.der --work /w --admin-cert /c/a.der "
              "--admin-key /c/a.key --user admin --user-password-file /c/pw --allow-changes --slow");
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
    eq_str(s, "/bin/gdsaudit gds --events /dev/fd/3 --report /r/report "
                           "--url opc.tcp://gds:58810 --trust /a/ca1.der --trust /a/ca2.der "
                           "--crl /a/ca.crl --work /w");
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
    /* no --allow-changes: the client profile has no target to change; the
     * trigger's program is a path, made absolute as in a plan file */
    char *cwd = g_get_current_dir();
    char *want = g_strdup_printf("/bin/gdsaudit client --events /dev/fd/3 --report /r/report "
                                 "--listen 4850 --work /w --user registrar -- %s%sstart-client.sh "
                                 "two words --x",
                                 cwd, g_str_has_suffix(cwd, "/") ? "" : "/");
    eq_str(s, want);
    g_free(want);
    g_free(cwd);
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

/* The run's command line without the program, --events and --report:
 * what the plan file stands for. */
static char *plan_part(const AvmPlan *p) {
    GError *e = NULL;
    char **argv = avm_plan_argv(p, "/bin/gdsaudit", "", "", &e);
    g_assert_no_error(e);
    char *s = g_strjoinv(" ", argv + 1);
    g_strfreev(argv);
    return s;
}

/* The AT5 gate: a plan saved from the form runs headless with exactly the
 * command line the UI runs (gdsaudit run executes ga_plan_argv). */
static void same_run(const AvmPlan *p, const char *path) {
    GError *e = NULL;
    g_assert_true(avm_plan_save_file(p, path, &e));
    g_assert_no_error(e);
    char err[256];
    ga_plan *g = ga_plan_load(path, err, sizeof(err));
    g_assert_nonnull(g);
    char *dir = g_path_get_dirname(path);
    char **headless = ga_plan_argv(g, dir, NULL);
    char *h = g_strjoinv(" ", headless);
    char *ui = plan_part(p);
    eq_str(h, ui);
    g_free(ui);
    g_free(h);
    free((void *)headless);
    g_free(dir);
    ga_plan_free(g);
}

// NOLINTNEXTLINE(readability-function-cognitive-complexity): flat checks
static void test_plan_files(void) {
    char *dir = g_dir_make_tmp("avm-plan-XXXXXX", NULL);
    char *path = g_build_filename(dir, "sub", "plan.toml", NULL);
    GError *e = NULL;

    /* gds: preset, trust list */
    AvmPlan p, q;
    avm_plan_init(&p);
    p.profile = AVM_PROFILE_GDS;
    avm_plan_apply_preset(&p, AVM_PRESET_CERT);
    avm_plan_set(&p.workDir, "/w");
    avm_plan_set(&p.url, "opc.tcp://gds:58810");
    avm_plan_set(&p.trustFiles, "/a/ca1.der;/a/ca2.der");
    avm_plan_set(&p.name, "Line 3 GDS");
    same_run(&p, path);
    avm_plan_init(&q);
    g_assert_true(avm_plan_load(&q, path, &e));
    g_assert_no_error(e);
    g_assert_true(q.profile == AVM_PROFILE_GDS && q.preset == AVM_PRESET_CERT && q.allowChanges);
    eq_str(q.url, "opc.tcp://gds:58810");
    eq_str(q.trustFiles, "/a/ca1.der;/a/ca2.der");
    eq_str(q.name, "Line 3 GDS");
    avm_plan_clear(&q);
    avm_plan_clear(&p);

    /* client: the trigger keeps its words */
    avm_plan_init(&p);
    p.profile = AVM_PROFILE_CLIENT;
    p.listenPort = 4999;
    avm_plan_set(&p.workDir, "/w");
    avm_plan_set(&p.triggerCmd, "/opt/start 'two words'");
    same_run(&p, path);
    avm_plan_init(&q);
    g_assert_true(avm_plan_load(&q, path, &e));
    g_assert_true(q.profile == AVM_PROFILE_CLIENT && q.listenPort == 4999);
    eq_str(q.triggerCmd, "/opt/start 'two words'");
    eq_str(q.clientUser, "registrar");
    avm_plan_clear(&q);
    avm_plan_clear(&p);

    /* server, written by hand: relative paths are the plan's folder's;
     * keys the form has no field for are kept and run; the UI's own
     * per-run keys are not taken */
    const char *text = "schema = \"gdsaudit-plan\"\nversion = 1\nprofile = \"server\"\n"
                       "preset = \"full\"\n[target]\nurl = \"opc.tcp://plc:4840\"\n"
                       "server_cert = \"certs/plc.der\"\ntrust = [\"certs/ca.der\"]\n"
                       "[identity]\nwork = \"work\"\n[tests]\nallow_changes = true\nslow = true\n"
                       "only = \"SRV-TL\"\nsettle_timeout = 30\n"
                       "[hooks]\nrestart_cmd = \"sh restart.sh\"\nprompts = \"answers.txt\"\n"
                       "[report]\ndir = \"out\"\n";
    g_assert_true(g_file_set_contents(path, text, -1, NULL));
    avm_plan_init(&q);
    g_assert_true(avm_plan_load(&q, path, &e));
    char *sub = g_path_get_dirname(path);
    char *cert = g_build_filename(sub, "certs", "plc.der", NULL);
    eq_str(q.serverCert, cert);
    eq_str(q.restartCmd, "sh restart.sh");
    g_assert_true(q.preset == AVM_PRESET_FULL && q.allowChanges && q.slow && !q.tofu);
    char *s = plan_part(&q);
    char *ca = g_build_filename(sub, "certs", "ca.der", NULL);
    char *work = g_build_filename(sub, "work", NULL);
    char *want = g_strdup_printf("server --url opc.tcp://plc:4840 --server-cert %s "
                                 "--target-trust %s --work %s --allow-changes --only SRV-TL "
                                 "--slow --settle-timeout 30 --restart-cmd sh restart.sh",
                                 cert, ca, work);
    eq_str(s, want);
    g_assert_null(strstr(s, "--prompts"));
    g_assert_null(strstr(s, "--report"));
    g_free(want);
    g_free(s);
    /* saved again (to another folder) it still runs the same */
    char *other = g_build_filename(dir, "elsewhere.toml", NULL);
    same_run(&q, other);
    g_unlink(other);
    g_free(other);
    /* and a saved target keeps the extra keys */
    char *ini = g_build_filename(dir, "targets.ini", NULL);
    g_assert_true(avm_target_save(ini, "PLC", &q, &e));
    avm_plan_init(&p);
    g_assert_true(avm_target_load(ini, "PLC", &p, &e));
    g_assert_no_error(e);
    char *s2 = plan_part(&p);
    s = plan_part(&q);
    eq_str(s2, s);
    g_free(s);
    g_free(s2);
    g_unlink(ini);
    g_free(ini);
    avm_plan_clear(&p);
    g_free(ca);
    g_free(work);
    g_free(cert);
    avm_plan_clear(&q);

    /* errors name the line; the form is kept */
    g_assert_true(g_file_set_contents(path, "profile = \"server\"\n[target]\npasword = 1\n", -1,
                                      NULL));
    avm_plan_init(&q);
    g_assert_false(avm_plan_load(&q, path, &e));
    g_assert_nonnull(e);
    g_assert_nonnull(strstr(e->message, ":3"));
    g_clear_error(&e);
    eq_str(q.url, "opc.tcp://localhost:4840");
    avm_plan_clear(&q);
    g_unlink(path);
    g_rmdir(sub);
    g_free(sub);

    /* the form kept before plan files: last-plan.ini is read once */
    char *last = g_build_filename(dir, "last-plan.toml", NULL);
    char *old = g_build_filename(dir, "last-plan.ini", NULL);
    g_assert_true(g_file_set_contents(old, "[plan]\nprofile=gds\nurl=opc.tcp://old:1\n", -1,
                                      NULL));
    avm_plan_init(&q);
    g_assert_true(avm_plan_load(&q, last, &e));
    g_assert_true(q.profile == AVM_PROFILE_GDS);
    eq_str(q.url, "opc.tcp://old:1");
    g_assert_true(avm_plan_save(&q, last, &e));
    avm_plan_clear(&q);
    g_assert_true(g_file_test(last, G_FILE_TEST_EXISTS));
    g_unlink(last);
    g_unlink(old);
    g_free(last);
    g_free(old);
    g_rmdir(dir);
    g_free(path);
    g_free(dir);
}

int main(int argc, char **argv) {
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/avm/plan/presets", test_presets);
    g_test_add_func("/avm/plan/server", test_server);
    g_test_add_func("/avm/plan/gds", test_gds);
    g_test_add_func("/avm/plan/client", test_client);
    g_test_add_func("/avm/plan/thumbprint", test_thumbprint);
    g_test_add_func("/avm/plan/files", test_plan_files);
    return g_test_run();
}
