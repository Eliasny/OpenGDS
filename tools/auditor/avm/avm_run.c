/* OpenGDS Auditor view-model - one live run of the headless engine.
 * SPDX-License-Identifier: MPL-2.0 */
#include "avm_run.h"

#include <gio/gunixinputstream.h>
#include <errno.h>
#include <glib/gstdio.h>
#include <glib-unix.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

#include "common/banned.h"

struct AvmRun {
    GSubprocess *proc;
    GCancellable *cancel;
    GDataInputStream *events, *output;
    FILE *eventsCopy, *outputCopy;
    char *dir;
    ga_results results;
    AvmRunCallbacks cb;
    void *user;
    gboolean exited, eventsDone, outputDone, reported;
    int exitCode;
    char *error;
};

static void maybe_finished(AvmRun *r) {
    if(r->reported || !r->exited || !r->eventsDone || !r->outputDone)
        return;
    r->reported = TRUE;
    if(r->eventsCopy) {
        fclose(r->eventsCopy);
        r->eventsCopy = NULL;
    }
    if(r->outputCopy) {
        fclose(r->outputCopy);
        r->outputCopy = NULL;
    }
    if(r->cb.finished)
        r->cb.finished(r, r->exitCode, r->error, r->user);
}

static void set_error(AvmRun *r, const char *msg) {
    if(!r->error)
        r->error = g_strdup(msg);
}

static void handle_event_line(AvmRun *r, const char *line, gsize len) {
    if(r->eventsCopy) {
        fwrite(line, 1, len, r->eventsCopy);
        fputc('\n', r->eventsCopy);
        fflush(r->eventsCopy);
    }
    ga_event ev;
    ga_jsonl_strings strs;
    int p = ga_jsonl_parse(line, len, &ev, &strs);
    if(p < 0)
        set_error(r, "the engine sent a line that is not an Auditor event");
    else if(p > 0 && !ga_results_apply(&r->results, &ev))
        set_error(r, "the engine's event stream is out of range");
    else if(p > 0 && r->cb.event)
        r->cb.event(r, &ev, r->user);
    ga_jsonl_strings_free(&strs);
}

static void read_events(AvmRun *r);
static void read_output(AvmRun *r);

static void on_event_line(GObject *src, GAsyncResult *res, gpointer data) {
    GError *e = NULL;
    gsize len = 0;
    char *line = g_data_input_stream_read_line_finish_utf8(G_DATA_INPUT_STREAM(src), res, &len, &e);
    if(g_error_matches(e, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
        g_error_free(e);
        return; /* freed: data is gone */
    }
    AvmRun *r = data;
    if(e || !line) {
        if(e)
            set_error(r, e->message);
        g_clear_error(&e);
        r->eventsDone = TRUE;
        maybe_finished(r);
        return;
    }
    if(len > GA_MAX_LINE)
        set_error(r, "the engine sent an event line that is too long");
    else
        handle_event_line(r, line, len);
    g_free(line);
    read_events(r);
}

static void read_events(AvmRun *r) {
    g_data_input_stream_read_line_async(r->events, G_PRIORITY_DEFAULT, r->cancel, on_event_line, r);
}

static void on_output_line(GObject *src, GAsyncResult *res, gpointer data) {
    GError *e = NULL;
    gsize len = 0;
    char *line = g_data_input_stream_read_line_finish(G_DATA_INPUT_STREAM(src), res, &len, &e);
    if(g_error_matches(e, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
        g_error_free(e);
        return;
    }
    AvmRun *r = data;
    g_clear_error(&e);
    if(!line) {
        r->outputDone = TRUE;
        maybe_finished(r);
        return;
    }
    if(r->outputCopy) {
        fwrite(line, 1, len, r->outputCopy);
        fputc('\n', r->outputCopy);
        fflush(r->outputCopy);
    }
    /* the log view needs UTF-8; the TAP evidence may not be */
    char *valid = g_utf8_make_valid(line, (gssize)len);
    if(r->cb.log)
        r->cb.log(r, valid, r->user);
    g_free(valid);
    g_free(line);
    read_output(r);
}

static void read_output(AvmRun *r) {
    g_data_input_stream_read_line_async(r->output, G_PRIORITY_DEFAULT, r->cancel, on_output_line,
                                        r);
}

static void on_exit(GObject *src, GAsyncResult *res, gpointer data) {
    GError *e = NULL;
    gboolean ok = g_subprocess_wait_finish(G_SUBPROCESS(src), res, &e);
    if(g_error_matches(e, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
        g_error_free(e);
        return;
    }
    AvmRun *r = data;
    if(!ok)
        set_error(r, e ? e->message : "lost the engine process");
    g_clear_error(&e);
    r->exited = TRUE;
    r->exitCode = g_subprocess_get_if_exited(r->proc) ? g_subprocess_get_exit_status(r->proc) : -1;
    maybe_finished(r);
}

static GDataInputStream *line_reader(GInputStream *in) {
    GDataInputStream *d = g_data_input_stream_new(in);
    g_data_input_stream_set_newline_type(d, G_DATA_STREAM_NEWLINE_TYPE_LF);
    return d;
}

static FILE *open_in(const char *dir, const char *name) {
    char *path = g_build_filename(dir, name, NULL);
    FILE *f = g_fopen(path, "w");
    g_free(path);
    return f;
}

AvmRun *avm_run_start(char **argv, const char *runDir, const AvmRunCallbacks *cb, void *user,
                      GError **error) {
    if(g_mkdir_with_parents(runDir, 0700) != 0) {
        g_set_error(error, G_FILE_ERROR, (gint)g_file_error_from_errno(errno), "cannot create %s",
                    runDir);
        return NULL;
    }
    int fds[2];
    if(!g_unix_open_pipe(fds, FD_CLOEXEC, error))
        return NULL;
    /* GSubprocessFlags is a flags enum: OR-ing its values is how GIO is used */
    GSubprocessFlags flags = G_SUBPROCESS_FLAGS_STDOUT_PIPE | G_SUBPROCESS_FLAGS_STDERR_MERGE | // NOLINT(clang-analyzer-optin.core.EnumCastOutOfRange)
                             G_SUBPROCESS_FLAGS_STDIN_INHERIT;
    GSubprocessLauncher *l = g_subprocess_launcher_new(flags);
    g_subprocess_launcher_take_fd(l, fds[1], 3); /* the child's --events /dev/fd/3 */
    GSubprocess *proc = g_subprocess_launcher_spawnv(l, (const char *const *)argv, error);
    g_object_unref(l); /* closes our copy of the write end */
    if(!proc) {
        close(fds[0]);
        return NULL;
    }
    AvmRun *r = g_new0(AvmRun, 1);
    r->proc = proc;
    r->cancel = g_cancellable_new();
    r->dir = g_strdup(runDir);
    r->cb = *cb;
    r->user = user;
    r->eventsCopy = open_in(runDir, "events.jsonl");
    r->outputCopy = open_in(runDir, "output.log");
    GInputStream *evIn = g_unix_input_stream_new(fds[0], TRUE);
    r->events = line_reader(evIn);
    g_object_unref(evIn);
    r->output = line_reader(g_subprocess_get_stdout_pipe(proc));
    read_events(r);
    read_output(r);
    g_subprocess_wait_async(proc, r->cancel, on_exit, r);
    return r;
}

void avm_run_abort(AvmRun *run) {
    if(run && !run->exited)
        g_subprocess_send_signal(run->proc, SIGINT);
}

gboolean avm_run_is_running(const AvmRun *run) {
    return run && !run->reported;
}

const ga_results *avm_run_results(const AvmRun *run) {
    return &run->results;
}

const char *avm_run_dir(const AvmRun *run) {
    return run->dir;
}

void avm_run_free(AvmRun *run) {
    if(!run)
        return;
    g_cancellable_cancel(run->cancel);
    if(!run->exited)
        g_subprocess_force_exit(run->proc);
    g_clear_object(&run->events);
    g_clear_object(&run->output);
    g_clear_object(&run->proc);
    g_clear_object(&run->cancel);
    if(run->eventsCopy)
        fclose(run->eventsCopy);
    if(run->outputCopy)
        fclose(run->outputCopy);
    ga_results_free(&run->results);
    g_free(run->dir);
    g_free(run->error);
    g_free(run);
}

char *avm_engine_path(void) {
    const char *env = g_getenv("GDSAUDIT_ENGINE");
    if(env && *env)
        return g_strdup(env);
    char *self = g_file_read_link("/proc/self/exe", NULL);
    char *dir = self ? g_path_get_dirname(self) : g_strdup(".");
    char *path = g_build_filename(dir, "gdsaudit", NULL);
    g_free(dir);
    g_free(self);
    return path;
}

char *avm_new_run_dir(const char *profile) {
    GDateTime *now = g_date_time_new_now_utc();
    char *stamp = g_date_time_format(now, "%Y%m%d-%H%M%S");
    g_date_time_unref(now);
    char *name = g_strdup_printf("%s-%s", stamp, profile);
    char *dir = g_build_filename(g_get_user_data_dir(), "gdsaudit", "runs", name, NULL);
    /* two runs in the same second get their own folder */
    for(unsigned i = 2; g_file_test(dir, G_FILE_TEST_EXISTS) && i < 100; i++) {
        g_free(dir);
        char *n2 = g_strdup_printf("%s-%u", name, i);
        dir = g_build_filename(g_get_user_data_dir(), "gdsaudit", "runs", n2, NULL);
        g_free(n2);
    }
    g_free(name);
    g_free(stamp);
    return dir;
}

gboolean avm_run_export(const AvmRun *run, const char *dir, GError **error) {
    char err[512];
    if(!ga_report_write_dir(dir, &run->results, err, sizeof(err))) {
        g_set_error(error, G_FILE_ERROR, G_FILE_ERROR_FAILED, "%s", err);
        return FALSE;
    }
    char *from = g_build_filename(run->dir, "events.jsonl", NULL);
    char *to = g_build_filename(dir, "events.jsonl", NULL);
    GFile *src = g_file_new_for_path(from), *dst = g_file_new_for_path(to);
    gboolean ok = g_file_copy(src, dst, G_FILE_COPY_OVERWRITE, NULL, NULL, NULL, error);
    g_object_unref(src);
    g_object_unref(dst);
    g_free(from);
    g_free(to);
    return ok;
}
