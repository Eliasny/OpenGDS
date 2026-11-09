/* OpenGDS Auditor view-model - one live run of the headless engine.
 * SPDX-License-Identifier: MPL-2.0 */
#include "avm_run.h"

#include <errno.h>
#include <glib/gstdio.h>
#include <string.h>
#ifdef G_OS_WIN32
/* No fds 3 and 4 to hand a child, and no signals: named pipes carry the
 * events and the answers, and named events pause, resume and abort the
 * engine (its --control option). */
#include <gio/gwin32inputstream.h>
#include <windows.h>
#else
#include <gio/gunixinputstream.h>
#include <glib-unix.h>
#include <signal.h>
#include <unistd.h>
#endif

#include "common/banned.h"

struct AvmRun {
    GSubprocess *proc;
    GCancellable *cancel;
    GDataInputStream *events, *output;
    int answerFd;      /* write end of the engine's --prompts pipe, or -1 */
    size_t pendingSeq; /* the prompt the engine waits on, or 0 */
    FILE *eventsCopy, *outputCopy;
    char *dir;
    ga_results results;
    AvmRunCallbacks cb;
    void *user;
    gboolean exited, eventsDone, outputDone, reported;
    guint replaySource; /* avm_run_open: the pending replay */
    int exitCode;
    char *error;
#ifdef G_OS_WIN32
    HANDLE answerPipe;  /* the engine's --prompts pipe (answerFd is unused) */
    HANDLE control[3];  /* pause, resume, abort (the engine's --control) */
    struct pipe_connect *connecting; /* pipes the engine has not opened yet */
#endif
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
    else if(p > 0) {
        if(ev.kind == GA_EV_PROMPT)
            r->pendingSeq = ev.seq;
        else if(ev.kind == GA_EV_PROMPT_ANSWERED && ev.seq == r->pendingSeq)
            r->pendingSeq = 0;
        if(r->cb.event)
            r->cb.event(r, &ev, r->user);
    }
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

static void close_answers(AvmRun *r) {
#ifdef G_OS_WIN32
    if(r->answerPipe)
        CloseHandle(r->answerPipe); /* the engine reads end of file: no more answers */
    r->answerPipe = NULL;
#else
    if(r->answerFd >= 0)
        close(r->answerFd); /* the engine reads end of file: no more answers */
#endif
    r->answerFd = -1;
    r->pendingSeq = 0;
}

#ifdef G_OS_WIN32
static void cancel_connect(AvmRun *r);
#endif

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
#ifdef G_OS_WIN32
    cancel_connect(r); /* an engine that never opened its pipes */
#endif
    close_answers(r);
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

/* argv with "--prompts PROMPTS" (and on Windows "--control CONTROL") after
 * the profile name, before any "--" and the client profile's trigger
 * command. events, if not NULL, replaces the AVM_EVENTS_FD after
 * "--events". Only the array is new: g_free it, not its strings. */
static char **engine_argv(char **argv, char *prompts, char *control,
                          char *events) {
    GPtrArray *a = g_ptr_array_new();
    gboolean rest = FALSE;
    for(guint i = 0; argv[i]; i++) {
        rest = rest || !strcmp(argv[i], "--");
        if(events && !rest && i > 0 && !strcmp(argv[i - 1], "--events") &&
           !strcmp(argv[i], AVM_EVENTS_FD))
            g_ptr_array_add(a, (gpointer)events);
        else
            g_ptr_array_add(a, (gpointer)argv[i]);
        if(i == 1) {
            g_ptr_array_add(a, (gpointer) "--prompts");
            g_ptr_array_add(a, (gpointer)prompts);
            if(control) {
                g_ptr_array_add(a, (gpointer) "--control");
                g_ptr_array_add(a, (gpointer)control);
            }
        }
    }
    g_ptr_array_add(a, NULL);
    return (char **)g_ptr_array_free(a, FALSE);
}

static AvmRun *new_run(GSubprocess *proc, const char *runDir, const AvmRunCallbacks *cb,
                       void *user) {
    AvmRun *r = g_new0(AvmRun, 1);
    r->proc = proc;
    r->answerFd = -1;
    r->cancel = g_cancellable_new();
    r->dir = g_strdup(runDir);
    r->cb = *cb;
    r->user = user;
    r->eventsCopy = open_in(runDir, "events.jsonl");
    r->outputCopy = open_in(runDir, "output.log");
    r->output = line_reader(g_subprocess_get_stdout_pipe(proc));
    return r;
}

static gboolean check_args(char **argv, const char *runDir, GError **error) {
    if(!argv || !argv[0] || !argv[1]) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT, "no engine command line");
        return FALSE;
    }
    if(g_mkdir_with_parents(runDir, 0700) != 0) {
        g_set_error(error, G_FILE_ERROR, (gint)g_file_error_from_errno(errno), "cannot create %s",
                    runDir);
        return FALSE;
    }
    return TRUE;
}

static GSubprocessLauncher *new_launcher(void) {
    /* GSubprocessFlags is a flags enum: OR-ing its values is how GIO is used */
    GSubprocessFlags flags = G_SUBPROCESS_FLAGS_STDOUT_PIPE | G_SUBPROCESS_FLAGS_STDERR_MERGE | // NOLINT(clang-analyzer-optin.core.EnumCastOutOfRange)
                             G_SUBPROCESS_FLAGS_STDIN_INHERIT;
    return g_subprocess_launcher_new(flags);
}

#ifdef G_OS_WIN32
/* The engine opens both pipes as it starts; until it has, a thread waits
 * for the two overlapped ConnectNamedPipe calls. on_exit and avm_run_free
 * cancel them (CancelIoEx) if the engine never comes. */
struct pipe_connect {
    HANDLE events, answers;
    OVERLAPPED ovEvents, ovAnswers;
    gboolean answersOk;
};

static void pipe_connect_free(gpointer data) {
    struct pipe_connect *c = data;
    if(c->events)
        CloseHandle(c->events);
    if(c->answers)
        CloseHandle(c->answers);
    CloseHandle(c->ovEvents.hEvent);
    CloseHandle(c->ovAnswers.hEvent);
    g_free(c);
}

/* TRUE if the client is (or was) there */
static gboolean start_connect(HANDLE pipe, OVERLAPPED *ov) {
    if(ConnectNamedPipe(pipe, ov))
        return TRUE;
    DWORD e = GetLastError();
    if(e == ERROR_PIPE_CONNECTED || e == ERROR_NO_DATA)
        SetEvent(ov->hEvent);
    return e == ERROR_IO_PENDING || e == ERROR_PIPE_CONNECTED || e == ERROR_NO_DATA;
}

static gboolean wait_connect(HANDLE pipe, OVERLAPPED *ov) {
    DWORD n = 0;
    if(WaitForSingleObject(ov->hEvent, INFINITE) != WAIT_OBJECT_0)
        return FALSE;
    if(GetOverlappedResult(pipe, ov, &n, FALSE))
        return TRUE;
    DWORD e = GetLastError();
    /* ERROR_IO_INCOMPLETE: the event was set because it was already connected */
    return e == ERROR_PIPE_CONNECTED || e == ERROR_NO_DATA || e == ERROR_IO_INCOMPLETE;
}

static void connect_thread(GTask *task, gpointer src, gpointer data, GCancellable *cancel) {
    (void)src;
    (void)cancel;
    struct pipe_connect *c = data;
    gboolean ev = wait_connect(c->events, &c->ovEvents);
    c->answersOk = wait_connect(c->answers, &c->ovAnswers);
    g_task_return_boolean(task, ev);
}

static void on_connected(GObject *src, GAsyncResult *res, gpointer data) {
    (void)src;
    GTask *task = G_TASK(res);
    if(g_cancellable_is_cancelled(g_task_get_cancellable(task)))
        return; /* freed: data is gone */
    AvmRun *r = data;
    struct pipe_connect *c = g_task_get_task_data(task);
    r->connecting = NULL;
    if(!g_task_propagate_boolean(task, NULL)) {
        /* the engine exited before it opened its pipes: its output says why */
        r->eventsDone = TRUE;
        maybe_finished(r);
        return;
    }
    GInputStream *evIn = g_win32_input_stream_new(c->events, TRUE);
    c->events = NULL;
    r->events = line_reader(evIn);
    g_object_unref(evIn);
    if(!r->exited && c->answersOk) {
        r->answerPipe = c->answers;
        c->answers = NULL;
    }
    read_events(r);
}

static void cancel_connect(AvmRun *r) {
    if(r->connecting) {
        CancelIoEx(r->connecting->events, &r->connecting->ovEvents);
        CancelIoEx(r->connecting->answers, &r->connecting->ovAnswers);
    }
}

static HANDLE new_pipe(const char *name, DWORD direction) {
    /* one instance, ours (FIRST_PIPE_INSTANCE), local clients only */
    return CreateNamedPipeA(name, direction | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
                            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT |
                                PIPE_REJECT_REMOTE_CLIENTS,
                            1, 65536, 65536, 0, NULL);
}

AvmRun *avm_run_start(char **argv, const char *runDir, const AvmRunCallbacks *cb, void *user,
                      GError **error) {
    if(!check_args(argv, runDir, error))
        return NULL;
    static unsigned counter;
    char *base = g_strdup_printf("gdsaudit-%lu-%u-%08x", (unsigned long)GetCurrentProcessId(),
                                 ++counter, g_random_int());
    char *evName = g_strdup_printf("\\\\.\\pipe\\%s-events", base);
    char *ansName = g_strdup_printf("\\\\.\\pipe\\%s-prompts", base);
    char *ctlName = g_strdup_printf("Local\\%s", base);
    struct pipe_connect *c = g_new0(struct pipe_connect, 1);
    c->ovEvents.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    c->ovAnswers.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    c->events = new_pipe(evName, PIPE_ACCESS_INBOUND);
    c->answers = new_pipe(ansName, PIPE_ACCESS_OUTBOUND);
    HANDLE control[3] = {NULL, NULL, NULL};
    static const char *const suffix[3] = {"-pause", "-resume", "-abort"};
    gboolean ok = c->ovEvents.hEvent && c->ovAnswers.hEvent &&
                  c->events != INVALID_HANDLE_VALUE && c->answers != INVALID_HANDLE_VALUE;
    for(int i = 0; ok && i < 3; i++) {
        char *n = g_strconcat(ctlName, suffix[i], NULL);
        control[i] = CreateEventA(NULL, FALSE, FALSE, n); /* auto-reset */
        ok = control[i] && GetLastError() != ERROR_ALREADY_EXISTS;
        g_free(n);
    }
    if(c->events == INVALID_HANDLE_VALUE)
        c->events = NULL;
    if(c->answers == INVALID_HANDLE_VALUE)
        c->answers = NULL;
    ok = ok && start_connect(c->events, &c->ovEvents) && start_connect(c->answers, &c->ovAnswers);
    GSubprocess *proc = NULL;
    if(!ok) {
        char *m = g_win32_error_message((gint)GetLastError());
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "cannot create the engine's pipes: %s", m);
        g_free(m);
    } else {
        GSubprocessLauncher *l = new_launcher();
        char **full = engine_argv(argv, ansName, ctlName, evName);
        proc = g_subprocess_launcher_spawnv(l, (const char *const *)full, error);
        g_free((gpointer)full); /* only the array: the strings are argv's or ours */
        g_object_unref(l);
    }
    g_free(evName);
    g_free(ansName);
    g_free(ctlName);
    g_free(base);
    if(!proc) {
        if(c->events)
            CancelIoEx(c->events, &c->ovEvents);
        if(c->answers)
            CancelIoEx(c->answers, &c->ovAnswers);
        for(int i = 0; i < 3; i++)
            if(control[i])
                CloseHandle(control[i]);
        /* the cancelled connects complete before the handles close */
        if(c->events)
            (void)WaitForSingleObject(c->ovEvents.hEvent, 1000);
        if(c->answers)
            (void)WaitForSingleObject(c->ovAnswers.hEvent, 1000);
        pipe_connect_free(c);
        return NULL;
    }
    AvmRun *r = new_run(proc, runDir, cb, user);
    memcpy(r->control, control, sizeof(control));
    r->connecting = c;
    GTask *task = g_task_new(NULL, r->cancel, on_connected, r);
    g_task_set_task_data(task, c, pipe_connect_free);
    g_task_run_in_thread(task, connect_thread);
    g_object_unref(task);
    read_output(r);
    g_subprocess_wait_async(proc, r->cancel, on_exit, r);
    return r;
}
#else
/* A write to the answer pipe after the engine died must fail with EPIPE,
 * not kill the UI. */
static void ignore_sigpipe(void) {
    struct sigaction old;
    if(sigaction(SIGPIPE, NULL, &old) == 0 && old.sa_handler == SIG_DFL) {
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = SIG_IGN;
        sigemptyset(&sa.sa_mask);
        sigaction(SIGPIPE, &sa, NULL);
    }
}

static void close_pair(int fds[2]) {
    close(fds[0]);
    close(fds[1]);
}

AvmRun *avm_run_start(char **argv, const char *runDir, const AvmRunCallbacks *cb, void *user,
                      GError **error) {
    if(!check_args(argv, runDir, error))
        return NULL;
    int fds[2], ans[2];
    if(!g_unix_open_pipe(fds, FD_CLOEXEC, error))
        return NULL;
    if(!g_unix_open_pipe(ans, FD_CLOEXEC, error)) {
        close_pair(fds);
        return NULL;
    }
    ignore_sigpipe();
    GSubprocessLauncher *l = new_launcher();
    g_subprocess_launcher_take_fd(l, fds[1], 3); /* the child's --events /dev/fd/3 */
    g_subprocess_launcher_take_fd(l, ans[0], 4); /* the child's --prompts /dev/fd/4 */
    char **full = engine_argv(argv, (char *)AVM_PROMPTS_FD, NULL, NULL);
    GSubprocess *proc = g_subprocess_launcher_spawnv(l, (const char *const *)full, error);
    g_free((gpointer)full); /* only the array: the strings are argv's */
    g_object_unref(l); /* closes our copies of the child's ends */
    if(!proc) {
        close(fds[0]);
        close(ans[1]);
        return NULL;
    }
    AvmRun *r = new_run(proc, runDir, cb, user);
    r->answerFd = ans[1];
    GInputStream *evIn = g_unix_input_stream_new(fds[0], TRUE);
    r->events = line_reader(evIn);
    g_object_unref(evIn);
    read_events(r);
    read_output(r);
    g_subprocess_wait_async(proc, r->cancel, on_exit, r);
    return r;
}
#endif

/* Replay of a stored run: one idle callback feeds every event. */
typedef struct {
    AvmRun *run;
    ga_results stored;
} replay;

static void replay_event(AvmRun *r, ga_event *ev, const ga_result *x, ga_event_kind kind) {
    ev->kind = kind;
    ev->id = x->id;
    ev->clause = x->clause;
    ev->title = x->title;
    ev->needsWrite = x->needsWrite;
    ev->needsOperator = x->needsOperator;
    if(ga_results_apply(&r->results, ev) && r->cb.event)
        r->cb.event(r, ev, r->user);
}

static void replay_test(AvmRun *r, const ga_result *x, size_t n) {
    ga_event ev = {.n = n};
    replay_event(r, &ev, x, GA_EV_TEST_STARTED);
    if(x->notes) {
        char **lines = g_strsplit(x->notes, "\n", -1);
        for(char **l = lines; *l; l++) {
            ga_event note = {.n = n, .text = *l};
            replay_event(r, &note, x, GA_EV_NOTE);
        }
        g_strfreev(lines);
    }
    if(x->done) {
        ga_event v = {.n = n, .verdict = x->verdict, .ms = x->ms, .text = x->evidence};
        replay_event(r, &v, x, GA_EV_VERDICT);
    }
}

static gboolean replay_all(gpointer data) {
    replay *p = data;
    AvmRun *r = p->run;
    const ga_results *s = &p->stored;
    ga_event start = {.kind = GA_EV_RUN_STARTED, .profile = s->profile, .target = s->target,
                      .allowChanges = s->allowChanges, .planned = s->planned, .time = s->started};
    if(ga_results_apply(&r->results, &start) && r->cb.event)
        r->cb.event(r, &start, r->user);
    for(size_t i = 0; i < s->n; i++)
        replay_test(r, &s->items[i], i + 1);
    if(s->finishedSeen) {
        ga_event fin = {.kind = GA_EV_RUN_FINISHED, .exitCode = s->exitCode,
                        .aborted = s->aborted, .time = s->finished};
        memcpy(fin.counts, s->counts, sizeof(fin.counts));
        if(ga_results_apply(&r->results, &fin) && r->cb.event)
            r->cb.event(r, &fin, r->user);
    }
    r->reported = TRUE;
    r->replaySource = 0;
    if(r->cb.finished)
        r->cb.finished(r, s->finishedSeen ? s->exitCode : 2, NULL, r->user);
    return G_SOURCE_REMOVE;
}

static void replay_free(gpointer data) {
    replay *p = data;
    ga_results_free(&p->stored);
    g_free(p);
}

AvmRun *avm_run_open(const char *runDir, const AvmRunCallbacks *cb, void *user, GError **error) {
    char *path = g_build_filename(runDir, "events.jsonl", NULL);
    replay *p = g_new0(replay, 1);
    char err[512];
    gboolean ok = ga_results_load(path, &p->stored, err, sizeof(err));
    g_free(path);
    if(!ok || !p->stored.profile) {
        g_set_error(error, G_FILE_ERROR, G_FILE_ERROR_FAILED, "%s",
                    ok ? "the events file holds no run" : err);
        replay_free(p);
        return NULL;
    }
    AvmRun *r = g_new0(AvmRun, 1);
    r->cancel = g_cancellable_new();
    r->dir = g_strdup(runDir);
    r->cb = *cb;
    r->user = user;
    r->exited = r->eventsDone = r->outputDone = TRUE;
    r->answerFd = -1;
    p->run = r;
    r->replaySource = g_idle_add_full(G_PRIORITY_DEFAULT_IDLE, replay_all, p, replay_free);
    return r;
}

void avm_run_abort(AvmRun *run) {
    if(!run || run->exited || !run->proc)
        return;
#ifdef G_OS_WIN32
    if(run->control[2])
        SetEvent(run->control[2]);
    close_answers(run); /* a prompt the engine waits on ends */
#else
    g_subprocess_send_signal(run->proc, SIGINT);
#endif
}

void avm_run_pause(AvmRun *run, gboolean paused) {
    if(!run || run->exited || !run->proc)
        return;
#ifdef G_OS_WIN32
    HANDLE h = run->control[paused ? 0 : 1];
    if(h)
        SetEvent(h);
#else
    g_subprocess_send_signal(run->proc, paused ? SIGUSR1 : SIGUSR2);
#endif
}

#ifdef G_OS_WIN32
static gboolean write_answer(AvmRun *run, const char *line, size_t len, GError **error) {
    OVERLAPPED ov;
    memset(&ov, 0, sizeof(ov));
    ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    DWORD n = 0;
    BOOL ok = ov.hEvent && WriteFile(run->answerPipe, line, (DWORD)len, &n, &ov);
    if(!ok && ov.hEvent && GetLastError() == ERROR_IO_PENDING)
        ok = GetOverlappedResult(run->answerPipe, &ov, &n, TRUE);
    DWORD e = GetLastError();
    if(ov.hEvent)
        CloseHandle(ov.hEvent);
    if(ok && n == len)
        return TRUE;
    char *m = g_win32_error_message((gint)e);
    g_set_error(error, G_IO_ERROR, G_IO_ERROR_BROKEN_PIPE, "cannot send the answer to the engine: %s",
                m);
    g_free(m);
    return FALSE;
}
#else
static gboolean write_answer(AvmRun *run, const char *line, size_t len, GError **error) {
    size_t off = 0;
    while(off < len) {
        ssize_t w = write(run->answerFd, line + off, len - off);
        if(w < 0 && errno == EINTR)
            continue;
        if(w <= 0) {
            g_set_error(error, G_IO_ERROR, (gint)g_io_error_from_errno(errno),
                        "cannot send the answer to the engine: %s", g_strerror(errno));
            return FALSE;
        }
        off += (size_t)w;
    }
    return TRUE;
}
#endif

size_t avm_run_pending_prompt(const AvmRun *run) {
    return run ? run->pendingSeq : 0;
}

/* Room for the note in one answer line: prompts.h reads lines of up to
 * GA_PROMPT_LINE (1024) bytes; "<seq> fail " takes at most 32. */
#define AVM_ANSWER_NOTE 960

static char *clean_note(const char *note) {
    char *n = g_utf8_make_valid(note ? note : "", -1);
    for(char *c = n; *c; c++)
        if((guchar)*c < 0x20 || *c == 0x7f)
            *c = ' ';
    if(strlen(n) > AVM_ANSWER_NOTE) {
        /* cut on a character boundary */
        const char *end = g_utf8_find_prev_char(n, n + AVM_ANSWER_NOTE + 1);
        n[end ? end - n : 0] = '\0';
    }
    return g_strstrip(n);
}

gboolean avm_run_answer(AvmRun *run, size_t seq, ga_answer answer, const char *note,
                        GError **error) {
#ifdef G_OS_WIN32
    gboolean connected = run && run->answerPipe;
#else
    gboolean connected = run && run->answerFd >= 0;
#endif
    if(!connected || run->exited) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_CLOSED, "the engine is not running");
        return FALSE;
    }
    if(seq == 0 || seq != run->pendingSeq || (size_t)answer >= GA_ANSWER_COUNT) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
                    "the engine is not waiting for that answer");
        return FALSE;
    }
    char *n = clean_note(note);
    char *line = g_strdup_printf("%zu %s%s%s\n", seq, ga_answer_name(answer), *n ? " " : "", n);
    g_free(n);
    gboolean ok = write_answer(run, line, strlen(line), error);
    g_free(line);
    return ok;
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
    if(run->replaySource)
        g_source_remove(run->replaySource);
#ifdef G_OS_WIN32
    cancel_connect(run); /* the thread ends; the task frees the pipes */
    for(int i = 0; i < 3; i++)
        if(run->control[i])
            CloseHandle(run->control[i]);
#endif
    close_answers(run);
    if(!run->exited && run->proc)
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
#ifdef G_OS_WIN32
    wchar_t w[MAX_PATH];
    DWORD wl = GetModuleFileNameW(NULL, w, MAX_PATH);
    char *self = wl > 0 && wl < MAX_PATH ? g_utf16_to_utf8((const gunichar2 *)w, (glong)wl, NULL, NULL, NULL) : NULL;
    const char *engine = "gdsaudit.exe";
#else
    char *self = g_file_read_link("/proc/self/exe", NULL);
    const char *engine = "gdsaudit";
#endif
    char *dir = self ? g_path_get_dirname(self) : g_strdup(".");
    char *path = g_build_filename(dir, engine, NULL);
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
