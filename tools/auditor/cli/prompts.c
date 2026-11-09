/* OpenGDS Auditor - operator answers for the headless front end (prompts.h).
 * SPDX-License-Identifier: MPL-2.0 */
#define _POSIX_C_SOURCE 200809L
#include "prompts.h"

#include <errno.h>
#include <fcntl.h>
#ifndef _WIN32
#include <poll.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "common/platform.h"
#include "common/banned.h"

static int fd = -1;
static bool ended; /* end of file seen */
static char buf[GA_PROMPT_LINE + 1];
static size_t have;

bool prompts_parse_line(const char *line, size_t *seq, ga_answer *answer, char *note,
                        size_t noteLen) {
    const char *p = line;
    size_t n = 0;
    if(*p < '1' || *p > '9')
        return false;
    for(; *p >= '0' && *p <= '9'; p++) {
        if(n > (size_t)1000000)
            return false;
        n = n * 10 + (size_t)(*p - '0');
    }
    if(*p != ' ')
        return false;
    p++;
    const char *word = p;
    while(*p && *p != ' ')
        p++;
    char w[8];
    size_t wl = (size_t)(p - word);
    if(wl == 0 || wl >= sizeof(w))
        return false;
    memcpy(w, word, wl);
    w[wl] = '\0';
    if(!ga_answer_parse(w, answer))
        return false;
    if(*p == ' ')
        p++;
    snprintf(note, noteLen, "%s", p);
    *seq = n;
    return true;
}

/* Next complete line into out; false at end of file, on error or abort. */
static bool next_line(char *out, size_t outLen) {
    for(;;) {
        char *nl = memchr(buf, '\n', have);
        if(nl) {
            size_t len = (size_t)(nl - buf);
            snprintf(out, outLen, "%.*s", (int)len, buf);
            memmove(buf, nl + 1, have - len - 1);
            have -= len + 1;
            return true;
        }
        if(have == GA_PROMPT_LINE) /* a line too long: drop it */
            have = 0;
        if(ended || ga_abort_requested())
            return false;
#ifndef _WIN32
        struct pollfd pfd = {fd, POLLIN, 0};
        int r = poll(&pfd, 1, 100);
        if(r < 0 && errno != EINTR)
            return false;
        if(r <= 0)
            continue; /* look at the abort flag again */
#endif
        /* Windows: a plain file, whose read never blocks, or the desktop
         * UI's named pipe, whose read waits for the answer; the UI closes
         * the pipe on abort, so read ends there */
        ssize_t got = read(fd, buf + have, GDS_IO_CHUNK(GA_PROMPT_LINE - have));
        if(got < 0 && errno == EINTR)
            continue;
        if(got <= 0) {
            ended = true;
            continue;
        }
        have += (size_t)got;
    }
}

static bool ask(size_t seq, const char *text, ga_answer *answer, char *note, size_t noteLen,
                void *user) {
    (void)user;
    printf("# waiting for the operator: answer \"%zu done|skip|fail [note]\" (%s)\n", seq, text);
    fflush(stdout);
    char line[GA_PROMPT_LINE + 1];
    while(next_line(line, sizeof(line))) {
        size_t got = 0;
        if(prompts_parse_line(line, &got, answer, note, noteLen) && got == seq)
            return true;
    }
    return false;
}

bool prompts_open(const char *path) {
#ifdef _WIN32
    fd = gds_open_pipe(path, false);
    if(fd == -2)
#endif
        fd = open(path, O_RDONLY | GDS_O_CLOEXEC);
    if(fd < 0) {
        perror(path);
        return false;
    }
    ended = false;
    have = 0;
    ga_set_prompt_handler(ask, NULL);
    return true;
}

void prompts_close(void) {
    ga_set_prompt_handler(NULL, NULL);
    if(fd >= 0)
        close(fd);
    fd = -1;
}
