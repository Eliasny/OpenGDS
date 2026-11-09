/* OpenGDS Auditor - operator answers for the headless front end
 * (--prompts FILE; engine.h operator prompts).
 *
 * Each prompt the engine shows is also a "prompt" event (--events) and a
 * TAP comment. The answer is one line in FILE (a pipe from the desktop UI,
 * or /dev/stdin for a person at the terminal):
 *   <seq> done|skip|fail [note]
 * Lines for another prompt number are ignored. End of file, or an abort
 * while waiting, answers no more prompts (those tests are Not tested).
 * SPDX-License-Identifier: MPL-2.0 */
#ifndef GDSAUDIT_PROMPTS_H
#define GDSAUDIT_PROMPTS_H

#include <stdbool.h>
#include <stddef.h>

#include "gdsaudit/engine.h"

#define GA_PROMPT_LINE 1024

/* Open FILE and install the prompt handler; false (and a message) if it
 * cannot be opened. */
bool prompts_open(const char *path);
void prompts_close(void);

/* Parse one answer line; false if it is not one. note gets the rest of the
 * line (may be empty). For tests. */
bool prompts_parse_line(const char *line, size_t *seq, ga_answer *answer, char *note,
                        size_t noteLen);

#endif
