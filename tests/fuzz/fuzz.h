/* OpenGDS fuzz targets (docs/architecture.md, "Fuzz targets"): the libFuzzer
 * entry points every target defines, and the small helpers they share.
 *
 * With -DOPENGDS_FUZZ=ON the targets link libFuzzer; otherwise fuzz_main.c
 * replays the corpus files and directories given on the command line, so
 * regular CI runs every seed through the same code.
 * SPDX-License-Identifier: MPL-2.0 */
#ifndef OPENGDS_FUZZ_H
#define OPENGDS_FUZZ_H

#include <stddef.h>
#include <stdint.h>

#include "common/buf.h"
#include "common/compiler.h"

/* Ids of the application and request stored by the fuzz_signer_msg fixture
 * (gen_seeds.c writes seeds that name the request). */
#define FUZZ_APP_ID {0x0a11ce00, 0x0001, 0x4000, {0x80, 0, 0, 0, 0, 0, 0, 1}}
#define FUZZ_REQ_ID {0x5e0e5700, 0x0001, 0x4000, {0x80, 0, 0, 0, 0, 0, 0, 2}}

int LLVMFuzzerInitialize(int *argc, char ***argv);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

/* A fresh private directory (0700) under $TMPDIR or /tmp, removed with its
 * contents at exit. Fixtures (store, CA) live there; nothing is written
 * anywhere else. One per process. */
GDS_MUST_CHECK gds_status fuzz_tmpdir(char *out, size_t outLen);

/* The fixed CA key passphrase of the fuzz fixtures: a test value compiled
 * in, never read from argv or the environment. */
const uint8_t *fuzz_passphrase(size_t *len);

/* A fresh RSA-2048 key and its self-signed CSR (DER). */
GDS_MUST_CHECK gds_status fuzz_make_csr(gds_buf *out);

#endif
