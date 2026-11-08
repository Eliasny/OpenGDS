/* OpenGDS - the signer program, for embedders (UASM ask A21).
 *
 * gds_signer_main is opengds-signer: the same arguments, checks, issuance
 * journal, CA loading and sandbox. An embedder whose requests and records
 * live in a store of its own (gds_store_open_backend, e.g. a replicated
 * one) builds its own signer executable whose main() calls it with hooks:
 *   - open_store replaces gds_store_open_readonly(--store PATH), and
 *     --store is refused. It runs before the sandbox, once (with --listen:
 *     at the first connection). It must leave everything the store needs
 *     open: once sandboxed the signer may not create sockets or connect
 *     (the seccomp filter of GDS_SB_SIGNER kills it), so a backend that
 *     talks to a store service connects here and never reconnects. When
 *     that connection breaks, the backend answers GDS_EIO: the signer
 *     sends that refusal and then exits with status 1 (with --listen once
 *     the connection ends), so the service manager restarts it.
 *   - paths are extra files or directories the backend reads after the
 *     sandbox is applied (Landlock, read-only); at most
 *     GDS_SIGNER_MAX_HOOK_PATHS.
 * The store the hook returns is closed with gds_store_close when the
 * signer ends. The signer only reads it (gds_signer_serve).
 * SPDX-License-Identifier: MPL-2.0 */
#ifndef OPENGDS_SIGNER_MAIN_H
#define OPENGDS_SIGNER_MAIN_H

#include <stddef.h>
#include <stdint.h>

#include "store.h"

#ifdef __cplusplus
extern "C" {
#endif

#define GDS_SIGNER_HOOKS_ABI_MAJOR 1
#define GDS_SIGNER_HOOKS_ABI_MINOR 0
#define GDS_SIGNER_MAX_HOOK_PATHS 4

typedef struct {
    uint32_t abi_major; /* GDS_SIGNER_HOOKS_ABI_MAJOR */
    uint32_t abi_minor;
    size_t struct_size; /* sizeof(gds_signer_hooks) */
    /* Opens the store; *out non-NULL on GDS_OK. */
    gds_status (*open_store)(void *ctx, gds_store **out);
    const char *const *paths;
    size_t nPaths;
    void *ctx;
} gds_signer_hooks;

/* The signer program; returns its exit status (0, 1 on an error, 2 on a
 * usage error or bad hooks). hooks NULL: opengds-signer itself. */
int gds_signer_main(int argc, char **argv, const gds_signer_hooks *hooks);

#ifdef __cplusplus
}
#endif

#endif
