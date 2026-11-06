# Gap 3: GDS headers are not installed with AUTOLOAD=GDS

**Status (2026-11-06):** not reported upstream (searched issues and PRs for
`types_gds_generated`, `nodeids_gds`, "AUTOLOAD headers", "nodeset injector
install"). Still present on master `24fc6b296`: after `cmake --install` of a
build with `-DUA_INFORMATION_MODEL_AUTOLOAD=GDS`, `include/open62541/` has no
`*gds*` header.

**Patch:** [patches/master/0003-install-autoload-headers.patch](patches/master/0003-install-autoload-headers.patch)
(backport, CMake part only: [patches/v1.5.10/0003-install-autoload-headers.patch](patches/v1.5.10/0003-install-autoload-headers.patch)).

## What goes wrong

The nodeset injector collects the generated files of every autoloaded model in
`UA_NODESETINJECTOR_SOURCE_FILES` and compiles them into the library through
`lib_sources`. Only `exported_headers` and `plugin_headers` are installed, so
`types_gds_generated.h`, `nodeids_gds.h` and `namespace_gds_generated.h` stay
in the build tree. An application linked against the installed library has
the GDS types and NodeIds in the binary but cannot include their declarations.

OpenGDS works around this today: `scripts/build_open62541.sh` copies the two
headers into the install prefix by hand.

## The fix

Six lines in the top-level `CMakeLists.txt`, inside the
`UA_ENABLE_NODESET_INJECTOR` block: take the `.h` files from
`UA_NODESETINJECTOR_SOURCE_FILES`, drop `*_internal.h`, and append them to
`exported_headers`. The existing install loop already maps
`src_generated/open62541/` to `include/open62541/`. This runs after the
amalgamation step reads `exported_headers`, so the amalgamated build is
unchanged. It works for every AUTOLOAD model, not only GDS.

## Test

A new CI job, "Install with autoloaded companion specification"
(`build_install_autoload` in `tools/ci/linux/ci.sh`), configures with
`AUTOLOAD=GDS`, installs to a prefix, and compiles and runs a small program
that includes the three headers and uses `UA_ApplicationRecordDataType` and
`UA_GDSID_DIRECTORY`, linking through the installed `open62541.pc`.

Checked on open62541 master `24fc6b296`:

| Run | Result |
|---|---|
| Install without the change | no `*gds*` header in `include/open62541/` |
| Install with the change | `types_gds_generated.h`, `nodeids_gds.h`, `namespace_gds_generated.h` installed |
| `build_install_autoload` run locally from the patched tree | builds, installs, consumer compiles and runs (exit 0) |
| v1.5.10 with the backport | the three headers are installed |

## Draft issue

> **Title:** Generated headers of autoloaded information models are not installed
>
> **Version:** v1.5.10 and master (24fc6b296).
>
> **Steps:** configure with `-DUA_INFORMATION_MODEL_AUTOLOAD=GDS`, build, `cmake --install`.
>
> **Expected:** `include/open62541/types_gds_generated.h` and `include/open62541/nodeids_gds.h` are installed, so an application can use the GDS datatypes and NodeIds that are compiled into the library.
>
> **Actual:** the generated headers stay in `build/src_generated/open62541/`. The nodeset injector adds them to `lib_sources` only, and only `exported_headers` are installed. Applications have to copy the headers from the build tree.

## Draft pull request

> **Title:** `fix(build): install the headers of autoloaded information models`
>
> **Problem.** With `UA_INFORMATION_MODEL_AUTOLOAD` the generated datatype, NodeId and namespace headers of the selected models (e.g. `types_gds_generated.h`, `nodeids_gds.h`) are compiled into the library but not installed. An application built against the installed library therefore cannot use the datatypes or NodeIds of a model it loads. Fixes #&lt;issue&gt;.
>
> **Solution.** Add the generated public headers (not `*_internal.h`) of the autoloaded models to `exported_headers`, so the existing install loop installs them next to the other generated headers. The amalgamation is not affected.
>
> **Tests.** New CI job `build_install_autoload`: installs a build with `AUTOLOAD=GDS` and compiles and runs an application against the installed headers via `pkg-config`.
