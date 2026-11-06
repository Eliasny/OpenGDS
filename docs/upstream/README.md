# Upstream fixes for open62541

The three open62541 v1.5.10 gaps listed in `00-project-context.md`, each with a
minimal patch, tests, and draft issue and pull request text, ready to post to
the open62541 project. **Nothing has been posted upstream yet.** Posting needs
Elias's OK, and the first PR needs him to sign the open62541 Contributor License
Agreement (the CLA bot links it on the PR).

Checked against open62541 master `24fc6b296` (2026-11-06) and our pinned
v1.5.10 (`93c3bdfc9`), on Ubuntu 24.04, GCC 13, OpenSSL 3.0.13.

| Gap | Upstream state | Patch | Notes |
|---|---|---|---|
| [1. No key file after a CSR push that keeps the key](01-filestore-key-kept-csr.md) | Not reported. Open PR [#8681](https://github.com/open62541/open62541/pull/8681) covers the neighbouring case (a key that CreateSigningRequest generated), not this one. | [master](patches/master/0001-filestore-store-key-in-use.patch), [v1.5.10](patches/v1.5.10/0001-filestore-store-key-in-use.patch) | Merges with #8681 after one trivial conflict; tests pass on the merge. |
| [2. Secure-only config blocks discovery](02-secure-policies-none-discovery.md) | Open issue [#6771](https://github.com/open62541/open62541/issues/6771) since 2024-10-15, no fix. | [master](patches/master/0002-secure-policies-none-discovery.patch), [v1.5.10](patches/v1.5.10/0002-secure-policies-none-discovery.patch) | Changes default behaviour, so maintainers may prefer an opt-in. The PR text offers that. |
| [3. GDS headers not installed with AUTOLOAD=GDS](03-install-autoload-headers.md) | Not reported. | [master](patches/master/0003-install-autoload-headers.patch), [v1.5.10](patches/v1.5.10/0003-install-autoload-headers.patch) | Six CMake lines plus a CI job. Works for every AUTOLOAD model. |

## Results

Each new test was run without the library change (it must fail) and with it
(it must pass).

| Gap | master without fix | master with fix | v1.5.10 with backport |
|---|---|---|---|
| 1 | new test fails | `check_update_certificate` 19/19; GDS and filestore suites pass | `check_update_certificate` 9/9 (test ported to the v1.5.10 API) |
| 2 | discovery test 0/3, config test 2 failures | discovery 3/3, config 16/16 | discovery 3/3 |
| 3 | no `*gds*` header installed | three headers installed; CI job builds, installs, compiles and runs a consumer | three headers installed |

## What is in `patches/`

- `patches/master/` holds the commits as they would go upstream: library
  change, tests, `CHANGES.md` entries where the public behaviour changes, and
  for gap 3 the CI job. They apply to open62541 master `24fc6b296` with
  `git am`, one branch per patch. Their author is set to Elias's GitHub
  noreply address so they can be pushed from his fork as they are. The
  commit messages follow open62541's `CONTRIBUTING.md` (Conventional Commits,
  100-column lines).
- `patches/v1.5.10/` holds only the library part of each patch (the
  `plugins/` and `CMakeLists.txt` changes). They apply cleanly to v1.5.10. If
  we want, `scripts/build_open62541.sh` can apply them to our pinned build and
  drop the workarounds in `push_test_server`, `mock_gds` and the header copy.
  That is a separate change and is not made here.

## Posting plan (after Elias's OK)

1. Fork open62541 under Eliasny, make one branch per patch from master, and
   `git am` the patch.
2. Gap 2: post the drafted comment on #6771, then open the PR with
   "Fixes #6771".
3. Gaps 1 and 3: open the drafted issue first, then the PR that fixes it.
   For gap 1, mention #8681 in both and offer to rebase once it merges.
4. Re-run the checks above if master has moved, and update this page with the
   issue and PR links.
