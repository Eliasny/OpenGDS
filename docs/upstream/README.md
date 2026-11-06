# Upstream fixes for open62541

The three open62541 v1.5.10 gaps listed in `00-project-context.md`, each with a
minimal patch, tests, and draft issue and pull request text. **Elias posts them
to open62541 himself** (decided 2026-11-06); nothing has been posted by Claude.
The first PR needs him to sign the open62541 Contributor License Agreement (the
CLA bot links it on the PR).

## Decisions (Elias, 2026-11-06)

| # | Question | Decision |
|---|---|---|
| O1 | Gap 2: change the default or add an opt-in helper | Change the default: the secure-only config adds #None for discovery only (patch 0002 as drafted) |
| O2 | Gap 1: small fix only, or also a public API change | Both: the small fix (0001) and a public API proposal on top of it (0004) |
| O3 | Carry the patches on our pinned v1.5.10 now | Yes, in a separate OpenGDS PR that also removes our workarounds |
| O4 | Upstream commit authorship | Elias only, no co-author line (the patches are already authored that way) |
| O5 | Who posts upstream | Elias, from his own account |

Checked against open62541 master `24fc6b296` (2026-11-06) and our pinned
v1.5.10 (`93c3bdfc9`), on Ubuntu 24.04, GCC 13, OpenSSL 3.0.13.

| Gap | Upstream state | Patch | Notes |
|---|---|---|---|
| [1. No key file after a CSR push that keeps the key](01-filestore-key-kept-csr.md) | Not reported. Open PR [#8681](https://github.com/open62541/open62541/pull/8681) covers the neighbouring case (a key that CreateSigningRequest generated), not this one. | [master](patches/master/0001-filestore-store-key-in-use.patch), [v1.5.10](patches/v1.5.10/0001-filestore-store-key-in-use.patch); API proposal [master 0004](patches/master/0004-filestore-keep-key-in-use-api.patch) | 0001 merges with #8681 after one trivial conflict; tests pass on the merge. 0004 adds `UA_SecurityPolicy_FilestoreWithKey`. |
| [2. Secure-only config blocks discovery](02-secure-policies-none-discovery.md) | Open issue [#6771](https://github.com/open62541/open62541/issues/6771) since 2024-10-15, no fix. | [master](patches/master/0002-secure-policies-none-discovery.patch), [v1.5.10](patches/v1.5.10/0002-secure-policies-none-discovery.patch) | Changes default behaviour (chosen, O1). The PR text still offers an opt-in if maintainers object. |
| [3. GDS headers not installed with AUTOLOAD=GDS](03-install-autoload-headers.md) | Not reported. | [master](patches/master/0003-install-autoload-headers.patch), [v1.5.10](patches/v1.5.10/0003-install-autoload-headers.patch) | Six CMake lines plus a CI job. Works for every AUTOLOAD model. |

## Results

Each new test was run without the library change (it must fail) and with it
(it must pass).

| Gap | master without fix | master with fix | v1.5.10 with backport |
|---|---|---|---|
| 1 | new test fails | `check_update_certificate` 19/19; GDS and filestore suites pass | `check_update_certificate` 9/9 (test ported to the v1.5.10 API) |
| 1, API (0004) | its test fails with only 0001 | `check_update_certificate` 20/20 | not carried (O3 covers 0001 to 0003) |
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
  A separate OpenGDS PR does that (O3).

## How to post (for Elias)

Everything to paste is in the three gap pages: each has a "Draft issue" and a
"Draft pull request" block, and gap 1 also has the "Draft proposal issue" for
the API change.

1. Fork https://github.com/open62541/open62541 to your account and clone it.
2. For each patch, branch from current master and apply it, for example
   `git checkout -b fix/install-autoload-headers origin/master` then
   `git am docs/upstream/patches/master/0003-install-autoload-headers.patch`
   (path relative to an OpenGDS checkout). Patch 0004 goes on top of 0001 on
   the same branch or a branch made from it.
3. Gap 2: post the drafted comment on
   [#6771](https://github.com/open62541/open62541/issues/6771), then push the
   0002 branch and open the PR with the drafted text (it says "Fixes #6771").
4. Gap 3: open the drafted issue, then the PR from the 0003 branch with
   "Fixes #<issue>".
5. Gap 1: open the drafted issue, then the PR from the 0001 branch. Mention
   [#8681](https://github.com/open62541/open62541/pull/8681) as the drafts do.
   After that, open the drafted proposal issue for 0004 and link the 0004
   branch as a draft PR; their rules want API changes discussed first.
6. If master has moved and a patch no longer applies, ask a thread to rebase
   it; the drafts and test results then need a refresh too.
7. Put the issue and PR links into the table above, or tell a thread and it
   will.
