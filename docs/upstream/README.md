# Upstream fixes for open62541

The three open62541 v1.5.10 gaps listed in `00-project-context.md`, plus a
fourth found by the week 1 approvals spike, a fifth (already fixed on
master, missing on 1.5) found by the Auditor client profile, and a sixth
(also fixed on master only) found by the UASM spec tests, each with a minimal patch, tests, and draft issue and pull request text. **Elias posts them
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
| gap 5 | Carry the client ApplicationUri check (#8478 backport) on v1.5.10 | No: OpenGDS's push engine and the Auditor's client check it themselves |
| G12 / refresh | Gap 4 (ConditionRefresh EventId): carry it, and when to offer it | Carry it on v1.5.10 now; offer it upstream later, together with the A&C improvements from the approvals spike |

Checked against open62541 master `24fc6b296` (2026-11-06) and our pinned
v1.5.10 (`93c3bdfc9`), on Ubuntu 24.04, GCC 13, OpenSSL 3.0.13.

| Gap | Upstream state | Patch | Notes |
|---|---|---|---|
| [1. No key file after a CSR push that keeps the key](01-filestore-key-kept-csr.md) | Not reported. Open PR [#8681](https://github.com/open62541/open62541/pull/8681) covers the neighbouring case (a key that CreateSigningRequest generated), not this one. | [master](patches/master/0001-filestore-store-key-in-use.patch), [v1.5.10](patches/v1.5.10/0001-filestore-store-key-in-use.patch); API proposal [master 0004](patches/master/0004-filestore-keep-key-in-use-api.patch) | 0001 merges with #8681 after one trivial conflict; tests pass on the merge. 0004 adds `UA_SecurityPolicy_FilestoreWithKey`. |
| [2. Secure-only config blocks discovery](02-secure-policies-none-discovery.md) | Open issue [#6771](https://github.com/open62541/open62541/issues/6771) since 2024-10-15, no fix. | [master](patches/master/0002-secure-policies-none-discovery.patch), [v1.5.10](patches/v1.5.10/0002-secure-policies-none-discovery.patch) | Changes default behaviour (chosen, O1). The PR text still offers an opt-in if maintainers object. |
| [3. GDS headers not installed with AUTOLOAD=GDS](03-install-autoload-headers.md) | Not reported. | [master](patches/master/0003-install-autoload-headers.patch), [v1.5.10](patches/v1.5.10/0003-install-autoload-headers.patch) | Six CMake lines plus a CI job. Works for every AUTOLOAD model. |
| [4. ConditionRefresh gives a new EventId](04-condition-refresh-eventid.md) | Not yet searched upstream (do before posting). Violates OPC 10000-9 §5.5.7. | [master 0005](patches/master/0005-condition-refresh-keep-eventid.patch), [v1.5.10 0004](patches/v1.5.10/0004-condition-refresh-keep-eventid.patch) | Ten lines in `refreshLogic`, no API change. Offer later (G12). |
| [5. Client accepts a server certificate that names another ApplicationUri](05-client-server-applicationuri.md) | Fixed on master by [#8478](https://github.com/open62541/open62541/pull/8478) (2026-09-22); not on the `1.5` branch or in any release. Violates OPC 10000-4 §6.1.3 (Table 100, "URI") and §5.7.2.1. | [1.5 backport](patches/1.5/0001-client-validate-server-applicationuri.patch) (cherry-pick of `980fe5866`) | Not carried (Elias): OpenGDS's client sessions check it themselves. Ask is a backport to `1.5`. |
| [6. SKS GetSecurityKeys returns a garbage TimeToNextKey](06-sks-time-to-next-key.md) | Not reported. Fixed on master only inside the feature commit `2745dd876`; not on `1.5` or in any release. Violates OPC 10000-14 §8.3.2. | [1.5 fix](patches/1.5/0002-sks-time-to-next-key.patch) | Not carried: neither OpenGDS nor UASM uses open62541's SKS (UASM has its own). |
| [7. FindServers cannot return the other servers of a redundant set](07-findservers-peers.md) | Not yet searched upstream. Violates OPC 10000-4 §6.6.2.4.5.1 and, for the mirror-back, §5.5.2.2. | [v1.5.10 0005](patches/v1.5.10/0005-findservers-peers.patch) | Carried (UASM ask A15): `UA_ServerConfig.findServersPeers`, and the EndpointUrl mirrored for the server itself only. |

## Results

Each new test was run without the library change (it must fail) and with it
(it must pass).

| Gap | master without fix | master with fix | v1.5.10 with backport |
|---|---|---|---|
| 1 | new test fails | `check_update_certificate` 19/19; GDS and filestore suites pass | `check_update_certificate` 9/9 (test ported to the v1.5.10 API) |
| 1, API (0004) | its test fails with only 0001 | `check_update_certificate` 20/20 | not carried (O3 covers 0001 to 0003) |
| 2 | discovery test 0/3, config test 2 failures | discovery 3/3, config 16/16 | discovery 3/3 |
| 3 | no `*gds*` header installed | three headers installed; CI job builds, installs, compiles and runs a consumer | three headers installed |
| 4 | new test fails | `check_server_alarmsconditions` 74/74, events suites pass | approvals spike: refreshed EventId equals the original |
| 5 | (fixed on master) | (fixed on master) | on `1.5`: mismatch test connects without the fix; with it `check_cert_validation_client_response` 3/3 and 13 more client/encryption suites pass |
| 6 | (fixed on master) | (fixed on master) | on `1.5`: `check_pubsub_sks_pull` 9/11 without the fix (TimeToNextKey −154290 ms); 11/11 with it, other SKS suites pass |

## What is in `patches/`

- `patches/master/` holds the commits as they would go upstream: library
  change, tests, `CHANGES.md` entries where the public behaviour changes, and
  for gap 3 the CI job. They apply to open62541 master `24fc6b296` with
  `git am`, one branch per patch. Their author is set to Elias's GitHub
  noreply address so they can be pushed from his fork as they are. The
  commit messages follow open62541's `CONTRIBUTING.md` (Conventional Commits,
  100-column lines).
- `patches/1.5/` holds fixes for open62541's `1.5` branch: 0001 (gap 5) is a
  cherry-pick from master that keeps its upstream author, 0002 (gap 6) is a
  small fix authored by Elias. They are not applied to our build.
- `patches/v1.5.10/` holds only the library part of each patch (the
  `plugins/` and `CMakeLists.txt` changes). `scripts/build_open62541.sh`
  applies them to our pinned v1.5.10 (O3), so `push_test_server` pairs its
  certificate and key by file name, `mock_gds` no longer adds #None itself,
  the GDS headers are installed by open62541, and ConditionRefresh keeps
  EventIds. **Editing these files changes our
  build** (the CI cache key includes them). Drop each one once open62541
  releases the fix and we move the pin.

## How to post (for Elias)

Everything to paste is in the gap pages: each has a "Draft issue" and a
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
7. Gap 4 waits for the later A&C offer (G12): open the drafted issue, then the
   PR from the 0005 branch.
8. Gap 5: post the drafted backport request, then branch from `origin/1.5`,
   `git am docs/upstream/patches/1.5/0001-client-validate-server-applicationuri.patch`,
   and open the PR against `1.5` (not master) with the drafted text.
9. Gap 6: open the drafted issue, then branch from `origin/1.5`,
   `git am docs/upstream/patches/1.5/0002-sks-time-to-next-key.patch`, and open
   the PR against `1.5` with the drafted text.
10. Put the issue and PR links into the table above, or tell a thread and it
   will.
