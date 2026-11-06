# Gap 6: SKS GetSecurityKeys returns a garbage TimeToNextKey

**Status (2026-11-06):** found by the UASM spec tests (UASM PR #34, SKS-037), which run against open62541's SKS as the reference implementation. The value there was about −1.16e13 ms. Present on our pinned v1.5.10 and on the `1.5` branch (`9a3f02a6d`). **Fixed on master**, but only inside the large feature commit `2745dd876` ("feat(pubsub): implement SKS information model methods", 2026-08), which cannot be backported as it is. No upstream issue or PR names it (searched "TimeToNextKey" and "GetSecurityKeys", 2026-11-06). The ask upstream is a small fix for `1.5`. Elias posts it (O5).

**Patch:** [patches/1.5/0002-sks-time-to-next-key.patch](patches/1.5/0002-sks-time-to-next-key.patch), against `origin/1.5` and authored by Elias (O4). Its library part also applies to v1.5.10 after our four carried patches. It is **not carried** on our build, because neither OpenGDS nor UASM uses open62541's SKS (see "OpenGDS and UASM" below).

## What the spec requires

OPC 10000-14 v1.05 §8.3.2 (GetSecurityKeys): TimeToNextKey is the time, in milliseconds, before the current key expires, and KeyLifetime is the lifetime of each key. So 0 ≤ TimeToNextKey ≤ KeyLifetime. A Subscriber uses it to know when to switch to the next key. UASM's catalogue row SKS-037 states the same bound.

## What goes wrong

`getSecurityKeysAction()` in `src/pubsub/ua_pubsub_ns0_sks.c` computes `KeyLifetime − (now − sg->baseTime)` on the EventLoop's monotonic clock. In 1.5, `UA_SecurityGroup.baseTime` is declared in `ua_pubsub_internal.h` but never assigned. It stays 0 from `calloc`, so the result is the KeyLifetime minus the whole monotonic clock: a large negative number (about −1.16e13 ms on a Linux host, −154290 ms under the unit tests' fake clock). Nothing keeps the value in range either.

## The fix

- `ua_pubsub_securitygroup.c`: set `sg->baseTime` to the monotonic now when the rollover timer is added (`initializeKeyStorageWithKeys`) and on every rollover (`updateSKSKeyStorage`, next to `modifyTimer`).
- `ua_pubsub_ns0_sks.c`: clamp TimeToNextKey to between 0 and the KeyLifetime.

Master does the same in `2745dd876`: it sets baseTime in the same places and clamps at 0. The change is nine added lines, with no API or ABI change.

## Test

In `tests/pubsub/check_pubsub_sks_pull.c` (needs `UA_ENABLE_PUBSUB_SKS` and mbedTLS):

- `getSecuritykeysGoodAndValidOutput` now also checks KeyLifetime = 2000 ms and 0 < TimeToNextKey ≤ 1000 ms, one second into the first key.
- New `timeToNextKeyAfterRollover`: after one rollover, the current token is 2 and 0 < TimeToNextKey ≤ 2000 ms.

Checked on `origin/1.5` `9a3f02a6d`, Ubuntu 24.04, GCC 13, mbedTLS 2.28.8, Debug:

| Run | Result |
|---|---|
| Tests without the library change | `check_pubsub_sks_pull` 9/11: TimeToNextKey −154290 and −160790 |
| With the change | `check_pubsub_sks_pull` 11/11; `check_pubsub_sks_securitygroups` 13/13, `check_pubsub_sks_keystorage` 12/12, `check_pubsub_sks_push` 7/7, `check_pubsub_sks_client` 11/11 |
| Library part on v1.5.10 after our four carried patches | applies cleanly |

## OpenGDS and UASM

- OpenGDS does not build PubSub, so it is not affected.
- UASM has its own SKS (`sks/`), which computes TimeToNextKey itself; its unit test SKS-037 checks the bound. open62541's SKS is only the reference target of UASM's spec tests (`scripts/build_open62541_pubsub.sh`), where SKS-037 is pinned as a known failure. UASM does not need the fix carried. Carrying it there would only flip that pinned verdict.

## Draft issue

> **Title:** SKS GetSecurityKeys returns a large negative TimeToNextKey on 1.5
>
> **Version:** v1.5.10 and the `1.5` branch (9a3f02a6d), `UA_ENABLE_PUBSUB_SKS`, mbedTLS.
>
> **Steps:** add a SecurityGroup with `UA_Server_addSecurityGroup` (KeyLifetime e.g. 2000 ms), then call GetSecurityKeys from an authorised session.
>
> **Expected:** TimeToNextKey between 0 and the KeyLifetime: the time before the current key expires (Part 14, 8.3.2).
>
> **Actual:** about −1.16e13 ms. `getSecurityKeysAction()` computes `keyLifeTime − (now − sg->baseTime)`, but `baseTime` is never assigned on 1.5, so it is 0 and the whole monotonic clock is subtracted.
>
> Master fixed this as part of 2745dd876 (the SKS information model work), which is too large to backport. A minimal fix for 1.5 is ready (PR to follow).

## Draft pull request (against `1.5`)

> **Title:** `fix(pubsub): return the remaining key lifetime as TimeToNextKey`
>
> **Problem.** GetSecurityKeys returns `keyLifeTime − (now − baseTime)` as TimeToNextKey, but on 1.5 `UA_SecurityGroup.baseTime` is never set, so the value is hugely negative. Part 14, 8.3.2 defines TimeToNextKey as the time before the current key expires. Fixes #&lt;issue&gt;.
>
> **Solution.** Set `baseTime` when the rollover timer is added and on every rollover, and clamp TimeToNextKey to between 0 and the KeyLifetime. This matches what master does since 2745dd876. No API or ABI change.
>
> **Tests.** `check_pubsub_sks_pull`: the valid-output test now checks the TimeToNextKey bound, and a new test checks it after a rollover. Both fail without the change and pass with it; the other SKS suites pass.
