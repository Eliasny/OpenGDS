# Gap 10: ConditionRefresh fails before the first Condition

**Status (2026-11-09):** found while building `gdsadm watch` (OpenGDS plan W5). Present on our pinned v1.5.10. open62541 master no longer has `src/server/ua_subscription_alarms_conditions.c` (checked at `09df022`, 2026-11-08), so the fix is offered for the `1.5` branch. Elias decided on 2026-11-09 to **carry** it; he posts it upstream himself (O5).

**Patch:** [patches/v1.5.10/0008-condition-refresh-before-first-condition.patch](patches/v1.5.10/0008-condition-refresh-before-first-condition.patch) (library only, carried on our build) and [patches/1.5/0003-condition-refresh-before-first-condition.patch](patches/1.5/0003-condition-refresh-before-first-condition.patch) (the same commit with its test, made on v1.5.10 plus 0001 to 0006; check it against the `1.5` head before posting). Authored by Elias (O4).

## What the spec requires

OPC 10000-9 §5.5.7: a client calls ConditionRefresh (or ConditionRefresh2) after it subscribes, and the server answers with a RefreshStartEvent, one event per retained Condition, and a RefreshEndEvent. With no retained Condition the client still gets RefreshStart and RefreshEnd. Nothing in §5.5.7 lets the call fail because no Condition exists yet.

## What goes wrong

The ConditionType Methods (Disable, Enable, AddComment, ConditionRefresh, ConditionRefresh2, Acknowledge, Confirm) get their callbacks in `setStandardConditionCallbacks`, and only when the first ConditionSource is added (`LIST_EMPTY(&server->conditionSources)`). Until then the Method nodes have no callback, and the Call service answers Bad_InternalError. A client that subscribes to a fresh server and calls ConditionRefresh, as Part 9 asks, gets an error, and may conclude the server does not support Conditions at all.

Seen on opengdsd: `gdsadm watch` against a GDS with no alarm and no waiting request printed `ConditionRefresh: BadInternalError`; once a request waited for approval (a DialogCondition), the same call worked.

## The fix

`UA_ConditionList_initMethods` sets the Method callbacks once in `UA_Server_init`, after namespace 0 is built (only with the full namespace 0, which holds the ConditionType nodes). `setStandardConditionCallbacks` no longer sets them. No API change.

## Test

`tests/server/check_server_alarmsconditions.c`, `conditionRefresh_beforeFirstCondition`: ConditionRefresh with an unknown SubscriptionId on a server without Conditions must answer Bad_SubscriptionIdInvalid (the callback ran) and not Bad_InternalError (no callback). Without the fix: 48/49, the new test fails with 0x80020000 (Bad_InternalError). With it: 49/49 (local, Ubuntu 24.04, GCC 13, 2026-11-09).

On opengdsd, `tests/integration/disc/run_mdns_watch.sh` step 4 checks that `gdsadm watch` gets through ConditionRefresh on a GDS with no Condition yet.

## Draft issue (for the `1.5` branch)

> **ConditionRefresh returns BadInternalError until the first Condition is created**
>
> On v1.5.10 with `UA_ENABLE_SUBSCRIPTIONS_ALARMS_CONDITIONS`, calling `ConditionType.ConditionRefresh` (i=3875) before any Condition exists returns `BadInternalError`. The Method callbacks of ConditionType are only set in `setStandardConditionCallbacks` when the first ConditionSource is added. OPC 10000-9 §5.5.7 expects RefreshStartEvent and RefreshEndEvent in that case. Clients that call ConditionRefresh right after subscribing (as Part 9 recommends) see an error on every server that has no active Condition yet.

## Draft pull request

> **fix(server): ConditionRefresh before the first Condition**
>
> Set the ConditionType Method callbacks once at server initialization instead of when the first ConditionSource is added, so ConditionRefresh and ConditionRefresh2 work before the first Condition (OPC 10000-9 §5.5.7). Adds `conditionRefresh_beforeFirstCondition` to `check_server_alarmsconditions`; it fails with BadInternalError without the change.
