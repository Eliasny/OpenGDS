# Gap 4: ConditionRefresh gives refreshed conditions a new EventId

**Status (2026-11-06):** found by the week 1 approvals spike ([docs/spikes/01-dialog-condition-approvals.md](../spikes/01-dialog-condition-approvals.md), finding 5). Present on our pinned v1.5.10 and on master `24fc6b296`. Not yet searched for in upstream issues and PRs: search for "ConditionRefresh EventId" and "lastEventId refresh" before posting. Elias decided (2026-11-06) to carry the fix now and to offer it upstream later, together with the A&C improvements (G12). Elias posts it (O5).

**Patch:** [patches/master/0005-condition-refresh-keep-eventid.patch](patches/master/0005-condition-refresh-keep-eventid.patch)
(backport, library part only: [patches/v1.5.10/0004-condition-refresh-keep-eventid.patch](patches/v1.5.10/0004-condition-refresh-keep-eventid.patch)). The numbers differ because master 0004 is the filestore API proposal, which is not carried.

## What goes wrong

OPC 10000-9 v1.05 §5.5.7 (ConditionRefresh): "the EventId for such a refreshed Notification shall be identical to the one for the original". `refreshLogic` (in `drivers/alarms_conditions.c` on master, `src/server/ua_subscription_alarms_conditions.c` in v1.5.10) clears `branch->lastEventId` of every retained branch and creates the refreshed event with a fresh EventId, which then becomes the branch's last EventId.

The effect goes beyond the refreshing Client. Acknowledge, Confirm and AddComment check their EventId argument against the branch's last EventId, so one Client's refresh invalidates the EventId that every other Client holds, and their next call fails with `Bad_EventIdUnknown`.

## The fix

The refreshed event gets the stored EventId through the event-field map of `UA_EventDescription` (`/EventId`), which takes precedence over the generated default. `lastEventId` is no longer cleared or replaced. That is about ten lines in `refreshLogic`, with no API change.

## Test

New test `conditionRefresh_keepsEventId` in `tests/server/check_server_alarmsconditions.c` (test case "Condition refresh"). It triggers a retained condition, refreshes twice through a local event MonitoredItem that selects `/EventType` and `/EventId`, checks that every refreshed condition Notification carries the original EventId, and checks that AddComment still accepts the original EventId.

Checked on open62541 master `24fc6b296`, Ubuntu 24.04, GCC 13, libcheck 0.15.2:

| Run | Result |
|---|---|
| master without the fix | `conditionRefresh_keepsEventId` fails (EventId differs) |
| master with the fix | `check_server_alarmsconditions` 74/74; `check_subscription_events` 69/69; `check_subscription_events_local` 15/15 |
| v1.5.10 with the backport and the other three carried patches (`scripts/build_open62541.sh`) | builds; the approvals spike reports `refreshed EventId equals the original: yes`, all checks pass |

## Draft issue

> **Title:** ConditionRefresh sends refreshed conditions with a new EventId
>
> **Version:** v1.5.10 and master (24fc6b296).
>
> **Spec:** OPC 10000-9 v1.05 §5.5.7: "the EventId for such a refreshed Notification shall be identical to the one for the original".
>
> **Steps:** create a retained condition and trigger it; note its EventId. Subscribe to events on the Server object and call ConditionRefresh.
>
> **Expected:** the refreshed Notification carries the EventId of the original one; Acknowledge/Confirm/AddComment keep accepting that EventId.
>
> **Actual:** `refreshLogic` clears the branch's `lastEventId` and creates the refreshed event with a new EventId. The original EventId is no longer accepted, so a refresh by one Client makes the next Acknowledge/Confirm/AddComment of every other Client fail with BadEventIdUnknown.

## Draft pull request

> **Title:** `fix(server): keep the EventId of conditions in ConditionRefresh`
>
> **Problem.** OPC 10000-9 §5.5.7 requires a refreshed Notification to carry the EventId of the original Notification. `refreshLogic` created the refreshed event with a new EventId and stored it as the branch's last EventId, which invalidated the EventId held by every other Client. Fixes #&lt;issue&gt;.
>
> **Solution.** Pass the stored EventId to the refreshed event through the event-field map (`/EventId`) and keep it as the branch's last EventId. No API change.
>
> **Tests.** New `conditionRefresh_keepsEventId` in `check_server_alarmsconditions`: two refreshes, both carry the original EventId, and AddComment still accepts it. Fails without the change, passes with it.
