# Spike 1: DialogCondition approvals on open62541 v1.5.10

Status: done, 6 Nov 2026 (week 1, T0). Throwaway: the code in [`code/spike_dialog.c`](code/spike_dialog.c) is evidence for this note, not a start for `gds_approvals.c`.

## Question

The OpenGDS plan (01, `gds_approvals.c` and Risks) puts every pending approval in a Part 9 **DialogConditionType** instance with the options Approve and Reject, answered with the standard **Respond2** method. Alarms & Conditions are flagged experimental in open62541 v1.5.10. Does that work well enough for the MVP (week 5), or do we need the fallback of emitting DialogConditionType events by hand?

## Answer

**It works, with three small workarounds in our code and one configuration setting.** No fallback is needed. The risk drops from high to low: the gaps are missing features in the A&C helper API, not broken behaviour, and each one is a few lines.

The spike runs one server and one client in one process, against open62541 v1.5.10 built by `scripts/build_open62541.sh` (commit `93c3bdf`, `UA_ENABLE_SUBSCRIPTIONS_ALARMS_CONDITIONS=ON`, `UA_MULTITHREADING=100`). All 26 checks pass, and it runs clean under AddressSanitizer and UBSan with the library itself instrumented.

| Check | Result |
|---|---|
| Create a DialogConditionType instance under an "Approvals" source object, set Prompt, ResponseOptionSet, Ok/Cancel/Default/LastResponse, DialogState, Retain, and trigger it | Works (after workaround 2) |
| Client subscribed to the Server object, ConditionRefresh | RefreshStart, every pending dialog with `DialogState/Id = true` and `Retain = true`, RefreshEnd |
| ResponseOptionSet `[Approve, Reject]` through the event filter | Delivered |
| New dialog while subscribed | Delivered without a refresh |
| Respond2(Approve, comment) | Good; request state changes; event with `DialogState/Id = false`, `Retain = false`; LastResponse readable in the address space |
| AuditConditionRespondEventType (AlwaysGeneratesEvent of Respond2) | Emitted from a key-value map with `UA_Server_createEvent`, no instance node needed |
| Respond2 again on a decided dialog | `Bad_DialogNotActive` |
| Respond2 with response 7 | `Bad_DialogResponseInvalid` |
| Respond2 with a String instead of Int32 | `Bad_InvalidArgument`, rejected by the stack before our callback |
| Respond2 on the Server object | `Bad_MethodInvalid` |
| Respond2 by a session without the role (access control `getUserExecutableOnObject` says no) | `Bad_UserAccessDenied`, request stays pending |
| ConditionRefresh after decisions | Only the still-pending dialog is resent |
| `UA_Server_deleteCondition` on a decided dialog, then Respond2 | Good, then `Bad_NodeIdUnknown` |
| 1,000 / 2,000 dialogs | Created at 0.7 to 1.0 ms each; refresh of 2,001 retained dialogs takes 216 ms inside the call; 100 Respond2 round trips take 0.25 ms each |

## What the library does not do, and what we do instead

1. **Respond2 is not callable on an instance.** Respond2 is *Optional* on DialogConditionType (ModellingRule `i=80`), so instantiation does not reference it and Call returns `Bad_MethodInvalid`. `UA_Server_addConditionOptionalField` does not handle methods (marked TODO upstream). Workaround: after `UA_Server_createCondition`, add a `HasComponent` reference from the instance to the type's method node `i=24312`. One callback is bound to that node with `UA_Server_setMethodNodeCallback` and serves every dialog; it finds the pending request through the node context (`UA_Server_setNodeContext`), which arrives as `objectContext`.
2. **`UA_Server_setConditionField` refuses arrays** (`Bad_NotImplemented`, "TODO implement logic for array variants"). ResponseOptionSet is an array. Workaround: resolve the field with `UA_Server_browseSimplifiedBrowsePath` and write it with `UA_Server_writeValue`.
3. **Respond (the 1.04 method) has no callback** and returns `Bad_InternalError`. It is Mandatory on the type, so generic clients may call it. Bind the same handler to `i=9069` (no comment argument), so both methods behave the same.
4. **Event queue size is capped at 100 by default** (`queueSizeLimits = 1..100` in the default config). A refresh with 1,001 pending dialogs delivered 99 and one EventQueueOverflow event; with the cap raised it delivered all 1,001 and 2,001. Set `queueSizeLimits.max` in `gds_config.c` (proposed 10,000) and document the limit on pending approvals per subscription.

## Behaviour to design around

- **Condition state lives only in the address space.** After a restart the dialogs are gone. `gds_approvals.c` must rebuild them at start-up from the store (every request in state `pending`), before the endpoint opens. The store is the truth; the condition is a view of it.
- **Write the decision to the store before touching the condition.** The Respond2 handler commits the state change in one store transaction, then updates the fields and triggers the event. If the commit fails, the call fails and the dialog stays active.
- **Delete decided conditions.** Each instance is a few dozen nodes; decided ones are only needed until their final event is sent. Delete them right after the `Retain = false` event (as the spike does) or in the hourly job.
- **ConditionRefresh holds the server lock** for the whole refresh, about 0.1 ms per retained condition (216 ms for 2,001). Fine for approvals; a reason to cap pending approvals rather than let them grow without bound.
- **Refresh changes EventIds** (from reading `refreshLogic` in `src/server/ua_subscription_alarms_conditions.c`: it clears `lastEventId` and creates a new event). Respond2 takes no EventId, so approvals are not affected. It matters for the later CertificateExpirationAlarmType (W4): an Acknowledge with an EventId from before another client's refresh can fail with `Bad_EventIdUnknown`. Test that in `test_spec_events.c`.
- **Role check belongs in access control, not the handler.** `getUserExecutableOnObject` sees the method, the object and the session, so the Part 18 role check (RegistrationAuthorityAdmin for requests, DiscoveryAdmin for registrations) is one place. The handler can still check again, cheaply.
- **The handler runs on the server thread with the server lock held.** Calling `UA_Server_*` from inside it is fine (the lock is recursive). A store write in the handler blocks the network loop for its duration; with SQLite WAL and one writer that is about a millisecond, so Respond2 stays synchronous. If it ever grows, it becomes an async method like the ones in [spike 2](02-async-methods-worker-pool.md).

## Changes this suggests to the plan

| Where | Change |
|---|---|
| 01 Risks, "A&C experimental" | Downgrade to low. Keep `gds_approvals.c` as the only file that touches A&C. The hand-rolled event fallback is not needed. |
| `src/server/gds_approvals.c` | Workarounds 1 to 3 above; rebuild from the store at start-up; store first, then condition; delete when decided. |
| `src/server/gds_config.c` | `queueSizeLimits.max = 10000`; a configured cap on pending approvals. |
| `tests/spec/test_spec_events.c` | Add: refresh after restart shows the pending dialogs; Respond (1.04) and Respond2 both work; second answer gives `Bad_DialogNotActive`; wrong role gives `Bad_UserAccessDenied`; more pending dialogs than the queue cap. |
| Upstream | Two small patches worth offering to open62541: methods in `addConditionOptionalField`, arrays in `setConditionField`. Not on our critical path. |

## How to run it

```sh
scripts/build_open62541.sh /tmp/o62541          # arrives with the build/CI pull request
docs/spikes/code/build.sh /tmp/o62541
docs/spikes/code/spike_dialog 1000              # default queue cap: shows the overflow
QUEUE_MAX=20000 docs/spikes/code/spike_dialog 2000
```
