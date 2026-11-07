# Gap 8: every session receives every event

**Status (2026-11-07):** found while adding plugin dialogs (UASM ask A19). Fleet discovery opens dialogs that name servers not yet registered, with their URLs, so only some Roles should see them. The gap is present on our pinned v1.5.10. It has not been searched upstream yet; do that before posting. Elias posts it (O5).

**Patch:** [patches/v1.5.10/0006-access-control-receive-event.patch](patches/v1.5.10/0006-access-control-receive-event.patch). It is authored by Elias (O4) and is **carried** on our build (A19).

## What the spec requires

- OPC 10000-3 §8.55 (PermissionType): the ReceiveEvents bit decides whether a Role may receive the events a node reports.
- OPC 10000-9 §5.5.7: ConditionRefresh replays the retained Conditions. It must not show a session what that session could not receive live.

## What goes wrong

`createEvent` (src/server/ua_subscription_event.c) adds an event to every MonitoredItem whose node reports it and whose filter selects it. No access control is asked. A server therefore cannot keep a Condition's events, live or replayed by `refreshLogic`, to the sessions that may see it. The only restriction available is `UA_EventDescription.sessionId`, but that works only for one-off events. It does not work for Conditions, which open62541 triggers and replays itself.

## The fix

`UA_AccessControl.allowReceiveEvent(server, ac, sessionId, sessionContext, sourceNode, eventInstance)` is asked for each MonitoredItem before the event is added to it. `eventInstance` is the Condition for condition events, and NULL otherwise. ConditionRefresh goes through `createEvent` too, so the same answer covers the replay. A NULL callback (the default) keeps the current behaviour. The callback runs with the service mutex held, like the other access-control callbacks.

OpenGDS answers it in `gds_access.c` with `gds_cond_may_receive` (gds_alarms.c). A plugin alarm or dialog with `visibleTo` Roles reaches only the sessions that hold one of them, and so do the events whose SourceNode it is, such as its AuditConditionRespondEventType. `tests/unit/test_dialogs.c` covers live events, ConditionRefresh, and an alarm, with one client that holds the Role and one that does not.
