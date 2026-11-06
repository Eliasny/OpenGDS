# Spike 2: async methods on a worker pool, open62541 v1.5.10

Status: done, 6 Nov 2026 (week 1, T0). Throwaway: the code in [`code/spike_async.c`](code/spike_async.c) is evidence for this note, not a start for `src/common/threadpool.c`.

## Question

The architecture ([Threads and ownership](../architecture.md#threads-and-ownership-across-them)) says the open62541 thread only decodes, dispatches and encodes, and that anything slower than a lookup runs as an async method on a worker pool, completed with `UA_Server_setAsyncCallMethodResult`. How does the v1.5.10 async API behave on timeouts, Cancel, disconnects and shutdown, and how must the pool hand results back without races or deadlocks?

## Answer

**The async Call API does what we need, but only with one completion pattern.** The pattern from the upstream tutorial, moved onto a worker thread, deadlocks; the spike reproduces that every time. The safe pattern is: workers never touch open62541 memory and never hold one of our locks while calling into open62541; results are handed back to the server thread, which writes the output and completes the call.

The spike also changes how much needs to be async at all: Part 12 is already asynchronous by protocol (StartSigningRequest / StartNewKeyPairRequest return a request id, FinishRequest returns `Bad_NothingToDo` until the result exists), so signing and key generation do not have to happen inside a method call.

## What was measured

8 workers, a bounded queue of 16, `asyncOperationTimeout = 1500 ms`, `maxAsyncOperationQueueSize = 256`. All checks pass in the default (handoff) pattern, also under ASan and UBSan with the library instrumented.

| Check | Result |
|---|---|
| 16 calls of 200 ms each | All Good with output, 408 ms wall time (serial would be 3,200 ms) |
| Read on a second session meanwhile | Under 0.5 ms (idle: 0.05 ms) |
| 40 calls at once against a queue of 16 | About 24 Good, the rest `Bad_ServerTooBusy` at once (D2), nothing queued without bound |
| 4 s job against the 1.5 s timeout | Client gets `Bad_Timeout` (the check runs once a second, so it fires at 1.5 to 2.5 s); the worker's late result is dropped, never written into freed memory |
| Cancel service on a pending call | `cancelCount = 1`; response `Bad_RequestCancelledByClient` with no results; late result dropped |
| Client disconnects mid-call | open62541 does **not** cancel the operation. The job completes, the response is dropped ("Session no longer exists") |
| 8 RSA-2048 key generations on the pool | 0.6 to 0.8 s in total; Read latency meanwhile at most 5 ms |
| Shutdown with calls in flight | Stop the loop, join the workers, complete what finished, then `UA_Server_delete` cancels the rest with `Bad_Shutdown`. Clean under ASan |
| `PATTERN=deadlock` (tutorial pattern on a worker, job lock held across the timeout tick) | **Deadlock**, every run: the watchdog fires after 10 s |

## How the API behaves (v1.5.10)

- The method callback returns `Good_CompletesAsynchronously`. The **output array pointer** identifies the operation; `UA_Server_setAsyncCallMethodResult(server, output, status)` completes it. After a cancel that memory is freed, and the same address can be reused by a later call, so a late `setAsyncCallMethodResult` with a stale pointer could complete the *wrong* operation. Never keep the output pointer anywhere a worker can see it.
- `asyncOperationCancelCallback(server, out)` is called **with the server lock held**: from the timeout check (server thread, once a second), from the Cancel service (server thread) and from `UA_Server_delete` (whichever thread deletes).
- The "server lock" is the **event loop mutex plus the service mutex** (`lockServer` in `ua_server.c`). The event loop holds its mutex for the whole iteration, timers and network processing included. So any `UA_Server_*` call from a worker waits for the current loop iteration to finish. That is fine for one completion, but a worker must never call into open62541 while it holds something the server thread may want.
- Method callbacks, A&C callbacks and our timed callbacks all run on the server thread. User timed callbacks run without the service mutex, but on the same thread as the cancel callback, so state touched only by these is single-threaded.
- Defaults: `maxAsyncOperationQueueSize = 0` (unlimited) and `asyncOperationTimeout = 120000 ms`. An unlimited queue is a memory denial-of-service; we must set both.
- A CallRequest with several methods is answered only when the last async one completes.

## Why the tutorial pattern deadlocks on a worker

`examples/tutorial_server_method_async.c` protects its job with a lock, and completes the call while holding that lock. It does this from a timer on the server thread, where it is safe. On a worker thread the lock order turns around:

```
worker:        job lock  ->  UA_Server_setAsyncCallMethodResult  ->  server lock (waits)
server thread: server lock (checkTimeouts)  ->  cancel callback  ->  job lock (waits)
```

ThreadSanitizer reports this as a lock-order inversion on every run of `PATTERN=direct`, and `PATTERN=deadlock` makes it hang deterministically by holding the job lock across the one-second timeout tick.

## The pattern that works (handoff)

1. **Server thread, method callback.** Check the arguments, refuse at once with `Bad_ServerTooBusy` if our queue is full (D2), deep-copy the inputs into a job (`UA_copy`), record the job and its output pointer in an in-flight table, queue the job, return `Good_CompletesAsynchronously`.
2. **Worker.** Run the job using only job-owned memory. Push the finished job onto a completion list (its own mutex, held only for the list operation), release it, then wake the server thread with `UA_Server_addTimedCallback(now)`. No lock of ours is held during that call.
3. **Server thread, completion callback.** Take the completion list. For each job whose output pointer is still set, write the output and call `UA_Server_setAsyncCallMethodResult`; otherwise drop the result. Free the job.
4. **Cancel callback.** Find the job by output pointer in the in-flight table and set its output pointer to NULL. No lock is taken.

The in-flight table and the output pointers are touched only on the server thread (or by `UA_Server_delete` after the loop has stopped), so they need no lock, and the pointer-reuse problem cannot happen. Workers and the server thread share only the job queue and the completion list.

**Shutdown order:** stop the loop (`running = false`, join the server thread); stop the pool and join the workers; run the completion callback once on the deleting thread; then `UA_Server_delete`, which cancels whatever is left.

## ThreadSanitizer noise from open62541 itself

Even in the safe pattern, TSan reports two lock-order inversions inside open62541: the timer mutex taken under the event loop mutex in `UA_Server_addTimedCallback` / `UA_Timer_add`, and the reverse inside `UA_Timer_process` (timer callbacks run with the timer mutex held and then take the server lock). Both paths always hold the event loop mutex first, so the event loop mutex gates them and they cannot deadlock. TSan's deadlock detector does not model such gate locks. The CI `tsan` job (`halt_on_error=1`) will stop on these as soon as a test runs a threaded server, so it needs a suppressions file:

```
# tsan.supp: open62541 v1.5.10, timer mutex is always nested in the event loop mutex
deadlock:UA_Timer_add
deadlock:UA_Timer_process
```

## Decisions from the specifications

**D1. Timeouts (Elias's decision, 6 Nov 2026: 30 s).** The Server cancels an async operation after **30 s**, or earlier when the Client's `timeoutHint` is shorter, and answers `Bad_Timeout`. Part 4 v1.05 §7.32 (RequestHeader, `timeoutHint`): for a Server the value "is only a hint"; it may be used to cancel long-running operations to free resources, the Server then returns `Bad_Timeout`, and 0 means no timeout. The same clause says the Server should wait at least the `timeoutHint` before cancelling, so a Client that sends a hint longer than 30 s gets cancelled before its hint runs out; that is the accepted cost of the 30 s bound. open62541 v1.5.10 ignores `timeoutHint` for async operations and applies one global `asyncOperationTimeout`, so: `asyncOperationTimeout = 30000`, and the method callback stores min(`timeoutHint`, 30 s) as the job's deadline; a worker skips a job whose deadline has passed and completes it with `Bad_Timeout`. Note the timeout check in open62541 runs once a second, so the global cancel lands up to a second late.

**D2. A full queue (Elias's decision, 6 Nov 2026: 256).** The async queue holds **256** operations. Part 4 v1.05 §7.38.2 Table 178: `Bad_TooManyOperations` means "the request ... specified too many operations" (the request itself is too large, as checked against the OperationLimits); `Bad_ServerTooBusy` means "the Server does not have the resources to process the request at this time". A full queue is the second case, so OpenGDS answers `Bad_ServerTooBusy`. open62541's own `maxAsyncOperationQueueSize` answers `Bad_TooManyOperations`, so our worker queue enforces the 256 and open62541's limit is set just above it (257) as a backstop that is never reached first.

**D3. Cancel and shutdown.** Table 178: `Bad_RequestCancelledByClient` and `Bad_Shutdown` are the codes; open62541 already uses both (measured above).

## Changes this suggests

| Where | Change |
|---|---|
| `docs/architecture.md`, Threads and ownership | Add: "No lock of ours is held across any call into open62541. Async results are completed on the server thread; workers never see the output pointer. The cancel callback runs under the server lock and takes no lock." |
| `src/common/threadpool.c` | The handoff pattern above; queue of 256 that refuses with `Bad_ServerTooBusy` (D2); per-job deadline min(`timeoutHint`, 30 s) (D1); shutdown order as above. |
| `src/server/gds_config.c` | `asyncOperationTimeout = 30000` (D1); `maxAsyncOperationQueueSize = 257` as a backstop above our queue of 256 (D2). |
| `src/server/gds_certmgr.c` | StartSigningRequest / StartNewKeyPairRequest validate and store the request (synchronous, about a millisecond), return the request id, and queue signing or key generation as a background job, not as an async method call. FinishRequest reads the store. A disconnect then loses nothing, because the result is in the store, and no call ties up a session while the signer works. Async method calls stay for calls that must answer with a slow result (for example UpdateCertificate push work on a managed server). |
| CI | `tsan.supp` as above for the `tsan` job, with a comment naming the open62541 version, so it is re-checked when the pin moves. |
| Tests | Timeout, Cancel, disconnect mid-call, queue full and shutdown with calls in flight, each under TSan and ASan. |

## How to run it

```sh
docs/spikes/code/build.sh /tmp/o62541
docs/spikes/code/spike_async                      # handoff pattern, all checks
PATTERN=deadlock docs/spikes/code/spike_async     # hangs; the watchdog reports it after 10 s
CFLAGS=-fsanitize=thread LDFLAGS=-fsanitize=thread docs/spikes/code/build.sh /tmp/o62541
PATTERN=direct docs/spikes/code/spike_async       # TSan: lock-order inversion with the cancel callback
```
