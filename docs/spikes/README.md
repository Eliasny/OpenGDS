# Spikes

Week 1 (T0) throwaway prototypes from the OpenGDS plan. A spike answers one question about a dependency before production code relies on it. Its code is kept here only as evidence for the note and is not built by CI, reviewed as production code, or reused: tracer code starts fresh.

| Spike | Question | Result |
|---|---|---|
| [1. DialogCondition approvals](01-dialog-condition-approvals.md) | Can approvals use Part 9 DialogConditionType and Respond2 on open62541 v1.5.10, where A&C is experimental? | Yes, with three small workarounds. Risk drops to low. Found an open62541 conformance deviation (refresh changes EventIds), with a fix. |
| [2. Async methods on a worker pool](02-async-methods-worker-pool.md) | How do async method calls behave on timeout, Cancel, disconnect and shutdown, and how must a worker pool complete them? | Works with a handoff to the server thread. The upstream tutorial pattern deadlocks on a worker. Proposes moving signing out of the method call (open with Elias). |

Both were run against open62541 v1.5.10 (commit `93c3bdfc9ea4718b503c6cbf57876237addd0f2c`) built with the OpenGDS options, with OpenSSL 3.0 on Ubuntu 24.04, and both run clean under AddressSanitizer and UBSan with the library instrumented. Build them with [`code/build.sh`](code/build.sh).
