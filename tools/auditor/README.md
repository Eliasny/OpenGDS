# OpenGDS Auditor (gdsaudit)

Free Part 12 test tool. Results are a self-test, not OPC Foundation certification.
Layout follows the Auditor plan; this commit holds the seed code from the 2 Nov demo,
brought under the rules in `docs/architecture.md`.

| Path | Contents |
| --- | --- |
| `core/` | X.509 helpers, test CA (`TEST` subjects, 30-day validity), OPC UA client helpers with checked results |
| `selftest/` | Known-good targets: `push_test_server` (its PushManagement methods and `--break` mutants in `push_mgmt.c`), `pull_test_client`, and `run_demo.sh` (CTest `selftest_demo_flow`) |
| `profile_server/` | `gdsaudit server`: the server profile of [docs/auditor/server-profile.md](../../docs/auditor/server-profile.md), with `run_vs_push.sh` (CTest `srv_profile_vs_push_test_server`: pinned verdicts against the good target, every mutant caught). `push_driver`: the demo's CertificateManager script |
| `profile_client/` | `mock_gds`: plays a minimal GDS for pull clients, loopback only by default (seed of the client profile) |
| `profile_gds/` | OpenGDS T0 spec test programs (week 1) |

Build:

```sh
scripts/build_open62541.sh "$HOME/.cache/open62541"     # pinned v1.5.10, hardened
cmake -S . -B build -G Ninja -DOPEN62541_PREFIX="$HOME/.cache/open62541"
cmake --build build && ctest --test-dir build --output-on-failure
```

Server profile against a push-managed Server (the Auditor's own certificate,
`<work>/own/cert.der`, must be trusted by the target and mapped to SecurityAdmin):

```sh
gdsaudit server --work ./w --init-only            # create the identity and test PKI
gdsaudit server --url opc.tcp://host:4840 --server-cert srv.der --work ./w --allow-changes
push_test_server --list-mutants                   # the --break faults and the test catching each
```
