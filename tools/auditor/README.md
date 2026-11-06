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
| `include/gdsaudit/engine.h` | The engine API the front ends use: the event stream (run started, test started, note, verdict, run finished), event sinks, abort, and the JSON Lines schema |
| `report/` | Result list built from the event stream, the JSON Lines writer and parser, the HTML and JUnit XML reports (libc only). CTest `auditor_report_events` |
| `avm/` | View-model of the desktop UI (GLib/GIO, no GTK): the plan form, presets and checks (`avm_plan.c`), and a live run of the headless engine (`avm_run.c`). CTests `avm_plan` and `avm_run_vs_push_test_server` (the UI's way of running gives the verdicts pinned for the headless run) |
| `ui/` | `gdsaudit-gui`, the GTK4 desktop app. CTest `gui_smoke` (the real window on a virtual display) |

Build:

```sh
scripts/build_openssl.sh "$HOME/.cache/openssl"         # pinned OpenSSL 3.5.9, static
OPENSSL_ROOT="$HOME/.cache/openssl" \
  scripts/build_open62541.sh "$HOME/.cache/open62541"   # pinned v1.5.10, hardened
cmake -S . -B build -G Ninja -DOPEN62541_PREFIX="$HOME/.cache/open62541" \
  -DOPENSSL_ROOT_DIR="$HOME/.cache/openssl"
cmake --build build && ctest --test-dir build --output-on-failure
```

Every subcommand also takes `--events FILE` (the event stream as JSON Lines,
schema in `engine.h`) and `--report DIR` (`report.html` and `junit.xml`).
SIGINT or SIGTERM aborts a run: later tests are Not tested and the server
profile still restores the target. SIGUSR1 pauses before the next test (the
test in progress finishes) and SIGUSR2 resumes. The HTML report has a table
per ConformanceUnit, taken from `docs/auditor/catalogue.csv`.

Desktop UI: `gdsaudit-gui` (built when GTK 4.12+ is found;
`-DOPENGDS_BUILD_AUDITOR_GUI=ON|OFF|AUTO`, needs `libgtk-4-dev`). It runs the
`gdsaudit` binary next to it (or `$GDSAUDIT_ENGINE`) with `--events` and shows
the stream live, so it holds no test logic and gives the headless verdicts.
Choose the profile (server, client, GDS) and a preset: quick read-only check,
full run, or preparation for certification (full run that needs the hooks, so
any Not tested makes the run Incomplete). Allowing changes asks for a
confirmation naming the endpoint and the pinned certificate's thumbprint, and
a banner stays while changes are allowed. Abort finishes the current test and
restores the target; closing the window during a run does the same. Each run
is kept in `~/.local/share/gdsaudit/runs/<time>-<profile>/` (`events.jsonl`,
`output.log`, `report/`); Export writes `report.html`, `junit.xml` and
`events.jsonl` to a folder. Pause waits before the next test. History lists
the kept runs, opens one (or any folder with an `events.jsonl` from a headless
`--events` run) and compares two runs test by test. The form is kept between
sessions in `~/.config/gdsaudit/last-plan.ini` (no passwords: only the paths
of password files).

Server profile against a push-managed Server (the Auditor's own certificate,
`<work>/own/cert.der`, must be trusted by the target and mapped to SecurityAdmin):

```sh
gdsaudit server --work ./w --init-only            # create the identity and test PKI
gdsaudit server --url opc.tcp://host:4840 --server-cert srv.der --work ./w --allow-changes
push_test_server --list-mutants                   # the --break faults and the test catching each
```

When the target's certificate is CA-issued (a device a GDS has already pushed),
also give its issuer and that issuer's CRL, or every session fails with
Bad_CertificateChainIncomplete:

```sh
gdsaudit server --url opc.tcp://host:4840 --server-cert srv.der \
    --target-trust gds-ca.der --target-crl gds-ca.crl --work ./w --allow-changes
```

Both options repeat for an intermediate. They are trusted wherever the pinned
certificate is, never in the checks that a new certificate from the test CA is
in use.

The push setup tests (SRV-SET-*, 12 Annex G.2) need the target in its
application setup state. They run only when selected, after `--setup-cmd`
(or the operator at a terminal) has reset it; ResetToServerDefaults is called
only with `--allow-reset`:

```sh
gdsaudit server --url opc.tcp://host:4840 --server-cert srv.der --work ./w \
    --allow-changes --only SRV-SET --setup-cmd ./factory-reset.sh --allow-reset
```

`push_test_server --setup` is the self-test's target for them: InApplicationSetup
until the SecurityAdmin Role has an identity (AddIdentity), and a
ResetToServerDefaults that starts it again from its defaults.
