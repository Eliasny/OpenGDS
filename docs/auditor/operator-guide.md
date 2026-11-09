# OpenGDS Auditor operator guide

This guide is for the person who runs the Auditor (`gdsaudit`) against a
device or application at a test bench, in CI or in the field. It covers
what to prepare, the first read-only run, runs that change the target, the
client and GDS profiles, reading the results, and what to do when a run goes
wrong.

The Auditor is a self-test tool. Its reports say "Self-test, not OPC
Foundation certification", and a clean run is preparation for
certification, not certification.

## 1. What the Auditor tests

| Profile | Command | Target | The Auditor plays |
| --- | --- | --- | --- |
| Server | `gdsaudit server` | A push-managed OPC UA Server (it has the ServerConfiguration Object, OPC 10000-12 §7.10) | The CertificateManager that pushes certificates and trust lists |
| Client | `gdsaudit client` | An application that pulls its certificate and trust list from a GDS (§7.3, §7.6) | A GDS that breaks the rules on cue |
| GDS | `gdsaudit gds` | A Global Discovery Server | Every client role of a GDS |

Every test has an id (`SRV-TL-02`, `CLI-CSR-03`), the clause it checks and a
verdict:

| Verdict | Meaning | Effect on the run |
| --- | --- | --- |
| Pass | Behaviour matches the cited clause | |
| Fail | Behaviour contradicts the cited clause; evidence is attached | Run Failed, exit 1 |
| Warn | Allowed by the spec but risky or ambiguous | Never fails a run |
| Not supported | An Optional feature the target does not advertise | |
| Not tested | A needed step did not happen (no `--allow-changes`, no hook, no operator) | Run Incomplete, exit 3 |

The test catalogues in [README.md](README.md), [server-profile.md](server-profile.md)
and [client-profile.md](client-profile.md) give, for each test, the check,
the pass rule and every other verdict's rule.

## 2. Before the first run

1. **Install** the `gdsaudit` binary (headless) and, for a desktop, `gdsaudit-gui`.
2. **Pick a work folder** (`--work DIR`, default `./gdsaudit-work`). It holds
   the Auditor's identities and its test PKI. Keep it between runs: the target
   is told to trust the identities once.
3. **Create the identities** without touching any target:

   ```sh
   gdsaudit server --work ./w --init-only
   ```

   This writes two application certificates and a test CA:

   | File | Use on the target |
   | --- | --- |
   | `w/own/cert.der` | The plain identity. Trust it, but do **not** give it the SecurityAdmin Role |
   | `w/admin/own/cert.der` | The admin identity. Trust it and map it to SecurityAdmin (or give `--admin-user` and `--admin-password-file` instead) |
   | `w/ca/` | The Auditor TEST CA. Every certificate it issues says "OpenGDS Auditor TEST" and lives at most 30 days |

4. **Get the target's certificate** (DER) and pin it with `--server-cert`.
   Most devices export it from their configuration tool or web page, or
   `gdsaudit discover --url opc.tcp://plc:4840 --certs certs/` lists the
   endpoints (policy, mode, user tokens, thumbprint) and writes each server
   certificate as `<SHA-1 thumbprint>.der`; check the thumbprint against the
   device before you pin it. The UI's Targets window does the same.
   `--tofu` (trust on first use) exists for test setups only.
5. **CA-issued targets.** When a GDS already pushed the target's certificate,
   give its issuer and CRL too, or every session fails with
   Bad_CertificateChainIncomplete:
   `--target-trust gds-ca.der --target-crl gds-ca.crl` (repeat for an
   intermediate).
6. **Passwords** are always read from files (`--admin-password-file`,
   `--user-password-file`, `--password-file`), never from the command line or
   a plan file. Keep those files readable only by you.

## 3. First run: read-only

Without `--allow-changes` only tests that read run; every test that would
change the target is Not tested. Start here on any device you care about.

```sh
gdsaudit server --url opc.tcp://plc:4840 --server-cert certs/plc.der \
    --work ./w --report results/plc-ro
```

The run prints TAP as it goes. At the end `results/plc-ro/` holds
`report.html`, `junit.xml`, `report.json` and `report.tap`. Expect exit 3
(Incomplete) on a read-only run.

## 4. Runs that change the target

`--allow-changes` lets the server profile push trust lists and
certificates. Before the first write the Auditor reads and saves every
CertificateGroup's trust list and certificates; at the end, on error and on
Ctrl-C it pushes them back and applies them. The restore is its own line in
the report (`SRV-RESTORE`) with its own verdict.

```sh
gdsaudit server --url opc.tcp://plc:4840 --server-cert certs/plc.der \
    --work ./w --allow-changes --report results/plc-full
```

Rules for live targets:

- Do not run against a device in production. A push changes the certificate
  peers use to reach it, and a target that does not apply changes
  atomically can be left half-changed if it crashes mid-test.
- SRV-UPD-09 (a pushed private key replaces the target's own) changes state
  the snapshot cannot restore, so it runs only when selected by name
  (`--only SRV-UPD-09`).
- If the restore line is not Pass, the run ends with exit 1. Check the
  target's trust list and certificate by hand before it goes back into
  service.
- Stopping a run: Ctrl-C (or SIGTERM, or Abort in the UI) lets the test in
  progress finish, marks the rest Not tested, and restores the target. A
  second Ctrl-C kills the Auditor without a restore.
- Pausing: SIGUSR1 (or Pause in the UI) waits before the next test; SIGUSR2
  resumes.

### Restarts, the setup state and operator steps

Some tests need something done to the target between steps:

| Tests | Need | Give |
| --- | --- | --- |
| SRV-PER-* (changes survive a restart) | The target restarted | `--restart-cmd CMD`: a command that starts the restart and returns |
| SRV-SET-* (application setup state, Annex G.2) | The target reset to its setup state | `--only SRV-SET --setup-cmd CMD`; ResetToServerDefaults (SRV-SET-06) only with `--allow-reset` |
| Any test marked O in the catalogue | A manual step by a person | An operator (below) |

Without the command or an operator, those tests are Not tested. The setup
tests run only when selected by name and are in no preset, because a reset
removes the target's configuration.

An operator answers manual steps. At a terminal, `--prompts /dev/stdin`
lets you answer as the run goes: the Auditor prints the step and waits for
`<n> done`, `<n> skip` or `<n> fail <note>`. Skip leaves the test Not
tested; fail fails it with your note. To repeat a run unattended, keep the
answers in a file and give it with `--prompts FILE` (or `hooks.prompts` in a
plan). Without `--prompts`, every manual step is skipped. In the desktop UI
an Operator step window asks instead.

Optional identities widen the run: `--user U --user-password-file F` (an
authenticated user without SecurityAdmin; tests that need it are Not tested
otherwise), and `--slow` for tests that take more than a minute.
`--settle-timeout S` (default 300) is how long the Auditor waits for the
target to re-key channels and close sessions after a change; past 30 s it
warns, past S it fails.

## 5. Client profile

The client profile waits for the application under test to come to the
Auditor's fake GDS. Each test starts the application's pull cycle through a
**trigger**: the program after `--` on the command line. The Auditor runs it
with the GDS URL, CA, CRL, user and password file in `GDSAUDIT_*`
environment variables ([client-profile.md](client-profile.md) lists them and
the `GDSAUDIT_ACTION` values for probe, restart and run).

```sh
gdsaudit client --listen 4850 --work ./wc --report results/hmi \
    -- ./pull-once.sh --device hmi-7
```

Before the run, make the application trust the fake GDS's certificate once
(the out-of-band step of Annex G.1). The fake GDS listens on localhost unless
`--listen-any` is given; the probe server uses the next port. Without a
trigger, the tests that need one are Not tested.

## 6. GDS profile

```sh
gdsaudit gds --url opc.tcp://gds:58810 --trust gds-ca.der --crl gds-ca.crl \
    --user admin --password-file admin.pw --work ./wg --report results/gds
```

The GDS is trusted explicitly (`--trust`, at least one). Add the Auditor's
`<work>/own/cert.der` to the GDS's trust list once. Without
`--allow-changes` the tests that register applications or issue
certificates are Not tested. Each run tags what it creates with a random run
tag printed at the start.

## 7. Plan files and the desktop UI

A plan file holds a whole run so it repeats exactly
([plan-files.md](plan-files.md)):

```sh
gdsaudit run plans/plc.toml
```

The desktop UI (`gdsaudit-gui`) runs the same engine, so it gives the same
verdicts. Read-only is its default; allowing changes asks for a confirmation
naming the endpoint and the target certificate's thumbprint. Its presets: quick read-only check, full
run, and preparation for certification (a full run that needs the hooks, so
any Not tested makes it Incomplete).

## 8. Reading the results

| File | For |
| --- | --- |
| `report.html` | People: summary, a table per ConformanceUnit, every test with clause, evidence and notes |
| `junit.xml` | CI: Fail is a failure, Not supported and Not tested are skipped |
| `report.tap` | The shell: TAP 13 with a YAML block per test |
| `report.json` | Machines and UASM: schema in [report-json.md](report-json.md) |
| `--events FILE` | The live event stream as JSON Lines; the UI's History window opens it |

Exit codes: 0 all passed (Warns allowed), 1 at least one Fail (or a failed
restore), 2 the run could not be done (bad options, target unreachable,
unreadable plan, report not written), 3 no Fail but some Not tested.

When a test fails, start from its row in the catalogue: the Check column
says what the Auditor did, the evidence line gives the status code or
thumbprint it saw. To repeat one test, use `--only SRV-TL-02` (a prefix
selects a group: `--only SRV-TL`).

## 9. Windows

The headless `gdsaudit.exe` is one static program in a zip with its
licences; it needs no DLLs beyond Windows' own. It runs the same tests and
gives the same verdicts, with these differences:

- **File protection.** Windows has no Unix mode bits. Keep the work folder
  (it holds private keys) and password files in your own profile, such as
  `%LOCALAPPDATA%\gdsaudit`, where NTFS permissions keep other users out.
- **Pausing.** There is no SIGUSR1. Ctrl-C and Ctrl-Break abort and restore
  as on Linux; to pause, use the desktop UI.
- **Client triggers.** The program after `--` can be an `.exe`, or a `.bat`
  or `.cmd` script (run through `cmd /c`). It gets the same `GDSAUDIT_*`
  variables plus the Windows basics (`SystemRoot`, `PATHEXT`, `TEMP`,
  profile folders).
- **Hooks and prompts.** `--restart-cmd` and `--setup-cmd` run through
  `cmd.exe /c`, so give a Windows command (a `.bat`, or `ssh` to the
  device). `--prompts` reads a file of answers prepared before the run.
- Paths in plan files can use `/`, or `\` inside single-quoted TOML strings
  (`dir = 'C:\audits\plc'`); a relative path is taken from the plan file's
  folder as on Linux.

## 10. Troubleshooting

| Symptom | Likely cause and fix |
| --- | --- |
| Every test Not tested with `setup: admin session -> BadSecurityChecksFailed` | The target does not trust `<work>/admin/own/cert.der`, or does not map it to SecurityAdmin |
| Every session fails with Bad_CertificateChainIncomplete | The target's certificate is CA-issued: add `--target-trust` and `--target-crl` |
| `BadCertificateUntrusted` on the plain identity | Trust `<work>/own/cert.der` on the target |
| Tests needing `user` are Not tested | Give `--user` and `--user-password-file` |
| SRV-PER tests are Not tested | Give `--restart-cmd`, or answer the restart prompt (`--prompts`) |
| Client tests are all Not tested | No trigger after `--`, or the trigger exits nonzero; see `<work>/trigger.log` |
| A wire test warns after 30 s | The target took longer than 30 s to re-key; it fails only past `--settle-timeout` |
| The run ends with `restore FAILED` | Check and fix the target's trust list and certificate by hand before reuse |

To check the Auditor itself, run it against its self-test targets:
`push_test_server` (and `push_test_server --list-mutants` for the faults
each test must catch) and `pull_test_client`. CI does this on every change.
