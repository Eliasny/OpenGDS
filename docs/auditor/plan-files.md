# Auditor plan files

A plan file describes one Auditor run: the profile, the target, the
Auditor's identity, which tests to run, the client's trigger and where the
reports go. The same plan gives the same run headless and from the desktop
UI:

```sh
gdsaudit run plans/plc.toml                 # the plan as it is
gdsaudit run plans/plc.toml --only SRV-TL   # options after the plan add to it
```

The desktop UI opens and saves plans (Open plan…, Save plan…) and builds
every run's command line from the plan of its form, so a plan saved there
runs headless unchanged (CTest `avm_plan`, `avm_plan_vs_headless`). It keeps
the keys its form has no field for; `report.*` and `hooks.prompts` belong to
each UI run and are not taken from a plan.

`gdsaudit run` prints the command line the plan stands for (`# plan ...:`)
and then runs exactly that command line, so a plan run and a command-line run
give the same verdicts (CTest `auditor_run_plan`). Options given after the
plan come after the plan's own options; where an option takes one value the
later one wins, and repeatable options (`--target-trust`, `--trust`, `--crl`)
add to the plan's.

Exit codes are those of the profile: 0 all passed, 1 at least one Fail, 2 the
run could not be done (including a plan that cannot be read), 3 no Fail but
some Not tested.

## Format

A plan is a [TOML v1.0.0](https://toml.io/en/v1.0.0) file restricted to:
comments, top-level keys, the five tables below, bare keys, basic (`"..."`)
and literal (`'...'`) strings on one line, decimal integers, `true`/`false`,
and arrays of strings (which may span lines). Floats, dates, inline tables,
arrays of tables, dotted or quoted keys and multi-line strings are refused,
as are unknown keys and keys that the plan's profile does not take. Every
refusal names the file and line. A plan is at most 64 KiB; a string at most
4096 bytes; an array at most 32 items.

**Passwords are never stored in a plan**, only the paths of password files.

**Relative paths are relative to the plan file**, so a plan and its
certificates can move together. This covers every path key below and the
first item of `hooks.trigger` when it contains a `/`. Other strings (URLs,
user names, test prefixes, the trigger's arguments) are passed as written.

### Top level

| Key | Value |
| --- | --- |
| `schema` | Optional; must be `"gdsaudit-plan"` |
| `version` | Optional; must be `1` |
| `profile` | Required, before any table: `"server"`, `"client"` or `"gds"` |
| `name` | Optional text for people (the UI shows it) |
| `preset` | Optional UI preset: `"quick"`, `"full"` or `"certification"`. Headless runs keep it but do not use it |

### Keys and the options they give

| Key | Type | server | client | gds |
| --- | --- | --- | --- | --- |
| `target.url` | string | `--url` | | `--url` |
| `target.server_cert` | path | `--server-cert` | | |
| `target.tofu` | bool | `--tofu` | | |
| `target.trust` | array of paths | `--target-trust` | | `--trust` |
| `target.crl` | array of paths | `--target-crl` | | `--crl` |
| `target.listen` | integer | | `--listen` | |
| `target.listen_any` | bool | | `--listen-any` | |
| `identity.work` | path | `--work` | `--work` | `--work` |
| `identity.admin_cert` | path | `--admin-cert` | | |
| `identity.admin_key` | path | `--admin-key` | | |
| `identity.admin_user` | string | `--admin-user` | | |
| `identity.admin_password_file` | path | `--admin-password-file` | | |
| `identity.user` | string | `--user` | | `--user` |
| `identity.password_file` | path | `--user-password-file` | | `--password-file` |
| `identity.client_user` | string | | `--user` (the fake GDS's user) | |
| `tests.allow_changes` | bool | `--allow-changes` | | `--allow-changes` |
| `tests.only` | string | `--only` | `--only` | `--only` |
| `tests.slow` | bool | `--slow` | `--slow` | |
| `tests.expect` | path | `--expect` | `--expect` | `--expect` |
| `tests.stop_after` | string | `--stop-after` | | |
| `tests.settle_timeout` | integer | `--settle-timeout` | | |
| `tests.poll_seconds` | integer | | | `--poll-seconds` |
| `tests.cycle_timeout` | integer | | `--cycle-timeout` | |
| `tests.cycle_period` | integer | | `--cycle-period` | |
| `hooks.trigger` | array of strings | | the command after `--` | |
| `hooks.restart_cmd` | string (a shell command, not a path) | `--restart-cmd` | | |
| `hooks.prompts` | path | `--prompts` | `--prompts` | `--prompts` |
| `report.dir` | path | `--report` | `--report` | `--report` |
| `report.events` | path | `--events` | `--events` | `--events` |

`hooks.prompts` holds the operator's answers (`<n> done|skip|fail [note]` per line), so a run with operator steps repeats with the same answers headless and in the UI. A bool `false` gives no option. The options and their meaning are in
the usage `gdsaudit` prints without arguments, `gdsaudit client --help` and `tools/auditor/README.md`.
When a profile gains an option, its key is added to the table in
`tools/auditor/core/plan.c` and to this page.

## Examples

Server profile against a device a GDS has already pushed, changes allowed:

```toml
schema = "gdsaudit-plan"
version = 1
profile = "server"
name = "Line 3 PLC, firmware 2.1"
preset = "full"

[target]
url = "opc.tcp://plc-line3:4840"
server_cert = "certs/plc-line3.der"
trust = ["certs/gds-ca.der"]
crl = ["certs/gds-ca.crl"]

[identity]
work = "work"
admin_user = "sysadmin"
admin_password_file = "secrets/sysadmin.pw"

[tests]
allow_changes = true

[report]
dir = "results/plc-line3"
events = "results/plc-line3/events.jsonl"
```

Client profile with a trigger script next to the plan:

```toml
schema = "gdsaudit-plan"
version = 1
profile = "client"

[target]
listen = 4850

[identity]
work = "work"
client_user = "registrar"

[hooks]
trigger = ["./pull-once.sh", "--device", "hmi-7"]

[report]
dir = "results/hmi-7"
```

## For front ends

`tools/auditor/include/gdsaudit/plan.h` is the API (libc only):
`ga_plan_load`, `ga_plan_save`, `ga_plan_set`/`add`/`get`/`unset` by
`"table.key"`, and `ga_plan_argv`, which gives the command line. The desktop
UI loads and saves plans through it, so a plan saved in the UI runs
unchanged headless.
