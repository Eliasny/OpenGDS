# Auditor JSON report (`report.json`)

`gdsaudit ... --report DIR` writes four reports from the same result list:
`report.html` for people, `junit.xml` for CI, `report.tap` (TAP version 13)
for the shell, and `report.json` for machines. This page describes
`report.json`. UASM can import it as compliance evidence.

Every report says "Self-test, not OPC Foundation certification". An Auditor
result per ConformanceUnit is a self-test result, not certification.

## Schema `gdsaudit-report`, version 1

One JSON object, UTF-8. Bytes from the target that are not UTF-8 become
U+FFFD. Readers must ignore keys they do not know; a new key does not change
the version, a changed meaning does.

| Key | Type | Meaning |
| --- | --- | --- |
| `schema` | string | Always `"gdsaudit-report"` |
| `version` | number | `1` |
| `note` | string | `"Self-test, not OPC Foundation certification."` |
| `tool` | string | `"gdsaudit"` |
| `profile` | string or null | `"server"`, `"client"` or `"gds"` |
| `target` | string or null | Endpoint URL, or the fake GDS's listen address for the client profile |
| `started`, `finished` | string or null | UTC, ISO 8601; `finished` is null if the run did not finish |
| `allow_changes` | bool | Whether tests that change the target were allowed |
| `planned` | number | Tests selected for the run |
| `outcome` | string | `"Passed"`, `"Failed"`, `"Incomplete"` (no Fail but some Not tested), `"Aborted"` or `"Did not finish"` |
| `exit` | number or null | The engine's exit code (0 all passed, 1 a Fail, 2 could not run, 3 some Not tested); null if the run did not finish |
| `aborted` | bool | The run was aborted (SIGINT, SIGTERM or the UI's Abort) |
| `counts` | object | `pass`, `fail`, `warn`, `not_supported`, `not_tested`, `no_verdict` |
| `conformance_units` | array | One object per ConformanceUnit, in order of first appearance (below) |
| `tests` | array | One object per test, in run order (below) |

### `conformance_units[]`

| Key | Type | Meaning |
| --- | --- | --- |
| `unit` | string or null | The ConformanceUnit name from `docs/auditor/catalogue.csv`; null unless `state` is `named` |
| `state` | string | `named`, `not_named` (TBD in the catalogue) or `not_in_catalogue` (GDS profile tests) |
| `counts` | object | As the run's `counts`, for this unit's tests |
| `outcome` | string | `"Failed"` (any Fail), `"Incomplete"` (any Not tested or missing verdict), else `"Passed"` |

### `tests[]`

| Key | Type | Meaning |
| --- | --- | --- |
| `n` | number | 1-based position in the run |
| `id` | string or null | Test id, for example `SRV-TL-02` |
| `clause` | string or null | Cited clause, for example `12 §7.8.2.1` |
| `title` | string or null | One-line title |
| `conformance_unit` | string or null | As `unit` above |
| `conformance_unit_state` | string | As `state` above |
| `changes` | bool | The test changes the target |
| `operator` | bool | The test needs an operator or a hook |
| `verdict` | string or null | `pass`, `fail`, `warn`, `not_supported`, `not_tested`; null if none arrived |
| `ms` | number or null | Duration in milliseconds |
| `evidence` | string or null | The verdict's evidence line |
| `notes` | array of strings | The test's note lines (status codes, thumbprints, steps), at most 16 KiB per test |

## Example

```json
{"schema":"gdsaudit-report","version":1,
 "note":"Self-test, not OPC Foundation certification.","tool":"gdsaudit",
 "profile":"server","target":"opc.tcp://127.0.0.1:4993",
 "started":"2026-11-07T03:07:55Z","finished":"2026-11-07T03:08:01Z",
 "allow_changes":false,"planned":9,"outcome":"Failed","exit":1,"aborted":false,
 "counts":{"pass":5,"fail":1,"warn":0,"not_supported":0,"not_tested":3,"no_verdict":0},
 "conformance_units":[
  {"unit":"Push Model for Global Certificate and TrustList Management","state":"named",
   "counts":{"pass":4,"fail":1,"warn":0,"not_supported":0,"not_tested":3,"no_verdict":0},
   "outcome":"Failed"},
  {"unit":"Server PushManagement Transactions","state":"named",
   "counts":{"pass":1,"fail":0,"warn":0,"not_supported":0,"not_tested":0,"no_verdict":0},
   "outcome":"Passed"}],
 "tests":[{"n":2,"id":"SRV-CAP-02","clause":"12 §7.10.3",
   "title":"CertificateGroups has DefaultApplicationGroup",
   "conformance_unit":"Push Model for Global Certificate and TrustList Management",
   "conformance_unit_state":"named","changes":false,"operator":false,"verdict":"fail","ms":0,
   "evidence":"CertificateGroups/DefaultApplicationGroup not found: BadNotFound","notes":[]}]}
```

(Shortened; a real report lists every test.)

## TAP report (`report.tap`)

TAP version 13. Fail and a test without a verdict are `not ok`; Pass and Warn
are `ok`; Not supported and Not tested are `ok ... # SKIP <verdict>: <reason>`.
A `#` or `\` in a description is escaped with `\`. Each test line is followed
by a YAML block (`verdict`, `clause`, `conformance_unit` when named,
`changes`, `operator`, `ms`, `evidence`, `notes`). The plan line counts the
planned tests, so a run that stopped early shows its missing tests to a TAP
consumer. The last lines are the counts and `# outcome: ...`.
