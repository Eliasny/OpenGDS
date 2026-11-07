# OpenGDS Auditor test catalogues

Status: proposal, 6 Nov 2026. These catalogues are the designs of the Auditor's server and client profiles: every test that `gdsaudit server` and `gdsaudit client` will run, the clause it checks, its verdict rules and the mutant that proves it can fail. The C code in `tools/auditor/profile_server/` and `profile_client/` is written from them, test by test, so a test ID in a report always points back to a row here. They refine the test catalogue in the Auditor plan (03); the changes are listed under [Changes to the plan](#changes-to-the-plan).

The GDS profile is not catalogued here. It is OpenGDS's T0 spec test programs (`tools/auditor/profile_gds/`), which have their own catalogue.

| Catalogue | Profile | Auditor plays | Tests | Self-test target |
| --- | --- | --- | --- | --- |
| [server-profile.md](server-profile.md) | `gdsaudit server` | The CertificateManager pushing to a Server | 106 (SRV-*) | `selftest/push_test_server` |
| [client-profile.md](client-profile.md) | `gdsaudit client` | A GDS that injects faults for a pull client | 54 (CLI-*) | `selftest/pull_test_client` |
| [catalogue.csv](catalogue.csv) | both | | 160 | |

## How to read a catalogue

Each group is one source file of the profile (named in the heading) and starts with its ConformanceUnit. Each row is one test:

| Column | Meaning |
| --- | --- |
| ID | Stable test ID, `SRV-<group>-NN` or `CLI-<group>-NN`. It is the test's name in every report format and in `--only`/`--skip`. IDs are never reused; a dropped test leaves a gap |
| Clause | The clause the test checks. `12 §7.10.5` is OPC 10000-12 §7.10.5; `4 §6.1.3` is OPC 10000-4; `6 §6.2.2` is OPC 10000-6 |
| Flags | `W` needs write access (`--allow-changes`); `O` needs an outside step (operator prompt, `--trigger-cmd`, `--restart-cmd` or `--setup-cmd`); `slow` takes more than a minute and runs only with `--slow` (Not tested otherwise). `—` means none |
| Check | What the Auditor does |
| Pass when | The behaviour the clause states |
| Fail / Warn / Not supported | The rules for every other verdict. A rule not listed cannot happen for that test |
| Mutant | The `--break <name>` option of the self-test target that this test must catch |

The ConformanceUnit of each test, its flags and its verification state are also in [catalogue.csv](catalogue.csv), one row per test, for the harness registry (`core/harness.c`) and for CI.

## Verdicts

| Verdict | When a catalogue row gives it |
| --- | --- |
| Pass | The target behaved as the clause states |
| Fail | The target did what the clause forbids, or failed to do what it requires with "shall". Evidence (status codes, thumbprints, timestamps, the exchanges) is attached |
| Warn | The clause allows the behaviour but it is risky, the clause says only "should" or "recommended", the spec text is ambiguous, or the check depends on timing a bench cannot control. A Warn never fails a run (exit code 0) |
| Not supported | The target does not have an Optional feature the test needs (for example no CancelChanges, no TransactionDiagnostics, no KeyCredentialConfiguration) |
| Not tested | A step did not happen: no `--allow-changes` for a `W` test, no hook or operator for an `O` test, no `user` identity, or an earlier test in the same group that this one builds on did not Pass |

Two rules apply to every row:

- **Bad code but the right outcome.** Where a row expects a specific Bad code and the target refuses with another one, the verdict is Warn, not Fail: the target was safe, only the reported reason differs. Where the row says "A Bad code", any Bad code passes.
- **Endpoints the target does not offer.** A test that needs a None or Sign-only channel passes when the target offers no such endpoint, because what the test checks (the call is refused) is then guaranteed. The endpoint list is kept as evidence. A test never weakens the target to make itself possible.

## Mutants

Each test ships with exactly one mutant in its self-test target, named in the Mutant column. Mutant names are unique across both profiles, so that a mutant is caught by the test it was written for and not only by accident.

- CI runs every test against the good self-test target (must Pass, or be Not supported when the good target leaves the Optional feature out on purpose) and against its mutant (must be caught).
- A mutant is **caught** when the verdict is Fail, or Warn for a test whose rules can only give Warn (for example SRV-SEC-05, CLI-PEN-02).
- A mutant may add what it needs to be observable. For example `sign-is-enough` also offers a Sign-only endpoint, because the good `push_test_server` offers only SignAndEncrypt.
- The self-test targets refuse to bind a non-loopback address while a mutant is active (architecture, "The Auditor under these rules").
- Each test is also run against the reference implementations that exist (UA-.NETStandard servers and clients). A test that does not Pass there gets a note in its row on the reference deviation, never a silent skip.

## Safety, snapshot and restore

Server profile: before the first `W` test the Auditor reads and saves every CertificateGroup's TrustList and certificates (GetCertificates when present, otherwise the endpoint certificates). Tests that open a transaction end it themselves (ApplyChanges or CancelChanges). After the last test, on error and on Ctrl-C, the saved state is pushed back and applied, and the restore is a line in the report with its own verdict. The Push setup group, SRV-UPD-09 (a pushed private key replaces the target's own) and SRV-SET-06 (ResetToServerDefaults) change state that the snapshot cannot restore, so they run only when selected by name, and SRV-SET-06 also needs `--allow-reset`.

Client profile: nothing on the client is written by the Auditor except through the client's own pull cycle. The fake GDS listens only on localhost unless `--listen-any` is given, and every certificate it issues carries "OpenGDS Auditor TEST" in its subject.

## Verification against the spec

Every clause was checked on the OPC Foundation online reference ([reference.opcfoundation.org/specs/OPC-10000-12](https://reference.opcfoundation.org/specs/OPC-10000-12), v1.05.07, 2026-04-15) on 6 Nov 2026, the same way as the UASM catalogues. `verified` in catalogue.csv is `ref` when every clause of the row was read there, and `todo` when the row cites a clause from outside Part 12 or Annex D that was not read: 6 rows (SRV-SEC-08, SRV-SEC-09, SRV-CAP-04, SRV-SET-04, CLI-TRU-07, CLI-FLT-08). They are read before their code is written.

The clause numbers in the plan's catalogue were correct at the level of clause it used (§7.8.2, §7.9, §7.10, §6.5, Annex G); this catalogue cites the subclause of each method instead. The only wrong citation was Annex F for persistence: F.1 is a recommended directory layout (mandatory only for the Local Discovery Server) and says nothing about restarts.

## Changes to the plan

| Plan said | Catalogue says | Why |
| --- | --- | --- |
| Persistence: 12 Annex F; certificate and trust list unchanged after restart | SRV-PER-01 is a Warn; SRV-PER-02 (LastUpdateTime) and SRV-PER-03 (the CSR's new key pair) are Fail | Annex F has no persistence rule. §7.8.2.1 and §7.10.10 do have one for LastUpdateTime and the new key pair. See D1 |
| Security: methods refuse unencrypted sessions | Split by method: UpdateCertificate, CreateSigningRequest and the KeyCredential methods need encryption (Fail on Sign); the other ServerConfiguration and TrustList methods need only an authenticated channel (Warn on Sign, because §7.4 says encrypted) | §7.10.5, §7.10.10 and §8.6 say "encrypted"; §7.10.9, §7.10.11, §7.10.12, §7.8.2.2–§7.8.2.7 say "authenticated" |
| Rejected list: an unknown client's certificate appears | SRV-REJ-01 is a Warn; SRV-REJ-02 (a certificate with an unsuppressible error must not appear) is a Fail | §7.10.12 only recommends adding; §7.8.3.2 says only valid but untrusted certificates are added |
| Registration: FindApplications before RegisterApplication | CLI-REG-04 is a Warn when a client stops on Bad_EntryExists | §6.5.6 does not require FindApplications first; RegisterApplication needs DiscoveryAdmin or ApplicationAdmin, so many clients are registered by an administrator instead |
| Trust in the GDS: the client refuses a GDS it was not told to trust | Connecting to an untrusted GDS is allowed. Fail when the client sends it a secret (CLI-TRU-01) or installs anything from it (CLI-TRU-02) | Annex G.1 lets an application connect to a CertificateManager it does not trust yet, but it shall not give it secrets |
| Pending approval: polls at a bounded rate | CLI-PEN-02 is a Warn; holding a session between cycles is a Fail (CLI-PEN-07) | §7.6 says only "after a short delay"; §6.3 says applications shall disconnect after each sequence and shall not keep connections open between them |
| Renewal: renews when a short-lived certificate nears expiry | CLI-REN-03 is a Warn; renewing on UpdateRequired TRUE is a Fail (CLI-REN-01) | §7.6 makes UpdateRequired the trigger and sets no lead time for expiry |
| Signing request: no private key leaves the client | Kept as Fail (CLI-CSR-07); StartNewKeyPairRequest is a Warn (CLI-CSR-09) | The CSR proves possession of the caller's own key (§7.9.3); §7.6 strongly recommends client-generated keys, but StartNewKeyPairRequest is standard |
| Server groups as listed | Added: CreateSelfSignedCertificate, DeleteCertificate, GetCertificates (in Certificate update), ResetToServerDefaults (in Push setup), Audit events (new file `srv_audit.c`) | They are part of ServerConfigurationType (§7.10.3); audit events are required when the server supports auditing (§7.8.2.13, §7.10.27) |

## Decisions

The open questions of the first version were settled on 6 Nov 2026 and confirmed by Elias. They bind the rows named.

| # | Question | Decision | Tests |
| --- | --- | --- | --- |
| D1 | Does Part 12 require applied certificates and trust lists to survive a restart? It states no rule | Losing pushed state after a restart is a Warn. OpenGDS's device interop matrix treats this Warn as blocking | SRV-PER-01 |
| D2 | Validity is a suppressible error in Part 4. Is accepting or installing an expired certificate right or wrong? | Warn (Elias, 2026-11-06, replacing an earlier Fail). Part 4 §6.1.3 Table 100 lists Validity Period as suppressible, and Part 12 §7.8.2.5 and §7.10.5 tell a server to ignore suppressible errors, so accepting an expired certificate follows the spec's letter; the Auditor flags it but does not fail it | SRV-UPD-08, SRV-TL-08, CLI-FLT-06 |
| D3 | §7.10.5 does not require UpdateCertificate to check the SAN URI against the ApplicationUri; Part 6 §6.2.2 requires the match of the certificate | Fail when accepted (Elias, 2026-11-06). A URI mismatch "may not be suppressed" (Part 4 §6.1.3 Table 100). The UA-.NETStandard reference server 1.5.378.182 accepts it (its validator does not compare the URI); that is noted as a .NET gap, not a reason to relax the verdict | SRV-UPD-03 |
| D4 | How does a server advertise the 1.05.07 SecureChannel enhancements? | Keep the test; a missing enhancement is a Warn. How it is seen from outside is read in OPC 10000-6 v1.05.07 before the code is written | SRV-SEC-09 |
| D5 | §7.10.9 and §7.10.11 write "Bad_BadSessionIdInvalid" | Expect Bad_SessionIdInvalid; any other Bad code is a Warn. A typo report for the OPC Foundation is drafted and sent only with Elias's OK | SRV-TXN-07 |
| D6 | Which client-side ConformanceUnits do the client tests map to? | Elias reads them on profiles.opcfoundation.org; they are filled in here | All CLI-* |
| D7 | How long may a server take to close sessions and re-key after a trust list or certificate change? | Warn after 30 s, Fail after `--settle-timeout` (default 300 s) | SRV-WIRE-02, -07, -08 |

Later OPC UA questions are settled from the spec text, and the row cites the clause. Only product, process or legal choices go to Elias, and nothing is assumed in the meantime.
