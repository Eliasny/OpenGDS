# Client profile: the Auditor plays a GDS that injects faults

`gdsaudit client --listen <port>` checks an OPC UA application that pulls its certificate and trust list from a GDS (OPC 10000-12 §7.3, §7.6, Annex G.1). The Auditor runs `fake_gds.c`, a minimal GDS of its own that breaks the rules on cue, and waits for the client to come to it. Each test starts the client's pull cycle with `--trigger-cmd` or an operator prompt and reports Not tested when neither is available. After a cycle the Auditor checks what the client installed by letting it connect to a probe server (below), so every check stays black-box.

Spec: OPC 10000-12 v1.05.07 (2026-04-15) unless the clause names another Part. How to read the columns, verdict words and mutants: [README](README.md#how-to-read-a-catalogue).

## ConformanceUnits

The reference site lists only the CertificateManager-side ConformanceUnits (GDS Certificate Manager Pull Model). The client-side GDS ConformanceUnits are published on profiles.opcfoundation.org, which needs JavaScript and was not reachable while this catalogue was written. Every row in this profile therefore carries ConformanceUnit `TBD` until Elias reads the names there and they are filled in ([decision D6](README.md#decisions)).

## Fixtures

| Fixture | What it is |
| --- | --- |
| `gds-trusted` | The fake GDS's certificate, issued by the Auditor test CA `ca`. Before the run the operator, or `--setup-cmd`, makes the client trust it (the out-of-band step of Annex G.1) |
| `gds-rogue` | Issued by `ca-rogue` (which the client never got), with the same ApplicationUri and host name as `gds-trusted` |
| `gds-revoked` | Issued by `ca` and listed in the CRL of `ca` that the Auditor hands the client (`GDSAUDIT_GDS_CRL`, rewritten before the cycle) |
| `gds-expired` | Issued by `ca`, validity ended yesterday |
| `gds-wronguri` | Issued by `ca`, SAN URI differs from the ApplicationUri in the fake GDS's endpoints |
| Rogue CA | `ca-rogue`, the issuer the fake GDS uses when it plays `gds-rogue` |
| Short-lived certificates | Certificates the fake GDS issues with a 10-minute validity, so that renewal can be watched in one run |
| Probe server | A small Server run by the Auditor. The client is triggered to connect to it after a cycle. Its certificate is chosen per test (issued by `ca`, by `ca-rogue`, revoked, from an issuer-only CA), and it records the certificate chain the client presents |
| Approval control | The fake GDS answers FinishRequest with Bad_NothingToDo N times, then Good, or with Bad_RequestNotAllowed |
| Cycle settings | The fake TrustList's UpdateFrequency, default 60 s, so several cycles fit in one run |

## Trust in the GDS (`cli_trust.c`)

| ID | Clause | Flags | Check | Pass when | Fail / Warn / Not supported | Mutant |
| --- | --- | --- | --- | --- | --- | --- |
| CLI-TRU-01 | 12 Annex G.1 | O | The fake GDS presents `gds-rogue`; offer UserName and Anonymous tokens | The client sends no UserName password or other secret | Fail: a secret is sent to the untrusted GDS. Connecting at all is allowed by G.1 | `send-password-untrusted` |
| CLI-TRU-02 | 12 Annex G.1; 4 §6.1.3 | O | After a cycle against `gds-rogue` (which hands out a certificate and trust list from `ca-rogue`), trigger a connection to the probe server with a `ca-rogue` certificate | The client refuses the probe and still presents its previous certificate | Fail: the client installed anything from the rogue GDS | `trust-any-gds` |
| CLI-TRU-03 | 4 §6.1.3 | O | The fake GDS presents `gds-revoked` | The client calls no GDS method (revocation is not suppressible) | Fail: any method is called | `ignore-gds-crl` |
| CLI-TRU-04 | 4 §6.1.3 | O | The fake GDS presents `gds-expired` | The client stops, or asks its operator | Warn: proceeds silently (validity is suppressible) | `accept-expired-gds` |
| CLI-TRU-05 | 4 §6.1.3 | O | The fake GDS presents `gds-wronguri` | The client calls no GDS method (the URI check is not suppressible) | Fail: any method is called | `no-gds-uri-check` |
| CLI-TRU-06 | 12 §7.6, §7.9.3, §7.9.4, §7.9.5 | O | The fake GDS offers None, Sign and SignAndEncrypt endpoints | StartSigningRequest, StartNewKeyPairRequest and FinishRequest arrive over SignAndEncrypt | Fail: any of them over Sign or None. Warn: GetTrustList or GetCertificateStatus over Sign (allowed, but §7.6 uses SignAndEncrypt) | `use-sign-only` |
| CLI-TRU-07 | OPC 10000-7 (security policy facets) | O | The fake GDS offers a deprecated and a current policy | The client picks the current one | Warn: picks the deprecated one | `prefer-deprecated` |

## Registration (`cli_register.c`)

RegisterApplication needs the DiscoveryAdmin Role or the ApplicationAdmin Privilege (12 §6.5.6), so a client that registers itself does so with administrator credentials (Annex G.1 step 3). When the client does not register itself, the Auditor registers it from `--client-record` and these tests report Not tested.

| ID | Clause | Flags | Check | Pass when | Fail / Warn / Not supported | Mutant |
| --- | --- | --- | --- | --- | --- | --- |
| CLI-REG-01 | 12 §6.5.5, §6.5.6; 6 §6.2.2 | O | Compare the ApplicationRecord's ApplicationUri with the SAN URI of the certificate on the channel | Equal | Fail: different | `register-wrong-uri` |
| CLI-REG-02 | 12 §6.5.5 | O | Compare ApplicationType with what the application is (a Client; ClientAndServer if it also serves) | Matches | Warn: different | `register-wrong-type` |
| CLI-REG-03 | 12 §6.5.5 | O | For a ClientAndServer, call GetEndpoints on every DiscoveryUrl in the record | Each answers with the same ApplicationUri | Fail: another ApplicationUri. Warn: a URL does not answer. Not supported: pure Client | `register-bad-url` |
| CLI-REG-04 | 12 §6.5.5, §6.5.6 | O | Run a second cycle with the record already present | The client finds its record (FindApplications) or handles Bad_EntryExists and goes on | Warn: the cycle stops on Bad_EntryExists. The spec does not require FindApplications first | `register-every-run` |
| CLI-REG-05 | 12 Annex G.1 | O | The operator types UserName credentials at the client's prompt in cycle 1; cycle 2 runs without an operator | Cycle 2 does not use those credentials again | Fail: the prompted credentials were persisted | `persist-prompted-creds` |

## Signing request (`cli_csr.c`)

| ID | Clause | Flags | Check | Pass when | Fail / Warn / Not supported | Mutant |
| --- | --- | --- | --- | --- | --- | --- |
| CLI-CSR-01 | 12 §7.9.3 | O | Decode the CertificateRequest from StartSigningRequest | DER PKCS #10 whose signature verifies with its own public key | Fail: does not decode or verify | `csr-bad-signature` |
| CLI-CSR-02 | 12 §7.9.3; 6 §6.2.2 | O | Read the CSR's subjectAltName | Exactly one URI, equal to the client's ApplicationUri | Fail: missing or different | `csr-wrong-uri` |
| CLI-CSR-03 | 12 §7.9.3, §7.8.4.9 | O | Compare the key type and length with the CertificateTypeId in the call | They meet the type's restrictions (for RsaSha256ApplicationCertificateType an RSA key of 2048, 3072 or 4096 bits; for the ECC types the named curve) | Fail: they do not | `csr-weak-key` |
| CLI-CSR-04 | 12 §7.9.3, §7.9.7, §7.8.3.1 | O | Compare the CertificateGroupId and CertificateTypeId with what GetCertificateGroups and the group's CertificateTypes returned | Both are from those lists | Fail: an unlisted group or type | `csr-unlisted-type` |
| CLI-CSR-05 | 12 §7.9.3 | O | For a ClientAndServer, read the CSR's DNS names | They include the domains of its DiscoveryUrls | Fail: a domain is missing. Not supported: pure Client | `csr-no-dns` |
| CLI-CSR-06 | 12 §7.6 | O | Two consecutive signing requests | Different public keys | Warn: the same key (a new key per request is strongly recommended) | `csr-reuse-key` |
| CLI-CSR-07 | 12 §7.9.3 | O | Search every argument and identity token the client sends for a private key matching the CSR's public key | None found | Fail: the private key left the client | `leak-private-key` |
| CLI-CSR-08 | 12 §7.9.3 | O | The fake GDS answers StartSigningRequest with Bad_CertificateUriInvalid | The client reports the error and makes at most one more attempt in the cycle | Warn: more attempts | `csr-retry-storm` |
| CLI-CSR-09 | 12 §7.6, §7.9.4 | O | Record whether the client uses StartNewKeyPairRequest | It uses StartSigningRequest | Warn: StartNewKeyPairRequest, so the GDS generates the client's key. Not supported: neither is called | `use-newkeypair` |

## Pending approval (`cli_pending.c`)

| ID | Clause | Flags | Check | Pass when | Fail / Warn / Not supported | Mutant |
| --- | --- | --- | --- | --- | --- | --- |
| CLI-PEN-01 | 12 §7.9.5, §7.6 | O, slow | FinishRequest returns Bad_NothingToDo 3 times, then Good | The client keeps calling FinishRequest with the same ApplicationId and RequestId (in this or later cycles) and installs the certificate | Fail: never completes within 5 cycles | `pending-give-up` |
| CLI-PEN-02 | 12 §7.6, §7.9.5 | O | Measure the interval between FinishRequest calls while pending | At least 1 s between calls, and at most a small repeat count (§7.6 says about 2) per cycle | Warn: faster, or more repeats. The spec says only "after a short delay" | `poll-no-backoff` |
| CLI-PEN-03 | 12 §7.6 | O | Start the next cycle while a request is pending | It begins with FinishRequest for the pending RequestId | Warn: a new StartSigningRequest instead | `pending-new-csr` |
| CLI-PEN-04 | 12 §7.6 | O | Restart the client (through the trigger hook) while a request is pending | After the restart it resumes the persisted RequestId | Warn: a new request instead | `pending-forget` |
| CLI-PEN-05 | 12 §7.9.5, §7.6 | O | FinishRequest returns Bad_RequestNotAllowed | The client never calls FinishRequest for that RequestId again | Fail: it polls the rejected RequestId again | `poll-after-reject` |
| CLI-PEN-06 | 12 §7.9.5 | O | After StartSigningRequest the fake GDS drops the session; FinishRequest then returns Bad_InvalidArgument | The client recovers with GetCertificates or a new request | Warn: stuck | `pending-stuck-invalid` |
| CLI-PEN-07 | 12 §6.3 | O | Watch sessions between cycles | The client closes its session when a cycle ends and holds none between cycles | Fail: a session stays open into the next cycle, or longer than 60 s after its last call | `keep-session-open` |
| CLI-PEN-08 | 12 §6.3 | O, slow | Start the client 3 times at the same moment and record when the second cycle begins | The delay varies between runs and lies between 1 % and at least 10 % of the cycle period | Warn: identical delays, or outside the range. Timing on a shared bench makes a Fail unsafe | `no-cycle-jitter` |

## Installation (`cli_install.c`)

| ID | Clause | Flags | Check | Pass when | Fail / Warn / Not supported | Mutant |
| --- | --- | --- | --- | --- | --- | --- |
| CLI-INS-01 | 12 Annex G.1, §7.6 | O | After FinishRequest returns the certificate, trigger a connection to the probe server | The client presents the issued certificate, byte for byte, and the handshake proves it holds the CSR's key | Fail: another certificate | `install-ignored` |
| CLI-INS-02 | 12 §7.9.5; 4 §6.1.3 | O | Issue from the intermediate `ca-int`; the probe server trusts only `ca` | The client sends a chain the probe can validate | Warn: no chain sent, so the probe has to know `ca-int` | `install-no-chain` |
| CLI-INS-03 | 12 §7.6 | O | Restart the client after installation; connect to the probe | It still presents the new certificate | Fail: it reverted | `install-in-ram` |

## Trust list (`cli_trustlist.c`)

The fake GDS serves a 40 KiB trust list and answers each Read with at most 1 KiB.

| ID | Clause | Flags | Check | Pass when | Fail / Warn / Not supported | Mutant |
| --- | --- | --- | --- | --- | --- | --- |
| CLI-TL-01 | 12 §7.9.9, §7.8.2.4 | O | Watch GetTrustList, Open/OpenWithMasks and Read | The client reads until the end of the file before it installs anything | Fail: it stops early and installs | `read-one-chunk` |
| CLI-TL-02 | 12 §7.8.2.4 | O | Watch the file handle | The client calls Close after reading | Warn: the handle is left open | `no-close` |
| CLI-TL-03 | 12 §7.9.9; 4 §6.1.3 | O | The probe presents a certificate from a CA in TrustedCertificates | The client connects | Fail: refused | `trustlist-not-installed` |
| CLI-TL-04 | 12 §7.9.9; 4 §6.1.3 | O | The probe presents a certificate revoked by a CRL in the list | The client refuses (Bad_CertificateRevoked) | Fail: connects | `ignore-crls` |
| CLI-TL-05 | 12 §7.8.2.8; 4 §6.1.3 | O | Next cycle serves a list without CA X; the probe presents a certificate from X | The client refuses | Fail: still trusts X (it merged instead of replacing) | `trustlist-merge` |
| CLI-TL-06 | 12 §7.8.2.8; 4 §6.1.3 | O | The probe presents a leaf issued by a CA that is only in IssuerCertificates | The client refuses (the issuer list only builds chains) | Fail: connects | `issuers-trusted` |
| CLI-TL-07 | 12 §7.6 | O | Leave the list unchanged for two cycles | The client reads LastUpdateTime and skips the download | Warn: downloads every cycle | `always-download` |
| CLI-TL-08 | 12 §7.6, §7.8.2.1 | O, slow | Set UpdateFrequency to 60 s | The client checks for updates within 2 × UpdateFrequency | Warn: it does not | `ignore-update-frequency` |

## Renewal (`cli_renew.c`)

| ID | Clause | Flags | Check | Pass when | Fail / Warn / Not supported | Mutant |
| --- | --- | --- | --- | --- | --- | --- |
| CLI-REN-01 | 12 §7.9.10, §7.6 | O | GetCertificateStatus returns UpdateRequired TRUE | The client starts a new signing request in the same cycle | Fail: no request | `ignore-update-required` |
| CLI-REN-02 | 12 §7.9.10, §7.6 | O | GetCertificateStatus returns UpdateRequired FALSE and the certificate is far from expiry | No new request | Warn: requests anyway | `renew-always` |
| CLI-REN-03 | 12 §7.6 | O, slow | Issue a 10-minute certificate; let cycles run | The client renews before the certificate expires | Warn: it expires. The spec sets no lead time | `no-expiry-renewal` |
| CLI-REN-04 | 12 §7.6 | O | After a renewal, trigger a connection to the probe | The new certificate is presented | Fail: the old one | `renew-keep-old` |
| CLI-REN-05 | 12 Annex G.1, §7.6 | O | Watch the identity token used for renewal | The client authenticates with its certificate and Anonymous user (ApplicationSelfAdmin) | Warn: it uses UserName credentials while it holds a valid certificate | `renew-with-password` |

## Faults (`cli_faults.c`)

In every fault test the Auditor first lets one good cycle finish, so the client has a known last good state, then injects the fault and checks with the probe server that the last good state is still in use.

| ID | Clause | Flags | Check | Pass when | Fail / Warn / Not supported | Mutant |
| --- | --- | --- | --- | --- | --- | --- |
| CLI-FLT-01 | 12 §7.6, §7.8.2.4 | O | Drop the session halfway through the trust list Reads | The previous trust list is still in use | Fail: a partial list is in use | `install-partial-trustlist` |
| CLI-FLT-02 | 12 §7.8.2.8 | O | Serve a malformed TrustListDataType (truncated, array lengths beyond the data) | The client keeps running and the previous list is in use | Fail: the client crashes (the trigger hook sees it exit) or uses the bad data | `parse-garbage` |
| CLI-FLT-03 | 12 §7.9.5; 4 §6.1.3 | O | FinishRequest returns a certificate from `ca2`, which no list holds | Not installed | Fail: installed | `install-unverified` |
| CLI-FLT-04 | 12 §7.9.5 | O | FinishRequest returns a certificate whose public key is not the CSR's | Not installed | Fail: installed | `install-wrong-key` |
| CLI-FLT-05 | 12 §7.9.5; 6 §6.2.2 | O | FinishRequest returns a certificate whose SAN URI is not the client's ApplicationUri | Not installed | Fail: installed | `install-wrong-uri` |
| CLI-FLT-06 | 12 §7.9.5; 4 §6.1.3 | O | FinishRequest returns an expired certificate | Not installed | Fail: installed ([decision D2](README.md#decisions)) | `install-expired` |
| CLI-FLT-07 | 12 §7.6 | O, slow | Stop answering in the middle of a FinishRequest (the answer is held back 40 s, or until the client process ends) | The client gives up the call within those 40 s and runs the next cycle | Warn: it still waits after 40 s | `no-call-timeout` |
| CLI-FLT-08 | 12 §7.8.2.4; OPC 10000-20 (FileType Read) | O | Answer a Read with more bytes than requested, and FinishRequest with a 10 000-element IssuerCertificates array | The client keeps running and keeps its last good state | Fail: it crashes or installs | `no-length-check` |
| CLI-FLT-09 | 12 §6.3 | O | The fake GDS closes the client's session mid-cycle (a GDS may do so when short of resources) | The client retries in its next cycle, not in a tight loop | Warn: more than 3 reconnects within 10 s | `reconnect-storm` |
