# Server profile: the Auditor plays the CertificateManager

`gdsaudit server <endpoint>` checks a push-managed OPC UA Server: one that exposes the ServerConfiguration Object (OPC 10000-12 §7.10) so that a CertificateManager can update its certificates and trust lists. The Auditor opens every connection itself. Tests run in the order listed. Every write is wrapped in the snapshot and restore of the [README](README.md#safety-snapshot-and-restore).

Spec: OPC 10000-12 v1.05.07 (2026-04-15) unless the clause names another Part. How to read the columns, verdict words and mutants: [README](README.md#how-to-read-a-catalogue).

## Fixtures

| Fixture | What it is |
| --- | --- |
| `admin` | An identity with the SecurityAdmin Role on the target (`--admin-cert`/`--admin-key`, default `<work>/admin/own`, or `--admin-user` with `--admin-password-file`), always over `ch-enc` unless the test says otherwise |
| `user` | An authenticated identity without SecurityAdmin (`--user` with `--user-password-file`). Tests that need it report Not tested when it is not given |
| `anon` | Anonymous identity |
| Plain identity | `<work>/own`: the application certificate of `user` and `anon` connections. It must be trusted by the target but not mapped to SecurityAdmin, so a refusal tests the user identity and not the application |
| `ch-enc` | A SignAndEncrypt SecureChannel with the strongest non-deprecated policy the target offers |
| `ch-sign` | A Sign-only SecureChannel, when the target offers one |
| `ch-none` | A None SecureChannel with a session, when the target offers one |
| Test CA | `ca` (root, subject contains "OpenGDS Auditor TEST", at most 30 days valid), `ca-int` (intermediate under `ca`), `ca2` (unrelated root), CRLs for each |
| Target certificates | `t-good` (from `ca` for the target's ApplicationUri and the key of the target's CSR), `t-wrongkey`, `t-wronguri`, `t-badsig`, `t-expired`, `t-otherca` (from `ca2`), `t-ecc` (an ECC certificate for an RSA slot), `t-withkey` (certificate plus a private key the Auditor generated) |
| Peer certificates | `peer-good` (client certificate from `ca`), `peer-revoked` (from `ca`, listed in `ca`'s CRL), `peer-unknown` (self-signed, never trusted), `peer-int` (from `ca-int`), `peer-badsig` (self-signed, signature broken: a server can see the error without trusting any CA, so SRV-REJ-02 also works in a read-only run) |
| Big list | A TrustListDataType one byte larger than MaxTrustListSize: the snapshot plus filler certificates from `ca` in TrustedCertificates (distinct, valid, sized with an nsComment padding so the encoding hits the size exactly). Built only for MaxTrustListSize below 4 MiB (`GDS_MAX_TRUSTLIST_SIZE`); above that SRV-CAP-07 is Not tested |
| Settle timeout | `--settle-timeout`, default 300 s: how long the Auditor waits for asynchronous effects (channels re-keyed, sessions closed) before a Fail |

## Security (`srv_security.c`)

ConformanceUnit: Push Model for Global Certificate and TrustList Management.

These tests call every method on ServerConfiguration and on each CertificateGroup's TrustList with arguments that are valid, so that a refusal can only come from the access check. Any call that succeeds by mistake is undone by CancelChanges or by the restore step.

| ID | Clause | Flags | Check | Pass when | Fail / Warn / Not supported | Mutant |
| --- | --- | --- | --- | --- | --- | --- |
| SRV-SEC-01 | 12 §7.10.5, §7.10.10, §7.10.12, §7.8.2.3, §7.8.2.5 | W | As `anon` over `ch-enc`, call UpdateCertificate, CreateSigningRequest, ApplyChanges, CancelChanges, GetRejectedList, OpenWithMasks and Open(Write+EraseExisting) | Every call returns Bad_UserAccessDenied | Fail: any call returns Good. Warn: refused with another Bad code | `anon-admin` |
| SRV-SEC-02 | 12 §7.10.5, §7.10.10, §7.10.12, §7.8.2.3, §7.8.2.5 | W | SRV-SEC-01 as `user` | Every call returns Bad_UserAccessDenied | Fail: any call returns Good. Warn: refused with another Bad code. Not tested: no `user` given | `no-secadmin` |
| SRV-SEC-03 | 12 §7.10.5, §7.10.9, §7.8.2.2 | W | As `admin` over `ch-none`, call the methods of SRV-SEC-01 | Every call returns Bad_SecurityModeInsufficient, or the target allows no session over None (the refused session is the evidence) | Fail: any call returns Good. Warn: refused with another Bad code | `allow-none` |
| SRV-SEC-04 | 12 §7.10.5, §7.10.10, §8.6.3 | W | As `admin` over `ch-sign`, call UpdateCertificate, CreateSigningRequest and (if present) CreateCredential, which require an encrypted channel | Every call returns Bad_SecurityModeInsufficient, or no Sign endpoint is offered or allows a session | Fail: any call returns Good. Warn: refused with another Bad code | `sign-is-enough` |
| SRV-SEC-05 | 12 §7.4, §7.10.9, §7.10.12, §7.8.2.3 | W | As `admin` over `ch-sign`, call ApplyChanges, GetRejectedList and OpenWithMasks, which require only an authenticated channel | Refused, or no Sign endpoint is offered or allows a session | Warn: accepted (Good, or Bad_NothingToDo from ApplyChanges, which passed the channel check). The method clauses allow Sign; §7.4 says push management needs an encrypted channel | `sign-for-apply` |
| SRV-SEC-06 | 12 §7.10.3 | — | As `user` and `anon`, browse and read TransactionDiagnostics | Not browsable, or every Read returns Bad_UserAccessDenied or Bad_NotReadable | Fail: a Read returns a value or another status (such as Bad_OutOfService before any transaction, which the access check let through). Not supported: TransactionDiagnostics absent | `diag-public` |
| SRV-SEC-07 | 12 §7.8.2.1, §7.8.2.3 | — | As `user` and `anon`, OpenWithMasks(All) on each TrustList | Bad_UserAccessDenied | Fail: a file handle is returned | `trustlist-read-any` |
| SRV-SEC-08 | OPC 10000-7 (security policy facets) | — | List the endpoints and their SecurityPolicyUris | No deprecated policy (Basic128Rsa15, Basic256) is offered | Warn: a deprecated policy is offered. Fail: SignAndEncrypt is only possible with a deprecated policy | `deprecated-policy` |
| SRV-SEC-09 | OPC 10000-6 v1.05.07 (SecureChannel enhancements) | — | Check whether the target negotiates the 1.05.07 SecureChannel enhancements | Enhancements in use | Warn: not in use (see architecture finding F4) | `no-sce` |

## Capabilities (`srv_capabilities.c`)

ConformanceUnit: Push Model for Global Certificate and TrustList Management (SRV-CAP-08: Server PushManagement Transactions).

| ID | Clause | Flags | Check | Pass when | Fail / Warn / Not supported | Mutant |
| --- | --- | --- | --- | --- | --- | --- |
| SRV-CAP-01 | 12 §7.10.3 | — | Browse ServerConfiguration | The Mandatory members exist: ServerCapabilities, SupportedPrivateKeyFormats, MaxTrustListSize, MulticastDnsEnabled, UpdateCertificate, ApplyChanges, CreateSigningRequest, GetRejectedList, CertificateGroups | Fail: one is missing (named in the evidence) | `no-rejected-list-method` |
| SRV-CAP-02 | 12 §7.10.3 | — | Browse CertificateGroups | DefaultApplicationGroup exists | Fail: missing | `no-default-group` |
| SRV-CAP-03 | 12 §7.8.3.1 | — | For each CertificateGroup read TrustList, CertificateTypes and Purpose | TrustList and CertificateTypes exist; all CertificateTypes are subtypes of one common type; Purpose, if present, is a direct subtype of CertificateType | Fail: any of these is violated | `mixed-cert-types` |
| SRV-CAP-04 | 12 §7.10.3, Annex D | — | Read ServerCapabilities | Every entry is a ServerCapabilityIdentifier from Annex D (Table D.1; the normative ServerCapabilities.csv it links to could not be read, so a newer identifier may Warn) | Warn: an unknown identifier | `bad-capability-id` |
| SRV-CAP-05 | 12 §7.10.3 | — | Read SupportedPrivateKeyFormats | Every entry is "PEM", "PFX" or "PKCS8" | Fail: another value | `bad-key-format-name` |
| SRV-CAP-06 | 12 §7.10.3, §7.10.5 | W | If SupportedPrivateKeyFormats is empty, UpdateCertificate with `t-withkey` and PrivateKeyFormat "PEM" | Refused (Bad_NotSupported expected) | Fail: accepted. Warn: refused with another Bad code. Not supported: the array is not empty (SRV-UPD-09 runs instead) | `accept-key-unadvertised` |
| SRV-CAP-07 | 12 §7.10.3, §7.8.2.5 | W | In its own admin session, Open(0x06), Write the big list in 4096-byte chunks and CloseAndUpdate; read the list before and after; close the session (CancelChanges first if it exists) | Bad_RequestTooLarge from a Write or from CloseAndUpdate (§7.8.2.5), trust list unchanged | Fail: accepted, or another code with the list changed. Warn: another Bad code, list unchanged. Not supported: MaxTrustListSize is 0 (no limit) | `ignore-max-size` |
| SRV-CAP-08 | 12 §7.10.2, §7.10.3 | — | If SupportsTransactions is TRUE, browse for CancelChanges | CancelChanges exists | Fail: missing. Not supported: SupportsTransactions absent or FALSE | `transactions-no-cancel` |
| SRV-CAP-09 | 12 §7.10.3, §7.10.10 | W | For each CertificateType in each group, CreateSigningRequest(RegeneratePrivateKey FALSE) | Good for every advertised type | Fail: Bad_InvalidArgument for an advertised type. Warn: another Bad code | `advertise-unsupported-type` |

## Trust list write (`srv_trustlist.c`)

ConformanceUnit: Push Model for Global Certificate and TrustList Management.

| ID | Clause | Flags | Check | Pass when | Fail / Warn / Not supported | Mutant |
| --- | --- | --- | --- | --- | --- | --- |
| SRV-TL-01 | 12 §7.8.2.2 | W | Open the TrustList with modes 0x02 (Write), 0x03 and 0x04 (EraseExisting alone); Close any handle returned | Every Open returns Bad_NotSupported | Fail: a handle is returned. Warn: another Bad code | `open-any-mode` |
| SRV-TL-02 | 12 §7.8.2.1, §7.8.2.5, §7.10.9 | W | Open(0x06), Write the new list in 512-byte chunks, CloseAndUpdate, ApplyChanges if ApplyChangesRequired, then OpenWithMasks(All) and Read back | The list read back equals the list written (same sets of certificates and CRLs) | Fail: any difference | `drop-last-chunk` |
| SRV-TL-03 | 12 §7.8.2.1, §7.8.2.8 | — | OpenWithMasks(All), Read until a Read returns no bytes, Close, decode | The bytes decode as one TrustListDataType in UA Binary, not wrapped in an ExtensionObject: the decoding uses every byte and SpecifiedLists has only TrustListMasks bits | Fail: decoding fails | `trustlist-wrapped` |
| SRV-TL-04 | 12 §7.8.2.5, §7.8.2.9 | W | Write a TrustListDataType with SpecifiedLists = TrustedCertificates (1) only, CloseAndUpdate, apply | TrustedCertificates replaced; TrustedCrls, IssuerCertificates and IssuerCrls unchanged | Fail: an unmasked list changed | `mask-ignored` |
| SRV-TL-05 | 12 §7.8.2.3, §7.8.2.9 | — | OpenWithMasks(TrustedCertificates) and read | Only TrustedCertificates is filled and SpecifiedLists says so | Warn: other lists returned too | `openwithmasks-ignores` |
| SRV-TL-06 | 12 §7.8.2.1 | W | In its own admin session, Open(0x06), Write a different list, call Close (not CloseAndUpdate), then ApplyChanges in the same session | Trust list and LastUpdateTime unchanged | Fail: the list changed | `close-applies` |
| SRV-TL-07 | 12 §7.8.2.5 | W | In its own admin session, write the applied list plus `t-badsig` (`peer-good` with the last signature byte flipped), CloseAndUpdate, then ApplyChanges in the same session | Bad_CertificateInvalid; the whole new list is discarded | Fail: Good, or any part of the new list is applied. Warn: another Bad code, nothing applied | `accept-invalid-cert` |
| SRV-TL-08 | 12 §7.8.2.5; 4 §6.1.3 | W | As SRV-TL-07, with a self-signed CA certificate that expired a day ago (valid for 9 days before) as the only change | Bad_CertificateTimeInvalid (or another Bad code); the whole new list is discarded | Warn: accepted. Validity is suppressible in Part 4 and §7.8.2.5 says suppressible errors are ignored ([decision D2](README.md#decisions)). Fail: refused but part of the list applied | `accept-expired-ca` |
| SRV-TL-09 | 12 §7.8.2.6 | W | AddCertificate(`peer-good`, IsTrustedCertificate TRUE) with `ca` already in the list; ApplyChanges (noted only: AddCertificate refuses while a transaction is in progress, so it acts at once), read back | Good; `peer-good` is in TrustedCertificates when read back | Fail: refused, or missing after apply | `addcert-noop` |
| SRV-TL-10 | 12 §7.8.2.6 | W | AddCertificate(`peer-good`, IsTrustedCertificate FALSE) | Bad_CertificateInvalid | Fail: Good. Warn: another Bad code | `addcert-issuer-allowed` |
| SRV-TL-11 | 12 §7.8.2.6 | W | AddCertificate(`peer-int`, TRUE) while `ca-int` is not in the list | A validation error (Bad_CertificateChainIncomplete or Bad_CertificateInvalid) | Fail: Good. Warn: another Bad code | `addcert-no-chain-check` |
| SRV-TL-12 | 12 §7.8.2.6 | W | Open(0x06), then AddCertificate of `peer-extra` (a second leaf from `ca`) before CloseAndUpdate; then Close | Bad_InvalidState | Fail: Good. Warn: another Bad code | `addcert-while-open` |
| SRV-TL-13 | 12 §7.8.2.7 | W | RemoveCertificate with the thumbprint of a certificate not in the list (`peer-int`) | Bad_InvalidArgument | Fail: Good. Warn: another Bad code | `remove-unknown-good` |
| SRV-TL-14 | 12 §7.8.2.7 | W | RemoveCertificate(thumbprint of `peer-good`, TRUE); apply | `peer-good` is gone when read back | Fail: still present | `remove-noop` |
| SRV-TL-15 | 12 §7.8.2.7 | W | Write the list plus `ca-int` (IssuerCertificates) and `peer-int` (TrustedCertificates) and apply; RemoveCertificate(`ca-int`, FALSE); read back; put the previous list back | Bad_CertificateChainIncomplete; nothing removed | Fail: Good. Warn: another Bad code | `remove-ca-in-use` |
| SRV-TL-16 | 12 §7.8.2.7 | W | Write the list plus `ca-int` and its CRL (IssuerCertificates, IssuerCrls) and apply; RemoveCertificate(`ca-int`, FALSE); read back; put the previous list back | The CA and all its CRLs are gone | Fail: the CA or a CRL of that CA remains | `remove-keeps-crl` |
| SRV-TL-17 | 12 §7.8.2.1 | W | Read LastUpdateTime around its own sequence: an applied change (the list plus `peer-good`), Open/Write/Close, CloseAndUpdate then CancelChanges (if the target has it and SupportsTransactions is TRUE), and an applied change back to the list | It moves forward after each applied change and stays the same after Close and CancelChanges | Fail: it does not move after an applied change, or moves without one | `lastupdate-frozen` |
| SRV-TL-18 | 12 §7.8.2.1 | W, slow | In its own admin session, Open(0x06), Write, stay idle for ActivityTimeout (the Property if present, else the 60 000 ms default) plus 10 s, then CloseAndUpdate | CloseAndUpdate fails and the list is unchanged | Fail: CloseAndUpdate succeeds | `no-activity-timeout` |
| SRV-TL-19 | 12 §7.8.2.1 | — | Read the TrustList's Size Property | A Bad status (OPC 10000-20 §4.2.1 names Bad_NotSupported), or no Size exposed | Warn: a value is returned | `size-readable` |
| SRV-TL-20 | 12 §7.8.2.1 | — | If UpdateFrequency exists, read its UserAccessLevel as `admin` | CurrentWrite is set | Fail: not writable for `admin`. Not supported: UpdateFrequency absent, which §7.8.2.1 requires for a TrustList inside ServerConfiguration | `updatefreq-readonly` |

## Signing request (`srv_csr.c`)

ConformanceUnit: Push Model for Global Certificate and TrustList Management.

| ID | Clause | Flags | Check | Pass when | Fail / Warn / Not supported | Mutant |
| --- | --- | --- | --- | --- | --- | --- |
| SRV-CSR-01 | 12 §7.10.10 | W | CreateSigningRequest(DefaultApplicationGroup, its type, SubjectName null, RegeneratePrivateKey FALSE, Nonce null) | A DER PKCS #10 request whose signature verifies and whose public key equals the key of the certificate the endpoint presents | Fail: does not parse, signature fails, or another key | `csr-new-key-always` |
| SRV-CSR-02 | 12 §7.10.10 | W | Compare the CSR subject of SRV-CSR-01 with the current certificate | Subjects equal | Fail: different | `csr-empty-subject` |
| SRV-CSR-03 | 12 §7.10.10; 6 §6.2.2 | W | Read the CSR's subjectAltName | Exactly one URI, equal to the target's ApplicationUri, and at least one DNS name or IP address | Fail: URI missing or different. Warn: no DNS name or IP | `csr-no-san` |
| SRV-CSR-04 | 12 §7.10.10 | W | CreateSigningRequest with RegeneratePrivateKey TRUE and a 32-byte Nonce | The CSR's public key differs from the current certificate's | Fail: same key | `csr-regen-ignored` |
| SRV-CSR-05 | 12 §7.10.10 | W | RegeneratePrivateKey TRUE with a 16-byte Nonce | Bad_InvalidArgument | Fail: Good. Warn: another Bad code | `csr-short-nonce` |
| SRV-CSR-06 | 12 §7.10.10 | W | As SRV-CSR-04 on its own session, then close it; on a new session call UpdateCertificate with a certificate from `ca` for the new key; close that session (the change is discarded) | Good | Fail: refused. Not tested: SupportsTransactions is not TRUE (the new key would be in use at once and the restore step cannot put the old key back) | `csr-key-per-session` |
| SRV-CSR-07 | 12 §7.10.10 | W | Two CSRs with RegeneratePrivateKey TRUE; UpdateCertificate with a certificate for the first new key; close the session | Refused (the first new key pair was discarded) | Fail: accepted. Not tested: as SRV-CSR-06 | `csr-keep-old-new-key` |
| SRV-CSR-08 | 12 §7.10.10 | W | CreateSigningRequest with a CertificateTypeId that is not in the group's CertificateTypes | Bad_InvalidArgument | Fail: Good. Warn: another Bad code | `csr-any-type` |

## Certificate update (`srv_update.c`)

ConformanceUnit: Push Model for Global Certificate and TrustList Management.

Before these tests the Auditor pushes a trust list that contains `ca`, so that `t-good` can validate.

| ID | Clause | Flags | Check | Pass when | Fail / Warn / Not supported | Mutant |
| --- | --- | --- | --- | --- | --- | --- |
| SRV-UPD-01 | 12 §7.10.5 | W | UpdateCertificate(DefaultApplicationGroup, type, `t-good`) | Good; ApplyChangesRequired is TRUE when SupportsTransactions is TRUE | Fail: refused | `update-refuse-valid` |
| SRV-UPD-02 | 12 §7.10.5 | W | UpdateCertificate with `t-wrongkey` (key matches neither the active nor the new key pair) | A Bad code | Fail: Good | `update-no-key-check` |
| SRV-UPD-03 | 12 §7.10.5; 6 §6.2.2; 4 §6.1.3 | W | UpdateCertificate with `t-wronguri` (SAN URI differs from the ApplicationUri) | Bad_CertificateUriInvalid or Bad_CertificateInvalid | Fail: Good (the server would present a certificate that breaks Part 6; [decision D3](README.md#decisions)). Warn: another Bad code. Not tested: SupportsTransactions not TRUE (an accepted certificate would be in use at once and break the rest of the run) | `update-no-uri-check` |
| SRV-UPD-04 | 12 §7.10.5 | W | UpdateCertificate with a certificate from `ca2`, passing `ca2` only in IssuerCertificates | Refused: for ApplicationCertificateType the issuer has to be in the TrustList already and IssuerCertificates is ignored | Fail: Good | `update-trust-issuer-arg` |
| SRV-UPD-05 | 12 §7.10.5; 4 §6.1.3 | W | UpdateCertificate with `t-badsig` | Bad_CertificateInvalid or Bad_SecurityChecksFailed | Fail: Good. Warn: another Bad code | `update-no-sig-check` |
| SRV-UPD-06 | 12 §7.10.5 | W | UpdateCertificate with a CertificateTypeId not in the group's CertificateTypes | Bad_InvalidArgument | Fail: Good. Warn: another Bad code | `update-any-type` |
| SRV-UPD-07 | 12 §7.10.5 | W | UpdateCertificate into an RSA slot with `t-ecc` | Bad_CertificateInvalid | Fail: Good. Warn: another Bad code | `update-type-mismatch` |
| SRV-UPD-08 | 12 §7.10.5; 4 §6.1.3 | W | UpdateCertificate with `t-expired` | Refused | Warn: accepted; Validity is suppressible in Part 4 and §7.10.5 says suppressible errors are ignored ([decision D2](README.md#decisions)) | `update-accept-expired` |
| SRV-UPD-09 | 12 §7.10.5 | W | If SupportedPrivateKeyFormats is not empty, UpdateCertificate with `t-withkey` in the first advertised format; apply; connect. The target's own key cannot be restored afterwards, so the test runs only when selected by name (`--only SRV-UPD-09`) and the restore leaves `t-withkey` in place | Good; the endpoint presents `t-withkey` and the handshake proves the matching key | Fail: refused, or the endpoint does not use it. Not supported: no formats advertised | `update-ignore-key` |
| SRV-UPD-10 | 12 §7.10.5 | W | As SRV-UPD-09 with a private key that does not match the certificate | Bad_NotSupported | Fail: Good. Warn: another Bad code. Not supported: no formats advertised | `update-accept-bad-key` |
| SRV-UPD-11 | 12 §7.10.8 | — | GetCertificates(DefaultApplicationGroup) | CertificateTypeIds and Certificates have equal length and include the certificate the endpoint presents | Fail: lengths differ or the endpoint certificate is missing. Not supported: method absent | `getcerts-mismatched` |
| SRV-UPD-12 | 12 §7.10.6 | W | CreateSelfSignedCertificate on the occupied DefaultApplicationGroup slot | Bad_InvalidState | Fail: Good. Warn: another Bad code. Not supported: method absent | `selfsigned-overwrite` |
| SRV-UPD-13 | 12 §7.10.7 | W | DeleteCertificate on the slot whose certificate an endpoint uses | Refused (Bad_InvalidState expected) | Fail: Good. Warn: another Bad code. Not supported: method absent | `delete-in-use` |

## Transactions (`srv_transaction.c`)

ConformanceUnit: Server PushManagement Transactions (SRV-TXN-03, -08, -09: Push Model for Global Certificate and TrustList Management).

| ID | Clause | Flags | Check | Pass when | Fail / Warn / Not supported | Mutant |
| --- | --- | --- | --- | --- | --- | --- |
| SRV-TXN-01 | 12 §7.10.2 | W | With SupportsTransactions TRUE, record ApplyChangesRequired from every UpdateCertificate and CloseAndUpdate in the run | Always TRUE | Fail: FALSE once. Not supported: SupportsTransactions absent or FALSE | `apply-required-false` |
| SRV-TXN-02 | 12 §7.10.2, §7.8.2.5 | W | Queue UpdateCertificate(`t-good`) and a new trust list; before ApplyChanges, open a fresh connection and read the TrustList on a second session | The old certificate is presented and the old trust list is read | Fail: either change is visible | `apply-early` |
| SRV-TXN-03 | 12 §7.10.9 | W | ApplyChanges after SRV-TXN-02; fresh connection; read the TrustList | The new certificate and the new trust list are both in use | Fail: either is missing | `apply-ignored` |
| SRV-TXN-04 | 12 §7.10.2, §7.10.11 | W | Queue both changes, CancelChanges | Good; old certificate and old list in use; LastUpdateTime unchanged | Fail: any change survives. Not supported: CancelChanges absent | `cancel-keeps-trustlist` |
| SRV-TXN-05 | 12 §7.10.2, §7.10.9 | W | Queue both changes, close the session, reconnect, ApplyChanges | Bad_NothingToDo; old state in use | Fail: Good, or any change in use | `txn-survives-session` |
| SRV-TXN-06 | 12 §7.10.2, §7.10.5, §7.8.2.2, §7.8.2.6 | W | While session A holds a transaction, session B (also `admin`) calls UpdateCertificate, Open(0x06) and AddCertificate | Each returns Bad_TransactionPending | Fail: any Good. Warn: another Bad code. Not supported: no transaction support | `txn-interleave` |
| SRV-TXN-07 | 12 §7.10.9, §7.10.11 | W | Session B calls ApplyChanges and CancelChanges for A's transaction | Bad_SessionIdInvalid (the spec text writes "Bad_BadSessionIdInvalid") | Fail: Good. Warn: another Bad code | `apply-any-session` |
| SRV-TXN-08 | 12 §7.10.9 | W | Open(0x06) and Write; ApplyChanges while the file is open; then CloseAndUpdate and ApplyChanges again | First ApplyChanges Bad_InvalidState with nothing applied; the second applies | Fail: the first applies anything, or the second fails | `apply-while-open` |
| SRV-TXN-09 | 12 §7.10.9 | W | ApplyChanges on a fresh session with no transaction | Bad_NothingToDo | Fail: Good. Warn: another Bad code | `apply-nothing-good` |
| SRV-TXN-10 | 12 §7.10.2 | W | In one transaction: a good trust list change, then UpdateCertificate(`t-wrongkey`) which fails, then ApplyChanges | The trust list change is applied | Fail: the failed call discarded the transaction | `fail-aborts-txn` |
| SRV-TXN-11 | 12 §7.10.2 | W | In one transaction: a trust list without `ca`, then UpdateCertificate(`t-good`), then ApplyChanges | Either UpdateCertificate is refused, or ApplyChanges fails with nothing applied | Fail: only some changes applied. Warn: ApplyChanges succeeds and the endpoint presents a certificate its own trust list cannot validate | `apply-partial` |
| SRV-TXN-12 | 12 §7.10.17 | W | Read TransactionDiagnostics during a transaction and after ApplyChanges | During: Result has status Bad_InvalidState, EndTime is DateTime.MinValue, AffectedTrustLists lists the TrustList queued (the test queues only a TrustList, the one in use, so nothing changes). After: Result is Good with the ApplyChanges code as value, StartTime ≤ EndTime, Errors empty | Fail: any value contradicts. Not supported: TransactionDiagnostics absent | `diag-stale` |
| SRV-TXN-13 | 12 §7.10.17 | W | Read TransactionDiagnostics after CancelChanges | Result value is Bad_RequestCancelledByClient | Fail: another value. Not supported: TransactionDiagnostics or CancelChanges absent | `diag-cancel-good` |

## On the wire (`srv_wire.c`)

ConformanceUnit: Push Model for Global Certificate and TrustList Management.

| ID | Clause | Flags | Check | Pass when | Fail / Warn / Not supported | Mutant |
| --- | --- | --- | --- | --- | --- | --- |
| SRV-WIRE-01 | 12 §7.10.9, §7.8.4.8, §7.8.4.9 | W | After SRV-TXN-03, GetEndpoints, and OpenSecureChannel on every endpoint whose SecurityPolicy uses the updated CertificateType (RsaMin for Basic128Rsa15 and Basic256, §7.8.4.8; RsaSha256 for Basic256Sha256 and the Aes RSA policies, §7.8.4.9), with a client that trusts only `ca` | Every such endpoint presents the new certificate; endpoints of other CertificateTypes are another slot of the group and are listed as evidence | Fail: any such endpoint presents the old one or refuses the channel | `wire-old-cert` |
| SRV-WIRE-02 | 12 §7.10.9 | W | A new certificate from `ca` for the key in use (`t-wire-02`), applied on an `admin` channel that trusts only `ca`; keep that channel open and watch it | The channel is closed or renewed with the new certificate within the settle timeout (the client takes a renewal that presents another certificate as a closed channel) | Warn: still on the old certificate after 30 s. Fail: still on it after the settle timeout | `wire-keep-channels` |
| SRV-WIRE-03 | 12 §7.10.9 | W | Subscribe to ServerStatus SecondsTillShutdown and ShutdownReason, then apply `t-wire-03` as in SRV-WIRE-02 on the same session | If the server closes connections, SecondsTillShutdown and ShutdownReason were set first | Warn: connections closed without notice (timing makes this unsafe to Fail) | `wire-no-shutdown-notice` |
| SRV-WIRE-04 | 12 §7.10.9; 4 §6.1.3 | W | With `ca` in the applied trust list, connect as `peer-good` | Session created | Fail: refused | `wire-trustlist-not-loaded` |
| SRV-WIRE-05 | 12 §7.10.9; 4 §6.1.3 | W | With `ca`'s CRL in the applied trust list, connect as `peer-revoked` | Refused (Bad_CertificateRevoked, or Bad_SecurityChecksFailed which hides the reason) | Fail: session created | `wire-ignore-crl` |
| SRV-WIRE-06 | 4 §6.1.3 | — | Connect as `peer-unknown` | Refused (Bad_CertificateUntrusted or Bad_SecurityChecksFailed) | Fail: session created | `wire-trust-all` |
| SRV-WIRE-07 | 12 §7.8.2.5 | W | Open a session as `peer-good`; RemoveCertificate(`peer-good`); apply | The `peer-good` session is closed: a Read on it fails | Warn: still open after 30 s. Fail: still open after the settle timeout | `wire-keep-removed-sessions` |
| SRV-WIRE-08 | 12 §7.8.2.5; 4 §6.1.3 | W | Open a session as `peer-good`; push a new CRL from `ca` that lists it; apply | The session is closed: a Read on it fails | Warn: still open after 30 s. Fail: still open after the settle timeout | `wire-crl-no-reeval` |

## Restore (`srv_restore.c`)

Not a conformance test: the last line of every run, with its own verdict (README, [Safety, snapshot and restore](README.md#safety-snapshot-and-restore)).

| ID | Clause | Flags | Check | Pass when | Fail / Warn / Not supported | Mutant |
| --- | --- | --- | --- | --- | --- | --- |
| SRV-RESTORE | README | W | On a new session (which discards any transaction a test left open, §7.10.2), push back the snapshot's certificate (if it changed) and trust list, and apply | Both pushed back and applied, or no test changed the target | Fail: either could not be restored; the evidence names what is left changed. When `--only` leaves this line out, the CLI still restores and prints the result as a comment | — |

## Persistence (`srv_persistence.c`)

ConformanceUnit: Push Model for Global Certificate and TrustList Management.

Each test restarts the target with `--restart-cmd` (run with `sh -c`; it must return once the restart is started) or an operator prompt when stdin is a terminal, and reports Not tested when neither is available. The Auditor then waits up to the settle timeout for GetEndpoints. SRV-PER-03 cancels its UpdateCertificate when the target has transactions, so the target keeps its key; without transactions the new key stays in use and the restore step warns.

| ID | Clause | Flags | Check | Pass when | Fail / Warn / Not supported | Mutant |
| --- | --- | --- | --- | --- | --- | --- |
| SRV-PER-01 | 12 §7.10.9 | W, O | Apply `t-good` and a new trust list; restart; connect and read back | Same certificate presented and same trust list read | Warn: either reverted. Part 12 states no persistence rule for applied changes (Annex F only recommends a store layout), so this is a Warn; see [decision D1](README.md#decisions) | `forget-on-restart` |
| SRV-PER-02 | 12 §7.8.2.1 | W, O | Read LastUpdateTime before and after the restart of SRV-PER-01 | Equal, or DateTime.MinValue | Fail: any other value | `lastupdate-reset-now` |
| SRV-PER-03 | 12 §7.10.10 | W, O | CreateSigningRequest(RegeneratePrivateKey TRUE); restart; UpdateCertificate with a certificate for the new key | Good | Fail: refused because the new key pair was lost | `csr-key-in-ram` |
| SRV-PER-04 | 12 §7.10.2 | W, O | Queue both changes without ApplyChanges; restart | The old certificate and trust list are in use | Fail: any queued change is in use | `txn-persist-uncommitted` |

## Rejected list (`srv_rejected.c`)

ConformanceUnit: Push Model for Global Certificate and TrustList Management.

| ID | Clause | Flags | Check | Pass when | Fail / Warn / Not supported | Mutant |
| --- | --- | --- | --- | --- | --- | --- |
| SRV-REJ-01 | 12 §7.10.12 | — | Connect as a fresh self-signed `peer-unknown` (refused, as in SRV-WIRE-06), then GetRejectedList as `admin` | `peer-unknown` is in the list | Warn: missing. Adding rejected certificates is only recommended | `rejected-not-recorded` |
| SRV-REJ-02 | 12 §7.8.3.2, §7.10.12 | — | Connect with `peer-badsig`, a self-signed client certificate with one signature bit flipped (an unsuppressible error, 4 §6.1.3), then GetRejectedList | It is not in the list (only valid but untrusted certificates are added) | Fail: it is in the list | `rejected-records-invalid` |
| SRV-REJ-03 | 12 §7.10.12 | — | Decode every entry GetRejectedList returns | Every entry is a DER certificate | Fail: an entry does not decode | `rejected-garbage` |
| SRV-REJ-04 | 12 §7.8.3.1, §7.8.3.2 | — | If a CertificateGroup has its own GetRejectedList, call it as `admin` | Good, and every entry decodes | Fail: Bad code or an entry that does not decode. Not supported: no group-level method | `group-rejected-broken` |

## Push setup (`srv_setup.c`)

ConformanceUnit: Push Model for Global Certificate and TrustList Management.

These tests need the target in its application setup state, so an operator (or `--setup-cmd`) has to reset it first. They run only when selected with `--only SRV-SET` and are not in any preset. Before the first of them `gdsaudit` runs `--setup-cmd` (or, at a terminal, asks the operator to reset the target) and waits for GetEndpoints; without either it takes the target as already reset. The Auditor connects with its usual admin identity, which the target's setup credentials must map to SecurityAdmin (12 §7.5). SRV-SET-04 adds that same identity to the SecurityAdmin Role: a UserName rule with `--admin-user`, else an Application rule with the ApplicationUri of the admin certificate (OPC 10000-18 §4.4.3; Bad_AlreadyExists counts as added, §4.4.5). SRV-SET-06 needs `--allow-reset`; after the Shutdown it waits up to the settle timeout for the target to come back by itself, then uses `--restart-cmd` (or the operator). The self-test runs these against `push_test_server --setup`.

| ID | Clause | Flags | Check | Pass when | Fail / Warn / Not supported | Mutant |
| --- | --- | --- | --- | --- | --- | --- |
| SRV-SET-01 | 12 Annex G.2 | O | With InApplicationSetup TRUE, read ServerStatus.State | NoConfiguration | Fail: another state. Not supported: InApplicationSetup absent | `setup-state-running` |
| SRV-SET-02 | 12 Annex G.2 | O | In setup state, GetEndpoints | Every secure endpoint presents a certificate (the default certificate) | Fail: no certificate | `setup-no-cert` |
| SRV-SET-03 | 12 Annex G.2 | W, O | Push a trust list and `t-good`, apply, but do not configure the SecurityAdmin Role | InApplicationSetup is still TRUE | Fail: the server left setup without a configured SecurityAdmin Role | `setup-exit-no-role` |
| SRV-SET-04 | 12 Annex G.2; OPC 10000-18 §4.4.3, §4.4.5 | W, O | Add the Auditor's identity to the SecurityAdmin Role (Part 18 AddIdentity) after SRV-SET-03 | InApplicationSetup FALSE and State Running | Fail: still in setup | `setup-sticky` |
| SRV-SET-05 | 12 §7.5 | W, O | After SRV-SET-04, connect with `peer-unknown` | Refused | Warn: accepted (the server should restrict access once it has a trust list) | `setup-open-after` |
| SRV-SET-06 | 12 §7.10.13 | W, O | If ResetToServerDefaults exists and `--allow-reset` is given, call it and watch ServerStatus | State goes to Shutdown with a localized ShutdownReason; after the restart InApplicationSetup is TRUE | Fail: neither happens. Not supported: method absent. Not tested: no `--allow-reset` | `reset-no-shutdown` |

## KeyCredential push (`srv_keycred.c`)

ConformanceUnit: Push Model for KeyCredential Service. Every test is Not supported when ServerConfiguration has no KeyCredentialConfiguration folder (12 §8.6.2).

| ID | Clause | Flags | Check | Pass when | Fail / Warn / Not supported | Mutant |
| --- | --- | --- | --- | --- | --- | --- |
| SRV-KC-01 | 12 §8.6.3, §8.6.5 | W | CreateCredential with valid Name, ResourceUri, ProfileUri and EndpointUrls | Good; CredentialNodeId is a KeyCredentialConfigurationType Object with the ResourceUri and ProfileUri given | Fail: refused, or the Object is wrong | `kc-create-noop` |
| SRV-KC-02 | 12 §8.6.3 | W | CreateCredential with an invalid ResourceUri, then ProfileUri, then EndpointUrl | Each returns Bad_InvalidArgument | Fail: any Good. Warn: another Bad code | `kc-no-uri-check` |
| SRV-KC-03 | 12 §8.6.3, §8.6.7, §8.6.8 | W | CreateCredential, UpdateCredential and DeleteCredential as `user` over `ch-enc` | Each returns Bad_UserAccessDenied | Fail: any Good | `kc-no-secadmin` |
| SRV-KC-04 | 12 §8.6.6 | W | GetEncryptingKey on the credential from SRV-KC-01, with RequestedSecurityPolicyUri empty | PublicKey not empty and RevisedSecurityPolicyUri a known policy | Fail: empty key or empty policy. Not supported: method absent | `kc-empty-key` |
| SRV-KC-05 | 12 §8.6.7 | W | UpdateCredential with a secret encrypted to the key from SRV-KC-04 | Good | Fail: refused. Not supported: method absent | `kc-update-refuse` |
| SRV-KC-06 | 12 §8.6.7 | W | UpdateCredential with an unknown SecurityPolicyUri | Bad_SecurityPolicyRejected | Fail: Good. Warn: another Bad code | `kc-any-policy` |
| SRV-KC-07 | 12 §8.6.7 | W | UpdateCredential with an RSA policy and a CertificateThumbprint that is not one of the server's certificates | Bad_CertificateInvalid | Fail: Good. Warn: another Bad code | `kc-any-thumbprint` |
| SRV-KC-08 | 12 §8.6.7 | W | UpdateCredential with no SecurityPolicyUri (plaintext secret) | Refused | Warn: accepted. The spec allows it; the secret is then protected only by the channel | `kc-accept-plaintext` |
| SRV-KC-09 | 12 §8.6.8 | W | DeleteCredential on the credential from SRV-KC-01 | Good; the Object is gone | Fail: still present. Not supported: method absent | `kc-delete-noop` |
| SRV-KC-10 | 12 §8.6.5 | W, slow | Point a credential at an unreachable EndpointUrl; wait; read ServiceStatus | Bad_NoCommunication | Warn: another value or none. Not supported: ServiceStatus absent | `kc-status-stale` |

## Audit events (`srv_audit.c`)

ConformanceUnit: Push Model for Global Certificate and TrustList Management. Every test is Not supported when Server.Auditing is FALSE. This group is new: the plan's file list has no `srv_audit.c` yet.

| ID | Clause | Flags | Check | Pass when | Fail / Warn / Not supported | Mutant |
| --- | --- | --- | --- | --- | --- | --- |
| SRV-AUD-01 | 12 §7.8.2.1, §7.8.2.13 | W | Subscribe to events on Server; run SRV-TL-02 and SRV-TL-09 | One TrustListUpdatedAuditEventType per completed update | Fail: missing or duplicated | `audit-no-trustlist-event` |
| SRV-AUD-02 | 12 §7.10.27 | W | Subscribe to events; run SRV-TXN-03 and SRV-UPD-02 | One CertificateUpdatedAuditEventType per changed certificate, with SourceNode the ServerConfiguration Object; none for the failed call | Fail: missing, extra, or raised for the failed call | `audit-no-cert-event` |
