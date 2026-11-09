# Spec coverage matrix

This file answers one question: does every function that the specifications
introduce have a spec test? It lists each Method, Object and Event that
OPC 10000-12 v1.05.07 defines, its ModellingRule as the OPC NodeSet
(`Opc.Ua.Gds.NodeSet2.xml`, `Opc.Ua.NodeSet2.xml`) gives it, the clause,
and the spec tests that cover it. The verdict in brackets is what opengdsd
gets today (`tests/integration/pull/expected/opengds.csv`). A failing or
not supported verdict is a finding against opengdsd, not a gap in the tests.
`tools/auditor/profile_gds/phases.csv` names the phase that turns each one
green.

Rule column: M is Mandatory, O is Optional. "M if service" is Mandatory on
the service Object, which is itself Optional.

## GDS side (Auditor GDS profile, `tools/auditor/profile_gds/`)

| Spec item | Kind | Rule | Clause | Tests (opengdsd verdict) |
|---|---|---|---|---|
| DirectoryType | Applications folder, member list | M | §6.5.3 | `gds.model.directory` (pass) |
| FindApplications | Method | M | §6.5.5 | `gds.dir.find_unknown` (pass) |
| RegisterApplication | Method | M | §6.5.6 | `gds.dir.register_bad_type` (pass), `gds.dir.register_no_names` (pass), `gds.dir.register_no_uri` (pass), `gds.dir.register_server_no_urls` (pass), `gds.dir.register_valid` (pass), `gds.sec.anonymous_register` (pass) |
| UpdateApplication | Method | M | §6.5.7 | `gds.acc.update_other` (pass), `gds.dir.update_application` (pass) |
| UnregisterApplication | Method | M | §6.5.8 | `gds.acc.unregister_other` (pass), `gds.dir.unregister` (pass), `gds.dir.unregister_revokes` (pass) |
| GetApplication | Method | M | §6.5.9 | `gds.dir.get_application` (pass), `gds.dir.get_unknown` (pass) |
| QueryApplications | Method | M | §6.5.10 | `gds.dir.query_by_uri` (pass), `gds.qry.capabilities` (pass), `gds.qry.na_excluded` (pass), `gds.qry.name` (pass), `gds.qry.paging` (pass), `gds.qry.product_uri` (pass), `gds.qry.type_mask` (pass), `gds.qry.uri_pattern` (pass) |
| QueryServers | Method (deprecated) | M | §6.5.11 | `gds.qry.servers` (pass) |
| ApplicationRegistrationChangedAuditEventType | Event | M | §6.5.12 | `gds.ev.auditing_flag` (pass), `gds.ev.registration_changed` (pass) |
| Directory roles | DiscoveryAdmin, self-admin | M | §6.2 | `gds.acc.unregister_other` (pass), `gds.acc.update_other` (pass), `gds.sec.anonymous_register` (pass) |
| CertificateDirectoryType | member list | M | §7.9.2 | `gds.model.directory` (pass) |
| StartSigningRequest | Method | M | §7.9.3 | `gds.acc.sign_other` (pass), `gds.acc.sign_sign_only` (pass), `gds.cm.bad_csr` (pass), `gds.cm.csr_wrong_uri` (pass), `gds.cm.sign_bad_group` (pass), `gds.cm.sign_bad_type` (pass), `gds.cm.sign_null_group` (pass), `gds.cm.sign_unknown_app` (pass), `gds.cm.signing_flow` (pass) |
| StartNewKeyPairRequest | Method | M | §7.9.4 | `gds.acc.keypair_sign_only` (pass), `gds.cm.keypair_bad_format` (pass), `gds.cm.keypair_pem` (pass), `gds.cm.keypair_pfx` (pass), `gds.cm.keypair_unknown_app` (pass) |
| FinishRequest | Method | M | §7.9.5 | `gds.cm.finish_unknown` (pass), `gds.cm.keypair_pem` (pass), `gds.cm.keypair_pfx` (pass), `gds.cm.signing_flow` (pass) |
| RevokeCertificate | Method | O | §7.9.6 | `gds.acc.revoke_needs_ca_admin` (pass), `gds.cm.revoke` (pass), `gds.cm.revoke_foreign` (pass), `gds.cm.revoke_unknown_app` (pass), `gds.ev.certificate_revoked` (pass) |
| GetCertificateGroups | Method | M | §7.9.7 | `gds.cm.groups` (pass), `gds.cm.groups_unknown` (pass) |
| GetCertificates | Method | O | §7.9.8 | `gds.acc.get_certificates_other` (pass), `gds.cm.get_certificates` (pass), `gds.cm.get_certificates_bad_group` (pass), `gds.cm.get_certificates_unknown` (pass), `gds.cm.revoke` (pass) |
| GetTrustList | Method | M | §7.9.9 | `gds.tl.get_trustlist` (pass) |
| GetCertificateStatus | Method | M | §7.9.10 | `gds.cm.status_after_issue` (pass), `gds.cm.status_new` (pass) |
| CheckRevocationStatus | Method | O | §7.9.11 | `gds.cm.check_bad_signature` (pass), `gds.cm.check_good` (pass), `gds.cm.check_revoked` (pass) |
| CertificateRequestedAuditEventType | Event | M | §7.9.12 | `gds.ev.certificate_requested_delivered` (pass) |
| CertificateDeliveredAuditEventType | Event | M | §7.9.13 | `gds.ev.certificate_requested_delivered` (pass) |
| CertificateRevokedAuditEventType | Event | O | §7.9.14 | `gds.ev.certificate_revoked` (pass) |
| CertificateManager roles | CertificateAuthorityAdmin, self-admin | M | §7.2 | `gds.acc.get_certificates_other` (pass), `gds.acc.revoke_needs_ca_admin` (pass), `gds.acc.sign_other` (pass), `gds.acc.tl_add_needs_ca_admin` (pass), `gds.sec.none_session` (pass) |
| TrustListType | Object, LastUpdateTime, FileType | M | §7.8.2.1 | `gds.ev.trustlist_updated` (pass), `gds.model.certificate_group` (pass), `gds.tl.add_remove` (pass), `gds.tl.close_discards` (pass), `gds.tl.write_update` (pass) |
| Open | Method (FileType) | M | §7.8.2.2 | `gds.tl.open_bad_mode` (pass), `gds.tl.write_anonymous` (pass) |
| OpenWithMasks | Method | M | §7.8.2.3 | `gds.tl.open_with_masks` (pass) |
| Read / file position | FileType | M | §7.8.2.4 | `gds.tl.read_bad_handle` (pass), `gds.tl.read_chunked` (pass) |
| CloseAndUpdate | Method | M | §7.8.2.5 | `gds.tl.write_update` (pass) |
| AddCertificate | Method | M | §7.8.2.6 | `gds.acc.tl_add_needs_ca_admin` (pass), `gds.tl.add_no_issuer` (pass), `gds.tl.add_remove` (pass), `gds.tl.add_untrusted_flag` (pass), `gds.tl.add_while_open` (pass) |
| RemoveCertificate | Method | M | §7.8.2.7 | `gds.tl.add_remove` (pass), `gds.tl.remove_unknown` (pass) |
| TrustListMasks | DataType | M | §7.8.2.9 | `gds.tl.open_with_masks` (pass) |
| CertificateGroupType | TrustList, CertificateTypes, alarms | M | §7.8.3.1 | `gds.ev.group_alarms` (not_supported), `gds.model.certificate_group` (pass) |
| KeyCredentialManagement / KeyCredentialServiceType | Object | O | §8.5.3 | `gds.kc.service` (pass) |
| StartRequest (KeyCredential) | Method | M if service | §8.5.5 | `gds.kc.policy_without_key` (pass), `gds.kc.request_flow` (pass), `gds.kc.sign_only` (pass), `gds.kc.start_unknown_uri` (pass) |
| FinishRequest (KeyCredential) | Method | M if service | §8.5.6 | `gds.kc.cancel` (pass), `gds.kc.finish_unknown` (pass), `gds.kc.request_flow` (pass) |
| Revoke (KeyCredential) | Method | O | §8.5.7 | `gds.ev.keycred_revoked` (pass), `gds.kc.revoke` (pass), `gds.kc.revoke_unknown` (pass) |
| KeyCredential audit events | Events | M if service | §8.5.8 - §8.5.11 | `gds.ev.keycred_requested_delivered` (pass), `gds.ev.keycred_revoked` (pass) |
| AuthorizationServices / AuthorizationServiceType | Object | O | §9.6.4 | `gds.az.service` (pass) |
| RequestAccessToken | Method (deprecated) | O | §9.6.5 | **none** (not offered: deprecated) |
| StartRequestToken | Method | O | §9.6.6 | `gds.az.sign_only` (pass), `gds.az.start_unknown_resource` (pass), `gds.az.token_flow` (pass) |
| FinishRequestToken | Method | O | §9.6.7 | `gds.az.finish_unknown` (pass), `gds.az.token_flow` (pass) |
| RefreshToken | Method | O | §9.6.8 | `gds.az.refresh_rejected` (pass), `gds.az.token_refresh` (pass) |
| GetServiceDescription | Method | M if service | §9.6.9 | `gds.az.description` (pass) |
| AccessTokenRequestedAuditEventType | Event | M if service | §9.6.10 | `gds.az.audit_requested` (pass) |
| AccessTokenIssuedAuditEventType | Event | M if service | §9.6.11 | `gds.az.audit_issued` (pass) |
| mDNS announce, FindServersOnNetwork (LDS-ME) | SRV and TXT records, capability `GDS` | O | §4.3.4, §5, Annex C, Annex D | `unit_disc_mdns`, `integration_mdns_watch` step 3 (pass; not Auditor tests: the GDS profile does not cover discovery) |
| MulticastDnsEnabled (the GDS's own ServerConfiguration) | Property | M | §7.10.3 | `unit_disc_mdns` (reads TRUE with `mdns = true`); writing it is refused, see Known gaps |

Security of the channel and sessions: `gds.sec.endpoints` (pass; Part 4
§5.4.4, Part 7), `gds.sec.none_session` (pass), `gds.sec.anonymous_register`
(pass), and the sign-only tests `gds.acc.sign_sign_only` (pass),
`gds.acc.keypair_sign_only` (pass), `gds.kc.sign_only` (pass) and
`gds.az.sign_only` (pass). FileType handles are per Session
(Part 20 §4.2.2): `gds.tl.handle_other_session` (pass).

## Push side (Auditor server profile, `docs/auditor/server-profile.md`)

ServerConfigurationType (§7.10), the push TrustList (§7.8.2) and the
KeyCredentialConfiguration (§8.6) of a server under test are covered by the
107 SRV-* tests: SRV-CAP (capabilities), SRV-TL (TrustList methods), SRV-CSR
(CreateSigningRequest), SRV-UPD (UpdateCertificate), SRV-TXN (transactions,
ApplyChanges, CancelChanges), SRV-WIRE, SRV-PER, SRV-REJ (GetRejectedList),
SRV-SET (Annex G.2 setup), SRV-KC (KeyCredentialConfiguration) and SRV-AUD.

KeyCredential push (§8.6), against `push_test_server` with a mutant per test:

| Spec item | Clause | Tests (verdict) |
|---|---|---|
| CreateCredential, KeyCredentialConfigurationType Object | 12 §8.6.3, §8.6.5 | `SRV-KC-01` (pass), `SRV-KC-02` (pass) |
| SecurityAdmin for Create-, Update- and DeleteCredential | 12 §8.6.3, §8.6.7, §8.6.8 | `SRV-KC-03` (pass) |
| GetEncryptingKey | 12 §8.6.6 | `SRV-KC-04` (pass) |
| UpdateCredential: RsaEncryptedSecret, SecurityPolicy, thumbprint, plaintext | 12 §8.6.7 | `SRV-KC-05` .. `SRV-KC-08` (pass) |
| DeleteCredential | 12 §8.6.8 | `SRV-KC-09` (pass) |
| ServiceStatus | 12 §8.6.5 | `SRV-KC-10` (pass, slow) |
| OpenGDS as the administration component (§8.4): `gdsadm push keycred` and `keycred-delete` | 12 §8.4, §8.5.5 - §8.5.7, §8.6.3 - §8.6.8 | `integration_push_vs_opengdsd` step 7b |

## Application setup (Annex G) and Reverse Connect (`tests/spec/`)

OpenGDS's own client side of Annex G is covered by `tests/spec/test_spec_annex_g.c`
(against the Auditor's `push_test_server --setup` and `mock_gds`) and end to
end with opengdsd by `tests/spec/run_annex_g_vs_opengdsd.sh`.

| Spec item | Clause | Tests (verdict) |
|---|---|---|
| Push setup: setup state check (State NoConfiguration, InApplicationSetup) | 12 Annex G.2, §7.10.3 | `annexg.g2.state` (pass), `annexg.g2.not-in-setup` (pass) |
| Push setup: only a pre-authorized device | 12 Annex G.2 (last paragraph), §7.5 | `annexg.g2.not-preauthorized` (pass) |
| Push setup: trust list, certificate, ApplyChanges; CancelChanges on failure, device stays in setup | 12 Annex G.2, §7.7.2, §7.10.11 | `annexg.g2.setup` (pass), `annexg.g2.presents-issued` (pass), `annexg.g2.cancel-in-setup` (pass) |
| Push setup: SecurityAdmin Role configured (AddIdentity, Application rule), device leaves setup | 12 Annex G.2, G.3; 18 §4.4.3, §4.4.5 | `annexg.g2.admin-rule` (pass), `annexg.g2.setup` (pass) |
| Reverse Connect: ReverseHello, Server identity checked | 6 §7.1.3 (Table 78) | `annexg.rc.wrong-uri` (pass), `annexg.rc.setup` (pass) |
| Pull setup: register, CSR with a new key, FinishRequest, trust list, persisted together | 12 Annex G.1, §7.6 (Table 21) | `annexg.g1.first` (pass) |
| Pull setup: the issued certificate instead of credentials; no connection to an untrusted GDS | 12 Annex G.1 | `annexg.g1.renew-check` (pass), `annexg.g1.untrusted-gds` (pass) |
| Pull setup: a pending request continues in the next run | 12 §7.6 (Table 21, SigningRequestPending) | `annexg.g1.pending` (pass) |

## UASM (Part 14 SKS, Part 21 onboarding, Part 100)

UASM keeps its own matrix in `tests/spec/coverage.csv` in the UASM
repository (merged in UASM PR #30). It lists 202 NodeSet members: 53 from
Part 14 (PubSubKeyServiceType, SecurityGroupType and the key push types),
80 from Part 21 (the Registrar and DeviceRegistrar types), 66 from Part 100
and 3 from Part 5. Each row names the catalogue tests that check it, or
says why none applies, or names the open decision it waits on.

## Known gaps

These items have no test yet, and each needs work before it can have one:

- AccessTokens for the UserName and X.509 UserTokenPolicies. The Auditor
  has no user credentials of the target, so `gds.az.token_flow` uses the
  Session's own identity (an Anonymous policy, §9.3 Implicit); opengdsd's
  unit test `unit_authz` covers the other two policies and the lockout.
- RequestAccessToken (§9.6.5), which the spec deprecates; opengdsd does not
  offer it.
- Writing MulticastDnsEnabled on the GDS's own ServerConfiguration
  (§7.10.3: "It can be changed by writing to the Variable"). opengdsd
  reads it from `mdns` in its configuration and refuses the write (every
  Variable is read-only to sessions): open62541 v1.5.10 has no public call
  to start or stop the announce at run time.
- GetRejectedList (§7.8.3.1, Optional) on GDS certificate groups. The push
  side covers it as SRV-REJ, and the push engine calls it on devices
  (`tests/integration/test_push_engine.c`, `docs/push.md`).
- Push side: DefaultValidationOptions, HasSecureElement and
  ConfigurationFile, the ServerConfiguration ProductUri, ApplicationNames and
  ApplicationType, the CertificateExpired and TrustListOutOfDate alarms, and
  AuthorizationServiceConfigurationType (§9.7) have no SRV-* test yet.
- KeyCredentialUpdatedAuditEventType and KeyCredentialDeletedAuditEventType
  (§8.6.9, §8.6.10) on a managed Server: no SRV-* test yet, and
  `push_test_server` does not raise them.
