# Gap 5: the client does not check the server certificate's ApplicationUri

**Status (2026-11-06):** found by the Auditor client profile (CLI-TRU-05, OpenGDS PR #54): a GDS whose certificate is issued by a trusted CA but names another ApplicationUri than the GDS describes itself with is accepted by an open62541 client. **Fixed on master** by [open62541#8478](https://github.com/open62541/open62541/pull/8478) ("fix(client): validate server certificate ApplicationUri", merged 2026-09-22, commit `980fe5866`). **Not on the `1.5` branch** (`9a3f02a6d`, checked 2026-11-06) and not in any release, so our pinned v1.5.10 has the gap. No upstream issue or backport PR exists. The ask upstream is a backport to `1.5`, not a new fix. Elias posts it (O5).

**Patch:** [patches/1.5/0001-client-validate-server-applicationuri.patch](patches/1.5/0001-client-validate-server-applicationuri.patch): `git cherry-pick -x 980fe5866` onto `origin/1.5`, with one conflict resolved in the test file (1.5 has no `UA_atomic_store`, so the test keeps `running = true`). The commit keeps its upstream author. It is **not carried** on our v1.5.10 build (there is no `patches/v1.5.10/` copy); see "OpenGDS" below.

## What the spec requires

- OPC 10000-4 v1.05 §6.1.3, Table 100 (Certificate validation steps), step "URI": Application Certificates "contain an application or product URI that shall match the URI specified in the ApplicationDescription", error `Bad_CertificateUriInvalid`, and "This error may not be suppressed."
- OPC 10000-4 v1.05 §5.7.2.1 (CreateSession): "The Client shall check that the ApplicationUri specified in the Server Certificate matches the ApplicationUri" of the Server, and "If there is a difference then the Client shall close the Session and report an error."

## What goes wrong on v1.5.10

`createSessionCallback()` in `src/client/ua_client_connect.c` checks that the CreateSession certificate equals the SecureChannel certificate and checks the signature, and the CertificateGroup checks the chain. Nothing compares the certificate's subjectAltName URI with the ApplicationUri the Server claims. So any certificate from a trusted CA (for example one issued by the same GDS to another application) can stand in for the Server. The only `UA_CertificateUtils_verifyApplicationUri` call on the client side checks the client's own certificate.

## The fix (already on master)

After the certificate and signature checks, the client calls `UA_CertificateUtils_verifyApplicationUri(serverCertificate, serverEndpoints[i].server.applicationUri)` for every EndpointDescription in the CreateSession response and closes with the error on a mismatch. A response that has a certificate but no EndpointDescription is rejected with `Bad_SecurityChecksFailed`. Many test fixtures had to get matching ApplicationUris, which is why the commit touches 19 files.

A neighbouring master fix, [#8479](https://github.com/open62541/open62541/pull/8479) (`07b632a6f`, "verify selected CreateSession endpoint"), binds the unauthenticated GetEndpoints choice to the authenticated CreateSession endpoints. It adds the `endpointDescriptionRule` field to `UA_ClientConfig`, which changes the ABI, so it is left out of this backport. The draft mentions it so maintainers can decide.

## Test

The backport brings master's tests along. `check_cert_validation_client_response` gains `testCreateSessionAcceptsMatchingServerApplicationUri` and `testCreateSessionRejectsMismatchingServerApplicationUri`; the other fixtures get matching URIs.

Checked on `origin/1.5` `9a3f02a6d`, Ubuntu 24.04, GCC 13, OpenSSL 3.0.13, Debug:

| Run | Result |
|---|---|
| Backport without the `src/` change | `check_cert_validation_client_response` 2/3: the mismatch test connects with Good |
| Backport | `check_cert_validation_client_response` 3/3; `check_client_encryption`, `check_client_authentication`, `check_crl_validation`, `check_certificategroup`, `check_crypto_coverage`, `check_gds_informationmodel`, `check_username_connect_none` and the RSA `check_encryption_*` suites pass (14 suites) |
| `src/` part on v1.5.10 after our four carried patches | applies cleanly |

## OpenGDS

- **Push engine (`src/push/push_session.c`): exposed, fixed.** It compared the ApplicationUri from GetEndpoints with the expected one, but never looked at the certificate. `push_session_open` now records the certificate the client verifies on the SecureChannel (a thin wrapper around the client's CertificateGroup), and after connecting it checks that the Server describes itself with the expected ApplicationUri and that the certificate names it. Otherwise it closes with `Bad_ServerUriInvalid` or `Bad_CertificateUriInvalid`. This does not depend on the library fix. New integration case `cert-uri-mismatch` in `tests/integration/test_push_flow.c`: a second `push_test_server` whose certificate comes from the trusted CA but names `urn:opengds:test:someone-else`.
- **`gdsadm`: not exposed.** It works on the local store and opens no OPC UA connection.
- **Auditor `pull_test_client`:** PR #54 adds the same check there.
- **Carrying the library fix:** not done, because it would also make PR #54's `no-gds-uri-check` mutant stop tripping (the library would refuse the GDS before the client code runs). That choice is open for Elias.

## Draft comment or issue

> **Title:** Backport #8478 (client: validate server certificate ApplicationUri) to 1.5
>
> #8478 makes the client check that the server certificate names the ApplicationUri returned by CreateSession, which OPC UA Part 4 requires (§6.1.3, Table 100, step "URI", "may not be suppressed"; §5.7.2.1). It is on master but not on `1.5`, so v1.5.10 clients accept any certificate from a trusted CA as the server's, for example one issued by the same GDS to another application. Could it go into the next 1.5 patch release? The cherry-pick applies with one small conflict in the test file; I have a branch ready and can open the PR against `1.5`. #8479 (CreateSession endpoint binding) is related but adds a `UA_ClientConfig` field, so I left it out.

## Draft pull request (against `1.5`)

> **Title:** `fix(client): validate server certificate ApplicationUri` (backport of #8478 to 1.5)
>
> **Problem.** On 1.5 the client does not check that the server certificate's subjectAltName URI matches the ApplicationUri the server claims. Part 4 §6.1.3 (Table 100, step "URI") and §5.7.2.1 require this check, and it may not be suppressed. Fixes #&lt;issue&gt;.
>
> **Solution.** Cherry-pick of 980fe5866 from master (#8478), unchanged in `src/`. In `check_cert_validation_client_response.c` the fixture keeps `running = true` because 1.5 has no `UA_atomic_store`.
>
> **Tests.** `check_cert_validation_client_response` 3/3; the mismatch test fails without the `src/` change. The client, encryption, CRL and certificate group suites pass.
