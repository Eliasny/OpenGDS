# Gap 1: no key file after a CSR push that keeps the key

**Status (2026-11-06):** not reported upstream. Open PR
[open62541#8681](https://github.com/open62541/open62541/pull/8681) ("Persist
locally generated CSR key pair", opened 2026-11-05) fixes a neighbouring case:
it persists a key that CreateSigningRequest *generated*, so a push still works
after a restart. It does not touch the case where the CSR **keeps** the
current key (`regeneratePrivateKey = false`). Our patch covers that case and
works with or without #8681 (tested both ways, see below).

**Patches:** the small fix [patches/master/0001-filestore-store-key-in-use.patch](patches/master/0001-filestore-store-key-in-use.patch), and on top of it the public API proposal [patches/master/0004-filestore-keep-key-in-use-api.patch](patches/master/0004-filestore-keep-key-in-use-api.patch)
(backport for our pinned build: [patches/v1.5.10/0001-filestore-store-key-in-use.patch](patches/v1.5.10/0001-filestore-store-key-in-use.patch)).

## What goes wrong

`updateCertificate_filestore()` in `plugins/crypto/ua_securitypolicy_filestore.c`
writes the new certificate to `<pki>/ApplCerts/own/certs/<CN>[<thumbprint>].der`,
but writes `own/private/<CN>[<thumbprint>].key` only when UpdateCertificate
carried a new private key. In the CSR flow with the key kept, no key travels,
so the store ends up with a certificate and no key of the same name. After a
restart, an application that loads its own certificate from the store finds no
key for it. Two smaller problems sit in the same function: a certificate that
is already in the store returns early, so its key is never written, and the
old certificate copy (`localCertificateTmp`) is made and then thrown away.

OpenGDS works around this today: `push_test_server` keeps its key in
`own/private/app.key` and pairs it with the newest certificate whose public key
matches, preferring a CA-issued one over the self-signed one.

## The fix

When UpdateCertificate brings no new key, the filestore looks in `own/private`
for the key that pairs with the new certificate
(`UA_CertificateUtils_checkKeyPair`) and stores a copy under the certificate's
name. A certificate that is already stored no longer skips writing its key. If
no key in the store matches, it logs a warning and returns Good as before, so
nothing that works today starts failing. The key buffers are zeroed after use.

Limit: the fix needs the key in use to be somewhere in `own/private`. An
application that keeps its key outside the store gets the warning instead.
That case is covered by the API proposal below (Elias chose to send both).

## Test

`tests/encryption/check_update_certificate.c`, new test
`update_certificate_noKey_storesKeyInUse` in the "Update Certificate Filestore"
case: the application key is put in `own/private/app.key`, the matching
certificate is pushed without a key, and the test checks that `own/certs` and
`own/private` now hold the certificate and a copy of that key under the same
base name.

Checked on open62541 master `24fc6b296` (OpenSSL 3.0, GDS receiver on):

| Run | Result |
|---|---|
| New test without the fix, fresh store | fails: no key file next to the certificate |
| New test with the fix (fresh store, and rerun on the same store) | 19/19 pass |
| `check_gds_csr_key`, `check_gds_informationmodel`, `check_gds_trustlist`, `check_certificategroup`, `check_encryption_basic256sha256` | all pass |
| Merged onto PR #8681 (one trivial conflict at the `writeCertificateAndPrivateKeyToFilestore` call) | `check_update_certificate` 19/19, `check_gds_csr_key` 14/14 |
| v1.5.10 with the backport, test ported to `UA_Server_updateCertificate` | `check_update_certificate` 9/9 |

## Draft issue

> **Title:** Filestore writes no private key for a certificate pushed after a CSR that keeps the key
>
> **Version:** v1.5.10 and master (24fc6b296), `UA_ENABLE_ENCRYPTION=OPENSSL`, GDS push receiver.
>
> **Steps:**
> 1. Start a server with `UA_ServerConfig_setDefaultWithFilestore` and a PKI folder.
> 2. Call `CreateSigningRequest` with `regeneratePrivateKey = false`.
> 3. Have a CA sign the CSR and call `UpdateCertificate` with the new certificate and no private key.
> 4. Look at `<pki>/ApplCerts/own/`.
>
> **Expected:** `own/certs/<name>.der` and `own/private/<name>.key` exist as a pair, so the application can load them after a restart (Part 12, Annex F.1 store layout).
>
> **Actual:** only `own/certs/<name>.der` is written. `writeCertificateAndPrivateKeyToFilestore()` writes the key file only when UpdateCertificate carried a new key. After a restart there is no key with the certificate's name. In addition, a certificate that is already in the store returns early and never gets its key written.
>
> PR #8681 persists a key that CreateSigningRequest *generated*; this issue is the key-kept case, which #8681 does not change. A fix is ready (PR to follow).

## Draft pull request

> **Title:** `fix(plugin): store the key in use for a certificate pushed without a key`
>
> **Problem.** When UpdateCertificate installs a certificate without a new private key (the certificate was issued for a CSR without `regeneratePrivateKey`), the filestore SecurityPolicy writes the certificate to `own/certs` but no key to `own/private`. After a restart, the application finds the new certificate in the store but no key with the same name. Fixes #&lt;issue&gt;.
>
> **Solution.** If no new key arrives, look in `own/private` for the key that pairs with the new certificate (`UA_CertificateUtils_checkKeyPair`) and store it under the certificate's name. A certificate already in the store no longer skips writing its key. If no stored key pairs with the certificate, log a warning and keep the current behaviour (return Good). Key buffers are zeroed after use.
>
> **Compatibility.** No API change. The only new file is the extra `.key` copy next to the certificate. This complements #8681 (generated keys); the two touch neighbouring lines and merge with one trivial conflict, and both test suites pass on the merge.
>
> **Tests.** New `update_certificate_noKey_storesKeyInUse` in `check_update_certificate.c`. It fails without the change and passes with it; the existing GDS and filestore tests pass.
>
> **Security note.** The change copies a private key that is already in `own/private` to a second file in the same directory with the same permissions. It reads only regular files in that directory and does not follow the certificate's subject into the path (the existing `createCertName` sanitising is unchanged).

## Public API proposal (patch 0004, on top of 0001)

open62541's `CONTRIBUTING.md` asks for public API changes to be discussed
before they are merged, so this goes in as a proposal issue first, with the
patch attached or linked as a draft PR.

**The change.** New `UA_SecurityPolicy_FilestoreWithKey(policy, innerPolicy,
storePath, privateKey)` in `securitypolicy_default.h`. The wrapper keeps a copy
of the key in use, zeroed on clear. When UpdateCertificate brings no new key,
it stores that copy with the new certificate (after checking the pair),
before falling back to the `own/private` scan from 0001. A new key installed
by UpdateCertificate replaces the copy. `UA_ServerConfig_addSecurityPolicies_Filestore`
already holds the decrypted key and now passes it, so
`UA_ServerConfig_setDefaultWithFilestore` users get the fix with no code
change. `UA_SecurityPolicy_Filestore` and `UA_ServerConfig_addSecurityPolicy_Filestore`
keep their signatures and behaviour, so the change is source and binary
compatible. It has a `CHANGES.md` entry.

**Test.** New `update_certificate_noKey_storesConfiguredKey`: every copy of
the key is removed from `own/private`, the matching certificate is pushed
without a key, and the key must appear under the certificate's name. On master
`24fc6b296` it fails with only 0001 applied and passes with 0004
(`check_update_certificate` 20/20; `check_gds_csr_key`,
`check_server_config_default`, `check_encryption_basic256sha256` pass).

**Security note.** The wrapper now holds one more copy of the private key in
memory per filestore SecurityPolicy, the same key the inner policy already
holds. The copy is zeroed with `UA_ByteString_memZero` before it is freed.

### Draft proposal issue

> **Title:** Proposal: let the filestore SecurityPolicy keep the key in use
>
> Follow-up to #&lt;gap 1 issue&gt;. The filestore wrapper (`UA_SecurityPolicy_Filestore`) never sees the private key of the inner SecurityPolicy. When UpdateCertificate installs a certificate without a new key (CSR without `regeneratePrivateKey`), #&lt;gap 1 PR&gt; can store a key only if a matching one is already in `own/private`. Applications that keep their key elsewhere still end up with no key for the new certificate after a restart.
>
> Proposal: add `UA_SecurityPolicy_FilestoreWithKey(policy, innerPolicy, storePath, privateKey)`. The wrapper keeps a zeroed-on-clear copy of the key in use, stores it with a certificate pushed without a key, and replaces it when UpdateCertificate brings a new key. `UA_ServerConfig_addSecurityPolicies_Filestore` passes the key it already holds, so `UA_ServerConfig_setDefaultWithFilestore` users get it for free. The existing functions keep their signatures and behaviour.
>
> A patch with a test and a CHANGES.md entry is ready (stacked on #&lt;gap 1 PR&gt;). Would you take it in this form, or prefer another shape (e.g. a key argument on `UA_ServerConfig_addSecurityPolicy_Filestore`)?
