# Gap 9: DER CRLs shorter than 256 bytes do not load

**Status (2026-11-09):** found when OpenGDS began publishing ECC issuing CAs (#135). The `gcc asan-ubsan` and `clang asan-ubsan` CI jobs failed `integration_push_vs_opengdsd`: the push test server, which keeps its trust list in open62541's file store, aborted in `getCertFileName` (`ua_certificategroup_filestore.c:157`, memcpy from NULL) while writing the pushed trust list. The gap is present on our pinned v1.5.10 and on master `24fc6b296` (same code). It has not been searched upstream yet; do that before posting. Elias posts it (O5).

**Patch:** [patches/v1.5.10/0007-load-short-der-crl.patch](patches/v1.5.10/0007-load-short-der-crl.patch). It is authored by Elias (O4) and is **carried** on our build.

## What goes wrong

`UA_OpenSSL_LoadCrl` (plugins/crypto/openssl/securitypolicy_common.c) and `UA_mbedTLS_LoadCrl` (plugins/crypto/mbedtls/securitypolicy_common.c) treat a CRL as DER only when it starts `0x30 0x82`, a SEQUENCE with a two-byte length. A DER CRL of 128 to 255 bytes starts `0x30 0x81`. An ECC CA's CRL with no entries is about 200 bytes (an RSA CA's is over 256 bytes because of its signature), so it goes to the PEM parser and fails. As a result:

- `UA_CertificateUtils_getSubjectName` returns an empty name, and the file store copies it with `memcpy(buf, NULL, 0)`, which UBSan reports.
- The CRL is stored under a name made of zero bytes and is never loaded, so the certificates that CA revokes stay trusted.

## The fix

OpenSSL: try DER first and fall back to PEM, as `UA_OpenSSL_LoadCertificate` already does. mbedTLS: any input that starts with a SEQUENCE tag (`0x30`) is DER; PEM starts with `-----BEGIN`.

## Tests

`tests/unit/test_revoke.c` (`test_ecc`) loads the P-256 and P-384 CRLs that opengdsd publishes with `UA_CertificateUtils_getSubjectName`: Bad_SecurityChecksFailed for the P-256 CRL without the patch, Good with it. `integration_push_vs_opengdsd` in the sanitizer CI jobs covers the file store path.

## Devices with an unpatched open62541

A device on open62541 v1.5.10 without this patch accepts the trust list but does not load the P-256 and P-384 CRLs. Revocation by those CAs is therefore not enforced on such a device until open62541 is fixed. RSA is unaffected.
