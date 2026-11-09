# OpenGDS CA: what goes into a certificate

The built-in CA backend (`src/ca/ca_openssl.c`) issues application instance certificates for StartSigningRequest. It runs inside `opengds-signer` (decision G1). Every field comes from the registered application record or from the CA configuration. From the CSR, only the public key is used, and only after the CSR's signature verifies with that key (decision G5; OPC 10000-12 §7.9.4).

## Issued application certificate

| Field | Value | Source |
|---|---|---|
| Version | v3 | RFC 5280 |
| Serial number | 20 random bytes, positive, non-zero | RFC 5280 §4.1.2.2 |
| Signature | sha256WithRSAEncryption | RsaSha256ApplicationCertificateType |
| Subject | `CN` = first ApplicationName of the record, cut to 64 bytes at a UTF-8 boundary; `O` = configured organization | record, config |
| Validity | from now minus 5 minutes (clock skew) to now plus `leafLifetimeDays` (default 365, G6), never past the CA's notAfter | config |
| basicConstraints | cA FALSE, critical | OPC 10000-6 §6.2.2 |
| keyUsage | digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment, critical | OPC 10000-6 §6.2.2 (RSA) |
| extendedKeyUsage | servers: serverAuth and clientAuth; clients: clientAuth | OPC 10000-6 §6.2.2 |
| subjectAltName | URI = ApplicationUri; one DNS or IP entry per distinct DiscoveryUrl host | record |
| subjectKeyIdentifier, authorityKeyIdentifier | key ids (RFC 5280 method 1) | RFC 5280 §4.2.1.1–2 |

The CSR's subject, its SAN (including any ApplicationUri it names) and its requested extensions are ignored. Every extension is built from ASN.1 objects. OpenSSL configuration strings are never used, so no record value is parsed as configuration.

## Accepted CSRs

- DER only, at most `GDS_MAX_CSR_SIZE`, with no trailing bytes.
- The CSR's signature must verify with its own key (proof of possession).
- CertificateType ApplicationCertificateType or RsaSha256ApplicationCertificateType needs an RSA key of 2048 to 4096 bits.
- EccNistP256ApplicationCertificateType needs a P-256 key, EccNistP384ApplicationCertificateType a P-384 key (§7.8.4.11, §7.8.4.12); each is signed by the issuing CA on its curve (below).
- RsaMinApplicationCertificateType, Brainpool and Curve25519/448 return Bad_NotSupported. RsaMin belongs to the deprecated Basic128Rsa15 and Basic256 profiles; Elias chose RSA, P-256 and P-384 for 1.0 (2026-11-09).

## The CA itself

- **Key:** created on first start, RSA `caKeyBits` (default 3072, decision G6; within the RsaSha256 range of 2048 to 4096).
  - Always stored as encrypted PKCS#8 (G6) in `ca.key.pem` with mode 0600: PBES2, PBKDF2-HMAC-SHA256 with 600,000 iterations, and AES-256-CBC.
  - The passphrase is required. It comes from systemd credentials, never from argv or the environment.
  - Written atomically through a secure-heap buffer.
- **Certificate:** `ca.der`, self-signed.
  - Validity is `caLifetimeDays`, default 10 years.
  - basicConstraints cA TRUE (critical); keyUsage keyCertSign, cRLSign and digitalSignature (critical).
- **CRL:** `ca.crl`, v2, with a CRL number and the authority key id.
  - Valid for `crlLifetimeDays` (default 30).
  - Reissued with the next number when it is within a day of nextUpdate.
  - A CRL on disk is used only if this CA signed it.
- **Recovery:**
  - A key without a certificate (a crash between the two writes) gets a new certificate.
  - A certificate without its key is refused (`GDS_ESTATE`), never replaced by a new CA.

The defaults are Elias's decision G6: CA RSA 3072 with SHA-256 for 10 years, application certificates for 1 year, all configurable. They are not values the specification requires.

## ECC: one issuing CA per curve

The ECC SecurityPolicy profiles fix the curve of the issuing CA, not only the leaf's. For example, CertificateKeyAlgorithm_ECC-nistP256 in SecurityPolicy [ECC-B] ECC-nistP256 (OPC 10000-7, profile `http://opcfoundation.org/UA/SecurityPolicy#ECC_nistP256`) says: "An end entity Certificate shall use P-256. A CA that issues end entity Certificates shall use P-256." The signature algorithm is ECDSA with SHA-256, or SHA-384 above 256 bits. The ECC-brainpoolP256r1 profile has the same rule for its curve. So the RSA CA above cannot sign an ECC application certificate: each ECC CertificateType needs an issuing CA on its own curve.

OpenGDS 1.0 issues RSA, P-256 and P-384 (Elias, 2026-11-09). Both the signer and opengdsd do.

- **Signer:** one CA per key algorithm. RSA stays in `ca_dir` as today. P-256 and P-384 each have a subdirectory with the same layout, `ca_dir/nistP256/` and `ca_dir/nistP384/`, created on first start:
  - `ca.key.pem`: encrypted PKCS#8 under the same passphrase (G6).
  - `ca.der`: self-signed with ECDSA (SHA-256 for P-256, SHA-384 for P-384); keyUsage keyCertSign, cRLSign and digitalSignature; CN with " P-256" or " P-384" appended.
  - `ca.crl`: its own CRL with its own CRL numbers.
  - A key file of the wrong kind or curve is refused (`GDS_ESTATE`).
- **Dispatch:** SIGN_CSR and NEW_KEY_PAIR choose the CA by the request's CertificateType, which the signer reads from the store. GET_CHAIN, ISSUE_CRL and REVOKE carry an optional issuer byte; without it they mean RSA, as before. A REVOKE still needs a serial that the store marks revoked. CA backends of ABI 4 offer `get_issuer_cert`, `get_issuer_crl` and `revoke_issuer`; older backends have the RSA issuer only.
- **Leaves:** the same fields as the RSA table, with these differences: keyUsage is digitalSignature only (Part 6 §6.2.2, Table 50: "For ECC keys, the keyUsage shall include digitalSignature"), and the signature is ecdsa-with-SHA256 (P-256) or ecdsa-with-SHA384 (P-384). The CSR key must be on the type's curve: §7.8.4.11 says "They shall have an ECC nistP256 Public Key".
- **opengdsd:** DefaultApplicationGroup.CertificateTypes lists RsaSha256, then EccNistP256 and EccNistP384 when the CA slot has their issuers (a third-party CA backend before ABI 4 offers RSA only). StartSigningRequest and StartNewKeyPairRequest accept exactly those types, others get Bad_InvalidArgument. The trust list starts with every issuing CA's certificate and CRL, in the order RSA, P-256, P-384; Write and AddCertificate drop copies of them and RemoveCertificate refuses them. FinishRequest (and `gds_server_sign_request`) returns the issuer that matches the request's type. CheckRevocationStatus finds the issuer by name and checks the signature and CRL of that issuer. RevokeCertificate puts the serial on the CRL of the certificate's issuer, and UnregisterApplication on the CRL of each certificate's type.

## AccessToken signing key

The AuthorizationService (docs/opengdsd.md, "AccessTokens") signs its JWTs with a key that the CA backend holds, so it can sit in an HSM like the CA keys (Elias, 2026-11-09). CA backends of ABI 5 offer `token_chain` and `token_sign`; earlier backends have no token key, and opengdsd then refuses to start with `authorization_service = true`.

- **Files:** `ca_dir/token/token.key.pem` (RSA 2048, encrypted PKCS#8 under the CA passphrase) and `ca_dir/token/token.der`, both made on first use.
- **Certificate:** issued by the RSA CA. CN is the CA's CN followed by " AuthorizationService", O as configured, subjectAltName URI = the ServiceUri, keyUsage digitalSignature only, basicConstraints cA false, the leaf lifetime of the CA. It is not stored in the directory. It is issued again with the same key when the ServiceUri changes, the RSA CA changes, or fewer than 30 days remain.
- **Signer operations:** TOKEN_CHAIN (6) carries the ServiceUri and returns the token certificate followed by the RSA CA certificate. TOKEN_SIGN (7) carries a JWS signing input and returns the RS256 signature. The signer refuses any input that is not base64url header, '.', base64url payload with a header that starts `{"alg":"RS256"`, so the key cannot be used to sign certificates, CRLs or anything else.

## Plugin hooks (UASM asks)

- `pre_sign` (issue #13): optional. It is called right before every signature with the operation, the store's request id and a borrowed view of the record. A refusal leaves no certificate and no store change, and `GDS_ESTATE` maps to Bad_InvalidState.
- `pluginFd` (issue #12): an optional pre-connected socket that the signer hands to its CA plugin. The signer never reads from it.
- `gds_server_revoke_serial` (A23, `gds_plugin.h`): puts a serial that the store already marks revoked on the issuing CA's CRL, chosen by the certificate's issuer name, by its certificate type, or, with neither, on every issuer's CRL. UASM uses it for certificates that old nodes issued after a forced new primary and that the new primary never recorded. The signer still revokes only what the store marks revoked.
