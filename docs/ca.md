# OpenGDS CA: what goes into a certificate

The built-in CA backend (`src/ca/ca_openssl.c`) issues application instance certificates for StartSigningRequest. It runs inside `opengds-signer` (decision G1). Every field comes from the registered application record or from the CA configuration. From the CSR, only the public key is used, and only after the CSR's signature verifies with that key (decision G5; OPC 10000-12 §7.9.4).

## Issued application certificate

| Field | Value | Source |
|---|---|---|
| Version | v3 | RFC 5280 |
| Serial number | 20 random bytes, positive, non-zero | RFC 5280 §4.1.2.2 |
| Signature | sha256WithRSAEncryption | RsaSha256ApplicationCertificateType |
| Subject | `CN` = first ApplicationName of the record, cut to 64 bytes at a UTF-8 boundary; `O` = configured organization | record, config |
| Validity | from now minus 5 minutes (clock skew) to now plus `leafLifetimeDays` (default 365), never past the CA's notAfter | config |
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
- RsaMinApplicationCertificateType and the ECC types return Bad_NotSupported. RsaMin belongs to the deprecated Basic128Rsa15 and Basic256 profiles. ECC issuance comes later.

## The CA itself

- **Key:** created on first start, RSA `caKeyBits` (default 3072, within the RsaSha256 range of 2048 to 4096).
  - Stored as PKCS#8 PEM in `ca.key.pem` with mode 0600.
  - Encrypted with AES-256 when a passphrase is configured.
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

The lifetimes are configuration defaults chosen for OpenGDS. They are not values the specification requires.

## Plugin hooks (UASM asks)

- `pre_sign` (issue #13): optional. It is called right before every signature with the operation, the store's request id and a borrowed view of the record. A refusal leaves no certificate and no store change, and `GDS_ESTATE` maps to Bad_InvalidState.
- `pluginFd` (issue #12): an optional pre-connected socket that the signer hands to its CA plugin. The signer never reads from it.
