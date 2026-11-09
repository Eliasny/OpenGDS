/* OpenGDS - the RsaEncryptedSecret format (OPC 10000-4 §7.40.2.3 and
 * §7.40.2.4), used to hand a KeyCredential secret to its owner: the GDS's
 * FinishRequest (OPC 10000-12 §8.5.6) and the push of a credential with
 * UpdateCredential (§8.6.7).
 *
 * Layout (UA Binary): TypeId (NodeId i=17545, the RsaEncryptedSecret
 * DataType), EncodingMask (1), Length (bytes after this field), the
 * SecurityPolicyUri, Certificate (the SHA1 of the receiver's DER
 * certificate), SigningTime, KeyDataLength, the KeyData (SigningKey,
 * EncryptingKey, InitializationVector as ByteStrings) encrypted with the
 * receiver's RSA public key, then the payload (Nonce, Secret, padding,
 * PaddingSize UInt16) encrypted with the symmetric algorithm, then the
 * HMAC of everything before it.
 *
 * Policies: the RSA SecurityPolicies of OPC 10000-7 that are not
 * deprecated: Basic256Sha256 and Aes128_Sha256_RsaOaep (RSA-OAEP with
 * SHA1), Aes256_Sha256_RsaPss (RSA-OAEP with SHA256). ECC and RSA-DH
 * policies need an ephemeral key exchange and are refused.
 * SPDX-License-Identifier: MPL-2.0 */
#ifndef OPENGDS_COMMON_ENC_SECRET_H
#define OPENGDS_COMMON_ENC_SECRET_H

#include <openssl/evp.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "buf.h"
#include "compiler.h"
#include "errors.h"

#define GDS_POLICY_BASIC256SHA256 "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256"
#define GDS_POLICY_AES128_RSAOAEP                                                         \
    "http://opcfoundation.org/UA/SecurityPolicy#Aes128_Sha256_RsaOaep"
#define GDS_POLICY_AES256_RSAPSS "http://opcfoundation.org/UA/SecurityPolicy#Aes256_Sha256_RsaPss"

/* The largest secret this module protects. */
#define GDS_MAX_SECRET ((size_t)4096)
/* The SHA1 thumbprint of a certificate as text: 40 hex digits + NUL. */
#define GDS_SHA1_HEX 41

/* Is uri (len bytes) one of the policies above? */
bool gds_enc_secret_policy_ok(const char *uri, size_t len);

/* Can a secret be encrypted for certDer under policy? GDS_EUNSUPPORTED:
 * not a policy above; GDS_EINVAL: not a DER certificate; GDS_ESTATE: its
 * key is not RSA or not a size the policy allows. */
GDS_MUST_CHECK gds_status gds_enc_secret_check(const char *policy, size_t policyLen,
                                               const gds_buf *certDer);

/* Encrypts secret for the holder of the RSA certificate certDer under
 * policy (len bytes). GDS_EUNSUPPORTED: not a policy above; GDS_EINVAL: not
 * an RSA certificate, a key the policy does not allow, or a bad secret
 * size; GDS_ECRYPTO: OpenSSL refused. *out is the encoded secret. */
GDS_MUST_CHECK gds_status gds_enc_secret_rsa(const char *policy, size_t policyLen,
                                             const gds_buf *certDer, const gds_buf *secret,
                                             gds_buf *out);

/* The reverse, for the receiver: key is the private key of certDer.
 * Checks the type, the policy (must be `policy`), the certificate hash,
 * the signature and the padding. GDS_EINVAL for anything that does not
 * verify. *secret is wiped by gds_buf_free_secret. */
GDS_MUST_CHECK gds_status gds_enc_secret_rsa_decrypt(const char *policy, size_t policyLen,
                                                     const gds_buf *certDer, EVP_PKEY *key,
                                                     const gds_buf *blob, gds_buf *secret);

/* The SHA1 of certDer as upper-case hex (FinishRequest's
 * CertificateThumbprint, §8.5.6). */
GDS_MUST_CHECK gds_status gds_sha1_hex(const gds_buf *certDer, char out[GDS_SHA1_HEX]);

#endif
