/* OpenGDS - JSON Web Tokens for the AuthorizationService (OPC 10000-12
 * §9.6, OPC 10000-6 §6.5.2): base64url, the claims of Table 56, the JWS
 * compact serialization (IETF RFC 7515, RFC 7519) and a signer that holds
 * a private key.
 * SPDX-License-Identifier: MPL-2.0 */
#ifndef OPENGDS_GDS_JWT_H
#define OPENGDS_GDS_JWT_H

#include <stddef.h>
#include <stdint.h>

#include "common/buf.h"
#include "common/compiler.h"
#include "common/errors.h"

#define GDS_JWT_THUMBPRINT 32 /* SHA-256, x5t#S256 (RFC 7515 §4.1.8, RFC 8705 §3.1) */
#define GDS_JWT_MAX_ROLES 64

/* Signs data (the JWS signing input) for the alg it was made for: the
 * signature as JWS wants it (RSASSA-PKCS1-v1_5 bytes, or R || S for
 * ECDSA, RFC 7518 §3.4). */
typedef gds_status (*gds_jwt_sign_fn)(void *ctx, const uint8_t *data, size_t len, gds_buf *sig);

typedef struct {
    const char *iss;  /* the ServiceUri (Part 6 Table 56) */
    const char *sub;  /* unique within iss */
    const char *aud;  /* the ResourceId */
    const char *jti;  /* a unique token id (RFC 7519 §4.1.7) */
    int64_t iat, nbf, exp; /* seconds since 1970 */
    const char *const *roles;
    size_t nRoles;
    /* cnf {"x5t#S256": ...}: only the client with this certificate may use
     * the token (Part 6 Table 56, RFC 8705 §3.1); NULL leaves it out */
    const uint8_t *cnfThumbprint;
} gds_jwt_claims;

/* base64url without padding (RFC 7515 §2), NUL-terminated in out. */
GDS_MUST_CHECK gds_status gds_b64url(const uint8_t *in, size_t n, gds_buf *out);
/* The reverse; GDS_EINVAL for a character outside the alphabet or padding. */
GDS_MUST_CHECK gds_status gds_b64url_decode(const char *in, size_t n, gds_buf *out);

/* header.payload.signature, NUL-terminated in out. alg is the JWS "alg"
 * (RS256, ES256, ES384); x5t is the signing certificate's SHA-256
 * thumbprint, so a server that holds several ServiceCertificates finds the
 * right one. */
GDS_MUST_CHECK gds_status gds_jwt_make(const char *alg, const uint8_t x5t[GDS_JWT_THUMBPRINT],
                                       const gds_jwt_claims *c, gds_jwt_sign_fn sign,
                                       void *signCtx, gds_buf *out);

/* An in-process signer from a DER private key (RSA, or ECDSA on P-256 or
 * P-384); *alg is the JWS alg it signs with. Free with gds_jwt_key_free. */
typedef struct gds_jwt_key gds_jwt_key;
GDS_MUST_CHECK gds_status gds_jwt_key_new(const gds_buf *der, gds_jwt_key **out,
                                          const char **alg);
void gds_jwt_key_free(gds_jwt_key *k);
/* A gds_jwt_sign_fn; ctx is the gds_jwt_key. */
GDS_MUST_CHECK gds_status gds_jwt_key_sign(void *ctx, const uint8_t *data, size_t len,
                                           gds_buf *sig);

#endif
