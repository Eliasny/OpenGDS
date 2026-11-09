/* OpenGDS push - KeyCredentials to a managed Server (OPC 10000-12 v1.05.07
 * §8.4, §8.6).
 * SPDX-License-Identifier: MPL-2.0 */
#include "push_keycred.h"

#include <openssl/err.h>
#include <openssl/x509.h>

#include <string.h>

#include "common/enc_secret.h"
#include "common/limits.h"
#include "common/ua_args.h"
#include "common/banned.h"

/* The policy asked for first: OAEP-SHA256 (12 §8.6.6 lets the Server revise it) */
#define REQUESTED_POLICY GDS_POLICY_AES256_RSAPSS

const char *push_kc_step_name(push_kc_step s) {
    switch(s) {
    case PUSH_KC_STEP_NONE: return "none";
    case PUSH_KC_STEP_FIND: return "find the KeyCredentialConfiguration Object";
    case PUSH_KC_STEP_CREATE: return "CreateCredential";
    case PUSH_KC_STEP_ISSUE: return "issue the credential";
    case PUSH_KC_STEP_KEY: return "GetEncryptingKey";
    case PUSH_KC_STEP_ENCRYPT: return "encrypt the secret";
    case PUSH_KC_STEP_UPDATE: return "UpdateCredential";
    case PUSH_KC_STEP_DELETE: return "DeleteCredential";
    default: return "?";
    }
}

static gds_status failed(push_kc_report *rep, push_kc_step step, UA_StatusCode r) {
    rep->failedStep = step;
    rep->failedCode = r;
    return GDS_EREMOTE;
}

/* Is der exactly one DER certificate? */
static bool is_cert(const gds_buf *der) {
    if(!der->len || der->len > GDS_MAX_CERT_SIZE)
        return false;
    const unsigned char *p = der->data;
    X509 *x = d2i_X509(NULL, &p, (long)der->len);
    bool ok = x && p == der->data + der->len;
    X509_free(x);
    ERR_clear_error();
    return ok;
}

/* Step 1: the Object for the ResourceUri, made if missing */
static gds_status object(UA_Client *c, const push_kc_job *job, UA_NodeId *obj,
                         push_kc_report *rep) {
    UA_StatusCode r = gdsc_kc_config_find(c, job->resourceUri, obj);
    if(r == UA_STATUSCODE_GOOD)
        return GDS_OK;
    if(r != UA_STATUSCODE_BADNOTFOUND)
        return failed(rep, PUSH_KC_STEP_FIND, r);
    r = gdsc_kc_config_create(c, job->name, job->resourceUri, job->profileUri, job->endpointUrls,
                              job->endpointUrlsN, obj);
    if(r != UA_STATUSCODE_GOOD)
        return failed(rep, PUSH_KC_STEP_CREATE, r);
    rep->created = true;
    return GDS_OK;
}

/* Steps 3 and 4: the secret as an RsaEncryptedSecret for the Server */
static gds_status encrypt(UA_Client *c, const push_kc_job *job, const UA_NodeId *obj,
                          const gds_buf *secret, gds_buf *blob, char thumb[GDS_SHA1_HEX],
                          push_kc_report *rep) {
    gds_buf key = {0};
    UA_StatusCode r =
        gdsc_kc_config_key(c, obj, rep->credentialId, REQUESTED_POLICY, &key, rep->policy);
    if(r != UA_STATUSCODE_GOOD)
        return failed(rep, PUSH_KC_STEP_KEY, r);
    const gds_buf *cert = is_cert(&key) ? &key : job->serverCert;
    gds_status s = GDS_EUNSUPPORTED;
    if(!gds_enc_secret_policy_ok(rep->policy, strlen(rep->policy))) {
        r = UA_STATUSCODE_BADSECURITYPOLICYREJECTED; /* ECC or RSA-DH: not supported here */
    } else if(!cert || !cert->len) {
        r = UA_STATUSCODE_BADCERTIFICATEINVALID;
    } else {
        s = gds_sha1_hex(cert, thumb);
        if(s == GDS_OK)
            s = gds_enc_secret_rsa(rep->policy, strlen(rep->policy), cert, secret, blob);
        r = s == GDS_OK ? UA_STATUSCODE_GOOD : UA_STATUSCODE_BADCERTIFICATEINVALID;
    }
    gds_buf_free(&key);
    return r == UA_STATUSCODE_GOOD ? GDS_OK : failed(rep, PUSH_KC_STEP_ENCRYPT, r);
}

gds_status push_keycred_run(UA_Client *c, const push_kc_job *job, push_kc_report *rep) {
    memset(rep, 0, sizeof(*rep));
    if(!c || !job || !job->name || !job->resourceUri || !job->profileUri || !job->issue)
        return GDS_EINVAL;
    UA_NodeId obj;
    UA_NodeId_init(&obj);
    gds_status s = object(c, job, &obj, rep);
    gds_buf secret = {0}, blob = {0};
    char thumb[GDS_SHA1_HEX] = "";
    if(s == GDS_OK) {
        s = job->issue(job->issueCtx, rep->credentialId, &secret);
        if(s != GDS_OK)
            (void)failed(rep, PUSH_KC_STEP_ISSUE, gds_status_to_ua(s));
    }
    if(s == GDS_OK)
        s = encrypt(c, job, &obj, &secret, &blob, thumb, rep);
    gds_buf_free_secret(&secret);
    if(s == GDS_OK) {
        UA_StatusCode r =
            gdsc_kc_config_update(c, &obj, rep->credentialId, &blob, thumb, rep->policy);
        s = r == UA_STATUSCODE_GOOD ? GDS_OK : failed(rep, PUSH_KC_STEP_UPDATE, r);
        rep->updated = r == UA_STATUSCODE_GOOD;
    }
    gds_buf_free(&blob);
    UA_NodeId_clear(&obj);
    return s;
}

gds_status push_keycred_delete(UA_Client *c, const char *resourceUri, push_kc_report *rep) {
    memset(rep, 0, sizeof(*rep));
    if(!c || !resourceUri)
        return GDS_EINVAL;
    UA_NodeId obj;
    UA_StatusCode r = gdsc_kc_config_find(c, resourceUri, &obj);
    if(r != UA_STATUSCODE_GOOD)
        return failed(rep, PUSH_KC_STEP_FIND, r);
    r = gdsc_kc_config_id(c, &obj, rep->credentialId);
    if(r == UA_STATUSCODE_GOOD)
        r = gdsc_kc_config_delete(c, &obj);
    UA_NodeId_clear(&obj);
    if(r != UA_STATUSCODE_GOOD)
        return failed(rep, PUSH_KC_STEP_DELETE, r);
    rep->deleted = true;
    return GDS_OK;
}
