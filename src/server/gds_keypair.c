/* OpenGDS - the secrets of StartNewKeyPairRequest (OPC 10000-12 §7.9.4,
 * §7.9.5), kept in opengdsd memory only.
 *
 * The PrivateKeyPassword "shall not persist" and the generated key leaves
 * the signer only encrypted under it (PFX, or encrypted PEM when a password
 * is given). Neither is written to the store: the request row has no CSR,
 * which marks it as a key pair request, and this table holds the format,
 * the password until the key is generated, and then the key until
 * FinishRequest delivers it. After a restart or a switchover the entry is
 * gone, the request fails with Bad_RequestNotAllowed and the client starts
 * again (§7.9.5). An entry not collected within GDS_KEYPAIR_TTL is dropped.
 * kpLock is a leaf lock; every buffer is wiped when released.
 * SPDX-License-Identifier: MPL-2.0 */
#include <string.h>

#include "gds_internal.h"
#include "common/banned.h"

static gds_kp_entry *find(gds_server *s, const UA_Guid *id) {
    for(size_t i = 0; i < GDS_MAX_KEYPAIR_REQUESTS; i++)
        if(s->kp[i].used && UA_Guid_equal(&s->kp[i].id, id))
            return &s->kp[i];
    return NULL;
}

static void release(gds_kp_entry *e) {
    gds_buf_free_secret(&e->password);
    gds_buf_free_secret(&e->key);
    memset(e, 0, sizeof(*e));
}

static void expire(gds_server *s, UA_DateTime now) {
    for(size_t i = 0; i < GDS_MAX_KEYPAIR_REQUESTS; i++)
        if(s->kp[i].used && now - s->kp[i].created > GDS_KEYPAIR_TTL)
            release(&s->kp[i]);
}

gds_status gds_kp_add(gds_server *s, const UA_Guid *id, gds_ca_key_format format,
                      const UA_String *password) {
    gds_kp_entry *slot = NULL;
    UA_DateTime now = UA_DateTime_nowMonotonic();
    gds_status r = GDS_OK;
    pthread_mutex_lock(&s->kpLock);
    expire(s, now);
    for(size_t i = 0; i < GDS_MAX_KEYPAIR_REQUESTS && !slot; i++)
        if(!s->kp[i].used)
            slot = &s->kp[i];
    if(!slot)
        r = GDS_ETOOBIG; /* the method answers Bad_ServerTooBusy */
    else if(password->length > 0)
        r = gds_buf_dup(password->data, password->length, &slot->password);
    if(r == GDS_OK) {
        slot->used = true;
        slot->id = *id;
        slot->format = format;
        slot->created = now;
    }
    pthread_mutex_unlock(&s->kpLock);
    return r;
}

gds_status gds_kp_password(gds_server *s, const UA_Guid *id, gds_ca_key_format *format,
                           gds_buf *password) {
    memset(password, 0, sizeof(*password));
    pthread_mutex_lock(&s->kpLock);
    gds_kp_entry *e = find(s, id);
    gds_status r = e && !e->ready ? GDS_OK : GDS_ENOTFOUND;
    if(r == GDS_OK) {
        *format = e->format;
        if(e->password.len > 0)
            r = gds_buf_dup(e->password.data, e->password.len, password);
    }
    pthread_mutex_unlock(&s->kpLock);
    return r;
}

gds_status gds_kp_set_key(gds_server *s, const UA_Guid *id, gds_buf *key) {
    pthread_mutex_lock(&s->kpLock);
    gds_kp_entry *e = find(s, id);
    gds_status r = e && !e->ready ? GDS_OK : GDS_ENOTFOUND;
    if(r == GDS_OK) {
        gds_buf_free_secret(&e->password); /* §7.9.4: discarded once the key exists */
        e->key = *key;
        e->ready = true;
        memset(key, 0, sizeof(*key));
    }
    pthread_mutex_unlock(&s->kpLock);
    return r;
}

gds_status gds_kp_take_key(gds_server *s, const UA_Guid *id, gds_buf *key) {
    memset(key, 0, sizeof(*key));
    pthread_mutex_lock(&s->kpLock);
    gds_kp_entry *e = find(s, id);
    gds_status r = e && e->ready ? GDS_OK : GDS_ENOTFOUND;
    if(r == GDS_OK) {
        *key = e->key;
        memset(&e->key, 0, sizeof(e->key));
        release(e);
    }
    pthread_mutex_unlock(&s->kpLock);
    return r;
}

void gds_kp_drop(gds_server *s, const UA_Guid *id) {
    pthread_mutex_lock(&s->kpLock);
    gds_kp_entry *e = find(s, id);
    if(e)
        release(e);
    pthread_mutex_unlock(&s->kpLock);
}

void gds_kp_free(gds_server *s) {
    for(size_t i = 0; i < GDS_MAX_KEYPAIR_REQUESTS; i++)
        release(&s->kp[i]);
}
