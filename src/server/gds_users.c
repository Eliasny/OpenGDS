/* OpenGDS - OPC 10000-18 §5 User Management: the UserManagement Object
 * under ServerConfiguration (§5.3) with AddUser, ModifyUser, RemoveUser
 * and ChangePassword (§5.2.5 - §5.2.8).
 *
 * Managed users live in the store (schema 6) as users-file credentials
 * (PBKDF2-SHA256, the same hashing as gdsadm hash-password); a password
 * never reaches the store, the log or an audit event. They get Roles only
 * from mapping rules (UserName criteria, gds_roles.c). The users of the
 * users file are listed too, with NoDelete and NoChangeByUser: they change
 * in the file only, so RemoveUser, ModifyUser and ChangePassword refuse
 * them with Bad_NotSupported.
 *
 * PasswordOptions: disable, NoDelete, NoChangeByUser and descriptions are
 * supported; MustChangePassword is not (ActivateSession would have to
 * answer Good_PasswordChangeRequired), so that bit is refused with
 * Bad_NotSupported. PasswordLength: `password_min_length` (default 15,
 * NIST SP 800-63B-4 §3.1.1.2) to 256 characters.
 *
 * Disabling or removing a user closes its sessions (§5.2.6, §5.2.7). Every
 * call is audited as an AuditUpdateMethodEventType with the passwords
 * blanked out of its InputArguments.
 * SPDX-License-Identifier: MPL-2.0 */
#include <open62541/nodeids.h>
#include <openssl/crypto.h>

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "gds_internal.h"
#include "gds_roles.h"
#include "common/banned.h"

/* Copy a C string into a UA_String */
static UA_StatusCode cs_copy(const char *v, UA_String *out) {
    UA_String tmp = UA_STRING((char *)(uintptr_t)v);
    return UA_String_copy(&tmp, out);
}

#define SUPPORTED_CONFIG (GDS_USER_NO_DELETE | GDS_USER_DISABLED | GDS_USER_NO_CHANGE_BY_USER)
#define PASSWORD_OPTIONS                                                                    \
    (GDS_PWOPT_SUPPORT_DISABLE_USER | GDS_PWOPT_SUPPORT_DISABLE_DELETE |                    \
     GDS_PWOPT_SUPPORT_NO_CHANGE | GDS_PWOPT_SUPPORT_DESCRIPTION)
#define FILE_USER_CONFIG (GDS_USER_NO_DELETE | GDS_USER_NO_CHANGE_BY_USER)
#define FILE_USER_DESCRIPTION "users file"

static pthread_mutex_t ulock = PTHREAD_MUTEX_INITIALIZER;
static gds_store_user *users;
static size_t nUsers;
static const gds_users *fileUsers;
static unsigned minLength = GDS_PASSWORD_DEFAULT_MIN_LENGTH;

void gds_users_reset(void) {
    pthread_mutex_lock(&ulock);
    if(users)
        OPENSSL_cleanse(users, nUsers * sizeof(*users));
    free(users);
    users = NULL;
    nUsers = 0;
    fileUsers = NULL;
    pthread_mutex_unlock(&ulock);
}

/* ulock held */
static gds_store_user *find(const char *name) {
    for(size_t i = 0; i < nUsers; i++)
        if(strcmp(users[i].name, name) == 0)
            return &users[i];
    return NULL;
}

typedef struct {
    gds_store_user *arr;
    size_t n;
    gds_status st;
} load_ctx;

static bool load_cb(void *ctx, const gds_store_user *u) {
    load_ctx *l = ctx;
    if(l->n == GDS_MAX_MANAGED_USERS)
        return false;
    l->arr[l->n++] = *u;
    return true;
}

void gds_users_reload(gds_server *s) {
    load_ctx l = {calloc(GDS_MAX_MANAGED_USERS, sizeof(gds_store_user)), 0, GDS_OK};
    if(!l.arr)
        return;
    gds_lock(s);
    gds_status st = gds_store_user_scan(s->store, load_cb, &l);
    gds_unlock(s);
    if(st != GDS_OK && st != GDS_EUNSUPPORTED) {
        fprintf(stderr, "opengds: reading the managed users failed: %s\n", gds_status_name(st));
        OPENSSL_cleanse(l.arr, GDS_MAX_MANAGED_USERS * sizeof(gds_store_user));
        free(l.arr);
        return;
    }
    pthread_mutex_lock(&ulock);
    if(users)
        OPENSSL_cleanse(users, nUsers * sizeof(*users));
    free(users);
    users = l.arr;
    nUsers = l.n;
    pthread_mutex_unlock(&ulock);
}

bool gds_musers_login(const UA_String *name, const UA_ByteString *password) {
    char cred[GDS_MAX_USER_CREDENTIAL + 1] = "";
    char n[GDS_MAX_STORE_USER_NAME + 1];
    bool known = false;
    if(name->length <= GDS_MAX_STORE_USER_NAME && name->length > 0 &&
       !memchr(name->data, 0, name->length)) {
        memcpy(n, name->data, name->length);
        n[name->length] = '\0';
        pthread_mutex_lock(&ulock);
        const gds_store_user *u = find(n);
        /* §5.2.3: a disabled user behaves like one that does not exist */
        if(u && !(u->config & GDS_USER_DISABLED)) {
            memcpy(cred, u->credential, sizeof(cred));
            known = true;
        }
        pthread_mutex_unlock(&ulock);
    }
    /* an unknown user costs one PBKDF2 like a known one */
    bool ok = gds_password_verify(known ? cred : NULL, password) && known;
    OPENSSL_cleanse(cred, sizeof(cred));
    return ok;
}

/* ---- arguments ---- */

static bool str_arg(size_t n, const UA_Variant *in, size_t i, const UA_String **out) {
    if(i >= n || !UA_Variant_hasScalarType(&in[i], &UA_TYPES[UA_TYPES_STRING]))
        return false;
    *out = in[i].data;
    return true;
}

static bool u32_arg(size_t n, const UA_Variant *in, size_t i, UA_UInt32 *out) {
    if(i >= n || !UA_Variant_isScalar(&in[i]))
        return false;
    /* UserConfigurationMask is a UInt32 subtype; open62541 may hand it over
     * as either type */
    if(!in[i].type || in[i].type->typeKind != UA_DATATYPEKIND_UINT32 || !in[i].data)
        return false;
    *out = *(const UA_UInt32 *)in[i].data;
    return true;
}

static bool bool_arg(size_t n, const UA_Variant *in, size_t i, UA_Boolean *out) {
    if(i >= n || !UA_Variant_hasScalarType(&in[i], &UA_TYPES[UA_TYPES_BOOLEAN]))
        return false;
    *out = *(const UA_Boolean *)in[i].data;
    return true;
}

static UA_StatusCode count(size_t got, size_t want) {
    if(got < want)
        return UA_STATUSCODE_BADARGUMENTSMISSING;
    return got > want ? UA_STATUSCODE_BADTOOMANYARGUMENTS : UA_STATUSCODE_GOOD;
}

static bool name_ok(const UA_String *v, char *out) {
    if(v->length == 0 || v->length > GDS_MAX_USER_NAME)
        return false;
    for(size_t i = 0; i < v->length; i++) {
        char c = (char)v->data[i];
        if(!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
             c == '.' || c == '_' || c == '-' || c == '@'))
            return false;
    }
    memcpy(out, v->data, v->length);
    out[v->length] = '\0';
    return true;
}

/* §5.2.1 PasswordLength: characters, counted as UTF-8 code points */
static bool password_ok(const UA_String *pw) {
    if(pw->length == 0 || memchr(pw->data, 0, pw->length))
        return false;
    size_t chars = 0;
    for(size_t i = 0; i < pw->length; i++)
        if((pw->data[i] & 0xC0) != 0x80)
            chars++;
    return chars >= minLength && chars <= GDS_PASSWORD_MAX_LENGTH;
}

/* §5.2.3: Bad_ConfigurationError for MustChangePassword with
 * NoChangeByUser, Bad_NotSupported for bits OpenGDS does not offer */
static UA_StatusCode config_ok(UA_UInt32 c) {
    if((c & GDS_USER_MUST_CHANGE_PASSWORD) && (c & GDS_USER_NO_CHANGE_BY_USER))
        return UA_STATUSCODE_BADCONFIGURATIONERROR;
    return (c & ~SUPPORTED_CONFIG) ? UA_STATUSCODE_BADNOTSUPPORTED : UA_STATUSCODE_GOOD;
}

static bool desc_ok(const UA_String *d, char *out) {
    if(d->length > GDS_MAX_USER_DESCRIPTION || (d->length && memchr(d->data, 0, d->length)))
        return false;
    if(d->length)
        memcpy(out, d->data, d->length);
    out[d->length] = '\0';
    return true;
}

static UA_StatusCode hash(const UA_String *pw, char *cred) {
    gds_status st = gds_password_hash(pw->data, pw->length, GDS_PBKDF2_DEFAULT_ITER, cred,
                                      GDS_MAX_USER_CREDENTIAL + 1);
    return st == GDS_OK ? UA_STATUSCODE_GOOD : UA_STATUSCODE_BADINTERNALERROR;
}

static bool is_self(const void *sessionContext, const char *name) {
    const gds_session *ss = sessionContext;
    return ss && ss->token == GDS_TOKEN_USERNAME && ss->managedUser &&
           strcmp(ss->user, name) == 0;
}

/* The arguments for the audit event, with the passwords (indexes in pw)
 * left empty. */
static void audit(gds_server *s, const void *sessionContext, const UA_NodeId *methodId,
                  const UA_Variant *in, size_t n, const size_t *pw, size_t nPw,
                  UA_StatusCode res) {
    UA_Variant args[8];
    if(n > GDS_ARRAY_SIZE(args))
        n = GDS_ARRAY_SIZE(args);
    UA_String blank = UA_STRING_NULL;
    for(size_t i = 0; i < n; i++) {
        args[i] = in[i];
        args[i].storageType = UA_VARIANT_DATA_NODELETE;
        for(size_t k = 0; k < nPw; k++)
            if(pw[k] == i)
                UA_Variant_setScalar(&args[i], &blank, &UA_TYPES[UA_TYPES_STRING]);
    }
    UA_NodeId source = UA_NODEID_NUMERIC(0, UA_NS0ID_USERMANAGEMENT);
    gds_roles_audit(s, sessionContext, UA_NS0ID_AUDITUPDATEMETHODEVENTTYPE, &source, methodId,
                    args, n, res);
}

/* ---- the methods ---- */

/* AddUser (UserName, Password, UserConfiguration, Description), §5.2.5 */
static UA_StatusCode add_user(gds_server *s, const void *ctx, size_t n, const UA_Variant *in) {
    UA_StatusCode r = gds_roles_check_admin(s, ctx);
    const UA_String *name = NULL, *pw = NULL, *desc = NULL;
    UA_UInt32 config = 0;
    gds_store_user *u = calloc(1, sizeof(*u));
    if(!u)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    if(r == UA_STATUSCODE_GOOD)
        r = count(n, 4);
    if(r == UA_STATUSCODE_GOOD && (!str_arg(n, in, 0, &name) || !str_arg(n, in, 1, &pw) ||
                                   !u32_arg(n, in, 2, &config) || !str_arg(n, in, 3, &desc)))
        r = UA_STATUSCODE_BADTYPEMISMATCH;
    if(r == UA_STATUSCODE_GOOD && (!name_ok(name, u->name) || !desc_ok(desc, u->description)))
        r = UA_STATUSCODE_BADINVALIDARGUMENT;
    if(r == UA_STATUSCODE_GOOD && gds_users_find(gds_access_users(), u->name))
        r = UA_STATUSCODE_BADALREADYEXISTS;
    if(r == UA_STATUSCODE_GOOD) {
        pthread_mutex_lock(&ulock);
        if(find(u->name))
            r = UA_STATUSCODE_BADALREADYEXISTS;
        else if(nUsers >= GDS_MAX_MANAGED_USERS)
            r = UA_STATUSCODE_BADRESOURCEUNAVAILABLE;
        pthread_mutex_unlock(&ulock);
    }
    if(r == UA_STATUSCODE_GOOD)
        r = config_ok(config);
    if(r == UA_STATUSCODE_GOOD && !password_ok(pw))
        r = UA_STATUSCODE_BADOUTOFRANGE;
    if(r == UA_STATUSCODE_GOOD)
        r = hash(pw, u->credential);
    u->config = config;
    if(r == UA_STATUSCODE_GOOD) {
        gds_lock(s);
        gds_status st = gds_store_user_put(s->store, u, true);
        gds_unlock(s);
        r = gds_roles_store_status(st);
    }
    if(r == UA_STATUSCODE_GOOD) {
        pthread_mutex_lock(&ulock);
        gds_store_user *grown = realloc(users, (nUsers + 1) * sizeof(*users));
        if(grown) {
            users = grown;
            users[nUsers++] = *u;
        }
        pthread_mutex_unlock(&ulock);
        if(!grown)
            gds_users_reload(s);
    }
    OPENSSL_cleanse(u, sizeof(*u));
    free(u);
    return r;
}

/* Find a managed user by the name argument; Good, Bad_NotFound or
 * Bad_NotSupported (a users-file user). */
static UA_StatusCode target(const UA_String *name, gds_store_user *out) {
    if(!name_ok(name, out->name))
        return UA_STATUSCODE_BADNOTFOUND;
    if(gds_users_find(gds_access_users(), out->name))
        return UA_STATUSCODE_BADNOTSUPPORTED;
    pthread_mutex_lock(&ulock);
    const gds_store_user *u = find(out->name);
    if(u)
        *out = *u;
    pthread_mutex_unlock(&ulock);
    return u ? UA_STATUSCODE_GOOD : UA_STATUSCODE_BADNOTFOUND;
}

static UA_StatusCode replace(gds_server *s, const gds_store_user *u) {
    gds_lock(s);
    gds_status st = gds_store_user_put(s->store, u, false);
    gds_unlock(s);
    UA_StatusCode r = gds_roles_store_status(st);
    if(r == UA_STATUSCODE_GOOD) {
        pthread_mutex_lock(&ulock);
        gds_store_user *c = find(u->name);
        if(c)
            *c = *u;
        pthread_mutex_unlock(&ulock);
    }
    return r;
}

/* ModifyUser (UserName, ModifyPassword, Password, ModifyUserConfiguration,
 * UserConfiguration, ModifyDescription, Description), §5.2.6 */
static UA_StatusCode modify_user(gds_server *s, const UA_NodeId *sessionId, const void *ctx,
                                 size_t n, const UA_Variant *in) {
    UA_StatusCode r = gds_roles_check_admin(s, ctx);
    const UA_String *name = NULL, *pw = NULL, *desc = NULL;
    UA_Boolean modPw = false, modCfg = false, modDesc = false;
    UA_UInt32 config = 0;
    gds_store_user *u = calloc(1, sizeof(*u));
    if(!u)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    if(r == UA_STATUSCODE_GOOD)
        r = count(n, 7);
    if(r == UA_STATUSCODE_GOOD &&
       (!str_arg(n, in, 0, &name) || !bool_arg(n, in, 1, &modPw) || !str_arg(n, in, 2, &pw) ||
        !bool_arg(n, in, 3, &modCfg) || !u32_arg(n, in, 4, &config) ||
        !bool_arg(n, in, 5, &modDesc) || !str_arg(n, in, 6, &desc)))
        r = UA_STATUSCODE_BADTYPEMISMATCH;
    if(r == UA_STATUSCODE_GOOD)
        r = target(name, u);
    bool wasDisabled = (u->config & GDS_USER_DISABLED) != 0;
    if(r == UA_STATUSCODE_GOOD && modCfg)
        r = config_ok(config);
    if(r == UA_STATUSCODE_GOOD && modCfg && (config & GDS_USER_DISABLED) &&
       is_self(ctx, u->name))
        r = UA_STATUSCODE_BADINVALIDSELFREFERENCE;
    if(r == UA_STATUSCODE_GOOD && modPw && !password_ok(pw))
        r = UA_STATUSCODE_BADOUTOFRANGE;
    if(r == UA_STATUSCODE_GOOD && modDesc && !desc_ok(desc, u->description))
        r = UA_STATUSCODE_BADINVALIDARGUMENT;
    if(r == UA_STATUSCODE_GOOD && modPw)
        r = hash(pw, u->credential);
    if(r == UA_STATUSCODE_GOOD && modCfg)
        u->config = config;
    if(r == UA_STATUSCODE_GOOD && (modPw || modCfg || modDesc))
        r = replace(s, u);
    if(r == UA_STATUSCODE_GOOD && !wasDisabled && (u->config & GDS_USER_DISABLED))
        gds_access_close_user_sessions(s->ua, u->name, sessionId);
    OPENSSL_cleanse(u, sizeof(*u));
    free(u);
    return r;
}

/* RemoveUser (UserName), §5.2.7 */
static UA_StatusCode remove_user(gds_server *s, const UA_NodeId *sessionId, const void *ctx,
                                 size_t n, const UA_Variant *in) {
    UA_StatusCode r = gds_roles_check_admin(s, ctx);
    const UA_String *name = NULL;
    gds_store_user *u = calloc(1, sizeof(*u));
    if(!u)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    if(r == UA_STATUSCODE_GOOD)
        r = count(n, 1);
    if(r == UA_STATUSCODE_GOOD && !str_arg(n, in, 0, &name))
        r = UA_STATUSCODE_BADTYPEMISMATCH;
    if(r == UA_STATUSCODE_GOOD)
        r = target(name, u);
    if(r == UA_STATUSCODE_GOOD && (u->config & GDS_USER_NO_DELETE))
        r = UA_STATUSCODE_BADNOTSUPPORTED;
    if(r == UA_STATUSCODE_GOOD && is_self(ctx, u->name))
        r = UA_STATUSCODE_BADINVALIDSELFREFERENCE;
    if(r == UA_STATUSCODE_GOOD) {
        gds_lock(s);
        gds_status st = gds_store_user_delete(s->store, u->name);
        gds_unlock(s);
        r = gds_roles_store_status(st);
    }
    if(r == UA_STATUSCODE_GOOD) {
        pthread_mutex_lock(&ulock);
        gds_store_user *c = find(u->name);
        if(c) {
            size_t i = (size_t)(c - users);
            OPENSSL_cleanse(c, sizeof(*c));
            memmove(&users[i], &users[i + 1], (nUsers - i - 1) * sizeof(*users));
            nUsers--;
        }
        pthread_mutex_unlock(&ulock);
        gds_access_close_user_sessions(s->ua, u->name, sessionId);
    }
    OPENSSL_cleanse(u, sizeof(*u));
    free(u);
    return r;
}

/* ChangePassword (OldPassword, NewPassword), §5.2.8: the session's own
 * user, any Role, USERNAME token over an encrypted channel */
static UA_StatusCode change_password(gds_server *s, const void *ctx, size_t n,
                                     const UA_Variant *in) {
    const gds_session *ss = ctx;
    UA_StatusCode r = UA_STATUSCODE_GOOD;
    if(!ss || ss->securityMode != UA_MESSAGESECURITYMODE_SIGNANDENCRYPT)
        r = UA_STATUSCODE_BADSECURITYMODEINSUFFICIENT;
    else if(ss->token != GDS_TOKEN_USERNAME)
        r = UA_STATUSCODE_BADINVALIDSTATE;
    if(r == UA_STATUSCODE_GOOD)
        r = gds_refuse_on_standby(s);
    const UA_String *oldPw = NULL, *newPw = NULL;
    if(r == UA_STATUSCODE_GOOD)
        r = count(n, 2);
    if(r == UA_STATUSCODE_GOOD && (!str_arg(n, in, 0, &oldPw) || !str_arg(n, in, 1, &newPw)))
        r = UA_STATUSCODE_BADTYPEMISMATCH;
    gds_store_user *u = calloc(1, sizeof(*u));
    if(!u)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    if(r == UA_STATUSCODE_GOOD) {
        UA_String me = UA_STRING((char *)(uintptr_t)ss->user);
        r = ss->managedUser ? target(&me, u) : UA_STATUSCODE_BADNOTSUPPORTED;
    }
    if(r == UA_STATUSCODE_GOOD && (u->config & GDS_USER_NO_CHANGE_BY_USER))
        r = UA_STATUSCODE_BADNOTSUPPORTED;
    if(r == UA_STATUSCODE_GOOD && !gds_password_verify(u->credential, oldPw))
        r = UA_STATUSCODE_BADIDENTITYTOKENINVALID;
    if(r == UA_STATUSCODE_GOOD && UA_String_equal(oldPw, newPw))
        r = UA_STATUSCODE_BADALREADYEXISTS;
    if(r == UA_STATUSCODE_GOOD && !password_ok(newPw))
        r = UA_STATUSCODE_BADOUTOFRANGE;
    if(r == UA_STATUSCODE_GOOD)
        r = hash(newPw, u->credential);
    if(r == UA_STATUSCODE_GOOD)
        r = replace(s, u);
    OPENSSL_cleanse(u, sizeof(*u));
    free(u);
    return r;
}

static GDS_METHOD(m_add_user) {
    (void)server, (void)objectId, (void)objectContext, (void)outputSize, (void)output;
    gds_server *s = gds_ctx(methodContext);
    UA_StatusCode r = add_user(s, sessionContext, inputSize, input);
    static const size_t pw[] = {1};
    if(gds_server_role(s) != GDS_NODE_STANDBY)
        audit(s, sessionContext, methodId, input, inputSize, pw, 1, r);
    (void)sessionId;
    return r;
}

static GDS_METHOD(m_modify_user) {
    (void)server, (void)objectId, (void)objectContext, (void)outputSize, (void)output;
    gds_server *s = gds_ctx(methodContext);
    UA_StatusCode r = modify_user(s, sessionId, sessionContext, inputSize, input);
    static const size_t pw[] = {2};
    if(gds_server_role(s) != GDS_NODE_STANDBY)
        audit(s, sessionContext, methodId, input, inputSize, pw, 1, r);
    return r;
}

static GDS_METHOD(m_remove_user) {
    (void)server, (void)objectId, (void)objectContext, (void)outputSize, (void)output;
    gds_server *s = gds_ctx(methodContext);
    UA_StatusCode r = remove_user(s, sessionId, sessionContext, inputSize, input);
    if(gds_server_role(s) != GDS_NODE_STANDBY)
        audit(s, sessionContext, methodId, input, inputSize, NULL, 0, r);
    return r;
}

static GDS_METHOD(m_change_password) {
    (void)server, (void)objectId, (void)objectContext, (void)outputSize, (void)output;
    (void)sessionId;
    gds_server *s = gds_ctx(methodContext);
    UA_StatusCode r = change_password(s, sessionContext, inputSize, input);
    static const size_t pw[] = {0, 1};
    if(gds_server_role(s) != GDS_NODE_STANDBY)
        audit(s, sessionContext, methodId, input, inputSize, pw, 2, r);
    return r;
}

/* ---- the Properties ---- */

static UA_StatusCode read_users(UA_Server *server, const UA_NodeId *sessionId,
                                void *sessionContext, const UA_NodeId *nodeId, void *nodeContext,
                                UA_Boolean includeSourceTimeStamp, const UA_NumericRange *range,
                                UA_DataValue *value) {
    (void)server, (void)sessionId, (void)nodeId, (void)nodeContext, (void)includeSourceTimeStamp;
    if(range || !gds_roles_admin(sessionContext)) {
        value->hasStatus = true;
        value->status = range ? UA_STATUSCODE_BADINDEXRANGEINVALID
                              : UA_STATUSCODE_BADUSERACCESSDENIED;
        return UA_STATUSCODE_GOOD;
    }
    const UA_DataType *t = &UA_TYPES[UA_TYPES_USERMANAGEMENTDATATYPE];
    pthread_mutex_lock(&ulock);
    size_t nFile = fileUsers ? fileUsers->n : 0, n = nFile + nUsers;
    UA_UserManagementDataType *arr = n ? UA_Array_new(n, t) : UA_EMPTY_ARRAY_SENTINEL;
    UA_StatusCode r = arr ? UA_STATUSCODE_GOOD : UA_STATUSCODE_BADOUTOFMEMORY;
    for(size_t i = 0; i < n && r == UA_STATUSCODE_GOOD; i++) {
        bool file = i < nFile;
        const char *name = file ? fileUsers->users[i].name : users[i - nFile].name;
        const char *desc = file ? FILE_USER_DESCRIPTION : users[i - nFile].description;
        arr[i].userConfiguration = file ? FILE_USER_CONFIG : users[i - nFile].config;
        r = cs_copy(name, &arr[i].userName);
        if(r == UA_STATUSCODE_GOOD)
            r = cs_copy(desc, &arr[i].description);
    }
    pthread_mutex_unlock(&ulock);
    if(r != UA_STATUSCODE_GOOD) {
        if(arr && n)
            UA_Array_delete(arr, n, t);
        return r;
    }
    UA_Variant_setArray(&value->value, arr, n, t);
    value->hasValue = true;
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode bind(gds_server *s, UA_UInt32 id, UA_MethodCallback cb) {
    UA_NodeId m = UA_NODEID_NUMERIC(0, id);
    UA_StatusCode r = UA_Server_setMethodNodeCallback(s->ua, m, cb);
    if(r == UA_STATUSCODE_GOOD)
        r = UA_Server_setNodeContext(s->ua, m, s);
    if(r == UA_STATUSCODE_GOOD)
        gds_roles_mark_method(&m);
    return r;
}

/* open62541 v1.5.10 deletes ServerConfiguration/UserManagement at start
 * (ua_server_ns0.c). §5.2.8 wants it under its well-known NodeIds, so it is
 * added again with them; addNode_finish then leaves out the type's
 * children that are already there. */
typedef struct {
    const char *name;
    UA_UInt32 type;
} arg_def;

static UA_StatusCode add_method(UA_Server *ua, UA_UInt32 id, UA_UInt32 argsId, const char *name,
                                const arg_def *args, size_t n) {
    UA_Argument a[7];
    for(size_t i = 0; i < n; i++) {
        UA_Argument_init(&a[i]);
        a[i].name = UA_STRING((char *)(uintptr_t)args[i].name);
        a[i].dataType = UA_NODEID_NUMERIC(0, args[i].type);
        a[i].valueRank = UA_VALUERANK_SCALAR;
    }
    UA_MethodAttributes ma = UA_MethodAttributes_default;
    ma.displayName = UA_LOCALIZEDTEXT("", (char *)(uintptr_t)name);
    ma.executable = true;
    ma.userExecutable = true;
    return UA_Server_addMethodNodeEx(
        ua, UA_NODEID_NUMERIC(0, id), UA_NODEID_NUMERIC(0, UA_NS0ID_USERMANAGEMENT),
        UA_NODEID_NUMERIC(0, UA_NS0ID_HASCOMPONENT), UA_QUALIFIEDNAME(0, (char *)(uintptr_t)name),
        ma, NULL, n, a, UA_NODEID_NUMERIC(0, argsId), NULL, 0, NULL, UA_NODEID_NULL, NULL, NULL,
        NULL);
}

static UA_StatusCode add_prop(UA_Server *ua, UA_UInt32 id, const char *name, UA_UInt32 type,
                              UA_Int32 rank, const UA_Variant *initial) {
    UA_VariableAttributes va = UA_VariableAttributes_default;
    va.value = *initial;
    va.displayName = UA_LOCALIZEDTEXT("", (char *)(uintptr_t)name);
    va.dataType = UA_NODEID_NUMERIC(0, type);
    va.valueRank = rank;
    UA_UInt32 dims[1] = {0};
    if(rank == UA_VALUERANK_ONE_DIMENSION) {
        va.arrayDimensions = dims;
        va.arrayDimensionsSize = 1;
    }
    va.accessLevel = UA_ACCESSLEVELMASK_READ;
    return UA_Server_addVariableNode(
        ua, UA_NODEID_NUMERIC(0, id), UA_NODEID_NUMERIC(0, UA_NS0ID_USERMANAGEMENT),
        UA_NODEID_NUMERIC(0, UA_NS0ID_HASPROPERTY), UA_QUALIFIEDNAME(0, (char *)(uintptr_t)name),
        UA_NODEID_NUMERIC(0, UA_NS0ID_PROPERTYTYPE), va, NULL, NULL);
}

static UA_StatusCode create_user_management(UA_Server *ua) {
    static const arg_def addArgs[] = {{"UserName", UA_NS0ID_STRING},
                                      {"Password", UA_NS0ID_STRING},
                                      {"UserConfiguration", UA_NS0ID_USERCONFIGURATIONMASK},
                                      {"Description", UA_NS0ID_STRING}};
    static const arg_def modArgs[] = {{"UserName", UA_NS0ID_STRING},
                                      {"ModifyPassword", UA_NS0ID_BOOLEAN},
                                      {"Password", UA_NS0ID_STRING},
                                      {"ModifyUserConfiguration", UA_NS0ID_BOOLEAN},
                                      {"UserConfiguration", UA_NS0ID_USERCONFIGURATIONMASK},
                                      {"ModifyDescription", UA_NS0ID_BOOLEAN},
                                      {"Description", UA_NS0ID_STRING}};
    static const arg_def rmArgs[] = {{"UserName", UA_NS0ID_STRING}};
    static const arg_def cpArgs[] = {{"OldPassword", UA_NS0ID_STRING},
                                     {"NewPassword", UA_NS0ID_STRING}};
    UA_ObjectAttributes oa = UA_ObjectAttributes_default;
    oa.displayName = UA_LOCALIZEDTEXT("", "UserManagement");
    UA_NodeId um = UA_NODEID_NUMERIC(0, UA_NS0ID_USERMANAGEMENT);
    UA_StatusCode r = UA_Server_addNode_begin(
        ua, UA_NODECLASS_OBJECT, um, UA_NODEID_NUMERIC(0, UA_NS0ID_SERVERCONFIGURATION),
        UA_NODEID_NUMERIC(0, UA_NS0ID_HASCOMPONENT), UA_QUALIFIEDNAME(0, "UserManagement"),
        UA_NODEID_NUMERIC(0, UA_NS0ID_USERMANAGEMENTTYPE), &oa,
        &UA_TYPES[UA_TYPES_OBJECTATTRIBUTES], NULL, NULL);
    UA_Variant none, rangeV, optsV, textV;
    UA_Variant_setArray(&none, UA_EMPTY_ARRAY_SENTINEL, 0,
                        &UA_TYPES[UA_TYPES_USERMANAGEMENTDATATYPE]);
    UA_Range range = {0, 0};
    UA_Variant_setScalar(&rangeV, &range, &UA_TYPES[UA_TYPES_RANGE]);
    UA_UInt32 opts = 0;
    UA_Variant_setScalar(&optsV, &opts, &UA_TYPES[UA_TYPES_UINT32]);
    UA_LocalizedText text = UA_LOCALIZEDTEXT("", "");
    UA_Variant_setScalar(&textV, &text, &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]);
    if(r == UA_STATUSCODE_GOOD)
        r = add_prop(ua, UA_NS0ID_USERMANAGEMENT_USERS, "Users",
                     UA_NS0ID_USERMANAGEMENTDATATYPE, UA_VALUERANK_ONE_DIMENSION, &none);
    if(r == UA_STATUSCODE_GOOD)
        r = add_prop(ua, UA_NS0ID_USERMANAGEMENT_PASSWORDLENGTH, "PasswordLength",
                     UA_NS0ID_RANGE, UA_VALUERANK_SCALAR, &rangeV);
    if(r == UA_STATUSCODE_GOOD)
        r = add_prop(ua, UA_NS0ID_USERMANAGEMENT_PASSWORDOPTIONS, "PasswordOptions",
                     UA_NS0ID_PASSWORDOPTIONSMASK, UA_VALUERANK_SCALAR, &optsV);
    if(r == UA_STATUSCODE_GOOD)
        r = add_prop(ua, UA_NS0ID_USERMANAGEMENT_PASSWORDRESTRICTIONS, "PasswordRestrictions",
                     UA_NS0ID_LOCALIZEDTEXT, UA_VALUERANK_SCALAR, &textV);
    if(r == UA_STATUSCODE_GOOD)
        r = add_method(ua, UA_NS0ID_USERMANAGEMENT_ADDUSER,
                       UA_NS0ID_USERMANAGEMENT_ADDUSER_INPUTARGUMENTS, "AddUser", addArgs,
                       GDS_ARRAY_SIZE(addArgs));
    if(r == UA_STATUSCODE_GOOD)
        r = add_method(ua, UA_NS0ID_USERMANAGEMENT_MODIFYUSER,
                       UA_NS0ID_USERMANAGEMENT_MODIFYUSER_INPUTARGUMENTS, "ModifyUser", modArgs,
                       GDS_ARRAY_SIZE(modArgs));
    if(r == UA_STATUSCODE_GOOD)
        r = add_method(ua, UA_NS0ID_USERMANAGEMENT_REMOVEUSER,
                       UA_NS0ID_USERMANAGEMENT_REMOVEUSER_INPUTARGUMENTS, "RemoveUser", rmArgs,
                       GDS_ARRAY_SIZE(rmArgs));
    if(r == UA_STATUSCODE_GOOD)
        r = add_method(ua, UA_NS0ID_USERMANAGEMENT_CHANGEPASSWORD,
                       UA_NS0ID_USERMANAGEMENT_CHANGEPASSWORD_INPUTARGUMENTS, "ChangePassword",
                       cpArgs, GDS_ARRAY_SIZE(cpArgs));
    if(r == UA_STATUSCODE_GOOD)
        r = UA_Server_addNode_finish(ua, um);
    return r;
}

UA_StatusCode gds_users_install(gds_server *s) {
    pthread_mutex_lock(&ulock);
    minLength = s->passwordMinLength ? s->passwordMinLength : GDS_PASSWORD_DEFAULT_MIN_LENGTH;
    pthread_mutex_unlock(&ulock);
    UA_NodeClass nc = UA_NODECLASS_UNSPECIFIED;
    UA_NodeId um = UA_NODEID_NUMERIC(0, UA_NS0ID_USERMANAGEMENT);
    UA_StatusCode r = UA_STATUSCODE_GOOD;
    if(UA_Server_readNodeClass(s->ua, um, &nc) != UA_STATUSCODE_GOOD)
        r = create_user_management(s->ua);
    if(r == UA_STATUSCODE_GOOD)
        r = bind(s, UA_NS0ID_USERMANAGEMENT_ADDUSER, m_add_user);
    if(r == UA_STATUSCODE_GOOD)
        r = bind(s, UA_NS0ID_USERMANAGEMENT_MODIFYUSER, m_modify_user);
    if(r == UA_STATUSCODE_GOOD)
        r = bind(s, UA_NS0ID_USERMANAGEMENT_REMOVEUSER, m_remove_user);
    if(r == UA_STATUSCODE_GOOD)
        r = bind(s, UA_NS0ID_USERMANAGEMENT_CHANGEPASSWORD,
                 m_change_password);
    UA_NodeId usersNode = UA_NODEID_NUMERIC(0, UA_NS0ID_USERMANAGEMENT_USERS);
    UA_CallbackValueSource src = {read_users, NULL};
    if(r == UA_STATUSCODE_GOOD)
        r = UA_Server_setVariableNode_callbackValueSource(s->ua, usersNode, src);
    if(r == UA_STATUSCODE_GOOD)
        gds_roles_mark_secret(&usersNode);
    UA_Range len = {(UA_Double)minLength, (UA_Double)GDS_PASSWORD_MAX_LENGTH};
    UA_Variant v;
    UA_Variant_setScalar(&v, &len, &UA_TYPES[UA_TYPES_RANGE]);
    if(r == UA_STATUSCODE_GOOD)
        r = UA_Server_writeValue(
            s->ua, UA_NODEID_NUMERIC(0, UA_NS0ID_USERMANAGEMENT_PASSWORDLENGTH),
            v);
    UA_UInt32 opts = PASSWORD_OPTIONS;
    UA_Variant_setScalar(&v, &opts, &UA_TYPES[UA_TYPES_UINT32]);
    if(r == UA_STATUSCODE_GOOD)
        r = UA_Server_writeValue(
            s->ua, UA_NODEID_NUMERIC(0, UA_NS0ID_USERMANAGEMENT_PASSWORDOPTIONS),
            v);
    char text[160];
    (void)snprintf(text, sizeof(text),
                   "%u to %u characters. Users of the users file are changed in that file.",
                   minLength, (unsigned)GDS_PASSWORD_MAX_LENGTH);
    UA_LocalizedText lt = UA_LOCALIZEDTEXT("en", text);
    UA_Variant_setScalar(&v, &lt, &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]);
    UA_NodeId restr =
        UA_NODEID_NUMERIC(0, UA_NS0ID_USERMANAGEMENT_PASSWORDRESTRICTIONS);
    if(r == UA_STATUSCODE_GOOD && UA_Server_readNodeClass(s->ua, restr, &nc) == UA_STATUSCODE_GOOD)
        r = UA_Server_writeValue(s->ua, restr, v);
    return r;
}

void gds_users_set_file(const gds_users *u) {
    pthread_mutex_lock(&ulock);
    fileUsers = u;
    pthread_mutex_unlock(&ulock);
}
