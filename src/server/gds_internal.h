/* OpenGDS - state and helpers shared by the src/server files only.
 * SPDX-License-Identifier: MPL-2.0 */
#ifndef OPENGDS_GDS_INTERNAL_H
#define OPENGDS_GDS_INTERNAL_H

#include <open62541/nodeids_gds.h>
#include <open62541/server.h>
#include <open62541/types_gds_generated.h>

#include <pthread.h>
#include <stdbool.h>

#include "ca.h"
#include "common/ua_args.h"
#include "gds_access.h"
#include "gds_server.h"
#include "store.h"

#define GDS_NS_URI "http://opcfoundation.org/UA/GDS/"

struct gds_server {
    UA_Server *ua;
    UA_UInt16 ns;
    gds_store *store;
    /* The store is single-writer: the server thread and the signing worker
     * take this lock around store calls only, never across a CA call. */
    pthread_mutex_t storeLock;
    gds_ca *ca;
    gds_buf caCert; /* issuer certificate for FinishRequest, read once at start */
    bool autoApprove;
    UA_DateTime counterReset; /* QueryApplications lastCounterResetTime */
    /* node role (gds_server.c); roleLock is a leaf lock */
    pthread_mutex_t roleLock;
    gds_node_role role;
    UA_Byte serviceLevel;
    UA_DateTime estimatedReturnTime;
    /* signing worker (decision G7) */
    pthread_t worker;
    bool workerStarted;
    pthread_mutex_t workLock;
    pthread_cond_t workCond;
    bool workPending, workStop;
};

#define GDS_METHOD(name)                                                                 \
    UA_StatusCode name(UA_Server *server, const UA_NodeId *sessionId, void *sessionContext, \
                       const UA_NodeId *methodId, void *methodContext,                     \
                       const UA_NodeId *objectId, void *objectContext, size_t inputSize,   \
                       const UA_Variant *input, size_t outputSize, UA_Variant *output)
#define GDS_METHOD_UNUSED                                                                \
    (void)server, (void)sessionId, (void)methodId, (void)objectId, (void)objectContext,   \
        (void)outputSize

/* The method's node context is the gds_server. */
static inline gds_server *gds_ctx(void *methodContext) {
    return (gds_server *)methodContext;
}

static inline void gds_lock(gds_server *s) {
    pthread_mutex_lock(&s->storeLock);
}
static inline void gds_unlock(gds_server *s) {
    pthread_mutex_unlock(&s->storeLock);
}

/* Inputs: the count first, then each argument's type and shape. */
GDS_MUST_CHECK UA_StatusCode gds_in_nodeid(size_t inputSize, const UA_Variant *input, size_t i,
                                           const UA_NodeId **out);
/* An ApplicationId / RequestId: a GUID NodeId in the GDS namespace. */
GDS_MUST_CHECK UA_StatusCode gds_in_guid(const gds_server *s, size_t inputSize,
                                         const UA_Variant *input, size_t i, UA_Guid *out);
GDS_MUST_CHECK UA_StatusCode gds_in_record(size_t inputSize, const UA_Variant *input, size_t i,
                                           const UA_ApplicationRecordDataType **out);

/* Record checks for Register/UpdateApplication (gds_validate.c). */
GDS_MUST_CHECK UA_StatusCode gds_validate_record(const UA_ApplicationRecordDataType *rec);

/* The record from the store with its applicationId in the GDS namespace. */
GDS_MUST_CHECK UA_StatusCode gds_load_app(gds_server *s, const UA_Guid *id,
                                          UA_ApplicationRecordDataType *out);

/* Method wiring, one table per file. */
GDS_MUST_CHECK UA_StatusCode gds_directory_install(gds_server *s);
GDS_MUST_CHECK UA_StatusCode gds_certmgr_install(gds_server *s);
GDS_MUST_CHECK UA_StatusCode gds_trustlist_install(gds_server *s);

/* Signing worker (gds_certmgr.c). */
GDS_MUST_CHECK gds_status gds_worker_start(gds_server *s);
void gds_worker_stop(gds_server *s);
void gds_worker_kick(gds_server *s);

typedef struct {
    UA_UInt32 id;
    UA_MethodCallback cb;
} gds_method_entry;
GDS_MUST_CHECK UA_StatusCode gds_install_methods(gds_server *s, const gds_method_entry *m,
                                                 size_t n);

#endif
