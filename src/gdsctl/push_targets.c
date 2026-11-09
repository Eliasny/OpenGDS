/* OpenGDS - gdsctl push-targets (push_targets.h).
 *
 *   gdsctl push-targets add --store <store.db> --uri <ApplicationUri>
 *                           [--endpoint <opc.tcp URL>] [--disabled]
 *   gdsctl push-targets remove --store <store.db> --uri <ApplicationUri>
 *   gdsctl push-targets list --store <store.db>
 *
 * add needs a registered Server (Server or ClientAndServer); without
 * --endpoint the record's first opc.tcp DiscoveryUrl is used. Adding a
 * target again replaces its endpoint and state. opengdsd picks changes up
 * at its next push_interval.
 * SPDX-License-Identifier: MPL-2.0 */
#include "push_targets.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "common/limits.h"
#include "store.h"
#include "common/banned.h"

typedef struct {
    const char *store, *uri, *endpoint;
    bool disabled;
} pt_args;

static int usage(void) {
    fprintf(stderr,
            "usage: gdsctl push-targets add --store <store.db> --uri <ApplicationUri>\n"
            "                               [--endpoint <opc.tcp URL>] [--disabled]\n"
            "       gdsctl push-targets remove --store <store.db> --uri <ApplicationUri>\n"
            "       gdsctl push-targets list --store <store.db>\n");
    return 2;
}

static bool parse(int argc, char **argv, pt_args *a) {
    memset(a, 0, sizeof(*a));
    for(int i = 3; i < argc; i++) {
        const char **dst = NULL;
        if(strcmp(argv[i], "--disabled") == 0 && !a->disabled) {
            a->disabled = true;
            continue;
        }
        if(strcmp(argv[i], "--store") == 0)
            dst = &a->store;
        else if(strcmp(argv[i], "--uri") == 0)
            dst = &a->uri;
        else if(strcmp(argv[i], "--endpoint") == 0)
            dst = &a->endpoint;
        if(!dst || *dst || i + 1 >= argc)
            return false;
        *dst = argv[++i];
    }
    return a->store != NULL;
}

static bool is_server(UA_ApplicationType t) {
    return t == UA_APPLICATIONTYPE_SERVER || t == UA_APPLICATIONTYPE_CLIENTANDSERVER;
}

/* The one record with this ApplicationUri; *rec owned by the caller. */
static int find(gds_store *st, const char *uri, UA_ApplicationRecordDataType *rec) {
    if(!uri) {
        fprintf(stderr, "gdsctl: --uri is required\n");
        return 2;
    }
    UA_ApplicationRecordDataType *recs = NULL;
    size_t n = 0;
    gds_status r = gds_store_app_find_uri(st, &(UA_String){strlen(uri), (UA_Byte *)(uintptr_t)uri},
                                          2, &recs, &n);
    if(r != GDS_OK) {
        fprintf(stderr, "gdsctl: find %s: %s\n", uri, gds_status_name(r));
        return 2;
    }
    int rc = 0;
    if(n != 1) {
        fprintf(stderr, "gdsctl: %s is not registered\n", uri);
        rc = 1;
    } else if(UA_ApplicationRecordDataType_copy(&recs[0], rec) != UA_STATUSCODE_GOOD) {
        rc = 2;
    }
    UA_Array_delete(recs, n, &UA_TYPES_GDS[UA_TYPES_GDS_APPLICATIONRECORDDATATYPE]);
    return rc;
}

static bool first_tcp_url(const UA_ApplicationRecordDataType *rec, char *out, size_t len) {
    for(size_t i = 0; i < rec->discoveryUrlsSize; i++) {
        const UA_String *u = &rec->discoveryUrls[i];
        if(u->length > 10 && u->length < len && memcmp(u->data, "opc.tcp://", 10) == 0) {
            memcpy(out, u->data, u->length);
            out[u->length] = '\0';
            return true;
        }
    }
    return false;
}

static int add(gds_store *st, const pt_args *a) {
    UA_ApplicationRecordDataType rec;
    UA_ApplicationRecordDataType_init(&rec);
    int rc = find(st, a->uri, &rec);
    char url[GDS_MAX_PUSH_ENDPOINT];
    if(rc == 0 && !is_server(rec.applicationType)) {
        fprintf(stderr, "gdsctl: %s is not a Server\n", a->uri);
        rc = 1;
    }
    if(rc == 0 && a->endpoint) {
        if(strlen(a->endpoint) >= sizeof(url))
            rc = 2;
        else
            memcpy(url, a->endpoint, strlen(a->endpoint) + 1);
    } else if(rc == 0 && !first_tcp_url(&rec, url, sizeof(url))) {
        fprintf(stderr, "gdsctl: %s has no opc.tcp DiscoveryUrl; give --endpoint\n", a->uri);
        rc = 1;
    }
    if(rc == 0) {
        gds_status r = gds_store_push_target_put(st, &rec.applicationId.identifier.guid, url,
                                                 !a->disabled);
        if(r != GDS_OK) {
            fprintf(stderr, "gdsctl: push target %s: %s%s\n", a->uri, gds_status_name(r),
                    r == GDS_EINVAL ? " (the endpoint must be an opc.tcp:// URL)" : "");
            rc = 2;
        } else {
            printf("push target %s at %s%s\n", a->uri, url, a->disabled ? " (disabled)" : "");
        }
    }
    UA_ApplicationRecordDataType_clear(&rec);
    return rc;
}

static int remove_target(gds_store *st, const pt_args *a) {
    UA_ApplicationRecordDataType rec;
    UA_ApplicationRecordDataType_init(&rec);
    int rc = find(st, a->uri, &rec);
    if(rc == 0) {
        gds_status r = gds_store_push_target_delete(st, &rec.applicationId.identifier.guid);
        if(r == GDS_ENOTFOUND) {
            fprintf(stderr, "gdsctl: %s is not a push target\n", a->uri);
            rc = 1;
        } else if(r != GDS_OK) {
            fprintf(stderr, "gdsctl: remove %s: %s\n", a->uri, gds_status_name(r));
            rc = 2;
        } else {
            printf("removed push target %s\n", a->uri);
        }
    }
    UA_ApplicationRecordDataType_clear(&rec);
    return rc;
}

static bool print_cb(void *ctx, const gds_push_target_row *row) {
    gds_store *st = ctx;
    UA_ApplicationRecordDataType rec;
    UA_ApplicationRecordDataType_init(&rec);
    if(gds_store_app_get(st, &row->appId, &rec) == GDS_OK)
        printf("%.*s\t%s\t%s\n", (int)rec.applicationUri.length,
               (const char *)rec.applicationUri.data, row->endpoint,
               row->enabled ? "enabled" : "disabled");
    UA_ApplicationRecordDataType_clear(&rec);
    return true;
}

int gdsctl_push_targets(int argc, char **argv) {
    pt_args a;
    if(argc < 3 || !parse(argc, argv, &a))
        return usage();
    bool isAdd = strcmp(argv[2], "add") == 0, isRemove = strcmp(argv[2], "remove") == 0,
         isList = strcmp(argv[2], "list") == 0;
    if((!isAdd && !isRemove && !isList) || (isList && (a.uri || a.endpoint || a.disabled)) ||
       (!isList && !a.uri) || (isRemove && (a.endpoint || a.disabled)))
        return usage();
    /* never create a store here: opengdsd creates and migrates it */
    if(access(a.store, R_OK | W_OK) != 0) {
        fprintf(stderr, "gdsctl: store %s cannot be opened for writing\n", a.store);
        return 2;
    }
    gds_store *st = NULL;
    gds_status r = gds_store_open(a.store, &st);
    if(r != GDS_OK) {
        fprintf(stderr, "gdsctl: store %s: %s\n", a.store, gds_status_name(r));
        return 2;
    }
    int rc = 0;
    if(isAdd) {
        rc = add(st, &a);
    } else if(isRemove) {
        rc = remove_target(st, &a);
    } else {
        r = gds_store_push_target_scan(st, print_cb, st);
        if(r != GDS_OK) {
            fprintf(stderr, "gdsctl: list: %s\n", gds_status_name(r));
            rc = 2;
        }
    }
    gds_store_close(st);
    return rc;
}
