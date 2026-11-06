/* OpenGDS example: an application that embeds OpenGDS and adds its own
 * method next to the GDS (UASM ask A5, issue #16).
 *
 * It adds a namespace, an object and one method, Greet(String) -> String,
 * callable by sessions with the Operator Role (users file) over
 * SignAndEncrypt. Greet runs on the OpenGDS plugin worker pool, gets the
 * caller as a gds_caller and checks its own argument with gds_arg_string.
 *
 *   embed_method <dir> <users file> [--check]
 *
 * <dir> holds the store and an in-process test CA (never the default for
 * opengdsd, see docs/architecture.md). --check sets everything up and exits.
 * SPDX-License-Identifier: MPL-2.0 */
#include <open62541/plugin/create_certificate.h>
#include <open62541/plugin/log_stdout.h>

#include <signal.h>
#include <stdio.h>
#include <string.h>

#include "ca.h"
#include "common/buf.h"
#include "common/ua_args.h"
#include "gds_plugin.h"
#include "gds_server.h"
#include "store.h"
#include "common/banned.h"

#define APP_URI "urn:opengds:example:embed"
#define EXAMPLE_NS "urn:opengds:example"
#define MAX_NAME 64

static volatile UA_Boolean running = true;

static void on_signal(int sig) {
    (void)sig;
    running = false;
}

/* Greet(Name) -> Greeting. Runs on a worker; caller and arguments are
 * borrowed for this call only. */
static UA_StatusCode greet(void *ctx, const gds_caller *caller, const UA_NodeId *objectId,
                           size_t inputSize, const UA_Variant *input, size_t outputSize,
                           UA_Variant *output) {
    (void)ctx, (void)objectId;
    const UA_String *name = NULL;
    if(inputSize != 1 || outputSize != 1)
        return UA_STATUSCODE_BADINTERNALERROR;
    UA_StatusCode r = gds_arg_string(&input[0], MAX_NAME, &name);
    if(r != UA_STATUSCODE_GOOD)
        return r;
    char text[2 * MAX_NAME + 32];
    int n = snprintf(text, sizeof(text), "Hello %.*s, from %s", (int)name->length,
                     (const char *)name->data, caller->userName ? caller->userName : "anonymous");
    if(n < 0 || (size_t)n >= sizeof(text))
        return UA_STATUSCODE_BADINTERNALERROR;
    UA_String out = {(size_t)n, (UA_Byte *)text};
    return UA_Variant_setScalarCopy(&output[0], &out, &UA_TYPES[UA_TYPES_STRING]);
}

static gds_status add_greet(gds_server *s) {
    UA_UInt16 ns = 0;
    gds_status st = gds_server_add_namespace(s, EXAMPLE_NS, &ns);
    if(st != GDS_OK)
        return st;
    UA_NodeId obj = UA_NODEID_NUMERIC(ns, 1000);
    UA_NodeId objects = UA_NODEID_NUMERIC(0, UA_NS0ID_OBJECTSFOLDER);
    st = gds_server_add_object(s, &obj, &objects, "Example", NULL);
    if(st != GDS_OK)
        return st;

    UA_Argument in, out;
    UA_Argument_init(&in);
    in.name = UA_STRING("Name");
    in.dataType = UA_TYPES[UA_TYPES_STRING].typeId;
    in.valueRank = UA_VALUERANK_SCALAR;
    UA_Argument_init(&out);
    out.name = UA_STRING("Greeting");
    out.dataType = UA_TYPES[UA_TYPES_STRING].typeId;
    out.valueRank = UA_VALUERANK_SCALAR;
    UA_NodeId operatorRole = UA_NODEID_NUMERIC(0, UA_NS0ID_WELLKNOWNROLE_OPERATOR);

    gds_method_def d;
    memset(&d, 0, sizeof(d));
    d.abi_major = GDS_PLUGIN_ABI_MAJOR;
    d.abi_minor = GDS_PLUGIN_ABI_MINOR;
    d.struct_size = sizeof(d);
    d.methodId = UA_NODEID_NUMERIC(ns, 1001);
    d.parentId = obj;
    d.browseName = "Greet";
    d.inputArguments = &in;
    d.inputArgumentsSize = 1;
    d.outputArguments = &out;
    d.outputArgumentsSize = 1;
    d.roles = &operatorRole;
    d.rolesSize = 1;
    d.minSecurityMode = GDS_SECURITY_MODE_SIGN_AND_ENCRYPT;
    d.flags = GDS_METHOD_READ_ONLY;
    d.fn = greet;
    return gds_server_add_method(s, &d);
}

int main(int argc, char **argv) {
    if(argc < 3) {
        fprintf(stderr, "usage: %s <dir> <users file> [--check]\n", argv[0]);
        return 2;
    }
    bool check = argc > 3 && strcmp(argv[3], "--check") == 0;
    char db[GDS_MAX_PATH], caDir[GDS_MAX_PATH];
    if(gds_mkdirs(argv[1], 0700) != GDS_OK ||
       gds_path(db, sizeof(db), "%s/store.db", argv[1]) != GDS_OK ||
       gds_path(caDir, sizeof(caDir), "%s/ca", argv[1]) != GDS_OK)
        return 1;

    static gds_users users;
    if(gds_users_load(argv[2], &users) != GDS_OK) {
        fprintf(stderr, "cannot load users file %s\n", argv[2]);
        return 1;
    }
    static uint8_t pw[] = "example-only-passphrase";
    static gds_buf pass = {pw, sizeof(pw) - 1};
    gds_ca_config cc;
    gds_ca_config_init(&cc);
    cc.dir = caDir;
    cc.caKeyBits = 2048;
    cc.keyPassphrase = &pass;
    gds_ca *ca = NULL;
    gds_store *st = NULL;
    UA_ByteString cert = UA_BYTESTRING_NULL, key = UA_BYTESTRING_NULL;
    UA_String subject[] = {UA_STRING_STATIC("CN=OpenGDS embed example")};
    UA_String san[] = {UA_STRING_STATIC("URI:" APP_URI), UA_STRING_STATIC("DNS:localhost")};
    int rc = 1;
    gds_server *s = NULL;
    if(gds_ca_openssl_open(&cc, &ca) != GDS_OK || gds_store_open(db, &st) != GDS_OK ||
       UA_CreateCertificate(UA_Log_Stdout, subject, 1, san, 2, UA_CERTIFICATEFORMAT_DER, NULL,
                            &key, &cert) != UA_STATUSCODE_GOOD)
        goto out;

    gds_server_config cfg = {0};
    cfg.port = 4841;
    cfg.loopbackOnly = true;
    cfg.applicationUri = APP_URI;
    cfg.productUri = "urn:opengds:example";
    cfg.applicationName = "OpenGDS embed example";
    cfg.ownCert = (gds_buf){cert.data, cert.length};
    cfg.ownKey = (gds_buf){key.data, key.length};
    cfg.store = st;
    cfg.ca = ca;
    cfg.users = &users;
    cfg.approval = GDS_APPROVE_RENEWALS; /* the opengds.conf default */
    if(gds_server_new(&cfg, &s) != GDS_OK || add_greet(s) != GDS_OK)
        goto out;
    if(check) {
        printf("embed_method: Greet added\n");
        rc = 0;
        goto out;
    }
    (void)signal(SIGINT, on_signal);
    (void)signal(SIGTERM, on_signal);
    rc = gds_server_run(s, &running) == GDS_OK ? 0 : 1;
out:
    gds_server_delete(s);
    UA_ByteString_clear(&cert);
    UA_ByteString_clear(&key);
    gds_store_close(st);
    gds_ca_close(ca);
    return rc;
}
