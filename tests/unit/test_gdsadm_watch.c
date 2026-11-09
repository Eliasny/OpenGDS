/* OpenGDS unit test: gdsadm watch output (src/daemon/gdsadm_watch.c). The
 * text line and the JSON object for an audit event and a Condition event;
 * fields the event lacks are left out; text escapes control characters and
 * JSON escapes quotes and replaces malformed UTF-8.
 * SPDX-License-Identifier: MPL-2.0 */
#include <open62541/types.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "check.h"
#include "gdsadm_watch.h"
#include "common/banned.h"

static char *render(bool json, const UA_Variant *f, const char *type, bool refresh) {
    char *buf = NULL;
    size_t len = 0;
    FILE *o = open_memstream(&buf, &len);
    if(!o)
        return NULL;
    gdsadm_watch_print(o, json, f, type, refresh);
    fclose(o);
    return buf;
}

static void set_str(UA_Variant *v, const char *s) {
    UA_String str = UA_STRING((char *)(uintptr_t)s);
    UA_Variant_setScalarCopy(v, &str, &UA_TYPES[UA_TYPES_STRING]);
}

static void base(UA_Variant *f, UA_UInt32 type, const char *source, const char *msg) {
    for(size_t i = 0; i < GW_NFIELDS; i++)
        UA_Variant_init(&f[i]);
    UA_NodeId t = UA_NODEID_NUMERIC(0, type);
    UA_Variant_setScalarCopy(&f[GW_EVENT_TYPE], &t, &UA_TYPES[UA_TYPES_NODEID]);
    UA_DateTimeStruct ts = {0};
    ts.year = 2026;
    ts.month = 11;
    ts.day = 9;
    ts.hour = 6;
    ts.min = 30;
    ts.sec = 1;
    ts.milliSec = 25;
    UA_DateTime dt = UA_DateTime_fromStruct(ts);
    UA_Variant_setScalarCopy(&f[GW_TIME], &dt, &UA_TYPES[UA_TYPES_DATETIME]);
    UA_UInt16 sev = 500;
    UA_Variant_setScalarCopy(&f[GW_SEVERITY], &sev, &UA_TYPES[UA_TYPES_UINT16]);
    set_str(&f[GW_SOURCE_NAME], source);
    UA_LocalizedText lt = UA_LOCALIZEDTEXT("en", (char *)(uintptr_t)msg);
    UA_Variant_setScalarCopy(&f[GW_MESSAGE], &lt, &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]);
    UA_ByteString id = {2, (UA_Byte *)(uintptr_t)"\x0a\xff"};
    UA_Variant_setScalarCopy(&f[GW_EVENT_ID], &id, &UA_TYPES[UA_TYPES_BYTESTRING]);
}

static void clear(UA_Variant *f) {
    for(size_t i = 0; i < GW_NFIELDS; i++)
        UA_Variant_clear(&f[i]);
}

static void set_bool(UA_Variant *v, bool b) {
    UA_Boolean x = b;
    UA_Variant_setScalarCopy(v, &x, &UA_TYPES[UA_TYPES_BOOLEAN]);
}

static void test_audit(void) {
    UA_Variant f[GW_NFIELDS];
    base(f, UA_NS0ID_AUDITUPDATEMETHODEVENTTYPE, "Directory", "RegisterApplication");
    set_str(&f[GW_CLIENT_USER], "registrar");
    set_bool(&f[GW_STATUS], true);
    char *t = render(false, f, "AuditUpdateMethodEventType", false);
    CHECK(t && strcmp(t, "2026-11-09T06:30:01.025Z   500  AuditUpdateMethodEventType  "
                         "Directory: RegisterApplication  user=registrar  status=ok\n") == 0);
    free(t);
    char *j = render(true, f, "AuditUpdateMethodEventType", false);
    CHECK(j && strcmp(j, "{\"time\":\"2026-11-09T06:30:01.025Z\",\"eventType\":"
                         "\"AuditUpdateMethodEventType\",\"eventTypeId\":\"i=2127\","
                         "\"severity\":500,\"sourceName\":\"Directory\",\"message\":"
                         "\"RegisterApplication\",\"eventId\":\"0aff\",\"clientUserId\":"
                         "\"registrar\",\"status\":true,\"refresh\":false}\n") == 0);
    if(j)
        printf("%s", j);
    free(j);
    clear(f);
}

static void test_condition(void) {
    UA_Variant f[GW_NFIELDS];
    base(f, UA_NS0ID_DIALOGCONDITIONTYPE, "Approvals", "waits");
    UA_NodeId cid = UA_NODEID_NUMERIC(1, 42);
    UA_Variant_setScalarCopy(&f[GW_CONDITION_ID], &cid, &UA_TYPES[UA_TYPES_NODEID]);
    set_str(&f[GW_CONDITION_NAME], "CertificateRequest");
    set_bool(&f[GW_RETAIN], true);
    set_bool(&f[GW_ENABLED], true);
    set_str(&f[GW_CLIENT_USER], ""); /* not an audit event: left out */
    /* no type name: the EventType NodeId stands in */
    char *t = render(false, f, NULL, true);
    CHECK(t && strcmp(t, "2026-11-09T06:30:01.025Z   500  i=2830  Approvals: waits  "
                         "[condition CertificateRequest enabled retained]  (refresh)\n") == 0);
    free(t);
    char *j = render(true, f, "DialogConditionType", true);
    CHECK(j && strstr(j, "\"conditionId\":\"ns=1;i=42\",\"conditionName\":\"CertificateRequest\","
                         "\"retain\":true,\"enabled\":true,\"refresh\":true}") != NULL);
    CHECK(j && !strstr(j, "clientUserId") && !strstr(j, "\"active\""));
    free(j);
    clear(f);
}

/* What a GDS sends is data: no terminal control, valid JSON. */
static void test_escaping(void) {
    UA_Variant f[GW_NFIELDS];
    base(f, UA_NS0ID_BASEEVENTTYPE, "src\x1b[2J", "a \"quoted\"\\ line\nnext \xc3\xa4 \xff");
    char *t = render(false, f, "BaseEventType", false);
    CHECK(t && strstr(t, "src\\x1b[2J: a \"quoted\"\\x5c line\\x0anext \xc3\xa4 \\xff\n") != NULL);
    CHECK(t && !strchr(t, '\x1b'));
    free(t);
    char *j = render(true, f, "BaseEventType", false);
    CHECK(j && strstr(j, "\"sourceName\":\"src\\u001b[2J\"") != NULL);
    CHECK(j && strstr(j, "\"message\":\"a \\\"quoted\\\"\\\\ line\\nnext \xc3\xa4 \\ufffd\"") != NULL);
    free(j);
    /* an event with no fields at all still makes one line */
    for(size_t i = 0; i < GW_NFIELDS; i++)
        UA_Variant_clear(&f[i]);
    t = render(false, f, NULL, false);
    CHECK(t && strcmp(t, "-     -  -  -\n") == 0);
    free(t);
    j = render(true, f, NULL, false);
    CHECK(j && strcmp(j, "{\"refresh\":false}\n") == 0);
    free(j);
}

int main(void) {
    test_audit();
    test_condition();
    test_escaping();
    return CHECK_DONE();
}
