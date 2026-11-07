/* OpenGDS unit test: gdsadm apps import file parsing (gdsadm_import.h).
 * SPDX-License-Identifier: MPL-2.0 */
#include <stdio.h>
#include <string.h>

#include "check.h"
#include "gdsadm_import.h"
#include "common/banned.h"

static gds_status parse(const char *text, gdsadm_import *im, char *err, size_t errLen) {
    gds_buf b = {(uint8_t *)(uintptr_t)text, strlen(text)};
    return gdsadm_import_parse(&b, im, err, errLen);
}

static bool str_is(const UA_String *s, const char *want) {
    UA_String w = UA_STRING((char *)(uintptr_t)want);
    return UA_String_equal(s, &w);
}

static void test_csv(void) {
    gdsadm_import im;
    char err[256];
    /* any column order, quotes with commas, "" and a line break, CRLF, a BOM,
     * blank lines, lists */
    const char *f = "\xEF\xBB\xBF"
                    "ApplicationType,ApplicationUri,ApplicationName,DiscoveryUrls,"
                    "ServerCapabilities,ProductUri\r\n"
                    "Server,urn:a,\"Press, line 1\",opc.tcp://a:4840  opc.tcp://a2:4840,LDS DA,"
                    "urn:p\r\n"
                    "\r\n"
                    "Client,urn:b,\"He said \"\"hi\"\"\nand left\",,,\n"
                    "ClientAndServer,urn:c,C,opc.tcp://c:4840,,";
    if(!CHECK(parse(f, &im, err, sizeof(err)) == GDS_OK)) {
        printf("# %s\n", err);
        return;
    }
    if(CHECK_EQ_INT(im.n, 3)) {
        const UA_ApplicationRecordDataType *a = &im.recs[0], *b = &im.recs[1], *c = &im.recs[2];
        CHECK(str_is(&a->applicationUri, "urn:a") && a->applicationType == UA_APPLICATIONTYPE_SERVER);
        CHECK(a->applicationNamesSize == 1 && str_is(&a->applicationNames[0].text, "Press, line 1") &&
              str_is(&a->applicationNames[0].locale, "en"));
        CHECK(a->discoveryUrlsSize == 2 && str_is(&a->discoveryUrls[1], "opc.tcp://a2:4840"));
        CHECK(a->serverCapabilitiesSize == 2 && str_is(&a->serverCapabilities[0], "LDS"));
        CHECK(str_is(&a->productUri, "urn:p"));
        CHECK(str_is(&b->applicationNames[0].text, "He said \"hi\"\nand left"));
        CHECK(b->discoveryUrlsSize == 0 && b->productUri.length == 0);
        CHECK(c->applicationType == UA_APPLICATIONTYPE_CLIENTANDSERVER);
        CHECK_EQ_INT(im.lines[0], 2);
        CHECK_EQ_INT(im.lines[1], 4);
        CHECK_EQ_INT(im.lines[2], 6); /* the quoted line break counts */
    }
    gdsadm_import_clear(&im);
}

/* a locale column; no rows at all is fine */
static void test_csv_small(void) {
    gdsadm_import im;
    char err[256];
    CHECK(parse("ApplicationUri,ApplicationName,ApplicationType,ApplicationNameLocale\n"
                "urn:d,Pumpe,Client,de-DE\n",
                &im, err, sizeof(err)) == GDS_OK);
    CHECK(im.n == 1 && str_is(&im.recs[0].applicationNames[0].locale, "de-DE"));
    gdsadm_import_clear(&im);
    CHECK(parse("ApplicationUri,ApplicationName,ApplicationType\n", &im, err, sizeof(err)) ==
              GDS_OK &&
          im.n == 0);
    gdsadm_import_clear(&im);
}

static void bad(const char *text, const char *errPart) {
    gdsadm_import im;
    char err[256];
    CHECK(parse(text, &im, err, sizeof(err)) != GDS_OK);
    CHECK(im.n == 0 && im.recs == NULL);
    if(!CHECK(strstr(err, errPart) != NULL))
        printf("# got '%s', want '%s'\n", err, errPart);
}

static void test_csv_errors(void) {
    bad("", "no header row");
    bad("ApplicationUri,ApplicationName\n", "'ApplicationType' is missing");
    bad("ApplicationUri,ApplicationName,ApplicationType,Colour\n", "unknown column 'Colour'");
    bad("ApplicationUri,ApplicationUri,ApplicationName,ApplicationType\n", "given twice");
    bad("ApplicationUri,ApplicationName,ApplicationType\nurn:a,A,Device\n",
        "line 2: ApplicationType 'Device'");
    bad("ApplicationUri,ApplicationName,ApplicationType\nurn:a,\"A,Client\n",
        "line 2: unterminated quoted field");
    bad("ApplicationUri,ApplicationName,ApplicationType\nurn:a,A\"b,Client\n",
        "quote inside an unquoted field");
    bad("ApplicationUri,ApplicationName,ApplicationType\nurn:a,\"A\"b,Client\n",
        "text after a closing quote");
    bad("ApplicationUri,ApplicationName,ApplicationType\rurn:a,A,Client\n", "bare carriage return");
    char many[2048];
    size_t k = (size_t)snprintf(many, sizeof(many), "%s",
                                "ApplicationUri,ApplicationName,ApplicationType,DiscoveryUrls\n"
                                "urn:a,A,Server,");
    for(int i = 0; i < 33; i++)
        k += (size_t)snprintf(many + k, sizeof(many) - k, "u ");
    (void)snprintf(many + k, sizeof(many) - k, "\n");
    bad(many, "more than 32 values");
    char longf[5200];
    k = (size_t)snprintf(longf, sizeof(longf), "%s",
                         "ApplicationUri,ApplicationName,ApplicationType\nurn:a,");
    memset(longf + k, 'x', 5000);
    longf[k + 5000] = '\0';
    bad(longf, "field longer than");
    gds_buf nul = {(uint8_t *)(uintptr_t)"ApplicationUri,ApplicationName,ApplicationType\nu\0", 49};
    gdsadm_import im;
    char err[128];
    CHECK(gdsadm_import_parse(&nul, &im, err, sizeof(err)) == GDS_EINVAL);
}

static void test_json(void) {
    gdsadm_import im;
    char err[256];
    const char *f = "  {\"Applications\": ["
                    "{\"ApplicationUri\": \"urn:j1\", \"ApplicationType\": 0,"
                    " \"ApplicationNames\": [{\"Locale\": \"en\", \"Text\": \"J1\"}],"
                    " \"DiscoveryUrls\": [\"opc.tcp://j1:4840\"], \"ServerCapabilities\": [\"DA\"]},"
                    "{\"ApplicationUri\": \"urn:j2\", \"ApplicationType\": 1,"
                    " \"ApplicationId\": \"i=99\","
                    " \"ApplicationNames\": [{\"Text\": \"J2\"}], \"ProductUri\": \"urn:p\"}]}";
    if(!CHECK(parse(f, &im, err, sizeof(err)) == GDS_OK)) {
        printf("# %s\n", err);
        return;
    }
    if(CHECK_EQ_INT(im.n, 2)) {
        CHECK(str_is(&im.recs[0].applicationUri, "urn:j1") &&
              im.recs[0].applicationType == UA_APPLICATIONTYPE_SERVER &&
              im.recs[0].discoveryUrlsSize == 1 && im.recs[0].serverCapabilitiesSize == 1);
        CHECK(im.recs[1].applicationType == UA_APPLICATIONTYPE_CLIENT &&
              str_is(&im.recs[1].productUri, "urn:p"));
        CHECK(UA_NodeId_isNull(&im.recs[1].applicationId)); /* the GDS assigns it */
        CHECK_EQ_INT(im.lines[1], 2);
    }
    gdsadm_import_clear(&im);
    CHECK(parse("{\"Applications\": []}", &im, err, sizeof(err)) == GDS_OK && im.n == 0);
    gdsadm_import_clear(&im);
    bad("{\"Applications\": [{\"ApplicationUri\": 5}]}", "not a JSON object");
    bad("{\"Applications\": [", "not a JSON object");
    bad("{\"Apps\": []}", "not a JSON object");
}

int main(void) {
    test_csv();
    test_csv_small();
    test_csv_errors();
    test_json();
    return CHECK_DONE();
}
