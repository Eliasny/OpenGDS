/* OpenGDS unit test: opengdsd configuration parser.
 * SPDX-License-Identifier: MPL-2.0 */
#include <string.h>

#include "check.h"
#include "common/buf.h"
#include "config.h"
#include "common/banned.h"

#define BASE                                                                             \
    "application_uri = urn:test:gds\n"                                                   \
    "data_dir = /var/lib/opengds\n"                                                      \
    "users_file = /etc/opengds/users\n"                                                  \
    "ca_dir = /var/lib/opengds-signer/ca\n"

static gds_status parse(const char *t, gdsd_config *c, unsigned *line) {
    return gdsd_config_parse(t, strlen(t), c, line);
}

static void test_ok(void) {
    gdsd_config c;
    unsigned line = 9;
    CHECK(parse("# comment\n\n" BASE "  port =  4840 \r\nloopback_only=true\n"
                "signer = /usr/libexec/opengds-signer\napproval = manual",
                &c, &line) == GDS_OK);
    CHECK_EQ_INT(line, 0);
    CHECK(strcmp(c.applicationUri, "urn:test:gds") == 0);
    CHECK(strcmp(c.signer, "/usr/libexec/opengds-signer") == 0);
    CHECK_EQ_INT(c.port, 4840);
    CHECK(c.loopbackOnly && c.approval == GDSD_APPROVE_MANUAL);
    CHECK(strcmp(c.applicationName, "OpenGDS") == 0); /* default */
    CHECK(parse(BASE, &c, &line) == GDS_OK && c.port == 58810 &&
          c.approval == GDSD_APPROVE_RENEWALS); /* default */
    CHECK(parse(BASE "approval = auto\n", &c, &line) == GDS_OK && c.approval == GDSD_APPROVE_AUTO);
}

/* Values a key does not accept. */
static void test_bad_values(void) {
    gdsd_config c;
    unsigned line = 0;
    CHECK(parse(BASE "colour = blue\n", &c, &line) == GDS_EINVAL && line == 5);
    CHECK(parse(BASE "port = 70000\n", &c, &line) == GDS_EINVAL && line == 5);
    CHECK(parse(BASE "approval = sometimes\n", &c, &line) == GDS_EINVAL && line == 5);
    CHECK(parse(BASE "auto_approve = true\n", &c, &line) == GDS_EINVAL); /* the T1 key is gone */
    CHECK(parse(BASE "port = 12x\n", &c, &line) == GDS_EINVAL);
    CHECK(parse(BASE "loopback_only = yes\n", &c, &line) == GDS_EINVAL);
}

static void test_refused(void) {
    gdsd_config c;
    unsigned line = 0;
    CHECK(parse(BASE "signer = relative/path\n", &c, &line) == GDS_EINVAL);
    CHECK(parse(BASE "data_dir = /again\n", &c, &line) == GDS_EINVAL && line == 5);
    CHECK(parse(BASE "hostname =\n", &c, &line) == GDS_EINVAL);
    CHECK(parse(BASE "no equals sign\n", &c, &line) == GDS_EINVAL);
    CHECK(parse(BASE "signer = /s\nsigner_socket = /run/s.sock\n", &c, &line) == GDS_EINVAL &&
          line == 0); /* exclusive */
    CHECK(parse(BASE "signer_socket = /run/opengds/signer.sock\n", &c, &line) == GDS_OK &&
          strcmp(c.signerSocket, "/run/opengds/signer.sock") == 0);
    CHECK(parse(BASE "hostname = a\x01" "b\n", &c, &line) == GDS_EINVAL);
    CHECK(parse("data_dir = /x\nusers_file = /u\nca_dir = /c\n", &c, &line) == GDS_EINVAL &&
          line == 0); /* application_uri missing */
    static const char nul[] = BASE "hostname = a\0b\n";
    CHECK(gdsd_config_parse(nul, sizeof(nul) - 1, &c, &line) == GDS_EINVAL && line == 5);
    char longValue[GDSD_MAX_VALUE + 10];
    memset(longValue, 'a', sizeof(longValue) - 1);
    longValue[sizeof(longValue) - 1] = '\0';
    char text[4096];
    CHECK(gds_path(text, sizeof(text), "%shostname = %s\n", BASE, longValue) == GDS_OK);
    CHECK(parse(text, &c, &line) == GDS_EINVAL && line == 5);
}

/* keycred_service: the one repeatable key (OPC 10000-12 §8.5). */
static void test_keycred(void) {
    gdsd_config c;
    unsigned line = 0;
    CHECK(parse(BASE, &c, &line) == GDS_OK && c.nKeycred == 0);
    CHECK(parse(BASE "keycred_service = mqtt urn:test:broker http://a/P1,http://a/P2\n"
                     "keycred_service  =  amqp-1  urn:test:amqp   urn:p:x \n",
                &c, &line) == GDS_OK);
    CHECK_EQ_INT(c.nKeycred, 2);
    CHECK(strcmp(c.keycred[0].name, "mqtt") == 0);
    CHECK(strcmp(c.keycred[0].resourceUri, "urn:test:broker") == 0);
    CHECK_EQ_INT(c.keycred[0].nProfiles, 2);
    CHECK(strcmp(c.keycred[0].profiles + c.keycred[0].profile[0], "http://a/P1") == 0);
    CHECK(strcmp(c.keycred[0].profiles + c.keycred[0].profile[1], "http://a/P2") == 0);
    CHECK(strcmp(c.keycred[1].name, "amqp-1") == 0 && c.keycred[1].nProfiles == 1);
    CHECK(strcmp(c.keycred[1].profiles, "urn:p:x") == 0);
    static const char *const bad[] = {
        "keycred_service = mqtt urn:test:broker\n",               /* no profiles */
        "keycred_service = mqtt urn:test:broker urn:p extra\n",   /* four words */
        "keycred_service = mq/tt urn:test:broker urn:p\n",        /* name */
        "keycred_service = mqtt broker urn:p\n",                  /* not a URI */
        "keycred_service = mqtt urn:b urn:p,,urn:q\n",            /* empty profile */
        "keycred_service = mqtt urn:b urn:p,\n",                  /* empty profile */
        "keycred_service = mqtt urn:b nouri\n",                   /* profile not a URI */
        "keycred_service = m urn:b urn:p\nkeycred_service = m urn:c urn:p\n", /* same name */
        "keycred_service = m urn:b u:1,u:2,u:3,u:4,u:5,u:6,u:7,u:8,u:9\n",    /* 9 profiles */
    };
    for(size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        char t[1024];
        CHECK(gds_path(t, sizeof(t), "%s%s", BASE, bad[i]) == GDS_OK);
        CHECK(parse(t, &c, &line) == GDS_EINVAL);
    }
    char many[2048] = BASE;
    for(int i = 0; i <= GDSD_MAX_KC; i++) {
        char l[128];
        CHECK(gds_path(l, sizeof(l), "keycred_service = s%d urn:b urn:p\n", i) == GDS_OK);
        strncat(many, l, sizeof(many) - strlen(many) - 1);
    }
    CHECK(parse(many, &c, &line) == GDS_EINVAL && line == 5 + GDSD_MAX_KC); /* 9th line */
}

int main(void) {
    test_ok();
    test_keycred();
    test_bad_values();
    test_refused();
    return CHECK_DONE();
}
