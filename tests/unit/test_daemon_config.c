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

int main(void) {
    test_ok();
    test_bad_values();
    test_refused();
    return CHECK_DONE();
}
