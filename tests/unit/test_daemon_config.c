/* OpenGDS unit test: opengdsd configuration parser.
 * SPDX-License-Identifier: MPL-2.0 */
#include <string.h>

#include "check.h"
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
                "signer = /usr/libexec/opengds-signer\nauto_approve = false",
                &c, &line) == GDS_OK);
    CHECK_EQ_INT(line, 0);
    CHECK(strcmp(c.applicationUri, "urn:test:gds") == 0);
    CHECK(strcmp(c.signer, "/usr/libexec/opengds-signer") == 0);
    CHECK_EQ_INT(c.port, 4840);
    CHECK(c.loopbackOnly && !c.autoApprove);
    CHECK(strcmp(c.applicationName, "OpenGDS") == 0); /* default */
    CHECK(parse(BASE, &c, &line) == GDS_OK && c.port == 58810 && c.autoApprove);
}

static void test_refused(void) {
    gdsd_config c;
    unsigned line = 0;
    CHECK(parse(BASE "colour = blue\n", &c, &line) == GDS_EINVAL && line == 5);
    CHECK(parse(BASE "port = 70000\n", &c, &line) == GDS_EINVAL && line == 5);
    CHECK(parse(BASE "port = 12x\n", &c, &line) == GDS_EINVAL);
    CHECK(parse(BASE "loopback_only = yes\n", &c, &line) == GDS_EINVAL);
    CHECK(parse(BASE "signer = relative/path\n", &c, &line) == GDS_EINVAL);
    CHECK(parse(BASE "data_dir = /again\n", &c, &line) == GDS_EINVAL && line == 5);
    CHECK(parse(BASE "hostname =\n", &c, &line) == GDS_EINVAL);
    CHECK(parse(BASE "no equals sign\n", &c, &line) == GDS_EINVAL);
    CHECK(parse(BASE "hostname = a\x01" "b\n", &c, &line) == GDS_EINVAL);
    CHECK(parse("data_dir = /x\nusers_file = /u\nca_dir = /c\n", &c, &line) == GDS_EINVAL &&
          line == 0); /* application_uri missing */
    static const char nul[] = BASE "hostname = a\0b\n";
    CHECK(gdsd_config_parse(nul, sizeof(nul) - 1, &c, &line) == GDS_EINVAL && line == 5);
    char big[2000];
    memset(big, 'a', sizeof(big));
    memcpy(big, "hostname = ", 11);
    big[sizeof(big) - 1] = '\n';
    char text[4096];
    size_t n = strlen(BASE);
    memcpy(text, BASE, n);
    memcpy(text + n, big, sizeof(big));
    CHECK(gdsd_config_parse(text, n + sizeof(big), &c, &line) == GDS_EINVAL);
}

int main(void) {
    test_ok();
    test_refused();
    return CHECK_DONE();
}
