/* OpenGDS unit test: the sealed CA key export (src/ca/ca_seal.h, "OGKX").
 * Round trip to two recipients, refusal for a stranger's key and for any
 * altered byte, the recipients file rules, and the OpenSSL CA's export:
 * the private key inside matches its certificate.
 * SPDX-License-Identifier: MPL-2.0 */
#include <openssl/evp.h>
#include <openssl/x509.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "ca.h"
#include "ca_seal.h"
#include "check.h"
#include "common/buf.h"
#include "common/limits.h"
#include "common/banned.h"

static void keypair(uint8_t priv[32], uint8_t pub[32]) {
    EVP_PKEY *k = EVP_PKEY_Q_keygen(NULL, NULL, "X25519");
    size_t a = 32, b = 32;
    CHECK(k && EVP_PKEY_get_raw_private_key(k, priv, &a) == 1 &&
          EVP_PKEY_get_raw_public_key(k, pub, &b) == 1 && a == 32 && b == 32);
    EVP_PKEY_free(k);
}

static gds_status dup_bytes(const char *s, gds_buf *out) {
    size_t n = strlen(s);
    out->data = malloc(n ? n : 1);
    out->len = n;
    if(!out->data)
        return GDS_ENOMEM;
    memcpy(out->data, s, n);
    return GDS_OK;
}

static void test_altered(gds_buf *blob, const uint8_t priv[32]);

static void check_opens(const gds_buf *blob, const uint8_t priv[32], int64_t created) {
    gds_seal_contents o;
    CHECK(gds_seal_open(blob->data, blob->len, priv, &o) == GDS_OK);
    CHECK(o.created == created && o.n == 2);
    CHECK(o.items[0].issuer == GDS_CA_ISSUER_RSA && o.items[1].issuer == GDS_CA_ISSUER_P384);
    CHECK(o.items[0].key.len == 7 && memcmp(o.items[0].key.data, "key-rsa", 7) == 0);
    CHECK(o.items[0].crl.len == 7 && o.items[1].crl.len == 0);
    CHECK(o.items[1].cert.len == 8 && memcmp(o.items[1].cert.data, "cert-384", 8) == 0);
    gds_seal_contents_clear(&o);
}

static void test_round_trip(void) {
    uint8_t priv[3][32], pub[3][32];
    for(int i = 0; i < 3; i++)
        keypair(priv[i], pub[i]);
    gds_seal_contents c;
    memset(&c, 0, sizeof(c));
    c.created = 1762700000;
    c.n = 2;
    c.items[0].issuer = GDS_CA_ISSUER_RSA;
    c.items[1].issuer = GDS_CA_ISSUER_P384;
    CHECK(dup_bytes("cert-rsa", &c.items[0].cert) == GDS_OK);
    CHECK(dup_bytes("key-rsa", &c.items[0].key) == GDS_OK);
    CHECK(dup_bytes("crl-rsa", &c.items[0].crl) == GDS_OK);
    CHECK(dup_bytes("cert-384", &c.items[1].cert) == GDS_OK);
    CHECK(dup_bytes("key-384", &c.items[1].key) == GDS_OK); /* no CRL */
    gds_buf blob = {0};
    CHECK(gds_seal_ca_keys(&c, (const uint8_t (*)[32])pub, 2, &blob) == GDS_OK);
    CHECK(blob.len > 16 && memcmp(blob.data, "OGKX", 4) == 0);
    /* nothing of the plaintext in the clear */
    CHECK(blob.data && !memmem(blob.data, blob.len, "key-rsa", 7));

    for(int i = 0; i < 2; i++) /* either recipient opens it */
        check_opens(&blob, priv[i], c.created);
    gds_seal_contents o;
    CHECK(gds_seal_open(blob.data, blob.len, priv[2], &o) == GDS_EDENIED); /* a stranger */
    test_altered(&blob, priv[0]);
    CHECK(gds_seal_ca_keys(&c, (const uint8_t (*)[32])pub, 0, &blob) == GDS_EINVAL);
    gds_buf_free(&blob);
    gds_seal_contents_clear(&c);
    CHECK(c.items[0].key.data == NULL);
}

/* Every altered byte is refused, never opened. */
static void test_altered(gds_buf *blob, const uint8_t priv[32]) {
    gds_seal_contents o;
    int opened = 0;
    for(size_t i = 0; blob->data && i < blob->len; i++) {
        blob->data[i] ^= 0x01;
        if(gds_seal_open(blob->data, blob->len, priv, &o) == GDS_OK) {
            opened++;
            gds_seal_contents_clear(&o);
        }
        blob->data[i] ^= 0x01;
    }
    CHECK_EQ_INT(opened, 0);
    CHECK(gds_seal_open(blob->data, blob->len - 1, priv, &o) != GDS_OK);
    CHECK(gds_seal_open(blob->data, 10, priv, &o) == GDS_EINVAL);
}

#define HEX_A "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
#define HEX_B "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100"

static void test_parse(void) {
    uint8_t k[4][32];
    size_t n = 0;
    const char *ok = "# backup key holders\n\n" HEX_A "\nuasm-backup-recipient " HEX_B "\n";
    CHECK(gds_seal_recipients_parse(ok, strlen(ok), k, 4, &n) == GDS_OK && n == 2);
    CHECK(k[0][0] == 0x00 && k[0][1] == 0x11 && k[1][0] == 0xff && k[1][31] == 0x00);
    static const char *bad[] = {
        "",                              /* no key */
        "# only a comment\n",            /* no key */
        HEX_A "0\n",                     /* 65 digits */
        "zz" HEX_A "\n",                 /* not hex, no space */
        HEX_A "\n" HEX_A "\n",           /* repeated */
        "two words " HEX_A "\n",         /* more than one word */
    };
    for(size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
        CHECK(gds_seal_recipients_parse(bad[i], strlen(bad[i]), k, 4, &n) == GDS_EINVAL);
    const char *two = HEX_A "\n" HEX_B "\n";
    CHECK(gds_seal_recipients_parse(two, strlen(two), k, 1, &n) == GDS_ETOOBIG);
}

static void write_file(const char *path, const char *text, mode_t mode) {
    (void)unlink(path);
    FILE *f = fopen(path, "w");
    CHECK(f && fputs(text, f) >= 0);
    if(f)
        (void)fclose(f);
    CHECK(chmod(path, mode) == 0);
}

static void test_read(const char *dir) {
    char path[1024], link[1100];
    CHECK(gds_path(path, sizeof(path), "%s/recipients", dir) == GDS_OK);
    CHECK(gds_path(link, sizeof(link), "%s/recipients.link", dir) == GDS_OK);
    uint8_t k[4][32];
    size_t n = 0;
    write_file(path, HEX_A "\n", 0644);
    gds_status own = gds_seal_recipients_read(path, k, 4, &n);
    if(geteuid() == 0) {
        CHECK(own == GDS_OK && n == 1);
        write_file(path, HEX_A "\n", 0664); /* group-writable */
        CHECK(gds_seal_recipients_read(path, k, 4, &n) == GDS_EDENIED);
        write_file(path, HEX_A "\n", 0646); /* writable by others */
        CHECK(gds_seal_recipients_read(path, k, 4, &n) == GDS_EDENIED);
        write_file(path, HEX_A "\n", 0600);
        (void)unlink(link);
        CHECK(symlink(path, link) == 0);
        CHECK(gds_seal_recipients_read(link, k, 4, &n) == GDS_EDENIED); /* not a link */
        CHECK(gds_seal_recipients_read(dir, k, 4, &n) == GDS_EDENIED);  /* not a file */
    } else {
        CHECK(own == GDS_EDENIED); /* not root's */
    }
    CHECK(gds_seal_recipients_read("/nonexistent/recipients", k, 4, &n) != GDS_OK);
}

/* The OpenSSL CA's export: each issuer's key matches its certificate. */
static void test_openssl_export(const char *dir) {
    static uint8_t pw[] = "seal-test-passphrase";
    static gds_buf pass = {pw, sizeof(pw) - 1};
    char caDir[1100];
    CHECK(gds_path(caDir, sizeof(caDir), "%s/ca", dir) == GDS_OK);
    gds_ca_config cfg;
    gds_ca_config_init(&cfg);
    cfg.dir = caDir;
    cfg.caKeyBits = 2048;
    cfg.keyPassphrase = &pass;
    gds_ca *ca = NULL;
    if(!CHECK(gds_ca_openssl_open(&cfg, &ca) == GDS_OK && ca))
        return;
    uint8_t priv[32], pub[32];
    keypair(priv, pub);
    gds_buf blob = {0};
    CHECK(gds_ca_export_keys(ca, NULL, 0, &blob) == GDS_EINVAL); /* in process: names some */
    CHECK(gds_ca_export_keys(ca, (const uint8_t (*)[32])pub, 1, &blob) == GDS_OK);
    gds_seal_contents o;
    memset(&o, 0, sizeof(o));
    CHECK(blob.data && gds_seal_open(blob.data, blob.len, priv, &o) == GDS_OK);
    CHECK_EQ_INT(o.n, GDS_CA_ISSUERS);
    for(size_t i = 0; i < o.n; i++) {
        gds_buf want = {0};
        CHECK(gds_ca_get_issuer_cert(ca, o.items[i].issuer, &want) == GDS_OK);
        CHECK(want.len == o.items[i].cert.len &&
              memcmp(want.data, o.items[i].cert.data, want.len) == 0);
        gds_buf_free(&want);
        const unsigned char *p = o.items[i].cert.data;
        X509 *x = d2i_X509(NULL, &p, (long)o.items[i].cert.len);
        p = o.items[i].key.data;
        PKCS8_PRIV_KEY_INFO *p8 = d2i_PKCS8_PRIV_KEY_INFO(NULL, &p, (long)o.items[i].key.len);
        EVP_PKEY *k = p8 ? EVP_PKCS82PKEY(p8) : NULL;
        CHECK(x && k && X509_check_private_key(x, k) == 1);
        CHECK(o.items[i].crl.len > 0);
        EVP_PKEY_free(k);
        PKCS8_PRIV_KEY_INFO_free(p8);
        X509_free(x);
    }
    gds_seal_contents_clear(&o);
    gds_buf_free(&blob);
    gds_ca_close(ca);
}

int main(int argc, char **argv) {
    if(argc < 2) {
        fprintf(stderr, "usage: %s <dir>\n", argv[0]);
        return 2;
    }
    CHECK(gds_mkdirs(argv[1], 0700) == GDS_OK);
    test_round_trip();
    test_parse();
    test_read(argv[1]);
    test_openssl_export(argv[1]);
    return CHECK_DONE();
}
