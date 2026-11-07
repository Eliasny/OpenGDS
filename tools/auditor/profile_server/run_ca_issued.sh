#!/bin/sh
# The server profile against a target whose own certificate is CA-issued
# (a device already pushed by a GDS): without the issuer every session
# fails; with --target-trust/--target-crl the read-only tests run.
# Usage: run_ca_issued.sh <bindir> <workdir> <port>
# SPDX-License-Identifier: MPL-2.0
set -u
B=$(cd "$1" && pwd)
rm -rf "$2"
mkdir -p "$2"
chmod 700 "$2"
W=$(cd "$2" && pwd)
PORT=$3
O=${OPENSSL:-openssl}
SRV=""
trap '[ -n "$SRV" ] && kill "$SRV" 2>/dev/null; true' EXIT INT TERM
cd "$W" || exit 2

cat > ca.cnf <<'EOF'
[req]
distinguished_name=dn
[dn]
[v3_ca]
basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
[leaf]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,nonRepudiation,keyEncipherment,dataEncipherment
extendedKeyUsage=serverAuth,clientAuth
subjectAltName=URI:urn:opengds:test:pushserver,DNS:localhost
authorityKeyIdentifier=keyid
subjectKeyIdentifier=hash
[ca]
default_ca=CA_default
[CA_default]
database=index.txt
crlnumber=crlnum
default_md=sha256
default_crl_days=30
EOF
: > index.txt
echo 01 > crlnum
mkdir -p pki/ApplCerts/own/certs pki/ApplCerts/own/private
{
    "$O" req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.pem -subj "/CN=Other GDS CA" \
        -days 30 -config ca.cnf -extensions v3_ca &&
    "$O" req -newkey rsa:2048 -nodes -keyout srv.key -out srv.csr -subj "/CN=Push Test Server" \
        -config ca.cnf &&
    "$O" x509 -req -in srv.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out srv.pem -days 20 \
        -extfile ca.cnf -extensions leaf &&
    "$O" ca -gencrl -keyfile ca.key -cert ca.pem -out ca.crl.pem -config ca.cnf &&
    "$O" x509 -in ca.pem -outform DER -out ca.der &&
    "$O" crl -in ca.crl.pem -outform DER -out ca.crl &&
    "$O" x509 -in srv.pem -outform DER -out pki/ApplCerts/own/certs/srv.der &&
    "$O" pkey -in srv.key -outform DER -out pki/ApplCerts/own/private/srv.key
} > openssl.log 2>&1 || { echo "openssl failed:"; cat openssl.log; exit 2; }

"$B/gdsaudit" server --work "$W/aud" --init-only > /dev/null || exit 2
"$B/push_test_server" --port "$PORT" --pki "$W/pki" --trust "$W/aud/own/cert.der" \
    --trust "$W/aud/admin/own/cert.der" --admin-cert "$W/aud/admin/own/cert.der" > server.log 2>&1 &
SRV=$!
i=0
until grep -q "Creating listen socket" server.log 2>/dev/null; do
    i=$((i + 1))
    if [ $i -gt 100 ]; then echo "push_test_server did not start:"; cat server.log; exit 2; fi
    sleep 0.1
done

audit() {
    "$B/gdsaudit" server --url "opc.tcp://127.0.0.1:$PORT" \
        --server-cert "$W/pki/ApplCerts/own/certs/srv.der" --work "$W/aud" --only SRV-CAP-01 "$@"
}
RC=0
audit > without.tap 2>&1
if ! grep -q "BadCertificateChainIncomplete" without.tap; then
    echo "FAILED: without the target's issuer the session should fail on the chain"
    cat without.tap
    RC=1
fi
audit --target-trust "$W/ca.der" --target-crl "$W/ca.crl" > with.tap 2>&1
if ! grep -q "^ok .* SRV-CAP-01" with.tap || ! grep -q "verdict: pass" with.tap; then
    echo "FAILED: with --target-trust and --target-crl SRV-CAP-01 should pass"
    cat with.tap
    RC=1
fi
[ $RC -eq 0 ] && echo "CA-issued target: chain refused without the issuer, SRV-CAP-01 passes with it"
exit $RC
