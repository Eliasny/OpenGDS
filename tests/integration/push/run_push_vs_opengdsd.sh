#!/bin/sh
# T2 push tracer gate (OpenGDS plan, T2): gdsadm push now -> opengdsd ->
# push_test_server, end to end on localhost, all over standard OPC UA.
#   1. opengdsd with opengds-signer; gdsadm gets its own certificate from it
#      (pull_test_client stands in for that step)
#   2. the device (push_test_server) starts with its self-signed certificate,
#      trusts the GDS CA and maps gdsadm's certificate to SecurityAdmin
#   3. gdsadm apps register: the device's record in the GDS
#   4. gdsadm push now --server-cert: first push, the trust list from
#      GetTrustList, then a certificate the GDS signed, then ApplyChanges
#   5. gdsadm push now again: the device is now trusted through the GDS CA
#   6. a user without CertificateAuthorityAdmin is refused by the GDS before
#      the device is touched (CancelChanges after a failed step is covered by
#      tests/integration/test_push_flow.c)
#   7. gdsadm certs status shows the device's certificate in the store
# Usage: run_push_vs_opengdsd.sh <build-dir> <work-dir>
# SPDX-License-Identifier: MPL-2.0
set -u
B=$(cd "${1:?build dir}" && pwd)
W=${2:?work dir}
PORT=${OPENGDS_PORT:-4874}
DEV_PORT=${OPENGDS_DEV_PORT:-4875}
GDSD="$B/src/daemon/opengdsd"
SIGNER="$B/src/signer/opengds-signer"
GDSADM="$B/src/daemon/gdsadm"
PULL="$B/tools/auditor/pull_test_client"
DEV="$B/tools/auditor/push_test_server"
DEV_URI="urn:opengds:test:pushserver"

rm -rf "$W"
mkdir -p "$W"
chmod 700 "$W"
W=$(cd "$W" && pwd)
PID=""
DPID=""
cleanup() { [ -n "$PID" ] && kill "$PID" 2>/dev/null; [ -n "$DPID" ] && kill "$DPID" 2>/dev/null; true; }
trap cleanup EXIT INT TERM

fail() {
    echo "PUSH TRACER FAILED: $1"
    for l in "$W"/*.log; do [ -f "$l" ] && { echo "--- tail of $l"; tail -40 "$l"; }; done
    exit 1
}
expect() { grep -q "$1" "$2" || { cat "$2"; fail "'$1' not found in $2"; }; }
wait_log() { # wait_log <pid> <log> <what>
    i=0
    until grep -q "listening at\|Creating listen socket" "$2" 2>/dev/null; do
        i=$((i + 1))
        kill -0 "$1" 2>/dev/null || fail "$3 exited during start"
        [ $i -gt 300 ] && fail "$3 did not start in 30 s"
        sleep 0.1
    done
}

printf 'secret\n' > "$W/admin.pw"
printf 'viewer-secret\n' > "$W/viewer.pw"
printf 'push-tracer-ca-passphrase\n' > "$W/ca.pw"
chmod 600 "$W/admin.pw" "$W/viewer.pw" "$W/ca.pw"
CRED=$("$GDSADM" hash-password < "$W/admin.pw") || fail "gdsadm hash-password"
VCRED=$("$GDSADM" hash-password < "$W/viewer.pw") || fail "gdsadm hash-password"
{
    echo "admin DiscoveryAdmin,CertificateAuthorityAdmin $CRED"
    echo "viewer - $VCRED"
} > "$W/users"
chmod 600 "$W/users"
cat > "$W/opengds.conf" <<CONF
application_uri = urn:opengds:push-tracer:gds
port = $PORT
loopback_only = true
data_dir = $W/data
users_file = $W/users
ca_dir = $W/ca
signer = $SIGNER
ca_passphrase_file = $W/ca.pw
organization = OpenGDS push tracer
approval = auto
CONF

echo "=============== 1. opengdsd, and gdsadm's own certificate ==============="
"$GDSD" --config "$W/opengds.conf" > "$W/gds.log" 2>&1 &
PID=$!
wait_log "$PID" "$W/gds.log" opengdsd
GDS="opc.tcp://127.0.0.1:$PORT"
"$PULL" --gds "$GDS" --pki "$W/pki-adm" --trust "$W/ca/ca.der" --crl "$W/ca/ca.crl" \
    --user admin --password-file "$W/admin.pw" --app-uri urn:opengds:push-tracer:gdsadm \
    > "$W/adm-cert.txt" 2>&1 || { cat "$W/adm-cert.txt"; fail "gdsadm certificate"; }
ADM_CERT="$W/pki-adm/own/cert.der"
ADM_KEY="$W/pki-adm/own/private/key.der"
[ -f "$ADM_CERT" ] && [ -f "$ADM_KEY" ] || fail "no gdsadm certificate in $W/pki-adm/own"
conn() { # conn <user> <password-file>
    echo --gds "$GDS" --cert "$ADM_CERT" --key "$ADM_KEY" --trust "$W/ca/ca.der" \
        --crl "$W/ca/ca.crl" --user "$1" --password-file "$2"
}

echo "=============== 2. the device, self-signed, trusting the GDS CA ==============="
"$DEV" --port "$DEV_PORT" --pki "$W/pki-dev" --trust "$W/ca/ca.der" --crl "$W/ca/ca.crl" \
    --admin-cert "$ADM_CERT" > "$W/device.log" 2>&1 &
DPID=$!
wait_log "$DPID" "$W/device.log" push_test_server
DEV_CERT=$(ls "$W"/pki-dev/ApplCerts/own/certs/selfsigned*.der 2>/dev/null | head -1)
[ -n "$DEV_CERT" ] || fail "device has no self-signed certificate"

echo "=============== 3. gdsadm apps register ==============="
# shellcheck disable=SC2046 # conn's words are file names without spaces
"$GDSADM" apps register --uri "$DEV_URI" --name "OpenGDS push test server" --type Server \
    --discovery-url "opc.tcp://127.0.0.1:$DEV_PORT" $(conn admin "$W/admin.pw") \
    > "$W/register.txt" 2>&1 || { cat "$W/register.txt"; fail "apps register"; }
expect "registered $DEV_URI" "$W/register.txt"

echo "=============== 4. gdsadm push now (first push, pinned device certificate) ==============="
# shellcheck disable=SC2046
"$GDSADM" push now "$DEV_URI" --server-cert "$DEV_CERT" $(conn admin "$W/admin.pw") \
    > "$W/push1.txt" 2>&1 || { cat "$W/push1.txt"; fail "first push"; }
cat "$W/push1.txt"
expect "trust list updated, certificate updated, ApplyChanges done" "$W/push1.txt"
expect "the device presents the issued certificate" "$W/push1.txt"

echo "=============== 5. gdsadm push now (device trusted through the GDS CA) ==============="
# shellcheck disable=SC2046
"$GDSADM" push now "$DEV_URI" $(conn admin "$W/admin.pw") \
    > "$W/push2.txt" 2>&1 || { cat "$W/push2.txt"; fail "second push"; }
expect "the device presents the issued certificate" "$W/push2.txt"

echo "=============== 6. no CertificateAuthorityAdmin: refused ==============="
# shellcheck disable=SC2046
if "$GDSADM" push now "$DEV_URI" $(conn viewer "$W/viewer.pw") > "$W/push3.txt" 2>&1; then
    cat "$W/push3.txt"; fail "a push without CertificateAuthorityAdmin succeeded"
fi
cat "$W/push3.txt"
expect "BadUserAccessDenied" "$W/push3.txt"

echo "=============== 7. the store has the device's certificate ==============="
"$GDSADM" certs status --store "$W/data/opengds.db" > "$W/certs.txt" || fail "certs status"
grep "$DEV_URI" "$W/certs.txt" | grep -q "valid until" || { cat "$W/certs.txt"; fail "no device certificate"; }
grep "$DEV_URI" "$W/certs.txt"

# revoked <cert.der>: the certificate fails a CRL check against the GDS CA's current CRL
revoked() {
    openssl x509 -inform DER -in "$1" -out "$W/check.pem" || fail "openssl x509 $1"
    openssl x509 -inform DER -in "$W/ca/ca.der" -out "$W/ca.pem" || fail "openssl x509 ca"
    openssl crl -inform DER -in "$W/ca/ca.crl" -out "$W/crl.pem" || fail "openssl crl"
    openssl verify -CAfile "$W/ca.pem" -CRLfile "$W/crl.pem" -crl_check "$W/check.pem" \
        > "$W/verify.txt" 2>&1 && return 1
    grep -q "certificate revoked" "$W/verify.txt"
}
# The device certificates the GDS issued, newest first, taken from the GDS's
# store (read-only): the device's own file store may still be rewriting
# its files after a push, and two files can share an mtime.
NEWEST="$W/issued-newest.der"
OLDER="$W/issued-older.der"
python3 - "$W/data/opengds.db" "$DEV_URI" "$NEWEST" "$OLDER" <<'PY' || fail "the store should hold two certificates issued to the device"
import sqlite3, sys
db, uri, newest, older = sys.argv[1:5]
con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
rows = con.execute("SELECT c.der FROM certificates c JOIN applications a ON a.id = c.app_id "
                   "WHERE a.uri = ? ORDER BY c.rowid DESC LIMIT 2", (uri,)).fetchall()
if len(rows) != 2:
    sys.exit(f"{len(rows)} certificates issued to {uri}")
for path, (der,) in zip((newest, older), rows):
    with open(path, "wb") as f:
        f.write(der)
PY

echo "=============== 8. gdsadm certs revoke (no CertificateAuthorityAdmin: refused) ==============="
# shellcheck disable=SC2046
if "$GDSADM" certs revoke "$DEV_URI" --revoke-cert "$NEWEST" $(conn viewer "$W/viewer.pw") \
    > "$W/revoke0.txt" 2>&1; then
    cat "$W/revoke0.txt"; fail "a revoke without CertificateAuthorityAdmin succeeded"
fi
expect "BadUserAccessDenied" "$W/revoke0.txt"
revoked "$NEWEST" && fail "refused revoke still put the certificate on the CRL"

echo "=============== 9. gdsadm certs revoke ==============="
# shellcheck disable=SC2046
"$GDSADM" certs revoke "$DEV_URI" --revoke-cert "$NEWEST" $(conn admin "$W/admin.pw") \
    > "$W/revoke1.txt" 2>&1 || { cat "$W/revoke1.txt"; fail "certs revoke"; }
expect "revoked" "$W/revoke1.txt"
revoked "$NEWEST" || { cat "$W/verify.txt"; fail "the revoked certificate is not on the CRL"; }
revoked "$OLDER" && fail "the other certificate was revoked too"
# a certificate the GDS did not issue to this application
# shellcheck disable=SC2046
if "$GDSADM" certs revoke "$DEV_URI" --revoke-cert "$DEV_CERT" $(conn admin "$W/admin.pw") \
    > "$W/revoke2.txt" 2>&1; then
    cat "$W/revoke2.txt"; fail "revoking a self-signed certificate succeeded"
fi
expect "BadInvalidArgument" "$W/revoke2.txt"

echo "=============== 10. gdsadm apps unregister revokes the rest ==============="
# shellcheck disable=SC2046
"$GDSADM" apps unregister "$DEV_URI" $(conn admin "$W/admin.pw") \
    > "$W/unreg.txt" 2>&1 || { cat "$W/unreg.txt"; fail "apps unregister"; }
expect "unregistered $DEV_URI" "$W/unreg.txt"
revoked "$OLDER" || { cat "$W/verify.txt"; fail "unregister left a certificate off the CRL"; }
echo "PUSH TRACER PASSED"
