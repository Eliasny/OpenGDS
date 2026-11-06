#!/bin/sh
# T1 pull tracer: opengdsd with opengds-signer, end to end on localhost.
#   1. gdsaudit gds: every T0 spec test, verdicts pinned in expected/opengds.csv
#   2. pull_test_client: register, sign, FinishRequest, trust list
#   3. restart opengdsd: records, certificates and the GDS's own certificate
#      persist; the client finds itself registered and up to date
#   4. gdsadm reads the store while opengdsd runs
# Usage: run_pull_vs_opengdsd.sh <build-dir> <work-dir> <expected.csv>
# SPDX-License-Identifier: MPL-2.0
set -u
B=$(cd "${1:?build dir}" && pwd)
W=${2:?work dir}
EXPECT=${3:?expected csv}
PORT=${OPENGDS_PORT:-4854}
GDSD="$B/src/daemon/opengdsd"
SIGNER="$B/src/signer/opengds-signer"
GDSADM="$B/src/daemon/gdsadm"
AUDIT="$B/tools/auditor/gdsaudit"
PULL="$B/tools/auditor/pull_test_client"

rm -rf "$W"
mkdir -p "$W"
chmod 700 "$W"
W=$(cd "$W" && pwd)
PID=""
cleanup() { [ -n "$PID" ] && kill "$PID" 2>/dev/null; true; }
trap cleanup EXIT INT TERM

fail() {
    echo "PULL TRACER FAILED: $1"
    for l in "$W"/gds*.log; do [ -f "$l" ] && { echo "--- tail of $l"; tail -40 "$l"; }; done
    exit 1
}
expect() { grep -q "$1" "$2" || { cat "$2"; fail "'$1' not found in $2"; }; }

start_gds() { # start_gds <log>
    "$GDSD" --config "$W/opengds.conf" > "$1" 2>&1 &
    PID=$!
    i=0
    until grep -q "listening at\|Creating listen socket" "$1" 2>/dev/null; do
        i=$((i + 1))
        kill -0 "$PID" 2>/dev/null || fail "opengdsd exited during start"
        [ $i -gt 300 ] && fail "opengdsd did not start in 30 s"
        sleep 0.1
    done
}
stop_gds() {
    kill -TERM "$PID"
    wait "$PID" || fail "opengdsd did not exit cleanly on SIGTERM"
    PID=""
}

printf 'secret\n' > "$W/registrar.pw"
printf 'pull-tracer-ca-passphrase\n' > "$W/ca.pw"
chmod 600 "$W/registrar.pw" "$W/ca.pw"
CRED=$("$GDSADM" hash-password < "$W/registrar.pw") || fail "gdsadm hash-password"
echo "registrar DiscoveryAdmin,CertificateAuthorityAdmin,SecurityAdmin $CRED" > "$W/users"
chmod 600 "$W/users"
cat > "$W/opengds.conf" <<CONF
application_uri = urn:opengds:pull-tracer:gds
port = $PORT
loopback_only = true
data_dir = $W/data
users_file = $W/users
ca_dir = $W/ca
signer = $SIGNER
ca_passphrase_file = $W/ca.pw
organization = OpenGDS pull tracer
CONF

echo "=============== 1. gdsaudit gds -> opengdsd ==============="
start_gds "$W/gds1.log"
"$AUDIT" gds --url "opc.tcp://127.0.0.1:$PORT" --trust "$W/ca/ca.der" --crl "$W/ca/ca.crl" \
    --user registrar --password-file "$W/registrar.pw" --work "$W/auditor" \
    --allow-changes --poll-seconds 10 --expect "$EXPECT" || fail "gdsaudit verdicts differ"

echo "=============== 2. pull_test_client -> opengdsd ==============="
"$PULL" --gds "opc.tcp://127.0.0.1:$PORT" --pki "$W/pki-pull" --trust "$W/ca/ca.der" \
    --crl "$W/ca/ca.crl" --user registrar --password-file "$W/registrar.pw" \
    > "$W/pull1.log" 2>&1 || { cat "$W/pull1.log"; fail "first pull run"; }
expect "PULL WORKFLOW COMPLETE" "$W/pull1.log"
OWN1=$(sha256sum "$W/data/own/cert.der" | cut -d' ' -f1)

echo "=============== 3. restart: state persists ==============="
stop_gds
start_gds "$W/gds2.log"
grep -q "issuing the GDS's own certificate" "$W/gds2.log" && fail "own certificate reissued"
OWN2=$(sha256sum "$W/data/own/cert.der" | cut -d' ' -f1)
[ "$OWN1" = "$OWN2" ] || fail "own certificate changed across restart"
"$PULL" --gds "opc.tcp://127.0.0.1:$PORT" --pki "$W/pki-pull" --trust "$W/ca/ca.der" \
    --crl "$W/ca/ca.crl" --user registrar --password-file "$W/registrar.pw" \
    > "$W/pull2.log" 2>&1 || { cat "$W/pull2.log"; fail "second pull run"; }
expect "already registered" "$W/pull2.log"
expect "updateRequired = false" "$W/pull2.log"

echo "=============== 4. gdsadm reads the live store ==============="
"$GDSADM" apps list --store "$W/data/opengds.db" > "$W/apps.txt" || fail "gdsadm apps list"
expect "urn:opengds:pull-tracer:gds" "$W/apps.txt"
"$GDSADM" certs status --store "$W/data/opengds.db" > "$W/certs.txt" || fail "gdsadm certs status"
expect "valid until" "$W/certs.txt"
cat "$W/apps.txt"
stop_gds
echo "PULL TRACER PASSED"
