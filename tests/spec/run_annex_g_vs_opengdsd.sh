#!/bin/sh
# OPC 10000-12 Annex G application setup end to end with opengdsd (OpenGDS
# plan W3): gdsadm push setup (G.2), the same over Reverse Connect
# (OPC 10000-6 §7.1.3), and the libgdsclient pull agent (G.1).
#   1. opengdsd with opengds-signer; gdsadm gets its own certificate from it
#   2. a new device: push_test_server --setup, self-signed, no trust list,
#      setup credentials setup:secret
#   3. gdsadm push setup: registers the device from its own description,
#      pushes trust list + certificate, adds gdsadm to SecurityAdmin, and the
#      device leaves the application setup state
#   4. gdsadm push now without device credentials: gdsadm's certificate is
#      SecurityAdmin on the device now (Annex G.3)
#   5. gdsadm push setup again is refused: the device is configured
#   6. a device behind a firewall: push_test_server --setup
#      --reverse-connect; gdsadm push setup --reverse-port, then push now
#      --reverse-port (the existing record is reused)
#   7. examples/pull_agent: first run registers with ApplicationAdmin
#      credentials and gets a certificate and the trust list; the second
#      run uses the certificate alone, finds nothing to update and does not
#      read the unchanged trust list again
# Usage: run_annex_g_vs_opengdsd.sh <build-dir> <work-dir>
# SPDX-License-Identifier: MPL-2.0
set -u
B=$(cd "${1:?build dir}" && pwd)
W=${2:?work dir}
PORT=${OPENGDS_PORT:-4905}
DEV_PORT=$((PORT + 1))
DEV2_PORT=$((PORT + 2))
REV_PORT=$((PORT + 3))
GDSD="$B/src/daemon/opengdsd"
SIGNER="$B/src/signer/opengds-signer"
GDSADM="$B/src/daemon/gdsadm"
PULL="$B/tools/auditor/pull_test_client"
DEV="$B/tools/auditor/push_test_server"
AGENT="$B/examples/pull_agent"
DEV_URI="urn:opengds:test:pushserver"

rm -rf "$W"
mkdir -p "$W"
chmod 700 "$W"
W=$(cd "$W" && pwd)
PIDS=""
cleanup() { for p in $PIDS; do kill "$p" 2>/dev/null; done; true; }
trap cleanup EXIT INT TERM

fail() {
    echo "ANNEX G FAILED: $1"
    for l in "$W"/*.log; do [ -f "$l" ] && { echo "--- tail of $l"; tail -30 "$l"; }; done
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
printf 'secret\n' > "$W/setup.pw"
printf 'annex-g-ca-passphrase\n' > "$W/ca.pw"
chmod 600 "$W/admin.pw" "$W/setup.pw" "$W/ca.pw"
CRED=$("$GDSADM" hash-password < "$W/admin.pw") || fail "gdsadm hash-password"
echo "admin DiscoveryAdmin,CertificateAuthorityAdmin $CRED" > "$W/users"
chmod 600 "$W/users"
cat > "$W/opengds.conf" <<CONF
application_uri = urn:opengds:annex-g:gds
port = $PORT
loopback_only = true
data_dir = $W/data
users_file = $W/users
ca_dir = $W/ca
signer = $SIGNER
ca_passphrase_file = $W/ca.pw
organization = OpenGDS Annex G
approval = auto
CONF

echo "=============== 1. opengdsd, and gdsadm's own certificate ==============="
"$GDSD" --config "$W/opengds.conf" > "$W/gds.log" 2>&1 &
PID=$!
PIDS="$PIDS $PID"
wait_log "$PID" "$W/gds.log" opengdsd
GDS="opc.tcp://127.0.0.1:$PORT"
"$PULL" --gds "$GDS" --pki "$W/pki-adm" --trust "$W/ca/ca.der" --crl "$W/ca/ca.crl" \
    --user admin --password-file "$W/admin.pw" --app-uri urn:opengds:annex-g:gdsadm \
    > "$W/adm-cert.txt" 2>&1 || { cat "$W/adm-cert.txt"; fail "gdsadm certificate"; }
ADM_CERT="$W/pki-adm/own/cert.der"
ADM_KEY="$W/pki-adm/own/private/key.der"
CONN="--gds $GDS --cert $ADM_CERT --key $ADM_KEY --trust $W/ca/ca.der --crl $W/ca/ca.crl \
--user admin --password-file $W/admin.pw"
SETUP="--setup-user setup --setup-password-file $W/setup.pw"

echo "=============== 2. a new device in the application setup state ==============="
"$DEV" --port "$DEV_PORT" --pki "$W/pki-dev" --setup --admin setup:secret > "$W/device.log" 2>&1 &
DPID=$!
PIDS="$PIDS $DPID"
wait_log "$DPID" "$W/device.log" push_test_server
DEV_CERT=$(ls "$W"/pki-dev/ApplCerts/own/certs/selfsigned*.der 2>/dev/null | head -1)
[ -n "$DEV_CERT" ] || fail "device has no self-signed certificate"

echo "=============== 3. gdsadm push setup ==============="
# shellcheck disable=SC2086 # CONN and SETUP are words without spaces
"$GDSADM" push setup --server-url "opc.tcp://127.0.0.1:$DEV_PORT" --server-uri "$DEV_URI" \
    --server-cert "$DEV_CERT" $SETUP $CONN > "$W/setup1.txt" 2>&1 \
    || { cat "$W/setup1.txt"; fail "push setup"; }
cat "$W/setup1.txt"
expect "before: State NoConfiguration, InApplicationSetup TRUE" "$W/setup1.txt"
expect "registered $DEV_URI" "$W/setup1.txt"
expect "trust list updated, certificate updated, ApplyChanges done" "$W/setup1.txt"
expect "SecurityAdmin Role: our ApplicationUri added" "$W/setup1.txt"
expect "after: State Running; the device left the application setup state" "$W/setup1.txt"

echo "=============== 4. gdsadm push now: gdsadm's certificate is SecurityAdmin ==============="
# shellcheck disable=SC2086
"$GDSADM" push now "$DEV_URI" $CONN > "$W/push1.txt" 2>&1 || { cat "$W/push1.txt"; fail "push now"; }
expect "the device presents the issued certificate" "$W/push1.txt"

echo "=============== 5. gdsadm push setup again: refused ==============="
# shellcheck disable=SC2086
if "$GDSADM" push setup --server-url "opc.tcp://127.0.0.1:$DEV_PORT" --server-uri "$DEV_URI" \
    --server-cert "$DEV_CERT" $SETUP $CONN > "$W/setup2.txt" 2>&1; then
    cat "$W/setup2.txt"; fail "a configured device was set up again"
fi
expect "not in the application setup state" "$W/setup2.txt"

echo "=============== 6. a device behind a firewall: Reverse Connect ==============="
"$DEV" --port "$DEV2_PORT" --pki "$W/pki-dev2" --setup --admin setup:secret \
    --reverse-connect "opc.tcp://127.0.0.1:$REV_PORT" > "$W/device2.log" 2>&1 &
D2PID=$!
PIDS="$PIDS $D2PID"
wait_log "$D2PID" "$W/device2.log" "push_test_server (reverse)"
DEV2_CERT=$(ls "$W"/pki-dev2/ApplCerts/own/certs/selfsigned*.der 2>/dev/null | head -1)
[ -n "$DEV2_CERT" ] || fail "device 2 has no self-signed certificate"
# shellcheck disable=SC2086
"$GDSADM" push setup --reverse-port "$REV_PORT" --server-uri "$DEV_URI" \
    --server-cert "$DEV2_CERT" $SETUP $CONN > "$W/setup3.txt" 2>&1 \
    || { cat "$W/setup3.txt"; fail "push setup over Reverse Connect"; }
cat "$W/setup3.txt"
expect "registered already; using that record" "$W/setup3.txt"
expect "after: State Running; the device left the application setup state" "$W/setup3.txt"
grep -q "Reverse Connect to opc.tcp://127.0.0.1:$REV_PORT" "$W/device2.log" || fail "device 2 did not reverse connect"
# shellcheck disable=SC2086
"$GDSADM" push now "$DEV_URI" --reverse-port "$REV_PORT" $CONN > "$W/push2.txt" 2>&1 \
    || { cat "$W/push2.txt"; fail "push now over Reverse Connect"; }
expect "the device presents the issued certificate" "$W/push2.txt"

echo "=============== 7. the pull agent (Annex G.1) ==============="
"$AGENT" --gds "$GDS" --gds-uri urn:opengds:annex-g:gds --trust "$W/ca/ca.der" \
    --crl "$W/ca/ca.crl" --app-uri urn:opengds:annex-g:app --name "Annex G app" \
    --dir "$W/app" --user admin --password-file "$W/admin.pw" > "$W/agent1.txt" 2>&1 \
    || { cat "$W/agent1.txt"; fail "pull agent, first run"; }
cat "$W/agent1.txt"
expect "registered urn:opengds:annex-g:app" "$W/agent1.txt"
expect "certificate issued" "$W/agent1.txt"
expect "trust list updated" "$W/agent1.txt"
[ -f "$W/app/issuer0.der" ] || fail "no issuer chain stored"
grep -rq "secret" "$W/app" && fail "the agent stored the password"
"$AGENT" --gds "$GDS" --gds-uri urn:opengds:annex-g:gds --trust "$W/ca/ca.der" \
    --crl "$W/ca/ca.crl" --app-uri urn:opengds:annex-g:app --name "Annex G app" \
    --dir "$W/app" > "$W/agent2.txt" 2>&1 || { cat "$W/agent2.txt"; fail "pull agent, second run"; }
cat "$W/agent2.txt"
expect "update required: no" "$W/agent2.txt"
grep -q "registered\|certificate issued" "$W/agent2.txt" && fail "second run registered or renewed"
# Table 21: LastUpdateTime did not move, so the TrustList is not read again
grep -q "trust list updated" "$W/agent2.txt" && fail "second run downloaded an unchanged trust list"
"$GDSADM" certs status --store "$W/data/opengds.db" > "$W/certs.txt" || fail "certs status"
grep "urn:opengds:annex-g:app" "$W/certs.txt" | grep -q "valid until" \
    || { cat "$W/certs.txt"; fail "no certificate for the pull agent's application"; }
echo "ANNEX G PASSED"
