#!/bin/sh
# OpenGDS Auditor self-test: pull and push workflows end to end on localhost.
# Pull client <-> mock GDS, push driver -> push test server, restart
# persistence, and a non-admin refused with BadUserAccessDenied.
# SPDX-License-Identifier: MPL-2.0
#
# Usage: run_demo.sh <bin-dir> [<work-dir>]
#   PULL_PORT, PUSH_PORT  override the ports (defaults 4850, 4841)
set -eu

B=${1:?usage: run_demo.sh <bin-dir> [<work-dir>]}
W=${2:-./demo-run}
PULL_PORT=${PULL_PORT:-4850}
PUSH_PORT=${PUSH_PORT:-4841}

rm -rf "$W"
mkdir -p "$W"
chmod 700 "$W"
GDS=""
SRV=""
cleanup() { [ -n "$GDS" ] && kill "$GDS" 2>/dev/null; [ -n "$SRV" ] && kill "$SRV" 2>/dev/null; true; }
trap cleanup EXIT INT TERM

# Wait for the "Creating listen socket" log line, at most 10 s
wait_listen() {
    i=0
    until grep -q "Creating listen socket" "$1" 2>/dev/null; do
        i=$((i + 1))
        if [ $i -gt 100 ]; then echo "server did not start:"; cat "$1"; exit 1; fi
        sleep 0.1
    done
}
expect() { # expect <pattern> <file>: fail the self-test if the pattern is missing
    if ! grep -q "$1" "$2"; then echo "SELFTEST FAILED: '$1' not found in $2"; cat "$2"; exit 1; fi
}

printf 'secret\n' > "$W/registrar.pw"
chmod 600 "$W/registrar.pw"

echo "=============== PULL: test client <-> mock GDS ==============="
"$B/mock_gds" --port "$PULL_PORT" --ca-dir "$W/ca" --approve-after 2 > "$W/mock_gds.log" 2>&1 &
GDS=$!
wait_listen "$W/mock_gds.log"
"$B/pull_test_client" --gds "opc.tcp://localhost:$PULL_PORT" --pki "$W/pki-pull" \
    --trust "$W/ca/ca.der" --crl "$W/ca/ca.crl" --user registrar \
    --password-file "$W/registrar.pw" | tee "$W/pull1.log"
expect "PULL WORKFLOW COMPLETE" "$W/pull1.log"
expect "BadNothingToDo" "$W/pull1.log"
echo "--- second run: already registered, certificate up to date ---"
"$B/pull_test_client" --gds "opc.tcp://localhost:$PULL_PORT" --pki "$W/pki-pull" \
    --trust "$W/ca/ca.der" --crl "$W/ca/ca.crl" --user registrar \
    --password-file "$W/registrar.pw" > "$W/pull2.log"
grep -E "already|updateRequired|COMPLETE" "$W/pull2.log"
expect "already registered" "$W/pull2.log"
expect "updateRequired = false" "$W/pull2.log"
echo "--- pull client must refuse a GDS it was not told to trust ---"
if "$B/pull_test_client" --gds "opc.tcp://localhost:$PULL_PORT" --pki "$W/pki-rogue" \
    --trust "$W/pki-pull/own/cert.der" --user registrar \
    --password-file "$W/registrar.pw" > "$W/pull-rogue.log" 2>&1; then
    echo "SELFTEST FAILED: connected to an untrusted GDS"; exit 1
fi
expect "FAILED: connect" "$W/pull-rogue.log"
echo "refused as expected"

echo
echo "=============== PUSH: push driver -> test server ==============="
"$B/push_driver" --ca-dir "$W/ca" --init-only
"$B/push_test_server" --port "$PUSH_PORT" --pki "$W/pki-push" \
    --trust "$W/ca/ca.der" --crl "$W/ca/ca.crl" \
    --admin-cert "$W/ca/pushdriver.der" > "$W/push_server.log" 2>&1 &
SRV=$!
wait_listen "$W/push_server.log"
"$B/push_driver" --server "opc.tcp://localhost:$PUSH_PORT" --ca-dir "$W/ca" --tofu \
    | tee "$W/push1.log"
expect "PUSH WORKFLOW COMPLETE" "$W/push1.log"

echo
echo "=============== RESTART: pushed state must survive ==============="
kill "$SRV"; wait "$SRV" 2>/dev/null || true
"$B/push_test_server" --port "$PUSH_PORT" --pki "$W/pki-push" > "$W/push_server2.log" 2>&1 &
SRV=$!
wait_listen "$W/push_server2.log"
grep -o "Own certificate [0-9A-F]*.*" "$W/push_server2.log" | cut -c1-140
expect "issuer=/O=OpenGDS Auditor TEST" "$W/push_server2.log"
echo "(no --admin-cert this time: the push driver must now be refused)"
"$B/push_driver" --server "opc.tcp://localhost:$PUSH_PORT" --ca-dir "$W/ca" --tofu \
    > "$W/push2.log" 2>&1 || true
grep -E "current|connected|TrustList.Open|FAILED" "$W/push2.log" || true
expect "BadUserAccessDenied" "$W/push2.log"

echo
echo "SELFTEST PASSED"
