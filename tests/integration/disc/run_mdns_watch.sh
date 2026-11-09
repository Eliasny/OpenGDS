#!/bin/sh
# mDNS announce and gdsadm watch against opengdsd (OpenGDS plan W5).
#   1. `mdns = true` with `loopback_only = true` is refused at start
#   2. opengdsd with `mdns = false`: FindServersOnNetwork lists no GDS
#   3. opengdsd with `mdns = true`: the Auditor's discover (an independent
#      client) finds the GDS by FindServersOnNetwork (OPC 10000-4 §5.5.3)
#      with its DiscoveryUrl and the capability GDS (OPC 10000-12 Annex C,
#      Annex D); skipped where the host cannot open the multicast socket
#   4. gdsadm watch --json: a certificate request that waits for approval
#      (approval = manual) shows as its DialogCondition, live
#   5. gdsadm watch (text) started later: ConditionRefresh shows the
#      waiting request (OPC 10000-9 §5.5.7); approving it ends the wait
#   6. gdsadm watch with a wrong password fails (exit 1)
# Usage: run_mdns_watch.sh <build-dir> <work-dir>
# SPDX-License-Identifier: MPL-2.0
set -u
B=$(cd "${1:?build dir}" && pwd)
W=${2:?work dir}
PORT=${OPENGDS_PORT:-4856}
GDSD="$B/src/daemon/opengdsd"
SIGNER="$B/src/signer/opengds-signer"
GDSADM="$B/src/daemon/gdsadm"
AUDIT="$B/tools/auditor/gdsaudit"
PULL="$B/tools/auditor/pull_test_client"
URL="opc.tcp://127.0.0.1:$PORT"

rm -rf "$W"
mkdir -p "$W"
chmod 700 "$W"
W=$(cd "$W" && pwd)
PID=""
BG=""
cleanup() {
    [ -n "$PID" ] && kill "$PID" 2>/dev/null
    for p in $BG; do kill "$p" 2>/dev/null; done
    true
}
trap cleanup EXIT INT TERM

fail() {
    echo "MDNS/WATCH TEST FAILED: $1"
    for l in "$W"/*.log; do [ -f "$l" ] && { echo "--- tail of $l"; tail -30 "$l"; }; done
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

printf 'secret\n' > "$W/admin.pw"
printf 'wrong\n' > "$W/wrong.pw"
printf 'mdns-watch-ca-passphrase\n' > "$W/ca.pw"
chmod 600 "$W/admin.pw" "$W/wrong.pw" "$W/ca.pw"
CRED=$("$GDSADM" hash-password < "$W/admin.pw") || fail "gdsadm hash-password"
echo "registrar DiscoveryAdmin,CertificateAuthorityAdmin $CRED" > "$W/users"
echo "approver RegistrationAuthorityAdmin $CRED" >> "$W/users"
chmod 600 "$W/users"
base_conf() {
    cat <<CONF
application_uri = urn:opengds:mdns-watch:gds
application_name = OpenGDS mdns watch
port = $PORT
data_dir = $W/data
users_file = $W/users
ca_dir = $W/ca
signer = $SIGNER
ca_passphrase_file = $W/ca.pw
approval = manual
CONF
}

echo "=============== 1. mdns with loopback_only is refused ==============="
{ base_conf; echo "loopback_only = true"; echo "mdns = true"; } > "$W/opengds.conf"
"$GDSD" --config "$W/opengds.conf" > "$W/refused.txt" 2>&1 && fail "opengdsd started"
expect "mdns and loopback_only" "$W/refused.txt"

echo "=============== 2. mdns off: no record on the network ==============="
{ base_conf; echo "hostname = 127.0.0.1"; } > "$W/opengds.conf"
start_gds "$W/gds-off.log"
"$AUDIT" discover --url "$URL" --network > "$W/discover-off.txt" 2>&1
grep "^network" "$W/discover-off.txt" | grep -q "GDS" && fail "a GDS record without mdns"
stop_gds

echo "=============== 3. mdns on: FindServersOnNetwork finds the GDS ==============="
{ base_conf; echo "hostname = 127.0.0.1"; echo "mdns = true"; } > "$W/opengds.conf"
start_gds "$W/gds.log"
FOUND=0
i=0
while [ $i -lt 30 ]; do
    "$AUDIT" discover --url "$URL" --network > "$W/discover.txt" 2>&1
    if grep "^network" "$W/discover.txt" | grep -q "$URL	GDS\$"; then FOUND=1; break; fi
    i=$((i + 1)); sleep 0.2
done
if [ $FOUND = 1 ]; then
    grep "^network" "$W/discover.txt" | grep -q "OpenGDS mdns watch" \
        || fail "the record does not carry the ApplicationName"
    grep "^network" "$W/discover.txt"
elif grep -q "Could not create multicast socket\|No UDP communication" "$W/gds.log"; then
    echo "SKIPPED: no multicast socket on this host"
else
    cat "$W/discover.txt"
    fail "FindServersOnNetwork did not return the GDS"
fi

echo "=============== 4. gdsadm watch --json: a request waits ==============="
WATCH="--url $URL --password-file $W/admin.pw --trust $W/ca/ca.der --crl $W/ca/ca.crl"
# shellcheck disable=SC2086 # WATCH is a list of words
"$GDSADM" watch $WATCH --user approver --json --count 1 --seconds 60 \
    > "$W/watch.json" 2> "$W/watch-json.log" &
WP=$!
BG="$WP"
sleep 2 # the subscription is up before the request arrives
"$PULL" --gds "$URL" --pki "$W/pki" --trust "$W/ca/ca.der" --crl "$W/ca/ca.crl" \
    --user registrar --password-file "$W/admin.pw" --app-uri "urn:opengds:mdns-watch:device" \
    --poll-seconds 60 > "$W/pull.log" 2>&1 &
PC=$!
BG="$WP $PC"
wait "$WP" || fail "gdsadm watch --json exited with an error"
cat "$W/watch.json"
expect '"eventType":"DialogConditionType"' "$W/watch.json"
expect '"refresh":false' "$W/watch.json"
expect '"conditionId":"ns=1;g=' "$W/watch.json"
python3 -c 'import json,sys; [json.loads(l) for l in open(sys.argv[1])]' "$W/watch.json" \
    || fail "gdsadm watch --json wrote a line that is not JSON"

echo "=============== 5. gdsadm watch: ConditionRefresh shows the waiting request ==============="
# shellcheck disable=SC2086
"$GDSADM" watch $WATCH --user approver --count 1 --seconds 30 > "$W/watch.txt" 2> "$W/watch-text.log" \
    || fail "gdsadm watch exited with an error"
cat "$W/watch.txt"
expect "DialogConditionType" "$W/watch.txt"
expect "(refresh)" "$W/watch.txt"
RID=$("$GDSADM" approvals list --store "$W/data/opengds.db" | grep "urn:opengds:mdns-watch:device" | cut -f1)
[ -n "$RID" ] || fail "no request waits for approval"
# shellcheck disable=SC2086
"$GDSADM" approvals approve --url "$URL" --password-file "$W/admin.pw" --trust "$W/ca/ca.der" \
    --crl "$W/ca/ca.crl" --user approver "$RID" > "$W/approve.log" 2>&1 || fail "approve"
wait "$PC" || { cat "$W/pull.log"; fail "pull after approval"; }
expect "PULL WORKFLOW COMPLETE" "$W/pull.log"

echo "=============== 6. gdsadm watch refuses a wrong password ==============="
"$GDSADM" watch --url "$URL" --password-file "$W/wrong.pw" --trust "$W/ca/ca.der" \
    --user approver --seconds 5 > /dev/null 2> "$W/watch-wrong.txt" && fail "watched with a wrong password"
expect "connecting to" "$W/watch-wrong.txt"
stop_gds
echo "MDNS/WATCH TEST PASSED"
