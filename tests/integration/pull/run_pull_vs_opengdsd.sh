#!/bin/sh
# T1 pull tracer: opengdsd with opengds-signer, end to end on localhost.
#   1. gdsaudit gds: every T0 spec test, verdicts pinned in expected/opengds.csv
#   2. pull_test_client: register, sign, FinishRequest, trust list
#   3. restart opengdsd: records, certificates and the GDS's own certificate
#      persist; the client finds itself registered and up to date
#   4. gdsadm reads the store while opengdsd runs
#   5. the production split: opengds-signer socket-activated in its own
#      process tree (systemd-socket-activate, as opengds-signer.socket does),
#      opengdsd connecting through signer_socket
#   6. opengds-signer --listen (hosts without systemd, e.g. containers):
#      started before opengdsd has created the store (a first start), then
#      one signer serves successive opengdsd connections
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

echo "=============== 5. socket-activated signer (signer_socket) ==============="
if command -v systemd-socket-activate > /dev/null 2>&1; then
    # a short path: sun_path holds at most 107 bytes
    SOCKDIR=$(mktemp -d /tmp/ogs-pull.XXXXXX)
    SOCK="$SOCKDIR/signer.sock"
    systemd-socket-activate --seqpacket -a -l "$SOCK" \
        "$SIGNER" --fd systemd --store "$W/data/opengds.db" --ca-dir "$W/ca" \
        --passphrase-file "$W/ca.pw" > "$W/activate.log" 2>&1 &
    ACT=$!
    trap 'cleanup; kill "$ACT" 2>/dev/null; rm -rf "$SOCKDIR"; true' EXIT INT TERM
    i=0
    until [ -S "$SOCK" ]; do
        i=$((i + 1)); [ $i -gt 100 ] && fail "socket activation did not listen"; sleep 0.1
    done
    sed -e '/^signer = /d' -e '/^ca_passphrase_file = /d' "$W/opengds.conf" > "$W/socket.conf"
    echo "signer_socket = $SOCK" >> "$W/socket.conf"
    cp "$W/socket.conf" "$W/opengds.conf"
    start_gds "$W/gds3.log"
    "$PULL" --gds "opc.tcp://127.0.0.1:$PORT" --pki "$W/pki-pull2" --trust "$W/ca/ca.der" \
        --crl "$W/ca/ca.crl" --user registrar --password-file "$W/registrar.pw" \
        --app-uri "urn:opengds:pull-tracer:second" > "$W/pull3.log" 2>&1 \
        || { cat "$W/pull3.log" "$W/activate.log"; fail "pull through the socket-activated signer"; }
    expect "PULL WORKFLOW COMPLETE" "$W/pull3.log"
    stop_gds
    kill "$ACT" 2>/dev/null
else
    echo "SKIPPED: systemd-socket-activate not installed"
fi
echo "=============== 6. listening signer (--listen) ==============="
LDIR=$(mktemp -d /tmp/ogs-listen.XXXXXX)
LSOCK="$LDIR/signer.sock"
trap 'cleanup; kill "$LST" 2>/dev/null; rm -rf "$LDIR"; true' EXIT INT TERM
LST=""
# data-listen does not exist yet: opengdsd creates the store after the
# signer starts. As root, the signer runs the production way: its own uid
# (65534) in opengdsd's group (0 here), its own CA directory, and the
# store mounted read-only (ReadOnlyPaths= in signer@, :ro in compose).
if [ "$(id -u)" = 0 ] && command -v setpriv > /dev/null && command -v unshare > /dev/null \
   && unshare -m true 2> /dev/null; then
    SEP=1
    mkdir -p "$W/data-listen" "$LDIR/store" "$LDIR/ca"
    chmod 0750 "$W/data-listen" "$LDIR"
    cp "$W/ca.pw" "$LDIR/ca.pw"
    cp -p "$W/ca/"* "$LDIR/ca/" # the same CA, now owned by the signer's user
    chown -R 65534:0 "$LDIR"
    chmod 0711 "$W" # opengdsd's work dir: the signer may only traverse it
    LCA="$LDIR/ca"
    unshare -m sh -c 'mount --bind "$1" "$2" && mount -o remount,bind,ro "$2" && shift 2 && \
        exec setpriv --reuid 65534 --regid 0 --clear-groups -- "$@"' sh \
        "$W/data-listen" "$LDIR/store" \
        "$SIGNER" --listen "$LSOCK" --store "$LDIR/store/opengds.db" --ca-dir "$LCA" \
        --passphrase-file "$LDIR/ca.pw" > "$W/listen.log" 2>&1 &
    LST=$!
else
    SEP=0
    echo "(signer under the same uid: separate-user check needs root, setpriv and unshare)"
    LCA="$W/ca"
    "$SIGNER" --listen "$LSOCK" --store "$W/data-listen/opengds.db" --ca-dir "$LCA" \
        --passphrase-file "$W/ca.pw" > "$W/listen.log" 2>&1 &
    LST=$!
fi
i=0
until [ -S "$LSOCK" ]; do
    i=$((i + 1)); kill -0 "$LST" 2>/dev/null || { cat "$W/listen.log"; fail "signer --listen exited"; }
    [ $i -gt 100 ] && fail "signer --listen did not listen"; sleep 0.1
done
[ "$(stat -c %a "$LSOCK")" = "660" ] || fail "--listen socket mode is $(stat -c %a "$LSOCK"), not 660"
sed -e '/^signer = /d' -e '/^signer_socket = /d' -e '/^ca_passphrase_file = /d' \
    -e "s#^data_dir = .*#data_dir = $W/data-listen#" "$W/opengds.conf" > "$W/listen.conf"
echo "signer_socket = $LSOCK" >> "$W/listen.conf"
cp "$W/listen.conf" "$W/opengds.conf"
for n in 1 2; do # the second start is a second connection to the same signer
    start_gds "$W/gds-listen$n.log"
    "$PULL" --gds "opc.tcp://127.0.0.1:$PORT" --pki "$W/pki-listen$n" --trust "$LCA/ca.der" \
        --crl "$LCA/ca.crl" --user registrar --password-file "$W/registrar.pw" \
        --app-uri "urn:opengds:pull-tracer:listen$n" > "$W/pull-listen$n.log" 2>&1 \
        || { cat "$W/pull-listen$n.log" "$W/listen.log"; fail "pull through signer --listen ($n)"; }
    expect "PULL WORKFLOW COMPLETE" "$W/pull-listen$n.log"
    [ "$(stat -c %a "$W/data-listen/opengds.db")" = "640" ] || fail "store is not 0640"
    stop_gds
done
[ "$SEP" = 1 ] && echo "signer ran as uid 65534 on a read-only store mount"
kill -0 "$LST" 2>/dev/null || { cat "$W/listen.log"; fail "signer --listen exited after a connection"; }
kill "$LST" 2>/dev/null
echo "PULL TRACER PASSED"
