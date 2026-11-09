#!/bin/sh
# OpenGDS performance run (OpenGDS plan, "Performance design and targets";
# docs/perf.md). opengdsd with opengds-signer on localhost, approval = auto:
#   1. bench_sign: CA slot issuance against the bare OpenSSL signature
#   2. bench_register: RegisterApplication rate, store filled to $APPS
#   3. memory: opengdsd and signer resident set at $APPS records
#   4. load_pull: $AGENTS concurrent sessions, then the pull workflow each
#   5. cold start: opengdsd restarted on the full store, time to listening
#   6. load_push: $DEVICES push_test_server devices, $PUSH_PARALLEL parallel
#      push sessions, $PUSH_JOBS pushes
# Every RESULT line goes to <work-dir>/results.txt.
# Usage: run_perf.sh <build-dir> <work-dir>
# SPDX-License-Identifier: MPL-2.0
set -u
B=$(cd "${1:?build dir}" && pwd)
W=${2:?work dir}
APPS=${APPS:-50000}
REG_THREADS=${REG_THREADS:-16}
AGENTS=${AGENTS:-500}
DEVICES=${DEVICES:-64}
PUSH_PARALLEL=${PUSH_PARALLEL:-64}
PUSH_JOBS=${PUSH_JOBS:-256}
SIGN_SECONDS=${SIGN_SECONDS:-5}
PORT=${OPENGDS_PORT:-4890}
DEV_PORT0=${OPENGDS_DEV_PORT:-4900}
P="$B/tests/perf"
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
R="$W/results.txt"
: > "$R"
PID=""
DPIDS=""
cleanup() {
    [ -n "$PID" ] && kill "$PID" 2>/dev/null
    for d in $DPIDS; do kill "$d" 2>/dev/null; done
    true
}
trap cleanup EXIT INT TERM
fail() {
    echo "PERF RUN FAILED: $1"
    for l in "$W"/gds*.log; do [ -f "$l" ] && { echo "--- tail of $l"; tail -30 "$l"; }; done
    exit 1
}
# Each push_test_server's file certificate stores take inotify instances
# (open62541 filestore); the Linux default of 128 per user stops at about 60
# devices with "server config failed: BadInternalError".
INO=$(cat /proc/sys/fs/inotify/max_user_instances 2>/dev/null || echo 0)
if [ "$INO" -lt $((DEVICES * 2 + 32)) ]; then
    fail "fs.inotify.max_user_instances is $INO; $DEVICES devices need $((DEVICES * 2 + 32)) (sysctl -w fs.inotify.max_user_instances=1024)"
fi
# run <log> <cmd...>: RESULT and ERRORS lines to results.txt, the rest to the log
run() {
    log=$1
    shift
    "$@" > "$W/$log" 2>&1
    rc=$?
    grep -E '^(RESULT|ERRORS|#)' "$W/$log" | tee -a "$R"
    return $rc
}
result() { echo "RESULT $1 $2 $3" | tee -a "$R"; }
now_ms() { date +%s%3N; }
wait_listen() { # wait_listen <pid> <log> <what>
    w=0
    until grep -q "listening at\|Creating listen socket" "$2" 2>/dev/null; do
        w=$((w + 1))
        kill -0 "$1" 2>/dev/null || fail "$3 exited during start"
        [ $w -gt 6000 ] && fail "$3 did not start in 60 s"
        sleep 0.01
    done
}
rss_kib() { awk '/^VmRSS:/ { print $2 }' "/proc/$1/status" 2>/dev/null || echo 0; }
signer_pid() { pgrep -P "$PID" -f opengds-signer | head -1; }
GDS_RUN=0
start_gds() { # every start has its own log: gds1.log, gds2.log, ...
    GDS_RUN=$((GDS_RUN + 1))
    "$GDSD" --config "$W/opengds.conf" > "$W/gds$GDS_RUN.log" 2>&1 &
    PID=$!
    wait_listen "$PID" "$W/gds$GDS_RUN.log" opengdsd
}
stop_gds() {
    kill -TERM "$PID"
    wait "$PID" || fail "opengdsd did not exit cleanly"
    PID=""
}

{
    echo "# host: $(uname -srm), $(nproc) CPUs, $(awk '/MemTotal/ {print int($2/1024)" MiB"}' /proc/meminfo)"
    echo "# cpu: $(awk -F': ' '/model name/ {print $2; exit}' /proc/cpuinfo)"
    echo "# date: $(date -u +%Y-%m-%dT%H:%MZ), APPS=$APPS AGENTS=$AGENTS DEVICES=$DEVICES PUSH_PARALLEL=$PUSH_PARALLEL PUSH_JOBS=$PUSH_JOBS"
} | tee -a "$R"

echo "=============== 1. bench_sign ==============="
run sign.log "$P/bench_sign" --dir "$W/sign-ca" --seconds "$SIGN_SECONDS" || fail "bench_sign"

printf 'perf-secret\n' > "$W/admin.pw"
printf 'perf-ca-passphrase\n' > "$W/ca.pw"
chmod 600 "$W/admin.pw" "$W/ca.pw"
CRED=$("$GDSADM" hash-password < "$W/admin.pw") || fail "gdsadm hash-password"
echo "admin DiscoveryAdmin,CertificateAuthorityAdmin,SecurityAdmin $CRED" > "$W/users"
chmod 600 "$W/users"
cat > "$W/opengds.conf" <<CONF
application_uri = urn:opengds:perf:gds
port = $PORT
loopback_only = true
data_dir = $W/data
users_file = $W/users
ca_dir = $W/ca
signer = $SIGNER
ca_passphrase_file = $W/ca.pw
organization = OpenGDS perf
approval = auto
CONF
start_gds
GDS="opc.tcp://127.0.0.1:$PORT"
# The tools' own certificate, issued by the GDS (as in the push tracer)
"$PULL" --gds "$GDS" --pki "$W/pki-adm" --trust "$W/ca/ca.der" --crl "$W/ca/ca.crl" \
    --user admin --password-file "$W/admin.pw" --app-uri urn:opengds:perf:tools \
    > "$W/adm-cert.log" 2>&1 || { cat "$W/adm-cert.log"; fail "tools certificate"; }
CERT="$W/pki-adm/own/cert.der"
KEY="$W/pki-adm/own/private/key.der"
set -- --gds "$GDS" --cert "$CERT" --key "$KEY" --trust "$W/ca/ca.der" --crl "$W/ca/ca.crl" \
    --user admin --password-file "$W/admin.pw"
RSS0=$(rss_kib "$PID")
result gds_rss_empty "$((RSS0 / 1024))" MiB

echo "=============== 2. bench_register ($APPS applications) ==============="
run register.log "$P/bench_register" "$@" --count "$APPS" --threads "$REG_THREADS" \
    || echo "(bench_register: not every registration succeeded, see ERRORS)"

echo "=============== 3. memory at $APPS applications ==============="
RSS1=$(rss_kib "$PID")
SP=$(signer_pid)
result gds_rss_at_apps "$((RSS1 / 1024))" MiB
[ -n "$SP" ] && result signer_rss_at_apps "$(($(rss_kib "$SP") / 1024))" MiB
result store_size "$(($(stat -c %s "$W/data/opengds.db") / 1048576))" MiB

echo "=============== 4. load_pull ($AGENTS agents) ==============="
run pull.log "$P/load_pull" "$@" --agents "$AGENTS" || echo "(load_pull: not every agent finished, see ERRORS)"
result gds_rss_after_pull "$(($(rss_kib "$PID") / 1024))" MiB

echo "=============== 5. cold start on the full store ==============="
stop_gds
T0=$(now_ms)
start_gds
T1=$(now_ms)
result cold_start "$(echo "$T0 $T1" | awk '{printf "%.3f", ($2 - $1) / 1000}')" s
result gds_rss_idle_after_restart "$(($(rss_kib "$PID") / 1024))" MiB

echo "=============== 6. load_push ($DEVICES devices, $PUSH_PARALLEL parallel) ==============="
: > "$W/devices.txt"
# push_test_server has one fixed ApplicationUri, so every device shares one
# GDS record (a duplicate ApplicationUri is refused); each device keeps its
# own key, certificate, trust list and session. Each device's self-signed
# certificate is pinned next to the GDS CA. A device that fails its start
# (rarely seen: "server config failed") is started again, at most 3 times.
dev_up() { # dev_up <i>: 0 when the device listens
    "$DEV" --port "$((DEV_PORT0 + $1))" --pki "$W/dev$1" --trust "$W/ca/ca.der" \
        --crl "$W/ca/ca.crl" --admin-cert "$CERT" > "$W/dev$1.log" 2>&1 &
    DPID=$!
    w=0
    until grep -q "Creating listen socket" "$W/dev$1.log" 2>/dev/null; do
        w=$((w + 1))
        kill -0 "$DPID" 2>/dev/null || return 1
        [ $w -gt 3000 ] && return 1
        sleep 0.01
    done
    DPIDS="$DPIDS $DPID"
}
i=0
while [ $i -lt "$DEVICES" ]; do
    tries=0
    until dev_up "$i"; do
        tries=$((tries + 1))
        echo "# push_test_server $i failed to start: $(tail -1 "$W/dev$i.log")" | tee -a "$R"
        [ $tries -ge 3 ] && fail "push_test_server $i did not start"
        rm -rf "$W/dev$i"
    done
    dcert=$(ls "$W/dev$i"/ApplCerts/own/certs/selfsigned*.der 2>/dev/null | head -1)
    [ -n "$dcert" ] || fail "device $i has no certificate"
    echo "$DEV_URI opc.tcp://127.0.0.1:$((DEV_PORT0 + i)) $dcert" >> "$W/devices.txt"
    i=$((i + 1))
done
"$GDSADM" apps register --uri "$DEV_URI" --name "OpenGDS perf device" --type Server \
    --discovery-url "opc.tcp://127.0.0.1:$DEV_PORT0" --gds "$GDS" --cert "$CERT" --key "$KEY" \
    --trust "$W/ca/ca.der" --crl "$W/ca/ca.crl" --user admin \
    --password-file "$W/admin.pw" > "$W/dev-register.log" 2>&1 \
    || { cat "$W/dev-register.log"; fail "gdsadm apps register (device)"; }
run push.log "$P/load_push" "$@" --devices "$W/devices.txt" --parallel "$PUSH_PARALLEL" \
    --jobs "$PUSH_JOBS" || echo "(load_push: not every push succeeded, see ERRORS)"
stop_gds
# opengdsd's own error lines (not the open62541 log), e.g. store errors
grep -hv '^\[20' "$W"/gds*.log | sort | uniq -c | sed 's/^/# gds.log: /' | tee -a "$R"
echo "PERF RUN DONE: $R"
