#!/bin/sh
# Pause and resume between tests (engine.h ga_request_pause): SIGUSR1 to a
# running gdsaudit makes it emit "paused" and start no new test until
# SIGUSR2; the run then finishes as it would have without the pause.
# Usage: test_pause.sh <bindir> <workdir>
#   PUSH_PORT  port (default 4991)
# SPDX-License-Identifier: MPL-2.0
set -u
B=$(cd "$1" && pwd)
mkdir -p "$2"
W=$(cd "$2" && pwd)
rm -rf "$W/auditor" "$W/pki" "$W/events.jsonl"
PORT=${PUSH_PORT:-4991}
SRV=""
AUD=""
trap '[ -n "$SRV" ] && kill "$SRV" 2>/dev/null; [ -n "$AUD" ] && kill "$AUD" 2>/dev/null; true' EXIT INT TERM
fail() { echo "FAIL: $*"; echo "--- events"; cat "$W/events.jsonl"; echo "--- output"; cat "$W/out.log"; exit 1; }
count() { grep -c "\"ev\":\"$1\"" "$W/events.jsonl" 2>/dev/null || true; }

"$B/gdsaudit" server --work "$W/auditor" --init-only > /dev/null || exit 2
cp "$W/auditor/own/cert.der" "$W/auditor-plain.der"
"$B/push_test_server" --port "$PORT" --pki "$W/pki" --trust "$W/auditor-plain.der" \
    > "$W/server.log" 2>&1 &
SRV=$!
i=0
until grep -q "Creating listen socket" "$W/server.log" 2>/dev/null; do
    i=$((i + 1))
    [ $i -gt 100 ] && { echo "push_test_server did not start"; cat "$W/server.log"; exit 2; }
    sleep 0.1
done

"$B/gdsaudit" server --url "opc.tcp://127.0.0.1:$PORT" --tofu --work "$W/auditor" \
    --events "$W/events.jsonl" > "$W/out.log" 2>&1 &
AUD=$!
i=0
until [ "$(count test_started)" -ge 1 ]; do
    i=$((i + 1))
    [ $i -gt 300 ] && fail "no test started"
    sleep 0.1
done
kill -USR1 "$AUD"
i=0
until [ "$(count paused)" -ge 1 ]; do
    i=$((i + 1))
    [ $i -gt 600 ] && fail "no paused event"
    sleep 0.1
done
started=$(count test_started)
sleep 2
[ "$(count test_started)" -eq "$started" ] || fail "a test started while paused"
kill -0 "$AUD" 2>/dev/null || fail "the engine exited while paused"
kill -USR2 "$AUD"
wait "$AUD"
RC=$?
AUD=""
[ "$(count resumed)" -eq 1 ] || fail "no resumed event"
[ "$(count run_finished)" -eq 1 ] || fail "run did not finish"
grep -q '"aborted":false' "$W/events.jsonl" || fail "run was aborted"
[ "$(count test_started)" -gt "$started" ] || fail "no test ran after resume"
grep -q '^# paused' "$W/out.log" && grep -q '^# resumed' "$W/out.log" || fail "TAP comments missing"
# without --allow-changes most tests are Not tested: exit 3 (harness.h)
grep -q "\"exit\":$RC," "$W/events.jsonl" || fail "exit $RC differs from run_finished"
[ $RC -le 1 ] || [ $RC -eq 3 ] || fail "engine exit $RC"
echo "ok: paused after $started test(s), resumed, run finished (exit $RC)"
