#!/bin/sh
# The AT5 gate for plan files: a plan opened in the desktop UI runs with
# the verdicts of the same plan run headless (gdsaudit run PLAN.toml).
# One plan, with paths relative to its own folder, against a
# push_test_server mutant: headless first, then the UI's way (avm_selftest
# --plan: "Open plan…", then the UI's command line) checked against the
# headless verdicts. (test_avm_plan checks that a plan saved by the UI
# gives exactly the headless command line.)
# Usage: run_avm_plan.sh <bindir> <avm-bindir> <workdir>
#   PUSH_PORT  port (default 4989)
# SPDX-License-Identifier: MPL-2.0
set -u
B=$(cd "$1" && pwd)
A=$(cd "$2" && pwd)
mkdir -p "$3"
W=$(cd "$3" && pwd)
rm -rf "$W"/*
PORT=${PUSH_PORT:-4989}
SRV=""
trap '[ -n "$SRV" ] && kill "$SRV" 2>/dev/null; true' EXIT INT TERM
fail() { echo "FAIL: $*"; for f in "$W"/*.log; do echo "--- $f"; cat "$f"; done; exit 1; }
verdicts() { grep '"ev":"verdict"' "$1" | sed -E 's/.*"id":"([^"]*)".*"verdict":"([^"]*)".*/\1,\2/'; }

mkdir -p "$W/plans/w"
"$B/gdsaudit" server --work "$W/plans/w" --init-only > /dev/null || exit 2
"$B/push_test_server" --port "$PORT" --pki "$W/pki" \
    --trust "$W/plans/w/own/cert.der" --trust "$W/plans/w/admin/own/cert.der" \
    --admin-cert "$W/plans/w/admin/own/cert.der" --break no-default-group > "$W/server.log" 2>&1 &
SRV=$!
i=0
until grep -q "Creating listen socket" "$W/server.log" 2>/dev/null; do
    i=$((i + 1))
    [ $i -gt 100 ] && fail "push_test_server did not start"
    sleep 0.1
done

cat > "$W/plans/cap.toml" <<TOML
schema = "gdsaudit-plan"
version = 1
profile = "server"
name = "push_test_server, no default group"
preset = "quick"

[target]
url = "opc.tcp://127.0.0.1:$PORT"
tofu = true

[identity]
work = "w"

[tests]
only = "SRV-CAP"

[report]
events = "headless/events.jsonl"
TOML

"$B/gdsaudit" run "$W/plans/cap.toml" > "$W/headless.log" 2>&1
RC=$?
[ $RC -eq 1 ] || fail "headless exit $RC, expected 1 (the mutant's Fail)"
verdicts "$W/plans/headless/events.jsonl" > "$W/expected.csv"
grep -q "SRV-CAP-02,fail" "$W/expected.csv" || fail "mutant not caught headless"

# the UI's way; avm_selftest exits 1 for the engine's exit 1, so check its
# comparison line instead of its exit code
"$A/avm_selftest" "$W/expected.csv" "$W/ui" --plan "$W/plans/cap.toml" "$B/gdsaudit" \
    > "$W/ui.log" 2>&1
grep -q "MISMATCH" "$W/ui.log" && fail "UI verdicts differ from headless"
grep -q "^# UI command line: .* server .*--only SRV-CAP" "$W/ui.log" ||
    fail "the UI did not keep tests.only from the plan"
grep -q -- "--report $W/ui/report" "$W/ui.log" || fail "the UI's own report folder not used"
verdicts "$W/ui/events.jsonl" > "$W/ui.csv"
cmp -s "$W/expected.csv" "$W/ui.csv" || { diff "$W/expected.csv" "$W/ui.csv"; fail "verdicts differ"; }
echo "ok: the plan gives the same verdicts headless and in the UI ($(wc -l < "$W/ui.csv") tests)"
