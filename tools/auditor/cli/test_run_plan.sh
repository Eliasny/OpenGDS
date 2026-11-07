#!/bin/sh
# gdsaudit run PLAN.toml (gdsaudit/plan.h): a plan file gives the same run
# as the command line it stands for. One plan with paths relative to its own
# folder is run from another folder against a push_test_server mutant; its
# verdicts, exit code and reports must equal those of the same options given
# on the command line. Options after the plan add to it; a bad plan is
# refused with its line number and exit 2.
# Usage: test_run_plan.sh <bindir> <workdir>
#   PUSH_PORT  port (default 4995)
# SPDX-License-Identifier: MPL-2.0
set -u
B=$(cd "$1" && pwd)
mkdir -p "$2"
W=$(cd "$2" && pwd)
rm -rf "$W"/*
PORT=${PUSH_PORT:-4995}
SRV=""
trap '[ -n "$SRV" ] && kill "$SRV" 2>/dev/null; true' EXIT INT TERM
fail() { echo "FAIL: $*"; for f in "$W"/*.log; do echo "--- $f"; cat "$f"; done; exit 1; }
verdicts() { grep '"ev":"verdict"' "$1" | sed -E 's/.*"id":"([^"]*)".*"verdict":"([^"]*)".*/\1 \2/'; }

mkdir -p "$W/plans/w" "$W/elsewhere"
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
# relative paths: relative to this file
schema = "gdsaudit-plan"
version = 1
profile = "server"
name = "push_test_server, no default group"

[target]
url = "opc.tcp://127.0.0.1:$PORT"
tofu = true

[identity]
work = "w"

[tests]
only = "SRV-CAP"
allow_changes = false

[report]
dir = "out"
events = "out/events.jsonl"
TOML

# the plan, run from another folder
(cd "$W/elsewhere" && "$B/gdsaudit" run ../plans/cap.toml > "$W/plan.log" 2>&1)
RC_PLAN=$?
# the same run on the command line
"$B/gdsaudit" server --url "opc.tcp://127.0.0.1:$PORT" --tofu --work "$W/plans/w" \
    --only SRV-CAP --report "$W/cli" --events "$W/cli/events.jsonl" > "$W/cli.log" 2>&1
RC_CLI=$?

[ $RC_PLAN -eq 1 ] || fail "plan run exit $RC_PLAN, expected 1 (the mutant's Fail)"
[ $RC_PLAN -eq $RC_CLI ] || fail "plan exit $RC_PLAN, command line exit $RC_CLI"
grep -q "^# plan ../plans/cap.toml: server --url opc.tcp://127.0.0.1:$PORT --tofu --work ../plans/w " \
    "$W/plan.log" || fail "plan command line not printed with joined paths"
[ -s "$W/plans/out/events.jsonl" ] || fail "no events next to the plan"
for f in report.html junit.xml; do
    [ -s "$W/plans/out/$f" ] || fail "no $f next to the plan"
done
verdicts "$W/plans/out/events.jsonl" > "$W/plan.verdicts"
verdicts "$W/cli/events.jsonl" > "$W/cli.verdicts"
[ -s "$W/plan.verdicts" ] || fail "no verdicts"
cmp -s "$W/plan.verdicts" "$W/cli.verdicts" || {
    diff "$W/plan.verdicts" "$W/cli.verdicts"
    fail "plan and command line verdicts differ"
}
grep -q "SRV-CAP-02 fail" "$W/plan.verdicts" || fail "mutant not caught through the plan"

# options after the plan add to it: --only narrows the run
"$B/gdsaudit" run "$W/plans/cap.toml" --only SRV-CAP-01 --events "$W/narrow.jsonl" \
    > "$W/narrow.log" 2>&1
RC=$?
[ $RC -eq 0 ] || fail "narrowed run exit $RC"
[ "$(verdicts "$W/narrow.jsonl")" = "SRV-CAP-01 pass" ] || fail "--only after the plan not applied"

# a bad plan: refused before any connection, with file and line
printf 'profile = "server"\n[tests]\nonly = "x"\nbogus = 1\n' > "$W/bad.toml"
"$B/gdsaudit" run "$W/bad.toml" > "$W/bad.log" 2>&1
RC=$?
[ $RC -eq 2 ] || fail "bad plan exit $RC"
grep -q "bad.toml:4: unknown key tests.bogus for profile server" "$W/bad.log" ||
    fail "bad plan error does not name the line"
"$B/gdsaudit" run "$W/missing.toml" > "$W/missing.log" 2>&1
[ $? -eq 2 ] || fail "missing plan not exit 2"
echo "ok: plan run equals the command line (exit $RC_PLAN), options after the plan apply, bad plans refused"
