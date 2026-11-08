#!/bin/sh
# The report folder (--report DIR): report.html, junit.xml, report.json and
# report.tap from one read-only run of gdsaudit server against a
# push_test_server mutant (--break no-default-group), so the run has a Fail
# next to Passes. The TAP report must give each test the same ok / not ok and
# SKIP as the TAP the engine prints, and report.json must be one JSON
# document whose verdicts match the --events stream.
# Usage: test_reports.sh <bindir> <workdir>
#   PUSH_PORT  port (default 4993)
# SPDX-License-Identifier: MPL-2.0
set -u
B=$(cd "$1" && pwd)
mkdir -p "$2"
W=$(cd "$2" && pwd)
rm -rf "$W/auditor" "$W/pki" "$W/report" "$W/events.jsonl"
PORT=${PUSH_PORT:-4993}
SRV=""
trap '[ -n "$SRV" ] && kill "$SRV" 2>/dev/null; true' EXIT INT TERM
fail() { echo "FAIL: $*"; echo "--- output"; cat "$W/out.log"; exit 1; }

"$B/gdsaudit" server --work "$W/auditor" --init-only > /dev/null || exit 2
cp "$W/auditor/own/cert.der" "$W/auditor-plain.der"
cp "$W/auditor/admin/own/cert.der" "$W/auditor-admin.der"
"$B/push_test_server" --port "$PORT" --pki "$W/pki" \
    --trust "$W/auditor-plain.der" --trust "$W/auditor-admin.der" \
    --admin-cert "$W/auditor-admin.der" --break no-default-group > "$W/server.log" 2>&1 &
SRV=$!
i=0
until grep -q "Creating listen socket" "$W/server.log" 2>/dev/null; do
    i=$((i + 1))
    [ $i -gt 100 ] && { echo "push_test_server did not start"; cat "$W/server.log"; exit 2; }
    sleep 0.1
done

"$B/gdsaudit" server --url "opc.tcp://127.0.0.1:$PORT" --tofu --work "$W/auditor" \
    --only SRV-CAP --events "$W/events.jsonl" --report "$W/report" > "$W/out.log" 2>&1
RC=$?
[ $RC -eq 1 ] || fail "engine exit $RC, expected 1 (the mutant's Fail)"
grep -q '^not ok [0-9]* - SRV-CAP-02 ' "$W/report/report.tap" || fail "SRV-CAP-02 not failed in TAP"
grep -q '^ok [0-9]* - SRV-CAP-01 [^#]*$' "$W/report/report.tap" || fail "SRV-CAP-01 not passed in TAP"
for f in report.html junit.xml report.json report.tap; do
    [ -s "$W/report/$f" ] || fail "no $f"
    [ -e "$W/report/$f.tmp" ] && fail "$f.tmp left behind"
done
grep -q "report.json,report.tap" "$W/out.log" || fail "report line does not name all four"

# TAP: the same test lines as the engine's own TAP output
grep -E '^(not )?ok [0-9]+ - ' "$W/out.log" |
    sed -E 's/^((not )?ok [0-9]+) - ([^ ]+) .*/\1 \3/' > "$W/engine.lines"
grep -E '^(not )?ok [0-9]+ - ' "$W/report/report.tap" |
    sed -E 's/^((not )?ok [0-9]+) - ([^ ]+) .*/\1 \3/' > "$W/report.lines"
[ -s "$W/engine.lines" ] || fail "engine printed no TAP lines"
cmp -s "$W/engine.lines" "$W/report.lines" || {
    diff "$W/engine.lines" "$W/report.lines"
    fail "report.tap test lines differ from the engine's TAP"
}
skips_engine=$(grep -cE '^ok [0-9]+ - .* # SKIP$' "$W/out.log")
skips_report=$(grep -cE '^ok [0-9]+ - .* # SKIP ' "$W/report/report.tap")
[ "$skips_engine" -eq "$skips_report" ] || fail "SKIP count $skips_report, engine $skips_engine"
head -n 1 "$W/report/report.tap" | grep -qx 'TAP version 13' || fail "no TAP 13 header"
planned=$(sed -n 2p "$W/report/report.tap")
[ "$planned" = "1..$(wc -l < "$W/report.lines" | tr -d ' ')" ] || fail "TAP plan $planned"

# JSON: one document; the same verdict sequence as the event stream
if command -v python3 > /dev/null; then
    python3 -I - "$W/report/report.json" "$W/events.jsonl" <<'PY' || fail "report.json check"
import json, sys
rep = json.load(open(sys.argv[1], encoding="utf-8"))
evs = [json.loads(l) for l in open(sys.argv[2], encoding="utf-8") if l.strip()]
assert rep["schema"] == "gdsaudit-report" and rep["version"] == 1, "schema"
assert "not OPC Foundation certification" in rep["note"], "note"
got = [(t["id"], t["verdict"]) for t in rep["tests"]]
want = [(e["id"], e["verdict"]) for e in evs if e["ev"] == "verdict"]
assert got == want, (got, want)
assert ("SRV-CAP-02", "fail") in got and rep["outcome"] == "Failed", "mutant"
fin = [e for e in evs if e["ev"] == "run_finished"][0]
assert rep["exit"] == fin["exit"], "exit"
for k in ("pass", "fail", "warn", "not_supported", "not_tested"):
    assert rep["counts"][k] == fin[k], k
assert sum(u["counts"][k] for u in rep["conformance_units"] for k in rep["counts"]) == len(got)
PY
else
    echo "note: python3 not found, report.json checked for its schema line only"
    grep -q '^{"schema":"gdsaudit-report","version":1,' "$W/report/report.json" ||
        fail "report.json header"
fi
echo "ok: four reports, TAP and JSON agree with the engine (exit $RC)"
