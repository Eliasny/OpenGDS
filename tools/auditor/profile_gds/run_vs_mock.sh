#!/bin/sh
# Run the GDS spec tests (gdsaudit gds) against the mock GDS.
# Usage: run_vs_mock.sh <bindir> <workdir> [expected.csv]
#   PLAN=1  run it from a plan file written to <workdir>/plan.toml
# SPDX-License-Identifier: MPL-2.0
set -u
B=$1
W=$2
EXPECT=${3:-}
PORT=${GDS_PORT:-4852}
rm -rf "$W"
mkdir -p "$W"
B=$(cd "$B" && pwd)
W=$(cd "$W" && pwd)
# GDSAUDIT: another gdsaudit to check against the pins, for example a
# wrapper that runs the Windows build under Wine (packaging/windows/)
GA=${GDSAUDIT:-$B/gdsaudit}
GDS=""
trap '[ -n "$GDS" ] && kill "$GDS" 2>/dev/null; true' EXIT INT TERM

printf 'secret\n' > "$W/registrar.pw"
chmod 600 "$W/registrar.pw"
"$B/mock_gds" --port "$PORT" --ca-dir "$W/ca" --user registrar:secret --approve-after 1 \
    > "$W/mock_gds.log" 2>&1 &
GDS=$!
i=0
until grep -q "Creating listen socket" "$W/mock_gds.log" 2>/dev/null; do
    i=$((i + 1))
    if [ $i -gt 100 ]; then echo "mock GDS did not start:"; cat "$W/mock_gds.log"; exit 2; fi
    sleep 0.1
done

if [ -n "${PLAN:-}" ]; then
    # The same run from a plan file (gdsaudit run, docs/auditor/plan-files.md);
    # paths are relative to the plan's folder
    cp "$EXPECT" "$W/expected.csv" 2>/dev/null || true
    {
        printf 'schema = "gdsaudit-plan"\nversion = 1\nprofile = "gds"\n\n'
        printf '[target]\nurl = "opc.tcp://127.0.0.1:%s"\n' "$PORT"
        printf 'trust = ["ca/ca.der"]\ncrl = ["ca/ca.crl"]\n\n'
        printf '[identity]\nwork = "auditor"\nuser = "registrar"\npassword_file = "registrar.pw"\n\n'
        printf '[tests]\nallow_changes = true\npoll_seconds = 10\n'
        [ -n "$EXPECT" ] && printf 'expect = "expected.csv"\n'
        printf '\n[report]\ndir = "results"\n'
    } > "$W/plan.toml"
    "$GA" run "$W/plan.toml"
    RC=$?
else
    set -- --url "opc.tcp://127.0.0.1:$PORT" --trust "$W/ca/ca.der" --crl "$W/ca/ca.crl" \
        --user registrar --password-file "$W/registrar.pw" --work "$W/auditor" \
        --allow-changes --poll-seconds 10
    [ -n "$EXPECT" ] && set -- "$@" --expect "$EXPECT"
    "$GA" gds "$@"
    RC=$?
fi
echo "# gdsaudit exit code $RC"
exit $RC
