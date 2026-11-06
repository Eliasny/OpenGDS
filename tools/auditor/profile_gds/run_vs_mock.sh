#!/bin/sh
# Run the GDS spec tests (gdsaudit gds) against the mock GDS.
# Usage: run_vs_mock.sh <bindir> <workdir> [expected.csv]
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

set -- --url "opc.tcp://127.0.0.1:$PORT" --trust "$W/ca/ca.der" --crl "$W/ca/ca.crl" \
    --user registrar --password-file "$W/registrar.pw" --work "$W/auditor" \
    --allow-changes --poll-seconds 10
[ -n "$EXPECT" ] && set -- "$@" --expect "$EXPECT"
"$B/gdsaudit" gds "$@"
RC=$?
echo "# gdsaudit exit code $RC"
exit $RC
