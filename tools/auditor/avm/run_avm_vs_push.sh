#!/bin/sh
# Run the server profile against push_test_server the way the desktop UI
# does (avm_selftest: child process, event stream on fd 3) and check the
# verdicts against the file the headless run is pinned to.
# Usage: run_avm_vs_push.sh <bindir> <workdir> <expected.csv>
#   PUSH_PORT  port (default 4881)
# SPDX-License-Identifier: MPL-2.0
set -u
B=$(cd "$1" && pwd)
rm -rf "$2"
mkdir -p "$2"
chmod 700 "$2"
W=$(cd "$2" && pwd)
PORT=${PUSH_PORT:-4881}
SRV=""
trap '[ -n "$SRV" ] && kill "$SRV" 2>/dev/null; true' EXIT INT TERM

"$B/gdsaudit" server --work "$W/auditor" --init-only || exit 2
"$B/push_test_server" --port "$PORT" --pki "$W/pki" \
    --trust "$W/auditor/own/cert.der" --admin-cert "$W/auditor/own/cert.der" \
    > "$W/server.log" 2>&1 &
SRV=$!
i=0
until grep -q "Creating listen socket" "$W/server.log" 2>/dev/null; do
    i=$((i + 1))
    if [ $i -gt 100 ]; then echo "push_test_server did not start:"; cat "$W/server.log"; exit 2; fi
    sleep 0.1
done

"$B/avm_selftest" "$3" "$W/run" -- "$B/gdsaudit" server --url "opc.tcp://127.0.0.1:$PORT" \
    --tofu --work "$W/auditor" --allow-changes
RC=$?
[ $RC -ne 0 ] && { echo "--- engine output"; cat "$W/run/output.log"; }
exit $RC
