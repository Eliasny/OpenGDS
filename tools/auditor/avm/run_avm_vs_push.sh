#!/bin/sh
# Run the server profile against push_test_server the way the desktop UI
# does (avm_selftest: child process, event stream on fd 3) and check the
# verdicts against the file the headless run is pinned to.
# Usage: run_avm_vs_push.sh <bindir> <workdir> <expected.csv>
#   PUSH_PORT  port (default 4881)
# SPDX-License-Identifier: MPL-2.0
set -u
B=$(cd "$1" && pwd)
EXPECT=$3
rm -rf "$2"
mkdir -p "$2"
chmod 700 "$2"
W=$(cd "$2" && pwd)
PORT=${PUSH_PORT:-4881}
# the server's pid is in $W/server.pid: --restart-cmd (SRV-PER-*) replaces it
trap '[ -f "$W/server.pid" ] && kill "$(cat "$W/server.pid")" 2>/dev/null; true' EXIT INT TERM

# same fixture as profile_server/run_vs_push.sh
"$B/gdsaudit" server --work "$W/auditor" --init-only || exit 2
# distinct file names: the target's PKI store keys files by name
cp "$W/auditor/own/cert.der" "$W/auditor-plain.der"
cp "$W/auditor/admin/own/cert.der" "$W/auditor-admin.der"
printf 'operator\n' > "$W/user.pw"
chmod 600 "$W/user.pw"
set -- --port "$PORT" --pki "$W/pki" \
    --trust "$W/auditor-plain.der" --trust "$W/auditor-admin.der" \
    --admin-cert "$W/auditor-admin.der" --user operator:operator
# restart.sh stops the server and starts it again on the same PKI
{
    echo '#!/bin/sh'
    echo "pid=\$(cat '$W/server.pid')"
    echo 'kill "$pid"; while kill -0 "$pid" 2>/dev/null; do sleep 0.1; done'
    printf "'%s' " "$B/push_test_server" "$@"
    echo ">> '$W/server.log' 2>&1 &"
    echo "echo \$! > '$W/server.pid'"
} > "$W/restart.sh"
"$B/push_test_server" "$@" > "$W/server.log" 2>&1 &
echo $! > "$W/server.pid"
i=0
until grep -q "Creating listen socket" "$W/server.log" 2>/dev/null; do
    i=$((i + 1))
    if [ $i -gt 100 ]; then echo "push_test_server did not start:"; cat "$W/server.log"; exit 2; fi
    sleep 0.1
done

"$B/avm_selftest" "$EXPECT" "$W/run" -- "$B/gdsaudit" server --url "opc.tcp://127.0.0.1:$PORT" \
    --tofu --work "$W/auditor" --user operator --user-password-file "$W/user.pw" --allow-changes --slow \
    --restart-cmd "sh '$W/restart.sh'"
RC=$?
[ $RC -ne 0 ] && { echo "--- engine output"; cat "$W/run/output.log"; }
exit $RC
