#!/bin/bash
# Run the Auditor server profile (gdsaudit server) against the OPC Foundation
# .NET Reference Server (UA-.NETStandard, Applications/ConsoleReferenceServer),
# a push-managed Server. Its verdicts settle readings of the spec that the
# catalogue leaves to a reference run (docs/auditor/README.md, decision D3);
# reference deviations are recorded in
# profile_server/expected/dotnet_reference.csv, and the run fails when a
# verdict changes.
#
# Usage: run_dotnet_server.sh <gdsaudit binary> <UA-.NETStandard checkout> <workdir>
# Needs a .NET 8 SDK on PATH. The server keeps its PKI under
# $HOME/.local/share/OPC Foundation/pki: run it where that may be changed
# (a CI job), since the profile pushes test certificates and trust lists.
# SPDX-License-Identifier: MPL-2.0
set -u
AUDIT=$1
SRC=$2
W=$3
HERE=$(cd "$(dirname "$0")" && pwd)
EXPECT="$HERE/../profile_server/expected/dotnet_reference.csv"
PORT=62541
URL=${SERVER_URL:-opc.tcp://localhost:$PORT/Quickstarts/ReferenceServer}

mkdir -p "$W"
chmod 700 "$W"
W=$(cd "$W" && pwd)
# CustomTestTarget narrows the build to one framework (targets.props)
CustomTestTarget=net8.0 dotnet publish \
    "$SRC/Applications/ConsoleReferenceServer/ConsoleReferenceServer.csproj" \
    -c Release -o "$W/server" > "$W/build.log" 2>&1 ||
    { tail -50 "$W/build.log"; echo "reference server build failed"; exit 2; }

# -a: the server accepts the Auditor's application certificates (test setup
# only); the Auditor pins the server's certificate on first use (--tofu).
# stdin is a FIFO held open, so that a console read never sees end of input.
rm -f "$W/stdin"
mkfifo "$W/stdin"
sleep infinity > "$W/stdin" &
HOLD=$!
(cd "$W/server" && exec dotnet ConsoleReferenceServer.dll -a -c < "$W/stdin" > "$W/server.log" 2>&1) &
SRV=$!
trap 'kill $SRV $HOLD 2>/dev/null; true' EXIT
for _ in $(seq 1 120); do
    grep -q 'Server started' "$W/server.log" && break
    kill -0 $SRV 2>/dev/null || break
    sleep 1
done
grep -q 'Server started' "$W/server.log" || { tail -60 "$W/server.log"; echo "reference server did not start"; exit 2; }

# sysadmin/demo is the server's SecurityAdmin (SystemConfigurationIdentity);
# user1/password an authenticated user without it
printf 'demo\n' > "$W/admin.pw"
printf 'password\n' > "$W/user.pw"
chmod 600 "$W/admin.pw" "$W/user.pw"
set -- --url "$URL" --tofu --work "$W/auditor" --allow-changes \
    --admin-user sysadmin --admin-password-file "$W/admin.pw" \
    --user user1 --user-password-file "$W/user.pw"
if [ -f "$EXPECT" ]; then
    set -- "$@" --expect "$EXPECT"
fi
"$AUDIT" server "$@" | tee "$W/reference.tap"
RC=${PIPESTATUS[0]}
echo "# gdsaudit exit code $RC"
kill -0 $SRV 2>/dev/null || { tail -60 "$W/server.log"; echo "reference server exited during the run"; exit 2; }
# A run that opened no admin session says nothing about the reference.
if [ "$RC" = 2 ] || ! grep -qE '^(not )?ok ' "$W/reference.tap"; then
    tail -60 "$W/server.log"
    echo "gdsaudit could not run the profile on the reference server: the run itself failed"
    exit 2
fi
# The verdict lines, for dotnet_reference.csv
grep -A1 -E '^(not )?ok [0-9]+ - ' "$W/reference.tap" |
    sed -n -e 's/^\(not \)\{0,1\}ok [0-9]* - \([A-Z0-9-]*\) .*/\2/p' -e 's/^#   verdict: \([a-z_]*\).*/\1/p' |
    paste -d, - - > "$W/verdicts.csv"
if [ ! -f "$EXPECT" ]; then
    echo "# no $EXPECT yet: verdicts recorded only"
    cat "$W/verdicts.csv"
    exit 0
fi
[ $RC -ne 0 ] && { echo "--- tail of the reference server log"; tail -40 "$W/server.log"; }
exit $RC
