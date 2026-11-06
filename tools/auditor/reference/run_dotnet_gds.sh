#!/bin/bash
# Run the GDS spec tests (gdsaudit gds) against the OPC Foundation .NET
# reference GDS (UA-.NETStandard-Samples, Samples/GDS/ConsoleServer).
# The T0 gate of the OpenGDS plan: every spec test passes on the reference
# GDS or is recorded as a reference deviation in expected/dotnet_reference.csv.
#
# Usage: run_dotnet_gds.sh <gdsaudit binary> <samples checkout> <workdir>
# Needs a .NET SDK (8.0 or 10.0) on PATH.
# SPDX-License-Identifier: MPL-2.0
set -u
AUDIT=$1
SAMPLES=$2
W=$3
HERE=$(cd "$(dirname "$0")" && pwd)
EXPECT="$HERE/../profile_gds/expected/dotnet_reference.csv"
TFM=${TFM:-net8.0}
URL=${GDS_URL:-opc.tcp://127.0.0.1:58810/GlobalDiscoveryServer}
DATA="$HOME/.local/share/OPC Foundation/GDS"

mkdir -p "$W"
W=$(cd "$W" && pwd)
dotnet publish "$SAMPLES/Samples/GDS/ConsoleServer/NetCoreGlobalDiscoveryServer.csproj" \
    -c Release -p:AppTargetFramework="$TFM" -o "$W/gds" > "$W/build.log" 2>&1 ||
    { tail -50 "$W/build.log"; echo "reference GDS build failed"; exit 2; }

# stdin is not a console: the sample then creates its default users
# (appadmin/demo has DiscoveryAdmin and CertificateAuthorityAdmin). Its
# command loop quits on end of input, so stdin is a FIFO held open, never
# /dev/null.
rm -f "$W/stdin"
mkfifo "$W/stdin"
sleep infinity > "$W/stdin" &
HOLD=$!
(cd "$W/gds" && exec dotnet NetCoreGlobalDiscoveryServer.dll < "$W/stdin" > "$W/gds.log" 2>&1) &
GDS=$!
trap 'kill $GDS $HOLD 2>/dev/null; true' EXIT
for _ in $(seq 1 120); do
    (echo > /dev/tcp/127.0.0.1/58810) 2>/dev/null && break
    sleep 1
done
(echo > /dev/tcp/127.0.0.1/58810) 2>/dev/null || { tail -60 "$W/gds.log"; echo "reference GDS did not start"; exit 2; }
# The listener opens before the server leaves its startup state (GetEndpoints
# then answers BadServerHalted): wait for the sample's own "listening" line.
for _ in $(seq 1 60); do
    grep -q 'OPC UA server listening at' "$W/gds.log" && break
    sleep 1
done
grep -q 'OPC UA server listening at' "$W/gds.log" || { tail -60 "$W/gds.log"; echo "reference GDS never reported listening"; exit 2; }
sleep 2 # CA certificate creation finishes after the listener is up
kill -0 $GDS 2>/dev/null || { tail -60 "$W/gds.log"; echo "reference GDS exited"; exit 2; }

# Trust exactly the GDS's own certificate and its CA (Annex G: explicit trust)
set --
for f in "$DATA"/pki/own/certs/*.der "$DATA"/PKI/CA/default/certs/*.der; do
    [ -f "$f" ] && set -- "$@" --trust "$f"
done
for f in "$DATA"/PKI/CA/default/crl/*.crl; do
    [ -f "$f" ] && set -- "$@" --crl "$f"
done
[ $# -gt 0 ] || { ls -R "$DATA" | head -40; echo "no GDS certificates found"; exit 2; }
printf 'demo\n' > "$W/appadmin.pw"
chmod 600 "$W/appadmin.pw"
set -- "$@" --url "$URL" --user appadmin --password-file "$W/appadmin.pw" \
    --work "$W/auditor" --allow-changes --poll-seconds 20
if [ -f "$EXPECT" ]; then
    set -- "$@" --expect "$EXPECT"
fi
"$AUDIT" gds "$@" | tee "$W/reference.tap"
RC=${PIPESTATUS[0]}
echo "# gdsaudit exit code $RC"
kill -0 $GDS 2>/dev/null || { echo "reference GDS exited during the run"; exit 2; }
# A run in which no session could be opened says nothing about the reference.
if grep -q 'cannot open a session on the target' "$W/reference.tap" || [ "$RC" = 2 ]; then
    echo "gdsaudit could not open a session on the reference GDS: the run itself failed"
    exit 2
fi
if [ ! -f "$EXPECT" ]; then
    echo "# no $EXPECT yet: verdicts recorded only"
    exit 0
fi
[ $RC -ne 0 ] && { echo "--- tail of the reference GDS log"; tail -40 "$W/gds.log"; }
exit $RC
