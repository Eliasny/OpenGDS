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
# (appadmin/demo has DiscoveryAdmin and CertificateAuthorityAdmin)
(cd "$W/gds" && exec dotnet NetCoreGlobalDiscoveryServer.dll < /dev/null > "$W/gds.log" 2>&1) &
GDS=$!
trap 'kill $GDS 2>/dev/null; true' EXIT
for _ in $(seq 1 120); do
    (echo > /dev/tcp/127.0.0.1/58810) 2>/dev/null && break
    sleep 1
done
(echo > /dev/tcp/127.0.0.1/58810) 2>/dev/null || { tail -60 "$W/gds.log"; echo "reference GDS did not start"; exit 2; }
sleep 3 # CA certificate creation finishes after the listener is up

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
if [ ! -f "$EXPECT" ]; then
    echo "# no $EXPECT yet: verdicts recorded only"
    exit 0
fi
[ $RC -ne 0 ] && { echo "--- tail of the reference GDS log"; tail -40 "$W/gds.log"; }
exit $RC
