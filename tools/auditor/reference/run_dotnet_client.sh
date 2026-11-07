#!/bin/bash
# Run the Auditor client profile (gdsaudit client) against a pull-managed
# client built on the OPC Foundation .NET GDS client library
# (UA-.NETStandard, Libraries/Opc.Ua.Gds.Client.Common). UA-.NETStandard has
# no ready pull-client application, so reference/dotnet_pull_client is a
# small trigger hook on that library (one pull cycle per run, Annex G.1);
# it is built inside the pinned checkout so that it uses its package
# versions. Verdicts are pinned in profile_client/expected/dotnet_reference.csv
# and the run fails when one changes.
#
# Usage: run_dotnet_client.sh <gdsaudit binary> <UA-.NETStandard checkout> <workdir>
# Needs a .NET SDK on PATH that builds the checkout (C# 14: .NET 10).
# SPDX-License-Identifier: MPL-2.0
set -u
AUDIT=$1
SRC=$2
W=$3
HERE=$(cd "$(dirname "$0")" && pwd)
EXPECT="$HERE/../profile_client/expected/dotnet_reference.csv"
PORT=${GDS_PORT:-4863}

rm -rf "$W"
mkdir -p "$W"
chmod 700 "$W"
W=$(cd "$W" && pwd)
rm -rf "$SRC/Applications/AuditorPullClient"
cp -r "$HERE/dotnet_pull_client" "$SRC/Applications/AuditorPullClient"
# CustomTestTarget narrows the build to one framework (targets.props);
# Nerdbank.GitVersioning cannot work out a version from a shallow fetch
NBGV_GitEngine=Disabled CustomTestTarget=net8.0 dotnet publish \
    "$SRC/Applications/AuditorPullClient/AuditorPullClient.csproj" \
    -c Release -f net8.0 -o "$W/client" > "$W/build.log" 2>&1 ||
    { tail -50 "$W/build.log"; echo ".NET pull client build failed"; exit 2; }
DOTNET=$(command -v dotnet)

set -- client --listen "$PORT" --work "$W/auditor" --cycle-timeout 90
if [ -f "$EXPECT" ]; then
    set -- "$@" --expect "$EXPECT"
fi
"$AUDIT" "$@" -- "$DOTNET" "$W/client/AuditorPullClient.dll" | tee "$W/reference.tap"
RC=${PIPESTATUS[0]}
echo "# gdsaudit exit code $RC"
cp "$W/auditor/trigger.log" "$W/client.log" 2>/dev/null
if [ "$RC" = 2 ] || ! grep -qE '^(not )?ok ' "$W/reference.tap"; then
    tail -40 "$W/client.log"
    echo "gdsaudit could not run the profile against the .NET client: the run itself failed"
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
[ $RC -ne 0 ] && { echo "--- tail of the client log"; tail -40 "$W/client.log"; }
exit $RC
