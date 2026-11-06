#!/bin/bash
# T2 push tracer gate, second target (OpenGDS plan, T2: "against
# push_test_server and a .NET server"): gdsadm push now through opengdsd to a
# .NET Server. The push target is the OPC Foundation .NET reference GDS
# (UA-.NETStandard-Samples, pinned in .github/workflows/reference-gds.yml):
# like every UA-.NETStandard server it exposes ServerConfiguration for push
# management (OPC 10000-12 §7.10), and its sample user sysadmin has
# SecurityAdmin (§7.4).
#
# Usage: run_push_vs_dotnet.sh <build-dir> <samples checkout> <work-dir>
# Needs a .NET SDK (8.0) on PATH and the openssl command.
# SPDX-License-Identifier: MPL-2.0
set -u
B=$(cd "${1:?build dir}" && pwd)
SAMPLES=${2:?samples checkout}
W=${3:?work dir}
TFM=${TFM:-net8.0}
PORT=${OPENGDS_PORT:-4876}
DEV_URL="opc.tcp://127.0.0.1:58810/GlobalDiscoveryServer"
DATA="$HOME/.local/share/OPC Foundation/GDS"
GDSD="$B/src/daemon/opengdsd"
SIGNER="$B/src/signer/opengds-signer"
GDSADM="$B/src/daemon/gdsadm"
PULL="$B/tools/auditor/pull_test_client"

rm -rf "$W"
mkdir -p "$W"
chmod 700 "$W"
W=$(cd "$W" && pwd)
PID=""
DEV=""
HOLD=""
cleanup() { for p in $PID $DEV $HOLD; do kill "$p" 2>/dev/null; done; true; }
trap cleanup EXIT INT TERM

fail() {
    echo "PUSH VS .NET FAILED: $1"
    for l in "$W"/*.log; do [ -f "$l" ] && { echo "--- tail of $l"; tail -60 "$l"; }; done
    exit 1
}
expect() { grep -q "$1" "$2" || { cat "$2"; fail "'$1' not found in $2"; }; }

echo "=============== 1. opengdsd, and gdsadm's own certificate ==============="
printf 'secret\n' > "$W/admin.pw"
printf 'demo\n' > "$W/sysadmin.pw"
printf 'push-dotnet-ca-passphrase\n' > "$W/ca.pw"
chmod 600 "$W/admin.pw" "$W/ca.pw" "$W/sysadmin.pw"
CRED=$("$GDSADM" hash-password < "$W/admin.pw") || fail "gdsadm hash-password"
echo "admin DiscoveryAdmin,CertificateAuthorityAdmin $CRED" > "$W/users"
chmod 600 "$W/users"
cat > "$W/opengds.conf" <<CONF
application_uri = urn:opengds:push-dotnet:gds
port = $PORT
loopback_only = true
data_dir = $W/data
users_file = $W/users
ca_dir = $W/ca
signer = $SIGNER
ca_passphrase_file = $W/ca.pw
organization = OpenGDS push vs .NET
CONF
"$GDSD" --config "$W/opengds.conf" > "$W/gds.log" 2>&1 &
PID=$!
for _ in $(seq 1 300); do
    grep -q "listening at\|Creating listen socket" "$W/gds.log" 2>/dev/null && break
    kill -0 "$PID" 2>/dev/null || fail "opengdsd exited during start"
    sleep 0.1
done
GDS="opc.tcp://127.0.0.1:$PORT"
"$PULL" --gds "$GDS" --pki "$W/pki-adm" --trust "$W/ca/ca.der" --crl "$W/ca/ca.crl" \
    --user admin --password-file "$W/admin.pw" --app-uri urn:opengds:push-dotnet:gdsadm \
    > "$W/adm-cert.txt" 2>&1 || { cat "$W/adm-cert.txt"; fail "gdsadm certificate"; }
CONN=(--gds "$GDS" --cert "$W/pki-adm/own/cert.der" --key "$W/pki-adm/own/private/key.der"
      --trust "$W/ca/ca.der" --crl "$W/ca/ca.crl" --user admin --password-file "$W/admin.pw")

echo "=============== 2. the .NET Server (push target), trusting the OpenGDS CA ==============="
# The device must trust gdsadm before the first push (OPC 10000-12 §7.4,
# Annex G.3): out of band, put the OpenGDS CA and its CRL in its trusted store
# (.NET DirectoryCertificateStore layout: certs/ and crl/)
mkdir -p "$DATA/pki/trusted/certs" "$DATA/pki/trusted/crl"
cp "$W/ca/ca.der" "$DATA/pki/trusted/certs/opengds-ca.der"
cp "$W/ca/ca.crl" "$DATA/pki/trusted/crl/opengds-ca.crl"
dotnet publish "$SAMPLES/Samples/GDS/ConsoleServer/NetCoreGlobalDiscoveryServer.csproj" \
    -c Release -p:AppTargetFramework="$TFM" -o "$W/dotnet" > "$W/dotnet-build.log" 2>&1 ||
    fail ".NET server build"
# Its command loop quits on end of input: stdin is a FIFO held open
mkfifo "$W/stdin"
sleep infinity > "$W/stdin" &
HOLD=$!
(cd "$W/dotnet" && exec dotnet NetCoreGlobalDiscoveryServer.dll < "$W/stdin" > "$W/dotnet.log" 2>&1) &
DEV=$!
for _ in $(seq 1 120); do
    grep -q 'OPC UA server listening at' "$W/dotnet.log" 2>/dev/null && break
    kill -0 "$DEV" 2>/dev/null || fail ".NET server exited during start"
    sleep 1
done
grep -q 'OPC UA server listening at' "$W/dotnet.log" || fail ".NET server never reported listening"
sleep 2
DEV_CERT=$(ls "$DATA"/pki/own/certs/*.der 2>/dev/null | head -1)
[ -n "$DEV_CERT" ] || fail "no .NET server certificate in $DATA/pki/own/certs"
# Its ApplicationUri is the SAN URI of its certificate (OPC 10000-6 §6.2.2)
DEV_URI=$(openssl x509 -inform der -in "$DEV_CERT" -noout -ext subjectAltName |
    grep -o 'URI:[^,]*' | head -1 | cut -c5-)
[ -n "$DEV_URI" ] || fail "no SAN URI in $DEV_CERT"
echo "device $DEV_URI"

echo "=============== 3. register the device ==============="
"$GDSADM" apps register --uri "$DEV_URI" --name "OPC Foundation .NET Server" --type Server \
    --discovery-url "$DEV_URL" "${CONN[@]}" > "$W/register.txt" 2>&1 ||
    { cat "$W/register.txt"; fail "apps register"; }

echo "=============== 4. gdsadm push now (sysadmin has SecurityAdmin) ==============="
"$GDSADM" push now "$DEV_URI" --server-cert "$DEV_CERT" --device-user sysadmin \
    --device-password-file "$W/sysadmin.pw" "${CONN[@]}" > "$W/push.txt" 2>&1 ||
    { cat "$W/push.txt"; fail "push to the .NET server"; }
cat "$W/push.txt"
expect "certificate updated" "$W/push.txt"
expect "the device presents the issued certificate" "$W/push.txt"
echo "PUSH VS .NET PASSED"
