#!/bin/sh
# "gdsaudit discover" against push_test_server: FindServers names the
# server, GetEndpoints lists its endpoints with the certificate's SHA-1
# thumbprint, --certs writes that certificate, a bad URL is a usage error.
# With a third argument (test_avm_target) the desktop UI's discovery is run
# against the same server.
# Usage: test_discover.sh <bindir> <workdir> [test_avm_target]
#   PUSH_PORT  port (default 4993)
# SPDX-License-Identifier: MPL-2.0
set -u
B=$(cd "$1" && pwd)
mkdir -p "$2"
W=$(cd "$2" && pwd)
AVM=${3:-}
rm -rf "$W/pki" "$W/certs"
PORT=${PUSH_PORT:-4993}
URL="opc.tcp://127.0.0.1:$PORT"
SRV=""
trap '[ -n "$SRV" ] && kill "$SRV" 2>/dev/null; true' EXIT INT TERM
fail() { echo "FAIL: $*"; echo "--- discover output"; cat "$W/out.tsv"; exit 1; }

"$B/push_test_server" --port "$PORT" --pki "$W/pki" > "$W/server.log" 2>&1 &
SRV=$!
i=0
until grep -q "Creating listen socket" "$W/server.log" 2>/dev/null; do
    i=$((i + 1))
    [ $i -gt 100 ] && { echo "push_test_server did not start"; cat "$W/server.log"; exit 2; }
    sleep 0.1
done

"$B/gdsaudit" discover --url "$URL" --network --certs "$W/certs" > "$W/out.tsv"
RC=$?
[ $RC -eq 0 ] || fail "exit $RC"
grep -q "^server	urn:opengds:test:pushserver	" "$W/out.tsv" || fail "no server record"
grep -q "^endpoint	$URL	http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256	signandencrypt	" \
    "$W/out.tsv" || fail "no Basic256Sha256 SignAndEncrypt endpoint"
# push_test_server is no LDS-ME: FindServersOnNetwork is refused, as a record
grep -q "^error	network	$URL	" "$W/out.tsv" || fail "no network error record"
# every record has its field count (discover.h)
awk -F'\t' '($1=="endpoint" && NF!=9) || ($1=="server" && NF!=5) || ($1=="error" && NF!=4) \
    { bad=1 } END { exit bad }' "$W/out.tsv" || fail "a record has the wrong field count"
thumb=$(awk -F'\t' '$1=="endpoint" && $4=="signandencrypt" { print $6; exit }' "$W/out.tsv")
[ -n "$thumb" ] && [ -f "$W/certs/$thumb.der" ] || fail "certificate $thumb.der not written"
got=$(openssl x509 -inform DER -in "$W/certs/$thumb.der" -noout -fingerprint -sha1 2>/dev/null |
      sed 's/.*=//; s/://g')
[ -z "$got" ] || [ "$got" = "$thumb" ] || fail "thumbprint $thumb, certificate has $got"

"$B/gdsaudit" discover --url "http://example" > /dev/null 2>&1
[ $? -eq 2 ] || fail "a non-opc.tcp URL is not a usage error"
"$B/gdsaudit" discover --url "opc.tcp://127.0.0.1:1" > "$W/none.tsv" 2>&1
[ $? -eq 1 ] || fail "no endpoints must exit 1"
grep -q "^error	getendpoints	" "$W/none.tsv" || fail "no getendpoints error record"

if [ -n "$AVM" ]; then
    "$AVM" "$B/gdsaudit" "$URL" || exit 1
fi
echo "ok: discovery against push_test_server"
