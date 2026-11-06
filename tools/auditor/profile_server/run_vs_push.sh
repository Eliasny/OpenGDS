#!/bin/sh
# Run the server profile (gdsaudit server) against push_test_server: once
# against the good target with pinned verdicts, then once per --break mutant,
# which the test named in mutants.csv must catch.
# Usage: run_vs_push.sh <bindir> <workdir> <expected-dir>
#   PUSH_PORT  first port (default 4861; each run uses the next one)
#   ONLY       run only this mutant (or "good")
# SPDX-License-Identifier: MPL-2.0
set -u
B=$(cd "$1" && pwd)
rm -rf "$2"
mkdir -p "$2"
chmod 700 "$2"
W=$(cd "$2" && pwd)
E=$(cd "$3" && pwd)
PORT=${PUSH_PORT:-4861}
ONLY=${ONLY:-}
SRV=""
trap '[ -n "$SRV" ] && kill "$SRV" 2>/dev/null; true' EXIT INT TERM

"$B/gdsaudit" server --work "$W/auditor" --init-only || exit 2
cp "$W/auditor/own/cert.der" "$W/auditor-plain.der"
cp "$W/auditor/admin/own/cert.der" "$W/auditor-admin.der"
printf 'operator\n' > "$W/user.pw"
chmod 600 "$W/user.pw"

# start_server <name> [--break mutant]: fresh PKI; both Auditor identities
# trusted, the admin one mapped to SecurityAdmin; "operator" a plain user
start_server() {
    name=$1
    shift
    PORT=$((PORT + 1))
    "$B/push_test_server" --port "$PORT" --pki "$W/pki-$name" \
        --trust "$W/auditor-plain.der" --trust "$W/auditor-admin.der" \
        --admin-cert "$W/auditor-admin.der" --user operator:operator "$@" \
        > "$W/server-$name.log" 2>&1 &
    SRV=$!
    i=0
    until grep -q "Creating listen socket" "$W/server-$name.log" 2>/dev/null; do
        i=$((i + 1))
        if [ $i -gt 100 ]; then echo "push_test_server did not start:"; cat "$W/server-$name.log"; exit 2; fi
        sleep 0.1
    done
}
stop_server() { kill "$SRV" 2>/dev/null; wait "$SRV" 2>/dev/null; SRV=""; }
audit() { # audit <name> [args]: run the profile, TAP into $W/<name>.tap
    name=$1
    shift
    "$B/gdsaudit" server --url "opc.tcp://127.0.0.1:$PORT" --tofu --work "$W/auditor" \
        --user operator --user-password-file "$W/user.pw" --allow-changes "$@" \
        > "$W/$name.tap" 2>&1
}

RC=0
SLOW_TESTS="SRV-TL-18"
if [ -z "$ONLY" ] || [ "$ONLY" = good ]; then
    echo "=== good push_test_server"
    start_server good
    audit good --slow --expect "$E/push_test_server.csv"
    G=$?
    stop_server
    cat "$W/good.tap"
    if [ $G -ne 0 ]; then
        echo "FAILED: verdicts against the good target differ from push_test_server.csv"
        tail -40 "$W/server-good.log"
        RC=1
    fi
fi

while IFS=, read -r mutant test want; do
    case "$mutant" in ''|\#*) continue ;; esac
    [ -n "$ONLY" ] && [ "$ONLY" != "$mutant" ] && continue
    start_server "$mutant" --break "$mutant"
    # tests flagged slow in the catalogue run only for their own mutant
    case " $SLOW_TESTS " in *" $test "*) audit "$mutant" --slow ;; *) audit "$mutant" ;; esac
    stop_server
    got=$(grep -A1 -E "^(not )?ok [0-9]+ - $test " "$W/$mutant.tap" | sed -n 's/^#   verdict: \([a-z_]*\).*/\1/p')
    if [ "$got" = "$want" ]; then
        echo "caught: --break $mutant -> $test $got"
    else
        echo "NOT CAUGHT: --break $mutant -> $test ${got:-missing}, want $want"
        cat "$W/$mutant.tap"
        tail -30 "$W/server-$mutant.log"
        RC=1
    fi
done < "$E/mutants.csv"
exit $RC
