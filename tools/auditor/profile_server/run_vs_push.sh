#!/bin/sh
# Run the server profile (gdsaudit server) against push_test_server: once
# against the good target with pinned verdicts, then once per --break mutant,
# which the test named in mutants.csv must catch.
# Usage: run_vs_push.sh <bindir> <workdir> <expected-dir>
#   PUSH_PORT  first port (default 4861; each run uses the next one)
#   ONLY       run only this mutant (or "good")
#   SHARD      k/n: run every n-th mutant from the k-th (the good runs are in 1/n)
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
SHARD=${SHARD:-1/1}
SK=${SHARD%/*}
SN=${SHARD#*/}
FIRST=false
[ "$SK" = 1 ] && FIRST=true
SRV=""
NAME=""
# the server's pid is in $W/server.pid: --restart-cmd (SRV-PER-*) replaces it
trap '[ -f "$W/server.pid" ] && kill "$(cat "$W/server.pid")" 2>/dev/null; true' EXIT INT TERM

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
    NAME=$name
    # restart-<name>.sh stops the server and starts it again on the same PKI
    {
        echo '#!/bin/sh'
        echo "pid=\$(cat '$W/server.pid')"
        echo 'kill "$pid"; while kill -0 "$pid" 2>/dev/null; do sleep 0.1; done'
        # fresh: back to the factory state, keeping the self-signed certificate
        echo "if [ \"\${1:-}\" = fresh ]; then"
        echo "  cd '$W/pki-$name' && rm -rf push ApplCerts/trusted ApplCerts/issuer ApplCerts/rejected"
        echo "  find ApplCerts/own -type f ! -name 'selfsigned\\[*' -exec rm -f {} +; cd /"
        echo "fi"
        printf "'%s' " "$B/push_test_server" --port "$PORT" --pki "$W/pki-$name" \
            --trust "$W/auditor-plain.der" --trust "$W/auditor-admin.der" \
            --admin-cert "$W/auditor-admin.der" --user operator:operator "$@"
        echo ">> '$W/server-$name.log' 2>&1 &"
        echo "echo \$! > '$W/server.pid'"
    } > "$W/restart-$name.sh"
    "$B/push_test_server" --port "$PORT" --pki "$W/pki-$name" \
        --trust "$W/auditor-plain.der" --trust "$W/auditor-admin.der" \
        --admin-cert "$W/auditor-admin.der" --user operator:operator "$@" \
        > "$W/server-$name.log" 2>&1 &
    SRV=$!
    echo "$SRV" > "$W/server.pid"
    i=0
    until grep -q "Creating listen socket" "$W/server-$name.log" 2>/dev/null; do
        i=$((i + 1))
        if [ $i -gt 100 ]; then echo "push_test_server did not start:"; cat "$W/server-$name.log"; exit 2; fi
        sleep 0.1
    done
}
stop_server() {
    pid=$(cat "$W/server.pid")
    kill "$pid" 2>/dev/null
    wait "$SRV" 2>/dev/null
    while kill -0 "$pid" 2>/dev/null; do sleep 0.1; done
    rm -f "$W/server.pid"
    SRV=""
}
audit() { # audit <name> [args]: run the profile, TAP into $W/<name>.tap
    name=$1
    shift
    # the target's certificate: from its first GetEndpoints, or (PIN=pki:
    # the setup tests, whose setup-no-cert mutant presents none) the
    # self-signed one in its PKI
    if [ "$PIN" = pki ]; then
        set -- --server-cert "$(ls "$W/pki-$NAME"/ApplCerts/own/certs/selfsigned*.der | head -1)" "$@"
    else
        set -- --tofu "$@"
    fi
    "$B/gdsaudit" server --url "opc.tcp://127.0.0.1:$PORT" --work "$W/auditor" \
        --user operator --user-password-file "$W/user.pw" --allow-changes --settle-timeout 40 \
        --restart-cmd "sh '$W/restart-$NAME.sh'" "$@" \
        > "$W/$name.tap" 2>&1
}

RC=0
SLOW_TESTS="SRV-TL-18"
# the setup tests: push_test_server --setup, selected with --only SRV-SET
SETUP_ARGS="--only SRV-SET --allow-reset"
PIN=tofu
if { [ -z "$ONLY" ] && $FIRST; } || [ "$ONLY" = good ]; then
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

# The tests that need SupportedPrivateKeyFormats: push_test_server
# --accept-keys, each test on its own (SRV-UPD-09 runs only by name)
KEY_TESTS="SRV-UPD-09 SRV-UPD-10"
if { [ -z "$ONLY" ] && $FIRST; } || [ "$ONLY" = good ]; then
    for test in $KEY_TESTS; do
        echo "=== good push_test_server --accept-keys, $test"
        start_server "keys-$test" --accept-keys
        audit "keys-$test" --only "$test" --expect "$E/push_test_server_keys.csv"
        G=$?
        stop_server
        cat "$W/keys-$test.tap"
        if [ $G -ne 0 ]; then
            echo "FAILED: $test against push_test_server --accept-keys differs from push_test_server_keys.csv"
            tail -40 "$W/server-keys-$test.log"
            RC=1
        fi
    done
fi

# Push setup (SRV-SET-*): the target starts in application setup
if { [ -z "$ONLY" ] && $FIRST; } || [ "$ONLY" = good ]; then
    echo "=== good push_test_server --setup, SRV-SET"
    start_server setup --setup
    PIN=pki
    audit setup $SETUP_ARGS --setup-cmd "sh '$W/restart-setup.sh' fresh" \
        --expect "$E/push_test_server_setup.csv"
    G=$?
    PIN=tofu
    stop_server
    cat "$W/setup.tap"
    if [ $G -ne 0 ]; then
        echo "FAILED: SRV-SET against push_test_server --setup differs from push_test_server_setup.csv"
        tail -40 "$W/server-setup.log"
        RC=1
    fi
fi

IDX=0
while IFS=, read -r mutant test want; do
    case "$mutant" in ''|\#*) continue ;; esac
    IDX=$((IDX + 1))
    [ -n "$ONLY" ] && [ "$ONLY" != "$mutant" ] && continue
    [ -z "$ONLY" ] && [ $(( (IDX - 1) % SN + 1 )) -ne "$SK" ] && continue
    case "$test" in
    SRV-SET-*)
        start_server "$mutant" --setup --break "$mutant"
        PIN=pki
        audit "$mutant" $SETUP_ARGS --setup-cmd "sh '$W/restart-$mutant.sh' fresh" \
            --stop-after "$test"
        PIN=tofu
        ;;
    *)
        if case " $KEY_TESTS " in *" $test "*) true ;; *) false ;; esac; then
            start_server "$mutant" --break "$mutant" --accept-keys
            audit "$mutant" --only "$test"
        else
            start_server "$mutant" --break "$mutant"
            # tests flagged slow in the catalogue run only for their own mutant;
            # the tests after the one that must catch the mutant are not run
            case " $SLOW_TESTS " in
            *" $test "*) audit "$mutant" --slow --stop-after "$test" ;;
            *) audit "$mutant" --stop-after "$test" ;;
            esac
        fi
        ;;
    esac
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
