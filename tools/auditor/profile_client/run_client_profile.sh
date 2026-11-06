#!/bin/sh
# Run the client profile (gdsaudit client) against the pull test client:
# once as the good client against the pinned verdicts, then once per
# --break mutant, each of which must trip its test with its verdict.
# Usage: run_client_profile.sh <bindir> <workdir> <expected-dir> [good|mutants]
# SPDX-License-Identifier: MPL-2.0
set -u
B=$(cd "$1" && pwd)
W=$2
E=$(cd "$3" && pwd)
WHAT=${4:-good}
PORT=${GDS_PORT:-4853}
rm -rf "$W"
mkdir -p "$W"
W=$(cd "$W" && pwd)

run() { # workdir, gdsaudit options..., -- trigger...
    d=$1
    shift
    "$B/gdsaudit" client --listen "$PORT" --work "$d" --cycle-timeout 60 "$@"
}

if [ "$WHAT" = good ]; then
    run "$W/good" --expect "$E/pull_test_client.csv" -- "$B/pull_test_client" --from-env
    RC=$?
    echo "# gdsaudit exit code $RC"
    [ $RC -ne 0 ] && tail -40 "$W/good/trigger.log"
    exit $RC
fi

FAILED=0
grep -v '^#' "$E/mutants.csv" | while IFS=, read -r mutant test verdict extra; do
    [ -z "$mutant" ] && continue
    printf '%s,%s\n' "$test" "$verdict" > "$W/$test-$mutant.csv"
    if [ "$mutant" = - ]; then brk=""; else brk="--break $mutant"; fi
    echo "# mutant $mutant: $test must be $verdict"
    # shellcheck disable=SC2086 # brk and extra are option lists
    run "$W/$mutant" --only "$test" --expect "$W/$test-$mutant.csv" -- \
        "$B/pull_test_client" --from-env $brk $extra
    RC=$?
    if [ $RC -ne 0 ]; then
        echo "not ok: mutant $mutant (exit $RC)"
        tail -20 "$W/$mutant/trigger.log"
        echo fail >> "$W/failed"
    fi
done
[ -f "$W/failed" ] && FAILED=1
echo "# mutants: $( [ $FAILED -eq 0 ] && echo all tripped || echo some did not trip)"
exit $FAILED
