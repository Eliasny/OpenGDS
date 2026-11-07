#!/bin/sh
# Check the Windows build on Linux: gdsaudit.exe, run under Wine, must give
# the verdicts pinned for the Linux build against the Linux self-test
# targets: the full server profile against the good push_test_server and
# the GDS profile against mock_gds. (The client profile needs a Windows
# pull client as its trigger; it is covered by the Windows smoke test.)
# Usage: check_under_wine.sh <linux-bindir> <gdsaudit.exe> <workdir>
# SPDX-License-Identifier: MPL-2.0
set -u
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
B=$(cd "$1" && pwd)
EXE=$(cd "$(dirname "$2")" && pwd)/$(basename "$2")
mkdir -p "$3"
W=$(cd "$3" && pwd)
export GDSAUDIT="$ROOT/packaging/windows/gdsaudit-wine" GDSAUDIT_EXE="$EXE"
export WINEPREFIX=${WINEPREFIX:-$W/wineprefix}
# Create the Wine prefix before the runs and keep one wineserver for the
# whole check. A wineserver that exits between two runs restarts Wine's
# services at the next start, and connections made meanwhile fail at random
# (BadSecurityPolicyRejected, BadCertificateInvalid within ~1 s).
WINE=${WINE:-$(command -v wine64 || command -v wine || echo /usr/lib/wine/wine64)}
WINESERVER=$(command -v wineserver || echo /usr/lib/wine/wineserver)
export WINE
WINEDEBUG=-all "$WINESERVER" -p
trap 'WINEDEBUG=-all "$WINESERVER" -k 2>/dev/null' EXIT
WINEDEBUG=-all "$WINE" wineboot -i > /dev/null 2>&1 || true
RC=0
echo "=== server profile, gdsaudit.exe vs the good push_test_server"
ONLY=good PUSH_PORT=${PUSH_PORT:-5901} sh "$ROOT/tools/auditor/profile_server/run_vs_push.sh" \
    "$B" "$W/server" "$ROOT/tools/auditor/profile_server/expected" || RC=1
echo "=== GDS profile, gdsaudit.exe vs mock_gds"
GDS_PORT=${GDS_PORT:-5951} sh "$ROOT/tools/auditor/profile_gds/run_vs_mock.sh" \
    "$B" "$W/gds" "$ROOT/tools/auditor/profile_gds/expected/mock_gds.csv" || RC=1
# Auditor plan AT5 gate (headless half): one plan file gives the same
# verdicts on Windows as the pins of the Linux build
echo "=== GDS profile from a plan file, gdsaudit.exe run plan.toml vs mock_gds"
PLAN=1 GDS_PORT=${GDS_PLAN_PORT:-5952} sh "$ROOT/tools/auditor/profile_gds/run_vs_mock.sh" \
    "$B" "$W/gds-plan" "$ROOT/tools/auditor/profile_gds/expected/mock_gds.csv" || RC=1
[ $RC -eq 0 ] && echo "ok: gdsaudit.exe gives the pinned verdicts" || echo "FAILED"
exit $RC
