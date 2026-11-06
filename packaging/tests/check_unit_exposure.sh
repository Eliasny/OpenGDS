#!/bin/sh
# Fails when `systemd-analyze security` rates a unit file above a threshold.
# Usage: check_unit_exposure.sh <systemd-analyze> <unit file> <max exposure>
# Exit 77 (skipped) when this systemd cannot check unit files offline.
# SPDX-License-Identifier: MPL-2.0
set -u
SA=$1 UNIT=$2 MAX=$3
if ! "$SA" security --help 2>/dev/null | grep -q -- '--offline'; then
    echo "systemd-analyze has no --offline (systemd < 252): skipped"
    exit 77
fi
out=$("$SA" security --offline=true --no-pager "$UNIT" 2>&1)
level=$(printf '%s\n' "$out" | sed -n 's/.*Overall exposure level for [^:]*: \([0-9.]*\).*/\1/p')
if [ -z "$level" ]; then
    printf '%s\n' "$out"
    echo "could not read the exposure level"
    exit 1
fi
printf '%s\n' "$out" | grep '✗' || true
echo "$(basename "$UNIT"): exposure $level (must be below $MAX)"
awk -v l="$level" -v m="$MAX" 'BEGIN { exit !(l < m) }'
