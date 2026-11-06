#!/bin/sh
# Build the throwaway spikes against an open62541 prefix made by
# scripts/build_open62541.sh (v1.5.10, OpenGDS flags).
# Usage: docs/spikes/code/build.sh <open62541-prefix>
# SPDX-License-Identifier: MPL-2.0
set -eu
P=${1:?usage: build.sh <open62541-prefix>}
cd "$(dirname "$0")"
for s in spike_dialog spike_async; do
    ${CC:-cc} -std=c11 -D_GNU_SOURCE -g -O1 -Wall -Wextra -Wno-unused-parameter \
        -I"$P/include" ${CFLAGS:-} -o "$s" "$s.c" "$P/lib/libopen62541.a" \
        -lssl -lcrypto -lpthread -lm ${LDFLAGS:-}
done
echo "built ./spike_dialog [N] and ./spike_async (PATTERN=direct|deadlock)"
