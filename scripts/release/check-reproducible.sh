#!/bin/sh
# Builds the release artifacts twice, from two clones in different
# directories, and fails unless every artifact is byte-identical.
# Usage: scripts/release/check-reproducible.sh <work-dir>
# Uses the same pinned dependencies for both builds (OPENSSL_PREFIX and
# OPEN62541_PREFIX, or built once into <work-dir>/deps). The release workflow
# additionally rebuilds on a second runner from scratch and compares.
# SPDX-License-Identifier: MPL-2.0
set -eu
W=${1:?usage: check-reproducible.sh <work-dir>}
SRC=$(cd "$(dirname "$0")/../.." && pwd)
mkdir -p "$W"
W=$(cd "$W" && pwd)
if [ -z "${OPENSSL_PREFIX:-}" ]; then
    export OPENSSL_PREFIX="$W/deps/openssl"
    [ -e "$OPENSSL_PREFIX/bin/openssl" ] || "$SRC/scripts/build_openssl.sh" "$OPENSSL_PREFIX" "$W/deps/openssl-src"
fi
if [ -z "${OPEN62541_PREFIX:-}" ]; then
    export OPEN62541_PREFIX="$W/deps/open62541"
    [ -e "$OPEN62541_PREFIX/include/open62541/config.h" ] ||
        OPENSSL_ROOT=$OPENSSL_PREFIX "$SRC/scripts/build_open62541.sh" "$OPEN62541_PREFIX"
fi
for n in a b; do
    rm -rf "${W:?}/$n"
    # Different depths, so a leaked path changes the bytes.
    d="$W/$n"; [ "$n" = b ] && d="$W/$n/deeper/tree"
    git clone --quiet --no-hardlinks "$SRC" "$d/opengds"
    git -C "$d/opengds" checkout --quiet "$(git -C "$SRC" rev-parse HEAD)"
    WORK="$d/work" SKIP_TESTS=1 WITH_TGZ=1 WITH_SOURCE=1 \
        "$d/opengds/scripts/release/build-release.sh" "$W/out-$n" > "$W/build-$n.log" 2>&1 ||
        { tail -30 "$W/build-$n.log"; exit 1; }
done
if cmp -s "$W/out-a/SHA256SUMS" "$W/out-b/SHA256SUMS"; then
    echo "reproducible: $(wc -l < "$W/out-a/SHA256SUMS") artifacts identical"
    cat "$W/out-a/SHA256SUMS"
    exit 0
fi
echo "NOT reproducible:"
diff "$W/out-a/SHA256SUMS" "$W/out-b/SHA256SUMS" || true
if command -v diffoscope >/dev/null; then
    for f in $(cd "$W/out-a" && ls); do
        cmp -s "$W/out-a/$f" "$W/out-b/$f" || diffoscope "$W/out-a/$f" "$W/out-b/$f" | head -60
    done
fi
exit 1
