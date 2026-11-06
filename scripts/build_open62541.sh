#!/bin/sh
# Build the pinned open62541 v1.5.10 into a prefix, with only the features
# OpenGDS uses and the OpenGDS hardening flags (docs/architecture.md, F2/F6).
# SPDX-License-Identifier: MPL-2.0
#
# Usage: scripts/build_open62541.sh <prefix> [<src-dir>]
#   SANITIZE=address,undefined  also instrument the library (ASan CI job)
#   CC=clang                    compiler
#   OPENSSL_ROOT=<prefix>       OpenSSL 3.5 from scripts/build_openssl.sh (required)
set -eu

TAG=v1.5.10
COMMIT=93c3bdfc9ea4718b503c6cbf57876237addd0f2c

PREFIX=${1:?usage: build_open62541.sh <prefix> [<src-dir>]}
SRC=${2:-$PREFIX/src/open62541}
SANITIZE=${SANITIZE:-}
OPENSSL_ROOT=${OPENSSL_ROOT:?set OPENSSL_ROOT to an OpenSSL 3.5 prefix (scripts/build_openssl.sh)}

if [ ! -d "$SRC/.git" ]; then
    git clone --quiet --depth 1 --branch "$TAG" --recurse-submodules \
        --shallow-submodules https://github.com/open62541/open62541.git "$SRC"
fi
GOT=$(git -C "$SRC" rev-parse HEAD)
if [ "$GOT" != "$COMMIT" ]; then
    echo "open62541 $TAG resolves to $GOT, expected $COMMIT: refusing to build" >&2
    exit 1
fi

# Carry our fixes for the open62541 v1.5.10 gaps until upstream releases them
# (docs/upstream/README.md): key file after a key-kept CSR push, #None for
# discovery in the secure-only config, GDS headers installed with AUTOLOAD,
# ConditionRefresh keeping the original EventId (Part 9, 5.5.7).
# A cached source tree may already have them; apply each patch only once.
PATCHES="$(cd "$(dirname "$0")/.." && pwd)/docs/upstream/patches/v1.5.10"
for p in "$PATCHES"/*.patch; do
    if git -C "$SRC" apply --reverse --check "$p" 2>/dev/null; then
        continue
    fi
    git -C "$SRC" apply "$p"
done

# Hardening flags for the library itself (warnings are left to upstream).
HARDEN="-O2 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3 -fstack-protector-strong \
-fstack-clash-protection -fno-delete-null-pointer-checks -fno-strict-overflow \
-fno-strict-aliasing -ftrivial-auto-var-init=zero -fPIE"
case "$(uname -m)" in
    x86_64) HARDEN="$HARDEN -fcf-protection=full" ;;
    aarch64|arm64) HARDEN="$HARDEN -mbranch-protection=standard" ;;
esac
LDHARDEN="-Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack"
if [ -n "$SANITIZE" ]; then
    HARDEN="-O1 -g -fno-omit-frame-pointer -fsanitize=$SANITIZE"
    LDHARDEN="-fsanitize=$SANITIZE"
    # Clang's UBSan "function" check fires on open62541's own EventLoop
    # function-pointer casts (v1.5.10); every other UBSan check stays on.
    case "$SANITIZE" in
        *undefined*) "${CC:-cc}" --version | grep -q clang && HARDEN="$HARDEN -fno-sanitize=function" ;;
    esac
fi

# JSON stays on: v1.5.10 needs it for event filter parsing (events, A&C).
# LTO off: a static library of LTO bitcode links only with the same compiler.
# XML stays on: without it the generated GDS nodeset has no Value attributes,
# so methods lose their InputArguments and every call fails BadTooManyArguments.
BUILD="$SRC/build-opengds"
cmake -S "$SRC" -B "$BUILD" -G "${CMAKE_GENERATOR:-Ninja}" \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DCMAKE_INSTALL_PREFIX="$PREFIX" \
    -DCMAKE_C_FLAGS="$HARDEN" \
    -DCMAKE_EXE_LINKER_FLAGS="$LDHARDEN" \
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
    -DCMAKE_INTERPROCEDURAL_OPTIMIZATION=OFF \
    -DBUILD_SHARED_LIBS=OFF \
    -DUA_NAMESPACE_ZERO=FULL \
    -DUA_ENABLE_ENCRYPTION=OPENSSL \
    -DOPENSSL_ROOT_DIR="$OPENSSL_ROOT" \
    -DOPENSSL_USE_STATIC_LIBS=TRUE \
    -DUA_ENABLE_GDS_PUSHMANAGEMENT=ON \
    -DUA_INFORMATION_MODEL_AUTOLOAD=GDS \
    -DUA_ENABLE_SUBSCRIPTIONS_EVENTS=ON \
    -DUA_ENABLE_SUBSCRIPTIONS_ALARMS_CONDITIONS=ON \
    -DUA_MULTITHREADING=100 \
    -DUA_ENABLE_PUBSUB=OFF \
    -DUA_ENABLE_HISTORIZING=OFF \
    -DUA_ENABLE_XML_ENCODING=ON \
    -DUA_ENABLE_JSON_ENCODING=ON \
    -DUA_ENABLE_MQTT=OFF \
    -DUA_BUILD_EXAMPLES=OFF \
    -DUA_BUILD_UNIT_TESTS=OFF
cmake --build "$BUILD"
cmake --install "$BUILD"

for h in types_gds_generated.h nodeids_gds.h; do
    [ -f "$PREFIX/include/open62541/$h" ] || { echo "missing installed $h" >&2; exit 1; }
done
# The patched tree reports itself as v1.5.10-dirty. Record which patches
# were applied so cmake/open62541.cmake can check them against the repository.
mkdir -p "$PREFIX/share/opengds"
: > "$PREFIX/share/opengds/open62541-patches.sha256"
for p in "$PATCHES"/*.patch; do
    sha256sum "$p" | cut -d' ' -f1 >> "$PREFIX/share/opengds/open62541-patches.sha256"
done
echo "open62541 $TAG ($COMMIT) installed in $PREFIX"
