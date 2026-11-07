#!/bin/sh
# Build the static Linux gdsaudit (Auditor plan AT5, "Headless: static Linux
# binaries") and pack it as a tarball: one static PIE linked with musl, the
# pinned OpenSSL and open62541, so it runs on any Linux of its architecture
# and in a distroless/static container (packaging/static/Dockerfile).
# Usage: packaging/static/build.sh <out-dir> [<cache-dir>]
# Needs: musl-tools (musl-gcc), linux-libc-dev, cmake, ninja, git, curl, perl.
# The pinned OpenSSL and open62541 are built once into <cache-dir> (default
# ~/.cache/opengds-musl) by scripts/build_openssl.sh and
# scripts/build_open62541.sh with TARGET=musl.
# Reproducible: SOURCE_DATE_EPOCH (default: the last commit's time) sets
# every time stamp in the tarball, and build paths are mapped away.
# SPDX-License-Identifier: MPL-2.0
set -eu
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
OUT=${1:?usage: build.sh <out-dir> [<cache-dir>]}
CACHE=${2:-$HOME/.cache/opengds-musl}
mkdir -p "$OUT" "$CACHE"
OUT=$(cd "$OUT" && pwd)
CACHE=$(cd "$CACHE" && pwd)
ARCH=$(uname -m)
# (in a container build without .git: pass it, or the time stamps are 0)
: "${SOURCE_DATE_EPOCH:=$(git -C "$ROOT" log -1 --format=%ct 2>/dev/null || echo 0)}"
export SOURCE_DATE_EPOCH

# musl-gcc has no kernel headers; OpenSSL and open62541 need a few
# (linux/mman.h, linux/if_*.h). Point at the system's, nothing else.
MUSL_KINC="$CACHE/kernel-include"
MULTIARCH=$(gcc -print-multiarch)
mkdir -p "$MUSL_KINC"
ln -sfn /usr/include/linux "$MUSL_KINC/linux"
ln -sfn /usr/include/asm-generic "$MUSL_KINC/asm-generic"
ln -sfn "/usr/include/$MULTIARCH/asm" "$MUSL_KINC/asm"
export MUSL_KINC

if [ ! -f "$CACHE/openssl/lib/libcrypto.a" ]; then
    TARGET=musl "$ROOT/scripts/build_openssl.sh" "$CACHE/openssl" "$CACHE/openssl-src"
fi
# rebuild when the patch set in docs/upstream/patches changed (cmake checks it)
want=$(for p in "$ROOT"/docs/upstream/patches/v1.5.10/*.patch; do sha256sum "$p" | cut -d' ' -f1; done)
have=$(cat "$CACHE/open62541/share/opengds/open62541-patches.sha256" 2>/dev/null || true)
if [ ! -f "$CACHE/open62541/lib/libopen62541.a" ] || [ "$want" != "$have" ]; then
    TARGET=musl OPENSSL_ROOT="$CACHE/openssl" \
        "$ROOT/scripts/build_open62541.sh" "$CACHE/open62541"
fi

BUILD="$OUT/build"
cmake -S "$ROOT" -B "$BUILD" -G Ninja \
    -DCMAKE_C_COMPILER=musl-gcc \
    -DCMAKE_C_FLAGS="-isystem $MUSL_KINC -ffile-prefix-map=$ROOT=. -ffile-prefix-map=$BUILD=build" \
    -DCMAKE_EXE_LINKER_FLAGS="-Wl,--build-id=sha1" \
    -DCMAKE_BUILD_TYPE=Release \
    -DOPENGDS_AUDITOR_ONLY=ON -DOPENGDS_STATIC=ON -DOPENGDS_BUILD_AUDITOR_GUI=OFF \
    -DOPEN62541_PREFIX="$CACHE/open62541" -DOPENSSL_ROOT_DIR="$CACHE/openssl" > "$OUT/configure.log"
cmake --build "$BUILD" --target gdsaudit > "$OUT/build.log"

VERSION=$(sed -n 's/^project(OpenGDS VERSION \([0-9.]*\).*/\1/p' "$ROOT/CMakeLists.txt")
PKG="gdsaudit-$VERSION-linux-$ARCH-static"
STAGE="$OUT/$PKG"
rm -rf "$STAGE" "$OUT/$PKG.tar.gz"
mkdir -p "$STAGE/licenses"
strip -o "$STAGE/gdsaudit" "$BUILD/tools/auditor/gdsaudit"
cp "$ROOT/LICENSE" "$STAGE/licenses/OpenGDS-MPL-2.0.txt"
cp "$CACHE/open62541/src/open62541/LICENSE" "$STAGE/licenses/open62541-MPL-2.0.txt"
cp "$CACHE/openssl-src/openssl-"*/LICENSE.txt "$STAGE/licenses/OpenSSL-Apache-2.0.txt"
cp /usr/share/doc/musl/copyright "$STAGE/licenses/musl-MIT.txt"
cp "$ROOT/packaging/static/README.txt" "$STAGE/README.txt"
# Nothing may be loaded at run time: no interpreter, no shared libraries
if readelf -lW "$STAGE/gdsaudit" | grep -q INTERP || readelf -d "$STAGE/gdsaudit" | grep -q NEEDED; then
    echo "gdsaudit is not static" >&2
    exit 1
fi
# It runs: create an identity and test PKI (OpenSSL, open62541, files)
rm -rf "$OUT/smoke"
"$STAGE/gdsaudit" server --work "$OUT/smoke" --init-only > /dev/null 2>&1
rm -rf "$OUT/smoke"
chmod 0755 "$STAGE/gdsaudit"
find "$STAGE" -type d -exec chmod 0755 {} + && find "$STAGE" -type f ! -name gdsaudit -exec chmod 0644 {} +
tar --sort=name --mtime="@$SOURCE_DATE_EPOCH" --owner=0 --group=0 --numeric-owner \
    -C "$OUT" -cf - "$PKG" | gzip -9n > "$OUT/$PKG.tar.gz"
sha256sum "$OUT/$PKG.tar.gz" | sed "s|$OUT/||" > "$OUT/$PKG.tar.gz.sha256"
echo "$OUT/$PKG.tar.gz"
