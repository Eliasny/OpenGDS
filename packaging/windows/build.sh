#!/bin/sh
# Cross-build the headless Auditor for 64-bit Windows (Auditor plan AT5) and
# pack it as a zip: gdsaudit.exe (static: only Windows system DLLs), its
# licence and the third-party notices.
# Usage: packaging/windows/build.sh <out-dir> [<cache-dir>]
# Needs: mingw-w64 (x86_64-w64-mingw32-gcc), cmake, ninja, zip.
# The pinned OpenSSL and open62541 are cross-built once into <cache-dir>
# (default ~/.cache/opengds-win64) by scripts/build_openssl.sh and
# scripts/build_open62541.sh with TARGET=mingw64.
# SPDX-License-Identifier: MPL-2.0
set -eu
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
OUT=${1:?usage: build.sh <out-dir> [<cache-dir>]}
CACHE=${2:-$HOME/.cache/opengds-win64}
mkdir -p "$OUT" "$CACHE"
OUT=$(cd "$OUT" && pwd)
CACHE=$(cd "$CACHE" && pwd)

if [ ! -f "$CACHE/openssl/lib/libcrypto.a" ]; then
    TARGET=mingw64 "$ROOT/scripts/build_openssl.sh" "$CACHE/openssl" "$CACHE/openssl-src"
fi
# rebuild when the patch set in docs/upstream/patches changed (cmake checks it)
want=$(for p in "$ROOT"/docs/upstream/patches/v1.5.10/*.patch; do sha256sum "$p" | cut -d' ' -f1; done)
have=$(cat "$CACHE/open62541/share/opengds/open62541-patches.sha256" 2>/dev/null || true)
if [ ! -f "$CACHE/open62541/lib/libopen62541.a" ] || [ "$want" != "$have" ]; then
    TARGET=mingw64 OPENSSL_ROOT="$CACHE/openssl" \
        "$ROOT/scripts/build_open62541.sh" "$CACHE/open62541"
fi

# Reproducible: build paths mapped away, no link time stamp in the PE
# header, and zip entries dated SOURCE_DATE_EPOCH (default: the last
# commit's time)
: "${SOURCE_DATE_EPOCH:=$(git -C "$ROOT" log -1 --format=%ct 2>/dev/null || echo 0)}"
export SOURCE_DATE_EPOCH
BUILD="$OUT/build"
cmake -S "$ROOT" -B "$BUILD" -G Ninja \
    -DCMAKE_TOOLCHAIN_FILE="$ROOT/packaging/windows/mingw64.cmake" \
    -DCMAKE_C_FLAGS="-ffile-prefix-map=$ROOT=. -ffile-prefix-map=$BUILD=build" \
    -DCMAKE_EXE_LINKER_FLAGS="-Wl,--no-insert-timestamp" \
    -DCMAKE_BUILD_TYPE=Release \
    -DOPEN62541_PREFIX="$CACHE/open62541" -DOPENSSL_ROOT_DIR="$CACHE/openssl" \
    -DOPENGDS_BUILD_AUDITOR_GUI=OFF > "$OUT/configure.log"
cmake --build "$BUILD" --target gdsaudit > "$OUT/build.log"

VERSION=$(sed -n 's/^project(OpenGDS VERSION \([0-9.]*\).*/\1/p' "$ROOT/CMakeLists.txt")
PKG="gdsaudit-$VERSION-windows-x86_64"
STAGE="$OUT/$PKG"
rm -rf "$STAGE" "$OUT/$PKG.zip"
mkdir -p "$STAGE/licenses"
x86_64-w64-mingw32-strip -o "$STAGE/gdsaudit.exe" "$BUILD/tools/auditor/gdsaudit.exe"
cp "$ROOT/LICENSE" "$STAGE/licenses/OpenGDS-MPL-2.0.txt"
cp "$CACHE/open62541/src/open62541/LICENSE" "$STAGE/licenses/open62541-MPL-2.0.txt"
cp "$CACHE/openssl-src/openssl-"*/LICENSE.txt "$STAGE/licenses/OpenSSL-Apache-2.0.txt"
# The MinGW-w64 runtime (CRT start-up code, winpthreads) is linked in
cp /usr/share/doc/mingw-w64-common/copyright "$STAGE/licenses/MinGW-w64-runtime.txt"
cp "$ROOT/packaging/windows/README.txt" "$STAGE/README.txt"
# Only Windows system DLLs may be imported: the exe must run on a clean PC
BAD=$(x86_64-w64-mingw32-objdump -p "$STAGE/gdsaudit.exe" | sed -n 's/.*DLL Name: //p' |
      grep -viE '^(advapi32|crypt32|iphlpapi|kernel32|user32|ws2_32|msvcrt|bcrypt)\.dll$' || true)
if [ -n "$BAD" ]; then
    echo "gdsaudit.exe imports non-system DLLs: $BAD" >&2
    exit 1
fi
find "$STAGE" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
(cd "$OUT" && find "$PKG" -print | LC_ALL=C sort | TZ=UTC zip -qX -@ "$PKG.zip")
sha256sum "$OUT/$PKG.zip" | sed "s|$OUT/||" > "$OUT/$PKG.zip.sha256"
echo "$OUT/$PKG.zip"
