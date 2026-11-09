#!/bin/sh
# Build the pinned OpenSSL 3.5 LTS (docs/architecture.md F3: OpenGDS requires
# OpenSSL 3.5; distributions such as Ubuntu 24.04 still ship 3.0).
# Usage: scripts/build_openssl.sh <prefix> [<workdir>]
# Static libraries only, so binaries carry no runtime dependency on an old
# system libssl. The tarball is checked against the pinned SHA-256.
#   TARGET=mingw64  cross-build for 64-bit Windows with MinGW-w64 (the
#                   Auditor's Windows build, packaging/windows/README.md)
#   TARGET=musl     static libraries for musl-gcc, MUSL_KINC naming the
#                   kernel headers folder (the static gdsaudit,
#                   packaging/static/build.sh)
# SPDX-License-Identifier: MPL-2.0
set -eu
VERSION=3.5.9
SHA256=603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a
PREFIX=$1
WORK=${2:-$(mktemp -d)}
mkdir -p "$WORK"
cd "$WORK"
TARBALL=openssl-$VERSION.tar.gz
if [ ! -f "$TARBALL" ]; then
    curl -fsSL --proto '=https' --tlsv1.2 --retry 5 -o "$TARBALL.part" \
        "https://github.com/openssl/openssl/releases/download/openssl-$VERSION/$TARBALL"
    mv "$TARBALL.part" "$TARBALL"
fi
echo "$SHA256  $TARBALL" | sha256sum -c -
rm -rf "openssl-$VERSION"
tar xzf "$TARBALL"
cd "openssl-$VERSION"
OPTS="no-shared no-tests no-docs no-legacy no-weak-ssl-ciphers no-ssl3 no-comp"
if [ "${TARGET:-}" = mingw64 ]; then
    # shellcheck disable=SC2086
    ./Configure mingw64 --cross-compile-prefix=x86_64-w64-mingw32- --prefix="$PREFIX" \
        --libdir=lib --openssldir="C:/Program Files/OpenGDS Auditor/ssl" $OPTS \
        -fstack-protector-strong > configure.log
    make -j"$(nproc)" build_libs > build.log
    make install_dev > install.log
    echo "OpenSSL $VERSION for Windows (mingw64) installed in $PREFIX"
    exit 0
fi
if [ "${TARGET:-}" = musl ]; then
    # no-async: musl has no makecontext; no-afalgeng/no-engine: nothing
    # outside the binary is loaded
    # shellcheck disable=SC2086
    CC="musl-gcc -isystem ${MUSL_KINC:?set MUSL_KINC}" ./Configure "linux-$(uname -m)" \
        --prefix="$PREFIX" --libdir=lib --openssldir=/etc/ssl $OPTS \
        no-afalgeng no-async no-engine -fPIC -fstack-protector-strong > configure.log
    make -j"$(nproc)" build_libs > build.log
    make install_dev > install.log
    echo "OpenSSL $VERSION for musl installed in $PREFIX"
    exit 0
fi
# shellcheck disable=SC2086
./Configure --prefix="$PREFIX" --libdir=lib --openssldir="$PREFIX/ssl" $OPTS \
    -fPIC -fstack-protector-strong -D_FORTIFY_SOURCE=2 > configure.log
make -j"$(nproc)" > build.log
make install_sw > install.log
"$PREFIX/bin/openssl" version
