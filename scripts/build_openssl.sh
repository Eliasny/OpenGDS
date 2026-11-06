#!/bin/sh
# Build the pinned OpenSSL 3.5 LTS (docs/architecture.md F3: OpenGDS requires
# OpenSSL 3.5; distributions such as Ubuntu 24.04 still ship 3.0).
# Usage: scripts/build_openssl.sh <prefix> [<workdir>]
# Static libraries only, so binaries carry no runtime dependency on an old
# system libssl. The tarball is checked against the pinned SHA-256.
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
    curl -fsSL --proto '=https' --tlsv1.2 -o "$TARBALL.part" \
        "https://github.com/openssl/openssl/releases/download/openssl-$VERSION/$TARBALL"
    mv "$TARBALL.part" "$TARBALL"
fi
echo "$SHA256  $TARBALL" | sha256sum -c -
rm -rf "openssl-$VERSION"
tar xzf "$TARBALL"
cd "openssl-$VERSION"
./Configure --prefix="$PREFIX" --libdir=lib --openssldir="$PREFIX/ssl" \
    no-shared no-tests no-docs no-legacy no-weak-ssl-ciphers no-ssl3 no-comp \
    -fPIC -fstack-protector-strong -D_FORTIFY_SOURCE=2 > configure.log
make -j"$(nproc)" > build.log
make install_sw > install.log
"$PREFIX/bin/openssl" version
