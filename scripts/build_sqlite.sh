#!/bin/sh
# Build a pinned SQLite as a static library, for distributions whose own
# SQLite is older than the store needs (find_package(SQLite3 3.37) in
# src/store/CMakeLists.txt): EL 9 ships 3.34. scripts/release/build-release.sh
# uses it only there; everywhere else the packages link the system SQLite.
# Usage: scripts/build_sqlite.sh <prefix> [<workdir>]
# The tarball is checked against the pinned SHA-256 (taken from the
# sqlite.org download over HTTPS on a GitHub runner, 2026-11-06; sqlite.org
# itself publishes SHA3-256). Built from the
# amalgamation with the OpenGDS hardening flags and without extension
# loading (opengdsd never loads SQLite extensions).
# SPDX-License-Identifier: MPL-2.0
set -eu
VERSION=3.50.4
NUM=3500400
YEAR=2025
SHA256=a3db587a1b92ee5ddac2f66b3edb41b26f9c867275782d46c3a088977d6a5b18
PREFIX=${1:?usage: build_sqlite.sh <prefix> [<workdir>]}
WORK=${2:-$(mktemp -d)}
mkdir -p "$WORK"
cd "$WORK"
TARBALL=sqlite-autoconf-$NUM.tar.gz
if [ ! -f "$TARBALL" ]; then
    curl -fsSL --proto '=https' --tlsv1.2 --retry 5 -o "$TARBALL.part" \
        "https://www.sqlite.org/$YEAR/$TARBALL"
    mv "$TARBALL.part" "$TARBALL"
fi
if ! echo "$SHA256  $TARBALL" | sha256sum -c - >/dev/null 2>&1; then
    echo "build_sqlite.sh: $TARBALL has SHA-256 $(sha256sum "$TARBALL" | cut -d' ' -f1), pinned $SHA256" >&2
    exit 1
fi
rm -rf "sqlite-autoconf-$NUM"
tar xzf "$TARBALL"
cd "sqlite-autoconf-$NUM"
${CC:-cc} -O2 -fPIC -fstack-protector-strong -fstack-clash-protection -D_FORTIFY_SOURCE=2 \
    -DSQLITE_THREADSAFE=1 -DSQLITE_OMIT_LOAD_EXTENSION -DSQLITE_DQS=0 \
    -c sqlite3.c -o sqlite3.o
mkdir -p "$PREFIX/lib" "$PREFIX/include" "$PREFIX/share/doc/sqlite"
ar rcs "$PREFIX/lib/libsqlite3.a" sqlite3.o
cp sqlite3.h sqlite3ext.h "$PREFIX/include/"
echo "$VERSION $SHA256 https://www.sqlite.org/$YEAR/$TARBALL" > "$PREFIX/share/doc/sqlite/pinned"
echo "SQLite $VERSION installed in $PREFIX"
