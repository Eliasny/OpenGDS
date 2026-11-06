#!/bin/sh
# Build the OpenGDS release artifacts for the distribution this runs on.
# SPDX-License-Identifier: MPL-2.0
#
# Usage: scripts/release/build-release.sh <out-dir>
#
# Produces in <out-dir>:
#   opengds-<ver>.tar.gz                    source (git archive of HEAD)    [WITH_SOURCE=1]
#   opengds-<ver>-<dist>-<arch>.tar.gz      binaries under usr/             [WITH_TGZ=1]
#   opengds_<ver>-<rel>_<arch>.deb, gdsaudit_...deb      on Debian and Ubuntu
#   opengds-<ver>-<rel>.<arch>.rpm, gdsaudit-...rpm      on EL and Fedora
#   <artifact>.spdx.json                    SPDX 2.3 SBOM for each binary artifact
#
# Reproducible: the same commit, built in the same build environment (the
# pinned container in packaging/release/), gives byte-identical artifacts.
# Every timestamp is SOURCE_DATE_EPOCH (the commit time); paths are mapped
# away with -ffile-prefix-map; locale, timezone and umask are fixed.
# scripts/release/check-reproducible.sh builds twice and compares.
#
# Environment:
#   OPENSSL_PREFIX / OPEN62541_PREFIX   prebuilt pinned dependencies (built
#                                       into $WORK/deps when unset)
#   WORK         scratch directory (default: mktemp)
#   DIST         distribution tag in package releases (default: from /etc/os-release)
#   SKIP_TESTS=1 do not run ctest
#   ALLOW_DIRTY=1  build a tree with uncommitted changes (never for a release)
set -eu

OUT=${1:?usage: build-release.sh <out-dir>}
SRC=$(cd "$(dirname "$0")/../.." && pwd)
WORK=${WORK:-$(mktemp -d)}
export LC_ALL=C TZ=UTC
umask 022

cd "$SRC"
if [ -z "${ALLOW_DIRTY:-}" ] && [ -n "$(git status --porcelain --untracked-files=no)" ]; then
    echo "build-release.sh: uncommitted changes; commit them (or set ALLOW_DIRTY=1 for a trial)" >&2
    exit 1
fi
COMMIT=$(git rev-parse HEAD)
SOURCE_DATE_EPOCH=$(git log -1 --format=%ct HEAD)
export SOURCE_DATE_EPOCH
VERSION=$(sed -n 's/^project(OpenGDS VERSION \([0-9.]*\).*/\1/p' CMakeLists.txt)
[ -n "$VERSION" ] || { echo "build-release.sh: no version in CMakeLists.txt" >&2; exit 1; }
# A release tag must name the version the build carries.
TAG=$(git describe --tags --exact-match HEAD 2>/dev/null || true)
case "$TAG" in
    v*) [ "$TAG" = "v$VERSION" ] || { echo "build-release.sh: tag $TAG but CMakeLists.txt says $VERSION" >&2; exit 1; } ;;
esac

# Distribution: picks the package format and tags the package release, so
# packages for different distributions never share a file name.
# (Read in a subshell: os-release also sets VERSION.)
eval "$(. /etc/os-release; printf 'ID=%s ID_LIKE="%s" VERSION_ID=%s\n' "${ID:-}" "${ID_LIKE:-}" "${VERSION_ID:-}")"
case "${ID:-}:${ID_LIKE:-}" in
    debian:*|ubuntu:*|*:*debian*) FORMAT=DEB ;;
    *:*rhel*|*:*fedora*|fedora:*|rhel:*) FORMAT=RPM ;;
    *) echo "build-release.sh: unsupported distribution ${ID:-unknown}" >&2; exit 1 ;;
esac
if [ -z "${DIST:-}" ]; then
    major=${VERSION_ID%%.*}
    case "$ID" in
        debian) DIST=deb$major ;;
        ubuntu) DIST=ubuntu$VERSION_ID ;;
        fedora) DIST=fc$major ;;
        *)      DIST=el$major ;;
    esac
fi
case "$FORMAT" in
    DEB) PKGREL="1~$DIST" ;;  # sorts below a distribution's own 1
    RPM) PKGREL="1.$DIST" ;;
esac
ARCH=$(uname -m)

mkdir -p "$OUT" "$WORK"
OUT=$(cd "$OUT" && pwd)

# Pinned dependencies (checksum and commit verified by the scripts).
if [ -z "${OPENSSL_PREFIX:-}" ]; then
    OPENSSL_PREFIX=$WORK/deps/openssl
    [ -e "$OPENSSL_PREFIX/bin/openssl" ] || scripts/build_openssl.sh "$OPENSSL_PREFIX" "$WORK/deps/openssl-src"
fi
if [ -z "${OPEN62541_PREFIX:-}" ]; then
    OPEN62541_PREFIX=$WORK/deps/open62541
    [ -e "$OPEN62541_PREFIX/include/open62541/config.h" ] ||
        OPENSSL_ROOT=$OPENSSL_PREFIX scripts/build_open62541.sh "$OPEN62541_PREFIX"
fi

BUILD=$WORK/build
rm -rf "$BUILD"
MAP="-ffile-prefix-map=$SRC=/usr/src/opengds-$VERSION -ffile-prefix-map=$BUILD=/usr/src/opengds-$VERSION/build"
cmake -S "$SRC" -B "$BUILD" -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_C_FLAGS="$MAP" \
    -DCMAKE_EXE_LINKER_FLAGS="-Wl,--build-id=sha1" \
    -DOPEN62541_PREFIX="$OPEN62541_PREFIX" -DOPENSSL_ROOT_DIR="$OPENSSL_PREFIX" \
    -DOPENGDS_PACKAGE_RELEASE="$PKGREL" \
    -DCPACK_PACKAGE_FILE_NAME="opengds-$VERSION-$DIST-$ARCH"
cmake --build "$BUILD"
[ -n "${SKIP_TESTS:-}" ] || ctest --test-dir "$BUILD" --output-on-failure

GENERATORS=$FORMAT
[ -z "${WITH_TGZ:-}" ] || GENERATORS="$GENERATORS;TGZ"
(cd "$BUILD" && cpack -G "$GENERATORS" -B "$BUILD/dist")

# Source archive: git archive stamps every entry with the commit time.
if [ -n "${WITH_SOURCE:-}" ]; then
    git archive --format=tar --prefix="opengds-$VERSION/" HEAD | gzip -9n > "$OUT/opengds-$VERSION.tar.gz"
fi

for f in "$BUILD"/dist/*.deb "$BUILD"/dist/*.rpm "$BUILD"/dist/*.tar.gz; do
    [ -e "$f" ] || continue
    cp "$f" "$OUT/"
    python3 -I "$SRC/scripts/release/sbom.py" --artifact "$OUT/$(basename "$f")" \
        --source "$SRC" --commit "$COMMIT" --version "$VERSION" --format "$FORMAT" \
        --openssl-prefix "$OPENSSL_PREFIX" --open62541-prefix "$OPEN62541_PREFIX" \
        > "$OUT/$(basename "$f").spdx.json"
done

(cd "$OUT" && find . -maxdepth 1 -type f ! -name SHA256SUMS -printf '%f\n' | sort |
    xargs sha256sum > SHA256SUMS)
cat "$OUT/SHA256SUMS"
