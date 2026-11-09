#!/bin/sh
# Build the Auditor's Flatpak bundle (packaging/flatpak/org.opengds.Auditor.yml)
# with its SBOM. Needs flatpak, flatpak-builder and the flathub remote (user
# installation); the SBOM needs the pinned open62541, built here the same way
# as for the packages (the manifest repeats those pins: CTest
# packaging_flatpak_pins).
# SPDX-License-Identifier: MPL-2.0
#
# Usage: scripts/release/build-flatpak.sh <out-dir>
#   -> gdsaudit-gui-<ver>-<arch>.flatpak, .spdx.json, SHA256SUMS
#
# Not byte-for-byte reproducible (the OSTree commit records its build time),
# so the release builds it once.
#
# Environment: WORK scratch directory (default: mktemp)
set -eu

OUT=${1:?usage: build-flatpak.sh <out-dir>}
SRC=$(cd "$(dirname "$0")/../.." && pwd)
WORK=${WORK:-$(mktemp -d)}
export LC_ALL=C TZ=UTC
umask 022

cd "$SRC"
COMMIT=$(git rev-parse HEAD)
SOURCE_DATE_EPOCH=$(git log -1 --format=%ct HEAD)
export SOURCE_DATE_EPOCH
VERSION=$(sed -n 's/^project(OpenGDS VERSION \([0-9.]*\).*/\1/p' CMakeLists.txt)
ARCH=$(flatpak --default-arch)
APP=org.opengds.Auditor
MANIFEST=packaging/flatpak/$APP.yml

mkdir -p "$OUT" "$WORK"
OUT=$(cd "$OUT" && pwd)
flatpak-builder --user --install-deps-from=flathub --disable-rofiles-fuse --force-clean \
    --state-dir="$WORK/state" --default-branch=stable --repo="$WORK/repo" \
    "$WORK/build" "$MANIFEST"
B="gdsaudit-gui-$VERSION-$ARCH.flatpak"
flatpak build-bundle --runtime-repo=https://dl.flathub.org/repo/flathub.flatpakrepo \
    "$WORK/repo" "$OUT/$B" "$APP" stable

[ -e "$WORK/deps/openssl/bin/openssl" ] || scripts/build_openssl.sh "$WORK/deps/openssl" "$WORK/deps/openssl-src"
[ -e "$WORK/deps/open62541/include/open62541/config.h" ] ||
    OPENSSL_ROOT="$WORK/deps/openssl" scripts/build_open62541.sh "$WORK/deps/open62541"
python3 -I "$SRC/scripts/release/sbom.py" --artifact "$OUT/$B" \
    --source "$SRC" --commit "$COMMIT" --version "$VERSION" \
    --format FLATPAK --flatpak-manifest "$MANIFEST" \
    --openssl-prefix "$WORK/deps/openssl" --open62541-prefix "$WORK/deps/open62541" \
    > "$OUT/$B.spdx.json"

(cd "$OUT" && find . -maxdepth 1 -type f ! -name SHA256SUMS -printf '%f\n' | sort |
    xargs sha256sum > SHA256SUMS)
cat "$OUT/SHA256SUMS"
