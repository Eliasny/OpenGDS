#!/bin/sh
# Build one of the Auditor's portable release artifacts with its SBOM, in the
# release workflow's Debian build container (scripts/release/install-build-deps.sh
# static|windows first).
# SPDX-License-Identifier: MPL-2.0
#
# Usage: scripts/release/build-auditor.sh static|windows <out-dir>
#
#   static    gdsaudit-<ver>-linux-<arch>-static.tar.gz   (packaging/static/build.sh)
#   windows   gdsaudit-<ver>-windows-x86_64.zip           (packaging/windows/build.sh)
#
# Each with <artifact>.spdx.json, auditor-<kind>-<arch>.buildenv.txt (the
# Debian packages installed) and SHA256SUMS, like build-release.sh, so the
# workflow compares two builds the same way.
#
# Environment: WORK scratch directory (default: mktemp)
set -eu

KIND=${1:?usage: build-auditor.sh static|windows <out-dir>}
OUT=${2:?usage: build-auditor.sh static|windows <out-dir>}
SRC=$(cd "$(dirname "$0")/../.." && pwd)
WORK=${WORK:-$(mktemp -d)}
export LC_ALL=C TZ=UTC
umask 022

cd "$SRC"
if [ -z "${ALLOW_DIRTY:-}" ] && [ -n "$(git status --porcelain --untracked-files=no)" ]; then
    echo "build-auditor.sh: uncommitted changes; commit them (or set ALLOW_DIRTY=1 for a trial)" >&2
    exit 1
fi
COMMIT=$(git rev-parse HEAD)
SOURCE_DATE_EPOCH=$(git log -1 --format=%ct HEAD)
export SOURCE_DATE_EPOCH
VERSION=$(sed -n 's/^project(OpenGDS VERSION \([0-9.]*\).*/\1/p' CMakeLists.txt)

case "$KIND" in
    static)  RUNTIME=musl;      ARCH=$(uname -m) ;;
    windows) RUNTIME=mingw-w64; ARCH=x86_64 ;;
    *) echo "build-auditor.sh: unknown kind $KIND" >&2; exit 1 ;;
esac

mkdir -p "$OUT" "$WORK"
OUT=$(cd "$OUT" && pwd)
# The build scripts keep their build tree and logs next to the artifact:
# build in $WORK, take only the artifact.
rm -rf "$WORK/out"
"$SRC/packaging/$KIND/build.sh" "$WORK/out" "$WORK/cache"
for f in "$WORK"/out/gdsaudit-*.tar.gz "$WORK"/out/gdsaudit-*.zip; do
    [ -e "$f" ] || continue
    n=$(basename "$f")
    cp "$f" "$OUT/$n"
    python3 -I "$SRC/scripts/release/sbom.py" --artifact "$OUT/$n" \
        --source "$SRC" --commit "$COMMIT" --version "$VERSION" --format STATIC --runtime "$RUNTIME" \
        --openssl-prefix "$WORK/cache/openssl" --open62541-prefix "$WORK/cache/open62541" \
        > "$OUT/$n.spdx.json"
done

dpkg-query -W -f='${Package} ${Version} ${Architecture}\n' | LC_ALL=C sort \
    > "$OUT/auditor-$KIND-$ARCH.buildenv.txt"

(cd "$OUT" && find . -maxdepth 1 -type f ! -name SHA256SUMS -printf '%f\n' | sort |
    xargs sha256sum > SHA256SUMS)
cat "$OUT/SHA256SUMS"
