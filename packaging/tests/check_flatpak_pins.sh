#!/bin/sh
# The Flatpak manifest builds OpenSSL and open62541 itself (no network in
# flatpak-builder's build step), so it repeats their pins. Check that it
# names the same OpenSSL version and SHA-256, open62541 tag and commit, and
# every patch in docs/upstream/patches/v1.5.10, in order.
# Usage: check_flatpak_pins.sh <source dir>
# SPDX-License-Identifier: MPL-2.0
set -eu
SRC=$1
M="$SRC/packaging/flatpak/org.opengds.Auditor.yml"
pin() { sed -n "s/^$1=\\(.*\\)$/\\1/p" "$2"; }
fail=0
need() { # need <what> <text>
    grep -qF -- "$2" "$M" || { echo "manifest lacks $1: $2"; fail=1; }
}
V=$(pin VERSION "$SRC/scripts/build_openssl.sh")
need "the OpenSSL tarball" "openssl-$V/openssl-$V.tar.gz"
need "the OpenSSL SHA-256" "sha256: $(pin SHA256 "$SRC/scripts/build_openssl.sh")"
need "the open62541 tag" "tag: $(pin TAG "$SRC/scripts/build_open62541.sh")"
need "the open62541 commit" "commit: $(pin COMMIT "$SRC/scripts/build_open62541.sh")"
want=$(cd "$SRC/docs/upstream/patches/v1.5.10" && ls -1 ./*.patch | sed 's|^\./||')
have=$(sed -n 's|^ *path: \.\./\.\./docs/upstream/patches/v1\.5\.10/||p' "$M")
if [ "$want" != "$have" ]; then
    echo "manifest patches differ from docs/upstream/patches/v1.5.10:"
    echo "want:"; echo "$want"; echo "have:"; echo "$have"
    fail=1
fi
# A text check passes on a manifest flatpak-builder can't parse: parse it
# too where PyYAML is there
if python3 -c 'import yaml' 2>/dev/null; then
    python3 -I -c 'import sys, yaml; yaml.safe_load(open(sys.argv[1]))' "$M" ||
        { echo "manifest is not valid YAML"; fail=1; }
fi
[ "$fail" = 0 ] && echo "Flatpak pins match the build scripts"
exit "$fail"
