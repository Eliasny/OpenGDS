#!/bin/sh
# Installs the build tree into a scratch root with the release prefix (/usr)
# and checks that every file the packages ship lands where the systemd unit,
# the example configuration and docs/packaging.md say it does.
# Usage: check_install_layout.sh <build dir> <scratch dir>
# SPDX-License-Identifier: MPL-2.0
set -eu
BUILD=$1 ROOT=$2/root
rm -rf "$2"
mkdir -p "$ROOT"
DESTDIR="$ROOT" cmake --install "$BUILD" --prefix /usr >/dev/null
fail=0
want() { # want <mode> <path>
    if [ ! -e "$ROOT$2" ]; then
        echo "missing: $2"; fail=1; return
    fi
    m=$(stat -c %a "$ROOT$2")
    if [ "$m" != "$1" ]; then
        echo "mode $m, want $1: $2"; fail=1
    fi
}
if [ -e "$BUILD/src/daemon/opengdsd" ]; then
    want 755 /usr/bin/opengdsd
    want 755 /usr/bin/gdsadm
    want 755 /usr/libexec/opengds/opengds-signer
    want 644 /usr/lib/systemd/system/opengds.service
    want 644 /usr/lib/systemd/system/opengds-signer.socket
    want 644 /usr/lib/systemd/system/opengds-signer@.service
    want 644 /usr/lib/sysusers.d/opengds.conf
    want 644 /usr/share/doc/opengds/opengds.conf.example
    want 644 /usr/share/doc/opengds/LICENSE
    # The units and the example configuration must name the installed paths.
    for f in /usr/lib/systemd/system/opengds.service /usr/lib/systemd/system/opengds-signer@.service \
             /usr/share/doc/opengds/opengds.conf.example; do
        for p in $(grep -o '/usr/[A-Za-z0-9_/.-]*' "$ROOT$f" | sort -u); do
            case "$p" in /usr/share/doc/*) continue ;; esac
            [ -e "$ROOT$p" ] || { echo "$f names $p, which is not installed"; fail=1; }
        done
    done
fi
if [ -e "$BUILD/tools/auditor/gdsaudit" ]; then
    want 755 /usr/bin/gdsaudit
fi
# Nothing outside /usr: configuration and state are created at run time.
extra=$(cd "$ROOT" && find . -mindepth 1 -maxdepth 1 ! -name usr)
if [ -n "$extra" ]; then
    echo "installed outside /usr: $extra"; fail=1
fi
[ "$fail" = 0 ] && echo "install layout OK"
exit "$fail"
