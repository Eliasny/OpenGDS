#!/bin/sh
# Install what scripts/release/build-release.sh needs, on a fresh Debian,
# Ubuntu, EL 9 or Fedora system (the release workflow's build containers).
# Run as root.
# SPDX-License-Identifier: MPL-2.0
#
#   install-build-deps.sh            the packages (build-release.sh)
#   install-build-deps.sh static     Debian only: the static Linux gdsaudit
#                                    (packaging/static/build.sh, musl)
#   install-build-deps.sh windows    Debian only: gdsaudit.exe
#                                    (packaging/windows/build.sh, MinGW-w64)
#
#   DEBIAN_SNAPSHOT=20261101T000000Z  Debian only: install from that
#                                     snapshot.debian.org date (reproducible
#                                     rebuilds later)
set -eu
WHAT=${1:-packages}
eval "$(. /etc/os-release; printf 'ID=%s ID_LIKE="%s" VERSION_CODENAME=%s\n' "${ID:-}" "${ID_LIKE:-}" "${VERSION_CODENAME:-}")"
case "$ID:$ID_LIKE" in
    debian:*|ubuntu:*|*:*debian*)
        export DEBIAN_FRONTEND=noninteractive
        if [ "$ID" = debian ] && [ -n "${DEBIAN_SNAPSHOT:-}" ]; then
            rm -f /etc/apt/sources.list.d/debian.sources
            printf 'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/%s %s main\ndeb [check-valid-until=no] http://snapshot.debian.org/archive/debian-security/%s %s-security main\n' \
                "$DEBIAN_SNAPSHOT" "$VERSION_CODENAME" "$DEBIAN_SNAPSHOT" "$VERSION_CODENAME" > /etc/apt/sources.list
        fi
        printf 'Acquire::Retries "10";\nAcquire::http::Timeout "60";\n' > /etc/apt/apt.conf.d/80-retries
        apt-get update
        case "$WHAT" in
            packages)
                # GTK 4 for gdsaudit-gui; Xvfb for its smoke test
                apt-get install -y --no-install-recommends \
                    build-essential cmake ninja-build git curl ca-certificates perl python3 \
                    libsqlite3-dev libseccomp-dev pkgconf dpkg-dev file openssl \
                    libgtk-4-dev xvfb xauth ;;
            static)
                apt-get install -y --no-install-recommends \
                    build-essential musl-tools linux-libc-dev cmake ninja-build git curl \
                    ca-certificates perl python3 dpkg-dev ;;
            windows)
                apt-get install -y --no-install-recommends \
                    build-essential mingw-w64 cmake ninja-build git curl ca-certificates \
                    perl python3 zip dpkg-dev
                # open62541's multithreading needs winpthreads: the POSIX
                # thread model, not Debian's default win32 one
                for t in gcc g++; do
                    update-alternatives --set "x86_64-w64-mingw32-$t" "/usr/bin/x86_64-w64-mingw32-$t-posix"
                done ;;
            *) echo "install-build-deps.sh: unknown target $WHAT" >&2; exit 1 ;;
        esac
        ;;
    *:*rhel*|*:*fedora*|fedora:*|rhel:*)
        [ "$WHAT" = packages ] || { echo "install-build-deps.sh: $WHAT builds on Debian" >&2; exit 1; }
        # EL 9's GCC 11 lacks part of the hardening set (docs/architecture.md,
        # "Build hardening"): build with GCC 13 from gcc-toolset-13, which
        # links against the system's own glibc and libgcc. build-release.sh
        # enables it when present. ninja-build is in CRB.
        # Mirrors sometimes serve an empty repomd.xml: retry with fresh
        # metadata before giving up.
        dnf_retry() {
            for i in 1 2 3 4 5; do
                dnf --setopt=retries=10 "$@" && return 0
                echo "dnf failed (attempt $i), retrying" >&2
                dnf clean metadata || true
                sleep $((i * 10))
            done
            return 1
        }
        toolset=
        case "$ID" in
            fedora) ;;
            *) dnf_retry install -y dnf-plugins-core && dnf config-manager --set-enabled crb
               toolset="gcc-toolset-13-gcc gcc-toolset-13-binutils" ;;
        esac
        # OpenSSL's Configure needs these perl modules; EL ships them split.
        # GTK 4 (EL 9: 4.12) for gdsaudit-gui, Xvfb for its smoke test.
        # --allowerasing: the base images carry curl-minimal.
        dnf_retry install -y --allowerasing --setopt=install_weak_deps=False $toolset \
            gcc make cmake ninja-build git curl ca-certificates python3 \
            perl-interpreter perl-FindBin perl-IPC-Cmd perl-File-Compare perl-File-Copy \
            perl-Time-Piece perl-lib \
            sqlite-devel libseccomp-devel pkgconf-pkg-config rpm-build file findutils diffutils \
            openssl gtk4-devel xorg-x11-server-Xvfb xorg-x11-xauth
        dnf clean all
        ;;
    *)
        echo "install-build-deps.sh: unsupported distribution $ID" >&2
        exit 1
        ;;
esac
