#!/bin/sh
# Build the Windows desktop UI (gdsaudit-gui.exe) with MSYS2's GTK 4 and
# stage it with the engine for the installer (Auditor plan AT5, Windows
# installer; gdsaudit.wxs packs the stage). Runs in an MSYS2 UCRT64 shell.
# Usage: build_gui.sh <out-dir> <engine-dir>
#   <engine-dir>  the unpacked zip of packaging/windows/build.sh: its static
#                 gdsaudit.exe (pinned OpenSSL and open62541) goes next to
#                 the UI, where avm_engine_path looks for it, with its
#                 licences
# Needs (pacman, UCRT64): gcc cmake ninja pkgconf gtk4 adwaita-icon-theme ntldd
# Writes <out-dir>/build (the GUI-only CMake build, with its tests) and
# <out-dir>/stage: bin/ (the two programs, the DLLs they load and GLib's
# spawn helpers), lib/gdk-pixbuf-2.0, share/ (schemas, icons) and licenses/.
# SPDX-License-Identifier: MPL-2.0
set -eu
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
OUT=${1:?usage: build_gui.sh <out-dir> <engine-dir>}
ENGINE=${2:?usage: build_gui.sh <out-dir> <engine-dir>}
: "${MINGW_PREFIX:?run in an MSYS2 UCRT64 shell}"
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
BUILD="$OUT/build"
STAGE="$OUT/stage"

cmake -S "$ROOT" -B "$BUILD" -G Ninja -DCMAKE_BUILD_TYPE=Release -DOPENGDS_AUDITOR_GUI_ONLY=ON \
    -DCMAKE_C_FLAGS="-ffile-prefix-map=$ROOT=."
cmake --build "$BUILD"

rm -rf "$STAGE"
mkdir -p "$STAGE/bin" "$STAGE/licenses" "$STAGE/share/glib-2.0/schemas" "$STAGE/share/icons"
cp "$BUILD/tools/auditor/gdsaudit-gui.exe" "$STAGE/bin/"
strip "$STAGE/bin/gdsaudit-gui.exe"
cp "$ENGINE/gdsaudit.exe" "$STAGE/bin/gdsaudit.exe"
# GSubprocess starts the engine through GLib's helpers
cp "$MINGW_PREFIX"/bin/gspawn-win64-helper*.exe "$STAGE/bin/"

# GdkPixbuf loaders (relocatable cache: paths relative to bin/)
PB=lib/gdk-pixbuf-2.0/2.10.0
mkdir -p "$STAGE/$PB/loaders"
cp "$MINGW_PREFIX/$PB"/loaders/*.dll "$STAGE/$PB/loaders/"
cp "$MINGW_PREFIX/$PB/loaders.cache" "$STAGE/$PB/"

# Every DLL from the MSYS2 prefix that the programs and loaders load
# (Windows' own DLLs are left out)
win_prefix=$(cygpath -m "$MINGW_PREFIX")
for f in "$STAGE"/bin/*.exe "$STAGE/$PB"/loaders/*.dll; do
    ntldd -R "$f"
done | sed -n 's/.* => \(.*\.dll\) (0x.*/\1/p' | tr '\\' '/' | sort -u |
    grep -i "^$win_prefix/bin/" | while read -r dll; do
    cp "$(cygpath -u "$dll")" "$STAGE/bin/"
done

# GTK's settings schemas, compiled for the stage
cp "$MINGW_PREFIX"/share/glib-2.0/schemas/org.gtk.gtk4.*.xml "$STAGE/share/glib-2.0/schemas/"
glib-compile-schemas "$STAGE/share/glib-2.0/schemas"
# Icons: Adwaita (GTK's symbolic icons) and the hicolor fallback theme
cp -r "$MINGW_PREFIX/share/icons/Adwaita" "$MINGW_PREFIX/share/icons/hicolor" "$STAGE/share/icons/"
mkdir -p "$STAGE/share/icons/hicolor/scalable/apps"
cp "$ROOT/packaging/desktop/org.opengds.Auditor.svg" "$STAGE/share/icons/hicolor/scalable/apps/"
gtk4-update-icon-cache -q -t -f "$STAGE/share/icons/hicolor" || true

# Licences: OpenGDS, then the engine's (its zip ships them) and the
# MSYS2 packages whose DLLs are staged
cp "$ROOT/LICENSE" "$STAGE/licenses/OpenGDS-MPL-2.0.txt"
for l in "$ENGINE"/licenses/*; do
    case $(basename "$l") in OpenGDS-*) ;; *) cp "$l" "$STAGE/licenses/engine-$(basename "$l")" ;; esac
done
cp "$ROOT/packaging/windows/msi/README.txt" "$STAGE/README.txt"
for dll in "$STAGE"/bin/*.dll; do
    pacman -Qqo "$MINGW_PREFIX/bin/$(basename "$dll")" 2>/dev/null || true
done | sort -u | while read -r pkg; do
    for l in "$MINGW_PREFIX/share/licenses/${pkg#mingw-w64-ucrt-x86_64-}"/*; do
        [ -f "$l" ] && cp "$l" "$STAGE/licenses/${pkg#mingw-w64-ucrt-x86_64-}-$(basename "$l")"
    done
    pacman -Qi "$pkg" | sed -n 's/^\(Name\|Version\|Licenses\) *: //p' | paste -sd' ' >> "$STAGE/licenses/THIRD-PARTY-PACKAGES.txt"
done
echo "$STAGE"
