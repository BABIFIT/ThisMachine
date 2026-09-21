#!/usr/bin/env bash
# Build ThisMachine-x86_64.AppImage — a self-contained, offline-capable bundle.
#
# Uses python-build-standalone (GLIBC 2.17+) so the AppImage runs on
# Ubuntu 18.04+, Debian Stretch+, Fedora 28+, and any distro with GLIBC ≥ 2.17.
# This avoids the "GLIBC_2.3x not found" errors that occur when building with
# a modern system Python on a machine with a newer GLIBC.
#
# Requirements: curl, tar, FUSE (to run the resulting AppImage).
# Usage:  ./build-appimage.sh
set -euo pipefail
cd "$(dirname "$0")"

BUILD=build
VENV="$BUILD/venv"
APPDIR="$BUILD/ThisMachine.AppDir"
XTERM_VER=5.3.0

mkdir -p "$BUILD" vendor

# 1. Portable Python (GLIBC 2.17+ — avoids "GLIBC too new" on target machines) -
# python-build-standalone ships a fully self-contained CPython that targets the
# oldest supported GLIBC, so the resulting AppImage runs on ancient distros too.
PBS_TAG="20250106"
PBS_VER="3.12.8"
PBS_ARCH="x86_64-unknown-linux-gnu"
PBS_TARBALL="cpython-${PBS_VER}+${PBS_TAG}-${PBS_ARCH}-install_only.tar.gz"
PBS_URL="https://github.com/astral-sh/python-build-standalone/releases/download/${PBS_TAG}/${PBS_TARBALL}"
PBS_DIR="$BUILD/portable-python"

if [ ! -x "$PBS_DIR/bin/python3" ]; then
  echo "Fetching portable Python ${PBS_VER} (GLIBC 2.17+ compatible)..."
  curl -sSL -o "$BUILD/$PBS_TARBALL" "$PBS_URL"
  tar -xf "$BUILD/$PBS_TARBALL" -C "$BUILD"   # extracts to $BUILD/python/
  mv "$BUILD/python" "$PBS_DIR"
  rm -f "$BUILD/$PBS_TARBALL"
fi
PYTHON="$PBS_DIR/bin/python3"

# 2. Build venv + deps --------------------------------------------------------
[ -d "$VENV" ] || "$PYTHON" -m venv "$VENV"
"$VENV/bin/pip" install --quiet --upgrade pip
"$VENV/bin/pip" install --quiet -r requirements.txt pyinstaller pillow

# 3. Vendor xterm.js (so the app needs no CDN at runtime) ---------------------
if [ ! -f vendor/xterm.min.js ]; then
  curl -sSL -o vendor/xterm.min.js  "https://cdn.jsdelivr.net/npm/xterm@${XTERM_VER}/lib/xterm.min.js"
  curl -sSL -o vendor/xterm.min.css "https://cdn.jsdelivr.net/npm/xterm@${XTERM_VER}/css/xterm.min.css"
fi

# 4. appimagetool -------------------------------------------------------------
if [ ! -x "$BUILD/appimagetool" ]; then
  curl -sSL -o "$BUILD/appimagetool" \
    https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-x86_64.AppImage
  chmod +x "$BUILD/appimagetool"
fi

# 5. Icon ---------------------------------------------------------------------
"$VENV/bin/python" - <<'PY'
from PIL import Image, ImageDraw, ImageFont
import glob
S = 256
img = Image.new("RGBA", (S, S), (0,0,0,0))
lerp = lambda a,b,t: tuple(int(a[i]+(b[i]-a[i])*t) for i in range(3))
grad = Image.new("RGB", (S,S)); gd = ImageDraw.Draw(grad)
for y in range(S): gd.line([(0,y),(S,y)], fill=lerp((0,122,255),(88,86,214),y/S))
mask = Image.new("L",(S,S),0)
ImageDraw.Draw(mask).rounded_rectangle([8,8,S-8,S-8], radius=56, fill=255)
img.paste(grad,(0,0),mask)
d = ImageDraw.Draw(img)
cand = (glob.glob("/usr/share/fonts/**/*Sans*Bold*.ttf", recursive=True) +
        glob.glob("/usr/share/fonts/**/*Bold*.ttf", recursive=True))
font = ImageFont.truetype(cand[0], 120) if cand else ImageFont.load_default()
bb = d.textbbox((0,0), "TM", font=font); w,h = bb[2]-bb[0], bb[3]-bb[1]
d.text(((S-w)/2-bb[0],(S-h)/2-bb[1]), "TM", font=font, fill=(255,255,255,255))
img.save("build/thismachine.png")
PY

# 6. Bundle the app into one binary -------------------------------------------
"$VENV/bin/pyinstaller" --noconfirm --clean --onefile \
  --name thismachine \
  --add-data "$(pwd)/vendor:vendor" \
  --collect-all cryptography \
  --distpath "$BUILD/dist" --workpath "$BUILD/work" --specpath "$BUILD" \
  thismachine.py

# 7. Assemble the AppDir ------------------------------------------------------
rm -rf "$APPDIR"
mkdir -p "$APPDIR/usr/bin" "$APPDIR/usr/share/applications" \
         "$APPDIR/usr/share/icons/hicolor/256x256/apps"
cp "$BUILD/dist/thismachine" "$APPDIR/usr/bin/thismachine"
cp "$BUILD/thismachine.png"  "$APPDIR/thismachine.png"
cp "$BUILD/thismachine.png"  "$APPDIR/usr/share/icons/hicolor/256x256/apps/thismachine.png"

cat > "$APPDIR/thismachine.desktop" <<'EOF'
[Desktop Entry]
Type=Application
Name=ThisMachine
GenericName=Terminal
Comment=iMessage-style shell in your browser (localhost only)
Exec=thismachine
Icon=thismachine
Categories=Utility;System;TerminalEmulator;
Terminal=false
EOF
cp "$APPDIR/thismachine.desktop" "$APPDIR/usr/share/applications/thismachine.desktop"

cat > "$APPDIR/AppRun" <<'EOF'
#!/bin/bash
HERE="$(dirname "$(readlink -f "${0}")")"
export TERMSITE_OPEN_BROWSER="${TERMSITE_OPEN_BROWSER:-1}"
exec "${HERE}/usr/bin/thismachine" "$@"
EOF
chmod +x "$APPDIR/AppRun"

# 8. Produce the AppImage -----------------------------------------------------
ARCH=x86_64 "$BUILD/appimagetool" --appimage-extract-and-run \
  "$APPDIR" "$BUILD/ThisMachine-x86_64.AppImage"

# 9. Tidy intermediates (keep portable-python and venv for faster rebuilds) ---
rm -rf "$BUILD/work" "$BUILD/dist" "$BUILD/thismachine.spec" "$APPDIR"

echo
echo "Built: $BUILD/ThisMachine-x86_64.AppImage"
echo
echo "Note: port 443 requires cap_net_bind_service. The app falls back to"
echo "port 5000 automatically if the capability is not set. To enable port 443:"
echo "  sudo setcap cap_net_bind_service=+ep \$(readlink -f \$(which python3))"
echo "(This must be applied to the Python binary, not the AppImage.)"
