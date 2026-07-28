#!/usr/bin/env bash
# android-postinit.sh — fix the Android adaptive-icon foreground layer after
# `cargo tauri android init`. Tauri's Android scaffolding scales the full-bleed
# icons/icon_source.png edge-to-edge into ic_launcher_foreground.png (0% margin,
# every pixel opaque) — the launcher's own mask (circle/squircle/rounded-square,
# OEM-dependent) then crops straight into the logo artwork with no safe zone,
# producing wrong/ugly corners on the home screen. Same class of bug as the iOS
# AppIcon regression scripts/ios-postinit.sh guards against — gen/android is
# regenerated scaffolding, so the fix must live here, not as a one-off hand-edit
# of the generated PNGs (does not survive the next init).
#
# Re-renders each density with the logo confined to Android's documented
# adaptive-icon safe zone (66dp circle centered in the 108dp full-bleed canvas)
# so any mask shape trims only transparent padding, never the logo. Run AFTER
# `cargo tauri android init` and BEFORE `cargo tauri android build`. Idempotent.
# [T:Android Adaptive Icons guide — developer.android.com/develop/ui/views/launch/icon_design_adaptive, safe zone 66dp/108dp]
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)" # client/ (workspace root)
SRC="$ROOT/gui/src-tauri/icons/icon_source.png"
RES="$ROOT/gui/src-tauri/gen/android/app/src/main/res"

if [ ! -f "$SRC" ]; then
  echo "✗ $SRC not found." >&2
  exit 1
fi
if [ ! -d "$RES/mipmap-xxxhdpi" ]; then
  echo "✗ $RES/mipmap-xxxhdpi not found — run 'cargo tauri android init' first." >&2
  exit 1
fi
command -v convert >/dev/null 2>&1 || { echo "✗ ImageMagick 'convert' not found (ubuntu-latest GitHub runners ship it by default)." >&2; exit 1; }

# canvas px per density = 108dp * density scale (1x/1.5x/2x/3x/4x). content px =
# canvas * 66/108 — Android's safe-zone ratio (all five divide evenly).
for pair in mdpi:108 hdpi:162 xhdpi:216 xxhdpi:324 xxxhdpi:432; do
  density="${pair%%:*}"
  canvas="${pair##*:}"
  content=$(( canvas * 66 / 108 ))
  out="$RES/mipmap-$density/ic_launcher_foreground.png"
  convert "$SRC" -resize "${content}x${content}" -background none -gravity center \
    -extent "${canvas}x${canvas}" "$out"
done

echo "✓ ic_launcher_foreground.png regenerated at 5 densities, logo confined to the adaptive-icon safe zone (~19% transparent margin)"
