#!/usr/bin/env bash
# release-ios.sh — build a signed iOS .ipa for App Store Connect upload.
# Credentials are read from the ENVIRONMENT (never committed). Run this ONLY after
# the Apple Developer Program membership is active and the Apple Distribution cert
# + App Store provisioning profile are installed (Xcode-managed signing).
#
# Prereqs that DO NOT need an active membership (do these first — see
# docs/ios-appstore-release-prep.md §1):
#   - Full Xcode installed + selected (xcode-select); `xcodebuild -version` works.
#   - cargo install tauri-cli --version "^2"
#   - rustup target add aarch64-apple-ios aarch64-apple-ios-sim
#   - cargo tauri ios init   (generates gen/apple/ — NOT yet committed in this repo)
#   - Network Extension / Packet Tunnel Provider target added by hand (§2) —
#     boringtun cannot open a TUN on iOS without it. This script does NOT create it.
#
# Required env (set before running — do NOT hard-code):
#   APPLE_DEVELOPMENT_TEAM   your 10-char Team ID (for Xcode signing)
# Upload — App Store Connect API key (preferred):
#   APPLE_API_KEY / APPLE_API_ISSUER / APPLE_API_KEY_PATH
set -euo pipefail

cd "$(dirname "$0")/../gui/src-tauri"

if [[ ! -d gen/apple ]]; then
  echo "✗ gen/apple/ missing — run 'cargo tauri ios init' first (needs full Xcode)."
  echo "  See docs/ios-appstore-release-prep.md §1."
  exit 1
fi
if [[ -z "${APPLE_DEVELOPMENT_TEAM:-}" ]]; then
  echo "✗ APPLE_DEVELOPMENT_TEAM is not set — cannot sign for distribution."
  echo "  Membership must be active + Apple Distribution cert installed. Refusing unsigned build."
  exit 1
fi
if [[ -z "${APPLE_API_KEY:-}" ]]; then
  echo "✗ No App Store Connect API key (APPLE_API_KEY*) — needed to export/upload."
  exit 1
fi

echo "→ Building signed iOS .ipa for App Store Connect…"
cargo tauri ios build --export-method app-store-connect

IPA=$(find gen/apple/build -iname "*.ipa" 2>/dev/null | head -1)
echo
echo "✓ Signed .ipa: ${IPA:-<not found — check the build output>}"
echo "  Upload with Transporter, or:"
echo "    xcrun altool --upload-app -f \"$IPA\" --type ios \\"
echo "      --apiKey \"\$APPLE_API_KEY\" --apiIssuer \"\$APPLE_API_ISSUER\""
echo "  (or notarytool/Transporter per your App Store Connect setup)."
