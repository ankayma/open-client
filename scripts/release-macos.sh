#!/usr/bin/env bash
# release-macos.sh — build a signed + notarized universal macOS DMG for website
# download. Credentials are read from the ENVIRONMENT (never committed). Run this
# once your Apple Developer account is active and the cert is in your login keychain.
#
# Required env (set these before running — do NOT hard-code them anywhere):
#   APPLE_SIGNING_IDENTITY  "Developer ID Application: Your Name (TEAMID)"
#   APPLE_TEAM_ID           your 10-char team id
# Notarization — either an App Store Connect API key (preferred) OR an Apple ID:
#   APPLE_API_KEY / APPLE_API_ISSUER / APPLE_API_KEY_PATH        (API key, preferred)
#   — or —
#   APPLE_ID / APPLE_PASSWORD (app-specific password) / APPLE_TEAM_ID
#
# Tauri auto-signs with APPLE_SIGNING_IDENTITY and auto-notarizes when the
# notarization vars are present, then staples the ticket into the .app/.dmg.
set -euo pipefail

cd "$(dirname "$0")/../gui/src-tauri"

if [[ -z "${APPLE_SIGNING_IDENTITY:-}" ]]; then
  echo "✗ APPLE_SIGNING_IDENTITY is not set — refusing to ship an unsigned build."
  echo "  See docs in the workspace runbook for how to get the Developer ID cert."
  exit 1
fi
if [[ -z "${APPLE_API_KEY:-}" && -z "${APPLE_ID:-}" ]]; then
  echo "✗ No notarization credentials (set APPLE_API_KEY* or APPLE_ID/APPLE_PASSWORD)."
  exit 1
fi

# Universal binary so both Apple Silicon and Intel Macs run it. Add the Intel
# target if missing (no-op when already installed).
rustup target add x86_64-apple-darwin >/dev/null 2>&1 || true

echo "→ Building signed + notarized universal DMG (this compiles both arches)…"
cargo tauri build --target universal-apple-darwin --bundles dmg

DMG=$(find ../../target/universal-apple-darwin/release/bundle/dmg -iname "*.dmg" 2>/dev/null | head -1)
echo
echo "✓ Signed + notarized DMG: ${DMG:-<not found — check the build output>}"
echo "  Verify before publishing:"
echo "    spctl -a -vv -t install \"$DMG\"        # should say: accepted, Notarized Developer ID"
echo "    xcrun stapler validate \"$DMG\"         # should say: validate worked"
echo "  Then upload that file and point the website Download button at its URL."
