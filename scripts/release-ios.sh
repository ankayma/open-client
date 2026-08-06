#!/usr/bin/env bash
# release-ios.sh — build + validate + UPLOAD the iOS app to App Store Connect / TestFlight,
# end-to-end from the CLI. One command, no Xcode Organizer. Encodes the verified 2026-08-05
# flow that shipped build 1.1.37.
#
#   source ~/.private/apple-asc.env && ./scripts/release-ios.sh
#   (the script also auto-sources that file if the env vars aren't already set)
#
# Bump the app version in gui/src-tauri/tauri.conf.json first — App Store Connect rejects a
# duplicate CFBundleVersion. This script syncs the PacketTunnel extension version to match
# (Apple rejects an extension whose version diverges from the app).
#
# Credentials, read from the ENVIRONMENT (never committed):
#   APPLE_DEVELOPMENT_TEAM                                   10-char Team ID (signing)
#   APPLE_API_KEY / APPLE_API_ISSUER / APPLE_API_KEY_PATH    App Store Connect API key (upload)
#
# WHY the key is hidden during the build (the trap that cost a day):
#   With no local "Apple Distribution" cert, Tauri hands the App Store Connect API key to
#   xcodebuild's cloud signing. A read-only key can't cloud-sign, so it falls back to a
#   placeholder "Apple Distribution: Tauri (unset)" cert that STRIPS the extension's
#   networkextension entitlement -> altool rejects with 90525, and Xcode Organizer reports
#   "no App Store Connect access for team Tauri". Fix: UNSET the key for the build so
#   xcodebuild cloud-signs via the Xcode account session (which can provision the real cert
#   + capabilities); re-supply the key only for altool upload (read-only uploads fine).
#   Persistent alternative: install an Apple Distribution cert (Xcode > Settings > Accounts >
#   Manage Certificates > + Apple Distribution) and the key may stay set the whole time.
#   Post-build checks + known gotchas: docs/ios-build-verify-checklist.md.
set -euo pipefail
cd "$(dirname "$0")/.."

# Load credentials if the caller hasn't already sourced them (local dev convention).
if [[ -z "${APPLE_API_KEY:-}" && -f "$HOME/.private/apple-asc.env" ]]; then
  # shellcheck disable=SC1091
  source "$HOME/.private/apple-asc.env"
fi
: "${APPLE_DEVELOPMENT_TEAM:?set APPLE_DEVELOPMENT_TEAM (or create ~/.private/apple-asc.env)}"
: "${APPLE_API_KEY:?set APPLE_API_KEY}"
: "${APPLE_API_ISSUER:?set APPLE_API_ISSUER}"

# Keep the upload creds; everything else about them stays out of the build environment.
ASC_KEY="$APPLE_API_KEY"; ASC_ISSUER="$APPLE_API_ISSUER"
export APPLE_DEVELOPMENT_TEAM
export PATH="$HOME/.cargo/bin:$PATH"

VER=$(sed -nE 's/.*"version": *"([^"]+)".*/\1/p' gui/src-tauri/tauri.conf.json | head -1)
echo "→ Releasing iOS version ${VER:?could not read version from tauri.conf.json}"

# Extension version must equal the app version (Apple rejects a divergence).
sed -i '' -E "s/(CFBundleShortVersionString: ).*/\1${VER}/; s/(CFBundleVersion: ).*/\1\"${VER}\"/" \
  gui/src-tauri/ios/PacketTunnel.target.yml

# Regenerate the iOS project. Empty Externals first, or xcodegen sees both the debug and
# release static libs and fails with "Multiple commands produce libapp.a".
echo "→ Regenerating gen/apple (empty Externals, purge DerivedData, run postinit)…"
rm -rf gui/src-tauri/gen/apple/Externals ~/Library/Developer/Xcode/DerivedData/ankayma-gui-* 2>/dev/null || true
mkdir -p gui/src-tauri/gen/apple/Externals
bash scripts/ios-postinit.sh

# Build + export, with the ASC API key HIDDEN so cloud signing uses the Xcode account.
echo "→ Building + exporting (App Store signing via Xcode account; API key hidden)…"
(
  unset APPLE_API_KEY APPLE_API_ISSUER APPLE_API_KEY_PATH APPLE_API_KEY_ID APPLE_SIGNING_IDENTITY
  cd gui/src-tauri && cargo tauri ios build --export-method app-store-connect
)

IPA=$(ls -t gui/src-tauri/gen/apple/build/arm64/*.ipa 2>/dev/null | head -1)
[[ -n "$IPA" ]] || { echo "✗ no .ipa produced — check the build log"; exit 1; }
echo "✓ signed .ipa: $IPA"

# Entitlement gate — two build steps rewrite associated-domains behind us; the signed
# artifact is the only witness. Also catches a stripped extension entitlement early.
echo "→ Verifying entitlements survived into the signed app…"
scripts/verify-ios-entitlements.sh "$IPA"

echo "→ altool validate…"
xcrun altool --validate-app -f "$IPA" --type ios --apiKey "$ASC_KEY" --apiIssuer "$ASC_ISSUER"

echo "→ altool upload → App Store Connect / TestFlight…"
xcrun altool --upload-app -f "$IPA" --type ios --apiKey "$ASC_KEY" --apiIssuer "$ASC_ISSUER"

echo
echo "✓ Uploaded ${VER}. It appears in TestFlight after Apple finishes processing (a few minutes)."
echo "  Verify: App Store Connect → Ankayma → TestFlight, or check the build's processingState via the API."
