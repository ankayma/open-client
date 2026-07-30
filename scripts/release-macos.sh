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

# Preflight: restricted entitlements need an embedded provisioning profile.
#
# `com.apple.developer.associated-domains` (entitlements.plist, needed for WebAuthn in
# WKWebView) is a RESTRICTED entitlement. macOS evaluates the app's embedded profile at
# EVERY launch, not just at install — so an app that claims a restricted entitlement with
# no matching profile is refused by launchd (RBSRequestErrorDomain Code=5 / POSIX 163)
# even though codesign, notarization and spctl all report it as perfectly valid. That is
# exactly how v1.1.26 and v1.1.28 shipped broken: every static check passed.
#
# Two things must hold, and neither is visible to codesign, so assert them here:
#   1. the profile file exists at the path tauri.conf.json points to
#   2. the Developer ID cert we are about to sign with is listed inside that profile —
#      a profile generated against a different cert fails the same way, silently
# [T:developer.apple.com/help/account/provisioning-profiles/provisioning-profile-updates]
PROFILE="macos/ankayma-devid.provisionprofile"
if grep -q '"entitlements"' tauri.conf.json; then
  if [[ ! -f "$PROFILE" ]]; then
    echo "✗ tauri.conf.json wires bundle.macOS.entitlements, but $PROFILE is missing."
    echo "  Shipping that combination produces an app that passes codesign/notarization"
    echo "  and still cannot launch. Refusing to build."
    echo "  Fix: developer.apple.com → Profiles → + → Developer ID → App ID com.ankayma.app"
    echo "       → pick the Developer ID Application cert → download → save it as"
    echo "       gui/src-tauri/$PROFILE  (CI: secret APPLE_PROVISION_PROFILE_BASE64)."
    exit 1
  fi
  # The signing identity's SHA-1 is the leading hex field of APPLE_SIGNING_IDENTITY when
  # a hash was given; otherwise resolve the name through the keychain.
  SIGN_SHA=$(security find-identity -v -p codesigning 2>/dev/null \
    | grep -F "$APPLE_SIGNING_IDENTITY" | head -1 | awk '{print $2}')
  if [[ -n "$SIGN_SHA" ]]; then
    if ! security cms -D -i "$PROFILE" 2>/dev/null \
      | python3 -c 'import plistlib,sys,hashlib; d=plistlib.loads(sys.stdin.buffer.read()); print("\n".join(hashlib.sha1(c).hexdigest().upper() for c in d.get("DeveloperCertificates",[])))' \
      | grep -qi "$SIGN_SHA"; then
      echo "✗ $PROFILE does not list the signing certificate ($SIGN_SHA)."
      echo "  The app would be refused at launch. Regenerate the profile against this cert."
      exit 1
    fi
    echo "✓ provisioning profile present and bound to the signing cert ($SIGN_SHA)"
  else
    echo "⚠ could not resolve '$APPLE_SIGNING_IDENTITY' in the keychain — skipping the"
    echo "  profile↔cert binding check (the file-exists check above still applies)."
  fi
fi

# Universal binary so both Apple Silicon and Intel Macs run it. Add the Intel
# target if missing (no-op when already installed).
rustup target add x86_64-apple-darwin >/dev/null 2>&1 || true

echo "→ Building signed + notarized universal DMG (this compiles both arches)…"
# `app` (alongside `dmg`) is required for Tauri to emit updater artifacts
# (.app.tar.gz + .sig) — `--bundles dmg` alone skips them entirely ("no
# updater-enabled targets were built") [T — observed 2026-07-02 CI run].
cargo tauri build --target universal-apple-darwin --bundles dmg,app

DMG=$(find ../../target/universal-apple-darwin/release/bundle/dmg -iname "*.dmg" 2>/dev/null | head -1)
if [[ -z "$DMG" ]]; then
  echo "✗ DMG not found after build — check the build output above." >&2
  exit 1
fi

# Post-build gate: the app must actually LAUNCH.
#
# The only check that catches a restricted-entitlement/profile mismatch is a real launch —
# `open` goes through LaunchServices → launchd → taskgated, which is where v1.1.26/1.1.28
# died. codesign/spctl/stapler are signature checks and all passed on those broken builds.
# So do the one check that would have caught it, and treat failure as fatal. [T: reproduced
# 2026-07-29 — `open` failed while every static check reported the bundle valid]
APP=$(find ../../target/universal-apple-darwin/release/bundle/macos -maxdepth 1 -iname "*.app" 2>/dev/null | head -1)
if [[ "${SKIP_LAUNCH_CHECK:-0}" != "1" && -n "$APP" ]]; then
  echo "→ Launch gate: verifying the bundle is allowed to spawn…"
  if grep -q '"entitlements"' tauri.conf.json && [[ ! -f "$APP/Contents/embedded.provisionprofile" ]]; then
    echo "✗ $APP/Contents/embedded.provisionprofile is missing — Tauri did not copy it."
    echo "  Check bundle.macOS.files in tauri.conf.json. Refusing to ship."
    exit 1
  fi
  # `open` returns non-zero the moment launchd refuses the spawn; a successful launch
  # leaves a live process. Background it (-g) so a release build never steals focus.
  if ! open -g "$APP" 2>/tmp/ankayma-launch-gate.err; then
    echo "✗ The app failed to launch:"
    cat /tmp/ankayma-launch-gate.err
    echo "  This is the entitlement/provisioning-profile failure mode. Refusing to ship."
    exit 1
  fi
  sleep 5
  if ! pgrep -f "$(basename "$APP" .app)" >/dev/null 2>&1; then
    echo "✗ The app launched and then died within 5s — refusing to ship."
    exit 1
  fi
  pkill -f "$(basename "$APP" .app)" >/dev/null 2>&1 || true
  echo "✓ launch gate passed (app spawned and stayed alive)"
fi

# Tauri notarizes + staples the inner .app but NOT the .dmg container. A DMG whose
# container is signed-but-not-notarized trips Gatekeeper on mount ("Apple could
# not verify… is free of malware") when downloaded from the web. So notarize +
# staple the DMG itself here, reusing the same credentials. [A: observed 2026-06-25
# on tauri 2.11.x — verify still needed if tauri starts notarizing the dmg upstream]
echo "→ Notarizing the DMG container (Tauri only handles the inner .app)…"
if [[ -n "${APPLE_API_KEY:-}" ]]; then
  xcrun notarytool submit "$DMG" \
    --key "$APPLE_API_KEY_PATH" --key-id "$APPLE_API_KEY" --issuer "$APPLE_API_ISSUER" --wait
else
  xcrun notarytool submit "$DMG" \
    --apple-id "$APPLE_ID" --password "$APPLE_PASSWORD" --team-id "$APPLE_TEAM_ID" --wait
fi
xcrun stapler staple "$DMG"

echo
echo "✓ Signed + notarized DMG: $DMG"
echo "  Verify before publishing:"
echo "    spctl -a -vv -t install \"$DMG\"        # should say: accepted, Notarized Developer ID"
echo "    xcrun stapler validate \"$DMG\"         # should say: validate worked"
echo "  Then upload that file and point the website Download button at its URL."
