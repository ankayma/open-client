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

# ── Build → fix signatures → gate → notarize → package ──────────────────────────
#
# Order matters, and getting it wrong is exactly how 1.1.29 through 1.1.32 shipped a
# dead tunnel. Tauri, given `--bundles dmg,app`, signs everything, notarizes, and packs
# BOTH the DMG and the updater tarball in one pass. Anything corrected afterwards
# corrects only the .app left in the build directory: the artifacts users actually
# receive still contain the binaries as Tauri signed them, and a notarization ticket
# issued mid-pass covers a bundle that no longer exists.
#
# So: let Tauri build and sign only. Withhold the notarization credentials from it —
# there is no flag to skip notarization, but it is skipped when the env is absent.
# Everything downstream of the fix is produced here, from the fixed bundle.
echo "→ Building + signing (Tauri); notarization and packaging deferred…"
env -u APPLE_API_KEY -u APPLE_API_ISSUER -u APPLE_API_KEY_PATH -u APPLE_ID -u APPLE_PASSWORD \
  cargo tauri build --target universal-apple-darwin --bundles app

BUNDLE_DIR=../../target/universal-apple-darwin/release/bundle/macos
APP=$(find "$BUNDLE_DIR" -maxdepth 1 -iname "*.app" 2>/dev/null | head -1)
if [[ -z "$APP" ]]; then
  echo "✗ .app not found after build — check the build output above." >&2
  exit 1
fi

# ── 1. Re-sign the nested standalone executables WITHOUT the app's entitlements ──
#
# Tauri applies bundle.macOS.entitlements to every binary it signs, sidecars included.
# Fatal for `agent` and `ankayma-helper`: neither runs as part of the app bundle — the
# helper is a root daemon and it spawns agent directly. A restricted entitlement
# (application-identifier, keychain-access-groups, associated-domains) is honoured only
# when a provisioning profile authorises it, and the embedded profile names
# 8UF87JS6WW.com.ankayma.app while these sign as `agent` / `ankayma-helper`. taskgated
# SIGKILLs them on exec: no output, no crash report, nothing in any log, and
# `codesign --verify` calls the bundle valid throughout. [T — 2026-07-30: same binary,
# exit 137 with the entitlements, exit 2 and normal usage output without them]
#
# Apple's rule for nested code: sign bottom-up, each nested executable with its own
# entitlements — here none, since neither needs any — and the outer bundle last, because
# re-signing nested code breaks its seal.
# [T:developer.apple.com/forums/thread/798947 · objc.io/issues/17-security/inside-code-signing]
echo "→ Re-signing sidecars without the app's entitlements (bottom-up)…"
for bin in agent ankayma-helper; do
  [[ -f "$APP/Contents/MacOS/$bin" ]] || continue
  codesign --force --options runtime --timestamp \
    --sign "$APPLE_SIGNING_IDENTITY" "$APP/Contents/MacOS/$bin"
done
codesign --force --options runtime --timestamp \
  --entitlements macos/entitlements.plist \
  --sign "$APPLE_SIGNING_IDENTITY" "$APP"

# ── 2. Gates, before spending a notarization round trip ─────────────────────────
if grep -q '"entitlements"' tauri.conf.json && [[ ! -f "$APP/Contents/embedded.provisionprofile" ]]; then
  echo "✗ $APP/Contents/embedded.provisionprofile is missing — Tauri did not copy it."
  echo "  Check bundle.macOS.files in tauri.conf.json. Refusing to ship."
  exit 1
fi

# Checks one binary and reports whether the OS let it run at all. 137 is SIGKILL, which
# is what a rejected entitlement looks like from the outside.
assert_execs() {
  local path="$1" label="$2" rc
  [[ -f "$path" ]] || return 0
  set +e; "$path" --help >/dev/null 2>&1; rc=$?; set -e
  if [[ $rc -eq 137 ]]; then
    echo "✗ $label is SIGKILLed on exec — it still carries entitlements it cannot use."
    echo "  This is the bug that shipped in 1.1.29-1.1.32. Refusing to ship."
    exit 1
  fi
  echo "  ✓ $label execs (exit $rc, not SIGKILL)"
}
echo "→ Sidecar gate…"
assert_execs "$APP/Contents/MacOS/agent" "agent (build dir)"
assert_execs "$APP/Contents/MacOS/ankayma-helper" "ankayma-helper (build dir)"

# The app must actually LAUNCH. `open` goes through LaunchServices → launchd → taskgated,
# which is where 1.1.26/1.1.28 died while codesign, spctl and stapler all reported the
# bundle valid. Note this gate CANNOT see the sidecar failure above — the app starts
# perfectly, only the tunnel is missing — which is why both exist.
if [[ "${SKIP_LAUNCH_CHECK:-0}" != "1" ]]; then
  echo "→ Launch gate…"
  if ! open -g "$APP" 2>/tmp/ankayma-launch-gate.err; then
    echo "✗ The app failed to launch:"; cat /tmp/ankayma-launch-gate.err
    exit 1
  fi
  sleep 5
  if ! pgrep -f "$(basename "$APP" .app)" >/dev/null 2>&1; then
    echo "✗ The app launched and then died within 5s — refusing to ship."
    exit 1
  fi
  pkill -f "$(basename "$APP" .app)" >/dev/null 2>&1 || true
  echo "  ✓ app spawned and stayed alive"
fi

# ── 3. Notarize the FIXED .app, then staple ─────────────────────────────────────
notarize() {
  local target="$1"
  if [[ -n "${APPLE_API_KEY:-}" ]]; then
    xcrun notarytool submit "$target" \
      --key "$APPLE_API_KEY_PATH" --key-id "$APPLE_API_KEY" --issuer "$APPLE_API_ISSUER" --wait
  else
    xcrun notarytool submit "$target" \
      --apple-id "$APPLE_ID" --password "$APPLE_PASSWORD" --team-id "$APPLE_TEAM_ID" --wait
  fi
}
echo "→ Notarizing the .app…"
APP_ZIP="$(mktemp -d)/Ankayma.zip"
ditto -c -k --keepParent "$APP" "$APP_ZIP"
notarize "$APP_ZIP"
xcrun stapler staple "$APP"

# ── 4. Updater artifact, rebuilt from the fixed bundle ──────────────────────────
#
# Tauri emitted a tarball during the build, from the pre-fix bundle. Replace it, then
# re-sign with the minisign key — the updater refuses an artifact whose signature does
# not match, so a stale .sig is not merely wrong, it blocks the update entirely.
echo "→ Rebuilding the updater artifact from the fixed bundle…"
TARBALL="$BUNDLE_DIR/$(basename "$APP").tar.gz"
rm -f "$TARBALL" "$TARBALL.sig"
tar -czf "$TARBALL" -C "$BUNDLE_DIR" "$(basename "$APP")"
cargo tauri signer sign "$TARBALL" >/tmp/ankayma-sig.out 2>&1 || {
  echo "✗ updater signing failed:"; cat /tmp/ankayma-sig.out; exit 1; }
if [[ ! -f "$TARBALL.sig" ]]; then
  # Older CLIs print the signature instead of writing it.
  grep -oE '^[A-Za-z0-9+/=]{40,}$' /tmp/ankayma-sig.out | tail -1 > "$TARBALL.sig"
fi
[[ -s "$TARBALL.sig" ]] || { echo "✗ no updater signature produced"; exit 1; }
echo "  ✓ $(basename "$TARBALL") + .sig"

# ── 5. DMG, built from the fixed bundle ─────────────────────────────────────────
echo "→ Building the DMG from the fixed bundle…"
VERSION=$(sed -n 's/.*"version": *"\(.*\)".*/\1/p' tauri.conf.json | head -1)
DMG_DIR=../../target/universal-apple-darwin/release/bundle/dmg
STAGE=$(mktemp -d)
mkdir -p "$DMG_DIR"
cp -R "$APP" "$STAGE/"
ln -s /Applications "$STAGE/Applications"
DMG="$DMG_DIR/Ankayma_${VERSION}_universal.dmg"
rm -f "$DMG"
hdiutil create -volname "Ankayma" -srcfolder "$STAGE" -ov -format UDZO "$DMG" >/dev/null
codesign --force --timestamp --sign "$APPLE_SIGNING_IDENTITY" "$DMG"

# A DMG whose container is signed but not notarized trips Gatekeeper on mount ("Apple
# could not verify… is free of malware") when downloaded from the web.
echo "→ Notarizing the DMG container…"
notarize "$DMG"
xcrun stapler staple "$DMG"

# ── 6. Gate the SHIPPED artifacts, not the build directory ──────────────────────
#
# This is the check that was missing. Everything above can be correct while the DMG and
# the tarball still carry older binaries — that is precisely what happened. Verify what
# users receive, by opening it the way they will.
echo "→ Shipped-artifact gate…"
MNT=$(mktemp -d)
hdiutil attach "$DMG" -nobrowse -readonly -mountpoint "$MNT" >/dev/null
DMG_APP=$(find "$MNT" -maxdepth 1 -iname "*.app" | head -1)
assert_execs "$DMG_APP/Contents/MacOS/agent" "agent (inside the DMG)"
assert_execs "$DMG_APP/Contents/MacOS/ankayma-helper" "ankayma-helper (inside the DMG)"
hdiutil detach "$MNT" >/dev/null

UNTAR=$(mktemp -d)
tar -xzf "$TARBALL" -C "$UNTAR"
TAR_APP=$(find "$UNTAR" -maxdepth 1 -iname "*.app" | head -1)
assert_execs "$TAR_APP/Contents/MacOS/agent" "agent (inside the updater tarball)"

echo
echo "✓ Signed + notarized DMG: $DMG"
echo "✓ Updater artifact:       $TARBALL (+ .sig)"
echo "  Verify before publishing:"
echo "    spctl -a -vv -t install \"$DMG\"        # accepted, Notarized Developer ID"
echo "    xcrun stapler validate \"$DMG\"         # validate worked"
