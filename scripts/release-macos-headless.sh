#!/usr/bin/env bash
# release-macos-headless.sh — build signed + notarized headless macOS binaries
# (mesh + agent, universal), for unattended/server deployment without the GUI app.
#
# Persistence on the target machine is a plain launchd LaunchDaemon (scripts/install-macos-headless.sh
# writes the plist + `launchctl bootstrap system`) — no app bundle, no SMAppService, no
# .pkg. Modeled on how `tailscaled install-system-daemon` runs headless on macOS in
# production: a binary + a plist in /Library/LaunchDaemons, nothing else. This is why
# this script builds loose binaries, not an .app/.dmg — release-macos.sh (the GUI
# pipeline) is not reused here beyond borrowing its signing/notarization credentials.
#
# Entitlements: NONE. The GUI's `com.apple.developer.associated-domains` entitlement
# (gui/src-tauri/macos/entitlements.plist) exists solely for WebAuthn inside the GUI's
# WKWebView — a headless agent/mesh binary has no WebView and claims no entitlements, so
# none of release-macos.sh's provisioning-profile preflight applies here. Plain
# `codesign --options runtime` (hardened runtime, required for notarization) is enough.
#
# Required env (same Apple credentials release-macos.sh already uses — no new secrets):
#   APPLE_SIGNING_IDENTITY  "Developer ID Application: Your Name (TEAMID)"
#   APPLE_TEAM_ID           your 10-char team id
# Notarization — either an App Store Connect API key (preferred) OR an Apple ID:
#   APPLE_API_KEY / APPLE_API_ISSUER / APPLE_API_KEY_PATH
#   — or —
#   APPLE_ID / APPLE_PASSWORD / APPLE_TEAM_ID
# Signing (cosign over SHA256SUMS, same model as release-linux.sh):
#   COSIGN_PASSWORD   password for cosign.key (script skips signing if cosign.key absent)
#
# Run from repo root: bash scripts/release-macos-headless.sh
# Output: dist/<version>/ — agent-macos-universal, mesh-macos-universal,
# SHA256SUMS(.sig), cosign.pub, install-macos-headless.sh.
set -euo pipefail

cd "$(dirname "$0")/.."

have() { command -v "$1" >/dev/null 2>&1; }

if [[ -z "${APPLE_SIGNING_IDENTITY:-}" ]]; then
  echo "✗ APPLE_SIGNING_IDENTITY is not set — refusing to ship an unsigned build." >&2
  exit 1
fi
if [[ -z "${APPLE_API_KEY:-}" && -z "${APPLE_ID:-}" ]]; then
  echo "✗ No notarization credentials (set APPLE_API_KEY* or APPLE_ID/APPLE_PASSWORD)." >&2
  exit 1
fi

VERSION="$(sed -n 's/^version *= *"\(.*\)"/\1/p' Cargo.toml | head -1)"
OUT="dist/$VERSION"

rustup target add x86_64-apple-darwin aarch64-apple-darwin >/dev/null 2>&1 || true

echo "→ Building agent + mesh for x86_64-apple-darwin + aarch64-apple-darwin …"
cargo build --release --locked --target x86_64-apple-darwin --bin agent --bin mesh
cargo build --release --locked --target aarch64-apple-darwin --bin agent --bin mesh

rm -rf "$OUT"; mkdir -p "$OUT"

echo "→ lipo -create (universal binaries) …"
lipo -create -output "$OUT/agent-macos-universal" \
  target/x86_64-apple-darwin/release/agent target/aarch64-apple-darwin/release/agent
lipo -create -output "$OUT/mesh-macos-universal" \
  target/x86_64-apple-darwin/release/mesh target/aarch64-apple-darwin/release/mesh

echo "→ Codesigning (hardened runtime, no entitlements) …"
codesign --force --options runtime --timestamp \
  --sign "$APPLE_SIGNING_IDENTITY" "$OUT/agent-macos-universal"
codesign --force --options runtime --timestamp \
  --sign "$APPLE_SIGNING_IDENTITY" "$OUT/mesh-macos-universal"

echo "→ Notarizing (loose binaries — stapling does not apply, only .app/.pkg/.dmg
   containers can be stapled; the binaries ship notarized-but-unstapled, same as most
   signed CLI tools; Gatekeeper does an online check on first run) …"
NOTARIZE_ZIP="$(mktemp -t ankayma-headless-XXXXXX).zip"
ditto -c -k --keepParent "$OUT/agent-macos-universal" "$NOTARIZE_ZIP.agent.zip"
ditto -c -k --keepParent "$OUT/mesh-macos-universal" "$NOTARIZE_ZIP.mesh.zip"
for f in "$NOTARIZE_ZIP.agent.zip" "$NOTARIZE_ZIP.mesh.zip"; do
  if [[ -n "${APPLE_API_KEY:-}" ]]; then
    xcrun notarytool submit "$f" \
      --key "$APPLE_API_KEY_PATH" --key-id "$APPLE_API_KEY" --issuer "$APPLE_API_ISSUER" --wait
  else
    xcrun notarytool submit "$f" \
      --apple-id "$APPLE_ID" --password "$APPLE_PASSWORD" --team-id "$APPLE_TEAM_ID" --wait
  fi
done
rm -f "$NOTARIZE_ZIP.agent.zip" "$NOTARIZE_ZIP.mesh.zip"

echo "→ Post-notarization gate: spctl must accept both binaries …"
spctl -a -vv -t execute "$OUT/agent-macos-universal"
spctl -a -vv -t execute "$OUT/mesh-macos-universal"

cp cosign.pub "$OUT/cosign.pub"
cp scripts/install-macos-headless.sh "$OUT/install-macos-headless.sh"

echo "→ Checksums …"
( cd "$OUT" && shasum -a 256 agent-macos-universal mesh-macos-universal > SHA256SUMS )

if [[ -f cosign.key ]]; then
  : "${COSIGN_PASSWORD:?set COSIGN_PASSWORD to sign (or remove cosign.key to skip signing)}"
  have cosign || { echo "✗ cosign not installed — see https://docs.sigstore.dev/cosign/installation" >&2; exit 1; }
  echo "→ Signing SHA256SUMS with cosign …"
  cosign sign-blob --yes --tlog-upload=false --key cosign.key \
    --output-signature "$OUT/SHA256SUMS.sig" "$OUT/SHA256SUMS"
  cosign verify-blob --insecure-ignore-tlog --key cosign.pub \
    --signature "$OUT/SHA256SUMS.sig" "$OUT/SHA256SUMS"
  echo "  ✓ signature verified"
else
  echo "⚠ cosign.key not found — skipping signature (unsigned artifacts; do NOT publish as release)."
fi

echo
echo "✓ Built $OUT:"
ls -lh "$OUT"
