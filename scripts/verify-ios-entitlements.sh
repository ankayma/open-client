#!/usr/bin/env bash
# verify-ios-entitlements.sh <path-to.ipa|path-to.app>
#
# Read the associated-domains claim out of a SIGNED artifact, never out of a file we wrote.
#
# Two separate build steps rewrite that key behind us: xcodegen regenerates the entitlements
# from project.yml, and tauri-plugin-deep-link's build script rewrites the generated file
# from the "Build Rust Code" phase — measured 2026-08-04, it REMOVES the key outright when
# no app link is configured (see scripts/ios-postinit.sh §3c and
# docs/macos-associated-domains.md §5.1).
#
# Every static check stays green when this goes wrong. The app installs, launches, and then
# either fails the security-key ceremony with "not associated with domain" or quietly opens
# invite links in a browser. The signed artifact is the only witness — which is why this is a
# separate script: it runs inside release-ios.sh, and it also runs on its own against an .ipa
# that already shipped, without a rebuild.
#
# Exit 0 = both services present. Exit 1 = something is missing (or unreadable).
set -euo pipefail

ARTIFACT="${1:-}"
if [[ -z "$ARTIFACT" || ! -e "$ARTIFACT" ]]; then
  echo "usage: $0 <path to .ipa or .app>" >&2
  exit 2
fi

# The complete set the app must claim. Both are load-bearing and neither is announced when
# absent, so they are checked together:
#   webcredentials — the OS validates the WebAuthn RP ID against it (native security-key
#                    ceremony, gui/src-tauri/src/webauthn_apple.rs).
#   applinks       — the OS opens this app for the invite link instead of a browser.
REQUIRED_SERVICES=(
  "webcredentials:ankayma.com"
  "applinks:cp.ankayma.com"
)

WORK=""
cleanup() { [[ -n "$WORK" ]] && rm -rf "$WORK"; }
trap cleanup EXIT

case "$ARTIFACT" in
  *.ipa)
    WORK=$(mktemp -d)
    unzip -q "$ARTIFACT" -d "$WORK"
    APP=$(find "$WORK/Payload" -maxdepth 1 -name "*.app" | head -1)
    ;;
  *)
    APP="$ARTIFACT"
    ;;
esac

if [[ -z "${APP:-}" || ! -d "$APP" ]]; then
  echo "✗ no .app bundle found in $ARTIFACT" >&2
  exit 1
fi

# `|| true` on purpose: an unsigned or malformed bundle makes codesign exit non-zero, and
# under `set -e` that would abort with codesign's own message instead of ours. An empty
# read then falls through to the missing-services report below, which is the honest outcome
# — we could not confirm the claim, so we must not pass.
ENTS=$(codesign -d --entitlements :- "$APP" 2>/dev/null || true)

MISSING=()
for svc in "${REQUIRED_SERVICES[@]}"; do
  grep -q -- "$svc" <<<"$ENTS" || MISSING+=("$svc")
done

if (( ${#MISSING[@]} > 0 )); then
  echo "✗ signed app is MISSING: ${MISSING[*]}" >&2
  echo "  webcredentials → the native security-key ceremony fails at runtime." >&2
  echo "  applinks       → invite links open a browser instead of the app." >&2
  echo "  Likeliest cause: tauri-plugin-deep-link rewrote the entitlements. Check that" >&2
  echo "  scripts/ios-postinit.sh §3c-bis renamed the app target's entitlements file," >&2
  echo "  and that gen/apple was regenerated after that change." >&2
  exit 1
fi

echo "✓ associated-domains intact in the signed app (${REQUIRED_SERVICES[*]})"
