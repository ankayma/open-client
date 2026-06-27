#!/usr/bin/env bash
# release-linux.sh — build static, Cosign-signed Linux binaries for website download.
#
# Produces a fully static x86_64 musl build of the CLI (`mesh`) and daemon (`agent`)
# that runs on ANY Linux distro/version (Ubuntu 18.04→24.04, Debian, Alpine, RHEL…)
# with no glibc/OpenSSL dependency — the dep tree is pure-Rust TLS (rustls+ring) and
# userspace WireGuard (boringtun), so musl-static links cleanly [T per Cargo.lock].
#
# You do NOT need a Linux VPS to build this. From macOS it cross-compiles via either
# `cargo zigbuild` (preferred, needs `brew install zig zigbuild`) or Docker using the
# CI-pinned image. On Linux it builds natively with musl-tools. [T:A.1.21] toolchain
# is pinned by rust-toolchain.toml (1.96.0).
#
# Signing (same model as .gitlab-ci.yml): we sign the SHA256SUMS manifest once; that
# one signature authenticates every listed binary. Requires the Cosign key:
#   COSIGN_PASSWORD   password for cosign.key   (env, never hard-coded)
#   cosign.key        repo-root private key (git-ignored / provided out of band)
#   cosign.pub        repo-root public key (committed)
#
# Output: dist/<version>/  ready to upload to the download host (e.g. the VPS nginx).
set -euo pipefail

cd "$(dirname "$0")/.."   # repo root
TARGET="x86_64-unknown-linux-musl"
PLAT="linux-amd64"
VERSION="$(sed -n 's/^version *= *"\(.*\)"/\1/p' Cargo.toml | head -1)"
OUT="dist/$VERSION"

have() { command -v "$1" >/dev/null 2>&1; }

# ── Build (pick the cross strategy that's available) ────────────────────────
build() {
  rustup target add "$TARGET" >/dev/null 2>&1 || true
  if have cargo-zigbuild; then
    echo "→ Building with cargo-zigbuild ($TARGET) …"
    cargo zigbuild --release --locked --target "$TARGET" --bin mesh --bin agent
  elif [[ "$(uname -s)" == "Linux" ]]; then
    echo "→ Building natively with musl-tools ($TARGET) …"
    have musl-gcc || { echo "✗ install musl-tools first: apt-get install -y musl-tools" >&2; exit 1; }
    CC_x86_64_unknown_linux_musl=musl-gcc \
      cargo build --release --locked --target "$TARGET" --bin mesh --bin agent
  elif have docker; then
    echo "→ Building in Docker (rust:1.96-slim, matches CI) …"
    docker run --rm -v "$PWD":/w -w /w rust:1.96-slim bash -euc "
      apt-get update -qq && apt-get install -y -qq musl-tools >/dev/null
      rustup target add $TARGET
      CC_x86_64_unknown_linux_musl=musl-gcc \
        cargo build --release --locked --target $TARGET --bin mesh --bin agent"
  else
    echo "✗ Need one of: cargo-zigbuild (brew install zig zigbuild), or Docker, or Linux+musl-tools." >&2
    exit 1
  fi
}

build

BIN_DIR="target/$TARGET/release"
[[ -x "$BIN_DIR/mesh" && -x "$BIN_DIR/agent" ]] || { echo "✗ binaries missing after build" >&2; exit 1; }

# ── Stage artifacts ─────────────────────────────────────────────────────────
rm -rf "$OUT"; mkdir -p "$OUT"
install -m 0755 "$BIN_DIR/mesh"  "$OUT/mesh-$PLAT"
install -m 0755 "$BIN_DIR/agent" "$OUT/agent-$PLAT"
strip "$OUT/mesh-$PLAT" "$OUT/agent-$PLAT" 2>/dev/null || true   # strip optional (no-op cross-stripping)
cp cosign.pub "$OUT/cosign.pub"
cp scripts/install.sh "$OUT/install.sh"

# ── Checksums + signature ───────────────────────────────────────────────────
( cd "$OUT" && sha256sum "mesh-$PLAT" "agent-$PLAT" > SHA256SUMS )

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
echo
echo "Publish (example — copy to the download host so the website can serve it):"
echo "    rsync -av $OUT/ root@<download-host>:/var/www/get.ankayma.com/$VERSION/"
echo "    ssh root@<download-host> 'ln -sfn $VERSION /var/www/get.ankayma.com/latest'"
echo "  Then: curl -fsSL https://get.ankayma.com/install.sh | sh"
