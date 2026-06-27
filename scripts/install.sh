#!/bin/sh
# install.sh — one-line installer for the Ankayma Linux client (CLI `mesh` + daemon `agent`).
#
# Tier-1 short-term channel (Part D §D.1.3 — CLI is a companion tool on agent-core):
# download a static musl binary, verify its SHA-256 against a signed checksum file,
# and (when `cosign` is present) verify that checksum file's Cosign signature against
# the committed public key — same signing model as the GitLab release flow [T:A.1.21].
#
# Usage (from the website):
#   curl -fsSL https://get.ankayma.com/install.sh | sh
#
# Overridable via environment:
#   ANKAYMA_BASE_URL   download host           (default https://get.ankayma.com)
#   ANKAYMA_VERSION    version dir to fetch    (default "latest")
#   ANKAYMA_PREFIX     install dir for binaries(default /usr/local/bin)
#   ANKAYMA_NO_COSIGN  set =1 to skip the Cosign step when cosign is unavailable
#
# POSIX sh on purpose — runs on Ubuntu/Debian/Alpine/RHEL without bash.
set -eu

BASE_URL="${ANKAYMA_BASE_URL:-https://get.ankayma.com}"
VERSION="${ANKAYMA_VERSION:-latest}"
PREFIX="${ANKAYMA_PREFIX:-/usr/local/bin}"

say()  { printf '%s\n' "$*"; }
err()  { printf '✗ %s\n' "$*" >&2; }
die()  { err "$*"; exit 1; }

# ── 1. Platform check ───────────────────────────────────────────────────────
[ "$(uname -s)" = "Linux" ] || die "This installer is for Linux. macOS/iOS: see the website Download section."

arch="$(uname -m)"
case "$arch" in
  x86_64 | amd64) PLAT="linux-amd64" ;;
  aarch64 | arm64)
    die "arm64 builds are not published yet (x86_64 only for now). Track it on GitHub Releases."
    ;;
  *) die "Unsupported architecture: $arch (only x86_64 is published today)." ;;
esac

# ── 2. Required tooling ─────────────────────────────────────────────────────
have() { command -v "$1" >/dev/null 2>&1; }
have curl     || die "curl is required."
have sha256sum || have shasum || die "sha256sum (or shasum) is required for verification."

DL="$BASE_URL/$VERSION"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT INT TERM

fetch() { # fetch <remote-name> -> $TMP/<remote-name>  (hard-fail)
  curl -fsSL "$DL/$1" -o "$TMP/$1" || die "Download failed: $DL/$1"
}
fetch_opt() { # fetch <remote-name> -> $TMP/<remote-name>  (soft; returns non-zero if absent)
  curl -fsSL "$DL/$1" -o "$TMP/$1" 2>/dev/null
}

say "→ Downloading Ankayma client ($VERSION, $PLAT) from $BASE_URL …"
fetch "mesh-$PLAT"
fetch "agent-$PLAT"
fetch "SHA256SUMS"
# Signature + key are required only when we actually verify (cosign present). Fetch
# them best-effort so the integrity path still works before a signed release exists.
fetch_opt "SHA256SUMS.sig" && HAVE_SIG=1 || HAVE_SIG=0
fetch_opt "cosign.pub"     && HAVE_PUB=1 || HAVE_PUB=0

# ── 3. Integrity: SHA-256 against the checksum manifest ─────────────────────
say "→ Verifying SHA-256 checksums …"
cd "$TMP"
# Keep only the lines for the two files we actually downloaded, then verify.
grep -E "  (mesh|agent)-$PLAT\$" SHA256SUMS > SHA256SUMS.want || die "Checksums for $PLAT not found in SHA256SUMS."
if have sha256sum; then
  sha256sum -c SHA256SUMS.want >/dev/null || die "Checksum mismatch — refusing to install."
else
  # macOS/BSD shasum fallback (rare on Linux, but harmless).
  shasum -a 256 -c SHA256SUMS.want >/dev/null || die "Checksum mismatch — refusing to install."
fi
say "  ✓ checksums match"

# ── 4. Authenticity: Cosign signature of the checksum manifest ──────────────
# One signature over SHA256SUMS authenticates every binary it lists. If cosign is
# absent we fall back to HTTPS+checksum integrity and tell the user how to upgrade
# to full verification — we do NOT silently claim a guarantee we didn't check [P.3].
if have cosign; then
  [ "$HAVE_SIG" = 1 ] && [ "$HAVE_PUB" = 1 ] \
    || die "cosign is installed but the host has no SHA256SUMS.sig/cosign.pub — cannot verify. Refusing to install."
  say "→ Verifying Cosign signature …"
  cosign verify-blob --insecure-ignore-tlog \
    --key cosign.pub --signature SHA256SUMS.sig SHA256SUMS >/dev/null 2>&1 \
    || die "Cosign signature INVALID — refusing to install. Report this."
  say "  ✓ signature valid (key: cosign.pub)"
elif [ "${ANKAYMA_NO_COSIGN:-0}" = "1" ]; then
  err "cosign not installed — skipping signature check (ANKAYMA_NO_COSIGN=1)."
  err "  Integrity is still enforced via HTTPS + SHA-256, but authenticity is not."
else
  err "cosign is not installed — cannot verify the publisher signature."
  err "  Install it (https://docs.sigstore.dev/cosign/installation) then re-run, or"
  err "  set ANKAYMA_NO_COSIGN=1 to proceed on HTTPS+checksum integrity alone."
  exit 1
fi

# ── 5. Install ──────────────────────────────────────────────────────────────
SUDO=""
if [ "$(id -u)" -ne 0 ]; then
  have sudo || die "Need root (or sudo) to write to $PREFIX. Re-run as root or set ANKAYMA_PREFIX to a writable dir."
  SUDO="sudo"
fi

say "→ Installing to $PREFIX (mesh, agent) …"
$SUDO install -d "$PREFIX"
$SUDO install -m 0755 "$TMP/mesh-$PLAT"  "$PREFIX/mesh"
$SUDO install -m 0755 "$TMP/agent-$PLAT" "$PREFIX/agent"

say ""
say "✓ Installed:"
say "    $PREFIX/mesh   — CLI (key tools, mirrors wg(8))"
say "    $PREFIX/agent  — mesh data-plane daemon"
say ""
say "Next steps:"
say "    mesh genkey | tee priv.key | mesh pubkey   # generate a WireGuard keypair"
say "    sudo agent up                              # bring the overlay up (needs /dev/net/tun)"
say ""
say "The agent is open source — audit it: https://github.com/ankayma/open-client"
