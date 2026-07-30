#!/bin/sh
# install-macos-headless.sh — one-line installer for the Ankayma headless macOS client
# (CLI `mesh` + daemon `agent`, no GUI/Tauri) — for servers, not desktop use.
#
# Persistence is a plain launchd LaunchDaemon (`/Library/LaunchDaemons/com.ankayma.agent.plist`,
# `launchctl bootstrap system`) — no SMAppService, no app bundle, no `.pkg` — mirroring how
# `tailscaled install-system-daemon` runs headless on macOS. `mesh`/`install.sh` (the Linux
# installer) is untouched; this is a separate script for a separate platform+channel.
#
# Usage:
#   curl -fsSL https://get.ankayma.com/macos-headless/install.sh | sudo sh
#
# First-time enrollment needs a node join-token (E-3, same mechanism the GUI's QR-scan /
# "paste an invite" flow redeems — get one from the control plane / an admin) — without it
# the daemon starts but has no identity to enroll with:
#   ANKAYMA_JOIN_TOKEN=<token> curl -fsSL https://get.ankayma.com/macos-headless/install.sh | sudo sh
# Re-running later (upgrade) with no token is fine — the daemon reuses the identity already
# persisted under /Library/Ankayma from the first run.
#
# Overridable via environment:
#   ANKAYMA_BASE_URL       download host        (default https://get.ankayma.com/macos-headless)
#   ANKAYMA_VERSION        version dir to fetch  (default "latest")
#   ANKAYMA_PREFIX         install dir           (default /usr/local/bin)
#   ANKAYMA_CONTROL_PLANE  control-plane URL     (default https://cp.ankayma.com)
#   ANKAYMA_JOIN_TOKEN     node join-token (E-3) — first run only
#   ANKAYMA_NO_COSIGN      set =1 to skip the Cosign step when cosign is unavailable
#
# POSIX sh on purpose (same reasoning as install.sh).
set -eu

BASE_URL="${ANKAYMA_BASE_URL:-https://get.ankayma.com/macos-headless}"
VERSION="${ANKAYMA_VERSION:-latest}"
PREFIX="${ANKAYMA_PREFIX:-/usr/local/bin}"
CONTROL_PLANE="${ANKAYMA_CONTROL_PLANE:-https://cp.ankayma.com}"
STATE_DIR="/Library/Ankayma"
PLIST="/Library/LaunchDaemons/com.ankayma.agent.plist"

say()  { printf '%s\n' "$*"; }
err()  { printf '✗ %s\n' "$*" >&2; }
die()  { err "$*"; exit 1; }

# ── 1. Platform check ───────────────────────────────────────────────────────
[ "$(uname -s)" = "Darwin" ] || die "This installer is for macOS. Linux: see install.sh. Windows: see install-windows.ps1."
[ "$(id -u)" -eq 0 ] || die "Run as root (sudo) — needs to write $PREFIX, $STATE_DIR and $PLIST."

# ── 2. Required tooling ─────────────────────────────────────────────────────
have() { command -v "$1" >/dev/null 2>&1; }
have curl   || die "curl is required."
have shasum || die "shasum is required for verification."

DL="$BASE_URL/$VERSION"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT INT TERM

fetch() {
  curl -fsSL "$DL/$1" -o "$TMP/$1" || die "Download failed: $DL/$1"
}
fetch_opt() {
  curl -fsSL "$DL/$1" -o "$TMP/$1" 2>/dev/null
}

say "→ Downloading Ankayma headless client ($VERSION, macOS universal) from $BASE_URL …"
fetch "agent-macos-universal"
fetch "mesh-macos-universal"
fetch "SHA256SUMS"
fetch_opt "SHA256SUMS.sig" && HAVE_SIG=1 || HAVE_SIG=0
fetch_opt "cosign.pub"     && HAVE_PUB=1 || HAVE_PUB=0

# ── 3. Integrity: SHA-256 against the checksum manifest ─────────────────────
say "→ Verifying SHA-256 checksums …"
cd "$TMP"
shasum -a 256 -c SHA256SUMS >/dev/null || die "Checksum mismatch — refusing to install."
say "  ✓ checksums match"

# ── 4. Authenticity: Cosign signature of the checksum manifest ──────────────
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

# ── 5. Install binaries ──────────────────────────────────────────────────────
say "→ Installing to $PREFIX (mesh, agent) …"
install -d "$PREFIX"
install -m 0755 "$TMP/agent-macos-universal" "$PREFIX/agent"
install -m 0755 "$TMP/mesh-macos-universal"  "$PREFIX/mesh"

# ── 6. First-run enrollment (only when a join-token was given) ──────────────
# `agent up --join-token <T>` is the intended "headless server path" (its own doc
# comment in up.rs::load_or_enroll: "a golden image / MOTD never redeems a full-power
# secret — the join token is single-use + short-TTL and enrolls this node directly").
# `agent up` is a long-running foreground dataplane process with no one-shot
# enroll-then-exit mode, so run it in the background just long enough for
# `AgentState` to land at $STATE_DIR/agent.json, then stop it — the LaunchDaemon
# below starts the real, persistent run. The token is deliberately never written to
# the LaunchDaemon plist or passed as an argument there: plist mode is world-readable
# and process args are visible to every local user via `ps` — it is only ever live on
# the command line of this short-lived foreground process.
install -d -m 0700 "$STATE_DIR"
if [ -n "${ANKAYMA_JOIN_TOKEN:-}" ]; then
  say "→ Enrolling this node (join-token given) …"
  "$PREFIX/agent" up --join-token "$ANKAYMA_JOIN_TOKEN" --control-plane "$CONTROL_PLANE" \
    --state-dir "$STATE_DIR" > "$TMP/enroll.log" 2>&1 &
  ENROLL_PID=$!
  i=0
  while [ ! -f "$STATE_DIR/agent.json" ] && [ $i -lt 30 ]; do
    sleep 1; i=$((i + 1))
  done
  kill "$ENROLL_PID" >/dev/null 2>&1 || true
  wait "$ENROLL_PID" 2>/dev/null || true
  if [ ! -f "$STATE_DIR/agent.json" ]; then
    err "Enrollment did not complete within 30s:"
    cat "$TMP/enroll.log" >&2
    die "Refusing to install the LaunchDaemon without a persisted identity."
  fi
  say "  ✓ enrolled, identity persisted to $STATE_DIR/agent.json"
elif [ ! -f "$STATE_DIR/agent.json" ]; then
  err "No ANKAYMA_JOIN_TOKEN given and no existing identity in $STATE_DIR — the daemon"
  err "will start but has nothing to enroll with. Get a node join-token from your admin /"
  err "control plane and re-run with ANKAYMA_JOIN_TOKEN=<token>."
fi

# ── 7. LaunchDaemon: always up, restart on crash, survives reboot ───────────
say "→ Installing LaunchDaemon ($PLIST) …"
launchctl bootout system "$PLIST" >/dev/null 2>&1 || true
cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.ankayma.agent</string>
  <key>ProgramArguments</key>
  <array>
    <string>$PREFIX/agent</string>
    <string>up</string>
    <string>--state-dir</string>
    <string>$STATE_DIR</string>
    <string>--control-plane</string>
    <string>$CONTROL_PLANE</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>$STATE_DIR/agent.log</string>
  <key>StandardErrorPath</key>
  <string>$STATE_DIR/agent.log</string>
</dict>
</plist>
EOF
chmod 0644 "$PLIST"
chown root:wheel "$PLIST"

launchctl bootstrap system "$PLIST"
launchctl enable "system/com.ankayma.agent" 2>/dev/null || true

say ""
say "✓ Installed and started:"
say "    $PREFIX/agent, $PREFIX/mesh"
say "    LaunchDaemon com.ankayma.agent (RunAtLoad + KeepAlive — survives reboot)"
say ""
say "Check status:"
say "    sudo launchctl print system/com.ankayma.agent"
say "    tail -f $STATE_DIR/agent.log"
say ""
say "The agent is open source — audit it: https://github.com/ankayma/open-client"
