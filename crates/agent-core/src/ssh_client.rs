//! ssh_client — F-2 NoKeySSH client transport (Part D f2 §H.1, deviation v0.5).
//!
//! Intensity: **Critical** (CLAUDE.md T/A §) — crypto/transport on a security path.
//!
//! A pure-Rust SSH client (russh) so the SSH stream rides the mesh overlay with NO
//! system `ssh` binary (iOS/iPad cannot spawn one) and the SAME engine drives the
//! CLI, the desktop GUI terminal, and the iOS/iPad in-app terminal. `[T:russh@0.62]`
//!
//! What this module OWNS: connect + authenticate (the device's enrolled ed25519
//! mesh-SSH key, A.1.3 — no password, no static key on the node) + a shell PTY +
//! a UI-agnostic byte duplex. What it does NOT own: the local terminal (raw mode,
//! xterm.js) — callers wire their own I/O onto [`SshSession::write`]/[`recv`], so
//! this one engine serves every front-end. `[T:A.3.1]` hexagonal seam.
//!
//! Host-key trust `[T:A.1.3]`: the server's host key is **pinned** from the value
//! the control plane returned in the `/ssh/session` response (bound to node
//! identity) — NOT blind trust-on-first-use. An unpinned connect is refused unless
//! the caller opts into TOFU explicitly (honest, logged; P.3).

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use russh::client::{self, Config, Handler};
use russh::keys::{PrivateKey, PrivateKeyWithHashAlg, PublicKey};
use russh::{ChannelMsg, Disconnect};
use tokio::sync::mpsc;

/// The persistent per-device ed25519 SSH identity. This is the "key device đã
/// enroll" of §H.1: generated once, stored 0600 next to `agent.json`, and used to
/// authenticate to any same-owner node's embedded server. Distinct from the
/// WireGuard X25519 key (encryption, not signing) — SSH auth needs a signing key.
pub struct MeshSshKey(PrivateKey);

impl MeshSshKey {
    /// Load the device's mesh-SSH key from `path`, generating + persisting a fresh
    /// ed25519 key on first use. OpenSSH PEM on disk, mode 0600 (private material).
    /// `[T:ssh-key@0.7-openssh]` `[T:A.1.21]` ed25519 only — no RSA/ECDSA issuance.
    pub fn load_or_generate(path: &Path) -> Result<Self> {
        if let Ok(pem) = std::fs::read_to_string(path) {
            let key = PrivateKey::from_openssh(pem.trim())
                .map_err(|e| anyhow!("parse mesh-ssh key {}: {e}", path.display()))?;
            return Ok(Self(key));
        }
        // First run: mint a fresh ed25519 key. We seed from the OS CSPRNG into a
        // 32-byte seed and build the keypair via `from_seed` — this sidesteps the
        // `ssh_key` rng-trait version (rand_core 0.10) without pinning yet another
        // rand crate; `rand::rng()` is a CSPRNG. `[T:ssh-key@0.7-Ed25519Keypair]`
        use rand::RngCore;
        let mut seed = [0u8; 32];
        rand::rng().fill_bytes(&mut seed);
        let keypair = russh::keys::ssh_key::private::Ed25519Keypair::from_seed(&seed);
        seed.fill(0); // scrub the seed off the stack promptly
        let key = PrivateKey::from(keypair);
        let pem = key
            .to_openssh(russh::keys::ssh_key::LineEnding::LF)
            .map_err(|e| anyhow!("encode mesh-ssh key: {e}"))?;
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).ok();
        }
        write_private(path, pem.as_bytes())?;
        Ok(Self(key))
    }

    /// The public half — this is the device's SSH identity the server authorizes
    /// against the same-owner roster (Lát 2). OpenSSH one-line `ssh-ed25519 …`.
    pub fn public_openssh(&self) -> Result<String> {
        self.0
            .public_key()
            .to_openssh()
            .map_err(|e| anyhow!("encode mesh-ssh pubkey: {e}"))
    }

    /// Borrow the underlying private key (for constructing the auth method).
    pub fn private(&self) -> &PrivateKey {
        &self.0
    }

    /// [T:ci-deploy exec] A fresh ed25519 identity that is never written to disk —
    /// for a CI run's one-shot exec, matching `ci_deploy`'s ephemeral WireGuard
    /// keypair (never persisted). The target's F0 `Authorizer::TrustOverlay`
    /// accepts any offered key (reaching the overlay already proved enrollment),
    /// so an identity nobody has seen before is expected here, not a gap.
    pub fn generate_ephemeral() -> Result<Self> {
        use rand::RngCore;
        let mut seed = [0u8; 32];
        rand::rng().fill_bytes(&mut seed);
        let keypair = russh::keys::ssh_key::private::Ed25519Keypair::from_seed(&seed);
        seed.fill(0);
        Ok(Self(PrivateKey::from(keypair)))
    }
}

/// Write `bytes` to `path` with owner-only permissions (0600). The mesh-SSH
/// private key must never be world-readable. `[T:A.1.21]`
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    std::fs::write(path, bytes).with_context(|| format!("write {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("chmod 0600 {}", path.display()))?;
    }
    Ok(())
}

/// How to reach + trust the target node's embedded SSH server.
pub struct SshConnectOptions {
    /// Overlay address of the target (from `/ssh/session`). Literal IPv4/IPv6.
    pub host: String,
    /// The embedded server's port (default 22022 — bound on the overlay only).
    pub port: u16,
    /// The POSIX login to land as (shared user `ankayma`; `root` for the legacy
    /// path). The embedded server maps this to a PTY.
    pub username: String,
    /// The pinned server host key (OpenSSH one-line form) the control plane bound
    /// to this node's identity. `None` + `allow_unpinned=false` ⟹ refuse (fail
    /// closed). `[T:A.1.3]`
    pub expected_host_key: Option<String>,
    /// Opt-in trust-on-first-use when no pin is available (honest, logged). Off by
    /// default — a pin is the norm.
    pub allow_unpinned: bool,
    /// Terminal type + initial window (drives the remote PTY).
    pub term: String,
    pub cols: u32,
    pub rows: u32,
    /// A CP-signed root-elevation grant to present (§H.4). When set, the client
    /// sends it as an SSH env var before requesting the shell, so the server lands
    /// a root PTY instead of the unprivileged shared user. `None` → normal login.
    pub elevate_grant: Option<String>,
    /// How long to wait for the TCP connect before giving up on a SINGLE attempt
    /// (fail-fast instead of the ~75s OS default when the mesh path is down).
    pub connect_timeout: Duration,
    /// Total budget across retry attempts. A freshly-established overlay drops the
    /// first packets while the WireGuard handshake settles, so the first connect
    /// can time out even though the path is about to come up; we retry within this
    /// budget so a first connect succeeds instead of failing the user.
    /// [owner feedback 2026-07-05]
    pub connect_deadline: Duration,
}

impl SshConnectOptions {
    /// Sensible defaults for the embedded-server transport: port 22022, `xterm`,
    /// 80x24, host-key pin required.
    pub fn new(host: impl Into<String>, username: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            port: 22022,
            username: username.into(),
            expected_host_key: None,
            allow_unpinned: false,
            term: "xterm-256color".to_string(),
            cols: 80,
            rows: 24,
            elevate_grant: None,
            connect_timeout: Duration::from_secs(12),
            connect_deadline: Duration::from_secs(30),
        }
    }
}

/// One event coming back from the remote shell. UI-agnostic: the CLI writes
/// `Data` to stdout, the GUI/iOS terminal emits it to xterm.js.
#[derive(Debug)]
pub enum SshEvent {
    /// stdout/stderr bytes from the remote PTY.
    Data(Vec<u8>),
    /// The remote shell exited with this status.
    Exit(u32),
    /// The remote sent EOF (no more data will follow).
    Eof,
    /// The transport dropped (channel closed / disconnected).
    Disconnected,
}

/// Messages the front-end sends into the running session.
enum Inbound {
    Data(Vec<u8>),
    Resize { cols: u32, rows: u32 },
    Eof,
    Close,
}

/// A live SSH session to a node's embedded server: a shell on a remote PTY, with
/// a byte duplex any front-end can drive. Dropping it (or calling [`close`]) tears
/// the session down. `[T:A.1.1]` the stream is direct over the overlay — the
/// control plane is never on this path.
#[derive(Debug)]
pub struct SshSession {
    input_tx: mpsc::Sender<Inbound>,
    output_rx: mpsc::Receiver<SshEvent>,
    // `Option` so `close()` can `.take()` + await the pump without moving a field
    // out of a `Drop` type. `Drop` aborts it if the caller never called `close()`.
    pump: Option<tokio::task::JoinHandle<()>>,
}

/// Outcome of a single connect+auth attempt, so the retry loop knows whether to
/// try again. `Transient` = worth retrying (path still settling); `Fatal` = fail
/// closed now (auth rejected).
enum AttemptError {
    Transient(anyhow::Error),
    Fatal(anyhow::Error),
}

impl SshSession {
    /// One connect+authenticate attempt: TCP connect (bounded by `attempt_timeout`),
    /// host-key check via the handler, then publickey auth. Returns the authenticated
    /// handle, or an [`AttemptError`] classifying whether a retry could help. A
    /// host-key mismatch surfaces as a transient connect error and is retried within
    /// the caller's budget — it still fails closed (never authenticates).
    async fn connect_and_auth(
        opts: &SshConnectOptions,
        key: &MeshSshKey,
        expected: Option<PublicKey>,
        attempt_timeout: Duration,
    ) -> std::result::Result<client::Handle<ClientHandler>, AttemptError> {
        let config = Arc::new(Config {
            // A torn-down idle overlay re-handshakes transparently; don't give up
            // during that gap. Mirrors the old system-ssh ServerAliveInterval.
            inactivity_timeout: Some(Duration::from_secs(3600)),
            keepalive_interval: Some(Duration::from_secs(5)),
            ..Default::default()
        });
        let handler = ClientHandler {
            expected_host_key: expected,
            allow_unpinned: opts.allow_unpinned,
        };

        // Bound the TCP connect so an unreachable target fails fast instead of
        // hanging on the OS default (~75s) — the mesh path may simply be settling.
        let connect = client::connect(config, (opts.host.as_str(), opts.port), handler);
        let mut handle = match tokio::time::timeout(attempt_timeout, connect).await {
            Ok(Ok(h)) => h,
            Ok(Err(e)) => {
                return Err(AttemptError::Transient(anyhow!(
                    "connect {}:{}: {e}",
                    opts.host,
                    opts.port
                )))
            }
            Err(_) => {
                return Err(AttemptError::Transient(anyhow!(
                    "connect {}:{} timed out after {}s — target unreachable (mesh path settling?)",
                    opts.host,
                    opts.port,
                    attempt_timeout.as_secs()
                )))
            }
        };

        // ed25519 needs no RSA hash negotiation → hash alg None. `[T:russh@0.62]`
        let auth = match handle
            .authenticate_publickey(
                opts.username.clone(),
                PrivateKeyWithHashAlg::new(Arc::new(key.private().clone()), None),
            )
            .await
        {
            Ok(a) => a,
            // The channel can drop mid-auth while the path is still settling — retry.
            Err(e) => return Err(AttemptError::Transient(anyhow!("authenticate: {e}"))),
        };
        if !auth.success() {
            // The node actively rejected this identity — retrying cannot help.
            return Err(AttemptError::Fatal(anyhow!(
                "identity-bound auth rejected as {} — device not authorized on this node",
                opts.username
            )));
        }
        Ok(handle)
    }

    /// [T:ci-deploy exec] One-shot non-interactive exec over an already-connected
    /// stream — e.g. a SOCKS5-`CONNECT`ed `TcpStream` through `netstack`'s
    /// userspace tunnel (`agent ci-deploy`), where there is no routable kernel
    /// path to the target's overlay IP for a plain `client::connect(host, port)`.
    /// No PTY (a batch command has no terminal), no retry loop (the caller
    /// already waited for the WireGuard handshake to settle before dialing).
    /// Same auth + host-key-pinning + elevation-grant rules as [`Self::connect`]
    /// — just a single command instead of an interactive shell, and the network
    /// transport is supplied by the caller instead of resolved from `opts.host`.
    pub async fn exec_over_stream<S>(
        stream: S,
        opts: &SshConnectOptions,
        key: &MeshSshKey,
        command: &str,
    ) -> Result<(u32, Vec<u8>)>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let expected = match &opts.expected_host_key {
            Some(s) => Some(
                PublicKey::from_openssh(s.trim())
                    .map_err(|e| anyhow!("parse pinned host key: {e}"))?,
            ),
            None => None,
        };
        if expected.is_none() && !opts.allow_unpinned {
            bail!(
                "no pinned host key for {} and TOFU not allowed — refusing (A.1.3 fail-closed)",
                opts.host
            );
        }

        let config = Arc::new(Config {
            inactivity_timeout: Some(Duration::from_secs(60)),
            keepalive_interval: Some(Duration::from_secs(5)),
            ..Default::default()
        });
        let handler = ClientHandler {
            expected_host_key: expected,
            allow_unpinned: opts.allow_unpinned,
        };

        let mut handle = client::connect_stream(config, stream, handler)
            .await
            .map_err(|e| anyhow!("connect over stream: {e}"))?;

        // ed25519 needs no RSA hash negotiation → hash alg None. `[T:russh@0.62]`
        let auth = handle
            .authenticate_publickey(
                opts.username.clone(),
                PrivateKeyWithHashAlg::new(Arc::new(key.private().clone()), None),
            )
            .await
            .map_err(|e| anyhow!("authenticate: {e}"))?;
        if !auth.success() {
            bail!(
                "identity-bound auth rejected as {} — device not authorized on this node",
                opts.username
            );
        }

        let mut channel = handle
            .channel_open_session()
            .await
            .map_err(|e| anyhow!("open session channel: {e}"))?;
        // [F-2 §H.4] Present the elevation grant BEFORE exec, same as the
        // interactive path — the server decides root-vs-unprivileged from it.
        if let Some(grant) = &opts.elevate_grant {
            channel
                .set_env(false, crate::ssh_server::ELEVATE_GRANT_ENV, grant.clone())
                .await
                .map_err(|e| anyhow!("present elevation grant: {e}"))?;
        }
        channel
            .exec(true, command.as_bytes())
            .await
            .map_err(|e| anyhow!("exec: {e}"))?;

        let mut output = Vec::new();
        let mut code: u32 = 1;
        loop {
            match channel.wait().await {
                Some(ChannelMsg::Data { data }) => output.extend_from_slice(&data),
                Some(ChannelMsg::ExtendedData { data, .. }) => output.extend_from_slice(&data),
                Some(ChannelMsg::ExitStatus { exit_status }) => code = exit_status,
                Some(ChannelMsg::Eof) | Some(ChannelMsg::Close) => {}
                Some(_) => {}
                None => break,
            }
        }
        let _ = handle
            .disconnect(Disconnect::ByApplication, "", "en")
            .await;
        Ok((code, output))
    }

    /// Connect, authenticate with the device's mesh-SSH key, open a shell PTY, and
    /// start pumping. Fails closed on a host-key mismatch or auth rejection.
    pub async fn connect(opts: &SshConnectOptions, key: &MeshSshKey) -> Result<Self> {
        let expected = match &opts.expected_host_key {
            Some(s) => Some(
                PublicKey::from_openssh(s.trim())
                    .map_err(|e| anyhow!("parse pinned host key: {e}"))?,
            ),
            None => None,
        };
        if expected.is_none() && !opts.allow_unpinned {
            bail!(
                "no pinned host key for {} and TOFU not allowed — refusing (A.1.3 fail-closed)",
                opts.host
            );
        }

        // A freshly-established overlay drops the first packets while the WireGuard
        // handshake settles, so the first TCP/SSH connect can time out even though
        // the path is about to work. Retry the connect+auth within a bounded budget
        // so a first connect succeeds instead of surfacing "target unreachable".
        // Auth rejection is fatal (fail closed) and never retried. [owner 2026-07-05]
        let start = Instant::now();
        let backoff = Duration::from_millis(1500);
        let mut attempt = 0u32;
        let handle = loop {
            attempt += 1;
            // Cap this attempt by whatever budget remains (min 1s so the last try is
            // not zero-length), never exceeding the per-attempt fail-fast timeout.
            let remaining = opts.connect_deadline.saturating_sub(start.elapsed());
            let attempt_timeout = opts
                .connect_timeout
                .min(remaining.max(Duration::from_secs(1)));
            match Self::connect_and_auth(opts, key, expected.clone(), attempt_timeout).await {
                Ok(h) => break h,
                Err(AttemptError::Fatal(e)) => return Err(e),
                Err(AttemptError::Transient(e)) => {
                    // Out of budget (no room for another attempt after backoff) → give up.
                    if start.elapsed() + backoff >= opts.connect_deadline {
                        return Err(e.context(format!(
                            "SSH connect to {}:{} failed after {} attempt(s) in {}s",
                            opts.host,
                            opts.port,
                            attempt,
                            opts.connect_deadline.as_secs()
                        )));
                    }
                    tokio::time::sleep(backoff).await;
                }
            }
        };

        let channel = handle
            .channel_open_session()
            .await
            .map_err(|e| anyhow!("open session channel: {e}"))?;
        channel
            .request_pty(false, &opts.term, opts.cols, opts.rows, 0, 0, &[])
            .await
            .map_err(|e| anyhow!("request pty: {e}"))?;
        // [F-2 §H.4] Present the root-elevation grant BEFORE the shell so the server
        // can decide root-vs-unprivileged when it spawns the PTY.
        if let Some(grant) = &opts.elevate_grant {
            channel
                .set_env(false, crate::ssh_server::ELEVATE_GRANT_ENV, grant.clone())
                .await
                .map_err(|e| anyhow!("present elevation grant: {e}"))?;
        }
        channel
            .request_shell(true)
            .await
            .map_err(|e| anyhow!("request shell: {e}"))?;

        let (input_tx, mut input_rx) = mpsc::channel::<Inbound>(64);
        let (output_tx, output_rx) = mpsc::channel::<SshEvent>(256);

        // One task owns the russh channel: russh's `wait` is `&mut` and `data` is
        // `&self`, so a single owner running the select loop is the correct shape
        // (no split). Keep `handle` alive here for the channel's lifetime.
        let pump = tokio::spawn(async move {
            let mut channel = channel;
            let _keepalive = handle;
            loop {
                tokio::select! {
                    inbound = input_rx.recv() => match inbound {
                        Some(Inbound::Data(d)) => {
                            if channel.data(&d[..]).await.is_err() { break; }
                        }
                        Some(Inbound::Resize { cols, rows }) => {
                            let _ = channel.window_change(cols, rows, 0, 0).await;
                        }
                        Some(Inbound::Eof) => { let _ = channel.eof().await; }
                        Some(Inbound::Close) | None => {
                            let _ = channel.eof().await;
                            break;
                        }
                    },
                    msg = channel.wait() => match msg {
                        Some(ChannelMsg::Data { data }) => {
                            if output_tx.send(SshEvent::Data(data.to_vec())).await.is_err() { break; }
                        }
                        Some(ChannelMsg::ExtendedData { data, .. }) => {
                            if output_tx.send(SshEvent::Data(data.to_vec())).await.is_err() { break; }
                        }
                        Some(ChannelMsg::ExitStatus { exit_status }) => {
                            let _ = output_tx.send(SshEvent::Exit(exit_status)).await;
                        }
                        Some(ChannelMsg::Eof) => {
                            let _ = output_tx.send(SshEvent::Eof).await;
                        }
                        Some(_) => {}
                        None => {
                            let _ = output_tx.send(SshEvent::Disconnected).await;
                            break;
                        }
                    },
                }
            }
        });

        Ok(Self {
            input_tx,
            output_rx,
            pump: Some(pump),
        })
    }

    /// Forward keystrokes / stdin bytes to the remote shell.
    pub async fn write(&self, data: &[u8]) -> Result<()> {
        self.input_tx
            .send(Inbound::Data(data.to_vec()))
            .await
            .map_err(|_| anyhow!("session closed"))
    }

    /// Tell the remote PTY the local window resized (xterm.js `onResize`, or a
    /// SIGWINCH on the CLI).
    pub async fn resize(&self, cols: u32, rows: u32) -> Result<()> {
        self.input_tx
            .send(Inbound::Resize { cols, rows })
            .await
            .map_err(|_| anyhow!("session closed"))
    }

    /// Signal EOF on stdin (Ctrl-D handoff) without closing the whole session.
    pub async fn send_eof(&self) -> Result<()> {
        self.input_tx
            .send(Inbound::Eof)
            .await
            .map_err(|_| anyhow!("session closed"))
    }

    /// Await the next event from the remote shell. `None` once the pump has ended.
    pub async fn recv(&mut self) -> Option<SshEvent> {
        self.output_rx.recv().await
    }

    /// A cloneable input handle (write/resize/close) that can be held separately
    /// from the session's `recv` loop. Needed by the GUI/iOS terminal: one task
    /// owns the session and pumps `recv` → xterm.js events, while the write/resize
    /// commands drive input through this handle.
    pub fn input(&self) -> SshInput {
        SshInput {
            input_tx: self.input_tx.clone(),
        }
    }

    /// Close the session and wait for the pump to wind down.
    pub async fn close(mut self) -> Result<()> {
        let _ = self.input_tx.send(Inbound::Close).await;
        if let Some(pump) = self.pump.take() {
            let _ = pump.await;
        }
        Ok(())
    }
}

/// A cloneable write side of a session — keystrokes, resize, EOF, close. Cheap to
/// clone (just an mpsc sender). See [`SshSession::input`].
#[derive(Clone)]
pub struct SshInput {
    input_tx: mpsc::Sender<Inbound>,
}

impl SshInput {
    /// Forward bytes to the remote shell.
    pub async fn write(&self, data: &[u8]) -> Result<()> {
        self.input_tx
            .send(Inbound::Data(data.to_vec()))
            .await
            .map_err(|_| anyhow!("session closed"))
    }

    /// Report a window resize to the remote PTY.
    pub async fn resize(&self, cols: u32, rows: u32) -> Result<()> {
        self.input_tx
            .send(Inbound::Resize { cols, rows })
            .await
            .map_err(|_| anyhow!("session closed"))
    }

    /// Ask the session to close.
    pub async fn close(&self) -> Result<()> {
        self.input_tx
            .send(Inbound::Close)
            .await
            .map_err(|_| anyhow!("session closed"))
    }
}

/// The client-side russh handler. Its one job is host-key verification — the
/// single most important MITM defense (A.1.3). We pin the key the control plane
/// bound to the node; anything else is refused.
struct ClientHandler {
    expected_host_key: Option<PublicKey>,
    allow_unpinned: bool,
}

impl Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKey,
    ) -> Result<bool, Self::Error> {
        match &self.expected_host_key {
            // Strict pin: accept ONLY the exact key bound to this node's identity.
            Some(pin) => Ok(server_public_key == pin),
            // No pin: only if the caller explicitly opted into TOFU (honest).
            None => Ok(self.allow_unpinned),
        }
    }
}

/// Best-effort teardown if the caller drops the session without `close()`.
impl Drop for SshSession {
    fn drop(&mut self) {
        let _ = self.input_tx.try_send(Inbound::Close);
        if let Some(pump) = self.pump.take() {
            pump.abort();
        }
    }
}

// Silence "unused" for the re-exported Disconnect on non-test builds where the
// pump doesn't reference it directly; kept for callers that map disconnects.
#[allow(unused_imports)]
use Disconnect as _Disconnect;

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use tempfile::tempdir;

    /// Generate a fresh ed25519 key for test host/CA keys, via `from_seed` (same
    /// rng-version-safe path as the engine — avoids ssh_key's rand_core bound).
    fn gen_ed25519() -> PrivateKey {
        use rand::RngCore;
        let mut seed = [0u8; 32];
        rand::rng().fill_bytes(&mut seed);
        PrivateKey::from(russh::keys::ssh_key::private::Ed25519Keypair::from_seed(
            &seed,
        ))
    }

    #[test]
    fn generates_and_reloads_stable_key() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("mesh-ssh-ed25519");
        let k1 = MeshSshKey::load_or_generate(&path).unwrap();
        let pub1 = k1.public_openssh().unwrap();
        assert!(pub1.starts_with("ssh-ed25519 "), "ed25519 pubkey: {pub1}");
        // Reload from disk → same identity (persistent, not regenerated).
        let k2 = MeshSshKey::load_or_generate(&path).unwrap();
        assert_eq!(pub1, k2.public_openssh().unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn private_key_is_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let path = dir.path().join("mesh-ssh-ed25519");
        MeshSshKey::load_or_generate(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn refuses_unpinned_without_optin() {
        // No pin + no TOFU opt-in ⟹ fail closed before any network I/O.
        let dir = tempdir().unwrap();
        let key = MeshSshKey::load_or_generate(&dir.path().join("k")).unwrap();
        let opts = SshConnectOptions::new("127.0.0.1", "ankayma");
        let err = SshSession::connect(&opts, &key).await.unwrap_err();
        assert!(err.to_string().contains("fail-closed"), "{err}");
    }

    // Full loopback: a minimal russh echo server that accepts our device pubkey,
    // grants a PTY+shell, and echoes bytes. Proves the client engine end-to-end:
    // host-key pin match, publickey auth, PTY/shell, byte duplex. This also
    // de-risks the Lát 2 server API.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn loopback_pin_auth_pty_echo() {
        use russh::server::{self, Auth, Msg, Server as _, Session};
        use russh::{Channel, ChannelId};

        // Fixed server host key so we can pin it on the client side.
        let host_key = gen_ed25519();
        let host_pub = host_key.public_key().to_openssh().unwrap();

        // Authorized client identity (the "enrolled device").
        let dir = tempdir().unwrap();
        let client_key = MeshSshKey::load_or_generate(&dir.path().join("k")).unwrap();
        let authorized: HashSet<String> = [client_key.public_openssh().unwrap()].into();

        #[derive(Clone)]
        struct Srv {
            authorized: Arc<HashSet<String>>,
        }
        impl server::Server for Srv {
            type Handler = SrvH;
            fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> SrvH {
                SrvH {
                    authorized: self.authorized.clone(),
                }
            }
        }
        struct SrvH {
            authorized: Arc<HashSet<String>>,
        }
        impl server::Handler for SrvH {
            type Error = russh::Error;
            async fn auth_publickey(
                &mut self,
                _user: &str,
                key: &PublicKey,
            ) -> Result<Auth, Self::Error> {
                let offered = key.to_openssh().unwrap_or_default();
                if self.authorized.contains(&offered) {
                    Ok(Auth::Accept)
                } else {
                    Ok(Auth::reject())
                }
            }
            async fn channel_open_session(
                &mut self,
                _channel: Channel<Msg>,
                reply: server::ChannelOpenHandle,
                _session: &mut Session,
            ) -> Result<(), Self::Error> {
                reply.accept().await;
                Ok(())
            }
            async fn shell_request(
                &mut self,
                channel: ChannelId,
                session: &mut Session,
            ) -> Result<(), Self::Error> {
                // Greet on shell start so the client sees data promptly.
                session.data(channel, b"ready> ".to_vec())?;
                Ok(())
            }
            async fn data(
                &mut self,
                channel: ChannelId,
                data: &[u8],
                session: &mut Session,
            ) -> Result<(), Self::Error> {
                // Echo back with a marker so the test can assert round-trip.
                let mut out = b"echo:".to_vec();
                out.extend_from_slice(data);
                session.data(channel, out)?;
                Ok(())
            }
        }

        let config = Arc::new(server::Config {
            keys: vec![host_key],
            ..Default::default()
        });
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let mut srv = Srv {
            authorized: Arc::new(authorized),
        };
        tokio::spawn(async move {
            let _ = srv.run_on_socket(config, &listener).await;
        });

        // Client connects with the pin → must succeed, get the greeting, echo.
        let mut opts = SshConnectOptions::new(addr.ip().to_string(), "ankayma");
        opts.port = addr.port();
        opts.expected_host_key = Some(host_pub.to_string());
        let mut sess = SshSession::connect(&opts, &client_key)
            .await
            .expect("pinned connect + auth should succeed");

        // Read the greeting.
        let mut saw_ready = false;
        let mut saw_echo = false;
        sess.write(b"hi").await.unwrap();
        // Drain a few events with a timeout so the test can't hang.
        for _ in 0..10 {
            match tokio::time::timeout(Duration::from_secs(5), sess.recv()).await {
                Ok(Some(SshEvent::Data(d))) => {
                    let s = String::from_utf8_lossy(&d);
                    if s.contains("ready>") {
                        saw_ready = true;
                    }
                    if s.contains("echo:hi") {
                        saw_echo = true;
                        break;
                    }
                }
                Ok(Some(_)) => {}
                Ok(None) | Err(_) => break,
            }
        }
        assert!(saw_ready, "expected shell greeting");
        assert!(saw_echo, "expected echoed input");
        sess.close().await.unwrap();
    }

    // A wrong pin must be refused (MITM defense): connect with a pin that does not
    // match the server's real host key ⟹ handshake fails.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn wrong_pin_is_refused() {
        use russh::server::{self, Auth, Msg, Server as _, Session};
        use russh::{Channel, ChannelId};

        let host_key = gen_ed25519();
        let dir = tempdir().unwrap();
        let client_key = MeshSshKey::load_or_generate(&dir.path().join("k")).unwrap();

        #[derive(Clone)]
        struct Srv;
        impl server::Server for Srv {
            type Handler = SrvH;
            fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> SrvH {
                SrvH
            }
        }
        struct SrvH;
        impl server::Handler for SrvH {
            type Error = russh::Error;
            async fn auth_publickey(
                &mut self,
                _u: &str,
                _k: &PublicKey,
            ) -> Result<Auth, Self::Error> {
                Ok(Auth::Accept)
            }
            async fn channel_open_session(
                &mut self,
                _c: Channel<Msg>,
                reply: server::ChannelOpenHandle,
                _s: &mut Session,
            ) -> Result<(), Self::Error> {
                reply.accept().await;
                Ok(())
            }
            #[allow(unused_variables)]
            async fn shell_request(
                &mut self,
                channel: ChannelId,
                session: &mut Session,
            ) -> Result<(), Self::Error> {
                Ok(())
            }
        }

        let config = Arc::new(server::Config {
            keys: vec![host_key],
            ..Default::default()
        });
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let mut srv = Srv;
            let _ = srv.run_on_socket(config, &listener).await;
        });

        // Pin a DIFFERENT key than the server actually presents.
        let wrong = gen_ed25519().public_key().to_openssh().unwrap();
        let mut opts = SshConnectOptions::new(addr.ip().to_string(), "ankayma");
        opts.port = addr.port();
        opts.expected_host_key = Some(wrong);
        let res = SshSession::connect(&opts, &client_key).await;
        assert!(res.is_err(), "wrong host-key pin must be refused");
    }
}
