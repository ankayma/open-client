//! ssh_server — F-2 NoKeySSH embedded server (Part D f2 §H.1, deviation v0.5).
//!
//! Intensity: **Critical** (CLAUDE.md T/A §) — crypto/transport + privilege on a
//! security path.
//!
//! The agent runs its OWN SSH server (russh) bound to the mesh overlay only — it
//! does NOT use the node's system `sshd`, never writes `authorized_keys`, never
//! mutates the node's config. A connecting device authenticates with its enrolled
//! ed25519 mesh-SSH key (A.1.3); it lands a shell as the shared unprivileged POSIX
//! user `ankayma` (§H.5), which the agent provisions itself (Linux useradd / macOS
//! sysadminctl, no password → no password login). Root is a *separate* step (Lát 3
//! elevation), never the landing. `[T:russh@0.62]` `[T:portable-pty@0.9]`
//!
//! Identity gate `[A-c §H.1]`: reaching the overlay port already proves the peer is
//! enrolled + same-owner (the WireGuard overlay + roster `allow-within-owner` is
//! the real gate). So at F0 the SSH layer records the offered key for the audit trail
//! and accepts ([`Authorizer::TrustOverlay`]); F1 tightens to a device allowlist
//! ([`Authorizer::Allowlist`]) once the control plane distributes per-device SSH
//! pubkeys in the roster.

use std::collections::HashSet;
use std::io::{Read, Write};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use portable_pty::{native_pty_system, Child, CommandBuilder, MasterPty, PtySize};
use russh::keys::{PrivateKey, PublicKey};
use russh::server::{self, Auth, Msg, Server as _, Session};
use russh::{Channel, ChannelId};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

use crate::ssh_grant::{ElevationGrant, GrantVerifier};

/// The SSH env var the client sets (via `set_env`) to carry a CP-signed elevation
/// grant. `[T:f2 §H.4]`
pub const ELEVATE_GRANT_ENV: &str = "ANKAYMA_ELEVATE_GRANT";

/// The node's persistent SSH host identity (ed25519). Generated once, stored 0600.
/// Its public half is what the control plane hands clients to PIN (A.1.3) — so a
/// client can tell it's really talking to this node's agent, not a MITM.
pub struct SshHostKey(PrivateKey);

impl SshHostKey {
    /// Load the host key from `path`, generating + persisting a fresh ed25519 key
    /// on first use. OpenSSH PEM, mode 0600. `[T:A.1.21]`
    pub fn load_or_generate(path: &Path) -> Result<Self> {
        if let Ok(pem) = std::fs::read_to_string(path) {
            let key = PrivateKey::from_openssh(pem.trim())
                .map_err(|e| anyhow!("parse ssh host key {}: {e}", path.display()))?;
            return Ok(Self(key));
        }
        use rand::RngCore;
        let mut seed = [0u8; 32];
        rand::rng().fill_bytes(&mut seed);
        let key = PrivateKey::from(russh::keys::ssh_key::private::Ed25519Keypair::from_seed(
            &seed,
        ));
        seed.fill(0);
        let pem = key
            .to_openssh(russh::keys::ssh_key::LineEnding::LF)
            .map_err(|e| anyhow!("encode ssh host key: {e}"))?;
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).ok();
        }
        std::fs::write(path, pem.as_bytes())
            .with_context(|| format!("write {}", path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).ok();
        }
        Ok(Self(key))
    }

    /// The host public key (OpenSSH one-line) — the pin the CP distributes.
    pub fn public_openssh(&self) -> Result<String> {
        self.0
            .public_key()
            .to_openssh()
            .map_err(|e| anyhow!("encode ssh host pubkey: {e}"))
    }
}

/// Who may authenticate to the embedded server.
#[derive(Clone)]
pub enum Authorizer {
    /// F0: accept any offered key (the overlay + roster already authenticated the
    /// peer) and record it for audit. `[A-c §H.1]`
    TrustOverlay,
    /// F1: only these OpenSSH pubkeys (same-owner device allowlist).
    Allowlist(HashSet<String>),
}

impl Authorizer {
    fn allows(&self, offered_openssh: &str) -> bool {
        match self {
            Authorizer::TrustOverlay => true,
            Authorizer::Allowlist(set) => set.contains(offered_openssh),
        }
    }
}

/// What to run when a shell is requested.
#[derive(Clone)]
pub enum ShellSpec {
    /// Land the shared POSIX user's login shell, provisioning the account if it is
    /// missing (Linux via useradd, macOS via sysadminctl). If the agent is already
    /// running AS that user (dev), spawns a login shell directly instead of `su`.
    LoginShell(String),
    /// A fixed program (tests / non-interactive). argv[0] is the program.
    Program(Vec<String>),
}

/// Embedded-server configuration.
pub struct SshServerConfig {
    /// Overlay address to bind — NEVER 0.0.0.0. The listener is reachable only over
    /// the mesh. `[T:A.1.6]`
    pub bind_ip: String,
    /// Port (default 22022).
    pub port: u16,
    /// Who may authenticate.
    pub authorizer: Authorizer,
    /// What a shell request spawns.
    pub shell: ShellSpec,
    /// Verifier for root-elevation grants (§H.4). `None` → elevation unavailable on
    /// this node (a client that presents a grant just lands unprivileged). Set once
    /// the agent has fetched the CP's elevation public key. `[T:f2 §H.4]`
    pub elevate: Option<GrantVerifier>,
}

impl SshServerConfig {
    /// F0 defaults: shared user `ankayma`, overlay-trust, port 22022, no elevation
    /// until a CP key is wired in via [`with_elevation`].
    pub fn f0(bind_ip: impl Into<String>) -> Self {
        Self {
            bind_ip: bind_ip.into(),
            port: 22022,
            authorizer: Authorizer::TrustOverlay,
            shell: ShellSpec::LoginShell("ankayma".to_string()),
            elevate: None,
        }
    }

    /// Enable root elevation on this node using the CP's elevation verifier.
    pub fn with_elevation(mut self, verifier: GrantVerifier) -> Self {
        self.elevate = Some(verifier);
        self
    }
}

/// The outcome of evaluating a presented grant, kept pure so it is unit-testable
/// without root or a real PTY.
#[derive(Debug)]
pub enum ElevationDecision {
    /// No grant presented (or no verifier configured) → land unprivileged.
    None,
    /// A valid grant → elevate to root; carries the validated grant.
    Granted(Box<ElevationGrant>),
    /// A grant was presented but rejected (expired/forged/wrong-node) → fail SAFE:
    /// land unprivileged, and log why.
    Denied(String),
}

/// Decide whether to elevate, given the (optional) verifier and presented grant.
/// Fail-safe: any problem denies elevation rather than granting it.
pub fn decide_elevation(
    verifier: Option<&GrantVerifier>,
    presented: Option<&str>,
    now: i64,
) -> ElevationDecision {
    match (verifier, presented) {
        (Some(v), Some(token)) => match v.verify(token, now) {
            Ok(grant) => ElevationDecision::Granted(Box::new(grant)),
            Err(e) => ElevationDecision::Denied(e.to_string()),
        },
        _ => ElevationDecision::None,
    }
}

/// Bind + serve the embedded SSH server on the configured overlay address. Runs
/// until the listener errors or the task is aborted.
pub async fn serve(cfg: SshServerConfig, host_key: SshHostKey) -> Result<()> {
    let listener = TcpListener::bind((cfg.bind_ip.as_str(), cfg.port))
        .await
        .with_context(|| format!("bind ssh server {}:{}", cfg.bind_ip, cfg.port))?;
    serve_on(listener, cfg, host_key).await
}

/// Serve on an already-bound listener (used by tests to grab an ephemeral port).
pub async fn serve_on(
    listener: TcpListener,
    cfg: SshServerConfig,
    host_key: SshHostKey,
) -> Result<()> {
    let config = Arc::new(server::Config {
        inactivity_timeout: Some(Duration::from_secs(3600)),
        auth_rejection_time: Duration::from_secs(2),
        keys: vec![host_key.0],
        ..Default::default()
    });
    let mut listener_srv = Listener {
        authorizer: Arc::new(cfg.authorizer),
        shell: cfg.shell,
        elevate: cfg.elevate.map(Arc::new),
    };
    listener_srv
        .run_on_socket(config, &listener)
        .await
        .map_err(|e| anyhow!("ssh server run: {e}"))
}

/// Per-listener factory: makes one [`ConnHandler`] per accepted connection.
struct Listener {
    authorizer: Arc<Authorizer>,
    shell: ShellSpec,
    elevate: Option<Arc<GrantVerifier>>,
}

impl server::Server for Listener {
    type Handler = ConnHandler;
    fn new_client(&mut self, _peer: Option<std::net::SocketAddr>) -> ConnHandler {
        ConnHandler {
            authorizer: self.authorizer.clone(),
            shell: self.shell.clone(),
            elevate: self.elevate.clone(),
            pending_grant: None,
            term: "xterm".to_string(),
            size: PtySize::default(),
            writer: None,
            master: None,
            child: None,
            authed_key: None,
        }
    }
    fn handle_session_error(&mut self, error: <ConnHandler as server::Handler>::Error) {
        eprintln!("[ssh] session error: {error:?}");
    }
}

/// Per-connection handler: verifies the key, tracks the requested PTY, and on a
/// shell request spawns a real PTY running the shared user's shell, bridging the
/// PTY master ↔ the SSH channel.
struct ConnHandler {
    authorizer: Arc<Authorizer>,
    shell: ShellSpec,
    elevate: Option<Arc<GrantVerifier>>,
    /// The grant token the client set via env, awaiting verification at shell time.
    pending_grant: Option<String>,
    term: String,
    size: PtySize,
    writer: Option<Box<dyn Write + Send>>,
    master: Option<Box<dyn MasterPty + Send>>,
    child: Option<Box<dyn Child + Send + Sync>>,
    authed_key: Option<String>,
}

impl ConnHandler {
    /// Build the command a shell request spawns. `elevated` switches the shared
    /// user for root (the agent already runs as root, so root's shell is spawned
    /// directly — no sudoers, no password; §H.4).
    fn build_command(&self, elevated: bool) -> Result<CommandBuilder> {
        if elevated {
            // Root PTY: the agent's euid is already 0, so a login shell runs as
            // root. Set HOME/USER so it's a proper root environment.
            let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/bash".to_string());
            let mut c = CommandBuilder::new(shell);
            c.arg("-l");
            c.env("TERM", &self.term);
            c.env("HOME", "/root");
            c.env("USER", "root");
            c.env("LOGNAME", "root");
            return Ok(c);
        }
        match &self.shell {
            ShellSpec::Program(argv) => {
                let mut c = CommandBuilder::new(&argv[0]);
                for a in &argv[1..] {
                    c.arg(a);
                }
                c.env("TERM", &self.term);
                Ok(c)
            }
            ShellSpec::LoginShell(user) => {
                // geteuid() is POSIX-only. On Windows the embedded server's user
                // landing (su/provision below) is out of scope for now (the Windows
                // build targets the CLIENT path first) — fall to the current-user
                // shell. [T:gate A.0-a windows-compat]
                #[cfg(unix)]
                let am_root = unsafe { libc::geteuid() } == 0;
                #[cfg(not(unix))]
                let am_root = false;
                let already_user = current_username().as_deref() == Some(user.as_str());
                let mut c = if am_root && !already_user {
                    // Landing a DIFFERENT user → provision if needed, then `su -`
                    // to get their login shell. Password stays locked (§H.5).
                    ensure_user_provisioned(user)?;
                    let mut c = CommandBuilder::new("su");
                    c.arg("-");
                    c.arg(user);
                    c
                } else {
                    // Already this user (dev/dogfood) → login shell directly.
                    let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string());
                    let mut c = CommandBuilder::new(shell);
                    c.arg("-l");
                    c
                };
                c.env("TERM", &self.term);
                Ok(c)
            }
        }
    }
}

impl Drop for ConnHandler {
    fn drop(&mut self) {
        // Don't leave an orphaned shell if the connection drops.
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
        }
    }
}

impl server::Handler for ConnHandler {
    type Error = russh::Error;

    async fn auth_publickey(&mut self, _user: &str, key: &PublicKey) -> Result<Auth, Self::Error> {
        let offered = key.to_openssh().unwrap_or_default();
        if self.authorizer.allows(&offered) {
            self.authed_key = Some(offered);
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

    async fn pty_request(
        &mut self,
        _channel: ChannelId,
        term: &str,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        _modes: &[(russh::Pty, u32)],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.term = if term.is_empty() {
            "xterm".to_string()
        } else {
            term.to_string()
        };
        self.size = PtySize {
            rows: row_height as u16,
            cols: col_width as u16,
            pixel_width: pix_width as u16,
            pixel_height: pix_height as u16,
        };
        Ok(())
    }

    async fn env_request(
        &mut self,
        _channel: ChannelId,
        variable_name: &str,
        variable_value: &str,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        // Capture ONLY the elevation grant var; ignore all other env (don't let a
        // client set arbitrary environment into the spawned shell).
        if variable_name == ELEVATE_GRANT_ENV {
            self.pending_grant = Some(variable_value.to_string());
        }
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        // Decide elevation from the presented grant (fail-safe: any problem lands
        // unprivileged). `[T:f2 §H.4]`
        let decision = decide_elevation(
            self.elevate.as_deref(),
            self.pending_grant.as_deref(),
            unix_now(),
        );
        let mut elevate_deadline: Option<i64> = None;
        let elevated = match &decision {
            ElevationDecision::Granted(g) => {
                audit_elevation(g, self.authed_key.as_deref());
                elevate_deadline = Some(g.expires_at);
                true
            }
            ElevationDecision::Denied(reason) => {
                eprintln!("[F-2] elevation denied, landing unprivileged: {reason}");
                false
            }
            ElevationDecision::None => false,
        };

        let cmd = self
            .build_command(elevated)
            .map_err(|e| russh::Error::from(std::io::Error::other(e.to_string())))?;

        let pair = native_pty_system()
            .openpty(self.size)
            .map_err(|e| russh::Error::from(std::io::Error::other(e.to_string())))?;
        let child = pair
            .slave
            .spawn_command(cmd)
            .map_err(|e| russh::Error::from(std::io::Error::other(e.to_string())))?;
        // Parent doesn't need the slave end once the child holds it.
        drop(pair.slave);

        // [F-2 §H.4] Auto-drop: an elevated (root) shell is killed at the grant's
        // expiry (TTL ≤15', A.1.7) — root never outlives the grant.
        if let Some(deadline) = elevate_deadline {
            let mut killer = child.clone_killer();
            let handle = session.handle();
            tokio::spawn(async move {
                let secs = deadline.saturating_sub(unix_now()).max(0) as u64;
                tokio::time::sleep(Duration::from_secs(secs)).await;
                let _ = killer.kill();
                let _ = handle.eof(channel).await;
                let _ = handle.close(channel).await;
            });
        }

        let reader = pair
            .master
            .try_clone_reader()
            .map_err(|e| russh::Error::from(std::io::Error::other(e.to_string())))?;
        let writer = pair
            .master
            .take_writer()
            .map_err(|e| russh::Error::from(std::io::Error::other(e.to_string())))?;
        self.writer = Some(writer);
        self.master = Some(pair.master);
        self.child = Some(child);

        // Bridge PTY master → SSH channel. The PTY reader is blocking, so an OS
        // thread drains it into an mpsc; a tokio task forwards to the channel.
        let handle = session.handle();
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(64);
        std::thread::spawn(move || {
            let mut reader = reader;
            let mut buf = [0u8; 8192];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if tx.blocking_send(buf[..n].to_vec()).is_err() {
                            break;
                        }
                    }
                }
            }
        });
        tokio::spawn(async move {
            while let Some(chunk) = rx.recv().await {
                if handle.data(channel, chunk).await.is_err() {
                    break;
                }
            }
            // Shell ended (EOF on the PTY): tell the client and close.
            let _ = handle.eof(channel).await;
            let _ = handle.exit_status_request(channel, 0).await;
            let _ = handle.close(channel).await;
        });
        Ok(())
    }

    async fn data(
        &mut self,
        _channel: ChannelId,
        data: &[u8],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        // Client keystrokes → PTY master. Small writes; blocking is negligible.
        if let Some(w) = self.writer.as_mut() {
            let _ = w.write_all(data);
            let _ = w.flush();
        }
        Ok(())
    }

    async fn window_change_request(
        &mut self,
        _channel: ChannelId,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(m) = self.master.as_ref() {
            let _ = m.resize(PtySize {
                rows: row_height as u16,
                cols: col_width as u16,
                pixel_width: pix_width as u16,
                pixel_height: pix_height as u16,
            });
        }
        Ok(())
    }
}

/// The euid's login name (env-based; good enough to decide "am I already this
/// user" in dev). Production landing runs as root and uses `su`.
fn current_username() -> Option<String> {
    std::env::var("USER")
        .ok()
        .or_else(|| std::env::var("LOGNAME").ok())
}

/// Current unix time in seconds.
fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Per-operation audit line for a granted elevation (§H.4 requires a per-op log;
/// full auditd/eBPF is `[A]` later). Written to stderr AND best-effort appended to
/// `~/.ankayma/ssh-elevations.log` — connection-level only (who/when/which grant),
/// never the session content (A.1.1/A.1.8).
fn audit_elevation(grant: &ElevationGrant, device_key: Option<&str>) {
    let line = format!(
        "elevation granted session={} node={} persona={} login={} expires_at={} device={}",
        grant.session_id,
        grant.node_id,
        grant.persona,
        grant.login,
        grant.expires_at,
        device_key.unwrap_or("?"),
    );
    eprintln!("[F-2 audit] {line}");
    if let Ok(home) = std::env::var("HOME") {
        let path = std::path::Path::new(&home)
            .join(".ankayma")
            .join("ssh-elevations.log");
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
        {
            let _ = writeln!(f, "{} {line}", unix_now());
        }
    }
}

/// Ensure the shared POSIX user exists (Linux). Idempotent; creates a home dir,
/// sets a shell, and LOCKS the password so no password login is possible — SSH is
/// key/identity-only (§H.5). Must run as root. `[T:useradd(8)+passwd(1)]`
#[cfg(target_os = "linux")]
fn ensure_user_provisioned(user: &str) -> Result<()> {
    if user_exists(user) {
        return Ok(());
    }
    run_cmd("useradd", &["-m", "-s", "/bin/bash", user])
        .with_context(|| format!("provision user {user}"))?;
    // Lock the password: `!` in shadow → password auth can never succeed.
    run_cmd("passwd", &["-l", user]).with_context(|| format!("lock password for {user}"))?;
    Ok(())
}

/// Ensure the shared POSIX user exists (macOS, Lát 5). Idempotent. `sysadminctl`
/// auto-assigns a free UID and creates the home dir; we set NO password, so there
/// is no password login (§H.5) — root `su - <user>` needs none. Must run as root
/// (the agent already does, for the utun). `[T:sysadminctl(8)]`
#[cfg(target_os = "macos")]
fn ensure_user_provisioned(user: &str) -> Result<()> {
    if user_exists(user) {
        return Ok(());
    }
    run_cmd(
        "sysadminctl",
        &[
            "-addUser",
            user,
            "-fullName",
            "Ankayma",
            "-shell",
            "/bin/zsh",
        ],
    )
    .with_context(|| format!("provision user {user}"))?;
    // sysadminctl has historically returned 0 even on some failures — confirm.
    if !user_exists(user) {
        return Err(anyhow!("sysadminctl did not create user {user}"));
    }
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn ensure_user_provisioned(_user: &str) -> Result<()> {
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn user_exists(user: &str) -> bool {
    std::process::Command::new("id")
        .arg("-u")
        .arg(user)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn run_cmd(prog: &str, args: &[&str]) -> Result<()> {
    let status = std::process::Command::new(prog)
        .args(args)
        .status()
        .with_context(|| format!("spawn {prog}"))?;
    if !status.success() {
        return Err(anyhow!("{prog} exited with {status}"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssh_client::{MeshSshKey, SshConnectOptions, SshEvent, SshSession};
    use tempfile::tempdir;

    fn gen_host_key(dir: &Path) -> SshHostKey {
        SshHostKey::load_or_generate(&dir.join("host")).unwrap()
    }

    #[test]
    fn host_key_persists() {
        let dir = tempdir().unwrap();
        let k1 = gen_host_key(dir.path());
        let p1 = k1.public_openssh().unwrap();
        assert!(p1.starts_with("ssh-ed25519 "));
        let k2 = gen_host_key(dir.path());
        assert_eq!(p1, k2.public_openssh().unwrap());
    }

    #[test]
    fn elevation_decision_granted_denied_none() {
        use crate::ssh_grant::{ElevationGrant, GrantSigner, GrantVerifier};
        let signer = GrantSigner::from_seed(&[3u8; 32]);
        let verifier = GrantVerifier::new(&signer.public_base64(), "node_9").unwrap();
        let g = ElevationGrant {
            node_id: "node_9".to_string(),
            persona: "root".to_string(),
            login: "root".to_string(),
            device_fp: "SHA256:x".to_string(),
            session_id: "e1".to_string(),
            issued_at: 1000,
            expires_at: 1300,
        };
        let token = signer.sign(&g).unwrap();

        // Valid grant → Granted.
        assert!(matches!(
            decide_elevation(Some(&verifier), Some(&token), 1100),
            ElevationDecision::Granted(_)
        ));
        // Expired grant → Denied (fail-safe, not Granted).
        assert!(matches!(
            decide_elevation(Some(&verifier), Some(&token), 9999),
            ElevationDecision::Denied(_)
        ));
        // No grant presented → None.
        assert!(matches!(
            decide_elevation(Some(&verifier), None, 1100),
            ElevationDecision::None
        ));
        // Grant presented but node has no verifier configured → None (elevation off).
        assert!(matches!(
            decide_elevation(None, Some(&token), 1100),
            ElevationDecision::None
        ));
    }

    #[test]
    fn allowlist_authorizer() {
        let mut set = HashSet::new();
        set.insert("ssh-ed25519 AAAA... a".to_string());
        let a = Authorizer::Allowlist(set);
        assert!(a.allows("ssh-ed25519 AAAA... a"));
        assert!(!a.allows("ssh-ed25519 BBBB... b"));
        assert!(Authorizer::TrustOverlay.allows("anything"));
    }

    // End-to-end: the real client engine (Lát 1) connects to the embedded server,
    // which spawns `/bin/cat` in a PTY. A PTY echoes its input, so writing "ping\n"
    // must come back. Proves auth + pty_request + shell_request + the master↔channel
    // bridge, without needing root or a provisioned user.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn client_engine_talks_to_embedded_server() {
        let dir = tempdir().unwrap();
        let host_key = gen_host_key(dir.path());
        let host_pub = host_key.public_openssh().unwrap();
        let client_key = MeshSshKey::load_or_generate(&dir.path().join("client")).unwrap();

        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let cfg = SshServerConfig {
            bind_ip: "127.0.0.1".to_string(),
            port: addr.port(),
            authorizer: Authorizer::TrustOverlay,
            shell: ShellSpec::Program(vec!["/bin/cat".to_string()]),
            elevate: None,
        };
        tokio::spawn(async move {
            let _ = serve_on(listener, cfg, host_key).await;
        });

        let mut opts = SshConnectOptions::new("127.0.0.1", "ankayma");
        opts.port = addr.port();
        opts.expected_host_key = Some(host_pub);
        let mut sess = SshSession::connect(&opts, &client_key)
            .await
            .expect("client should connect + auth to embedded server");

        sess.write(b"ping\n").await.unwrap();
        let mut echoed = false;
        for _ in 0..20 {
            match tokio::time::timeout(Duration::from_secs(5), sess.recv()).await {
                Ok(Some(SshEvent::Data(d))) => {
                    if String::from_utf8_lossy(&d).contains("ping") {
                        echoed = true;
                        break;
                    }
                }
                Ok(Some(_)) => {}
                Ok(None) | Err(_) => break,
            }
        }
        assert!(echoed, "PTY should echo the input back through the channel");
        sess.close().await.unwrap();
    }
}
