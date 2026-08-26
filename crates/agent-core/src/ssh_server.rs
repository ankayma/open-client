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

use crate::cmd_grant::{CommandGrantVerifier, Refusal, CMD_GRANT_ENV};
use crate::exec_outcome::{ExecOutcome, OutcomeQueue};
use crate::session_grant::{SessionGrantVerifier, SESSION_GRANT_ENV};

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
///
/// `TrustOverlay` accepts any offered key on the premise that the overlay plus
/// `list_peers` already decided who may reach this port — the roster the control plane
/// hands back must be scoped to the caller. That scoping is enforced control-plane side;
/// this authorizer has no way to check it itself, only to rely on it. `[A — verify: the
/// roster this node receives is scoped to its own tenant]`
///
/// `Allowlist` is the defence-in-depth that would stop depending on that premise, and it
/// is **not reachable yet: nothing distributes per-device SSH public keys.** The client
/// authenticates with an in-memory keypair that is never persisted and never registered,
/// so there is currently no key material to put on a list. Wiring it needs the control
/// plane to carry SSH pubkeys in the roster. `[A — blocked on roster key distribution]`
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
    /// Verifier for COMMAND grants. `None` → this node cannot enforce them,
    /// and the control plane will not issue one to it: absent capability means "has not
    /// said", which is not "yes". `[T:A.1.20 capability negotiation + A.1.6 fail-closed]`
    pub cmd_grant: Option<CommandGrantVerifier>,
    /// Verifier for AGENT-SESSION grants. `None` → this node cannot accept
    /// one, and a client that presents `ANKAYMA_SESSION_GRANT` anyway is refused rather
    /// than silently falling back to `authorizer`'s ordinary check — a token this node
    /// cannot verify is not evidence the control plane ever meant to let it in.
    /// `[T:A.1.6 fail-closed]` Only consulted when the connecting client actually sets
    /// the env var; a human's own `agent ssh <node>` never does, so that path is
    /// unaffected by whether this is configured at all.
    pub session_grant: Option<SessionGrantVerifier>,
    /// Where outcomes of command grants are queued for delivery. Shared with whatever
    /// drains it — the ssh server observes, it does not talk to the control plane.
    pub outcomes: Option<OutcomeQueue>,
    /// This node's own id, so an outcome can name WHICH enforcement point measured it.
    pub node_id: Option<String>,
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
            cmd_grant: None,
            session_grant: None,
            outcomes: None,
            node_id: None,
        }
    }

    /// Enable command grants on this node. Until this is set the node runs the legacy
    /// exec path, which is exactly why the control plane refuses to issue it a command
    /// grant — a node that cannot compare a digest would record an enforcement it did not
    /// perform. `[T:A.1.20 capability negotiation + A.1.6 fail-closed]`
    pub fn with_command_grants(mut self, verifier: CommandGrantVerifier) -> Self {
        self.cmd_grant = Some(verifier);
        self
    }

    /// Enable agent-session grants on this node. Same fail-closed reasoning
    /// as `with_command_grants`: until this is set, the control plane refuses to mint a
    /// session grant scoped to this node at all (R-1 shape).
    pub fn with_session_grants(mut self, verifier: SessionGrantVerifier) -> Self {
        self.session_grant = Some(verifier);
        self
    }

    /// Where to queue the outcome of every command grant, and the node id to attribute
    /// the measurement to.
    pub fn reporting_to(mut self, outcomes: OutcomeQueue, node_id: impl Into<String>) -> Self {
        self.outcomes = Some(outcomes);
        self.node_id = Some(node_id.into());
        self
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

/// Windows-only preflight: probe whether ConPTY (`CreatePseudoConsole`) actually
/// works on this host before claiming the embedded SSH server is up. `portable-pty`'s
/// Windows backend requires it — Windows 10 1809 (build 17763) / Windows Server
/// 2019+, per `[T:f2 §H.6.1]`. Without this, an older
/// host's failure only surfaces deep inside the first incoming connection's
/// `openpty()` call as a cryptic error; this turns it into one clear line at
/// startup. Feature-probing the real API is deliberately preferred over reading a
/// build number: `GetVersionEx`-family calls lie to processes without an OS-support
/// manifest entry, so a version check can be wrong in exactly the cases that matter.
/// `[A — inferred from ConPTY's documented minimum OS version; no Windows host was
/// available in this session to verify the exact old-OS failure mode]`
#[cfg(windows)]
pub fn windows_conpty_available() -> Result<()> {
    native_pty_system()
        .openpty(PtySize::default())
        .map(|_| ())
        .map_err(|e| {
            anyhow!(
                "ConPTY unavailable ({e}) — the embedded SSH server needs Windows 10 1809+ \
                 or Windows Server 2019+; this host is likely older"
            )
        })
}

/// `true` if this process's `USERNAME` environment variable is `SYSTEM` — what
/// Windows sets for a process running under the `LocalSystem` account (e.g. a
/// Windows Service registered `obj= LocalSystem`, as the headless-server service in
/// `win_service_headless.rs` is). The embedded server currently lands an SSH client
/// in the shell of whoever is RUNNING the agent (§H.5 — no per-user `su`-equivalent
/// on Windows yet), so a LocalSystem agent means SSH lands `NT AUTHORITY\SYSTEM`'s
/// shell — more powerful than a normal admin. `[T:f2 §H.6.1]`
///
/// A heuristic, not a hard security boundary: an operator could unset/override
/// `USERNAME`. Its job is catching the DEFAULT, unintentional case — a headless
/// service silently exposing a SYSTEM shell over SSH — not resisting an adversary
/// who already has SYSTEM (who has no need to go through SSH to get there). The
/// hard-boundary version (`OpenProcessToken`/`GetTokenInformation(TokenUser)`/
/// `EqualSid` against the well-known LocalSystem SID) was deliberately not written:
/// it could not be compiled or run against a real Windows host in this session, and
/// subtly-wrong raw SID FFI failing silently would be worse than this simpler,
/// by-inspection-correct check. `[A]`
#[cfg(windows)]
pub fn windows_running_as_system() -> bool {
    std::env::var("USERNAME")
        .map(|u| u.eq_ignore_ascii_case("SYSTEM"))
        .unwrap_or(false)
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
        cmd_grant: cfg.cmd_grant.map(Arc::new),
        session_grant: cfg.session_grant.map(Arc::new),
        outcomes: cfg.outcomes,
        node_id: cfg.node_id,
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
    cmd_grant: Option<Arc<CommandGrantVerifier>>,
    session_grant: Option<Arc<SessionGrantVerifier>>,
    outcomes: Option<OutcomeQueue>,
    node_id: Option<String>,
}

impl server::Server for Listener {
    type Handler = ConnHandler;
    fn new_client(&mut self, _peer: Option<std::net::SocketAddr>) -> ConnHandler {
        ConnHandler {
            authorizer: self.authorizer.clone(),
            shell: self.shell.clone(),
            elevate: self.elevate.clone(),
            cmd_grant: self.cmd_grant.clone(),
            session_grant: self.session_grant.clone(),
            outcomes: self.outcomes.clone(),
            node_id: self.node_id.clone(),
            pending_grant: None,
            pending_cmd_grant: None,
            pending_session_grant: None,
            active_grant: None,
            last_refusal: None,
            term: "xterm".to_string(),
            size: PtySize::default(),
            writer: None,
            master: None,
            child: None,
            authed_key: None,
            exec_child: None,
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
    cmd_grant: Option<Arc<CommandGrantVerifier>>,
    session_grant: Option<Arc<SessionGrantVerifier>>,
    outcomes: Option<OutcomeQueue>,
    node_id: Option<String>,
    /// The grant token the client set via env, awaiting verification at shell time.
    pending_grant: Option<String>,
    /// A COMMAND grant token set via env. Its presence changes what this channel is
    /// allowed to be: one authorised command, never a session.
    pending_cmd_grant: Option<String>,
    /// An AGENT-SESSION grant token set via env. Present only when the connecting
    /// client is an agent identity, not a human's own device — checked once, before
    /// either `shell_request` or `exec_request` does anything else.
    pending_session_grant: Option<String>,
    /// The verified grant this channel is executing under, kept so the outcome can name
    /// the grant it belongs to.
    active_grant: Option<crate::cmd_grant::CommandGrant>,
    /// Why a command was refused, if it was. Reported rather than discarded — the control
    /// plane records `rejected_digest_mismatch` as evidence, and a refusal nobody hears
    /// about is a refusal that did not happen as far as the ledger knows.
    last_refusal: Option<Refusal>,
    term: String,
    size: PtySize,
    writer: Option<Box<dyn Write + Send>>,
    master: Option<Box<dyn MasterPty + Send>>,
    child: Option<Box<dyn Child + Send + Sync>>,
    authed_key: Option<String>,
    /// [T:ci-deploy exec] A non-interactive `exec_request` child (no PTY — batch
    /// commands don't need a terminal). Separate from `child` (the PTY-shell case
    /// above) because `portable_pty::Child` and `std::process::Child` are
    /// different types; keeping them apart avoids forcing one path to fake the
    /// other's shape.
    exec_child: Option<std::process::Child>,
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
                    // Already this user (dev/dogfood) → login shell directly. On
                    // Windows there is no `su`/login-shell here; land the current
                    // user's shell (ComSpec/cmd.exe) over ConPTY — `-l` is POSIX-only
                    // and `/bin/sh` does not exist. [T:gate A.0-a windows-compat]
                    #[cfg(windows)]
                    {
                        // PowerShell by default (richer UX than cmd.exe); override via
                        // ANKAYMA_SHELL. PowerShell ships on every Win10/11.
                        // [T:gate A.0-a windows-compat]
                        let shell = std::env::var("ANKAYMA_SHELL")
                            .unwrap_or_else(|_| "powershell.exe".to_string());
                        CommandBuilder::new(shell)
                    }
                    #[cfg(not(windows))]
                    {
                        let shell =
                            std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string());
                        let mut c = CommandBuilder::new(shell);
                        c.arg("-l");
                        c
                    }
                };
                c.env("TERM", &self.term);
                Ok(c)
            }
        }
    }

    /// [T:ci-deploy exec] Same elevation/landing-user rules as [`build_command`],
    /// but for a single non-interactive command instead of a login shell — used
    /// by `exec_request`. Returns `None` when the server is locked to a forced
    /// program (`ShellSpec::Program`): overriding a forced command with an
    /// arbitrary exec string would defeat the point of that mode, so exec is
    /// refused there rather than silently running the wrong thing.
    fn resolve_exec_command(
        &self,
        elevated: bool,
        exec_cmd: &str,
    ) -> Option<std::process::Command> {
        if elevated {
            // Agent's euid is already 0 (§H.4) — run the command directly as root.
            let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/bash".to_string());
            let mut c = std::process::Command::new(shell);
            c.arg("-c").arg(exec_cmd);
            c.env("HOME", "/root")
                .env("USER", "root")
                .env("LOGNAME", "root");
            return Some(c);
        }
        match &self.shell {
            ShellSpec::Program(_) => None,
            ShellSpec::LoginShell(user) => {
                #[cfg(unix)]
                let am_root = unsafe { libc::geteuid() } == 0;
                #[cfg(not(unix))]
                let am_root = false;
                let already_user = current_username().as_deref() == Some(user.as_str());
                let mut c = if am_root && !already_user {
                    // Provision the landing user first — the shell path does this
                    // (`build_command`) and exec must too. A node that has never
                    // served an interactive F-2 session has no `ankayma` user yet,
                    // and `agent ci-deploy` is exactly that case: CI is often the
                    // first thing to ever land on a fresh deploy target.
                    if let Err(e) = ensure_user_provisioned(user) {
                        eprintln!("[F-2] exec: provision user {user} failed: {e}");
                        return None;
                    }
                    // `su - user -c "<cmd>"` — same landing-user rule as the shell
                    // case, just non-interactive.
                    let mut c = std::process::Command::new("su");
                    c.arg("-").arg(user).arg("-c").arg(exec_cmd);
                    c
                } else {
                    #[cfg(windows)]
                    {
                        let shell = std::env::var("ANKAYMA_SHELL")
                            .unwrap_or_else(|_| "powershell.exe".to_string());
                        let mut c = std::process::Command::new(shell);
                        c.arg("-Command").arg(exec_cmd);
                        c
                    }
                    #[cfg(not(windows))]
                    {
                        let shell =
                            std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string());
                        let mut c = std::process::Command::new(shell);
                        c.arg("-c").arg(exec_cmd);
                        c
                    }
                };
                c.env("TERM", &self.term);
                Some(c)
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
        if let Some(mut child) = self.exec_child.take() {
            let _ = child.kill();
        }
    }
}

impl ConnHandler {
    /// Verify a presented agent-session grant, if one was set. Absent env var → true,
    /// no-op — a human's own connection never sets it, so this never touches that path.
    /// Present-but-unverifiable → the channel is failed here and the caller must stop,
    /// never fall through to `Authorizer`'s ordinary check: a token this node could not
    /// check is not evidence the control plane meant to let this connection in.
    /// `[T:A.1.6 fail-closed]`
    async fn admit_session_grant(&mut self, channel: ChannelId, session: &mut Session) -> bool {
        let Some(token) = self.pending_session_grant.clone() else {
            return true;
        };
        let Some(verifier) = self.session_grant.clone() else {
            eprintln!("[F-2] agent-session grant presented, but this node cannot verify one");
            let _ = session.channel_failure(channel);
            return false;
        };
        match verifier.verify(&token, unix_now()) {
            Ok(_grant) => true,
            Err(refusal) => {
                eprintln!("[F-2] refusing agent session: {}", refusal.message());
                let _ = session.channel_failure(channel);
                false
            }
        }
    }

    /// Run exactly the command a CP-signed grant authorises — or refuse, with a reason.
    ///
    /// The argv comes from the GRANT. The exec string the client sent is used for nothing
    /// but a mismatch note: a client that could supply the command would be a client that
    /// decides what runs, which is the property this whole path removes.
    ///
    /// Elevation is deliberately NOT consulted here. A command grant authorises one
    /// command as configured, and silently running it as root because an elevation grant
    /// happened to be in the same channel would be two authorisations combining into one
    /// nobody issued. `[T:A.1.27 #5 — intersection, not union]`
    /// Returns the command to run, or `None` when it was refused (the channel has already
    /// been failed by then).
    fn exec_under_command_grant(
        &mut self,
        channel: ChannelId,
        token: &str,
        requested: &str,
        session: &mut Session,
    ) -> Option<std::process::Command> {
        let Some(verifier) = self.cmd_grant.clone() else {
            // The node was handed a command grant it cannot check. Refusing is the only
            // honest answer: running it anyway would produce a ledger entry claiming an
            // enforcement that never happened. [T:A.1.20 capability negotiation + A.1.6 fail-closed]
            eprintln!("[F-2] command grant presented, but this node cannot verify one");
            let _ = session.channel_failure(channel);
            return None;
        };

        let grant = match verifier.verify(token, unix_now()) {
            Ok(g) => g,
            Err(refusal) => {
                // The reason is logged in the node's own words AND is what gets reported
                // to the control plane as `termination_reason`. A refusal is stronger
                // evidence than a permit, so it must not be lost.
                eprintln!(
                    "[F-2] refusing command: {} (reported as {})",
                    refusal.message(),
                    refusal.termination_reason()
                );
                // Reported, not just logged. A refusal is stronger evidence than a
                // permit, and one that never reaches the ledger did not happen as far as
                // the record is concerned. The grant id comes from the token's payload
                // even though the token was refused — a digest mismatch still names WHICH
                // grant was mismatched, which is the interesting part.
                if let (Some(q), Some(node)) = (self.outcomes.as_ref(), self.node_id.as_ref()) {
                    if let Some(id) = grant_id_of(token) {
                        q.push(ExecOutcome::refused(id, refusal.termination_reason(), node));
                    }
                }
                self.last_refusal = Some(refusal);
                let _ = session.channel_failure(channel);
                return None;
            }
        };

        if !grant.matches_requested(requested) {
            // Not fatal to the grant — the argv is authoritative either way — but a client
            // asking for something other than what it holds is worth seeing.
            eprintln!(
                "[F-2] client asked for a command other than the one it holds a grant for;                  running the authorised one"
            );
        }

        let cmd = grant.to_command();
        eprintln!(
            "[F-2] command grant {} actor={} digest={}",
            grant.grant_id, grant.actor_id, grant.cmd_digest
        );
        self.active_grant = Some(grant);
        Some(cmd)
    }

    /// Spawn a non-interactive child and bridge it to the channel.
    ///
    /// Shared by both exec paths so that the command-grant path and the legacy one differ
    /// in WHICH command runs and in nothing else — a second copy of the plumbing would be
    /// a second place for the two to drift.
    async fn spawn_exec(
        &mut self,
        channel: ChannelId,
        mut cmd: std::process::Command,
        elevate_deadline: Option<i64>,
        session: &mut Session,
    ) -> Result<(), russh::Error> {
        let child = cmd
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn();
        let mut child = match child {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[F-2] exec spawn failed: {e}");
                let _ = session.channel_failure(channel);
                return Ok(());
            }
        };
        let _ = session.channel_success(channel);

        // [F-2 §H.4] Same auto-drop as the shell path: an elevated exec is killed
        // at the grant's TTL rather than allowed to outlive it. The shell path
        // gets this for free from portable-pty's cross-platform `clone_killer()`;
        // this exec path spawns a bare `std::process::Child` (no PTY needed), so
        // it needs its own per-platform kill-by-pid.
        if let Some(deadline) = elevate_deadline {
            let secs = deadline.saturating_sub(unix_now()).max(0) as u64;
            let pid = child.id();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(secs)).await;
                kill_pid(pid);
            });
        }

        self.writer = child
            .stdin
            .take()
            .map(|s| Box::new(s) as Box<dyn Write + Send>);
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        self.exec_child = Some(child);

        // Bridge stdout+stderr → SSH channel (merged, matching how a PTY shell's
        // combined output already works for interactive users). One reader thread
        // per stream (both blocking `Read`s), one tokio task forwards to the
        // channel and waits for the process exit to report the REAL exit code —
        // unlike the shell path (always reports 0; a login shell's own exit code
        // isn't the thing being proven there).
        let handle = session.handle();
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(64);
        for mut stream in [
            stdout.map(|s| Box::new(s) as Box<dyn Read + Send>),
            stderr.map(|s| Box::new(s) as Box<dyn Read + Send>),
        ]
        .into_iter()
        .flatten()
        {
            let tx = tx.clone();
            std::thread::spawn(move || {
                let mut buf = [0u8; 8192];
                loop {
                    match stream.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if tx.blocking_send(buf[..n].to_vec()).is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
        drop(tx);

        let mut exec_child = self.exec_child.take();
        let outcomes = self.outcomes.clone();
        let node_id = self.node_id.clone();
        let grant_id = self.active_grant.as_ref().map(|g| g.grant_id.clone());
        tokio::spawn(async move {
            // Counted here because this is the only place the bytes pass through. The
            // control plane can never measure them (A.1.1), so a NULL on its side means
            // nobody did — which is why the count is attributed to this node by name.
            let mut bytes_out: usize = 0;
            while let Some(chunk) = rx.recv().await {
                bytes_out += chunk.len();
                if handle.data(channel, chunk).await.is_err() {
                    break;
                }
            }
            // Both stdout+stderr are EOF (both reader threads exited) — the
            // process is done or about to be; wait() to reap it and get the
            // real exit code (blocking `wait()` off the async runtime).
            let code = tokio::task::spawn_blocking(move || {
                exec_child
                    .as_mut()
                    .and_then(|c| c.wait().ok())
                    .and_then(|s| s.code())
                    .unwrap_or(1)
            })
            .await
            .unwrap_or(1);
            // The only observation of this execution that ever reaches the ledger. The
            // control plane is not on the data path (A.1.1), so if this is not reported
            // the grant closes as `outcome_unreported` — true, and less useful.
            if let (Some(q), Some(node), Some(id)) = (outcomes, node_id, grant_id) {
                if q.push(ExecOutcome::from_exit(id, code, &node, bytes_out as i64)) {
                    eprintln!(
                        "[F-2] outcome queue full — the oldest was dropped and will \
                         resolve as outcome_unreported"
                    );
                }
            }
            let _ = handle.eof(channel).await;
            let _ = handle.exit_status_request(channel, code as u32).await;
            let _ = handle.close(channel).await;
        });
        Ok(())
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
        // [T:A.1.7 — authority is bounded to what was issued] A command grant authorises ONE command. Allowing a PTY
        // under it would turn that into an interactive session with one line of client
        // code — the exact degradation `kind` exists to prevent. Refused before the
        // terminal is even recorded.
        if self.pending_cmd_grant.is_some() {
            eprintln!("[F-2] {}", Refusal::PtyRefused.message());
            return Err(russh::Error::Inconsistent);
        }
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
        // [T:P.4 — one channel, one parser] Reuse the env-var channel the elevation grant already
        // uses rather than inventing a second one (P.4).
        if variable_name == CMD_GRANT_ENV {
            self.pending_cmd_grant = Some(variable_value.to_string());
        }
        if variable_name == SESSION_GRANT_ENV {
            self.pending_session_grant = Some(variable_value.to_string());
        }
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        // Checked first, before any other work: an agent-session grant that fails
        // verification must not fall through to a shell landed on `Authorizer`'s
        // ordinary say-so. [T:A.1.6 fail-closed]
        if !self.admit_session_grant(channel, session).await {
            return Ok(());
        }
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

    /// [T:ci-deploy exec, F-2 identity-bound] Non-interactive counterpart to
    /// `shell_request` — a single command, no PTY, real exit code. Reuses the
    /// same elevation-grant decision as the shell path (§H.4): the deploy runs
    /// unprivileged unless a valid CP-signed grant rode in via `env_request`.
    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        // Same fail-closed gate `shell_request` runs, first: an unverifiable
        // agent-session grant must not fall through to the command-grant check below,
        // let alone the plain unauthenticated exec path. No-op when the connecting
        // client is not an agent identity (no env var set). [T:A.1.6 fail-closed]
        if !self.admit_session_grant(channel, session).await {
            return Ok(());
        }
        let command = String::from_utf8_lossy(data).into_owned();

        // [T:A.1.27 #1 — a grant may not widen in transit] The command-grant path is taken FIRST and never falls back
        // to the legacy one: a token that fails to verify means no command runs, because
        // a fallback would let a caller downgrade to the unverified path by sending a
        // deliberately broken grant.
        //
        // Elevation is not consulted on this path. A command grant authorises one command
        // as configured, and running it as root because an elevation grant happened to be
        // in the same channel would be two authorisations combining into one nobody
        // issued. [T:A.1.27 #5 — intersection, not union]
        if let Some(token) = self.pending_cmd_grant.clone() {
            let Some(cmd) = self.exec_under_command_grant(channel, &token, &command, session)
            else {
                return Ok(());
            };
            return self.spawn_exec(channel, cmd, None, session).await;
        }

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
                eprintln!("[F-2] elevation denied, running unprivileged: {reason}");
                false
            }
            ElevationDecision::None => false,
        };

        let Some(cmd) = self.resolve_exec_command(elevated, &command) else {
            eprintln!("[F-2] exec refused — server is locked to a forced program");
            let _ = session.channel_failure(channel);
            return Ok(());
        };
        self.spawn_exec(channel, cmd, elevate_deadline, session)
            .await
    }

    async fn data(
        &mut self,
        _channel: ChannelId,
        data: &[u8],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        // Client keystrokes (PTY) or streamed stdin (exec). Small writes; blocking
        // is negligible.
        if let Some(w) = self.writer.as_mut() {
            let _ = w.write_all(data);
            let _ = w.flush();
        }
        Ok(())
    }

    async fn channel_eof(
        &mut self,
        _channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        // Client signalled end-of-input. Drop the child's stdin so a command that
        // drains it (`tee`, `cat`) sees EOF and exits — without this an exec that
        // streams an artifact in via stdin hangs forever waiting for more bytes.
        self.writer = None;
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

/// Best-effort hard-kill of `pid` (the F-2 §H.4 elevated-exec TTL auto-drop —
/// see `exec_request` above). The shell path gets this cross-platform for free
/// via portable-pty's `clone_killer()`; the bare-`std::process::Child` exec
/// path needs its own per-platform primitive. `[T:kill(2)]` `[T:Win32
/// OpenProcess/TerminateProcess]`
#[cfg(unix)]
fn kill_pid(pid: u32) {
    unsafe {
        libc::kill(pid as i32, libc::SIGKILL);
    }
}

#[cfg(windows)]
fn kill_pid(pid: u32) {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};
    // SAFETY: OpenProcess/TerminateProcess/CloseHandle per their documented
    // Win32 contracts; `pid` names a process this same node's agent spawned
    // moments ago (not attacker-controlled), and every outcome (pid already
    // exited, access denied) is handled by simply not calling the next step —
    // matching the original `libc::kill` call's own best-effort semantics
    // (return value was never checked there either).
    unsafe {
        let handle = OpenProcess(PROCESS_TERMINATE, 0, pid);
        if !handle.is_null() {
            TerminateProcess(handle, 1);
            CloseHandle(handle);
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
            cmd_grant: None,
            session_grant: None,
            outcomes: None,
            node_id: None,
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

    // End-to-end: `exec_request` (no PTY) runs a single command and reports its
    // real exit code — the ci-deploy path this exists for cares about both the
    // captured stdout and whether the deploy actually succeeded.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn client_exec_runs_command_and_reports_exit_code() {
        let dir = tempdir().unwrap();
        let host_key = gen_host_key(dir.path());
        let client_key = MeshSshKey::load_or_generate(&dir.path().join("client")).unwrap();

        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let cfg = SshServerConfig {
            bind_ip: "127.0.0.1".to_string(),
            port: addr.port(),
            authorizer: Authorizer::TrustOverlay,
            // am_root() is false in test — lands in the "already this user" branch
            // (plain `sh -c`), so the exact username here doesn't matter.
            shell: ShellSpec::LoginShell("whoever-is-running-this-test".to_string()),
            elevate: None,
            cmd_grant: None,
            session_grant: None,
            outcomes: None,
            node_id: None,
        };
        tokio::spawn(async move {
            let _ = serve_on(listener, cfg, host_key).await;
        });

        let mut opts = SshConnectOptions::new("127.0.0.1", "ankayma");
        opts.port = addr.port();
        opts.allow_unpinned = true; // exercising TOFU, same as the real ci-deploy path

        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (code, output) = SshSession::exec_over_stream(
            stream,
            &opts,
            &client_key,
            "echo hi-from-exec; exit 7",
            None,
        )
        .await
        .expect("exec should complete");

        assert_eq!(code, 7, "exit code must be the command's real exit code");
        assert!(
            String::from_utf8_lossy(&output).contains("hi-from-exec"),
            "stdout should be captured: {:?}",
            String::from_utf8_lossy(&output)
        );
    }

    // A secretless deploy has to *deliver* the new binary, not just restart a
    // service — and mesh SSH has no SFTP/SCP subsystem. Streaming the artifact
    // into the remote command's stdin is that delivery path, so prove the bytes
    // arrive intact (multi-frame, not a toy string) and stdin reaches EOF.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn client_streams_stdin_so_the_remote_command_can_write_a_file() {
        let dir = tempdir().unwrap();
        let host_key = gen_host_key(dir.path());
        let client_key = MeshSshKey::load_or_generate(&dir.path().join("client")).unwrap();

        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let cfg = SshServerConfig {
            bind_ip: "127.0.0.1".to_string(),
            port: addr.port(),
            authorizer: Authorizer::TrustOverlay,
            shell: ShellSpec::LoginShell("whoever-is-running-this-test".to_string()),
            elevate: None,
            cmd_grant: None,
            session_grant: None,
            outcomes: None,
            node_id: None,
        };
        tokio::spawn(async move {
            let _ = serve_on(listener, cfg, host_key).await;
        });

        let mut opts = SshConnectOptions::new("127.0.0.1", "ankayma");
        opts.port = addr.port();
        opts.allow_unpinned = true;

        // Big enough to cross russh's channel window, like a real binary would.
        let artifact: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
        let dest = dir.path().join("uploaded.bin");

        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (code, _) = SshSession::exec_over_stream(
            stream,
            &opts,
            &client_key,
            &format!("cat > {}", dest.display()),
            Some(&artifact),
        )
        .await
        .expect("exec with stdin should complete");

        assert_eq!(code, 0, "`cat > file` must exit 0 once stdin hits EOF");
        let written = std::fs::read(&dest).expect("remote command should have written the file");
        assert_eq!(
            written, artifact,
            "every byte streamed over the channel must land on disk unchanged"
        );
    }
}

/// The `grant_id` inside a token whose signature did NOT verify.
///
/// Used only to say WHICH grant was refused. Nothing is trusted from it — a caller that
/// forges an id gets a refusal recorded against an id that does not exist, which is
/// visible and harmless, while dropping the id entirely would lose the one detail that
/// makes a digest mismatch worth reading.
fn grant_id_of(token: &str) -> Option<String> {
    use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
    let payload = STANDARD_NO_PAD.decode(token.split_once('.')?.0).ok()?;
    let v: serde_json::Value = serde_json::from_slice(&payload).ok()?;
    v.get("grant_id")?.as_str().map(|s| s.to_string())
}

/// Structural guards for the command-grant path (command-grant gate).
///
/// These read the source rather than exercise a socket, deliberately. Each property below
/// is enforced by the ABSENCE of a line — no shell, no fallback, no PTY — and a behavioural
/// test cannot see a line that was deleted. Whoever removes one should be told by a test
/// rather than by an incident.
#[cfg(test)]
mod command_grant_structure {
    const SOURCE: &str = include_str!("ssh_server.rs");

    /// The body of `exec_under_command_grant`, which is the entire command-grant path.
    fn grant_path() -> &'static str {
        let start = SOURCE
            .find("fn exec_under_command_grant")
            .expect("the command-grant path exists");
        let rest = &SOURCE[start..];
        let end = rest.find("\n    }\n").expect("it ends");
        &rest[..end]
    }

    // The claim the whole tier rests on: argv is built from the signed grant, element by
    // element. `bash -c` is not forbidden here — it is unrepresentable, because nothing on
    // this path can produce a shell.
    #[test]
    fn the_command_grant_path_cannot_build_a_shell() {
        let body = grant_path();
        // Code-shaped patterns, not prose. A bare "-c" also matches the word
        // "fail-closed" in a comment, which makes the test fire on documentation and —
        // worse — makes it look strict while a differently-spelled shell would still walk
        // past it. These are the constructions that actually reach an interpreter.
        for forbidden in [
            r#".arg("-c")"#,
            r#"arg("-c")"#,
            "/bin/sh",
            "/bin/bash",
            r#"var("SHELL")"#,
            r#"Command::new(shell"#,
            r#"Command::new("su""#,
        ] {
            assert!(
                !body.contains(forbidden),
                "the command-grant path must not be able to reach a shell, found {forbidden:?}"
            );
        }
        assert!(
            body.contains("grant.to_command()"),
            "the command must come from the signed grant, not from the exec string"
        );
    }

    // No fallback. A token that fails to verify must mean no command runs — otherwise a
    // caller downgrades to the unverified path by sending a deliberately broken grant.
    #[test]
    fn a_failed_grant_never_falls_through_to_the_legacy_path() {
        let body = grant_path();
        assert!(
            !body.contains("resolve_exec_command"),
            "the grant path must not be able to reach the legacy exec builder"
        );
        assert_eq!(
            body.matches("return None").count(),
            2,
            "both refusal branches must return without running anything"
        );
    }

    // A PTY under a command grant turns one authorised command into a session.
    #[test]
    fn a_pty_is_refused_while_a_command_grant_is_in_force() {
        let start = SOURCE
            .find("async fn pty_request")
            .expect("pty_request exists");
        let body = &SOURCE[start..start + 900];
        assert!(
            body.contains("self.pending_cmd_grant.is_some()"),
            "pty_request must refuse while a command grant is in force"
        );
    }

    // Elevation is not consulted on the grant path. Two authorisations combining into one
    // nobody issued is A.1.27 #5 read backwards.
    #[test]
    fn the_grant_path_does_not_consult_the_elevation_grant() {
        let body = grant_path();
        assert!(!body.contains("decide_elevation"));
        assert!(!body.contains("elevated"));
    }
}
