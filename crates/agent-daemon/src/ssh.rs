//! ssh — `agent ssh <node>`: Sovereign SSH (Part C §H.3.6.1 F-2). OPEN, intensity Standard.
//!
//! "SSH into prod from anywhere — no bastion, no static key; session in the ledger."
//! The access boundary IS the mesh identity (A.1.3): the target is only reachable
//! over the per-tenant overlay, granted by enrollment, never by network location.
//! This command resolves one of YOUR OWN mesh nodes via the control plane (which
//! anchors a connection-level `SshSessionOpened` event, A.1.8) and then execs the
//! system `ssh` straight to the overlay address — the control plane (vendor) is the
//! control channel only, NEVER on the SSH data path (A.1.1).
//!
//! Session recording is F1 Growth `[A-p]`; F0 records only that a session opened.

use agent_core::domain::{
    SshElevateRequest, SshSessionReceipt, SshSessionRequest, SshSessionResponse,
};
use agent_core::ssh_client::{MeshSshKey, SshConnectOptions, SshEvent, SshSession};
use agent_core::{adapters, reqwest};
use anyhow::{anyhow, Result};

const DEFAULT_CONTROL_PLANE: &str = "https://cp.ankayma.com";

/// Where the device's persistent ed25519 mesh-SSH identity lives — next to
/// `agent.json` under `~/.ankayma/`. `[T:A.1.3]`
fn mesh_ssh_key_path() -> std::path::PathBuf {
    let home = crate::up::home_root();
    std::path::Path::new(&home)
        .join(".ankayma")
        .join("mesh-ssh-ed25519")
}

/// `agent ssh <node_id> [--login <user>] [--token <t>] [--control-plane <url>]
///                      [--print]`
///
/// The session token is the human's credential (the same one `agent up --token`
/// takes); pass it via `--token` or `ANKAYMA_TOKEN`.
pub async fn run(args: &[String]) -> Result<()> {
    let cfg = Config::parse(args)?;
    let http = reqwest::Client::new();

    // 1. [F-2 / A.1.3] Resolve the target + anchor the session in the ledger. The
    // control plane only hands back the overlay address — it never sees the stream.
    let resp = adapters::open_ssh_session(
        &http,
        &cfg.control_plane,
        &cfg.token,
        &SshSessionRequest {
            node_id: cfg.node_id.clone(),
            login: cfg.login.clone(),
        },
    )
    .await
    .map_err(|e| anyhow!("open ssh session: {e}"))?;

    // 2. [F-2] The wow is the *proof*, not just the connection: show the receipt the
    // control plane just anchored, and the path-proof (vendor off the data path).
    print_receipt(resp.receipt.as_ref(), &cfg.control_plane);
    print_path_proof(&resp.overlay_ip, &cfg.control_plane);

    // The effective login: server-sanitized echo wins; else what we asked for.
    // Default depends on transport: the mesh embedded server lands the shared
    // user `ankayma` (identity-bound, unprivileged — §H.1/§H.5); the legacy
    // system-ssh path lands `root` (the near-universal server login, since a raw
    // ssh would otherwise use the LOCAL username and dead-end at a password).
    let default_login = if cfg.mesh { "ankayma" } else { "root" };
    let login = resp
        .login
        .clone()
        .or(cfg.login.clone())
        .unwrap_or_else(|| default_login.to_string());

    if cfg.print_only {
        if cfg.mesh {
            println!(
                "\nagent ssh (mesh) → {login}@{}:{}",
                resp.overlay_ip,
                resp.ssh_port.unwrap_or(22022)
            );
        } else {
            println!("\nssh {login}@{}", resp.overlay_ip);
        }
        return Ok(());
    }

    // 3a. [F-2 v0.5] Mesh transport: pure-Rust russh client → the node's embedded
    // server, authenticated by the device's enrolled ed25519 key (A.1.3 — no
    // password, no static key). Same engine the GUI/iOS terminal uses.
    if cfg.mesh {
        return run_mesh(&cfg, &resp, &login).await;
    }

    // 3b. Legacy transport: exec the system ssh straight to the overlay address
    // (interactive TTY). [A.1.1] direct over the mesh — vendor not on this path.
    // Kept as a fallback for nodes whose agent hasn't shipped the embedded server
    // yet (A.1.20 graceful degrade). Auth here is the node's own sshd/root creds.
    // `accept-new`: the overlay address is a fresh, tenant-scoped identity the
    // user has never seen — a raw `ssh` blocks on the host-authenticity prompt.
    // `ServerAliveInterval`: keepalives bridge an idle-teardown re-handshake.
    // `[T:ssh_config(5)]`
    let dest = format!("{login}@{}", resp.overlay_ip);
    println!("\n── Connecting (system ssh) ───────────────────────────");
    println!("  ssh {dest}");
    let status = std::process::Command::new("ssh")
        .args(["-o", "StrictHostKeyChecking=accept-new"])
        .args(["-o", "ServerAliveInterval=5"])
        .arg(&dest)
        .status()
        .map_err(|e| anyhow!("launch ssh: {e}"))?;
    if !status.success() {
        return Err(anyhow!("ssh exited with {status}"));
    }
    Ok(())
}

/// [F-2 v0.5] Interactive mesh SSH: drive the russh engine with a raw-mode local
/// terminal. The engine is UI-agnostic (also feeds the GUI/iOS xterm.js terminal);
/// here we bridge it to the CLI's stdin/stdout.
async fn run_mesh(cfg: &Config, resp: &SshSessionResponse, login: &str) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let key = MeshSshKey::load_or_generate(&mesh_ssh_key_path())?;

    let mut opts = SshConnectOptions::new(resp.overlay_ip.clone(), login.to_string());
    opts.port = cfg.ssh_port.or(resp.ssh_port).unwrap_or(22022);
    // Pin the host key the control plane bound to this node's identity. If the CP
    // didn't return one (older CP), the connect fails closed unless --allow-unpinned.
    opts.expected_host_key = resp.server_host_key.clone();
    opts.allow_unpinned = cfg.allow_unpinned;
    if let Some((cols, rows)) = term_size() {
        opts.cols = cols;
        opts.rows = rows;
    }

    // [F-2 §H.4] --grant <token>: present a pre-issued grant directly, skipping the
    // /ssh/elevate call. For validation / pre-fetched grants; the node still verifies
    // the CP signature, so an invalid token just lands unprivileged.
    if let Some(g) = &cfg.grant {
        println!("  elevation      using provided grant");
        opts.elevate_grant = Some(g.clone());
    }
    // [F-2 §H.4] --root: ask the control plane for a root-elevation grant (F0 owner
    // is instant, no step-up; F1+ would carry a step-up proof). The grant rides the
    // SSH channel to the node's server, which verifies it and lands a root PTY.
    else if cfg.root {
        let http = reqwest::Client::new();
        let grant = adapters::elevate_ssh_session(
            &http,
            &cfg.control_plane,
            &cfg.token,
            &SshElevateRequest {
                node_id: cfg.node_id.clone(),
                persona: "root".to_string(),
                duration_secs: None,
                proof_token: cfg.proof_token.clone(),
            },
        )
        .await
        .map_err(|e| anyhow!("request elevation: {e}"))?;
        println!(
            "  elevation      granted (root, expires_at {})",
            grant.expires_at
        );
        opts.elevate_grant = Some(grant.grant);
    }

    println!("\n── Connecting (mesh, identity-bound) ─────────────────");
    let elevating = cfg.root || cfg.grant.is_some();
    let shown_login = if elevating { "root (elevated)" } else { login };
    println!("  {shown_login}@{}:{}", opts.host, opts.port);
    if opts.expected_host_key.is_none() {
        eprintln!("  ⚠ no pinned host key from control plane — using --allow-unpinned (TOFU)");
    }

    let mut sess = SshSession::connect(&opts, &key)
        .await
        .map_err(|e| anyhow!("mesh ssh: {e}"))?;

    // Raw mode so keystrokes reach the remote PTY unbuffered; restored on drop.
    let _raw = RawMode::enter();
    let mut stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let mut buf = [0u8; 4096];

    loop {
        tokio::select! {
            r = stdin.read(&mut buf) => match r {
                Ok(0) => { let _ = sess.send_eof().await; }
                Ok(n) => {
                    if sess.write(&buf[..n]).await.is_err() { break; }
                }
                Err(_) => break,
            },
            ev = sess.recv() => match ev {
                Some(SshEvent::Data(d)) => {
                    stdout.write_all(&d).await?;
                    stdout.flush().await?;
                }
                Some(SshEvent::Eof) => {}
                Some(SshEvent::Exit(_)) | Some(SshEvent::Disconnected) | None => break,
            },
        }
    }
    drop(_raw);
    let _ = sess.close().await;
    println!();
    Ok(())
}

/// RAII terminal raw-mode guard (unix). Puts fd 0 into raw mode on `enter` and
/// restores the saved termios on drop, so the shell isn't left in raw mode if the
/// session dies. No-op on non-unix. `[T:termios(3)]`
struct RawMode {
    #[cfg(unix)]
    saved: Option<libc::termios>,
}

impl RawMode {
    fn enter() -> Self {
        #[cfg(unix)]
        unsafe {
            let mut term: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(0, &mut term) == 0 {
                let saved = term;
                libc::cfmakeraw(&mut term);
                libc::tcsetattr(0, libc::TCSANOW, &term);
                return RawMode { saved: Some(saved) };
            }
            RawMode { saved: None }
        }
        #[cfg(not(unix))]
        RawMode {}
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        #[cfg(unix)]
        unsafe {
            if let Some(saved) = self.saved.take() {
                libc::tcsetattr(0, libc::TCSANOW, &saved);
            }
        }
    }
}

/// Best-effort local terminal size (cols, rows) for the initial PTY window.
/// `[T:ioctl_tty(2) TIOCGWINSZ]`
fn term_size() -> Option<(u32, u32)> {
    #[cfg(unix)]
    unsafe {
        let mut ws: libc::winsize = std::mem::zeroed();
        if libc::ioctl(1, libc::TIOCGWINSZ, &mut ws) == 0 && ws.ws_col > 0 {
            return Some((ws.ws_col as u32, ws.ws_row as u32));
        }
    }
    None
}

/// [F-2] Print the honest session receipt — identity-bound, no bastion, no static
/// key, ledger-anchored; NOT session-recorded at F0 (P.3). Print a re-verify
/// command so the user can prove it independently against the live ledger.
fn print_receipt(receipt: Option<&SshSessionReceipt>, control_plane: &str) {
    let Some(r) = receipt else {
        // Older control plane, or an edge path — nothing to show, don't fake it.
        return;
    };
    println!("── SSH session receipt ───────────────────────────────");
    println!("  session        {}", r.session_id);
    println!("  node           {}", r.node_id);
    println!("  target         {}", r.target);
    if let Some(login) = &r.login {
        println!("  login          {login}");
    }
    println!(
        "  identity-bound {} [A.1.3]",
        if r.identity_bound { "yes" } else { "no" }
    );
    println!(
        "  bastion        {}",
        if r.bastion { "yes" } else { "none" }
    );
    println!(
        "  static key     {}",
        if r.static_key { "yes" } else { "none" }
    );
    // Honest about the F0 ceiling (P.3): session recording is F1 Growth.
    println!(
        "  recording      {}",
        if r.session_recorded {
            "yes"
        } else {
            "none — session recording is F1 Growth"
        }
    );
    println!(
        "  ledger anchor  {}:{}",
        r.ledger_event, r.ledger_block_hash
    );
    println!(
        "  verify         curl {}/api/v1/ssh/receipt/{}",
        control_plane.trim_end_matches('/'),
        r.session_id
    );
}

/// [F-5 / A.1.1] The SSH stream is direct over the mesh overlay; the vendor is the
/// control channel only, never on the data path.
fn print_path_proof(overlay_ip: &str, control_plane: &str) {
    println!("\n── Path ──────────────────────────────────────────────");
    println!("  data plane     direct over mesh overlay → {overlay_ip}");
    println!(
        "  vendor         {} — control channel only, NOT on the data path [A.1.1]",
        control_plane.trim_end_matches('/')
    );
}

struct Config {
    node_id: String,
    login: Option<String>,
    token: String,
    control_plane: String,
    print_only: bool,
    /// Use the mesh embedded-server transport (russh, identity-bound) instead of
    /// spawning the system `ssh`. Opt-in until the embedded server ships on nodes
    /// (Lát 2); becomes the default afterward. `[A: flip default post-Lát-2 validate]`
    mesh: bool,
    /// Override the embedded server port (default 22022 / CP-provided).
    ssh_port: Option<u16>,
    /// Allow trust-on-first-use when the control plane returned no host-key pin
    /// (honest fallback; off by default). Only meaningful with `--mesh`.
    allow_unpinned: bool,
    /// Request a root-elevation grant and land a root PTY (§H.4). Mesh transport
    /// only. F0 owner is instant; F1+ carries `--proof`.
    root: bool,
    /// AAL step-up proof token for `--root` at F1+ tiers (E-7). F0 owner omits it.
    proof_token: Option<String>,
    /// A pre-issued elevation grant to present directly (skips `/ssh/elevate`).
    /// Implies `--mesh`. Node still verifies the CP signature.
    grant: Option<String>,
}

impl Config {
    fn parse(args: &[String]) -> Result<Self> {
        let mut node_id: Option<String> = None;
        let mut login = None;
        let mut token = std::env::var("ANKAYMA_TOKEN").ok();
        let mut control_plane = std::env::var("ANKAYMA_CONTROL_PLANE")
            .unwrap_or_else(|_| DEFAULT_CONTROL_PLANE.to_string());
        let mut print_only = false;
        let mut mesh = false;
        let mut ssh_port: Option<u16> = None;
        let mut allow_unpinned = false;
        let mut root = false;
        let mut proof_token: Option<String> = None;
        let mut grant: Option<String> = None;

        let mut it = args.iter();
        while let Some(a) = it.next() {
            match a.as_str() {
                "--login" => {
                    login = Some(
                        it.next()
                            .ok_or_else(|| anyhow!("--login needs a value"))?
                            .clone(),
                    )
                }
                "--token" => {
                    token = Some(
                        it.next()
                            .ok_or_else(|| anyhow!("--token needs a value"))?
                            .clone(),
                    )
                }
                "--control-plane" => {
                    control_plane = it
                        .next()
                        .ok_or_else(|| anyhow!("--control-plane needs a value"))?
                        .clone()
                }
                // Resolve + show the receipt, but print the ssh command instead of running it.
                "--print" => print_only = true,
                // [F-2 v0.5] Use the identity-bound mesh embedded-server transport.
                "--mesh" => mesh = true,
                "--ssh-port" => {
                    ssh_port = Some(
                        it.next()
                            .ok_or_else(|| anyhow!("--ssh-port needs a value"))?
                            .parse()
                            .map_err(|_| anyhow!("--ssh-port must be a port number"))?,
                    )
                }
                "--allow-unpinned" => allow_unpinned = true,
                // [F-2 §H.4] Elevate to root via a CP-signed grant (implies --mesh).
                "--root" => {
                    root = true;
                    mesh = true;
                }
                "--proof" => {
                    proof_token = Some(
                        it.next()
                            .ok_or_else(|| anyhow!("--proof needs a value"))?
                            .clone(),
                    )
                }
                "--grant" => {
                    grant = Some(
                        it.next()
                            .ok_or_else(|| anyhow!("--grant needs a value"))?
                            .clone(),
                    );
                    mesh = true;
                }
                other if other.starts_with("--") => {
                    return Err(anyhow!("unknown argument: {other}"))
                }
                // First positional is the node id.
                other => {
                    if node_id.is_some() {
                        return Err(anyhow!("unexpected extra argument: {other}"));
                    }
                    node_id = Some(other.to_string());
                }
            }
        }

        let node_id = node_id.ok_or_else(|| {
            anyhow!("usage: agent ssh <node_id> [--login <user>] [--token <t>] [--print]")
        })?;
        let token = token
            .filter(|t| !t.trim().is_empty())
            .ok_or_else(|| anyhow!("no session token — pass --token <t> or set ANKAYMA_TOKEN"))?;
        Ok(Config {
            node_id,
            login,
            token,
            control_plane,
            print_only,
            mesh,
            ssh_port,
            allow_unpinned,
            root,
            proof_token,
            grant,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn parses_node_and_flags() {
        let c = Config::parse(&s(&[
            "node_7", "--login", "deploy", "--token", "tok", "--print",
        ]))
        .unwrap();
        assert_eq!(c.node_id, "node_7");
        assert_eq!(c.login.as_deref(), Some("deploy"));
        assert_eq!(c.token, "tok");
        assert!(c.print_only);
    }

    #[test]
    fn requires_node_id() {
        assert!(Config::parse(&s(&["--token", "tok"])).is_err());
    }

    #[test]
    fn requires_token() {
        // No --token and (in a clean env) no ANKAYMA_TOKEN → error.
        if std::env::var("ANKAYMA_TOKEN").is_err() {
            assert!(Config::parse(&s(&["node_1"])).is_err());
        }
    }

    #[test]
    fn rejects_unknown_flag_and_extra_positional() {
        assert!(Config::parse(&s(&["node_1", "--bogus"])).is_err());
        assert!(Config::parse(&s(&["node_1", "node_2", "--token", "t"])).is_err());
    }
}
