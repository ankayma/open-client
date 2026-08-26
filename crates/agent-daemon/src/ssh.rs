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
    AgentSshSessionRequest, AgentSshSessionResponse, CommandGrantRequest, CommandReq,
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

/// Same idea, per AGENT HANDLE rather than per device: an agent connecting `--as
/// <handle>` uses its OWN SSH transport identity, not the human owner's personal
/// device key. `Authorizer::TrustOverlay` does not gate on this key's value at all
/// (module doc, `ssh_server.rs`) — the actual authority is the `session_grant` this
/// same connection presents — but keeping the keys apart keeps the audit trail
/// (`authed_key` in `ssh_server.rs`) honest about which identity actually connected.
fn agent_mesh_ssh_key_path(handle: &str) -> std::path::PathBuf {
    let home = crate::up::home_root();
    std::path::Path::new(&home)
        .join(".ankayma")
        .join(format!("agent-{handle}-mesh-ssh-ed25519"))
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// `agent ssh <node_id> [--login <user>] [--token <t>] [--control-plane <url>]
///                      [--print]`
///
/// The session token is the human's credential (the same one `agent up --token`
/// takes); pass it via `--token` or `ANKAYMA_TOKEN`.
pub async fn run(args: &[String]) -> Result<()> {
    let cfg = Config::parse(args)?;
    // `--as <handle>`: an AGENT identity, not the human's own session,
    // is connecting. Entirely separate auth (no bearer token at all) and a separate
    // mint call — branches out before anything below, which is all human-session-only.
    if let Some(handle) = cfg.agent_handle.clone() {
        return run_as_agent(&cfg, &handle).await;
    }
    // `--cmd`: a human authorises an actor to run ONE command on this
    // node. Human-session-authed only (A.1.27 #2 — an agent does not mint its own
    // authority) — this branches out before anything else below because it never
    // connects at all, it only mints (or asks a person to decide).
    if let Some(cmd) = cfg.cmd.clone() {
        return run_mint_command(&cfg, &cmd).await;
    }
    let http = reqwest::Client::new();
    // Validated present at parse time whenever `agent_handle` is absent.
    let token = cfg
        .token
        .as_deref()
        .expect("Config::parse guarantees a token on the human path");

    // 1. [F-2 / A.1.3] Resolve the target + anchor the session in the ledger. The
    // control plane only hands back the overlay address — it never sees the stream.
    let resp = adapters::open_ssh_session(
        &http,
        &cfg.control_plane,
        token,
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

/// `agent ssh <node> --token <t> --for-actor <actor_id> --cmd
///                    <template|FREEFORM> [--param k=v]... [--reason <text>]
///                    [--argv <elements...>]`
///
/// Mints ONE command grant, or asks a person to decide — never connects. Human-session-
/// authed only (A.1.27 #2): an agent does not mint its own authority, so there is no
/// `--as` variant of this branch. The token this prints is for whoever DOES connect,
/// typically `agent ssh --as <handle> <node> --cmd-grant <token>`.
async fn run_mint_command(cfg: &Config, template_id: &str) -> Result<()> {
    let http = reqwest::Client::new();
    let token = cfg
        .token
        .as_deref()
        .expect("Config::parse guarantees a token on the mint path");
    let actor_id = cfg
        .for_actor
        .as_deref()
        .ok_or_else(|| anyhow!("--cmd needs --for-actor <agent_actor_id>"))?;

    let command = if template_id == "FREEFORM" {
        if !cfg.cmd_params.is_empty() {
            return Err(anyhow!("FREEFORM takes --argv, not --param"));
        }
        CommandReq {
            template_id: template_id.to_string(),
            params: Default::default(),
            argv: cfg.cmd_argv.clone(),
            justification: cfg.cmd_reason.clone(),
        }
    } else {
        if !cfg.cmd_argv.is_empty() {
            return Err(anyhow!(
                "--argv is FREEFORM-only — a catalog command takes --param instead"
            ));
        }
        CommandReq {
            template_id: template_id.to_string(),
            params: cfg.cmd_params.iter().cloned().collect(),
            argv: vec![],
            justification: cfg.cmd_reason.clone(),
        }
    };

    let resp = adapters::mint_command_grants(
        &http,
        &cfg.control_plane,
        token,
        &CommandGrantRequest {
            node_id: cfg.node_id.clone(),
            actor_id: actor_id.to_string(),
            purpose_code: None,
            business_justification: cfg.cmd_reason.clone(),
            ttl_seconds: None,
            commands: vec![command],
        },
    )
    .await
    .map_err(|e| anyhow!("mint command grant: {e}"))?;

    println!("── Command grant ─────────────────────────────────────");
    println!("  task           {}", resp.task_id);
    println!("  node           {}", resp.node_id);
    println!("  for actor      {}", resp.actor_id);
    for c in &resp.commands {
        println!();
        println!("  template       {}", c.template_id);
        println!("  cmd_digest     {}", c.cmd_digest);
        println!("  status         {}", c.status);
        match c.status.as_str() {
            "GRANTED" => {
                let tok = c.grant_token.as_deref().unwrap_or("(missing)");
                println!("  grant_token    {tok}");
                println!(
                    "\n  hand this to whoever runs it:\n    agent ssh --as <handle> {} --cmd-grant {tok}",
                    cfg.node_id
                );
            }
            "PENDING_APPROVAL" => {
                println!(
                    "  approval_id    {}",
                    c.approval_id.as_deref().unwrap_or("(missing)")
                );
                println!(
                    "  gate_reason    {}",
                    c.gate_reason.as_deref().unwrap_or("?")
                );
                println!(
                    "\n  no credential exists yet — decide it in Ankayma → Governance. The \
                     approval response there is the ONLY place grant_token appears (this \
                     command cannot poll for it): copy it from there, then hand it to \
                     whoever runs it:\n    agent ssh --as <handle> {} --cmd-grant <token>",
                    cfg.node_id
                );
            }
            other => println!("  (unrecognised status \"{other}\" — see the raw response)"),
        }
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
        let token = cfg
            .token
            .as_deref()
            .expect("Config::parse guarantees a token on the human path");
        let grant = adapters::elevate_ssh_session(
            &http,
            &cfg.control_plane,
            token,
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

/// `agent ssh --as <handle> <node> [-- <command...>]` — connect as a
/// previously-enrolled AGENT identity instead of the human's own session. No bearer
/// token anywhere on this path: the identity proves itself by signature
/// (`anchor::resolve_anchor`'s agent branch, control-plane side), and the mint is
/// refused outright unless a human currently has a live delegation window open for
/// it — there is no fallback to try if one is not.
async fn run_as_agent(cfg: &Config, handle: &str) -> Result<()> {
    let identity = crate::agent_state::load(handle)?.ok_or_else(|| {
        anyhow!(
            "no local identity for \"{handle}\" on this machine — bootstrap it first: \
             agent enroll-identity --token <t> --name {handle}"
        )
    })?;
    let key = crate::agent_state::session_key(handle)?;
    let proof = key
        .proof(&identity.self_node_id, unix_now())
        .map_err(|e| anyhow!("sign agent session proof: {e}"))?;

    let http = reqwest::Client::new();
    let resp: AgentSshSessionResponse = adapters::open_agent_ssh_session(
        &http,
        &cfg.control_plane,
        &AgentSshSessionRequest {
            target_node_id: cfg.node_id.clone(),
            proof,
            ttl_seconds: None,
        },
    )
    .await
    .map_err(|e| anyhow!("open agent ssh session: {e}"))?;

    println!("── Agent session grant ───────────────────────────────");
    println!("  agent          {handle} ({})", identity.agent_actor_id);
    println!("  node           {}", cfg.node_id);
    println!("  grant          {}", resp.grant_id);
    println!("  task           {}", resp.task_id);
    println!("  expires_at     {}", resp.expires_at);
    print_path_proof(&resp.overlay_ip, &cfg.control_plane);

    if cfg.print_only {
        println!(
            "\nagent ssh --as {handle} (mesh) → ankayma@{}:{}",
            resp.overlay_ip,
            cfg.ssh_port.unwrap_or(22022)
        );
        return Ok(());
    }

    let mut opts = SshConnectOptions::new(resp.overlay_ip.clone(), "ankayma".to_string());
    opts.port = cfg.ssh_port.unwrap_or(22022);
    // No host-key pin on this path yet — `/api/v1/agents/ssh-session` does not return
    // one the way `/api/v1/ssh/session` does for the human path (forward dependency,
    // not built here). TOFU accepted deliberately, same reasoning `ssh_exec.rs`
    // already documents: the `session_grant` this connection presents is itself a
    // CP-signed, node-scoped check the target verifies before opening a channel at
    // all, so this SSH-layer pin would be a second barrier on top of that, not the
    // only one. `[A per owner 2026-07-14 precedent]`
    opts.allow_unpinned = true;
    opts.session_grant = Some(resp.session_grant.clone());
    if let Some((cols, rows)) = term_size() {
        opts.cols = cols;
        opts.rows = rows;
    }

    let ssh_key = MeshSshKey::load_or_generate(&agent_mesh_ssh_key_path(handle))?;

    // `--cmd-grant <token>`: present an already-minted COMMAND grant
    // (from `--cmd` on the human side) instead of the broad session-grant one-shot.
    // The node ignores the exec string entirely when a command grant is set — argv
    // comes from the grant — so an empty one is correct, not a placeholder.
    if let Some(grant) = &cfg.cmd_grant {
        opts.cmd_grant = Some(grant.clone());
        return run_agent_exec(&opts, &ssh_key, "").await;
    }

    if let Some(cmd) = &cfg.exec_cmd {
        return run_agent_exec(&opts, &ssh_key, cmd).await;
    }

    println!("\n── Connecting (mesh, agent identity-bound) ───────────");
    println!("  ankayma@{}:{}", opts.host, opts.port);

    let mut sess = SshSession::connect(&opts, &ssh_key)
        .await
        .map_err(|e| anyhow!("mesh ssh: {e}"))?;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
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

/// Headless one-shot under an agent session grant: dial the
/// target directly (this is a normal mesh connection, not the CI SOCKS5 tunnel
/// `ssh_exec.rs` uses) and run one command, no PTY, real exit code.
async fn run_agent_exec(opts: &SshConnectOptions, key: &MeshSshKey, command: &str) -> Result<()> {
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpStream;

    println!("\n── Running (mesh, agent identity-bound, no PTY) ──────");
    println!("  ankayma@{}:{}  -- {command}", opts.host, opts.port);

    let stream = TcpStream::connect((opts.host.as_str(), opts.port))
        .await
        .map_err(|e| anyhow!("connect {}:{}: {e}", opts.host, opts.port))?;
    let (code, output) = SshSession::exec_over_stream(stream, opts, key, command, None)
        .await
        .map_err(|e| anyhow!("exec: {e}"))?;

    tokio::io::stdout().write_all(&output).await.ok();
    std::process::exit(code as i32);
}

/// RAII terminal raw-mode guard (unix). Puts fd 0 into raw mode on `enter` and
/// restores the saved termios on drop, so the shell isn't left in raw mode if the
/// session dies. No-op on non-unix. `[T:termios(3)]`
struct RawMode {
    #[cfg(unix)]
    saved: Option<libc::termios>,
    #[cfg(windows)]
    saved_out_mode: Option<u32>,
    #[cfg(windows)]
    saved_in_mode: Option<u32>,
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
        #[cfg(windows)]
        unsafe {
            use windows_sys::Win32::System::Console::{
                GetConsoleMode, GetStdHandle, SetConsoleMode, ENABLE_ECHO_INPUT, ENABLE_LINE_INPUT,
                ENABLE_PROCESSED_INPUT, ENABLE_VIRTUAL_TERMINAL_INPUT,
                ENABLE_VIRTUAL_TERMINAL_PROCESSING, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
            };
            let mut rm = RawMode {
                saved_out_mode: None,
                saved_in_mode: None,
            };
            let hout = GetStdHandle(STD_OUTPUT_HANDLE);
            let mut out_mode: u32 = 0;
            if GetConsoleMode(hout, &mut out_mode) != 0 {
                rm.saved_out_mode = Some(out_mode);
                // Interpret the remote PTY's ANSI escapes instead of printing them raw.
                SetConsoleMode(hout, out_mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
            }
            let hin = GetStdHandle(STD_INPUT_HANDLE);
            let mut in_mode: u32 = 0;
            if GetConsoleMode(hin, &mut in_mode) != 0 {
                rm.saved_in_mode = Some(in_mode);
                // Raw input: stream keystrokes (no line buffering / local echo) and
                // let VT input through so the remote shell drives the terminal.
                let raw = (in_mode
                    & !(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_INPUT))
                    | ENABLE_VIRTUAL_TERMINAL_INPUT;
                SetConsoleMode(hin, raw);
            }
            rm
        }
        #[cfg(not(any(unix, windows)))]
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
        #[cfg(windows)]
        unsafe {
            use windows_sys::Win32::System::Console::{
                GetStdHandle, SetConsoleMode, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
            };
            if let Some(m) = self.saved_out_mode.take() {
                SetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE), m);
            }
            if let Some(m) = self.saved_in_mode.take() {
                SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), m);
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
    #[cfg(windows)]
    unsafe {
        use windows_sys::Win32::System::Console::{
            GetConsoleScreenBufferInfo, GetStdHandle, CONSOLE_SCREEN_BUFFER_INFO, STD_OUTPUT_HANDLE,
        };
        let mut info: CONSOLE_SCREEN_BUFFER_INFO = std::mem::zeroed();
        if GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &mut info) != 0 {
            let cols = (info.srWindow.Right - info.srWindow.Left + 1) as u32;
            let rows = (info.srWindow.Bottom - info.srWindow.Top + 1) as u32;
            if cols > 0 {
                return Some((cols, rows));
            }
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
    /// `None` only when `agent_handle` is set — the human session token and the
    /// agent's own proof are mutually exclusive ways to authenticate this connection.
    token: Option<String>,
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
    /// `--as <handle>`: connect as a previously-enrolled AGENT identity (locally
    /// bootstrapped via `agent enroll-identity --name <handle>`) instead of the
    /// human's own session.
    agent_handle: Option<String>,
    /// Everything after a literal `--`: a headless one-shot command instead of an
    /// interactive shell. Only meaningful with `agent_handle` set
    /// — still session-grant, not command-grant: broad, unaudited per-command, just
    /// without a PTY.
    exec_cmd: Option<String>,
    /// `--cmd <template_id>`: mint ONE command grant for `for_actor` instead of
    /// connecting. `"FREEFORM"` is break-glass (needs `cmd_argv` + `cmd_reason`); any
    /// other value is a catalog template (takes `cmd_params`). Human-token-authed
    /// only — mutually exclusive with `agent_handle`.
    cmd: Option<String>,
    /// `--for-actor <agent_actor_id>`: who `--cmd` authorises. Required with `--cmd`.
    for_actor: Option<String>,
    /// `--param k=v`, repeatable: catalog template parameters for `--cmd`.
    cmd_params: Vec<(String, String)>,
    /// `--reason <text>`: `justification` for `--cmd`. Required for FREEFORM.
    cmd_reason: Option<String>,
    /// `--argv <elements...>`: the literal command for FREEFORM `--cmd`, element by
    /// element (never a shell string). Consumes the rest of argv — must be last.
    cmd_argv: Vec<String>,
    /// `--cmd-grant <token>`: present an already-minted COMMAND grant (from `--cmd`
    /// on the human side) instead of the broad session-grant one-shot. Only
    /// meaningful with `agent_handle` set — presenting one on the human's own
    /// connection isn't a flow this command supports.
    cmd_grant: Option<String>,
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
        let mut agent_handle: Option<String> = None;
        let mut exec_cmd: Option<String> = None;
        let mut cmd: Option<String> = None;
        let mut for_actor: Option<String> = None;
        let mut cmd_params: Vec<(String, String)> = Vec::new();
        let mut cmd_reason: Option<String> = None;
        let mut cmd_argv: Vec<String> = Vec::new();
        let mut cmd_grant: Option<String> = None;

        let mut it = args.iter();
        while let Some(a) = it.next() {
            match a.as_str() {
                "--as" => {
                    agent_handle = Some(
                        it.next()
                            .ok_or_else(|| anyhow!("--as needs a value"))?
                            .clone(),
                    )
                }
                // Everything after `--` is the headless one-shot command, joined —
                // same convention `agent ssh-exec` already uses.
                "--" => {
                    let rest: Vec<String> = it.by_ref().cloned().collect();
                    if rest.is_empty() {
                        return Err(anyhow!("-- needs a command"));
                    }
                    exec_cmd = Some(rest.join(" "));
                }
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
                // Mint path.
                "--cmd" => {
                    cmd = Some(
                        it.next()
                            .ok_or_else(|| anyhow!("--cmd needs a template id (or FREEFORM)"))?
                            .clone(),
                    )
                }
                "--for-actor" => {
                    for_actor = Some(
                        it.next()
                            .ok_or_else(|| anyhow!("--for-actor needs an agent_actor_id"))?
                            .clone(),
                    )
                }
                "--param" => {
                    let kv = it
                        .next()
                        .ok_or_else(|| anyhow!("--param needs a key=value"))?;
                    let (k, v) = kv
                        .split_once('=')
                        .ok_or_else(|| anyhow!("--param must be key=value, got \"{kv}\""))?;
                    cmd_params.push((k.to_string(), v.to_string()));
                }
                "--reason" => {
                    cmd_reason = Some(
                        it.next()
                            .ok_or_else(|| anyhow!("--reason needs a value"))?
                            .clone(),
                    )
                }
                // Everything after `--argv` is the literal FREEFORM command, element by
                // element — never joined into a shell string. Consumes the rest, so it
                // must be the last flag, same convention as `--`.
                "--argv" => {
                    let rest: Vec<String> = it.by_ref().cloned().collect();
                    if rest.is_empty() {
                        return Err(anyhow!("--argv needs at least a program"));
                    }
                    cmd_argv = rest;
                }
                // Consume path.
                "--cmd-grant" => {
                    cmd_grant = Some(
                        it.next()
                            .ok_or_else(|| anyhow!("--cmd-grant needs a value"))?
                            .clone(),
                    )
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
            anyhow!(
                "usage: agent ssh <node_id> [--login <user>] [--token <t>] [--print] \
                 | agent ssh --as <handle> <node_id> [-- <command...>]"
            )
        })?;
        if exec_cmd.is_some() && agent_handle.is_none() {
            return Err(anyhow!(
                "-- <command> is only meaningful with --as <handle> — for a human's own \
                 one-shot exec, use `agent ssh-exec`"
            ));
        }
        // `--cmd` mints on the HUMAN's own authority (A.1.27 #2: an
        // agent does not mint its own authority) — it has no `--as` variant, so the
        // two are refused together rather than one silently winning.
        if cmd.is_some() && agent_handle.is_some() {
            return Err(anyhow!(
                "--cmd mints on your own (human) authority — use it without --as; hand the \
                 grant_token it prints to `--as <handle> ... --cmd-grant <token>`"
            ));
        }
        if cmd.is_none() && (for_actor.is_some() || cmd_reason.is_some() || !cmd_argv.is_empty()) {
            return Err(anyhow!(
                "--for-actor / --reason / --argv only mean something with --cmd"
            ));
        }
        if cmd_grant.is_some() && agent_handle.is_none() {
            return Err(anyhow!(
                "--cmd-grant needs --as <handle> — presenting a command grant on the \
                 human's own connection isn't a flow this command supports"
            ));
        }
        if cmd_grant.is_some() && exec_cmd.is_some() {
            return Err(anyhow!(
                "--cmd-grant already carries its own command — it and -- <command> are \
                 mutually exclusive"
            ));
        }
        // The agent's own signed proof authenticates `--as`; a human session token is
        // not just unused there, it is the wrong credential for that path entirely.
        // `--cmd` mints human-side even though it never connects, so it needs one too.
        let token = if agent_handle.is_some() {
            None
        } else {
            Some(token.filter(|t| !t.trim().is_empty()).ok_or_else(|| {
                anyhow!("no session token — pass --token <t> or set ANKAYMA_TOKEN")
            })?)
        };
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
            agent_handle,
            exec_cmd,
            cmd,
            for_actor,
            cmd_params,
            cmd_reason,
            cmd_argv,
            cmd_grant,
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
        assert_eq!(c.token.as_deref(), Some("tok"));
        assert!(c.print_only);
        assert!(c.agent_handle.is_none());
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

    // `--as` is a different credential entirely — no token required,
    // and none should be silently expected.
    #[test]
    fn as_flag_needs_no_token() {
        let c = Config::parse(&s(&["--as", "claude-1", "node_7"])).unwrap();
        assert_eq!(c.agent_handle.as_deref(), Some("claude-1"));
        assert_eq!(c.node_id, "node_7");
        assert!(
            c.token.is_none(),
            "the agent path authenticates by proof, not a token"
        );
    }

    #[test]
    fn exec_command_after_double_dash_is_joined() {
        let c = Config::parse(&s(&[
            "--as", "claude-1", "node_7", "--", "ls", "-la", "/var/log",
        ]))
        .unwrap();
        assert_eq!(c.exec_cmd.as_deref(), Some("ls -la /var/log"));
    }

    // `--` without `--as` is not a mode this subcommand offers — `agent ssh-exec`
    // already exists for a human's own one-shot exec, and silently accepting it here
    // would grow a second, half-implemented copy of that command.
    #[test]
    fn exec_without_as_is_refused() {
        assert!(Config::parse(&s(&["node_1", "--token", "t", "--", "ls"])).is_err());
    }

    #[test]
    fn dash_dash_with_nothing_after_it_is_refused() {
        assert!(Config::parse(&s(&["--as", "claude-1", "node_7", "--"])).is_err());
    }

    // Mint path.
    #[test]
    fn cmd_freeform_parses_argv_and_reason() {
        let c = Config::parse(&s(&[
            "node_7",
            "--token",
            "t",
            "--for-actor",
            "act_1",
            "--cmd",
            "FREEFORM",
            "--reason",
            "diagnose disk",
            "--argv",
            "df",
            "-h",
            "/",
        ]))
        .unwrap();
        assert_eq!(c.cmd.as_deref(), Some("FREEFORM"));
        assert_eq!(c.for_actor.as_deref(), Some("act_1"));
        assert_eq!(c.cmd_reason.as_deref(), Some("diagnose disk"));
        assert_eq!(c.cmd_argv, vec!["df", "-h", "/"]);
        assert_eq!(c.token.as_deref(), Some("t"));
    }

    #[test]
    fn cmd_catalog_parses_repeated_params() {
        let c = Config::parse(&s(&[
            "node_7",
            "--token",
            "t",
            "--for-actor",
            "act_1",
            "--cmd",
            "restart-svc",
            "--param",
            "service=web",
            "--param",
            "graceful=true",
        ]))
        .unwrap();
        assert_eq!(c.cmd.as_deref(), Some("restart-svc"));
        assert_eq!(
            c.cmd_params,
            vec![
                ("service".to_string(), "web".to_string()),
                ("graceful".to_string(), "true".to_string()),
            ]
        );
    }

    #[test]
    fn param_without_equals_is_refused() {
        assert!(Config::parse(&s(&[
            "node_7",
            "--token",
            "t",
            "--for-actor",
            "a",
            "--cmd",
            "x",
            "--param",
            "nope"
        ]))
        .is_err());
    }

    // `--cmd` mints on the human's own authority — it has no `--as` variant.
    #[test]
    fn cmd_with_as_is_refused() {
        assert!(Config::parse(&s(&[
            "--as", "claude-1", "node_7", "--cmd", "FREEFORM", "--argv", "ls"
        ]))
        .is_err());
    }

    #[test]
    fn cmd_only_flags_without_cmd_are_refused() {
        assert!(Config::parse(&s(&["node_7", "--token", "t", "--for-actor", "a"])).is_err());
    }

    // Consume path — `--cmd-grant` only makes sense on an agent's own
    // connection, which authenticates by proof rather than a human session token.
    #[test]
    fn cmd_grant_needs_as() {
        assert!(Config::parse(&s(&["node_7", "--token", "t", "--cmd-grant", "tok"])).is_err());
    }

    #[test]
    fn cmd_grant_with_as_parses_and_needs_no_token() {
        let c = Config::parse(&s(&["--as", "claude-1", "node_7", "--cmd-grant", "tok"])).unwrap();
        assert_eq!(c.cmd_grant.as_deref(), Some("tok"));
        assert!(c.token.is_none());
    }

    #[test]
    fn cmd_grant_and_exec_together_refused() {
        assert!(Config::parse(&s(&[
            "--as",
            "claude-1",
            "node_7",
            "--cmd-grant",
            "tok",
            "--",
            "ls"
        ]))
        .is_err());
    }
}
