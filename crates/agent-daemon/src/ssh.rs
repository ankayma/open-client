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

use agent_core::domain::{SshSessionReceipt, SshSessionRequest};
use agent_core::{adapters, reqwest};
use anyhow::{anyhow, Result};

const DEFAULT_CONTROL_PLANE: &str = "https://cp.ankayma.com";

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

    // The effective login: server-sanitized echo wins; else what we asked for;
    // else `root`. F-2 targets are servers ("SSH into prod") — without a default
    // the system ssh falls back to the LOCAL username (e.g. `alice`), which
    // almost never exists on the box and dead-ends at a password prompt. `root`
    // is the near-universal server login; override with `--login <user>`.
    let login = resp
        .login
        .or(cfg.login)
        .or_else(|| Some("root".to_string()));
    let dest = match &login {
        Some(u) => format!("{u}@{}", resp.overlay_ip),
        None => resp.overlay_ip.clone(),
    };

    if cfg.print_only {
        println!("\nssh {dest}");
        return Ok(());
    }

    // 3. Exec the system ssh straight to the overlay address (interactive TTY).
    // [A.1.1] direct over the mesh — vendor not on this path.
    // `accept-new`: the overlay address is a fresh, tenant-scoped identity the
    // user has never seen — a raw `ssh` blocks on the interactive "authenticity
    // of host … can't be established (yes/no)?" prompt, which reads as a hang in
    // the GUI-launched Terminal (F-2). accept-new trusts on first use and still
    // hard-fails on a later key CHANGE (MITM), unlike `no`.
    // `ServerAliveInterval`: an idle session that got torn down (idle-teardown)
    // re-handshakes transparently; keepalives keep the client from giving up
    // during that one-RTT gap. `[T:ssh_config(5)]`
    println!("\n── Connecting ────────────────────────────────────────");
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
}

impl Config {
    fn parse(args: &[String]) -> Result<Self> {
        let mut node_id: Option<String> = None;
        let mut login = None;
        let mut token = std::env::var("ANKAYMA_TOKEN").ok();
        let mut control_plane = std::env::var("ANKAYMA_CONTROL_PLANE")
            .unwrap_or_else(|_| DEFAULT_CONTROL_PLANE.to_string());
        let mut print_only = false;

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
