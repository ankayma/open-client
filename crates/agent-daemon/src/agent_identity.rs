//! agent-identity — `agent enroll-identity`: redeem a scoped, short-TTL, single-use
//! identity for a non-human actor (script / AI agent). F-4 (Part C §H.3.3).
//! OPEN, intensity Critical.
//!
//! A tenant mints the token (`POST /api/v1/agents/token`, session-authed). The agent
//! presents it here — the token IS the credential, no static secret persisted. The
//! control plane records the agent as a FIRST-CLASS actor in the audit ledger and
//! returns ephemeral mesh access + a tamper-evident receipt. The wow is the *proof*
//! (scoped, time-limited, secret-residue zero, in the ledger), not the connection.
//!
//! [A] Bringing the data path up afterwards reuses the same userspace/NAT slice as
//! `ci-deploy` (Part C [R] R3 #12), still pending. This subcommand redeems the
//! identity and surfaces the receipt; wiring the tunnel is the next slice.

use agent_core::domain::AgentEnrollRequest;
use agent_core::{adapters, reqwest, WgKeypair};
use anyhow::{anyhow, Result};

const DEFAULT_CONTROL_PLANE: &str = "https://cp.ankayma.com";

/// `agent enroll-identity --token <t> [--control-plane <url>] [--hostname <h>]`
pub async fn run(args: &[String]) -> Result<()> {
    let cfg = Config::parse(args)?;
    let http = reqwest::Client::new();

    // Ephemeral identity for this one grant (key never persisted) — secret-residue zero.
    let kp = WgKeypair::generate();

    let resp = adapters::agent_enroll(
        &http,
        &cfg.control_plane,
        &AgentEnrollRequest {
            token: cfg.token,
            public_key: kp.public_b64.clone(),
            hostname: cfg.hostname,
        },
    )
    .await
    .map_err(|e| anyhow!("agent identity redeem: {e}"))?;

    println!(
        "ephemeral access granted: node {} overlay {} (expires in {}s)",
        resp.node_id, resp.overlay_ip, resp.expires_in_seconds
    );
    print_agent_receipt(&resp.receipt, &cfg.control_plane);
    Ok(())
}

/// [F-4] Print the agent receipt — a non-human actor, scoped, time-limited,
/// first-class in the ledger, with zero secret residue. Include the re-verify command.
fn print_agent_receipt(r: &agent_core::domain::AgentReceipt, control_plane: &str) {
    println!("\n── Agent identity receipt ────────────────────────────");
    println!("  run            {}", r.run_id);
    println!("  agent          {}", r.agent_name);
    println!("  actor          {}", r.actor_kind);
    println!("  scope          {}", r.scope);
    println!("  expires in     {}s", r.ttl_seconds);
    println!("  secret residue {}", r.secret_residue);
    println!(
        "  ledger anchor  {}:{}",
        r.ledger_event, r.ledger_block_hash
    );
    println!(
        "  verify         curl {}/api/v1/agents/receipt/{}",
        control_plane.trim_end_matches('/'),
        r.run_id
    );
}

struct Config {
    control_plane: String,
    token: String,
    hostname: Option<String>,
}

impl Config {
    fn parse(args: &[String]) -> Result<Self> {
        let mut control_plane = std::env::var("ANKAYMA_CONTROL_PLANE")
            .unwrap_or_else(|_| DEFAULT_CONTROL_PLANE.to_string());
        let mut token = std::env::var("ANKAYMA_AGENT_TOKEN").ok();
        let mut hostname = None;

        let mut it = args.iter();
        while let Some(a) = it.next() {
            match a.as_str() {
                "--control-plane" => {
                    control_plane = it
                        .next()
                        .ok_or_else(|| anyhow!("--control-plane needs a value"))?
                        .clone()
                }
                "--token" => {
                    token = Some(
                        it.next()
                            .ok_or_else(|| anyhow!("--token needs a value"))?
                            .clone(),
                    )
                }
                "--hostname" => {
                    hostname = Some(
                        it.next()
                            .ok_or_else(|| anyhow!("--hostname needs a value"))?
                            .clone(),
                    )
                }
                other => return Err(anyhow!("unknown argument: {other}")),
            }
        }
        let token = token.ok_or_else(|| {
            anyhow!("missing identity token — pass --token <t> or set ANKAYMA_AGENT_TOKEN")
        })?;
        Ok(Config {
            control_plane,
            token,
            hostname,
        })
    }
}
