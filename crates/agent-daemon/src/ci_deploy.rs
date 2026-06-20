//! ci-deploy — `agent ci-deploy`: secretless deploy from CI (Part C §H.3.3, B-3).
//! OPEN, intensity Critical.
//!
//! Obtains a CI OIDC token (no static secret in CI), exchanges it for short-lived
//! mesh access, brings up the tunnel to the deploy target, and runs the deploy
//! command over it. The control plane verifies the token (closed IP); this side
//! only fetches + forwards it. `[T:A.1.4 golden rule]`
//!
//! [A] The github.com-hosted *userspace-only* path (no kernel TUN) plus NAT
//! traversal / relay fallback is the next load-bearing slice — Part C [R] R3 #12,
//! not yet live-tested. Today the tunnel reuses the same utun data plane as
//! `agent up`, i.e. needs a self-hosted runner (or any host with TUN). The
//! *secretless control channel* (token → ephemeral access) below is complete.

use agent_core::domain::CiDeployRequest;
use agent_core::{adapters, oidc, reqwest, WgKeypair};
use anyhow::{anyhow, Result};

use crate::up::{self, AfterUp, AgentState};

const DEFAULT_CONTROL_PLANE: &str = "https://cp.ankayma.com";
const DEFAULT_AUDIENCE: &str = "ankayma-deploy"; // [T:Part C §H.3.3] DEPLOY_AUDIENCE
const DEFAULT_LISTEN_PORT: u16 = 51820; // [T:wg(8)] WireGuard's default UDP port

/// `agent ci-deploy [--control-plane <url>] [--audience <a>] [--port <n>]
///                  [--hostname <h>] [--exec <cmd> <args…>]`
pub async fn run(args: &[String]) -> Result<()> {
    let cfg = Config::parse(args)?;
    let http = reqwest::Client::new();

    // 1. [T:Part C §H.3.3 B-3] fetch the CI OIDC token — the secretless credential.
    let token = oidc::fetch_ci_token(&http, &cfg.audience)
        .await
        .map_err(|e| anyhow!("obtain CI OIDC token: {e}"))?;

    // 2. ephemeral identity for this one deploy run (key never persisted).
    let kp = WgKeypair::generate();
    let hostname = cfg
        .hostname
        .clone()
        .or_else(|| std::env::var("GITHUB_REPOSITORY").ok());

    // 3. exchange the token for ephemeral mesh access.
    let resp = adapters::ci_deploy(
        &http,
        &cfg.control_plane,
        &CiDeployRequest {
            token,
            public_key: kp.public_b64.clone(),
            hostname,
        },
    )
    .await
    .map_err(|e| anyhow!("ci-deploy exchange: {e}"))?;

    println!(
        "ephemeral access granted: node {} overlay {} (expires in {}s)",
        resp.node_id, resp.overlay_ip, resp.expires_in_seconds
    );
    match resp.target.as_ref() {
        Some(t) => println!("deploy target: {} ({})", t.hostname, t.overlay_ip),
        None => println!("no deploy target in policy — bringing up mesh access only."),
    }

    // --dry-run: stop after the secretless control-channel (token verified, ephemeral
    // grant issued, access audited). Proves B-1/B-2/B-4 live WITHOUT needing a TUN —
    // so it runs on a Linux/hosted CI runner where the data plane is still `[A]`
    // (macOS-only utun at 1.1; userspace Linux transport = R3 #12, pending).
    if cfg.dry_run {
        println!("dry-run: secretless access verified + audited; tunnel not attempted.");
        return Ok(());
    }

    // 4. bring up the tunnel and run the deploy command over it, then tear down.
    let state = AgentState {
        private_b64: kp.private_b64,
        public_b64: kp.public_b64,
        node_id: resp.node_id,
        overlay_ip: resp.overlay_ip,
        listen_port: cfg.listen_port,
    };
    let initial: Vec<_> = resp.target.into_iter().collect();
    up::serve_dataplane(&state, initial, AfterUp::Oneshot(cfg.exec)).await
}

struct Config {
    control_plane: String,
    audience: String,
    listen_port: u16,
    hostname: Option<String>,
    exec: Option<Vec<String>>,
    dry_run: bool,
}

impl Config {
    fn parse(args: &[String]) -> Result<Self> {
        let mut control_plane = std::env::var("ANKAYMA_CONTROL_PLANE")
            .unwrap_or_else(|_| DEFAULT_CONTROL_PLANE.to_string());
        let mut audience = DEFAULT_AUDIENCE.to_string();
        let mut listen_port = DEFAULT_LISTEN_PORT;
        let mut hostname = None;
        let mut exec = None;
        let mut dry_run = false;

        let mut it = args.iter();
        while let Some(a) = it.next() {
            match a.as_str() {
                "--control-plane" => {
                    control_plane = it
                        .next()
                        .ok_or_else(|| anyhow!("--control-plane needs a value"))?
                        .clone()
                }
                "--audience" => {
                    audience = it
                        .next()
                        .ok_or_else(|| anyhow!("--audience needs a value"))?
                        .clone()
                }
                "--port" => {
                    listen_port = it
                        .next()
                        .ok_or_else(|| anyhow!("--port needs a value"))?
                        .parse()
                        .map_err(|_| anyhow!("--port must be a number"))?
                }
                "--hostname" => {
                    hostname = Some(
                        it.next()
                            .ok_or_else(|| anyhow!("--hostname needs a value"))?
                            .clone(),
                    )
                }
                "--dry-run" => dry_run = true,
                // Everything after --exec is the deploy command (run over the tunnel).
                "--exec" => exec = Some(it.by_ref().cloned().collect()),
                other => return Err(anyhow!("unknown argument: {other}")),
            }
        }
        Ok(Config {
            control_plane,
            audience,
            listen_port,
            hostname,
            exec,
            dry_run,
        })
    }
}
