//! ci-deploy — `agent ci-deploy`: secretless deploy from CI (Part C §H.3.3, B-3).
//! OPEN, intensity Critical.
//!
//! Obtains a CI OIDC token (no static secret in CI), exchanges it for short-lived
//! mesh access, brings up the tunnel to the deploy target, and runs the deploy
//! command over it. The control plane verifies the token (closed IP); this side
//! only fetches + forwards it. `[T:A.1.4 golden rule]`
//!
//! The github.com-hosted *userspace-only* path (no kernel TUN) is wired via
//! `netstack` (smoltcp + boringtun over a local SOCKS5 proxy) and was E2E-proven
//! SaaS-runner→VPS, secretless (2026-06-21, T-0039). The remaining load-bearing
//! slice is NAT traversal / relay fallback for targets behind strict NAT —
//! Part C [R] R3 #12 `[A-p]`; direct peer-to-peer (reachable endpoint) works today.

use agent_core::domain::CiDeployRequest;
use agent_core::{adapters, oidc, reqwest, WgKeypair};
use anyhow::{anyhow, Result};

use crate::up::AgentState;

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

    // [F-1] The wow is the *proof*, not the connection: show the signed
    // run-receipt the control plane just anchored into its append-only audit ledger.
    print_receipt(resp.receipt.as_ref(), &cfg.control_plane);

    // --dry-run: stop after the secretless control-channel (token verified, ephemeral
    // grant issued, access audited). Proves B-1/B-2/B-4 live WITHOUT needing a TUN —
    // so it runs on a Linux/hosted CI runner where the data plane is still `[A]`
    // (macOS-only utun at 1.1; userspace Linux transport = R3 #12, pending).
    if cfg.dry_run {
        // [F-5] Path-proof is strongest once a data path comes up; --dry-run brings
        // none up, so state that honestly (P.3) — control channel only this run.
        println!("── Path ──────────────────────────────────────────────");
        println!("  data plane   not established (--dry-run): control channel only");
        println!("dry-run: secretless access verified + audited; tunnel not attempted.");
        return Ok(());
    }

    // 4. bring up the tunnel and run the deploy command over it, then tear down.
    // [T:R3 #12] Hosted CI runners have no kernel TUN, so the deploy runs over a
    // USERSPACE TCP/IP stack (smoltcp) exposed as a SOCKS5 proxy — `netstack`.
    // The kernel-TUN path (`up::serve_dataplane`) is for `agent up` on a host that
    // can create a utun/tun device (the target server), not the runner.
    let target = resp.target.ok_or_else(|| {
        anyhow!(
            "policy named no deploy target — nothing to deploy to. \
             Register a policy with a target_hostname, or use --dry-run."
        )
    })?;

    // [F-5 / A.1.1] Path-proof: the data plane is a direct WireGuard tunnel to the
    // target peer — the control plane (vendor) is the control channel only, never on
    // the data path. No NAT-fallback relay exists yet, so this run is peer-to-peer.
    print_path_proof(&target, &cfg.control_plane);

    let state = AgentState {
        private_b64: kp.private_b64,
        public_b64: kp.public_b64,
        node_id: resp.node_id,
        overlay_ip: resp.overlay_ip,
        listen_port: cfg.listen_port,
        // Ephemeral CI node — no persistent service token.
        service_token: None,
        token_expires_at: None,
        workload_kind: Some("BatchWorker".to_string()),
        // Ephemeral CI node — lives minutes, never dials the broker: no Layer 2
        // cert material. [T:part-d-layer2-cert-infrastructure.md §H.3 F-x rows]
        node_cert_pem: None,
        provisioning_ca_pem: None,
        crl_pem: None,
        crl_url: None,
        cert_expires_at: None,
    };
    // The data plane is blocking (smoltcp poll loop + std process spawn); run it off
    // the async runtime so we don't stall the executor.
    tokio::task::spawn_blocking(move || crate::netstack::run_deploy(&state, target, cfg.exec))
        .await
        .map_err(|e| anyhow!("deploy task panicked: {e}"))?
}

/// [F-1] Print the signed run-receipt — "evidence you hold", not
/// "secretless" alone. The receipt is tamper-evident via the ledger anchor; print a
/// re-verify command so the user can prove it independently against the live ledger.
fn print_receipt(receipt: Option<&agent_core::domain::DeployReceipt>, control_plane: &str) {
    let Some(r) = receipt else {
        // Older control plane, or a denied/edge path — nothing to show, don't fake it.
        return;
    };
    println!("\n── Signed run-receipt ────────────────────────────────");
    println!("  run            {}", r.run_id);
    println!("  repo           {}", r.repo);
    println!("  ref            {}", r.git_ref);
    println!("  issuer         {}", r.issuer);
    if let Some(env) = &r.environment {
        println!("  environment    {env}");
    }
    if let Some(t) = &r.target {
        println!("  service        {t}");
    }
    println!("  scope          {}", r.scope);
    println!(
        "  static secret  {}",
        if r.static_secret { "yes" } else { "none" }
    );
    // Honest about the F0 ceiling (P.3): tamper-evident now, customer-signed is Part C.
    let signing = if r.customer_signed {
        "customer-key signed"
    } else {
        "tamper-evident (ledger hash-chain) — customer-key signing is Part C"
    };
    println!("  proof          {signing}");
    println!(
        "  ledger anchor  {}:{}",
        r.ledger_event, r.ledger_block_hash
    );
    println!(
        "  verify         curl {}/api/v1/ci/receipt/{}",
        control_plane.trim_end_matches('/'),
        r.run_id
    );
}

/// [F-5 / A.1.1] Print the path-proof: data plane peer-to-peer, vendor off the path.
fn print_path_proof(target: &agent_core::domain::PeerInfo, control_plane: &str) {
    println!("\n── Path ──────────────────────────────────────────────");
    match &target.endpoint {
        Some(ep) => println!(
            "  data plane     direct WireGuard → {} ({ep})",
            target.hostname
        ),
        None => println!(
            "  data plane     direct WireGuard → {} (peer-to-peer)",
            target.hostname
        ),
    }
    println!(
        "  vendor         {} — control channel only, NOT on the data path [A.1.1]",
        control_plane.trim_end_matches('/')
    );
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
