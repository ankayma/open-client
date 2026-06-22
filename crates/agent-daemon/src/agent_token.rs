//! agent-token — `agent agent-token`: mint a single-use agent identity token (F-4)
//! for a headless / non-human actor (CI runner, VPS) that cannot do interactive
//! GitHub OAuth. Run on an already-authenticated device (owner's session); the
//! headless node then redeems with `agent enroll-identity --token <minted>`.
//! OPEN. `[T:Part C §H.3.3 / F-4]`

use agent_core::{adapters, reqwest};
use anyhow::{anyhow, Result};

const DEFAULT_CONTROL_PLANE: &str = "https://cp.ankayma.com";

const USAGE: &str =
    "usage: agent agent-token --name <agent-name> [--scope <s>] [--ttl <secs>]\n       \
    [--token <session>|$ANKAYMA_TOKEN] [--control-plane <url>|$ANKAYMA_CONTROL_PLANE]";

fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1).cloned())
}

pub async fn run(args: &[String]) -> Result<()> {
    let name = flag(args, "--name").ok_or_else(|| anyhow!("missing --name\n{USAGE}"))?;
    let scope = flag(args, "--scope");
    let ttl = flag(args, "--ttl").and_then(|s| s.parse::<u64>().ok());
    let control_plane = flag(args, "--control-plane")
        .or_else(|| std::env::var("ANKAYMA_CONTROL_PLANE").ok())
        .unwrap_or_else(|| DEFAULT_CONTROL_PLANE.to_string());
    let token = flag(args, "--token")
        .or_else(|| std::env::var("ANKAYMA_TOKEN").ok())
        .ok_or_else(|| anyhow!("a session token is required: --token <t> or $ANKAYMA_TOKEN"))?;

    let http = reqwest::Client::new();
    // Raw JSON body (mint token + receipt). Copy the token, then on the headless
    // node: `agent enroll-identity --token <minted>`.
    let body =
        adapters::mint_agent_token(&http, &control_plane, &token, &name, scope.as_deref(), ttl)
            .await
            .map_err(|e| anyhow!("{e}"))?;
    println!("{body}");
    Ok(())
}
