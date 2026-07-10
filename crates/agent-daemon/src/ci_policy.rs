//! ci-policy — `agent ci-policy {list|add|rm}`: manage F0 CI/CD deploy rules.
//! OPEN. Uses the SAME control-plane endpoints + adapters as the GUI
//! (feature-03b-gui-spec.md §1.7), so GUI and CLI produce identical data —
//! neither is the mandatory door. Safe-by-default is server-enforced; the CLI
//! only mirrors the ref-XOR-environment rule for an early, clear error. [T:A.1.3]

use agent_core::domain::CiPolicyReq;
use agent_core::{adapters, reqwest};
use anyhow::{anyhow, bail, Result};

const DEFAULT_CONTROL_PLANE: &str = "https://cp.ankayma.com";

const USAGE: &str = "usage:\n  \
    agent ci-policy list\n  \
    agent ci-policy add <owner/repo> (--ref <r> | --environment <e>) [--issuer github|gitlab] [--target <host>]\n  \
    agent ci-policy rm <owner/repo>\n\
    common: [--token <t>|$ANKAYMA_TOKEN] [--control-plane <url>|$ANKAYMA_CONTROL_PLANE]";

/// Value following `--name`, if present.
fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1).cloned())
}

/// Control-plane URL + session token, from flags or env (token is required).
fn resolve(args: &[String]) -> Result<(String, String)> {
    let control_plane = flag(args, "--control-plane")
        .or_else(|| std::env::var("ANKAYMA_CONTROL_PLANE").ok())
        .unwrap_or_else(|| DEFAULT_CONTROL_PLANE.to_string());
    let token = flag(args, "--token")
        .or_else(|| std::env::var("ANKAYMA_TOKEN").ok())
        .ok_or_else(|| {
            anyhow!("a session token is required: pass --token <t> or set ANKAYMA_TOKEN")
        })?;
    Ok((control_plane, token))
}

/// First positional (not a `--flag`) in `args`.
fn positional(args: &[String]) -> Option<String> {
    args.iter().find(|a| !a.starts_with("--")).cloned()
}

pub async fn run(args: &[String]) -> Result<()> {
    let http = reqwest::Client::new();
    match args.first().map(String::as_str) {
        Some("list") => {
            let (cp, token) = resolve(&args[1..])?;
            let policies = adapters::list_ci_policies(&http, &cp, &token)
                .await
                .map_err(|e| anyhow!("{e}"))?;
            if policies.is_empty() {
                println!("No deploy rules.");
                return Ok(());
            }
            for p in policies {
                let scope = p
                    .git_ref
                    .map(|r| format!("ref={r}"))
                    .or_else(|| p.environment.map(|e| format!("env={e}")))
                    .unwrap_or_else(|| "-".into());
                println!(
                    "{:<28} {:<7} {:<26} -> {}",
                    p.repo,
                    p.issuer,
                    scope,
                    p.target_hostname.unwrap_or_else(|| "-".into())
                );
            }
            Ok(())
        }
        Some("add") => {
            let rest = &args[1..];
            let repo = positional(rest).ok_or_else(|| anyhow!("missing <owner/repo>\n{USAGE}"))?;
            let (cp, token) = resolve(rest)?;
            let git_ref = flag(rest, "--ref");
            let environment = flag(rest, "--environment");
            // Exactly one scope — mirror server safe-by-default for an early error.
            if git_ref.is_some() == environment.is_some() {
                bail!("pick exactly one of --ref or --environment");
            }
            let req = CiPolicyReq {
                issuer: flag(rest, "--issuer").unwrap_or_else(|| "github".into()),
                repo: repo.clone(),
                git_ref,
                environment,
                target_hostname: flag(rest, "--target"),
            };
            // CLI passes no step-up proof. On a paid tier the server will answer
            // STEP_UP_REQUIRED; interactive CLI step-up is a separate item. F0 (no
            // gate) works as before. [A: CLI step-up TODO]
            adapters::register_ci_policy(&http, &cp, &token, &req, None)
                .await
                .map_err(|e| anyhow!("{e}"))?;
            println!("ok: {repo}");
            Ok(())
        }
        Some("rm") => {
            let rest = &args[1..];
            let repo = positional(rest).ok_or_else(|| anyhow!("missing <owner/repo>\n{USAGE}"))?;
            let (cp, token) = resolve(rest)?;
            adapters::delete_ci_policy(&http, &cp, &token, &repo, None)
                .await
                .map_err(|e| anyhow!("{e}"))?;
            println!("deleted: {repo}");
            Ok(())
        }
        _ => {
            eprintln!("{USAGE}");
            std::process::exit(2);
        }
    }
}
