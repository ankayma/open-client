//! resolve — `agent resolve [<name>]`: F-3 private-default DNS (Part C §H.3.6.1).
//! OPEN, intensity Standard.
//!
//! Fetches the tenant's mesh-resolve table (`GET /api/v1/mesh/resolve`) and resolves
//! a branded name to its overlay address. The table is served ONLY to an enrolled
//! device — a non-enrolled caller gets 401, i.e. the name simply does not exist for
//! it (private-default). A revoked target node drops its name server-side (instant
//! revoke). Resolution + the subsequent connection are direct over the mesh overlay;
//! the vendor is the control channel only, never on the data path (A.1.1).
//!
//! Transparent OS-level resolution (so a browser "just works" on the name) is the
//! agent's local resolver — that OS plumbing is a later slice; this command proves
//! the table + the enrolled-only / revoke properties end-to-end today.

use agent_core::domain::ResolveTable;
use agent_core::{adapters, reqwest};
use anyhow::{anyhow, Result};

const DEFAULT_CONTROL_PLANE: &str = "https://cp.ankayma.com";

/// `agent resolve [<name>] [--token <t>] [--control-plane <url>]`
///
/// With a name → print the overlay address it resolves to (or that it does not
/// resolve). Without a name → print the whole private table this device can see.
pub async fn run(args: &[String]) -> Result<()> {
    let cfg = Config::parse(args)?;
    let http = reqwest::Client::new();

    let table = adapters::resolve_subdomains(&http, &cfg.control_plane, &cfg.token)
        .await
        .map_err(|e| anyhow!("fetch resolve table: {e}"))?;

    match &cfg.name {
        Some(query) => resolve_one(&table, query),
        None => print_table(&table),
    }
    Ok(())
}

/// Resolve a single name — match by exact FQDN or by short label. A miss is the
/// honest answer: the name does not exist for this device (not enrolled-for-it /
/// revoked / never registered). [P.3]
fn resolve_one(table: &ResolveTable, query: &str) {
    let hit = table
        .names
        .iter()
        .find(|n| n.fqdn == query || n.label == query);
    match hit {
        Some(n) => {
            println!("{}  →  {}", n.fqdn, n.overlay_ip);
            println!("\n── Path ──────────────────────────────────────────────");
            println!("  resolved mesh-internal (private-default); reachable only");
            println!("  from this enrolled device, direct over the overlay [A.1.1].");
        }
        None => {
            println!("{query}  →  does not resolve");
            println!("  (not a name this device can reach — unregistered, or its");
            println!("   target node was revoked, or you are not enrolled for it.)");
        }
    }
}

fn print_table(table: &ResolveTable) {
    if table.names.is_empty() {
        println!("no branded names in zone {} for this device.", table.zone);
        return;
    }
    println!(
        "── Private names (zone {}) ───────────────────────────",
        table.zone
    );
    for n in &table.names {
        println!("  {:<40}  {}", n.fqdn, n.overlay_ip);
    }
}

struct Config {
    name: Option<String>,
    token: String,
    control_plane: String,
}

impl Config {
    fn parse(args: &[String]) -> Result<Self> {
        let mut name: Option<String> = None;
        let mut token = std::env::var("ANKAYMA_TOKEN").ok();
        let mut control_plane = std::env::var("ANKAYMA_CONTROL_PLANE")
            .unwrap_or_else(|_| DEFAULT_CONTROL_PLANE.to_string());

        let mut it = args.iter();
        while let Some(a) = it.next() {
            match a.as_str() {
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
                other if other.starts_with("--") => {
                    return Err(anyhow!("unknown argument: {other}"))
                }
                other => {
                    if name.is_some() {
                        return Err(anyhow!("unexpected extra argument: {other}"));
                    }
                    name = Some(other.to_string());
                }
            }
        }
        let token = token
            .filter(|t| !t.trim().is_empty())
            .ok_or_else(|| anyhow!("no session token — pass --token <t> or set ANKAYMA_TOKEN"))?;
        Ok(Config {
            name,
            token,
            control_plane,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_core::domain::ResolvedName;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    fn table() -> ResolveTable {
        ResolveTable {
            zone: "int.ankayma.com".into(),
            names: vec![ResolvedName {
                fqdn: "epos.acme.int.ankayma.com".into(),
                label: "epos".into(),
                overlay_ip: "fd00::2".into(),
                target_node_id: "node-1".into(),
                target_port: 80,
            }],
        }
    }

    #[test]
    fn parses_optional_name_and_token() {
        let c = Config::parse(&s(&["epos", "--token", "tok"])).unwrap();
        assert_eq!(c.name.as_deref(), Some("epos"));
        assert_eq!(c.token, "tok");
        // no name is valid (means "print whole table").
        assert!(Config::parse(&s(&["--token", "tok"]))
            .unwrap()
            .name
            .is_none());
    }

    #[test]
    fn requires_token_and_rejects_junk() {
        if std::env::var("ANKAYMA_TOKEN").is_err() {
            assert!(Config::parse(&s(&["epos"])).is_err());
        }
        assert!(Config::parse(&s(&["--bogus", "--token", "t"])).is_err());
        assert!(Config::parse(&s(&["a", "b", "--token", "t"])).is_err());
    }

    #[test]
    fn matches_by_fqdn_or_label() {
        let t = table();
        // both the short label and the full FQDN find the same entry.
        assert!(t.names.iter().any(|n| n.label == "epos"));
        assert!(t
            .names
            .iter()
            .any(|n| n.fqdn == "epos.acme.int.ankayma.com"));
        // a name not in the table is a miss (does-not-resolve).
        assert!(!t.names.iter().any(|n| n.label == "ghost"));
    }
}
