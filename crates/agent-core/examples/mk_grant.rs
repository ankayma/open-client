//! mk_grant — sign an F-2 elevation grant with the CP's key, for VALIDATION only.
//!
//! Reuses the exact `ssh_grant` code the control plane uses, so the token format is
//! guaranteed to match what a node verifies. Reads the base64 signing seed from
//! `SSH_ELEVATE_SIGNING_KEY` (never on the command line) and prints a grant token.
//!
//!   SSH_ELEVATE_SIGNING_KEY=<base64-32B> \
//!     cargo run --example mk_grant -- <node_id> [ttl_secs]
//!
//! This is a test tool — run it on the CP host where the signing key lives; it must
//! NOT ship in the agent (a client must never be able to sign its own grants).

use agent_core::ssh_grant::{ElevationGrant, GrantSigner};
use base64::{engine::general_purpose::STANDARD, Engine as _};

fn main() {
    let seed_b64 = std::env::var("SSH_ELEVATE_SIGNING_KEY")
        .expect("set SSH_ELEVATE_SIGNING_KEY (base64 32-byte seed)");
    let seed_bytes = STANDARD
        .decode(seed_b64.trim())
        .expect("SSH_ELEVATE_SIGNING_KEY not base64");
    let seed: [u8; 32] = seed_bytes
        .as_slice()
        .try_into()
        .expect("seed must be 32 bytes");

    let args: Vec<String> = std::env::args().collect();
    let node_id = args
        .get(1)
        .expect("usage: mk_grant <node_id> [ttl_secs]")
        .clone();
    let ttl: i64 = args.get(2).map(|s| s.parse().unwrap_or(900)).unwrap_or(900);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    let signer = GrantSigner::from_seed(&seed);
    let grant = ElevationGrant {
        node_id,
        persona: "root".to_string(),
        login: "root".to_string(),
        device_fp: String::new(),
        session_id: format!("elev_test_{now}"),
        issued_at: now,
        expires_at: now + ttl,
    };
    println!("{}", signer.sign(&grant).expect("sign grant"));
}
