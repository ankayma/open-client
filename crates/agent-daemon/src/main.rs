//! mesh agent daemon — single binary, 5 platform targets (Linux/macOS/Windows/iOS/Android).
//! Part D §D.1.3 (Deployable 1). OPEN.
//!
//! Gate A.1.4 slice (real test): client-side XChaCha20-Poly1305 (AEAD) over real NATS.
//! Usage: `agent <nats-url> <user> <password> <subject-prefix> <canary>`
//!
//! Pass case (default build): session key (32 bytes) is held in client process memory
//! and never published to NATS. Client publishes 7 ciphertext envelopes (per spec
//! coverage: text · attachment · structured · rotated-key · sync-multi-device ·
//! reconnect/retry · response lỗi) on `<subject-prefix>.<kind>`. Each envelope =
//! 24-byte nonce || ciphertext+tag. Vendor sees ciphertext only.
//!
//! NC build (`key-escrow-build`): the same session key is ALSO published on
//! `<subject-prefix>.key.escrow` — vendor recovers via subscribe.

mod agent_identity;
mod agent_token;
mod ci_deploy;
mod ci_policy;
mod netstack;
mod resolve;
mod resolver;
mod ssh;
mod tls_relay;
mod tun;
mod up;

use anyhow::Result;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::rngs::OsRng;
use rand::RngCore;

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    // `agent up …` brings the WireGuard overlay online (data plane);
    // `agent ci-deploy …` does a secretless CI deploy (Part C §H.3.3);
    // `agent ssh <node> …` opens a Sovereign SSH session (F-2, Part C §H.3.6.1);
    // `agent enroll-identity …` redeems a non-human/agent identity (F-4). Anything
    // else stays the existing Gate A.1.4 NATS encryption harness.
    match args.first().map(String::as_str) {
        Some("up") => up::run(&args[1..]).await,
        Some("ci-deploy") => ci_deploy::run(&args[1..]).await,
        Some("ssh") => ssh::run(&args[1..]).await,
        Some("resolve") => resolve::run(&args[1..]).await,
        Some("ci-policy") => ci_policy::run(&args[1..]).await,
        Some("agent-token") => agent_token::run(&args[1..]).await,
        Some("enroll-identity") => agent_identity::run(&args[1..]).await,
        _ => run_gate(args).await,
    }
}

async fn run_gate(args: Vec<String>) -> Result<()> {
    if args.len() < 5 {
        eprintln!("usage: agent <nats-url> <user> <password> <subject-prefix> <canary>");
        eprintln!("   or: agent up [--token <t>] [--control-plane <url>] [--port <n>]");
        std::process::exit(2);
    }
    let url = &args[0];
    let user = &args[1];
    let pass = &args[2];
    let prefix = args[3].clone();
    let canary = &args[4];

    // Session key in client memory only.
    let mut key_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut key_bytes);
    let cipher = XChaCha20Poly1305::new((&key_bytes).into());

    let client = async_nats::ConnectOptions::with_user_and_password(user.clone(), pass.clone())
        .name("gate-a-1-4-agent")
        .connect(url)
        .await?;

    // Coverage cases per spec.
    let kinds: &[&str] = &[
        "text",
        "attachment",
        "structured",
        "rotated",
        "sync-dev2",
        "reconnect",
        "error-resp",
    ];

    for kind in kinds {
        let plaintext = format!("{kind}:{canary}");
        // Rotated-key case: derive a fresh subkey for this message (still client-only).
        let use_cipher = if *kind == "rotated" {
            let mut k2 = key_bytes;
            k2.rotate_left(1);
            XChaCha20Poly1305::new((&k2).into())
        } else {
            cipher.clone()
        };

        let mut nonce_bytes = [0u8; 24];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = XNonce::from_slice(&nonce_bytes);
        let ct = use_cipher
            .encrypt(nonce, plaintext.as_bytes())
            .map_err(|e| anyhow::anyhow!("encrypt: {e:?}"))?;

        // Envelope = nonce || ciphertext+tag
        let mut envelope = Vec::with_capacity(24 + ct.len());
        envelope.extend_from_slice(&nonce_bytes);
        envelope.extend_from_slice(&ct);

        client
            .publish(format!("{prefix}.{kind}"), envelope.into())
            .await?;
    }

    // NC bug: client escrows the session key onto a NATS subject vendor can subscribe to.
    if cfg!(feature = "key-escrow-build") {
        client
            .publish(format!("{prefix}.key.escrow"), key_bytes.to_vec().into())
            .await?;
        eprintln!("agent NC: escrowed session key onto {prefix}.key.escrow");
    }

    client.flush().await?;
    Ok(())
}
