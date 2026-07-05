//! ssh_serve — run the F-2 embedded SSH server standalone, for VALIDATION only
//! (e.g. testing macOS-as-target without the full dataplane). Not shipped in the
//! agent (the server runs inside `agent up` in production).
//!
//!   ssh_serve <bind_ip> [port]     # run as root to exercise provisioning + su

use agent_core::ssh_server::{serve, SshHostKey, SshServerConfig};

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let bind = args
        .get(1)
        .cloned()
        .unwrap_or_else(|| "127.0.0.1".to_string());
    let port: u16 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(22022);

    let key = SshHostKey::load_or_generate(std::path::Path::new("/tmp/f2-ssh-serve-hostkey"))
        .expect("host key");
    println!("host key: {}", key.public_openssh().unwrap());
    let mut cfg = SshServerConfig::f0(bind);
    cfg.port = port;
    println!(
        "[ssh_serve] serving on {}:{} (user ankayma)",
        cfg.bind_ip, cfg.port
    );
    if let Err(e) = serve(cfg, key).await {
        eprintln!("[ssh_serve] {e}");
    }
}
