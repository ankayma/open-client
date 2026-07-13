//! ssh-exec — `agent ssh-exec`: run one command against a node's embedded SSH
//! server through an already-open SOCKS5 proxy. Exists so `agent ci-deploy`'s
//! `--exec` on a hosted CI runner (no kernel TUN) can finish a secretless deploy
//! without shelling out to system `ssh` + a static key. `[T:ci-deploy exec]`
//!
//! Reads `ANKAYMA_SOCKS_PROXY` + `ANKAYMA_TARGET_IP` — set by
//! `netstack::run_deploy` before it execs this as the deploy command — and an
//! optional `ANKAYMA_ELEVATE_GRANT` if the deploy needs root.

use agent_core::ssh_client::{MeshSshKey, SshConnectOptions, SshSession};
use anyhow::{anyhow, bail, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const DEFAULT_PORT: u16 = 22022;

/// `agent ssh-exec [--port <n>] -- <command...>`
pub async fn run(args: &[String]) -> Result<()> {
    let (port, command) = parse(args)?;

    let proxy_addr = std::env::var("ANKAYMA_SOCKS_PROXY").map_err(|_| {
        anyhow!("ANKAYMA_SOCKS_PROXY not set — run this under `agent ci-deploy --exec`")
    })?;
    let target_ip = std::env::var("ANKAYMA_TARGET_IP").map_err(|_| {
        anyhow!("ANKAYMA_TARGET_IP not set — run this under `agent ci-deploy --exec`")
    })?;

    let stream = socks5_connect(&proxy_addr, &target_ip, port).await?;

    // [A per owner 2026-07-14] no pinned host key on this path: the `ci-deploy`
    // control-plane exchange doesn't carry the target's SSH host key the way
    // `/ssh/session` does for F-2 interactive sessions (forward dependency, not
    // built here — would need a control-plane change to CiDeployResponse).
    // TOFU accepted deliberately: the WireGuard tunnel already authenticated the
    // peer (its pubkey came from the CP-verified ci-deploy grant, checked before
    // any SSH byte is sent) — this SSH layer is a second, redundant check on top
    // of that, not the only barrier against an impostor.
    let mut opts = SshConnectOptions::new(target_ip.clone(), "ankayma".to_string());
    opts.port = port;
    opts.allow_unpinned = true;
    if let Ok(grant) = std::env::var("ANKAYMA_ELEVATE_GRANT") {
        opts.elevate_grant = Some(grant);
    }

    // Ephemeral — never written to disk, matching ci_deploy's ephemeral WG
    // keypair (both die with this one CI run).
    let key = MeshSshKey::generate_ephemeral()?;
    let (code, output) = SshSession::exec_over_stream(stream, &opts, &key, &command).await?;

    tokio::io::stdout().write_all(&output).await.ok();
    std::process::exit(code as i32);
}

/// Dial the local SOCKS5 proxy `netstack::run_deploy` exposed and CONNECT to
/// `target_ip:target_port` over it. Matches the fixed reply shape our own
/// server (`netstack.rs::socks5_handshake`) sends — not full RFC-1928 client
/// generality, since this only ever talks to that one server.
async fn socks5_connect(proxy_addr: &str, target_ip: &str, target_port: u16) -> Result<TcpStream> {
    let mut stream = TcpStream::connect(proxy_addr)
        .await
        .map_err(|e| anyhow!("connect to SOCKS5 proxy {proxy_addr}: {e}"))?;
    // Greeting: VER=5, NMETHODS=1, METHODS=[0x00 no-auth].
    stream.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp).await?;
    if resp != [0x05, 0x00] {
        bail!("SOCKS5 proxy rejected no-auth (got {:?})", resp);
    }
    // CONNECT request: VER=5, CMD=1 (CONNECT), RSV=0, ATYP + DST.ADDR + DST.PORT.
    let ip: std::net::IpAddr = target_ip
        .parse()
        .map_err(|_| anyhow!("target IP {target_ip} not a literal IP"))?;
    let mut req = vec![0x05, 0x01, 0x00];
    match ip {
        std::net::IpAddr::V4(v4) => {
            req.push(0x01);
            req.extend_from_slice(&v4.octets());
        }
        std::net::IpAddr::V6(v6) => {
            req.push(0x04);
            req.extend_from_slice(&v6.octets());
        }
    }
    req.extend_from_slice(&target_port.to_be_bytes());
    stream.write_all(&req).await?;
    let mut head = [0u8; 4]; // VER, REP, RSV, ATYP
    stream.read_exact(&mut head).await?;
    if head[1] != 0x00 {
        bail!("SOCKS5 CONNECT failed, reply code {}", head[1]);
    }
    // Our server always replies ATYP=IPv4 (netstack.rs) — BND.ADDR(4) + BND.PORT(2).
    let mut bnd = [0u8; 6];
    stream.read_exact(&mut bnd).await?;
    Ok(stream)
}

fn parse(args: &[String]) -> Result<(u16, String)> {
    let mut port = DEFAULT_PORT;
    let mut rest: Vec<String> = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--port" => {
                port = it
                    .next()
                    .ok_or_else(|| anyhow!("--port needs a value"))?
                    .parse()
                    .map_err(|_| anyhow!("--port must be a number"))?;
            }
            "--" => rest.extend(it.by_ref().cloned()),
            other => rest.push(other.to_string()),
        }
    }
    if rest.is_empty() {
        bail!("usage: agent ssh-exec [--port <n>] -- <command...>");
    }
    Ok((port, rest.join(" ")))
}
