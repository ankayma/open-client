//! up — `agent up`: bring the WireGuard overlay online. OPEN, intensity Critical.
//!
//! The data-plane half that milestone 1.1 left as `[A]`: take this node's
//! identity + the control plane's metadata-only peer list (`[T:A.1.1]`) and move
//! real encrypted packets between two machines.
//!
//! Flow:
//!   1. load (or create + enroll) this node's identity → overlay IP, persisted so
//!      re-runs don't leak a new control-plane node (the CP doesn't dedup by key);
//!   2. open a utun device, assign the overlay IP, route the CGNAT block to it;
//!   3. per peer, a boringtun `Tunn`; three threads move packets — utun →
//!      encapsulate → UDP, UDP → decapsulate → utun, and a timer driver;
//!   4. poll `GET /api/v1/peers` so peers that enroll later are picked up.
//!
//! macOS only at 1.1 (the utun adapter); other platforms error at runtime but
//! still compile (A.1.9). Requires root (utun + route).

use std::fs::OpenOptions;
use std::io::Write as _;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use agent_core::domain::EnrollRequest;
use agent_core::pump::{self, Peers}; // shared packet pump (tx/rx/timers + peer roster)
use agent_core::tunnel::StaticSecret;
use agent_core::{adapters, reqwest, WgKeypair};
use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};

const DEFAULT_CONTROL_PLANE: &str = "https://cp.ankayma.com";
const DEFAULT_LISTEN_PORT: u16 = 51820; // [T:wg(8)] WireGuard's default UDP port

/// Persisted node identity. Reused across runs so `agent up` does not enroll a
/// fresh node every time (the control plane assigns a new node + overlay IP per
/// enrollment — it does not dedup by public key).
#[derive(Serialize, Deserialize)]
pub(crate) struct AgentState {
    pub(crate) private_b64: String,
    pub(crate) public_b64: String,
    pub(crate) node_id: String,
    pub(crate) overlay_ip: String,
    pub(crate) listen_port: u16,
    /// [T:Part D §D.11] Scoped bearer token for GET /api/v1/peers/events.
    /// TTL 90d. None for nodes enrolled before migration 015.
    #[serde(default)]
    pub(crate) service_token: Option<String>,
    /// RFC3339 string of token expiry. Logged as warning when approaching expiry.
    #[serde(default)]
    pub(crate) token_expires_at: Option<String>,
    /// [T:Part B §B.1.4] Canonical workload kind, e.g. "AppServer".
    #[serde(default)]
    pub(crate) workload_kind: Option<String>,
}

// `PeerEntry` / `Peers` and the tx/rx/timer pump now live in `agent_core::pump`
// so the iOS Packet Tunnel extension reuses them (A.1.9). This file keeps only the
// host-specific plumbing: opening utun + assigning the overlay IP + per-peer routes.

/// `agent up [--token <t>] [--control-plane <url>] [--port <n>] [--state <path>]`
///
/// `--token` is required for the first enrollment. On subsequent runs, the persisted
/// `agent.json` carries a scoped node service token and `--token` is optional.
pub async fn run(args: &[String]) -> Result<()> {
    let cfg = Config::parse(args)?;
    let http = reqwest::Client::new();

    // 1. Identity: reuse persisted state, else generate + enroll (needs --token).
    let state = load_or_enroll(&http, &cfg).await?;

    // Service token: prefer persisted node service token (scoped, D.11);
    // fall back to --token for nodes enrolled before migration 015.
    let service_token = match state.service_token.clone() {
        Some(t) => {
            // Warn if expiry is known (Phase 1: display only, no auto-renew).
            if let Some(ref exp) = state.token_expires_at {
                eprintln!(
                    "node service token expires at {exp} — renew before that date with: \
                     agent renew-token"
                );
            }
            t
        }
        None => cfg.token.clone().ok_or_else(|| {
            anyhow!(
                "no node service token in agent.json — pass --token <session_token> to re-enroll"
            )
        })?,
    };

    // 2. Initial roster via GET /api/v1/peers.
    let initial = adapters::peers(&http, &cfg.control_plane, &service_token)
        .await
        .map_err(|e| anyhow!("fetch peers: {e}"))?;

    serve_dataplane(
        &state,
        initial,
        RefreshCtx {
            http,
            control_plane: cfg.control_plane.clone(),
            service_token,
        },
    )
    .await
}

/// Context for the `agent up` peer-event loop. (`agent ci-deploy` uses a
/// separate userspace data plane — see `netstack` — so there is no one-shot
/// variant here; this path is the kernel-TUN long-running agent only.)
pub(crate) struct RefreshCtx {
    pub http: reqwest::Client,
    pub control_plane: String,
    /// Node service token for GET /api/v1/peers/events. [T:Part D §D.11]
    pub service_token: String,
}

/// Bring the WireGuard overlay online for `state` and move packets. Shared by
/// `agent up` (refresh loop) and `agent ci-deploy` (one-shot). [T:A.1.3]
///
/// macOS only at 1.1 (the utun adapter); other platforms error at runtime but still
/// compile (A.1.9). Requires root (utun + route). Per-peer host routes (/32 v4,
/// /128 v6) are added as peers appear — more specific than any overlapping pool a
/// coexisting overlay (e.g. Tailscale's 100.64.0.0/10) holds, so ours wins.
pub(crate) async fn serve_dataplane(
    state: &AgentState,
    initial_peers: Vec<agent_core::domain::PeerInfo>,
    ctx: RefreshCtx,
) -> Result<()> {
    // [T:A.1.3] family-agnostic: control plane có thể cấp IPv4 hoặc IPv6 ULA.
    let self_overlay: IpAddr = state
        .overlay_ip
        .parse()
        .with_context(|| format!("control plane gave a bad overlay IP: {}", state.overlay_ip))?;
    let private_bytes = agent_core::key_bytes_from_b64(&state.private_b64)
        .map_err(|e| anyhow!("stored private key is invalid: {e:?}"))?;
    let static_private = StaticSecret::from(private_bytes);

    println!(
        "node {} — overlay {} — listening udp/{}",
        state.node_id, self_overlay, state.listen_port
    );

    // utun up + addressing.
    let dev = crate::tun::open().context("open utun device (needs root)")?;
    let dev_name = dev.name().to_string();
    let fd = dev.raw_fd();
    configure_interface(&dev_name, self_overlay).context("configure utun interface")?;
    println!("interface {dev_name} up, overlay {self_overlay} (per-peer host routes)");

    // UDP socket the whole mesh shares.
    let udp = Arc::new(
        UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], state.listen_port)))
            .with_context(|| format!("bind udp/{}", state.listen_port))?,
    );

    let peers: Peers = Arc::new(Mutex::new(Vec::new()));
    let index = Arc::new(Mutex::new(0u32));

    add_new_peers(
        &peers,
        &index,
        &static_private,
        self_overlay,
        &initial_peers,
        &udp,
        &dev_name,
    );

    // Hold the device for the process lifetime; the threads use the raw fd.
    let _dev = dev;

    // [slice 2] Publish live status for the GUI (proves the data plane is up,
    // not just enrolled). Refreshed every roster cycle below = a heartbeat.
    write_status(&state.node_id, &state.overlay_ip, state.listen_port, &peers);

    pump::spawn_tx(fd, udp.clone(), peers.clone());
    pump::spawn_rx(fd, udp.clone(), peers.clone());
    pump::spawn_timers(udp.clone(), peers.clone());

    // [F-3] Private DNS for branded names while the overlay is up: resolve the
    // tenant's `<name> → overlay_ip` table locally so a browser on this enrolled
    // device just works on the name, direct over the overlay (A.1.1). Names follow
    // the control plane's table → private-default + revoke come for free.
    let resolver = crate::resolver::Resolver::new();
    crate::resolver::serve(resolver.clone());
    let resolver_zone =
        match adapters::resolve_subdomains(&ctx.http, &ctx.control_plane, &ctx.service_token).await {
            Ok(t) => {
                resolver.set(resolve_entries(&t));
                crate::resolver::install_scoped_resolver(&t.zone);
                Some(t.zone)
            }
            Err(_) => None,
        };

    // [T:Part D §D.12] SSE event loop: replaces the 5s poll loop.
    // CP pushes peer_added when a CI runner enrolls; we add the peer immediately.
    // On disconnect: exponential backoff + full resync before reconnect.
    let refresh = {
        let (http, cp, svc_token) = (ctx.http, ctx.control_plane, ctx.service_token);
        let (peers, index, udp) = (peers.clone(), index.clone(), udp.clone());
        let dev_name = dev_name.clone();
        let resolver = resolver.clone();
        let (node_id, overlay_s, port) = (
            state.node_id.clone(),
            state.overlay_ip.clone(),
            state.listen_port,
        );
        async move {
            let mut backoff_secs: u64 = 1;
            loop {
                // Full resync before (re)connecting SSE — guarantees no missed events.
                if let Ok(list) = adapters::peers(&http, &cp, &svc_token).await {
                    let added = add_new_peers(
                        &peers,
                        &index,
                        &static_private,
                        self_overlay,
                        &list,
                        &udp,
                        &dev_name,
                    );
                    if added > 0 {
                        println!("discovered {added} peer(s) on sync");
                    }
                }
                if let Ok(t) = adapters::resolve_subdomains(&http, &cp, &svc_token).await {
                    resolver.set(resolve_entries(&t));
                }
                write_status(&node_id, &overlay_s, port, &peers);

                // Subscribe to SSE.
                match adapters::subscribe_peer_events(&http, &cp, &svc_token).await {
                    Ok(resp) => {
                        backoff_secs = 1; // reset on successful connect
                        if let Err(e) = consume_peer_sse(
                            resp,
                            &peers,
                            &index,
                            &static_private,
                            self_overlay,
                            &udp,
                            &dev_name,
                            &node_id,
                            &overlay_s,
                            port,
                        )
                        .await
                        {
                            eprintln!("SSE stream ended: {e} — reconnecting in {backoff_secs}s");
                        }
                    }
                    Err(e) => {
                        eprintln!("SSE connect error: {e} — retry in {backoff_secs}s");
                    }
                }
                tokio::time::sleep(Duration::from_secs(backoff_secs)).await;
                backoff_secs = (backoff_secs * 2).min(60);
            }
        }
    };
    println!("up. ping a peer's overlay IP to test (Ctrl-C to stop).");
    tokio::select! {
        _ = refresh => {}
        _ = tokio::signal::ctrl_c() => println!("\nshutting down."),
    }
    // Tunnel down → remove the status file + the scoped resolver so names stop
    // resolving (the overlay they point to is gone).
    let _ = std::fs::remove_file(status_path());
    if let Some(zone) = resolver_zone {
        crate::resolver::remove_scoped_resolver(&zone);
    }
    Ok(())
}

/// Read an SSE stream from the control plane and apply peer events.
/// Returns when the stream ends or an error occurs; caller handles reconnect.
#[allow(clippy::too_many_arguments)]
async fn consume_peer_sse(
    resp: reqwest::Response,
    peers: &Peers,
    index: &std::sync::Arc<std::sync::Mutex<u32>>,
    static_private: &StaticSecret,
    self_overlay: std::net::IpAddr,
    udp: &std::sync::Arc<std::net::UdpSocket>,
    dev_name: &str,
    node_id: &str,
    overlay_s: &str,
    port: u16,
) -> anyhow::Result<()> {
    use futures::StreamExt as _;
    let mut stream = resp.bytes_stream();
    let mut buf = String::new();
    let mut evt_type = String::new();
    let mut evt_data = String::new();

    while let Some(chunk) = stream.next().await {
        let bytes = chunk.map_err(|e| anyhow!("SSE read: {e}"))?;
        buf.push_str(&String::from_utf8_lossy(&bytes));
        // Process complete lines.
        while let Some(nl) = buf.find('\n') {
            let line = buf[..nl].trim_end_matches('\r').to_string();
            buf.drain(..=nl);
            if line.is_empty() {
                // Dispatch event on blank line.
                if evt_type == "peer_added" && !evt_data.is_empty() {
                    #[derive(serde::Deserialize)]
                    struct SsePeer {
                        node_id: String,
                        public_key: String,
                        overlay_ip: String,
                        hostname: String,
                        endpoint: Option<String>,
                    }
                    if let Ok(p) = serde_json::from_str::<SsePeer>(&evt_data) {
                        let peer_info = agent_core::domain::PeerInfo {
                            node_id: p.node_id,
                            public_key: p.public_key,
                            overlay_ip: p.overlay_ip,
                            hostname: p.hostname,
                            endpoint: p.endpoint,
                        };
                        let added = add_new_peers(
                            peers,
                            index,
                            static_private,
                            self_overlay,
                            &[peer_info],
                            udp,
                            dev_name,
                        );
                        if added > 0 {
                            println!("SSE: added {added} new peer(s)");
                            write_status(node_id, overlay_s, port, peers);
                        }
                    }
                }
                // peer_removed: Phase 1 — full resync on reconnect handles stale peers.
                // (Removing a WireGuard peer requires the public key, which would need
                // a lookup; defer to the resync-on-reconnect path for now.)
                evt_type.clear();
                evt_data.clear();
            } else if let Some(v) = line.strip_prefix("event: ") {
                evt_type = v.to_string();
            } else if let Some(v) = line.strip_prefix("data: ") {
                evt_data = v.to_string();
            }
            // SSE comments (":") and other fields are silently ignored.
        }
    }
    Err(anyhow!("SSE stream closed by server"))
}

/// Map the control plane's resolve table into (fqdn → overlay address) entries,
/// dropping any address that doesn't parse. `[T:F-3]`
fn resolve_entries(t: &agent_core::domain::ResolveTable) -> Vec<(String, IpAddr)> {
    t.names
        .iter()
        .filter_map(|n| n.overlay_ip.parse().ok().map(|ip| (n.fqdn.clone(), ip)))
        .collect()
}

struct Config {
    control_plane: String,
    token: Option<String>,
    listen_port: u16,
    state_path: String,
}

impl Config {
    fn parse(args: &[String]) -> Result<Self> {
        let mut control_plane = std::env::var("ANKAYMA_CONTROL_PLANE")
            .unwrap_or_else(|_| DEFAULT_CONTROL_PLANE.to_string());
        let mut token = std::env::var("ANKAYMA_TOKEN").ok();
        let mut listen_port = DEFAULT_LISTEN_PORT;
        let mut state_path = default_state_path();

        let mut it = args.iter();
        while let Some(a) = it.next() {
            match a.as_str() {
                "--control-plane" => {
                    control_plane = it.next().context("--control-plane needs a value")?.clone()
                }
                "--token" => token = Some(it.next().context("--token needs a value")?.clone()),
                "--port" => {
                    listen_port = it
                        .next()
                        .context("--port needs a value")?
                        .parse()
                        .context("--port must be a number")?
                }
                "--state" => state_path = it.next().context("--state needs a value")?.clone(),
                other => return Err(anyhow!("unknown argument: {other}")),
            }
        }
        Ok(Config {
            control_plane,
            token,
            listen_port,
            state_path,
        })
    }
}

fn default_state_path() -> String {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    format!("{home}/.ankayma/agent.json")
}

// [slice 2] Live data-plane status, published for the GUI to read. The GUI runs
// unprivileged and never opens the tunnel itself, so this file is how it learns
// the daemon is actually up (not just enrolled) + the current peer roster.
// Connection-level only (hostname/overlay/endpoint) — never payload [T:A.1.1].
fn status_path() -> String {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    format!("{home}/.ankayma/agent-status.json")
}

#[derive(serde::Serialize)]
struct StatusPeer {
    hostname: String,
    overlay_ip: String,
    endpoint: Option<String>,
}

#[derive(serde::Serialize)]
struct DataplaneStatus {
    pid: u32,
    node_id: String,
    overlay_ip: String,
    listen_port: u16,
    updated_at: u64, // unix seconds — GUI treats a stale file as "down"
    peers: Vec<StatusPeer>,
}

/// Write the live status file (best-effort; never fail the data plane on a write
/// error). Called at startup and on every roster refresh = a heartbeat.
fn write_status(node_id: &str, overlay_ip: &str, listen_port: u16, peers: &Peers) {
    let updated_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let list: Vec<StatusPeer> = peers
        .lock()
        .expect("peers lock")
        .iter()
        .map(|p| StatusPeer {
            hostname: p.peer.hostname.clone(),
            overlay_ip: p.peer.overlay_ip.to_string(),
            endpoint: p.endpoint().map(|e| e.to_string()),
        })
        .collect();
    let status = DataplaneStatus {
        pid: std::process::id(),
        node_id: node_id.to_string(),
        overlay_ip: overlay_ip.to_string(),
        listen_port,
        updated_at,
        peers: list,
    };
    if let Ok(bytes) = serde_json::to_vec_pretty(&status) {
        let _ = std::fs::write(status_path(), bytes);
    }
}

/// Reuse a persisted identity if present; otherwise generate a keypair, enroll
/// (advertising our LAN endpoint so peers can reach us), and persist the result.
/// `--token` is required only for the initial enrollment.
async fn load_or_enroll(http: &reqwest::Client, cfg: &Config) -> Result<AgentState> {
    if let Ok(bytes) = std::fs::read(&cfg.state_path) {
        if let Ok(state) = serde_json::from_slice::<AgentState>(&bytes) {
            println!("reusing identity from {}", cfg.state_path);
            return Ok(state);
        }
    }

    let token = cfg.token.clone().ok_or_else(|| {
        anyhow!("initial enrollment requires --token <session_token> or ANKAYMA_TOKEN")
    })?;

    let kp = WgKeypair::generate();
    let lan_ip = detect_lan_ip().context("detect this machine's LAN IP")?;
    let endpoint = format!("{lan_ip}:{}", cfg.listen_port);
    println!("enrolling new node (advertising endpoint {endpoint})…");

    let req = EnrollRequest {
        public_key: kp.public_b64.clone(),
        hostname: hostname(),
        endpoint: Some(endpoint),
        // [T:Part B §B.1.4] server nodes default to AppServer.
        workload_kind: Some("AppServer".to_string()),
    };
    let resp = adapters::enroll(http, &cfg.control_plane, &token, &req)
        .await
        .map_err(|e| anyhow!("enroll: {e}"))?;

    if resp.node_service_token.is_none() {
        eprintln!(
            "warning: control-plane did not return a node service token (pre-migration 015). \
             Re-enroll after updating the control plane."
        );
    }

    let state = AgentState {
        private_b64: kp.private_b64,
        public_b64: kp.public_b64,
        node_id: resp.node_id,
        overlay_ip: resp.overlay_ip,
        listen_port: cfg.listen_port,
        service_token: resp.node_service_token,
        token_expires_at: resp.token_expires_at,
        workload_kind: Some("AppServer".to_string()),
    };
    if let Some(dir) = std::path::Path::new(&cfg.state_path).parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    // mode 0o600: private key must not be readable by other users on the same host.
    #[cfg(unix)]
    let mut f = {
        use std::os::unix::fs::OpenOptionsExt;
        OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&cfg.state_path)
            .with_context(|| format!("create identity file {}", cfg.state_path))?
    };
    #[cfg(not(unix))]
    let mut f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&cfg.state_path)
        .with_context(|| format!("create identity file {}", cfg.state_path))?;
    f.write_all(&serde_json::to_vec_pretty(&state)?)
        .with_context(|| format!("persist identity to {}", cfg.state_path))?;
    Ok(state)
}

/// This machine's primary LAN IPv4, found by asking the OS which source address
/// it would use to reach an off-link address (no packet is actually sent).
fn detect_lan_ip() -> Result<Ipv4Addr> {
    let s = UdpSocket::bind("0.0.0.0:0")?;
    s.connect("8.8.8.8:80")?;
    match s.local_addr()?.ip() {
        std::net::IpAddr::V4(v4) => Ok(v4),
        other => Err(anyhow!("expected an IPv4 LAN address, got {other}")),
    }
}

fn hostname() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .filter(|h| !h.is_empty())
        .or_else(|| {
            Command::new("hostname")
                .output()
                .ok()
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        })
        .unwrap_or_else(|| "ankayma-node".to_string())
}

/// Bring the device up with this node's overlay address. Routing is per-peer
/// (`add_peer_route`), not a blanket pool route: a host route (/32 v4, /128 v6) is
/// more specific than any overlapping pool a coexisting overlay (Tailscale shares
/// the CGNAT range) holds, and keeps the client agnostic to whatever family/range
/// the control plane assigns. `[T:A.1.3]`
#[cfg(target_os = "macos")]
fn configure_interface(name: &str, overlay: IpAddr) -> Result<()> {
    let ip = overlay.to_string();
    match overlay {
        // [T:macos-ifconfig(8)] IPv4 point-to-point: local == remote == overlay.
        IpAddr::V4(_) => {
            run_cmd(Command::new("ifconfig").args([name, "inet", &ip, &ip, "up"]))?;
        }
        // [A? verify-on-macOS] IPv6: gán host /128 lên utun; per-peer /128 route thêm sau.
        IpAddr::V6(_) => {
            run_cmd(Command::new("ifconfig").args([name, "inet6", &ip, "prefixlen", "128", "up"]))?;
        }
    }
    Ok(())
}

/// Linux: assign the overlay host address and bring the link up via `ip(8)`.
/// Per-peer routes are added separately (`add_peer_route`). `[T:iproute2 ip(8)]`
#[cfg(target_os = "linux")]
fn configure_interface(name: &str, overlay: IpAddr) -> Result<()> {
    let ip = overlay.to_string();
    match overlay {
        IpAddr::V4(_) => {
            run_cmd(Command::new("ip").args(["addr", "add", &format!("{ip}/32"), "dev", name]))?;
        }
        IpAddr::V6(_) => {
            run_cmd(Command::new("ip").args([
                "-6",
                "addr",
                "add",
                &format!("{ip}/128"),
                "dev",
                name,
            ]))?;
        }
    }
    run_cmd(Command::new("ip").args(["link", "set", "dev", name, "up"]))?;
    Ok(())
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn configure_interface(_name: &str, _overlay: IpAddr) -> Result<()> {
    Err(anyhow!(
        "interface configuration is implemented for macOS + Linux [T:A.1.9]"
    ))
}

/// Route one peer's overlay address into the tunnel device. `route delete` first
/// makes it idempotent and steals the /32 from any other overlay holding it
/// (e.g. a stale Tailscale route). Best-effort: a failure is logged, not fatal.
#[cfg(target_os = "macos")]
fn add_peer_route(name: &str, overlay: IpAddr) {
    // host route per-peer: /32 (v4) hoặc /128 (v6) — thắng mọi dải trùng (vd Tailscale /10).
    let (inet, dst) = match overlay {
        IpAddr::V4(a) => ("-inet", format!("{a}/32")),
        IpAddr::V6(a) => ("-inet6", format!("{a}/128")),
    };
    // [T:macos-route(8)] ignore delete errors (route may not exist yet).
    let _ = Command::new("route")
        .args(["-q", "-n", "delete", inet, &dst])
        .output();
    if let Err(e) =
        run_cmd(Command::new("route").args(["-q", "-n", "add", inet, &dst, "-interface", name]))
    {
        eprintln!("warning: could not route {dst} via {name}: {e}");
    }
}

/// Linux: route this peer's overlay host into the tunnel device via `ip(8)`.
/// `ip route replace` is idempotent (no pre-delete needed). `[T:iproute2 ip(8)]`
#[cfg(target_os = "linux")]
fn add_peer_route(name: &str, overlay: IpAddr) {
    let (fam, dst) = match overlay {
        IpAddr::V4(a) => (None, format!("{a}/32")),
        IpAddr::V6(a) => (Some("-6"), format!("{a}/128")),
    };
    let mut cmd = Command::new("ip");
    if let Some(f) = fam {
        cmd.arg(f);
    }
    cmd.args(["route", "replace", &dst, "dev", name]);
    if let Err(e) = run_cmd(&mut cmd) {
        eprintln!("warning: could not route {dst} via {name}: {e}");
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn add_peer_route(_name: &str, _overlay: IpAddr) {}

// Only the macOS/Linux interface/route helpers above call this; gate it to match
// so a build without those helpers doesn't flag it as dead code. [T:A.1.9]
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn run_cmd(cmd: &mut Command) -> Result<()> {
    let out = cmd.output().with_context(|| format!("run {cmd:?}"))?;
    if !out.status.success() {
        return Err(anyhow!(
            "{cmd:?} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(())
}

/// Add peers we don't already have a tunnel for, then route each new peer's
/// overlay into the device. Returns how many were added. The Tunn setup + roster
/// push is the OS-agnostic part (`pump::add_tunn_peers`); this wrapper adds the
/// host route (macOS/Linux) the pump deliberately leaves to the caller. `[T:A.1.9]`
fn add_new_peers(
    peers: &Peers,
    index: &Arc<Mutex<u32>>,
    static_private: &StaticSecret,
    self_overlay: IpAddr,
    list: &[agent_core::domain::PeerInfo],
    udp: &Arc<UdpSocket>,
    dev_name: &str,
) -> usize {
    let added = pump::add_tunn_peers(peers, index, static_private, self_overlay, list, udp);
    for overlay in &added {
        // Route this peer's overlay /32 into the tunnel (wins over Tailscale's /10).
        add_peer_route(dev_name, *overlay);
    }
    added.len()
}
