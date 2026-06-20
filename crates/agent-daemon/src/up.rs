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

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use agent_core::dataplane::{self, DialablePeer};
use agent_core::domain::EnrollRequest;
use agent_core::tunnel::{make_tunn, PublicKey, StaticSecret, Tunn, TunnResult};
use agent_core::{adapters, reqwest, WgKeypair};
use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};

const DEFAULT_CONTROL_PLANE: &str = "https://cp.ankayma.com";
const DEFAULT_LISTEN_PORT: u16 = 51820; // [T:wg(8)] WireGuard's default UDP port
const MTU: usize = 1420; // [T:WireGuard] safe overlay MTU under a 1500 path

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
}

/// One peer's live tunnel: the dialable metadata + its boringtun state machine.
struct PeerEntry {
    peer: DialablePeer,
    tunn: Mutex<Tunn>,
}

type Peers = Arc<Mutex<Vec<Arc<PeerEntry>>>>;

/// `agent up [--token <t>] [--control-plane <url>] [--port <n>] [--state <path>]`
pub async fn run(args: &[String]) -> Result<()> {
    let cfg = Config::parse(args)?;

    let http = reqwest::Client::new();
    let token = cfg.token.clone().ok_or_else(|| {
        anyhow!("a session token is required: pass --token <t> or set ANKAYMA_TOKEN")
    })?;

    // 1. Identity: reuse persisted state, else generate + enroll.
    let state = load_or_enroll(&http, &cfg, &token).await?;

    // 2. Initial roster, then run the data plane with a live peer-refresh loop.
    let initial = adapters::peers(&http, &cfg.control_plane, &token)
        .await
        .map_err(|e| anyhow!("fetch peers: {e}"))?;

    serve_dataplane(
        &state,
        initial,
        AfterUp::Refresh(RefreshCtx {
            http,
            control_plane: cfg.control_plane.clone(),
            token,
        }),
    )
    .await
}

/// What [`serve_dataplane`] does once the tunnel threads are running.
pub(crate) enum AfterUp {
    /// Long-running agent (`agent up`): poll the control plane for new peers.
    Refresh(RefreshCtx),
    /// One-shot (`agent ci-deploy`): run a command over the tunnel then exit; an
    /// empty/None command waits for Ctrl-C. [T:Part C §H.3.3]
    Oneshot(Option<Vec<String>>),
}

pub(crate) struct RefreshCtx {
    pub http: reqwest::Client,
    pub control_plane: String,
    pub token: String,
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
    after: AfterUp,
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

    spawn_tx(fd, udp.clone(), peers.clone());
    spawn_rx(fd, udp.clone(), peers.clone());
    spawn_timers(udp.clone(), peers.clone());

    match after {
        // Keep the roster fresh: peers that enroll after us appear here.
        AfterUp::Refresh(ctx) => {
            let refresh = {
                let (http, cp, token) = (ctx.http, ctx.control_plane, ctx.token);
                let (peers, index, udp) = (peers.clone(), index.clone(), udp.clone());
                let dev_name = dev_name.clone();
                async move {
                    loop {
                        tokio::time::sleep(Duration::from_secs(5)).await;
                        if let Ok(list) = adapters::peers(&http, &cp, &token).await {
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
                                println!("discovered {added} new peer(s)");
                            }
                        }
                    }
                }
            };
            println!("up. ping a peer's overlay IP to test (Ctrl-C to stop).");
            tokio::select! {
                _ = refresh => {}
                _ = tokio::signal::ctrl_c() => println!("\nshutting down."),
            }
        }
        // Ephemeral deploy: tunnel is up; run the deploy command, then tear down.
        AfterUp::Oneshot(cmd) => {
            println!("up (ephemeral). tunnel ready.");
            match cmd {
                Some(parts) if !parts.is_empty() => {
                    let status = Command::new(&parts[0])
                        .args(&parts[1..])
                        .status()
                        .with_context(|| format!("run deploy command: {}", parts.join(" ")))?;
                    if !status.success() {
                        return Err(anyhow!("deploy command exited with {status}"));
                    }
                    println!("deploy command finished ok; tearing down ephemeral tunnel.");
                }
                _ => {
                    println!("no --exec given; holding tunnel until Ctrl-C.");
                    let _ = tokio::signal::ctrl_c().await;
                }
            }
        }
    }
    Ok(())
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

/// Reuse a persisted identity if present; otherwise generate a keypair, enroll
/// (advertising our LAN endpoint so peers can reach us), and persist the result.
async fn load_or_enroll(http: &reqwest::Client, cfg: &Config, token: &str) -> Result<AgentState> {
    if let Ok(bytes) = std::fs::read(&cfg.state_path) {
        if let Ok(state) = serde_json::from_slice::<AgentState>(&bytes) {
            println!("reusing identity from {}", cfg.state_path);
            return Ok(state);
        }
    }

    let kp = WgKeypair::generate();
    let lan_ip = detect_lan_ip().context("detect this machine's LAN IP")?;
    let endpoint = format!("{lan_ip}:{}", cfg.listen_port);
    println!("enrolling new node (advertising endpoint {endpoint})…");

    let req = EnrollRequest {
        public_key: kp.public_b64.clone(),
        hostname: hostname(),
        endpoint: Some(endpoint),
    };
    let resp = adapters::enroll(http, &cfg.control_plane, token, &req)
        .await
        .map_err(|e| anyhow!("enroll: {e}"))?;

    let state = AgentState {
        private_b64: kp.private_b64,
        public_b64: kp.public_b64,
        node_id: resp.node_id,
        overlay_ip: resp.overlay_ip,
        listen_port: cfg.listen_port,
    };
    if let Some(dir) = std::path::Path::new(&cfg.state_path).parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    std::fs::write(&cfg.state_path, serde_json::to_vec_pretty(&state)?)
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

#[cfg(not(target_os = "macos"))]
fn configure_interface(_name: &str, _overlay: IpAddr) -> Result<()> {
    Err(anyhow!(
        "interface configuration is implemented for macOS only at milestone 1.1 [T:A.1.9]"
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

#[cfg(not(target_os = "macos"))]
fn add_peer_route(_name: &str, _overlay: IpAddr) {}

// Only the macOS interface/route helpers above call this; gate it to match so a
// non-macOS build (e.g. Linux CI) doesn't flag it as dead code. [T:A.1.9]
#[cfg(target_os = "macos")]
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

/// Add peers we don't already have a tunnel for. Returns how many were added.
fn add_new_peers(
    peers: &Peers,
    index: &Arc<Mutex<u32>>,
    static_private: &StaticSecret,
    self_overlay: IpAddr,
    list: &[agent_core::domain::PeerInfo],
    udp: &Arc<UdpSocket>,
    dev_name: &str,
) -> usize {
    let dialable = dataplane::dialable_peers(list, self_overlay);
    let mut guard = peers.lock().expect("peers lock");
    let known: HashSet<String> = guard
        .iter()
        .map(|p| p.peer.public_key_b64.clone())
        .collect();
    let mut added = 0;

    for d in dialable {
        if known.contains(&d.public_key_b64) {
            continue;
        }
        let idx = {
            let mut i = index.lock().expect("index lock");
            *i += 1;
            *i
        };
        let peer_pub = PublicKey::from(d.public_key);
        let mut tunn = make_tunn(static_private.clone(), peer_pub, idx);

        // Proactively initiate the handshake so connectivity comes up without
        // waiting for the first data packet or timer tick.
        let mut buf = [0u8; 2048];
        if let TunnResult::WriteToNetwork(p) = tunn.format_handshake_initiation(&mut buf, false) {
            let _ = udp.send_to(p, d.endpoint);
        }

        // Route this peer's overlay /32 into the tunnel (wins over Tailscale's /10).
        add_peer_route(dev_name, d.overlay_ip);

        println!(
            "peer {} ({}) overlay {} via {}",
            d.hostname, d.node_id, d.overlay_ip, d.endpoint
        );
        guard.push(Arc::new(PeerEntry {
            peer: d,
            tunn: Mutex::new(tunn),
        }));
        added += 1;
    }
    added
}

/// Find the peer that owns an overlay destination (outgoing) or a UDP source
/// (incoming). Cheap linear scan — a personal mesh has a handful of peers.
fn peer_by_overlay(peers: &Peers, dst: IpAddr) -> Option<Arc<PeerEntry>> {
    let g = peers.lock().expect("peers lock");
    g.iter().find(|p| p.peer.overlay_ip == dst).cloned()
}

fn peer_by_source(peers: &Peers, src: SocketAddr) -> Option<Arc<PeerEntry>> {
    let g = peers.lock().expect("peers lock");
    // Exact endpoint match first; fall back to same-host (port may differ behind
    // NAT); fall back to the sole peer if there's only one.
    g.iter()
        .find(|p| p.peer.endpoint == src)
        .or_else(|| g.iter().find(|p| p.peer.endpoint.ip() == src.ip()))
        .or_else(|| if g.len() == 1 { g.first() } else { None })
        .cloned()
}

/// utun → encapsulate → UDP. Reads bare IP packets, routes by destination.
fn spawn_tx(fd: i32, udp: Arc<UdpSocket>, peers: Peers) {
    std::thread::spawn(move || {
        let mut pkt = [0u8; MTU + 80];
        let mut enc = [0u8; MTU + 80];
        loop {
            let n = match crate::tun::read_packet(fd, &mut pkt) {
                Ok(0) => continue,
                Ok(n) => n,
                Err(e) => {
                    eprintln!("utun read error: {e}");
                    break;
                }
            };
            let Some(dst) = dataplane::packet_dst(&pkt[..n]) else {
                continue; // not a routable IPv4/IPv6 packet (truncated / unknown version)
            };
            let Some(entry) = peer_by_overlay(&peers, dst) else {
                continue; // no peer owns this overlay address
            };
            let mut tunn = entry.tunn.lock().expect("tunn lock");
            match tunn.encapsulate(&pkt[..n], &mut enc) {
                TunnResult::WriteToNetwork(out) => {
                    let _ = udp.send_to(out, entry.peer.endpoint);
                }
                TunnResult::Err(e) => eprintln!("encapsulate error: {e:?}"),
                _ => {}
            }
        }
    });
}

/// UDP → decapsulate → utun. Demuxes by source, drains queued packets.
fn spawn_rx(fd: i32, udp: Arc<UdpSocket>, peers: Peers) {
    std::thread::spawn(move || {
        let mut datagram = [0u8; 2048];
        let mut out = [0u8; 2048];
        loop {
            let (n, src) = match udp.recv_from(&mut datagram) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("udp recv error: {e}");
                    break;
                }
            };
            let Some(entry) = peer_by_source(&peers, src) else {
                continue;
            };
            let mut tunn = entry.tunn.lock().expect("tunn lock");
            let mut res = tunn.decapsulate(Some(src.ip()), &datagram[..n], &mut out);
            loop {
                match res {
                    TunnResult::WriteToNetwork(pkt) => {
                        let _ = udp.send_to(pkt, entry.peer.endpoint);
                        // boringtun may have more queued (e.g. cookie/keepalive).
                        res = tunn.decapsulate(None, &[], &mut out);
                    }
                    TunnResult::WriteToTunnelV4(pkt, _) | TunnResult::WriteToTunnelV6(pkt, _) => {
                        let _ = crate::tun::write_packet(fd, pkt);
                        break;
                    }
                    TunnResult::Err(e) => {
                        eprintln!("decapsulate error: {e:?}");
                        break;
                    }
                    TunnResult::Done => break,
                }
            }
        }
    });
}

/// Drive WireGuard timers (rekey, keepalive, handshake retries).
/// `[T:WireGuard-whitepaper §6]` the protocol is timer-driven.
fn spawn_timers(udp: Arc<UdpSocket>, peers: Peers) {
    std::thread::spawn(move || {
        let mut buf = [0u8; 2048];
        loop {
            std::thread::sleep(Duration::from_millis(250));
            let snapshot: Vec<Arc<PeerEntry>> =
                peers.lock().expect("peers lock").iter().cloned().collect();
            for entry in snapshot {
                let mut tunn = entry.tunn.lock().expect("tunn lock");
                if let TunnResult::WriteToNetwork(p) = tunn.update_timers(&mut buf) {
                    let _ = udp.send_to(p, entry.peer.endpoint);
                }
            }
        }
    });
}
