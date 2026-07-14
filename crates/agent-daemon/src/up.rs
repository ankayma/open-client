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
use std::path::Path;
use std::process::Command;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use agent_core::domain::{EnrollRequest, EnrollResponse};
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
    /// [T:part-d-layer2-cert-infrastructure.md §H.2] Layer 2 node identity:
    /// leaf cert signed by the TenantCA. None until the CP ships Layer 2.
    #[serde(default)]
    pub(crate) node_cert_pem: Option<String>,
    /// Provisioning CA chain for broker TLS (TH-A dynamic trust — arrives at
    /// enrollment, never pinned in the binary). [T:A.1.18]
    #[serde(default)]
    pub(crate) provisioning_ca_pem: Option<String>,
    /// Cached CRL (revocation = CRL broadcast, B.4.2), refreshed every 4h.
    #[serde(default)]
    pub(crate) crl_pem: Option<String>,
    /// Where to refresh the CRL from. [A: persisted in addition to the spec's
    /// field list — without it a restarted daemon cannot refresh until the next
    /// re-enroll; recorded as a spec-log addendum]
    #[serde(default)]
    pub(crate) crl_url: Option<String>,
    /// RFC3339 notAfter of node_cert_pem, for the expiry warning + GUI display.
    #[serde(default)]
    pub(crate) cert_expires_at: Option<String>,
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
    // connect_timeout bounds TCP+TLS setup for EVERY call, including the SSE
    // subscribe (whose response body must stay unbounded). Round-trip bounds on
    // plain REST live in the adapters (CP_REST_TIMEOUT) — together they keep the
    // refresh loop from freezing on one dead connection, which wedged a
    // production node for 21h (2026-07-04: status written once, roster frozen).
    let http = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .build()
        .context("build control-plane HTTP client")?;

    // 1. Identity: reuse persisted state, else generate + enroll (needs --token).
    let state = load_or_enroll(&http, &cfg).await?;

    // [Layer 2] Expiry warning — display only; renewal flow ships on the P.8
    // trigger (1yr Personal TTL ⇒ not a 1.x launch gate).
    // [T:part-d-layer2-cert-infrastructure.md §H.1]
    if let Some(cert) = state.node_cert_pem.as_deref() {
        if let Ok(days) = agent_core::cert::cert_expiry_days(cert) {
            if days < 30 {
                eprintln!(
                    "node cert expires in {days} day(s) — re-enroll this device to renew \
                     (automatic renewal is not built yet)"
                );
            }
        }
    }
    // [Layer 2] CRL cache: fetch now + every 4h so revocations (E-4) reach the
    // broker handshake within one refresh window. [T:B.4.2 CRL broadcast]
    if let Some(url) = state.crl_url.clone() {
        spawn_crl_refresh(http.clone(), url, cfg.state_path.clone());
    }

    // Service token: prefer persisted node service token (scoped, D.11);
    // fall back to --token for nodes enrolled before migration 015.
    let service_token = match state.service_token.clone() {
        Some(t) => {
            // Auto-renewal (spawn_token_renewal below) keeps this fresh in the
            // background via proof-of-possession; this line is informational only.
            if let Some(ref exp) = state.token_expires_at {
                println!("node service token expires at {exp} — background auto-renewal active");
            }
            t
        }
        None => cfg.token.clone().ok_or_else(|| {
            anyhow!(
                "no node service token in agent.json — pass --token <session_token> to re-enroll"
            )
        })?,
    };

    // Shared token cell: the background renewer rotates it, the refresh loop reads it.
    let token_cell = Arc::new(RwLock::new(service_token));

    // Keep the node service token fresh in the background so a long-running headless
    // node never dies when the token expires — the fix for the "control-plane rejects
    // our credential" roster freeze. Renewal is proof-of-possession (present the
    // current token), so no login credential is needed on a headless box.
    // `[T:Part D §D.11 node service token]`
    spawn_token_renewal(
        http.clone(),
        cfg.control_plane.clone(),
        state.node_id.clone(),
        cfg.state_path.clone(),
        token_cell.clone(),
    );

    // 2. Initial roster via GET /api/v1/peers.
    let initial = {
        let tok = token_cell.read().unwrap().clone();
        adapters::peers(&http, &cfg.control_plane, &tok)
            .await
            .map_err(|e| anyhow!("fetch peers: {e}"))?
    };

    serve_dataplane(
        &state,
        initial,
        RefreshCtx {
            http,
            control_plane: cfg.control_plane.clone(),
            service_token: token_cell,
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
    /// Shared cell: `spawn_token_renewal` rotates it in the background (the old token
    /// is invalidated server-side on renewal), and the refresh loop re-reads it each
    /// cycle so a renewed token is picked up within one cycle.
    /// `[T:Part D §D.11 node service token]`
    pub service_token: Arc<RwLock<String>>,
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
    // [T:A.1.3] family-agnostic: control plane may assign IPv4 or IPv6 ULA.
    let self_overlay: IpAddr = state
        .overlay_ip
        .parse()
        .with_context(|| format!("control plane gave a bad overlay IP: {}", state.overlay_ip))?;
    let private_bytes = agent_core::key_bytes_from_b64(&state.private_b64)
        .map_err(|e| anyhow!("stored private key is invalid: {e:?}"))?;
    let static_private = StaticSecret::from(private_bytes);

    // PersistentKeepalive=25s ONLY when this node sits behind NAT — otherwise the
    // NAT mapping dies after >30-60s of silence and inbound goes dark until we
    // next send. A public-endpoint node needs none. Composes with idle-teardown:
    // boringtun only emits keepalives while a session exists. `[T:A.1.7]`
    // `[T:wireguard.com/quickstart PersistentKeepalive=25]`
    let keepalive = self_nat_keepalive();
    if keepalive.is_some() {
        println!("behind NAT — PersistentKeepalive=25s on active sessions");
    }

    println!(
        "node {} — overlay {} — listening udp/{}",
        state.node_id, self_overlay, state.listen_port
    );

    // utun up + addressing.
    let dev = crate::tun::open().context("open tunnel device (needs root/admin)")?;
    let dev_name = dev.name().to_string();
    let tun_handle = dev.handle();
    configure_interface(&dev_name, self_overlay).context("configure tunnel interface")?;
    println!("interface {dev_name} up, overlay {self_overlay} (per-peer host routes)");

    // UDP socket the whole mesh shares.
    let udp = Arc::new(
        UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], state.listen_port)))
            .with_context(|| format!("bind udp/{}", state.listen_port))?,
    );

    // Open the WireGuard data-plane port so peers that must INITIATE to this node (an
    // ephemeral CI runner, a node behind NAT) can hand-shake in — a default-deny host
    // firewall drops those packets and the mesh silently half-works. Handled on Linux
    // (ufw) and Windows (netsh), by default; `ANKAYMA_NO_FIREWALL=1` opts out. No-op on
    // macOS/iOS/Android (no port firewall on by default / client-only). `[T:A.1.6 + P.6]`
    advise_wg_firewall(state.listen_port);

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
        keepalive,
    );

    // Hold the device for the process lifetime; the threads use the raw fd.
    let _dev = dev;

    // [slice 2] Publish live status for the GUI (proves the data plane is up,
    // not just enrolled). Refreshed every roster cycle below = a heartbeat.
    write_status(&state.node_id, &state.overlay_ip, state.listen_port, &peers);

    // DNS answers via the loopback resolver below (fed by /etc/resolver/<zone>),
    // never on the tun fd itself — no DnsResponder needed here (iOS-only, no
    // split-DNS hook to piggyback on).
    let tun = tun_handle;
    pump::spawn_tx(tun.clone(), udp.clone(), peers.clone(), None);
    pump::spawn_rx(tun, udp.clone(), peers.clone());
    pump::spawn_timers(
        udp.clone(),
        peers.clone(),
        static_private.clone(),
        index.clone(),
    );

    // [F-3] Private DNS for branded names while the overlay is up: resolve the
    // tenant's `<name> → overlay_ip` table locally so a browser on this enrolled
    // device just works on the name, direct over the overlay (A.1.1). Names follow
    // the control plane's table → private-default + revoke come for free.
    let resolver = crate::resolver::Resolver::new();
    crate::resolver::serve(resolver.clone());
    // [F-3 auto-TLS, Slice 3] For each branded subdomain THIS node owns
    // (target_node_id == our node_id), keep a CSR on file + a local
    // TLS-terminating relay running once a cert lands — peer-to-peer, no
    // vendor edge in the data path (A.1.1).
    let relay = crate::tls_relay::Relay::new();
    let startup_token = ctx.service_token.read().unwrap().clone();
    let resolver_zone =
        match adapters::resolve_subdomains(&ctx.http, &ctx.control_plane, &startup_token).await {
            Ok(t) => {
                resolver.set(resolve_entries(&t));
                spawn_owned_subdomain_tasks(
                    &relay,
                    &ctx.http,
                    &ctx.control_plane,
                    &startup_token,
                    &t,
                    &state.node_id,
                    self_overlay,
                );
                crate::resolver::install_scoped_resolver(&t.zone);
                Some(t.zone)
            }
            Err(_) => None,
        };

    // [F-2 v0.5] Embedded SSH server: identity-bound NoKeySSH over the overlay only
    // (never a public port). Unix lands the shared user `ankayma`; Windows lands the
    // current user's ConPTY shell (§H.5 provisioning is unix-only for now). Clients
    // pin the host key the control plane distributes; root elevation (§H.4) is
    // enabled if the CP publishes an elevation key.
    #[cfg(any(unix, windows))]
    start_embedded_ssh(
        self_overlay,
        &ctx.control_plane,
        &state.node_id,
        &dev_name,
        &ctx.http,
    )
    .await;

    // [T:Part D §D.12] SSE event loop: replaces the 5s poll loop.
    // CP pushes peer_added when a CI runner enrolls; we add the peer immediately.
    // On disconnect: exponential backoff + full resync before reconnect.
    let refresh = {
        let (http, cp, svc_token_cell) = (ctx.http, ctx.control_plane, ctx.service_token);
        let (peers, index, udp) = (peers.clone(), index.clone(), udp.clone());
        let dev_name = dev_name.clone();
        let resolver = resolver.clone();
        let relay = relay.clone();
        let (node_id, overlay_s, port) = (
            state.node_id.clone(),
            state.overlay_ip.clone(),
            state.listen_port,
        );
        async move {
            let mut backoff_secs: u64 = 1;
            let mut consecutive_sync_failures: u32 = 0;
            loop {
                // Re-read the (possibly renewed) service token each cycle: the
                // background renewer rotates it and the previous token stops working
                // immediately, so the loop must pick up the new one (a single stale-
                // token 401 here self-heals on the next cycle).
                let svc_token = svc_token_cell.read().unwrap().clone();
                // Full resync before (re)connecting SSE — guarantees no missed events.
                // NEVER swallow the error silently: an agent whose token is missing/
                // expired/revoked polls 401 forever and its roster freezes — new peers
                // become unreachable with zero symptoms on this side (root cause of the
                // 2026-07-02 "0 inbound ever" incident; agent ran 11 days on 401s).
                match adapters::peers(&http, &cp, &svc_token).await {
                    Ok(list) => {
                        consecutive_sync_failures = 0;
                        let (added, removed) = reconcile_new_and_stale_peers(
                            &peers,
                            &index,
                            &static_private,
                            self_overlay,
                            &list,
                            &udp,
                            &dev_name,
                            keepalive,
                        );
                        if added > 0 {
                            println!("discovered {added} peer(s) on sync");
                        }
                        if removed > 0 {
                            println!("pruned {removed} stale peer(s) on sync");
                        }
                    }
                    Err(e) => {
                        consecutive_sync_failures += 1;
                        eprintln!(
                            "peer sync failed ({consecutive_sync_failures} consecutive): {e}"
                        );
                        if consecutive_sync_failures >= 3 {
                            // TODO[A]: auto re-enroll needs a login credential a headless
                            // daemon doesn't hold — surface loudly and keep serving the
                            // last-known roster (verify UX once GUI shows agent health).
                            eprintln!(
                                "peer roster is STALE — control-plane rejects our credential. \
                                 New devices will be unreachable until `agent up` re-enrolls \
                                 (sign in again on this device)."
                            );
                        }
                    }
                }
                if let Ok(t) = adapters::resolve_subdomains(&http, &cp, &svc_token).await {
                    resolver.set(resolve_entries(&t));
                    spawn_owned_subdomain_tasks(
                        &relay,
                        &http,
                        &cp,
                        &svc_token,
                        &t,
                        &node_id,
                        self_overlay,
                    );
                }
                write_status(&node_id, &overlay_s, port, &peers);

                // Subscribe to SSE for INSTANT peer_added, but CAP the session so the
                // loop re-syncs at least once a minute regardless of SSE liveness. A
                // half-open TCP stream (network blip, CP restart, NAT idle-drop) never
                // errors, so consuming it would block here forever and miss every peer
                // that enrolled afterward — the reason a long-lived server node had to
                // be manually restarted to see a new device. The periodic resync above
                // is the safety net; SSE just makes the common case instant. `[T:Part D §D.12]`
                const SSE_SESSION_CAP: Duration = Duration::from_secs(60);
                // Bound the subscribe handshake (connect_timeout covers TCP+TLS;
                // this covers "accepted but headers never arrive"). The response
                // BODY stays unbounded on purpose — SSE_SESSION_CAP bounds it.
                const SSE_CONNECT_CAP: Duration = Duration::from_secs(30);
                let subscribe = tokio::time::timeout(
                    SSE_CONNECT_CAP,
                    adapters::subscribe_peer_events(&http, &cp, &svc_token),
                );
                match subscribe.await.unwrap_or_else(|_elapsed| {
                    Err(agent_core::adapters::ApiError::Transport(format!(
                        "SSE subscribe timed out after {SSE_CONNECT_CAP:?}"
                    )))
                }) {
                    Ok(resp) => {
                        backoff_secs = 1; // reset on successful connect
                        let sse = consume_peer_sse(
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
                            keepalive,
                        );
                        match tokio::time::timeout(SSE_SESSION_CAP, sse).await {
                            Ok(Ok(())) => {}
                            Ok(Err(e)) => {
                                eprintln!("SSE stream ended: {e} — resync + reconnect")
                            }
                            Err(_) => {} // 60s cap — fall through to resync (safety net)
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
    keepalive: Option<u16>,
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
                            keepalive,
                        );
                        if added > 0 {
                            println!("SSE: added {added} new peer(s)");
                            write_status(node_id, overlay_s, port, peers);
                        }
                    }
                }
                if evt_type == "peer_removed" && !evt_data.is_empty() {
                    #[derive(serde::Deserialize)]
                    struct SseRemoved {
                        node_id: String,
                    }
                    if let Ok(r) = serde_json::from_str::<SseRemoved>(&evt_data) {
                        if pump::remove_peer_by_node_id(peers, &r.node_id) {
                            println!("SSE: removed peer {}", r.node_id);
                            write_status(node_id, overlay_s, port, peers);
                        }
                    }
                }
                if evt_type == "cert_issued" && !evt_data.is_empty() {
                    #[derive(serde::Deserialize)]
                    struct SseCert {
                        fqdn: String,
                        cert_pem: String,
                    }
                    if let Ok(c) = serde_json::from_str::<SseCert>(&evt_data) {
                        // Persist immediately; the relay listener itself starts on the
                        // next resync pass (same belt-and-suspenders gap as peer_removed
                        // above — acceptable, bounded by the reconnect backoff).
                        crate::tls_relay::on_cert_issued(&c.fqdn, &c.cert_pem);
                        println!("SSE: cert issued for {}", c.fqdn);
                    }
                }
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

/// For every branded subdomain THIS node owns (`target_node_id == my_node_id`),
/// drive it toward a running local TLS relay: CSR → cert → listener. Safe to
/// call every resync cycle — `Relay` dedupes CSR submission per fqdn.
/// `[T:F-3 auto-TLS, Slice 3]`
#[allow(clippy::too_many_arguments)]
fn spawn_owned_subdomain_tasks(
    relay: &crate::tls_relay::Relay,
    http: &reqwest::Client,
    control_plane: &str,
    service_token: &str,
    table: &agent_core::domain::ResolveTable,
    my_node_id: &str,
    overlay_ip: IpAddr,
) {
    for n in table
        .names
        .iter()
        .filter(|n| n.target_node_id == my_node_id)
    {
        // HTTP first: no cert/CSR dependency, so the name works immediately —
        // PrivDomain traffic is already private (overlay-only, A.1.1). TLS is
        // a nice-to-have layered on top once a cert lands. `[T: founder 2026-07-02]`
        relay.ensure_http_listener(&n.fqdn, overlay_ip, n.target_port);
        relay.spawn_owner_task(
            http.clone(),
            control_plane.to_string(),
            service_token.to_string(),
            n.fqdn.clone(),
            n.target_port,
            overlay_ip,
        );
    }
}

struct Config {
    control_plane: String,
    token: Option<String>,
    /// Scoped, short-lived, single-use join token (E-3). Preferred over `token` for
    /// initial enrollment: a golden image / MOTD carries this, never a full-power
    /// session token. `[T:P.3 + part-d-invite-flow.md §3]`
    join_token: Option<String>,
    listen_port: u16,
    state_path: String,
}

impl Config {
    fn parse(args: &[String]) -> Result<Self> {
        let mut control_plane = std::env::var("ANKAYMA_CONTROL_PLANE")
            .unwrap_or_else(|_| DEFAULT_CONTROL_PLANE.to_string());
        let mut token = std::env::var("ANKAYMA_TOKEN").ok();
        // Cloud-init user-data sets this on DO/other clouds so a fresh droplet joins
        // headlessly with no SSH. `[T:plan-do-1click-image Phase A-a]`
        let mut join_token = std::env::var("ANKAYMA_JOIN_TOKEN").ok();
        let mut listen_port = DEFAULT_LISTEN_PORT;
        let mut state_path = default_state_path();

        let mut it = args.iter();
        while let Some(a) = it.next() {
            match a.as_str() {
                "--control-plane" => {
                    control_plane = it.next().context("--control-plane needs a value")?.clone()
                }
                "--token" => token = Some(it.next().context("--token needs a value")?.clone()),
                "--join-token" => {
                    join_token = Some(it.next().context("--join-token needs a value")?.clone())
                }
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
            join_token,
            listen_port,
            state_path,
        })
    }
}

/// Home base for `~/.ankayma/…` — thin alias for the shared resolver so `agent up`
/// and `agent ssh` share one state dir with the GUI on every platform. `[T:A.1.3]`
pub(crate) fn home_root() -> String {
    agent_core::home_root()
}

fn default_state_path() -> String {
    format!("{}/.ankayma/agent.json", home_root())
}

/// [F-2 v0.5] Start the embedded SSH server on the overlay. Best-effort: a failure
/// here (e.g. can't bind, no host key) is logged, never fatal to the data plane.
/// The host key persists at `~/.ankayma/ssh-host-ed25519`; its public form is what
/// the control plane distributes for clients to PIN (A.1.3). Port default 22022,
/// override via `ANKAYMA_SSH_PORT` (shared-host knob, mirrors the relay-port env).
#[cfg(any(unix, windows))]
async fn start_embedded_ssh(
    self_overlay: std::net::IpAddr,
    control_plane: &str,
    node_id: &str,
    overlay_iface: &str,
    http: &reqwest::Client,
) {
    use agent_core::ssh_grant::GrantVerifier;
    use agent_core::ssh_server::{serve, SshHostKey, SshServerConfig};

    let home = home_root();
    let host_key_path = std::path::Path::new(&home)
        .join(".ankayma")
        .join("ssh-host-ed25519");
    let host_key = match SshHostKey::load_or_generate(&host_key_path) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("[F-2] embedded ssh server not started (host key): {e}");
            return;
        }
    };
    if let Ok(fp) = host_key.public_openssh() {
        // Print so the host key can be pinned manually until the control plane
        // returns it in /ssh/session. `[T:A.1.3]`
        println!("[F-2] ssh host key: {fp}");
    }
    let port = std::env::var("ANKAYMA_SSH_PORT")
        .ok()
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(22022);
    let mut cfg = SshServerConfig::f0(self_overlay.to_string());
    cfg.port = port;

    // [F-2 §H.4] Enable root elevation if the control plane publishes a verify key.
    // Best-effort: if the CP has no elevation key (or is unreachable), the node just
    // won't honor `--root` grants — it never grants root on its own.
    match adapters::elevate_pubkey(http, control_plane).await {
        Ok(pubkey) => match GrantVerifier::new(&pubkey, node_id) {
            Ok(v) => {
                cfg = cfg.with_elevation(v);
                println!("[F-2] root elevation enabled (CP grant-verified, §H.4)");
            }
            Err(e) => eprintln!("[F-2] elevation disabled (bad CP key): {e}"),
        },
        Err(e) => eprintln!("[F-2] elevation disabled (CP key unavailable): {e}"),
    }

    println!("[F-2] embedded ssh server on {self_overlay}:{port} (user ankayma, identity-bound)");
    // A default-deny firewall (ufw) silently drops the overlay port → clients time
    // out. Tell the operator (or auto-open with their opt-in). `[T:f2 §H.1]`
    advise_firewall(port, overlay_iface);
    tokio::spawn(async move {
        if let Err(e) = serve(cfg, host_key).await {
            eprintln!("[F-2] embedded ssh server stopped: {e}");
        }
    });
}

/// [F-2] Firewall for the embedded-server port. On a Linux node with `ufw` in
/// default-deny, the overlay port must be allowed or clients time out (packets
/// dropped before the listener). The rule is scoped to the overlay interface — it
/// admits ONLY authenticated WireGuard mesh peers, the same trust boundary as the
/// overlay-only bind (A.1.6) and `Authorizer::TrustOverlay`. So the agent opening
/// its own mesh port is not the "silent side-effect on the host firewall" P.2 warns
/// about; leaving it shut is the real footgun — F-2 mesh SSH silently times out on
/// every headless server, which is the core NoSecret-CI deploy target. So we open it
/// by DEFAULT and log it; `ANKAYMA_NO_FIREWALL=1` opts out for operators who manage
/// the firewall out of band. `[T:A.1.6 overlay-only + P.6 dogfood]`
#[cfg(target_os = "linux")]
fn advise_firewall(port: u16, iface: &str) {
    // F-2 mesh SSH — scope to the overlay interface: only authenticated WG peers.
    ufw_open(
        port,
        "tcp",
        Some(iface),
        "[F-2]",
        "mesh SSH clients time out",
    );
}

/// Open EVERY inbound port the agent needs on a headless Linux node with `ufw`
/// active — one place, so adding a port never turns into whack-a-mole (open one,
/// hit the next failure). The rule is added by DEFAULT and logged; a single
/// `ANKAYMA_NO_FIREWALL=1` opts out of all of it (operator manages the firewall out
/// of band). `iface = Some(overlay)` scopes the rule to the mesh interface (mesh-only
/// exposure, A.1.6). `iface = None` is a public port — used only for the WireGuard
/// data plane, safe to expose because WG authenticates every packet by key and
/// silently drops anything unsigned. `[T:A.1.6 overlay-only + P.6 dogfood]`
#[cfg(target_os = "linux")]
fn ufw_open(port: u16, proto: &str, iface: Option<&str>, tag: &str, why_if_shut: &str) {
    let status = std::process::Command::new("ufw")
        .arg("status")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();
    if !status.contains("Status: active") {
        // No ufw (or inactive). An iptables/nftables default-deny we can't reliably
        // detect — the operator opens it themselves in that case.
        return;
    }
    let port_proto = format!("{port}/{proto}");
    let manual = match iface {
        Some(i) => format!("ufw allow in on {i} to any port {port} proto {proto}"),
        None => format!("ufw allow {port_proto}"),
    };
    // Already allowed? Don't nag. (Status line like "22022/tcp on ank0 ALLOW" or
    // "51820/udp ... ALLOW".)
    if status
        .lines()
        .any(|l| l.contains(&port_proto) && l.contains("ALLOW"))
    {
        println!("{tag} firewall: {port_proto} already allowed ✓");
        return;
    }
    if std::env::var("ANKAYMA_NO_FIREWALL")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
    {
        eprintln!("{tag} ⚠ ufw active, {port_proto} NOT opened (ANKAYMA_NO_FIREWALL=1) —");
        eprintln!("{tag}   {why_if_shut} until you allow it: {manual}");
        return;
    }
    let pstr = port.to_string();
    let ok = if let Some(i) = iface {
        std::process::Command::new("ufw")
            .args([
                "allow", "in", "on", i, "to", "any", "port", &pstr, "proto", proto,
            ])
            .status()
    } else {
        std::process::Command::new("ufw")
            .args(["allow", &port_proto])
            .status()
    }
    .map(|s| s.success())
    .unwrap_or(false);
    if ok {
        let scope = if iface.is_some() {
            "overlay-only"
        } else {
            "public; WG key-authenticated"
        };
        println!(
            "{tag} firewall: opened {port_proto} ({scope}; set ANKAYMA_NO_FIREWALL=1 to skip)"
        );
    } else {
        eprintln!("{tag} firewall: could not auto-open {port_proto} — run: {manual}");
    }
}

/// [wg] WireGuard data-plane inbound. A default-deny `ufw` drops peers' handshake
/// packets, so any peer that must INITIATE to this node (an ephemeral CI runner, a
/// node behind NAT) never connects — the mesh silently half-works. Public port,
/// key-authenticated: open by default. `[T:A.1.6 + P.6]`
#[cfg(target_os = "linux")]
fn advise_wg_firewall(port: u16) {
    ufw_open(
        port,
        "udp",
        None,
        "[wg]",
        "peers can't hand-shake in (data plane)",
    );
}

#[cfg(target_os = "windows")]
fn advise_firewall(port: u16, _iface: &str) {
    // Mesh SSH target port. Windows Firewall has no interface-scoping like ufw, so
    // the rule is by port — safe: the SSH server binds the overlay address only.
    netsh_open(port, "TCP", "[F-2]", "mesh SSH clients time out");
}

/// Windows analogue of `ufw_open`: add by DEFAULT the inbound rule the agent needs
/// (the daemon runs elevated) and log it; `ANKAYMA_NO_FIREWALL=1` opts out — the same
/// switch as Linux, so "don't touch my firewall" is one flag on every platform.
/// Leaving the port shut is the real footgun: a Windows node used as a mesh SSH target
/// or a WG peer others initiate to silently times out. `[T:A.1.6 + P.6 dogfood]`
#[cfg(target_os = "windows")]
fn netsh_open(port: u16, proto: &str, tag: &str, why_if_shut: &str) {
    let rule = format!("Ankayma mesh {proto}/{port}");
    let manual = format!(
        "netsh advfirewall firewall add rule name=\"{rule}\" dir=in action=allow protocol={proto} localport={port}"
    );
    if std::env::var("ANKAYMA_NO_FIREWALL")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
    {
        eprintln!(
            "{tag} ⚠ Windows Firewall drops inbound {proto}/{port} (ANKAYMA_NO_FIREWALL=1) —"
        );
        eprintln!("{tag}   {why_if_shut} until you allow it: {manual}");
        return;
    }
    let ok = std::process::Command::new("netsh")
        .args([
            "advfirewall",
            "firewall",
            "add",
            "rule",
            &format!("name={rule}"),
            "dir=in",
            "action=allow",
            &format!("protocol={proto}"),
            &format!("localport={port}"),
        ])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if ok {
        println!(
            "{tag} firewall: allowed inbound {proto}/{port} (set ANKAYMA_NO_FIREWALL=1 to skip)"
        );
    } else {
        eprintln!("{tag} firewall: could not add the rule — run elevated: {manual}");
    }
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
fn advise_firewall(_port: u16, _iface: &str) {}

/// [port-to-Windows] Inbound allow for the data-plane UDP listen port — peers' handshake
/// packets are dropped until it is open, so the overlay never establishes. Default-on
/// via [`netsh_open`], like the Linux path.
#[cfg(target_os = "windows")]
fn advise_wg_firewall(port: u16) {
    netsh_open(
        port,
        "UDP",
        "[wg]",
        "peers can't hand-shake in (data plane)",
    );
}

// macOS (+ other unix): no port-based host firewall on by default — the macOS
// Application Firewall is per-app and off by default, and we don't manage pf. Nodes
// there work without opening ports; if the operator turns the app firewall on, macOS
// prompts per-app in the GUI (not ours to script). iOS/Android are client-only and
// cannot host an inbound listener, so there is nothing to open there either.
#[cfg(not(any(target_os = "windows", target_os = "linux")))]
fn advise_wg_firewall(_port: u16) {}

// [slice 2] Live data-plane status, published for the GUI to read. The GUI runs
// unprivileged and never opens the tunnel itself, so this file is how it learns
// the daemon is actually up (not just enrolled) + the current peer roster.
// Connection-level only (hostname/overlay/endpoint) — never payload [T:A.1.1].
fn status_path() -> String {
    let home = home_root();
    format!("{home}/.ankayma/agent-status.json")
}

#[derive(serde::Serialize)]
struct StatusPeer {
    hostname: String,
    overlay_ip: String,
    endpoint: Option<String>,
    /// Endpoint is known ⇒ direct WireGuard (no relay). False until handshake
    /// completes for a responder-only peer; flips to false for relay peers when
    /// relay lands (A.1.12). [T:A.1.1]
    direct: bool,
    /// Seconds since the last WireGuard handshake, or absent if none yet.
    #[serde(skip_serializing_if = "Option::is_none")]
    last_handshake_secs: Option<u64>,
    tx_bytes: u64,
    rx_bytes: u64,
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
        .map(|p| {
            let ep = p.endpoint();
            let (hs, tx, rx) = p.stats();
            StatusPeer {
                hostname: p.peer.hostname.clone(),
                overlay_ip: p.peer.overlay_ip.to_string(),
                endpoint: ep.map(|e| e.to_string()),
                direct: ep.is_some(),
                last_handshake_secs: hs.map(|d| d.as_secs()),
                tx_bytes: tx as u64,
                rx_bytes: rx as u64,
            }
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
/// `--token` is required only for the initial enrollment — EXCEPT when the
/// persisted identity predates node service tokens (migration 015): that
/// state is otherwise unusable (SSE only ever accepts a node service-token,
/// never a session, so the daemon would sit in a permanent 401 reconnect
/// loop) — re-enroll with the SAME keypair (server matches by pubkey,
/// idempotent — same node_id/overlay_ip come back) to obtain one.
async fn load_or_enroll(http: &reqwest::Client, cfg: &Config) -> Result<AgentState> {
    if let Ok(bytes) = std::fs::read(&cfg.state_path) {
        if let Ok(state) = serde_json::from_slice::<AgentState>(&bytes) {
            if state.service_token.is_some() {
                println!("reusing identity from {}", cfg.state_path);
                return Ok(state);
            }
            match cfg.token.clone() {
                Some(token) => {
                    println!(
                        "reusing identity from {} — missing node service token, \
                         re-enrolling with the same keypair to fetch one",
                        cfg.state_path
                    );
                    return enroll_and_persist(http, cfg, &token, Some(state)).await;
                }
                None => {
                    eprintln!(
                        "warning: {} has no node service token (pre-migration 015) — \
                         SSE peer updates will 401 forever. Pass --token to refresh.",
                        cfg.state_path
                    );
                    return Ok(state);
                }
            }
        }
    }

    // Fresh enroll. Prefer a scoped join token (headless server path) over a full
    // session token so a golden image / MOTD never redeems a full-power secret —
    // the join token is single-use + short-TTL and enrolls this node directly.
    // `[T:P.3 honest-power + part-d-invite-flow.md §3 join redeem]`
    if let Some(join_token) = cfg.join_token.clone() {
        return enroll_via_join_and_persist(http, cfg, &join_token, None).await;
    }
    let token = cfg.token.clone().ok_or_else(|| {
        anyhow!(
            "initial enrollment requires --join-token <token> / ANKAYMA_JOIN_TOKEN \
             (scoped, preferred) or --token <session_token> / ANKAYMA_TOKEN"
        )
    })?;
    enroll_and_persist(http, cfg, &token, None).await
}

/// Session-authed enroll (or idempotent re-enroll if `existing` carries a known
/// keypair) and persist the resulting identity. Shares the keypair/machine-proof
/// prelude with the join path via `enroll_inputs`; see it for the idempotency and
/// golden-image `machine.key` rules.
async fn enroll_and_persist(
    http: &reqwest::Client,
    cfg: &Config,
    token: &str,
    existing: Option<AgentState>,
) -> Result<AgentState> {
    let (kp, proof, endpoint) = enroll_inputs(cfg, &existing)?;
    println!("enrolling node (advertising endpoint {endpoint})…");

    let req = EnrollRequest {
        public_key: kp.public_b64.clone(),
        hostname: hostname(),
        endpoint: Some(endpoint),
        // [T:Part B §B.1.4] server nodes default to AppServer.
        workload_kind: Some("AppServer".to_string()),
        machine_proof: Some(proof),
    };
    let resp = adapters::enroll(http, &cfg.control_plane, token, &req)
        .await
        .map_err(|e| anyhow!("enroll: {e}"))?;

    finalize_enroll(cfg, kp, resp)
}

/// Fresh enroll via a scoped E-3 join token — the headless-server path. Same
/// idempotent keypair + machine-proof prelude and identical `EnrollResponse`
/// handling as `enroll_and_persist`; only the request/endpoint differ (no Bearer,
/// the join token IS the authorization — A.1.10/A.1.22). The node is tagged
/// `AppServer` (Part B §B.1.4) via the control plane's `join_enroll` workload_kind.
/// `[T:part-d-invite-flow.md §3 + A.1.10]`
async fn enroll_via_join_and_persist(
    http: &reqwest::Client,
    cfg: &Config,
    join_token: &str,
    existing: Option<AgentState>,
) -> Result<AgentState> {
    let (kp, proof, endpoint) = enroll_inputs(cfg, &existing)?;
    println!("enrolling node via join token (advertising endpoint {endpoint})…");

    let req = adapters::JoinEnrollRequest {
        join_token: join_token.to_string(),
        public_key: kp.public_b64.clone(),
        hostname: hostname(),
        endpoint: Some(endpoint),
        // [T:Part B §B.1.4] a headless node enrolled by `agent up` is a server.
        workload_kind: Some("AppServer".to_string()),
        machine_proof: Some(proof),
    };
    let resp = adapters::enroll_via_join_token(http, &cfg.control_plane, &req)
        .await
        .map_err(|e| anyhow!("join enroll: {e}"))?;

    finalize_enroll(cfg, kp, resp)
}

/// Shared enrollment prelude: the (idempotent) keypair, this device's machine
/// proof over it, and the advertised LAN endpoint. Reusing `existing`'s keypair —
/// rather than generating a new one — is what makes a re-enroll idempotent: the
/// control plane keys a persistent node on its enrolled public key, so the same
/// key returns the same node. The machine proof makes that survive losing the
/// keypair too: the server matches the DEVICE, so a rebuilt `agent.json` rotates
/// the node's key in place.
///
/// The machine key is a 0600 file beside `agent.json` (a headless node has no
/// keystore). It is NOT derived from `/etc/machine-id`, which systemd generates
/// randomly and forbids putting on the network. Golden images must ship without
/// `machine.key`, exactly as systemd requires for `/etc/machine-id`: every clone
/// would otherwise be the same device and fight over one node.
/// `[T:man 5 machine-id + systemd.io/BUILDING_IMAGES]`
fn enroll_inputs(
    cfg: &Config,
    existing: &Option<AgentState>,
) -> Result<(WgKeypair, String, String)> {
    let kp = match existing {
        Some(s) => WgKeypair {
            private_b64: s.private_b64.clone(),
            public_b64: s.public_b64.clone(),
        },
        None => WgKeypair::generate(),
    };
    let state_dir = Path::new(&cfg.state_path)
        .parent()
        .unwrap_or(Path::new("."))
        .to_path_buf();
    let machine = agent_core::machine_key::MachineKey::load_or_create(&state_dir)
        .context("load or create this device's machine key")?;
    let proof = machine
        .proof_now(&kp.public_b64)
        .context("sign the enrollment with this device's machine key")?;

    let lan_ip = detect_lan_ip().context("detect this machine's LAN IP")?;
    let endpoint = format!("{lan_ip}:{}", cfg.listen_port);
    Ok((kp, proof, endpoint))
}

/// Handle the `EnrollResponse` common to both enroll paths: warn on a missing node
/// service token, sanity-check the Layer 2 cert chain, then build + persist the
/// `AgentState`.
fn finalize_enroll(cfg: &Config, kp: WgKeypair, resp: EnrollResponse) -> Result<AgentState> {
    if resp.node_service_token.is_none() {
        eprintln!(
            "warning: control-plane did not return a node service token (pre-migration 015). \
             Re-enroll after updating the control plane."
        );
    }

    // [Layer 2] Post-enroll sanity check: the leaf the CP handed us really is
    // signed by the CA it handed us — catches CP misconfig at enroll time. A
    // failure is loud but non-fatal: Layer 1 (bearer token) still works and the
    // broker isn't dialed until the broker milestone. [A: fail-open here until
    // an mTLS consumer exists; revisit when broker transport lands]
    // [T:part-d-layer2-cert-infrastructure.md §H.2 Step 1]
    if let (Some(leaf), Some(ca)) = (&resp.node_cert_pem, &resp.provisioning_ca_pem) {
        match agent_core::cert::verify_cert_chain(leaf, ca) {
            Ok(()) => println!("node cert verified against provisioning CA"),
            Err(e) => eprintln!(
                "WARNING: node cert does NOT verify against the provisioning CA ({e}) — \
                 broker mTLS will fail; report this to your control-plane operator"
            ),
        }
    }
    let cert_expires_at = resp
        .node_cert_pem
        .as_deref()
        .and_then(|c| agent_core::cert::cert_expiry_rfc3339(c).ok());

    let state = AgentState {
        private_b64: kp.private_b64,
        public_b64: kp.public_b64,
        node_id: resp.node_id,
        overlay_ip: resp.overlay_ip,
        listen_port: cfg.listen_port,
        service_token: resp.node_service_token,
        token_expires_at: resp.token_expires_at,
        workload_kind: Some("AppServer".to_string()),
        node_cert_pem: resp.node_cert_pem,
        provisioning_ca_pem: resp.provisioning_ca_pem,
        crl_pem: None, // fetched from crl_url right after startup (4h loop)
        crl_url: resp.crl_url,
        cert_expires_at,
    };
    persist_state(&cfg.state_path, &state)?;
    Ok(state)
}

/// Write `agent.json`. mode 0o600: the WireGuard private key must not be
/// readable by other users on the same host (cert + CA ride along — not secret
/// per se, defense in depth). [T:A.3.4]
fn persist_state(state_path: &str, state: &AgentState) -> Result<()> {
    if let Some(dir) = std::path::Path::new(state_path).parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    #[cfg(unix)]
    let mut f = {
        use std::os::unix::fs::OpenOptionsExt;
        OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(state_path)
            .with_context(|| format!("create identity file {state_path}"))?
    };
    #[cfg(not(unix))]
    let mut f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(state_path)
        .with_context(|| format!("create identity file {state_path}"))?;
    f.write_all(&serde_json::to_vec_pretty(state)?)
        .with_context(|| format!("persist identity to {state_path}"))?;
    Ok(())
}

/// Read-modify-write the renewed service token + expiry into `agent.json` (the daemon
/// is the only writer after startup; mirror `refresh_crl_once`). Keeps a restarted
/// daemon on the fresh token. `[T:Part D §D.11]`
fn persist_service_token(state_path: &str, token: &str, expires_at: Option<&str>) -> Result<()> {
    let bytes = std::fs::read(state_path).context("read agent.json for token renewal")?;
    let mut state: AgentState = serde_json::from_slice(&bytes).context("parse agent.json")?;
    state.service_token = Some(token.to_string());
    state.token_expires_at = expires_at.map(|s| s.to_string());
    persist_state(state_path, &state)
}

/// How often to renew the node service token. Must stay well under the token TTL so a
/// single failed renewal still has margin before expiry: safe for the 24h+ TTLs
/// targeted for long-running nodes (renews with >=16h of slack at a 24h TTL). A test
/// tenant issuing sub-16h tokens should lower this.
/// `[T:Part D §D.11 node service token]`
const TOKEN_RENEW_INTERVAL: Duration = Duration::from_secs(8 * 3600);

/// Renew the node service token in the background so a long-running headless node
/// never dies at token expiry — the fix for the "control-plane rejects our credential"
/// roster freeze. Renewal is proof-of-possession (present the current token), so no
/// login credential is needed on a headless box. Mirrors `spawn_crl_refresh`: never
/// blocks the main loop; on failure the OLD token stays valid (renewal did not rotate)
/// so we simply retry next tick. The renewed token is published into `token_cell`
/// (the refresh loop reads it each cycle) and persisted to `agent.json`.
/// `[T:Part D §D.11 node service token]`
fn spawn_token_renewal(
    http: reqwest::Client,
    control_plane: String,
    node_id: String,
    state_path: String,
    token_cell: Arc<RwLock<String>>,
) {
    tokio::spawn(async move {
        loop {
            // Sleep first: the token is fresh at startup, so there is nothing to do
            // until roughly the renewal interval has elapsed.
            tokio::time::sleep(TOKEN_RENEW_INTERVAL).await;
            let current = token_cell.read().unwrap().clone();
            match adapters::renew_service_token(&http, &control_plane, &node_id, &current).await {
                Ok((new_token, new_expiry)) => {
                    // Publish for the refresh loop FIRST, then persist for restarts.
                    if let Ok(mut w) = token_cell.write() {
                        *w = new_token.clone();
                    }
                    if let Err(e) =
                        persist_service_token(&state_path, &new_token, new_expiry.as_deref())
                    {
                        eprintln!("service token renewed but persisting to agent.json failed: {e}");
                    }
                    println!("node service token renewed");
                }
                Err(e) => {
                    eprintln!(
                        "service token renewal failed: {e} — the current token stays valid \
                         until its expiry; will retry next cycle"
                    );
                }
            }
        }
    });
}

/// Fetch the CRL from the CP and cache it into `agent.json` (read-modify-write:
/// the daemon is the only writer after startup). Revocation = CRL broadcast
/// (B.4.2); rustls enforces the cached CRL at the next broker handshake.
async fn refresh_crl_once(http: &reqwest::Client, crl_url: &str, state_path: &str) -> Result<()> {
    let pem = http
        .get(crl_url)
        .timeout(agent_core::adapters::CP_REST_TIMEOUT)
        .send()
        .await
        .context("CRL fetch")?
        .error_for_status()
        .context("CRL fetch status")?
        .text()
        .await
        .context("CRL body")?;
    // [T:RFC-7468§6] PEM label for a CRL is "X509 CRL". Reject anything else
    // early so a captive portal / error page never lands in agent.json.
    if !pem.contains("-----BEGIN X509 CRL-----") {
        return Err(anyhow!(
            "CRL endpoint returned something that is not a PEM CRL"
        ));
    }
    let bytes = std::fs::read(state_path).context("read agent.json for CRL update")?;
    let mut state: AgentState = serde_json::from_slice(&bytes).context("parse agent.json")?;
    state.crl_pem = Some(pem);
    persist_state(state_path, &state)
}

/// Refresh the CRL now, then every 4h for the daemon's lifetime.
/// Fail-open on staleness (keep serving with the cached CRL, warn after ~48h
/// of consecutive failures); TLS verification itself stays fail-closed.
/// [A risk-accepted per spec §H.2: staleness window bounded by CRL TTL]
fn spawn_crl_refresh(http: reqwest::Client, crl_url: String, state_path: String) {
    tokio::spawn(async move {
        let mut consecutive_failures: u32 = 0;
        loop {
            match refresh_crl_once(&http, &crl_url, &state_path).await {
                Ok(()) => {
                    consecutive_failures = 0;
                    println!("CRL refreshed from {crl_url}");
                }
                Err(e) => {
                    consecutive_failures += 1;
                    eprintln!("CRL refresh failed: {e} — keeping cached CRL");
                    // 12 ticks × 4h = 48h without a fresh CRL.
                    if consecutive_failures >= 12 {
                        eprintln!(
                            "WARNING: cached CRL is >48h stale — recently revoked \
                             nodes may still be accepted until refresh succeeds"
                        );
                    }
                }
            }
            tokio::time::sleep(Duration::from_secs(4 * 3600)).await;
        }
    });
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

/// `Some(25)` when this node is behind NAT, `None` when its detected address is
/// globally routable. Behind-NAT = the OS's outbound source address is not a
/// public IP: RFC1918 private, link-local, or CGNAT `100.64.0.0/10`
/// `[T:RFC-6598§7]`. 25s is the conventional WireGuard NAT-keepalive interval
/// `[T:wireguard.com/quickstart PersistentKeepalive=25]`.
fn self_nat_keepalive() -> Option<u16> {
    let ip = detect_lan_ip().ok()?;
    let o = ip.octets();
    let cgnat = o[0] == 100 && (64..128).contains(&o[1]);
    if ip.is_private() || ip.is_link_local() || cgnat {
        Some(25)
    } else {
        None
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
        // [A? verify-on-macOS] IPv6: assign host /128 on utun; per-peer /128 routes added later.
        IpAddr::V6(_) => {
            run_cmd(Command::new("ifconfig").args([name, "inet6", &ip, "prefixlen", "128", "up"]))?;
        }
    }
    // Clamp the device MTU to the overlay MTU so the kernel never hands the pump
    // a packet that can't fit WireGuard's +32B overhead inside one UDP datagram.
    // utun defaults to 1500; large flows (ssh key-exchange was the reproducer,
    // 2026-07-03) then overflow the encapsulate buffer. `[T:WireGuard MTU 1420]`
    run_cmd(Command::new("ifconfig").args([name, "mtu", &agent_core::pump::MTU.to_string()]))?;
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
    // Same MTU clamp as macOS: never read a tun packet bigger than one encrypted
    // UDP datagram can carry. `[T:WireGuard MTU 1420]`
    run_cmd(Command::new("ip").args([
        "link",
        "set",
        "dev",
        name,
        "mtu",
        &agent_core::pump::MTU.to_string(),
    ]))?;
    Ok(())
}

// Windows: set the overlay host address + MTU on the Wintun adapter via netsh (found
// by the adapter name "Ankayma"). Same host-address + MTU-clamp model as macOS/Linux.
// [T:§H.6; netsh interface]
#[cfg(target_os = "windows")]
fn configure_interface(name: &str, overlay: IpAddr) -> Result<()> {
    let ip = overlay.to_string();
    match overlay {
        IpAddr::V4(_) => {
            run_cmd(Command::new("netsh").args([
                "interface",
                "ipv4",
                "set",
                "address",
                &format!("name={name}"),
                "static",
                &ip,
                "255.255.255.255",
            ]))?;
        }
        IpAddr::V6(_) => {
            run_cmd(Command::new("netsh").args([
                "interface",
                "ipv6",
                "add",
                "address",
                &format!("interface={name}"),
                &format!("address={ip}/128"),
            ]))?;
        }
    }
    // Same MTU clamp as macOS/Linux — never read a tun packet bigger than one
    // encrypted UDP datagram can carry. `[T:WireGuard MTU 1420]`
    run_cmd(Command::new("netsh").args([
        "interface",
        "ipv6",
        "set",
        "subinterface",
        name,
        &format!("mtu={}", agent_core::pump::MTU),
        "store=persistent",
    ]))?;
    Ok(())
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn configure_interface(_name: &str, _overlay: IpAddr) -> Result<()> {
    Err(anyhow!(
        "interface configuration is implemented for macOS + Linux + Windows [T:A.1.9]"
    ))
}

/// Route one peer's overlay address into the tunnel device. `route delete` first
/// makes it idempotent and steals the /32 from any other overlay holding it
/// (e.g. a stale Tailscale route). Best-effort: a failure is logged, not fatal.
#[cfg(target_os = "macos")]
fn add_peer_route(name: &str, overlay: IpAddr) {
    // host route per-peer: /32 (v4) or /128 (v6) — wins over any overlapping range (e.g. Tailscale /10).
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

/// Windows: route this peer's overlay host into the Wintun interface via netsh.
/// Delete-first for idempotency (best-effort — the route may not exist yet).
#[cfg(target_os = "windows")]
fn add_peer_route(name: &str, overlay: IpAddr) {
    let (fam, dst) = match overlay {
        IpAddr::V4(a) => ("ipv4", format!("{a}/32")),
        IpAddr::V6(a) => ("ipv6", format!("{a}/128")),
    };
    let _ = Command::new("netsh")
        .args([
            "interface",
            fam,
            "delete",
            "route",
            &format!("prefix={dst}"),
            &format!("interface={name}"),
        ])
        .output();
    if let Err(e) = run_cmd(Command::new("netsh").args([
        "interface",
        fam,
        "add",
        "route",
        &format!("prefix={dst}"),
        &format!("interface={name}"),
    ])) {
        eprintln!("warning: could not route {dst} via {name}: {e}");
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn add_peer_route(_name: &str, _overlay: IpAddr) {}

// Only the macOS/Linux interface/route helpers above call this; gate it to match
// so a build without those helpers doesn't flag it as dead code. [T:A.1.9]
#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
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
#[allow(clippy::too_many_arguments)]
fn add_new_peers(
    peers: &Peers,
    index: &Arc<Mutex<u32>>,
    static_private: &StaticSecret,
    self_overlay: IpAddr,
    list: &[agent_core::domain::PeerInfo],
    udp: &Arc<UdpSocket>,
    dev_name: &str,
    keepalive: Option<u16>,
) -> usize {
    let added = pump::add_tunn_peers(
        peers,
        index,
        static_private,
        self_overlay,
        list,
        udp,
        keepalive,
    );
    for overlay in &added {
        // Route this peer's overlay /32 into the tunnel (wins over Tailscale's /10).
        add_peer_route(dev_name, *overlay);
    }
    added.len()
}

/// Like `add_new_peers`, but also prunes any peer no longer in `list` — the
/// resync-on-reconnect path uses this instead of the pure-additive `add_new_peers`
/// so a revoked/replaced peer's real IP actually disappears from local state
/// (`pump::reconcile_peers`, A.5.3). Route cleanup for removed peers is left as-is
/// (stale `/32` host route is cosmetic residue, not a visibility leak — no session
/// exists to answer it).
#[allow(clippy::too_many_arguments)]
fn reconcile_new_and_stale_peers(
    peers: &Peers,
    index: &Arc<Mutex<u32>>,
    static_private: &StaticSecret,
    self_overlay: IpAddr,
    list: &[agent_core::domain::PeerInfo],
    udp: &Arc<UdpSocket>,
    dev_name: &str,
    keepalive: Option<u16>,
) -> (usize, usize) {
    let (added, removed) = pump::reconcile_peers(
        peers,
        index,
        static_private,
        self_overlay,
        list,
        udp,
        keepalive,
    );
    for overlay in &added {
        add_peer_route(dev_name, *overlay);
    }
    (added.len(), removed)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `--join-token` parses into `Config.join_token`; the session `--token` stays
    /// independent so `load_or_enroll` can prefer the scoped token. Uses only
    /// explicit args (no env mutation) so it is deterministic under parallel tests.
    /// [T:P.3 headless enroll]
    #[test]
    fn parse_join_token_flag() {
        let args = [
            "--control-plane".to_string(),
            "https://cp.example".to_string(),
            "--join-token".to_string(),
            "scoped-abc".to_string(),
        ];
        let cfg = Config::parse(&args).unwrap();
        assert_eq!(cfg.join_token.as_deref(), Some("scoped-abc"));
        assert_eq!(cfg.control_plane, "https://cp.example");
    }

    /// `--join-token` needs a value — a trailing flag is a parse error, not a
    /// silent empty token that would fail confusingly at enroll time.
    #[test]
    fn parse_join_token_requires_value() {
        let args = ["--join-token".to_string()];
        assert!(Config::parse(&args).is_err());
    }

    /// agent.json written by a pre-Layer-2 daemon must keep loading: every
    /// Layer 2 field is `#[serde(default)]` → None. [T per P.4 compose]
    #[test]
    fn agent_state_pre_layer2_json_still_loads() {
        let old = r#"{
            "private_b64": "priv",
            "public_b64": "pub",
            "node_id": "n1",
            "overlay_ip": "100.64.0.2",
            "listen_port": 51820
        }"#;
        let st: AgentState = serde_json::from_str(old).unwrap();
        assert_eq!(st.node_cert_pem, None);
        assert_eq!(st.provisioning_ca_pem, None);
        assert_eq!(st.crl_pem, None);
        assert_eq!(st.crl_url, None);
        assert_eq!(st.cert_expires_at, None);
    }

    /// persist_state round-trips the Layer 2 fields and keeps agent.json 0600
    /// (private key + cert material must not be world-readable). [T:A.3.4]
    #[test]
    fn persist_state_roundtrips_cert_fields_mode_0600() {
        let dir = std::env::temp_dir().join(format!("agent-up-test-{}", std::process::id()));
        let path = dir.join("agent.json");
        let path_s = path.to_str().unwrap().to_string();
        let state = AgentState {
            private_b64: "priv".into(),
            public_b64: "pub".into(),
            node_id: "n1".into(),
            overlay_ip: "100.64.0.2".into(),
            listen_port: 51820,
            service_token: None,
            token_expires_at: None,
            workload_kind: None,
            node_cert_pem: Some("LEAF".into()),
            provisioning_ca_pem: Some("CA".into()),
            crl_pem: Some("CRL".into()),
            crl_url: Some("https://cp.example/pki/crl.pem".into()),
            cert_expires_at: Some("2027-07-04T00:00:00Z".into()),
        };
        persist_state(&path_s, &state).unwrap();

        let loaded: AgentState = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(loaded.node_cert_pem.as_deref(), Some("LEAF"));
        assert_eq!(
            loaded.crl_url.as_deref(),
            Some("https://cp.example/pki/crl.pem")
        );
        assert_eq!(
            loaded.cert_expires_at.as_deref(),
            Some("2027-07-04T00:00:00Z")
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "agent.json must be owner-only");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// persist_service_token rotates the token + expiry and PRESERVES every other
    /// field (read-modify-write, not a blind overwrite — so a renewal in the
    /// background never drops the cert/CRL a concurrent path just wrote).
    /// [T:Part D §D.11]
    #[test]
    fn persist_service_token_rotates_and_preserves() {
        let dir = std::env::temp_dir().join(format!("agent-up-tok-test-{}", std::process::id()));
        let path = dir.join("agent.json");
        let path_s = path.to_str().unwrap().to_string();
        let state = AgentState {
            private_b64: "priv".into(),
            public_b64: "pub".into(),
            node_id: "n1".into(),
            overlay_ip: "100.64.0.2".into(),
            listen_port: 51820,
            service_token: Some("nst_old".into()),
            token_expires_at: Some("2026-07-14 00:00:00+00".into()),
            workload_kind: Some("AppServer".into()),
            node_cert_pem: Some("LEAF".into()),
            provisioning_ca_pem: Some("CA".into()),
            crl_pem: Some("CRL".into()),
            crl_url: Some("https://cp.example/pki/crl.pem".into()),
            cert_expires_at: Some("2027-07-04T00:00:00Z".into()),
        };
        persist_state(&path_s, &state).unwrap();

        // Postgres-text expiry (space, not RFC3339 'T') — same shape the CP returns.
        persist_service_token(&path_s, "nst_new", Some("2026-10-11 00:00:00+00")).unwrap();

        let loaded: AgentState = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        // rotated:
        assert_eq!(loaded.service_token.as_deref(), Some("nst_new"));
        assert_eq!(
            loaded.token_expires_at.as_deref(),
            Some("2026-10-11 00:00:00+00")
        );
        // preserved:
        assert_eq!(loaded.node_id, "n1");
        assert_eq!(loaded.workload_kind.as_deref(), Some("AppServer"));
        assert_eq!(loaded.node_cert_pem.as_deref(), Some("LEAF"));
        assert_eq!(
            loaded.crl_url.as_deref(),
            Some("https://cp.example/pki/crl.pem")
        );
        assert_eq!(
            loaded.cert_expires_at.as_deref(),
            Some("2027-07-04T00:00:00Z")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
