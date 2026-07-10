//! pump — the reusable WireGuard packet pump over a tun fd. OPEN, intensity
//! **Critical**.
//!
//! This is the OS-agnostic half of the data plane, lifted out of agent-daemon so
//! both hosts share it (A.1.9): the macOS/Linux daemon (`agent up`) and the iOS
//! Network Extension (Packet Tunnel Provider). It owns the per-peer boringtun
//! state and the three threads that move packets:
//!   1. tun → encapsulate → UDP   (`spawn_tx`)
//!   2. UDP → decapsulate → tun   (`spawn_rx`)
//!   3. WireGuard timer driver    (`spawn_timers`)
//!
//! What it deliberately does NOT do: open the tun device, assign the overlay IP,
//! or add routes. Those are host-specific (utun + ifconfig/route on the daemon;
//! `NEPacketTunnelNetworkSettings` in Swift on iOS) and stay with the caller. The
//! caller hands `pump` an already-open fd + a bound UDP socket. `[T:A.1.9]`

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::dataplane::{self, DialablePeer};
use crate::domain::PeerInfo;
use crate::tunnel::{handshake_established, make_tunn, PublicKey, StaticSecret, Tunn, TunnResult};

/// Safe overlay MTU under a typical 1500-byte path. `[T:WireGuard]`
pub const MTU: usize = 1420;

/// Optional diagnostic sink. The desktop daemon logs to stdout; the iOS Packet
/// Tunnel extension has no console, so it installs a hook that forwards to the
/// platform log (NSLog). Used to trace the outbound send path when a peer never
/// answers — the one place iOS visibility was missing. `[T:A.1.9]`
static LOG_HOOK: std::sync::OnceLock<fn(&str)> = std::sync::OnceLock::new();

/// Install a diagnostic log sink (idempotent; first caller wins).
pub fn set_log_hook(f: fn(&str)) {
    let _ = LOG_HOOK.set(f);
}

/// Emit a diagnostic line to the installed hook, else stdout.
fn plog(msg: &str) {
    match LOG_HOOK.get() {
        Some(f) => f(msg),
        None => println!("{msg}"),
    }
}

/// Tear down an established session after this much *data* silence — tunnels are
/// ephemeral, not process-lifetime. `[T:A.1.7 — idle timeout 5-10 min]` The next
/// outbound packet re-handshakes on demand (boringtun queues it and emits a fresh
/// initiation), so teardown costs one handshake RTT on resume, nothing else.
pub const IDLE_TEARDOWN: Duration = Duration::from_secs(300);

/// One peer's live tunnel: metadata + its boringtun state machine + the current
/// UDP endpoint. For a responder peer (no advertised endpoint, e.g. a CI runner
/// behind NAT) the endpoint starts `None` and is learned from the first handshake;
/// it is also refreshed on roaming. `[T:Part C §H.3.3 B-3]`
pub struct PeerEntry {
    /// Connection-level peer metadata (hostname/overlay/key) — never payload.
    pub peer: DialablePeer,
    endpoint: Mutex<Option<SocketAddr>>,
    tunn: Mutex<Tunn>,
    /// When *data* (not handshake/keepalive) last crossed this tunnel, either
    /// direction — drives idle-teardown. `[T:A.1.7]`
    last_activity: Mutex<Instant>,
    /// The keepalive this peer's `Tunn` was built with, so an idle-teardown
    /// rebuild preserves it (NAT'd node keeps 25s, public node keeps None).
    keepalive: Option<u16>,
}

impl PeerEntry {
    /// Where this peer is currently reachable, if known.
    pub fn endpoint(&self) -> Option<SocketAddr> {
        *self.endpoint.lock().expect("endpoint lock")
    }
    /// Learn/refresh where this peer is reachable (handshake source / roaming).
    fn set_endpoint(&self, ep: SocketAddr) {
        *self.endpoint.lock().expect("endpoint lock") = Some(ep);
    }
    fn touch(&self) {
        *self.last_activity.lock().expect("activity lock") = Instant::now();
    }
    fn idle_for(&self) -> Duration {
        self.last_activity.lock().expect("activity lock").elapsed()
    }
    /// WireGuard session statistics: time since last handshake (None if none yet),
    /// cumulative bytes sent, cumulative bytes received. Evidence for F-5 proof.
    /// [T:A.1.1] — byte counters prove data moved without transiting the vendor.
    pub fn stats(&self) -> (Option<Duration>, usize, usize) {
        let tunn = self.tunn.lock().expect("tunn lock");
        let (hs, tx, rx, _, _) = tunn.stats();
        (hs, tx, rx)
    }
}

/// The shared, mutable peer roster. `Arc<Mutex<…>>` because the three pump threads
/// and the caller's refresh loop all touch it.
pub type Peers = Arc<Mutex<Vec<Arc<PeerEntry>>>>;

/// Add peers we don't already have a tunnel for: build a boringtun `Tunn`, kick off
/// the handshake when we know the endpoint, and push it onto the roster. Returns
/// the overlay address of every peer added — the caller routes those into the tun
/// device (host route on the daemon; `includedRoutes` in Swift on iOS). Routing is
/// intentionally NOT done here so the pump stays OS-agnostic. `[T:A.1.9]`
/// `keepalive`: `Some(25)` only when THIS node sits behind NAT (see `make_tunn`).
pub fn add_tunn_peers(
    peers: &Peers,
    index: &Arc<Mutex<u32>>,
    static_private: &StaticSecret,
    self_overlay: IpAddr,
    list: &[PeerInfo],
    udp: &Arc<UdpSocket>,
    keepalive: Option<u16>,
) -> Vec<IpAddr> {
    let dialable = dataplane::dialable_peers(list, self_overlay);
    let mut guard = peers.lock().expect("peers lock");
    let known: HashSet<String> = guard
        .iter()
        .map(|p| p.peer.public_key_b64.clone())
        .collect();
    let mut added = Vec::new();

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
        let mut tunn = make_tunn(static_private.clone(), peer_pub, idx, keepalive);

        // Proactively initiate the handshake if we know where to send it. A
        // responder peer (endpoint None — e.g. a CI runner behind NAT) is left to
        // initiate; we answer and learn its endpoint from the first packet.
        if let Some(ep) = d.endpoint {
            let mut buf = [0u8; 2048];
            if let TunnResult::WriteToNetwork(p) = tunn.format_handshake_initiation(&mut buf, false)
            {
                match udp.send_to(p, ep) {
                    Ok(n) => plog(&format!("handshake→{ep} ({}) sent {n}B", d.hostname)),
                    Err(e) => plog(&format!("handshake→{ep} ({}) SEND FAILED: {e}", d.hostname)),
                }
            }
        }

        match d.endpoint {
            Some(ep) => println!(
                "peer {} ({}) overlay {} via {ep}",
                d.hostname, d.node_id, d.overlay_ip
            ),
            None => println!(
                "peer {} ({}) overlay {} (responder — endpoint learned on handshake)",
                d.hostname, d.node_id, d.overlay_ip
            ),
        }
        let overlay = d.overlay_ip;
        let ep = d.endpoint;
        guard.push(Arc::new(PeerEntry {
            peer: d,
            endpoint: Mutex::new(ep),
            tunn: Mutex::new(tunn),
            last_activity: Mutex::new(Instant::now()),
            keepalive,
        }));
        added.push(overlay);
    }
    added
}

/// Reconcile the roster against the control plane's authoritative list: drop any
/// peer no longer present, then add anything new via `add_tunn_peers`. Dropping the
/// `Arc<PeerEntry>` is sufficient teardown for its boringtun session — nothing else
/// holds a longer-lived clone. Closes the "no peer registry" promise (A.5.3): without
/// this, a revoked/replaced peer's real IP stays in local state
/// (`agent-status.json`) forever instead of disappearing with the peer. `[T:A.5.3]`
pub fn reconcile_peers(
    peers: &Peers,
    index: &Arc<Mutex<u32>>,
    static_private: &StaticSecret,
    self_overlay: IpAddr,
    list: &[PeerInfo],
    udp: &Arc<UdpSocket>,
    keepalive: Option<u16>,
) -> (Vec<IpAddr>, usize) {
    let live: HashSet<String> = dataplane::dialable_peers(list, self_overlay)
        .into_iter()
        .map(|d| d.public_key_b64)
        .collect();
    let removed = {
        let mut guard = peers.lock().expect("peers lock");
        let before = guard.len();
        guard.retain(|p| live.contains(&p.peer.public_key_b64));
        before - guard.len()
    };
    let added = add_tunn_peers(
        peers,
        index,
        static_private,
        self_overlay,
        list,
        udp,
        keepalive,
    );
    (added, removed)
}

/// Remove a single peer by `node_id` — matches CP's `PeerEvent::Removed { node_id }`
/// wire shape, for prompt removal on ephemeral-peer TTL expiry (SSE) without waiting
/// for the next resync cycle. Returns true if a peer was actually removed.
pub fn remove_peer_by_node_id(peers: &Peers, node_id: &str) -> bool {
    let mut guard = peers.lock().expect("peers lock");
    let before = guard.len();
    guard.retain(|p| p.peer.node_id != node_id);
    before != guard.len()
}

/// Find the peer that owns an overlay destination (outgoing). Cheap linear scan —
/// a personal mesh has a handful of peers.
fn peer_by_overlay(peers: &Peers, dst: IpAddr) -> Option<Arc<PeerEntry>> {
    let g = peers.lock().expect("peers lock");
    g.iter().find(|p| p.peer.overlay_ip == dst).cloned()
}

/// Find the peer for a UDP source (incoming): exact endpoint first, then same-host
/// (port may differ behind NAT), then the sole peer if there's only one.
fn peer_by_source(peers: &Peers, src: SocketAddr) -> Option<Arc<PeerEntry>> {
    let g = peers.lock().expect("peers lock");
    g.iter()
        .find(|p| p.endpoint() == Some(src))
        .or_else(|| {
            g.iter()
                .find(|p| p.endpoint().map(|e| e.ip()) == Some(src.ip()))
        })
        .or_else(|| if g.len() == 1 { g.first() } else { None })
        .cloned()
}

/// A self-addressed DNS responder for hosts with no OS-level split-DNS hook (iOS:
/// `NEDNSSettings.matchDomains` routes matching queries INTO the tunnel instead of
/// resolving them locally, so they arrive here as ordinary UDP packets). Optional —
/// `None` on the macOS/Linux daemon, which answers via a separate loopback socket
/// fed by `/etc/resolver/<zone>` and never sees DNS on the tun fd at all.
/// `[T: f3-privdomain-ios-plan.md Phase 2]`
pub struct DnsResponder {
    /// This node's own overlay address — queries are addressed here, never a peer.
    pub self_ip: IpAddr,
    /// name → overlay address, swapped wholesale on each reconnect (Phase 1 model:
    /// "reconnect to see new devices/services", not a live-refresh channel).
    pub table: Arc<Mutex<HashMap<String, IpAddr>>>,
    /// Delegate for names NOT in `table`. iOS needs `matchDomains=[""]` (route ALL
    /// DNS to us) for the OS to use our resolver at all — so we MUST forward
    /// non-private queries to the device's real DNS instead of NXDOMAIN'ing them,
    /// or every website breaks while the tunnel is up. `false` = authoritative-only
    /// (desktop never uses this responder). The forward goes through the platform
    /// hook (`FORWARD_HOOK`) — on iOS a plain BSD UDP socket in `agent-ios-ptp`
    /// (`ios_dns_forward`); raw sockets DO egress a Packet Tunnel Provider, exactly
    /// like the WG data socket. See docs/f3-ios-dns-forwarding-resolver.md.
    pub forward: bool,
}

// ---- DNS forwarding via the platform hook (iOS BSD-socket relay) ----
//
// The pump parks the original request under a token, hands the bare query to the
// platform hook, and the hook calls `dns_reply(token, response)` when the upstream
// answers — or `dns_fail(token)` when the round-trip fails, which writes a
// synthesized SERVFAIL back to the tun. NEVER silence: iOS drops a tunnel resolver
// that fails to answer and won't use it again until the VPN reconnects
// `[T:Apple-DevForums-114097]`; Tailscale maps every upstream failure to SERVFAIL
// for the same reason `[T:tailscale forwarder.go — "All such errors map to
// SERVFAIL at the client level"]`.

/// Sink that hands a forwarded query to the platform. Set by the iOS bridge; unset
/// on desktop (which never forwards).
static FORWARD_HOOK: std::sync::OnceLock<fn(u64, &[u8])> = std::sync::OnceLock::new();
/// token → (original request IP packet, bare DNS query bytes), awaiting the
/// upstream response. The query is kept so `dns_fail` can synthesize a SERVFAIL
/// without re-parsing the request.
type PendingEntry = (Vec<u8>, Vec<u8>);
static DNS_PENDING: std::sync::OnceLock<Mutex<HashMap<u64, PendingEntry>>> =
    std::sync::OnceLock::new();
/// The tun fd to write forwarded replies back to.
static DNS_TUN_FD: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(-1);
static DNS_TOKEN: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

fn dns_pending() -> &'static Mutex<HashMap<u64, PendingEntry>> {
    DNS_PENDING.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Install the platform forward sink (iOS bridge → `createUDPSession`).
pub fn set_dns_forward_hook(f: fn(u64, &[u8])) {
    let _ = FORWARD_HOOK.set(f);
}

/// Park `request` (the original query IP packet) under a fresh token and hand the
/// bare DNS `query` to the platform bridge. No-op (drop → OS fallback) if no bridge.
fn dns_forward(fd: i32, request: &[u8], query: &[u8]) {
    let Some(hook) = FORWARD_HOOK.get() else {
        return; // no forwarder (desktop) — drop, OS resolves itself
    };
    DNS_TUN_FD.store(fd, std::sync::atomic::Ordering::Relaxed);
    let token = DNS_TOKEN.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    {
        let mut pending = dns_pending().lock().expect("dns pending lock");
        // Reap entries whose hook died without calling `dns_reply`/`dns_fail` (e.g.
        // a panicked thread). Tokens are monotonic, so anything older than a fixed
        // window is dead; this bounds the map instead of leaking one per drop.
        const PENDING_WINDOW: u64 = 256;
        let low = token.saturating_sub(PENDING_WINDOW);
        pending.retain(|&t, _| t >= low);
        pending.insert(token, (request.to_vec(), query.to_vec()));
    }
    hook(token, query);
}

/// The platform bridge calls this with the upstream's raw DNS response for `token`.
/// Builds the reply IP packet from the parked request and writes it to the tun.
/// Unknown/duplicate token = dropped.
pub fn dns_reply(token: u64, response: &[u8]) {
    let request = dns_pending()
        .lock()
        .expect("dns pending lock")
        .remove(&token);
    match request {
        None => plog(&format!(
            "dns→tun reply token={token} UNKNOWN (expired/dup)"
        )),
        Some((req, _query)) => match crate::dns::build_dns_reply(&req, response) {
            None => plog(&format!(
                "dns→tun reply token={token} build FAILED ({}B)",
                response.len()
            )),
            Some(reply) => {
                let fd = DNS_TUN_FD.load(std::sync::atomic::Ordering::Relaxed);
                let w = if fd >= 0 {
                    crate::tundev::write_packet(fd, &reply)
                } else {
                    Ok(0)
                };
                plog(&format!(
                    "dns→tun reply token={token} wrote={w:?} ({}B)",
                    reply.len()
                ));
            }
        },
    }
}

/// The platform bridge calls this when the upstream round-trip for `token` FAILED
/// (send error, timeout, no usable reply). Writes a synthesized SERVFAIL back to
/// the tun so the client always gets an answer — iOS gives up on a tunnel resolver
/// that stays silent and won't use it again until the VPN reconnects
/// `[T:Apple-DevForums-114097 — eskimo: "giving up on 'broken' DNS servers" is by
/// design]`. Mirrors Tailscale: every upstream failure maps to SERVFAIL
/// `[T:tailscale forwarder.go servfailResponse]`.
pub fn dns_fail(token: u64) {
    let request = dns_pending()
        .lock()
        .expect("dns pending lock")
        .remove(&token);
    match request {
        None => plog(&format!(
            "dns→tun servfail token={token} UNKNOWN (expired/dup)"
        )),
        Some((req, query)) => {
            let reply = crate::dns::build_servfail(&query)
                .and_then(|sf| crate::dns::build_dns_reply(&req, &sf));
            match reply {
                None => plog(&format!("dns→tun servfail token={token} build FAILED")),
                Some(reply) => {
                    let fd = DNS_TUN_FD.load(std::sync::atomic::Ordering::Relaxed);
                    let w = if fd >= 0 {
                        crate::tundev::write_packet(fd, &reply)
                    } else {
                        Ok(0)
                    };
                    plog(&format!("dns→tun SERVFAIL token={token} wrote={w:?}"));
                }
            }
        }
    }
}

/// tun → encapsulate → UDP. Reads bare IP packets, routes by destination.
/// `dns`: if a packet is a query addressed at our own overlay IP on port 53,
/// answer it locally and never route it to a peer (self_ip is never a mesh peer).
pub fn spawn_tx(fd: i32, udp: Arc<UdpSocket>, peers: Peers, dns: Option<DnsResponder>) {
    std::thread::spawn(move || {
        let mut pkt = [0u8; MTU + 80];
        // Encapsulate needs src.len()+32 of headroom `[T:boringtun@0.7 session.rs]`
        // — undersizing PANICS inside boringtun (not an Err), which killed all
        // three pump threads via poisoned locks on 2026-07-03 (ssh key-exchange
        // packets at the interface-default 1500 MTU were the reproducer).
        let mut enc = [0u8; MTU + 80 + 32];
        loop {
            let n = match crate::tundev::read_packet(fd, &mut pkt) {
                Ok(0) => continue,
                Ok(n) => n,
                Err(e) => {
                    // Fatal only: tundev absorbs EAGAIN/EINTR itself (poll-and-retry
                    // — a non-blocking packetFlow fd killed this thread on the FIRST
                    // drained queue on-device 2026-07-03). plog, not eprintln: the
                    // iOS extension has no stderr, and a silent thread death here
                    // looks exactly like "iOS stopped routing DNS to us".
                    plog(&format!("tun read FATAL: {e} — tx loop exiting"));
                    break;
                }
            };
            if n > MTU {
                // Oversized for one encrypted datagram — configure_interface clamps
                // the device MTU so this shouldn't happen; drop loudly rather than
                // truncate-and-corrupt or panic inside boringtun.
                plog(&format!(
                    "tun packet {n}B exceeds overlay MTU {MTU} — dropped"
                ));
                continue;
            }
            if let Some(responder) = &dns {
                if let Some(query) = crate::dns::dns_query_payload(&pkt[..n], responder.self_ip) {
                    // Own the name (a private mesh subdomain)? Answer authoritatively.
                    // Otherwise delegate to the device's real resolver — required
                    // because iOS routes ALL DNS here (matchDomains=[""]), so an
                    // NXDOMAIN for a public name would break every website.
                    let owned = crate::dns::query_name(query)
                        .map(|name| {
                            responder
                                .table
                                .lock()
                                .expect("dns table lock")
                                .contains_key(&name)
                        })
                        .unwrap_or(false);
                    if owned {
                        let answer = {
                            let table = responder.table.lock().expect("dns table lock");
                            crate::dns::respond(&table, query)
                        };
                        if let Some(reply) =
                            answer.and_then(|a| crate::dns::build_dns_reply(&pkt[..n], &a))
                        {
                            let _ = crate::tundev::write_packet(fd, &reply);
                        }
                        plog("tun→dns private answered");
                    } else if responder.forward {
                        // Hand the query to the platform hook (iOS BSD-socket relay);
                        // it calls `dns_reply(token, …)` on success or `dns_fail(token)`
                        // on failure (→ SERVFAIL). No blocking here, and never silence:
                        // an unanswered query makes iOS drop our resolver until
                        // reconnect `[T:Apple-DevForums-114097]`.
                        plog(&format!(
                            "tun→dns forward {}",
                            crate::dns::query_name(query).unwrap_or_default()
                        ));
                        dns_forward(fd, &pkt[..n], query);
                    } else {
                        // No forwarder (desktop never hits this path) — NXDOMAIN.
                        let answer = {
                            let table = responder.table.lock().expect("dns table lock");
                            crate::dns::respond(&table, query)
                        };
                        if let Some(reply) =
                            answer.and_then(|a| crate::dns::build_dns_reply(&pkt[..n], &a))
                        {
                            let _ = crate::tundev::write_packet(fd, &reply);
                        }
                    }
                    continue; // handled (answered / forwarded / dropped) — never a peer
                }
            }
            let Some(dst) = dataplane::packet_dst(&pkt[..n]) else {
                continue; // not a routable IPv4/IPv6 packet (truncated / unknown version)
            };
            let Some(entry) = peer_by_overlay(&peers, dst) else {
                plog(&format!("tun→pkt dst {dst} — NO PEER owns it (dropped)"));
                continue; // no peer owns this overlay address
            };
            plog(&format!("tun→pkt dst {dst} → {}", entry.peer.hostname));
            let mut tunn = entry.tunn.lock().expect("tunn lock");
            match tunn.encapsulate(&pkt[..n], &mut enc) {
                TunnResult::WriteToNetwork(out) => {
                    if let Some(ep) = entry.endpoint() {
                        let _ = udp.send_to(out, ep);
                    }
                    // Outbound data (or the handshake it triggered) — the tunnel
                    // is in use, so it must not be torn down as idle.
                    entry.touch();
                }
                TunnResult::Err(e) => plog(&format!("encapsulate error: {e:?}")),
                _ => {}
            }
        }
    });
}

/// UDP → decapsulate → tun. Demuxes packets to the owning peer, draining queued
/// output. `[T:WireGuard]`
pub fn spawn_rx(fd: i32, udp: Arc<UdpSocket>, peers: Peers) {
    std::thread::spawn(move || {
        let mut datagram = [0u8; 2048];
        let mut out = [0u8; 2048];
        loop {
            let (n, src) = match udp.recv_from(&mut datagram) {
                Ok(v) => v,
                Err(e) => {
                    plog(&format!("udp recv FATAL: {e} — rx loop exiting"));
                    break;
                }
            };
            // (No per-datagram log here: a public node's UDP port sees constant
            // internet noise — per-packet logging floods the journal. Drops are
            // surfaced by the rate-limited counter below instead.)
            //
            // Pick the owning peer. Fast path FIRST, then every other peer:
            // trial-decapsulate until one Tunn accepts — only the peer whose Tunn
            // holds the matching key does; the rest return `Err`. `[T:WireGuard]`
            let candidates = rx_candidates(&peers, src);
            let mut handled = false;
            for entry in candidates {
                let mut tunn = entry.tunn.lock().expect("tunn lock");
                let mut res = tunn.decapsulate(Some(src.ip()), &datagram[..n], &mut out);
                // Wrong peer (trial mode): its Tunn rejects the packet → try the next.
                if matches!(res, TunnResult::Err(_)) {
                    continue;
                }
                // Learn / refresh this peer's endpoint from the source — how a
                // responder picks up a NAT'd runner's address. `[T:WireGuard roam]`
                entry.set_endpoint(src);
                loop {
                    match res {
                        TunnResult::WriteToNetwork(pkt) => {
                            // Reply to where the packet came from (correct for NAT/roam).
                            let _ = udp.send_to(pkt, src);
                            // boringtun may have more queued (e.g. cookie/keepalive).
                            res = tunn.decapsulate(None, &[], &mut out);
                        }
                        TunnResult::WriteToTunnelV4(pkt, _)
                        | TunnResult::WriteToTunnelV6(pkt, _) => {
                            let _ = crate::tundev::write_packet(fd, pkt);
                            // Inbound data decrypted — tunnel in use (handshake
                            // and keepalive frames don't reach this arm).
                            entry.touch();
                            break;
                        }
                        TunnResult::Err(_) => break,
                        TunnResult::Done => break,
                    }
                }
                handled = true;
                break; // handled by this peer
            }
            if !handled {
                log_undecryptable_drop(src);
            }
        }
    });
}

/// Candidate order for demuxing one inbound datagram: the endpoint-match guess
/// first, then EVERY other peer. The guess is an ordering optimization, never a
/// filter — two peers behind one NAT share a public IP (a phone and a laptop on
/// the same Wi-Fi), so the same-host match can pick the wrong sibling; gating on
/// it silently blackholes the other peer's handshakes forever. Found by review
/// after a 2026-07-04 field incident (one same-NAT peer's handshakes went
/// unanswered while every pump thread was healthy). `[T:WireGuard]`
/// trial-decapsulation is safe: only the Tunn holding the matching key accepts,
/// every other Tunn returns `Err`.
fn rx_candidates(peers: &Peers, src: SocketAddr) -> Vec<Arc<PeerEntry>> {
    let guess = peer_by_source(peers, src);
    let g = peers.lock().expect("peers lock");
    let mut v: Vec<Arc<PeerEntry>> = Vec::with_capacity(g.len());
    if let Some(hit) = &guess {
        v.push(hit.clone());
    }
    v.extend(
        g.iter()
            .filter(|p| guess.as_ref().map_or(true, |hit| !Arc::ptr_eq(p, hit)))
            .cloned(),
    );
    v
}

/// Rate-limited visibility for datagrams no peer's Tunn accepted (unknown sender,
/// stale key, or internet noise on a public port). At most one line per minute,
/// with the cumulative count — enough to diagnose a "peer can't handshake us"
/// incident from the journal without flooding it. `[A: counter resets on restart;
/// fine — it exists for live diagnosis, not accounting]`
fn log_undecryptable_drop(src: SocketAddr) {
    use std::sync::atomic::{AtomicU64, Ordering};
    static DROPPED: AtomicU64 = AtomicU64::new(0);
    static WINDOW: Mutex<Option<Instant>> = Mutex::new(None);

    let total = DROPPED.fetch_add(1, Ordering::Relaxed) + 1;
    let mut last = WINDOW.lock().expect("drop-log lock");
    let due = match *last {
        Some(t) => t.elapsed() >= Duration::from_secs(60),
        None => true,
    };
    if due {
        *last = Some(Instant::now());
        plog(&format!(
            "rx: datagram from {src} not decryptable by any peer \
             ({total} such drops since start) — sender unknown, revoked, or noise"
        ));
    }
}

/// Drive WireGuard timers (rekey, keepalive, handshake retries) and enforce
/// idle-teardown. `[T:WireGuard-whitepaper §6]` the protocol is timer-driven.
///
/// Idle-teardown `[T:A.1.7]`: an *established* session that has moved no data for
/// `IDLE_TEARDOWN` gets its `Tunn` replaced with a fresh one — session keys and
/// handshake state are dropped, so nothing stays hot while unused. The peer entry,
/// its learned endpoint, and the host route all remain: the next outbound packet
/// re-handshakes on demand. `static_private`/`index` are needed to rebuild.
pub fn spawn_timers(
    udp: Arc<UdpSocket>,
    peers: Peers,
    static_private: StaticSecret,
    index: Arc<Mutex<u32>>,
) {
    std::thread::spawn(move || {
        let mut buf = [0u8; 2048];
        loop {
            std::thread::sleep(Duration::from_millis(250));
            let snapshot: Vec<Arc<PeerEntry>> =
                peers.lock().expect("peers lock").iter().cloned().collect();
            teardown_idle(&snapshot, &static_private, &index, IDLE_TEARDOWN);
            for entry in snapshot {
                let mut tunn = entry.tunn.lock().expect("tunn lock");
                if let TunnResult::WriteToNetwork(p) = tunn.update_timers(&mut buf) {
                    if let Some(ep) = entry.endpoint() {
                        match udp.send_to(p, ep) {
                            Ok(n) => plog(&format!("timer→{ep} ({}) {n}B", entry.peer.hostname)),
                            Err(e) => plog(&format!(
                                "timer→{ep} ({}) SEND FAILED: {e}",
                                entry.peer.hostname
                            )),
                        }
                    }
                }
            }
        }
    });
}

/// One idle sweep: replace the `Tunn` of every peer whose session is established
/// but has moved no data for `limit`. Factored out of the timer thread so the
/// decision + effect are unit-testable without threads. `[T:A.1.7]`
fn teardown_idle(
    snapshot: &[Arc<PeerEntry>],
    static_private: &StaticSecret,
    index: &Arc<Mutex<u32>>,
    limit: Duration,
) {
    for entry in snapshot {
        {
            let tunn = entry.tunn.lock().expect("tunn lock");
            // No session → nothing to tear down (a fresh Tunn holds no keys and
            // boringtun stops retrying its handshake on its own).
            if !handshake_established(&tunn) || entry.idle_for() < limit {
                continue;
            }
        }
        let idx = {
            let mut i = index.lock().expect("index lock");
            *i += 1;
            *i
        };
        let peer_pub = PublicKey::from(entry.peer.public_key);
        *entry.tunn.lock().expect("tunn lock") =
            make_tunn(static_private.clone(), peer_pub, idx, entry.keepalive);
        entry.touch(); // restart the clock; don't re-tear a fresh Tunn every tick
        println!(
            "peer {} idle {}s — session torn down (re-handshakes on demand)",
            entry.peer.hostname,
            limit.as_secs()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tunnel::StaticSecret;
    use rand_core::OsRng;

    fn entry(overlay: &str, ep: Option<&str>) -> Arc<PeerEntry> {
        let sp = StaticSecret::random_from_rng(OsRng);
        let pp = PublicKey::from(&StaticSecret::random_from_rng(OsRng));
        let endpoint = ep.map(|s| s.parse().unwrap());
        Arc::new(PeerEntry {
            peer: DialablePeer {
                node_id: "n".into(),
                hostname: "h".into(),
                public_key: [0u8; 32],
                public_key_b64: overlay.into(), // unique-enough key for the test roster
                overlay_ip: overlay.parse().unwrap(),
                endpoint,
            },
            endpoint: Mutex::new(endpoint),
            tunn: Mutex::new(make_tunn(sp, pp, 1, None)),
            last_activity: Mutex::new(Instant::now()),
            keepalive: None,
        })
    }

    // Routing/demux selection is the part the iOS pump shares verbatim — pin it.
    #[test]
    fn peer_selection_by_overlay_and_source() {
        let peers: Peers = Arc::new(Mutex::new(vec![entry("10.0.0.1", Some("1.2.3.4:51820"))]));

        // outgoing: routed by overlay destination.
        assert!(peer_by_overlay(&peers, "10.0.0.1".parse().unwrap()).is_some());
        assert!(peer_by_overlay(&peers, "10.0.0.9".parse().unwrap()).is_none());

        // incoming: exact endpoint match, then sole-peer fallback for an unknown src.
        assert!(peer_by_source(&peers, "1.2.3.4:51820".parse().unwrap()).is_some());
        assert!(peer_by_source(&peers, "9.9.9.9:1".parse().unwrap()).is_some());
    }

    // With two peers, an unknown source has no sole-peer fallback → None (forces the
    // rx trial-decapsulate path instead of mis-routing). `[T:WireGuard]`
    #[test]
    fn unknown_source_with_multiple_peers_is_ambiguous() {
        let peers: Peers = Arc::new(Mutex::new(vec![
            entry("10.0.0.1", None),
            entry("10.0.0.2", None),
        ]));
        assert!(peer_by_source(&peers, "9.9.9.9:1".parse().unwrap()).is_none());
    }

    /// Two peers behind ONE NAT (same public IP, e.g. a laptop and a phone on
    /// the same Wi-Fi): the endpoint guess picks the sibling whose endpoint was
    /// learned first — the OTHER sibling's datagrams must still be trialed, not
    /// silently dropped. Regression for the 2026-07-04 field-incident class.
    #[test]
    fn rx_candidates_puts_guess_first_but_never_excludes_siblings() {
        let a = entry("10.0.0.1", Some("94.0.0.1:51820")); // learned NAT endpoint
        let b = entry("10.0.0.2", Some("192.168.1.5:51820")); // LAN-only endpoint
        let peers: Peers = Arc::new(Mutex::new(vec![a.clone(), b.clone()]));

        // Same public IP, different port (B's packets after NAT) → same-host
        // guess resolves to A (wrong!). B must still be in the candidate list.
        let c = rx_candidates(&peers, "94.0.0.1:60000".parse().unwrap());
        assert_eq!(c.len(), 2, "guess must not exclude the other peer");
        assert!(Arc::ptr_eq(&c[0], &a), "endpoint guess ordered first");
        assert!(
            Arc::ptr_eq(&c[1], &b),
            "sibling still trialed after the guess"
        );

        // Exact endpoint match → same ordering guarantee.
        let c = rx_candidates(&peers, "94.0.0.1:51820".parse().unwrap());
        assert_eq!(c.len(), 2);
        assert!(Arc::ptr_eq(&c[0], &a));

        // Unknown source → every peer, no duplicates.
        let c = rx_candidates(&peers, "9.9.9.9:1".parse().unwrap());
        assert_eq!(c.len(), 2);
    }

    /// The guessed peer must appear exactly once (no double trial of the same
    /// Tunn — decapsulate mutates handshake state).
    #[test]
    fn rx_candidates_never_duplicates_the_guess() {
        let a = entry("10.0.0.1", Some("1.2.3.4:51820"));
        let peers: Peers = Arc::new(Mutex::new(vec![a.clone()]));
        let c = rx_candidates(&peers, "1.2.3.4:51820".parse().unwrap());
        assert_eq!(c.len(), 1);
        assert!(Arc::ptr_eq(&c[0], &a));
    }

    /// Build an entry whose Tunn has a COMPLETED handshake (in-memory Noise
    /// roundtrip against a throwaway responder — same recipe as tunnel.rs).
    fn entry_with_established_session() -> Arc<PeerEntry> {
        let a_priv = StaticSecret::random_from_rng(OsRng);
        let b_priv = StaticSecret::random_from_rng(OsRng);
        let a_pub = PublicKey::from(&a_priv);
        let b_pub = PublicKey::from(&b_priv);
        let mut a = make_tunn(a_priv, b_pub, 1, None);
        let mut b = make_tunn(b_priv, a_pub, 2, None);
        let mut buf = [0u8; 2048];
        let init = match a.format_handshake_initiation(&mut buf, false) {
            TunnResult::WriteToNetwork(p) => p.to_vec(),
            _ => panic!("no initiation"),
        };
        let mut buf2 = [0u8; 2048];
        let resp = match b.decapsulate(None, &init, &mut buf2) {
            TunnResult::WriteToNetwork(p) => p.to_vec(),
            _ => panic!("no response"),
        };
        let _ = a.decapsulate(None, &resp, &mut buf);
        assert!(crate::tunnel::handshake_established(&a));
        Arc::new(PeerEntry {
            peer: DialablePeer {
                node_id: "n".into(),
                hostname: "h".into(),
                public_key: b_pub.to_bytes(),
                public_key_b64: "k".into(),
                overlay_ip: "10.0.0.1".parse().unwrap(),
                endpoint: None,
            },
            endpoint: Mutex::new(None),
            tunn: Mutex::new(a),
            last_activity: Mutex::new(Instant::now()),
            keepalive: None,
        })
    }

    // A.1.7: an established-but-idle session is torn down (fresh Tunn, no
    // session); an active or never-handshaked one is left alone. `[T:A.1.7]`
    #[test]
    fn idle_established_session_is_torn_down() {
        let established = entry_with_established_session();
        let never_handshaked = entry("10.0.0.2", Some("1.2.3.4:51820"));
        let snapshot = vec![established.clone(), never_handshaked.clone()];
        let sp = StaticSecret::random_from_rng(OsRng);
        let index = Arc::new(Mutex::new(10u32));

        // limit > 0: nothing is idle yet → no teardown.
        teardown_idle(&snapshot, &sp, &index, Duration::from_secs(300));
        assert!(crate::tunnel::handshake_established(
            &established.tunn.lock().unwrap()
        ));

        // limit 0: the established session counts as idle → torn down.
        teardown_idle(&snapshot, &sp, &index, Duration::ZERO);
        assert!(
            !crate::tunnel::handshake_established(&established.tunn.lock().unwrap()),
            "idle session must be replaced by a fresh Tunn"
        );
        // never-handshaked peer must be untouched (index only advanced once).
        assert_eq!(*index.lock().unwrap(), 11);
    }

    fn entry_keyed(overlay: &str, key_b64: &str) -> Arc<PeerEntry> {
        let sp = StaticSecret::random_from_rng(OsRng);
        let pp = PublicKey::from(&StaticSecret::random_from_rng(OsRng));
        Arc::new(PeerEntry {
            peer: DialablePeer {
                node_id: "n".into(),
                hostname: "h".into(),
                public_key: [0u8; 32],
                public_key_b64: key_b64.into(),
                overlay_ip: overlay.parse().unwrap(),
                endpoint: None,
            },
            endpoint: Mutex::new(None),
            tunn: Mutex::new(make_tunn(sp, pp, 1, None)),
            last_activity: Mutex::new(Instant::now()),
            keepalive: None,
        })
    }

    // A.5.3: a peer no longer in the fresh CP roster must disappear from the local
    // roster (not linger forever, per `peer-roster-no-registry-gap-2026-07-10.md`).
    #[test]
    fn reconcile_peers_prunes_stale_and_keeps_live() {
        let keep_key = crypto::WgKeypair::generate().public_b64;
        let peers: Peers = Arc::new(Mutex::new(vec![
            entry_keyed("10.0.0.1", &keep_key),
            entry_keyed("10.0.0.2", "stale-b"),
            entry_keyed("10.0.0.3", "stale-c"),
        ]));

        let fresh = vec![PeerInfo {
            node_id: "n".into(),
            hostname: "h".into(),
            public_key: keep_key,
            overlay_ip: "10.0.0.1".into(),
            endpoint: None,
        }];

        let index = Arc::new(Mutex::new(0u32));
        let static_private = StaticSecret::random_from_rng(OsRng);
        let udp = Arc::new(UdpSocket::bind("127.0.0.1:0").unwrap());
        let self_overlay: IpAddr = "10.0.0.99".parse().unwrap();

        let (added, removed) = reconcile_peers(
            &peers,
            &index,
            &static_private,
            self_overlay,
            &fresh,
            &udp,
            None,
        );

        assert_eq!(
            removed, 2,
            "the two peers absent from `fresh` must be pruned"
        );
        assert!(
            added.is_empty(),
            "the surviving peer was already known, not newly added"
        );
        assert_eq!(peers.lock().unwrap().len(), 1);
        assert_eq!(
            peers.lock().unwrap()[0].peer.overlay_ip,
            "10.0.0.1".parse::<IpAddr>().unwrap()
        );
    }
}
