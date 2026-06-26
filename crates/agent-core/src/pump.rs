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

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::dataplane::{self, DialablePeer};
use crate::domain::PeerInfo;
use crate::tunnel::{make_tunn, PublicKey, StaticSecret, Tunn, TunnResult};

/// Safe overlay MTU under a typical 1500-byte path. `[T:WireGuard]`
pub const MTU: usize = 1420;

/// One peer's live tunnel: metadata + its boringtun state machine + the current
/// UDP endpoint. For a responder peer (no advertised endpoint, e.g. a CI runner
/// behind NAT) the endpoint starts `None` and is learned from the first handshake;
/// it is also refreshed on roaming. `[T:Part C §H.3.3 B-3]`
pub struct PeerEntry {
    /// Connection-level peer metadata (hostname/overlay/key) — never payload.
    pub peer: DialablePeer,
    endpoint: Mutex<Option<SocketAddr>>,
    tunn: Mutex<Tunn>,
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
}

/// The shared, mutable peer roster. `Arc<Mutex<…>>` because the three pump threads
/// and the caller's refresh loop all touch it.
pub type Peers = Arc<Mutex<Vec<Arc<PeerEntry>>>>;

/// Add peers we don't already have a tunnel for: build a boringtun `Tunn`, kick off
/// the handshake when we know the endpoint, and push it onto the roster. Returns
/// the overlay address of every peer added — the caller routes those into the tun
/// device (host route on the daemon; `includedRoutes` in Swift on iOS). Routing is
/// intentionally NOT done here so the pump stays OS-agnostic. `[T:A.1.9]`
pub fn add_tunn_peers(
    peers: &Peers,
    index: &Arc<Mutex<u32>>,
    static_private: &StaticSecret,
    self_overlay: IpAddr,
    list: &[PeerInfo],
    udp: &Arc<UdpSocket>,
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
        let mut tunn = make_tunn(static_private.clone(), peer_pub, idx);

        // Proactively initiate the handshake if we know where to send it. A
        // responder peer (endpoint None — e.g. a CI runner behind NAT) is left to
        // initiate; we answer and learn its endpoint from the first packet.
        if let Some(ep) = d.endpoint {
            let mut buf = [0u8; 2048];
            if let TunnResult::WriteToNetwork(p) = tunn.format_handshake_initiation(&mut buf, false)
            {
                let _ = udp.send_to(p, ep);
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
        }));
        added.push(overlay);
    }
    added
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

/// tun → encapsulate → UDP. Reads bare IP packets, routes by destination.
pub fn spawn_tx(fd: i32, udp: Arc<UdpSocket>, peers: Peers) {
    std::thread::spawn(move || {
        let mut pkt = [0u8; MTU + 80];
        let mut enc = [0u8; MTU + 80];
        loop {
            let n = match crate::tundev::read_packet(fd, &mut pkt) {
                Ok(0) => continue,
                Ok(n) => n,
                Err(e) => {
                    eprintln!("tun read error: {e}");
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
                    if let Some(ep) = entry.endpoint() {
                        let _ = udp.send_to(out, ep);
                    }
                }
                TunnResult::Err(e) => eprintln!("encapsulate error: {e:?}"),
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
                    eprintln!("udp recv error: {e}");
                    break;
                }
            };
            // Pick the owning peer. Fast path: a peer whose learned endpoint matches
            // the source. Fallback: trial-decapsulate against every peer — needed
            // when more than one *responder* peer has no endpoint yet (e.g. a NAT'd
            // CI runner alongside another responder); only the peer whose Tunn holds
            // the matching key accepts the packet, the rest return `Err`. `[T:WireGuard]`
            let candidates: Vec<Arc<PeerEntry>> = match peer_by_source(&peers, src) {
                Some(e) => vec![e],
                None => peers.lock().expect("peers lock").iter().cloned().collect(),
            };
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
                            break;
                        }
                        TunnResult::Err(_) => break,
                        TunnResult::Done => break,
                    }
                }
                break; // handled by this peer
            }
        }
    });
}

/// Drive WireGuard timers (rekey, keepalive, handshake retries).
/// `[T:WireGuard-whitepaper §6]` the protocol is timer-driven.
pub fn spawn_timers(udp: Arc<UdpSocket>, peers: Peers) {
    std::thread::spawn(move || {
        let mut buf = [0u8; 2048];
        loop {
            std::thread::sleep(Duration::from_millis(250));
            let snapshot: Vec<Arc<PeerEntry>> =
                peers.lock().expect("peers lock").iter().cloned().collect();
            for entry in snapshot {
                let mut tunn = entry.tunn.lock().expect("tunn lock");
                if let TunnResult::WriteToNetwork(p) = tunn.update_timers(&mut buf) {
                    if let Some(ep) = entry.endpoint() {
                        let _ = udp.send_to(p, ep);
                    }
                }
            }
        }
    });
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
            tunn: Mutex::new(make_tunn(sp, pp, 1)),
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
}
