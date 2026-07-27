//! disco — NAT-traversal driver on the WireGuard socket. OPEN.
//!
//! G-2 (here): learn this node's server-reflexive endpoint by periodically sending a STUN
//! Binding Request to the relay's STUN reflector and reading the answer the pump diverts
//! back (via `pump::set_stun_sink`). The learned endpoint is the candidate a peer dials to
//! hole-punch a direct path (G-3). One long-lived thread, matching the pump's thread
//! model. `[T: decision/nat-traversal-disco-design-2026-07-21 §4]`

use std::net::{SocketAddr, UdpSocket};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::stun;

/// Re-discover on this cadence: refreshes the NAT mapping and catches a public-endpoint
/// change after a roam. `[A]` verify on mobile: shorten if mappings expire faster.
const DISCOVERY_INTERVAL: Duration = Duration::from_secs(60);
/// Tick for the inbound-STUN wait — also the upper bound on noticing the pump is gone.
const RECV_TICK: Duration = Duration::from_secs(1);

/// This node's learned server-reflexive endpoint (public `ip:port` as the relay's STUN
/// sees it). `None` until the first successful discovery; updated in place on each cycle.
pub type Reflexive = Arc<Mutex<Option<SocketAddr>>>;

/// Derive the relay's STUN address from its frame endpoint (`host:tcp_port`) — same host,
/// the well-known STUN UDP port. Keeps G-2 free of a control-plane schema change: the relay
/// runs `--stun <host>:3478` and the client derives it here. `[A-c convention]`
pub const STUN_PORT: u16 = 3478;

pub fn stun_addr_for(relay_endpoint: &str) -> Option<SocketAddr> {
    let host = relay_endpoint.rsplit_once(':').map(|(h, _)| h)?;
    // host may be an IPv6 literal in brackets or a bare IP/name; resolve to a socket addr.
    use std::net::ToSocketAddrs;
    (host.trim_matches(['[', ']']), STUN_PORT)
        .to_socket_addrs()
        .ok()?
        .next()
}

/// Run STUN discovery forever on `udp` (the WG socket). Sends a Binding Request to
/// `relay_stun` each `DISCOVERY_INTERVAL`, and drains `stun_rx` (fed by the pump's STUN
/// demux) for the matching response, recording the reflexive endpoint into `out`. Exits
/// when the pump drops the sink (agent shutdown). Blocks — spawn on its own thread.
pub fn run_discovery(
    udp: Arc<UdpSocket>,
    relay_stun: SocketAddr,
    stun_rx: Receiver<(Vec<u8>, SocketAddr)>,
    out: Reflexive,
) {
    let mut pending: Option<[u8; 12]> = None;
    let mut last: Option<Instant> = None; // None → discover immediately
    loop {
        if last.map_or(true, |t| t.elapsed() >= DISCOVERY_INTERVAL) {
            let txid: [u8; 12] = rand::random();
            // A send error is transient (roam mid-cycle); retry next tick.
            if udp
                .send_to(&stun::binding_request(&txid), relay_stun)
                .is_ok()
            {
                pending = Some(txid);
            }
            last = Some(Instant::now());
        }
        match stun_rx.recv_timeout(RECV_TICK) {
            Ok((pkt, _src)) => {
                if let Some(txid) = pending {
                    if let Some(addr) = stun::parse_binding_response(&pkt, &txid) {
                        let changed = { *out.lock().expect("reflexive lock") != Some(addr) };
                        if changed {
                            *out.lock().expect("reflexive lock") = Some(addr);
                            crate::pump::plog_public(&format!("reflexive endpoint: {addr}"));
                        }
                        pending = None;
                    }
                }
                // A Binding REQUEST from a peer (hole-punch, G-3) also lands here — handled
                // in the G-3 follow-up; ignored for discovery.
            }
            Err(RecvTimeoutError::Timeout) => {} // tick: loop to maybe re-discover
            Err(RecvTimeoutError::Disconnected) => return, // pump gone
        }
    }
}

// ── G-3 hole-punch rendezvous, carried over the relay (Tailscale CallMeMaybe-over-DERP) ──
//
// Our relay is DERP-style (routes by WG pubkey, bidirectional, already held open in the
// extension by boringtun), so the rendezvous "here is my endpoint, punch now" frame rides
// it directly — the exact substrate Tailscale's CallMeMaybe uses. No control-plane round
// trip, and it works identically on desktop and inside the iOS Packet Tunnel (both hold a
// relay leg). `[T:decision/nat-traversal-disco-design + iOS-signaling research 2026-07-21]`

use crate::pump::Peers;
use crate::relay_transport::RelayClient;
use std::collections::HashMap;

/// Frame magic. First byte `0x52` ('R') is disjoint from WireGuard message types (1-4), so
/// a relay payload is a rendezvous frame ONLY on an exact prefix match — never a WG frame.
const RENDEZVOUS_MAGIC: [u8; 4] = *b"RZV1";
/// How often we re-advertise our endpoint to relay-only peers (initiator). Short so a
/// freshly-discovered reflexive endpoint reaches peers quickly; both sides converge.
const INITIATE_INTERVAL: Duration = Duration::from_secs(5);
/// Per-peer debounce for reacting to an inbound rendezvous — breaks the reciprocation
/// ping-pong into a couple of overlapping bursts, then quiets (STUN-storm pitfall).
const RENDEZVOUS_DEBOUNCE: Duration = Duration::from_secs(5);

/// Encode a rendezvous frame: our STUN-reflexive endpoint, for a peer to punch toward.
pub fn encode_rendezvous(my_endpoint: SocketAddr) -> Vec<u8> {
    let mut m = Vec::with_capacity(28);
    m.extend_from_slice(&RENDEZVOUS_MAGIC);
    m.extend_from_slice(my_endpoint.to_string().as_bytes());
    m
}

/// Parse a rendezvous frame off a relay payload → the sender's endpoint. `None` for
/// anything else (WireGuard ciphertext) — the strict magic prefix is collision-free vs WG.
pub fn parse_rendezvous(payload: &[u8]) -> Option<SocketAddr> {
    let rest = payload.strip_prefix(&RENDEZVOUS_MAGIC[..])?;
    std::str::from_utf8(rest).ok()?.parse().ok()
}

fn relay_only_pubkeys(peers: &Peers) -> Vec<[u8; 32]> {
    peers
        .lock()
        .expect("peers lock")
        .iter()
        .filter(|p| p.endpoint().is_none())
        .map(|p| p.peer.public_key)
        .collect()
}

/// Drive relay-carried rendezvous. Two jobs in one loop:
/// - **Initiator**: every `INITIATE_INTERVAL`, send our reflexive endpoint over the relay
///   to each relay-only peer (no direct endpoint yet).
/// - **Responder**: on an inbound rendezvous (`src pubkey`, their endpoint), hole-punch
///   toward it and reciprocate once (debounced) so both NATs open together.
///
/// Exits when the pump drops the rendezvous sink (agent shutdown). Blocks — own thread.
pub fn run_rendezvous(
    relay: Arc<RelayClient>,
    peers: Peers,
    udp: Arc<UdpSocket>,
    reflexive: Reflexive,
    rendezvous_rx: Receiver<([u8; 32], SocketAddr)>,
) {
    let mut last_initiate: Option<Instant> = None;
    let mut recent: HashMap<[u8; 32], Instant> = HashMap::new();
    loop {
        if last_initiate.map_or(true, |t| t.elapsed() >= INITIATE_INTERVAL) {
            if let Some(my_ep) = *reflexive.lock().expect("reflexive lock") {
                let frame = encode_rendezvous(my_ep);
                for pk in relay_only_pubkeys(&peers) {
                    relay.send(pk, &frame);
                }
            }
            last_initiate = Some(Instant::now());
        }
        match rendezvous_rx.recv_timeout(RECV_TICK) {
            Ok((src_pubkey, their_ep)) => {
                let now = Instant::now();
                let react = match recent.get(&src_pubkey) {
                    Some(t) if t.elapsed() < RENDEZVOUS_DEBOUNCE => false,
                    _ => {
                        recent.insert(src_pubkey, now);
                        true
                    }
                };
                if react {
                    // Punch burst blocks → own thread.
                    let (peers_c, udp_c) = (peers.clone(), udp.clone());
                    std::thread::spawn(move || {
                        crate::pump::punch_toward_pubkey(&peers_c, src_pubkey, &udp_c, their_ep);
                    });
                    // Reciprocate so the peer punches back at the same moment.
                    if let Some(my_ep) = *reflexive.lock().expect("reflexive lock") {
                        relay.send(src_pubkey, &encode_rendezvous(my_ep));
                    }
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::sync::mpsc;

    #[test]
    fn rendezvous_roundtrips_and_is_disjoint_from_wireguard() {
        let ep = SocketAddr::from((Ipv4Addr::new(203, 0, 113, 5), 51820));
        assert_eq!(parse_rendezvous(&encode_rendezvous(ep)), Some(ep));
        // WireGuard message types 1-4 must never parse as a rendezvous frame.
        for t in [1u8, 2, 3, 4] {
            let mut wg = vec![0u8; 64];
            wg[0] = t;
            assert!(parse_rendezvous(&wg).is_none());
        }
        assert!(parse_rendezvous(b"RZV1not-an-addr").is_none());
    }

    #[test]
    fn derives_stun_addr_from_relay_endpoint() {
        let a = stun_addr_for("203.0.113.9:8443").unwrap();
        assert_eq!(
            a,
            SocketAddr::from((Ipv4Addr::new(203, 0, 113, 9), STUN_PORT))
        );
    }

    // End-to-end over real sockets: a stand-in relay STUN server reflects the request's
    // txid + a chosen public addr into the sink channel (as the pump would), and discovery
    // records it.
    #[test]
    fn discovery_learns_reflexive_endpoint() {
        let udp = Arc::new(UdpSocket::bind("127.0.0.1:0").unwrap());
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server_addr = server.local_addr().unwrap();
        let (tx, rx) = mpsc::channel();
        let out: Reflexive = Arc::new(Mutex::new(None));

        // Stand-in for pump+relay: read the Binding Request, echo a Success Response with
        // the SAME txid + a known reflexive addr, and hand it to the sink (as the pump's
        // demux does).
        let reflexive = SocketAddr::from((Ipv4Addr::new(198, 51, 100, 4), 51820));
        std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            let (_n, _from) = server.recv_from(&mut buf).unwrap();
            let mut txid = [0u8; 12];
            txid.copy_from_slice(&buf[8..20]);
            let resp = super::tests::success_response(&txid, reflexive);
            tx.send((resp, server_addr)).unwrap();
        });

        let udp2 = udp.clone();
        let out2 = out.clone();
        let h = std::thread::spawn(move || run_discovery(udp2, server_addr, rx, out2));

        // Poll until discovery records the reflexive (the sender drops → loop exits after).
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(a) = *out.lock().unwrap() {
                assert_eq!(a, reflexive);
                break;
            }
            assert!(
                Instant::now() < deadline,
                "discovery never recorded reflexive"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        let _ = h; // detached; loop exits on channel disconnect
    }

    // Build a Binding Success Response (mirrors the relay STUN server / agent-core stun.rs).
    pub(super) fn success_response(txid: &[u8; 12], src: SocketAddr) -> Vec<u8> {
        const COOKIE: [u8; 4] = 0x2112_A442u32.to_be_bytes();
        let xport = src.port() ^ 0x2112u16;
        let mut attr = vec![0x00, 0x01];
        attr.extend_from_slice(&xport.to_be_bytes());
        if let std::net::IpAddr::V4(v4) = src.ip() {
            for (i, b) in v4.octets().iter().enumerate() {
                attr.push(b ^ COOKIE[i]);
            }
        }
        let mut m = vec![0x01, 0x01];
        m.extend_from_slice(&(4 + attr.len() as u16).to_be_bytes());
        m.extend_from_slice(&COOKIE);
        m.extend_from_slice(txid);
        m.extend_from_slice(&0x0020u16.to_be_bytes());
        m.extend_from_slice(&(attr.len() as u16).to_be_bytes());
        m.extend_from_slice(&attr);
        m
    }
}
