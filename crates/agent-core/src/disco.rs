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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::sync::mpsc;

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
            let (n, _from) = server.recv_from(&mut buf).unwrap();
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
