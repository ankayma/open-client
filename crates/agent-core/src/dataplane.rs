//! dataplane — overlay peer model + packet-routing helpers. OPEN, intensity Standard.
//!
//! Pure, I/O-free logic that turns the control plane's metadata-only peer list
//! (`[T:A.1.1]`) into the set of peers this node can actually dial over the
//! WireGuard overlay, plus the routing decisions the daemon's event loop needs.
//! Kept here (not in the daemon) so it is unit-testable without root/utun and so
//! the agent stays auditable. `[T:A.1.4]`

use std::net::{Ipv4Addr, SocketAddr};

use crate::domain::PeerInfo;

/// A control-plane peer we can actually reach: a parseable 32-byte WireGuard
/// public key plus a resolved UDP endpoint to send to. Peers missing either are
/// dropped (e.g. nodes that enrolled without advertising an endpoint).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DialablePeer {
    pub node_id: String,
    pub hostname: String,
    /// Raw 32-byte X25519 public key for boringtun. `[T:RFC-7748§5]`
    pub public_key: [u8; 32],
    /// Public-key base64, kept for logging/dedup.
    pub public_key_b64: String,
    /// Overlay address inside the 100.64.0.0/10 CGNAT pool (RFC 6598).
    pub overlay_ip: Ipv4Addr,
    /// Where to send this peer's encrypted UDP traffic.
    pub endpoint: SocketAddr,
}

/// Extract the destination IPv4 address from a raw IPv4 packet (no utun header).
/// Returns `None` for anything that is not a well-formed IPv4 packet (e.g. IPv6,
/// or a truncated buffer). `[T:RFC-791§3.1]` IHL/version nibble + dst at bytes 16..20.
pub fn ipv4_dst(packet: &[u8]) -> Option<Ipv4Addr> {
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return None;
    }
    Some(Ipv4Addr::new(
        packet[16], packet[17], packet[18], packet[19],
    ))
}

/// Filter a raw control-plane peer list down to dialable peers, dropping:
///   * this node itself (matched by overlay IP),
///   * peers with no advertised endpoint,
///   * peers whose public key or endpoint does not parse.
///
/// The control plane returns every node (including self and stale/garbage
/// entries); the data plane must be defensive. `[T:A.1.1]`
pub fn dialable_peers(peers: &[PeerInfo], self_overlay: Ipv4Addr) -> Vec<DialablePeer> {
    peers
        .iter()
        .filter_map(|p| to_dialable(p, self_overlay))
        .collect()
}

fn to_dialable(p: &PeerInfo, self_overlay: Ipv4Addr) -> Option<DialablePeer> {
    let overlay_ip: Ipv4Addr = p.overlay_ip.parse().ok()?;
    if overlay_ip == self_overlay {
        return None; // never dial ourselves
    }
    let endpoint: SocketAddr = p.endpoint.as_deref()?.parse().ok()?;
    let public_key = crate::key_bytes_from_b64(&p.public_key).ok()?;
    Some(DialablePeer {
        node_id: p.node_id.clone(),
        hostname: p.hostname.clone(),
        public_key,
        public_key_b64: p.public_key.clone(),
        overlay_ip,
        endpoint,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(node: &str, pubkey: &str, overlay: &str, endpoint: Option<&str>) -> PeerInfo {
        PeerInfo {
            node_id: node.into(),
            public_key: pubkey.into(),
            overlay_ip: overlay.into(),
            hostname: node.into(),
            endpoint: endpoint.map(String::from),
        }
    }

    // A real 44-char base64 X25519 public key (from the live control plane).
    const REAL_PUBKEY: &str = "n1g1vyzFSN1KXHKHi6sw+L+fe/yxwXJIATSA3w24lB8=";

    #[test]
    fn ipv4_dst_reads_destination_octets() {
        // Minimal IPv4 header: dst = 100.64.0.2 at bytes 16..20.
        let mut pkt = [0u8; 20];
        pkt[0] = 0x45; // v4, IHL 5
        pkt[16..20].copy_from_slice(&[100, 64, 0, 2]);
        assert_eq!(ipv4_dst(&pkt), Some(Ipv4Addr::new(100, 64, 0, 2)));
    }

    #[test]
    fn ipv4_dst_rejects_non_ipv4_and_short() {
        let mut v6 = [0u8; 20];
        v6[0] = 0x60; // version 6
        assert_eq!(ipv4_dst(&v6), None);
        assert_eq!(ipv4_dst(&[0x45, 0x00]), None);
    }

    #[test]
    fn dialable_drops_self_no_endpoint_and_garbage() {
        let me = Ipv4Addr::new(100, 64, 0, 3);
        let peers = vec![
            // self — dropped by overlay match
            peer("self", REAL_PUBKEY, "100.64.0.3", Some("192.168.1.5:51820")),
            // no endpoint — can't dial
            peer("no-ep", REAL_PUBKEY, "100.64.0.2", None),
            // garbage pubkey (not 32 bytes) — boringtun can't use it
            peer(
                "garbage",
                "TEST_PUBKEY_AAA=",
                "100.64.0.4",
                Some("192.168.1.6:51820"),
            ),
            // good peer
            peer("good", REAL_PUBKEY, "100.64.0.9", Some("192.168.1.9:51820")),
        ];
        let out = dialable_peers(&peers, me);
        assert_eq!(out.len(), 1, "only the good peer survives");
        assert_eq!(out[0].node_id, "good");
        assert_eq!(out[0].overlay_ip, Ipv4Addr::new(100, 64, 0, 9));
        assert_eq!(out[0].endpoint.port(), 51820);
    }
}
