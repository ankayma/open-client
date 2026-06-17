//! tunnel — WireGuard data-plane engine (boringtun). OPEN, intensity **Critical**.
//!
//! Wraps boringtun's Noise `Tunn` — the WireGuard protocol state machine.
//! `[T:boringtun@0.6]` `[T:WireGuard-whitepaper §5]` Curve25519 + Noise IK_psk2 +
//! ChaCha20-Poly1305. This is the pure protocol engine; the OS plumbing (utun
//! device + UDP socket) lives in the privileged daemon, so this module is
//! unit-testable without root. `[T:A.1.4]` agent OPEN, customer-auditable.

pub use boringtun::noise::{Tunn, TunnResult};
pub use boringtun::x25519::{PublicKey, StaticSecret};

/// Build a boringtun tunnel toward one peer.
/// `index` must be unique per local tunnel (the WireGuard sender index).
/// `[T:boringtun@0.7-Tunn::new]`
pub fn make_tunn(local_private: StaticSecret, peer_public: PublicKey, index: u32) -> Tunn {
    Tunn::new(local_private, peer_public, None, None, index, None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::{OsRng, RngCore};

    fn keypair() -> (StaticSecret, PublicKey) {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        let secret = StaticSecret::from(bytes);
        let public = PublicKey::from(&secret);
        (secret, public)
    }

    /// Proves the REAL WireGuard data path end-to-end, in memory, no utun/root:
    /// two `Tunn` peers complete the Noise handshake, then an encrypted data
    /// packet from A decrypts back to the exact plaintext at B. If this passes,
    /// boringtun's encryption/decryption is wired correctly. `[T:A.1.4]`
    #[test]
    fn encrypted_roundtrip_between_two_peers() {
        let (a_priv, a_pub) = keypair();
        let (b_priv, b_pub) = keypair();
        let mut a = make_tunn(a_priv, b_pub, 1);
        let mut b = make_tunn(b_priv, a_pub, 2);

        let mut buf = [0u8; 2048];

        // 1. A initiates the handshake (explicit — a fresh Tunn won't auto-init
        //    until its timer fires). [T:boringtun@0.7-format_handshake_initiation]
        let hs_init = match a.format_handshake_initiation(&mut buf, false) {
            TunnResult::WriteToNetwork(p) => p.to_vec(),
            _ => panic!("A should emit a handshake initiation"),
        };
        // 2. B consumes the initiation and replies with a handshake response.
        let hs_resp = match b.decapsulate(None, &hs_init, &mut buf) {
            TunnResult::WriteToNetwork(p) => p.to_vec(),
            _ => panic!("B should emit a handshake response"),
        };
        // 3. A consumes the response → session established (may emit a keepalive).
        let _ = a.decapsulate(None, &hs_resp, &mut buf);

        // 4. A encrypts a real IPv4 packet (boringtun only surfaces decrypted
        //    payloads that parse as IP — it reads the version nibble). Minimal
        //    20-byte IPv4 header: src 100.64.0.1 → dst 100.64.0.2, proto ICMP.
        let ip_packet: [u8; 20] = [
            0x45, 0x00, 0x00, 0x14, // v4, IHL5, total len 20
            0x00, 0x00, 0x00, 0x00, // id, flags/frag
            0x40, 0x01, 0x00, 0x00, // ttl 64, proto ICMP, checksum 0
            100, 64, 0, 1, // src 100.64.0.1
            100, 64, 0, 2, // dst 100.64.0.2
        ];
        let data_pkt = match a.encapsulate(&ip_packet, &mut buf) {
            TunnResult::WriteToNetwork(p) => p.to_vec(),
            _ => panic!("A should emit an encrypted data packet"),
        };
        // 5. B decrypts → the exact original IP packet.
        let mut out = [0u8; 2048];
        match b.decapsulate(None, &data_pkt, &mut out) {
            TunnResult::WriteToTunnelV4(decrypted, _) => {
                assert_eq!(
                    decrypted, ip_packet,
                    "decrypted IP packet must equal original"
                );
            }
            _ => panic!("B should decrypt the data packet back to the IPv4 payload"),
        }
    }
}
