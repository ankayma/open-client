//! stun — client half of RFC 5389 endpoint discovery (G-2). OPEN.
//!
//! Runs on the SAME UDP socket as WireGuard (Tailscale/Netbird model): the pump's rx
//! loop calls [`is_stun`] on every datagram and diverts only the ones that *positively*
//! match a STUN message — everything else falls through to boringtun untouched, so a
//! misclassification can never drop a WireGuard packet. `[T: prior-art review 2026-07-21
//! — Tailscale net/stun/stun.go `Is`; decision/nat-traversal-disco-design-2026-07-21.md]`
//!
//! We send a Binding Request to the relay's STUN port and read our own public `ip:port`
//! back from the XOR-MAPPED-ADDRESS, then report it to the control plane so peers can dial
//! it for a hole-punched direct path (G-3).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

const MAGIC_COOKIE: u32 = 0x2112_A442;
const COOKIE_BE: [u8; 4] = MAGIC_COOKIE.to_be_bytes();
const BINDING_REQUEST: u16 = 0x0001;
const BINDING_SUCCESS: u16 = 0x0101;
const XOR_MAPPED_ADDRESS: u16 = 0x0020;
/// STUN method byte (b[1]) shared by Binding request/response — the low byte of both
/// 0x0001 and 0x0101. A packet must carry this to be diverted, tightening the check past
/// a bare cookie match (the residual 1/2³² WG-transport collision then also needs a
/// method-byte hit). `[T:RFC 5389 §6]`
const METHOD_BINDING: u8 = 0x01;

/// Strictest possible "is this STUN, not WireGuard?" test, run at the very front of the
/// pump rx loop. ALL must hold: ≥20 bytes, top two bits of the type zero (STUN class
/// bits; WireGuard message types 1–4 also satisfy this, so it is NOT sufficient alone),
/// the RFC 5389 magic cookie at bytes 4–8, and the Binding method byte. WireGuard's own
/// framing never satisfies the cookie except by a 1/2³² fluke on a transport packet,
/// which the method byte all but removes — and even then, biasing to WG only costs a
/// retried STUN probe, never user data. `[T: Tailscale stun.Is + magicsock fall-through]`
pub fn is_stun(pkt: &[u8]) -> bool {
    pkt.len() >= 20 && (pkt[0] & 0xC0) == 0 && pkt[1] == METHOD_BINDING && pkt[4..8] == COOKIE_BE
}

/// Build a Binding Request carrying `txid` (a fresh 96-bit random id — reuse is a
/// documented pitfall, RFC 5389 §6). No attributes.
pub fn binding_request(txid: &[u8; 12]) -> Vec<u8> {
    let mut m = Vec::with_capacity(20);
    m.extend_from_slice(&BINDING_REQUEST.to_be_bytes());
    m.extend_from_slice(&0u16.to_be_bytes()); // message length: 0 attributes
    m.extend_from_slice(&COOKIE_BE);
    m.extend_from_slice(txid);
    m
}

/// Decode our reflexive `ip:port` from a Binding Success Response, but only if it answers
/// `txid` (rejects stale/spoofed replies — reflexive addresses are spoofable, so a txid
/// match is the minimum bar; MESSAGE-INTEGRITY is layered on once we key the relay STUN).
/// Returns `None` for anything that isn't a matching success response with an
/// XOR-MAPPED-ADDRESS. `[T:RFC 5389 §15.2]`
pub fn parse_binding_response(pkt: &[u8], txid: &[u8; 12]) -> Option<SocketAddr> {
    if pkt.len() < 20
        || u16::from_be_bytes([pkt[0], pkt[1]]) != BINDING_SUCCESS
        || pkt[4..8] != COOKIE_BE
        || &pkt[8..20] != txid
    {
        return None;
    }
    let mut i = 20;
    while i + 4 <= pkt.len() {
        let atype = u16::from_be_bytes([pkt[i], pkt[i + 1]]);
        let alen = u16::from_be_bytes([pkt[i + 2], pkt[i + 3]]) as usize;
        if i + 4 + alen > pkt.len() {
            return None;
        }
        if atype == XOR_MAPPED_ADDRESS {
            return decode_xor_mapped(&pkt[i + 4..i + 4 + alen], txid);
        }
        // Attributes are 4-byte aligned; skip padding.
        i += 4 + alen.next_multiple_of(4);
    }
    None
}

fn decode_xor_mapped(val: &[u8], txid: &[u8; 12]) -> Option<SocketAddr> {
    if val.len() < 8 {
        return None;
    }
    let port = u16::from_be_bytes([val[2], val[3]]) ^ (MAGIC_COOKIE >> 16) as u16;
    match val[1] {
        0x01 => {
            let mut a = [0u8; 4];
            for (j, b) in a.iter_mut().enumerate() {
                *b = val[4 + j] ^ COOKIE_BE[j];
            }
            Some(SocketAddr::from((Ipv4Addr::from(a), port)))
        }
        0x02 if val.len() >= 20 => {
            let mut key = [0u8; 16];
            key[..4].copy_from_slice(&COOKIE_BE);
            key[4..].copy_from_slice(txid);
            let mut a = [0u8; 16];
            for (j, b) in a.iter_mut().enumerate() {
                *b = val[4 + j] ^ key[j];
            }
            Some(SocketAddr::from((Ipv6Addr::from(a), port)))
        }
        _ => None,
    }
}

/// The reflexive endpoint as `host:port`, the shape the control plane stores in
/// `nodes.endpoint`. IPv6 is bracketed. Helper so callers don't re-derive the format.
pub fn endpoint_string(addr: SocketAddr) -> String {
    match addr.ip() {
        IpAddr::V4(_) => addr.to_string(),
        IpAddr::V6(v6) => format!("[{v6}]:{}", addr.port()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A WireGuard datagram whose first byte is a real WG message type. The demux must
    // NEVER divert this to STUN, even if bytes 4-8 happen to look cookie-ish.
    fn wg_transport_packet() -> Vec<u8> {
        let mut p = vec![0u8; 64];
        p[0] = 0x04; // WG transport data message type
        p
    }

    #[test]
    fn wireguard_is_never_classified_as_stun() {
        assert!(!is_stun(&wg_transport_packet()));
        // WG handshake init/response/cookie types.
        for t in [1u8, 2, 3] {
            let mut p = vec![0u8; 148];
            p[0] = t;
            // Even if a WG transport packet's receiver index collides with the cookie,
            // the method byte (b[1]) must also match — vanishingly unlikely, and here it
            // doesn't, so this stays classified WG.
            p[4..8].copy_from_slice(&COOKIE_BE);
            assert!(!is_stun(&p), "WG type {t} must not divert to STUN");
        }
        assert!(!is_stun(&[])); // too short
        assert!(!is_stun(&[0u8; 10])); // too short
    }

    #[test]
    fn stun_response_is_classified_and_parsed() {
        let txid = [0x5Au8; 12];
        // A real binding-success response is STUN.
        let resp = make_response(
            txid,
            SocketAddr::from((Ipv4Addr::new(203, 0, 113, 7), 51820)),
        );
        assert!(is_stun(&resp));
        assert_eq!(
            parse_binding_response(&resp, &txid),
            Some(SocketAddr::from((Ipv4Addr::new(203, 0, 113, 7), 51820)))
        );
        // A binding REQUEST (what we send) is also STUN-classified (top2=0, cookie,
        // method) — the demux diverts both directions; only responses parse.
        assert!(is_stun(&binding_request(&txid)));
    }

    #[test]
    fn wrong_txid_is_rejected() {
        let resp = make_response([1u8; 12], SocketAddr::from((Ipv4Addr::LOCALHOST, 1)));
        assert!(parse_binding_response(&resp, &[2u8; 12]).is_none());
    }

    #[test]
    fn ipv6_roundtrips() {
        let txid = [0x11u8; 12];
        let src = SocketAddr::from((Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 9), 443));
        assert_eq!(
            parse_binding_response(&make_response(txid, src), &txid),
            Some(src)
        );
    }

    // Build a Binding Success Response with XOR-MAPPED-ADDRESS (mirrors the relay server).
    fn make_response(txid: [u8; 12], src: SocketAddr) -> Vec<u8> {
        let xport = src.port() ^ (MAGIC_COOKIE >> 16) as u16;
        let mut attr = vec![0x00];
        match src.ip() {
            IpAddr::V4(v4) => {
                attr.push(0x01);
                attr.extend_from_slice(&xport.to_be_bytes());
                for (i, b) in v4.octets().iter().enumerate() {
                    attr.push(b ^ COOKIE_BE[i]);
                }
            }
            IpAddr::V6(v6) => {
                attr.push(0x02);
                attr.extend_from_slice(&xport.to_be_bytes());
                let mut key = [0u8; 16];
                key[..4].copy_from_slice(&COOKIE_BE);
                key[4..].copy_from_slice(&txid);
                for (i, b) in v6.octets().iter().enumerate() {
                    attr.push(b ^ key[i]);
                }
            }
        }
        let mut m = Vec::new();
        m.extend_from_slice(&BINDING_SUCCESS.to_be_bytes());
        m.extend_from_slice(&(4 + attr.len() as u16).to_be_bytes());
        m.extend_from_slice(&COOKIE_BE);
        m.extend_from_slice(&txid);
        m.extend_from_slice(&XOR_MAPPED_ADDRESS.to_be_bytes());
        m.extend_from_slice(&(attr.len() as u16).to_be_bytes());
        m.extend_from_slice(&attr);
        m
    }
}
