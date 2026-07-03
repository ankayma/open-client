//! dns — portable F-3 private-DNS answering: parse a DNS question, answer it
//! from a name→address table, and (for hosts with no OS-level split-DNS hook)
//! frame/unframe the answer as a raw IP/UDP packet suitable for writing back
//! into a tun fd. OPEN, intensity Standard.
//!
//! `parse_qname`/`respond` are the pure, dependency-free responder shared by:
//!   - `agent-daemon::resolver` (macOS/Linux): a loopback UDP socket fed by a
//!     scoped `/etc/resolver/<zone>` file — DNS never touches the tun device.
//!   - `agent-core::pump` (iOS, via `agent-ios-ptp`): iOS has no split-DNS
//!     hook a Network Extension can use outside `NEDNSSettings.matchDomains`,
//!     which routes matching queries INTO the tunnel. Those queries arrive as
//!     ordinary UDP packets on the tun fd, addressed at this node's own
//!     overlay IP — `dns_query_payload`/`build_dns_reply` extract/frame them.
//!     `[T: f3-privdomain-ios-plan.md Phase 2]`

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const TTL_SECS: u32 = 30; // short — names follow enrollment/revoke, don't cache long
const QTYPE_A: u16 = 1;
const QTYPE_AAAA: u16 = 28;
const RCODE_OK: u8 = 0;
const RCODE_SERVFAIL: u8 = 2;
const RCODE_NXDOMAIN: u8 = 3;
const UDP_PORT_DNS: u16 = 53;
const IPPROTO_UDP: u8 = 17;

/// Walk a QNAME starting at `off`; return (name, offset just past the null label).
/// Rejects compression pointers — queries don't use them, and refusing keeps the
/// parser from following an attacker-crafted loop. `None` on malformed input.
pub fn parse_qname(buf: &[u8], mut off: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    loop {
        let len = *buf.get(off)? as usize;
        if len == 0 {
            return Some((labels.join("."), off + 1));
        }
        if len & 0xC0 != 0 {
            return None; // compression pointer — not expected in a question
        }
        let start = off + 1;
        let end = start + len;
        let label = buf.get(start..end)?;
        labels.push(String::from_utf8_lossy(label).to_ascii_lowercase());
        off = end;
    }
}

/// The queried name (lowercased) from a raw single-question DNS query message, or
/// `None` if it can't be parsed. Used to decide answer-locally vs forward-upstream.
pub fn query_name(query: &[u8]) -> Option<String> {
    if query.len() < 12 {
        return None;
    }
    parse_qname(query, 12).map(|(name, _)| name)
}

/// Build a response to a single-question query. Returns `None` only if the packet
/// is not a well-formed single-question query (malformed / not 1 question). Pure.
///
/// A resolver that owns a name must ANSWER every query type for it, never stay
/// silent: an unknown/unsupported type (Safari sends HTTPS/SVCB type-65 for every
/// name) gets NOERROR with zero answers — the standard behaviour, and what
/// Tailscale's resolver does. `[T:tailscale tsdns.go — "always return NOERROR
/// without any records whenever the requested record type is unknown"]` A silent
/// drop makes iOS mark the tunnel resolver dead and stop using it until reconnect
/// `[T:Apple-DevForums-114097]`.
pub fn respond(table: &HashMap<String, IpAddr>, query: &[u8]) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([query[4], query[5]]);
    if qdcount != 1 {
        return None;
    }
    let (name, after_name) = parse_qname(query, 12)?;
    let qtype = u16::from_be_bytes([*query.get(after_name)?, *query.get(after_name + 1)?]);
    let qend = after_name + 4; // QTYPE(2) + QCLASS(2)
    if query.len() < qend {
        return None;
    }

    // Echo header + question; flip to an authoritative answer.
    let mut resp = query[..qend].to_vec();
    resp[2] = 0x84 | (query[2] & 0x01); // QR=1, AA=1, keep RD
    let hit = table.get(&name);
    // Answer only when the record family matches the query type; a name that exists
    // but has no record of this type is NODATA (RCODE 0, 0 answers), not NXDOMAIN.
    let answer_ip = hit.filter(|ip| {
        matches!(
            (qtype, ip),
            (QTYPE_A, IpAddr::V4(_)) | (QTYPE_AAAA, IpAddr::V6(_))
        )
    });
    let rcode = if hit.is_some() {
        RCODE_OK
    } else {
        RCODE_NXDOMAIN
    };
    resp[3] = rcode;
    let ancount: u16 = if answer_ip.is_some() { 1 } else { 0 };
    resp[6..8].copy_from_slice(&ancount.to_be_bytes());
    resp[8..10].copy_from_slice(&[0, 0]); // NSCOUNT
    resp[10..12].copy_from_slice(&[0, 0]); // ARCOUNT (drop any EDNS OPT)

    if let Some(ip) = answer_ip {
        resp.extend_from_slice(&[0xC0, 0x0C]); // NAME → pointer to the question's QNAME
        resp.extend_from_slice(&qtype.to_be_bytes());
        resp.extend_from_slice(&[0x00, 0x01]); // CLASS IN
        resp.extend_from_slice(&TTL_SECS.to_be_bytes());
        match ip {
            IpAddr::V4(v4) => {
                resp.extend_from_slice(&[0x00, 0x04]);
                resp.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                resp.extend_from_slice(&[0x00, 0x10]);
                resp.extend_from_slice(&v6.octets());
            }
        }
    }
    Some(resp)
}

/// Build a SERVFAIL response echoing `query`'s header + question. Used when a
/// forwarded query's upstream round-trip fails: the client must get an ANSWER,
/// not silence — iOS drops a tunnel resolver that stays silent and won't use it
/// again until reconnect `[T:Apple-DevForums-114097]`. Tailscale does exactly
/// this: every upstream failure is mapped to a synthesized SERVFAIL
/// `[T:tailscale forwarder.go servfailResponse — "All such errors map to
/// SERVFAIL at the client level"]`. `None` if `query` is malformed.
pub fn build_servfail(query: &[u8]) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }
    if u16::from_be_bytes([query[4], query[5]]) != 1 {
        return None;
    }
    let (_, after_name) = parse_qname(query, 12)?;
    let qend = after_name + 4; // QTYPE(2) + QCLASS(2)
    if query.len() < qend {
        return None;
    }
    let mut resp = query[..qend].to_vec();
    resp[2] = 0x84 | (query[2] & 0x01); // QR=1, AA=1, keep RD
    resp[3] = RCODE_SERVFAIL;
    resp[6..12].fill(0); // ANCOUNT/NSCOUNT/ARCOUNT = 0
    Some(resp)
}

// ---- raw IP/UDP framing (tun-embedded DNS — iOS has no split-DNS hook) ----

/// If `packet` (a raw IP datagram read from a tun fd, no link-layer header) is a
/// UDP datagram addressed at `(self_ip, 53)`, return the UDP payload (the DNS
/// query bytes). A query for our own overlay IP is never a real mesh peer, so
/// the caller should intercept it here instead of routing it to a peer.
/// Handles IPv4 (with IHL/options) and IPv6 (no extension headers — a plain
/// resolver's outgoing query never has any). `[T: f3-privdomain-ios-plan.md]`
pub fn dns_query_payload(packet: &[u8], self_ip: IpAddr) -> Option<&[u8]> {
    match (packet.first()? >> 4, self_ip) {
        (4, IpAddr::V4(self_v4)) => {
            if packet.len() < 20 {
                return None;
            }
            let ihl = (packet[0] & 0x0F) as usize * 4;
            if ihl < 20 || packet[9] != IPPROTO_UDP || packet.len() < ihl + 8 {
                return None;
            }
            let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
            if dst != self_v4 {
                return None;
            }
            udp_payload_if_dns(&packet[ihl..])
        }
        (6, IpAddr::V6(self_v6)) => {
            if packet.len() < 48 || packet[6] != IPPROTO_UDP {
                return None; // < 40-byte IPv6 header + 8-byte UDP header
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&packet[24..40]);
            if Ipv6Addr::from(octets) != self_v6 {
                return None;
            }
            udp_payload_if_dns(&packet[40..])
        }
        _ => None, // version/family mismatch (e.g. an AAAA query while self_ip is v4)
    }
}

/// `udp` starts at the UDP header. Returns the payload if dest port is 53 and the
/// declared UDP length is consistent with the buffer.
fn udp_payload_if_dns(udp: &[u8]) -> Option<&[u8]> {
    if udp.len() < 8 {
        return None;
    }
    let dst_port = u16::from_be_bytes([udp[2], udp[3]]);
    if dst_port != UDP_PORT_DNS {
        return None;
    }
    let udp_len = u16::from_be_bytes([udp[4], udp[5]]) as usize;
    if udp_len < 8 || udp.len() < udp_len {
        return None;
    }
    Some(&udp[8..udp_len])
}

/// Build the raw IP/UDP reply packet for a query accepted by `dns_query_payload`:
/// swap src/dst against `request`, source port becomes 53, and wrap `answer` (the
/// DNS response bytes from `respond`). The reply's IP header is always minimal
/// (no options), even if the request's wasn't — a reply body doesn't need them.
///
/// IPv6 UDP checksum is **mandatory** (RFC 8200 §8.1) and computed here over the
/// pseudo-header; IPv4 leaves it `0` ("not computed"), legal per RFC 768 and what
/// the macOS loopback resolver already does.
pub fn build_dns_reply(request: &[u8], answer: &[u8]) -> Option<Vec<u8>> {
    match request.first()? >> 4 {
        4 => build_reply_v4(request, answer),
        6 => build_reply_v6(request, answer),
        _ => None,
    }
}

fn build_reply_v4(request: &[u8], answer: &[u8]) -> Option<Vec<u8>> {
    let ihl = (request[0] & 0x0F) as usize * 4;
    if ihl < 20 || request.len() < ihl + 8 {
        return None;
    }
    let orig_src: [u8; 4] = request[12..16].try_into().ok()?;
    let orig_dst: [u8; 4] = request[16..20].try_into().ok()?;
    let orig_src_port = [request[ihl], request[ihl + 1]];

    let udp_len = 8 + answer.len();
    let total_len = 20 + udp_len;
    let mut pkt = vec![0u8; total_len];
    pkt[0] = 0x45; // version 4, IHL 5 (minimal — no options in the reply)
    pkt[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    pkt[8] = 64; // TTL
    pkt[9] = IPPROTO_UDP;
    pkt[12..16].copy_from_slice(&orig_dst); // reply src = original dst (us)
    pkt[16..20].copy_from_slice(&orig_src); // reply dst = original src
    let cksum = ip_checksum(&pkt[..20]);
    pkt[10..12].copy_from_slice(&cksum.to_be_bytes());

    pkt[20..22].copy_from_slice(&UDP_PORT_DNS.to_be_bytes());
    pkt[22..24].copy_from_slice(&orig_src_port);
    pkt[24..26].copy_from_slice(&(udp_len as u16).to_be_bytes());
    // pkt[26..28] (UDP checksum) left 0 — "not computed", legal for IPv4 (RFC 768).
    pkt[28..].copy_from_slice(answer);
    Some(pkt)
}

fn build_reply_v6(request: &[u8], answer: &[u8]) -> Option<Vec<u8>> {
    if request.len() < 48 || request[6] != IPPROTO_UDP {
        return None;
    }
    let orig_src: [u8; 16] = request[8..24].try_into().ok()?;
    let orig_dst: [u8; 16] = request[24..40].try_into().ok()?;
    let orig_src_port = [request[40], request[41]];

    let udp_len = 8 + answer.len();
    let total_len = 40 + udp_len;
    let mut pkt = vec![0u8; total_len];
    pkt[0] = 0x60; // version 6, traffic class/flow label 0
    pkt[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes()); // payload length
    pkt[6] = IPPROTO_UDP;
    pkt[7] = 64; // hop limit
    pkt[8..24].copy_from_slice(&orig_dst); // reply src = original dst (us)
    pkt[24..40].copy_from_slice(&orig_src); // reply dst = original src

    pkt[40..42].copy_from_slice(&UDP_PORT_DNS.to_be_bytes());
    pkt[42..44].copy_from_slice(&orig_src_port);
    pkt[44..46].copy_from_slice(&(udp_len as u16).to_be_bytes());
    pkt[48..].copy_from_slice(answer);

    let cksum = udp6_checksum(&orig_dst, &orig_src, &pkt[40..]);
    pkt[46..48].copy_from_slice(&cksum.to_be_bytes());
    Some(pkt)
}

/// Standard Internet one's-complement checksum (RFC 1071) over an even-length
/// buffer with the checksum field itself zeroed.
fn ip_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = header
        .chunks_exact(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]) as u32)
        .sum();
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// IPv6 UDP checksum: pseudo-header (src + dst + upper-layer length + next-header)
/// followed by the UDP segment itself, with the checksum field zeroed. `[T:RFC 8200 §8.1]`
fn udp6_checksum(src: &[u8; 16], dst: &[u8; 16], udp_segment: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for chunk in src.chunks_exact(2).chain(dst.chunks_exact(2)) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    let len = udp_segment.len() as u32;
    sum += len >> 16;
    sum += len & 0xFFFF;
    sum += IPPROTO_UDP as u32;

    let mut iter = udp_segment.chunks_exact(2);
    for chunk in iter.by_ref() {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    if let [last] = *iter.remainder() {
        sum += u16::from_be_bytes([last, 0]) as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    let cksum = !(sum as u16);
    if cksum == 0 {
        0xFFFF // RFC 768: a computed checksum of 0 is transmitted as all-ones
    } else {
        cksum
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    // A real wire query: ID 0x1234, RD=1, 1 question, QNAME "a.b", QTYPE, QCLASS IN.
    fn query(qtype: u16) -> Vec<u8> {
        let mut q = vec![
            0x12, 0x34, // id
            0x01, 0x00, // flags: RD
            0x00, 0x01, // qdcount
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // an/ns/ar
            0x01, b'a', 0x01, b'b', 0x00, // QNAME a.b
        ];
        q.extend_from_slice(&qtype.to_be_bytes());
        q.extend_from_slice(&[0x00, 0x01]); // QCLASS IN
        q
    }

    fn table(ip: IpAddr) -> HashMap<String, IpAddr> {
        HashMap::from([("a.b".to_string(), ip)])
    }

    #[test]
    fn parses_qname_and_rejects_pointer() {
        let q = query(QTYPE_A);
        let (name, off) = parse_qname(&q, 12).unwrap();
        assert_eq!(name, "a.b");
        assert_eq!(off, 17);
        let bad = [0xC0u8, 0x0C];
        assert!(parse_qname(&bad, 0).is_none());
    }

    #[test]
    fn answers_a_record_when_present() {
        let ip = IpAddr::V4(Ipv4Addr::new(100, 64, 0, 7));
        let r = respond(&table(ip), &query(QTYPE_A)).unwrap();
        assert_eq!(r[2] & 0x80, 0x80, "QR set");
        assert_eq!(r[3] & 0x0F, RCODE_OK);
        assert_eq!(u16::from_be_bytes([r[6], r[7]]), 1, "one answer");
        assert_eq!(&r[r.len() - 4..], &[100, 64, 0, 7]);
    }

    #[test]
    fn nxdomain_for_unknown_name() {
        let r = respond(&HashMap::new(), &query(QTYPE_A)).unwrap();
        assert_eq!(r[3] & 0x0F, RCODE_NXDOMAIN);
    }

    // Safari sends HTTPS/SVCB (type 65) for every name. An owned name must get
    // NOERROR + 0 answers (NODATA), never silence — a silent drop makes iOS mark
    // the tunnel resolver dead until reconnect. `[T:tailscale tsdns.go]`
    #[test]
    fn unknown_qtype_for_owned_name_is_nodata_not_silence() {
        const QTYPE_HTTPS: u16 = 65;
        let ip = IpAddr::V6("fd00:a11a::7".parse().unwrap());
        let r = respond(&table(ip), &query(QTYPE_HTTPS)).expect("must answer, not drop");
        assert_eq!(r[2] & 0x80, 0x80, "QR set");
        assert_eq!(r[3] & 0x0F, RCODE_OK, "NOERROR");
        assert_eq!(u16::from_be_bytes([r[6], r[7]]), 0, "zero answers (NODATA)");
    }

    #[test]
    fn unknown_qtype_for_unknown_name_is_nxdomain() {
        const QTYPE_HTTPS: u16 = 65;
        let r = respond(&HashMap::new(), &query(QTYPE_HTTPS)).expect("must answer");
        assert_eq!(r[3] & 0x0F, RCODE_NXDOMAIN);
    }

    #[test]
    fn build_servfail_echoes_question_and_sets_rcode() {
        let q = query(QTYPE_A);
        let r = build_servfail(&q).unwrap();
        assert_eq!(r[0..2], q[0..2], "transaction id echoed");
        assert_eq!(r[2] & 0x80, 0x80, "QR set");
        assert_eq!(r[3] & 0x0F, RCODE_SERVFAIL);
        assert_eq!(u16::from_be_bytes([r[4], r[5]]), 1, "question echoed");
        assert_eq!(u16::from_be_bytes([r[6], r[7]]), 0, "no answers");
        assert_eq!(&r[12..17], &q[12..17], "QNAME intact");
        assert!(build_servfail(&[0u8; 4]).is_none(), "malformed rejected");
    }

    // ---- raw framing ----

    fn ipv4_dns_packet(self_ip: Ipv4Addr, src_ip: Ipv4Addr, src_port: u16, dns: &[u8]) -> Vec<u8> {
        let udp_len = 8 + dns.len();
        let total_len = 20 + udp_len;
        let mut pkt = vec![0u8; total_len];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        pkt[8] = 64;
        pkt[9] = IPPROTO_UDP;
        pkt[12..16].copy_from_slice(&src_ip.octets());
        pkt[16..20].copy_from_slice(&self_ip.octets());
        let cksum = ip_checksum(&pkt[..20]);
        pkt[10..12].copy_from_slice(&cksum.to_be_bytes());
        pkt[20..22].copy_from_slice(&src_port.to_be_bytes());
        pkt[22..24].copy_from_slice(&UDP_PORT_DNS.to_be_bytes());
        pkt[24..26].copy_from_slice(&(udp_len as u16).to_be_bytes());
        pkt[28..].copy_from_slice(dns);
        pkt
    }

    fn ipv6_dns_packet(self_ip: Ipv6Addr, src_ip: Ipv6Addr, src_port: u16, dns: &[u8]) -> Vec<u8> {
        let udp_len = 8 + dns.len();
        let total_len = 40 + udp_len;
        let mut pkt = vec![0u8; total_len];
        pkt[0] = 0x60;
        pkt[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
        pkt[6] = IPPROTO_UDP;
        pkt[7] = 64;
        pkt[8..24].copy_from_slice(&src_ip.octets());
        pkt[24..40].copy_from_slice(&self_ip.octets());
        pkt[40..42].copy_from_slice(&src_port.to_be_bytes());
        pkt[42..44].copy_from_slice(&UDP_PORT_DNS.to_be_bytes());
        pkt[44..46].copy_from_slice(&(udp_len as u16).to_be_bytes());
        pkt[48..].copy_from_slice(dns);
        // Checksum optional-but-common on the wire too; leave 0 for the *query* side,
        // dns_query_payload doesn't validate it (matches a real iOS-originated query,
        // which the OS resolver always checksums correctly — we only need our own
        // *replies* to have a valid one).
        pkt
    }

    #[test]
    fn dns_query_payload_extracts_ipv4() {
        let self_ip = Ipv4Addr::new(100, 64, 0, 1);
        let src_ip = Ipv4Addr::new(100, 64, 0, 9);
        let dns = query(QTYPE_A);
        let pkt = ipv4_dns_packet(self_ip, src_ip, 54321, &dns);
        let payload = dns_query_payload(&pkt, IpAddr::V4(self_ip)).unwrap();
        assert_eq!(payload, &dns[..]);
    }

    #[test]
    fn dns_query_payload_extracts_ipv6() {
        let self_ip: Ipv6Addr = "fd00:a11a::1".parse().unwrap();
        let src_ip: Ipv6Addr = "fd00:a11a::9".parse().unwrap();
        let dns = query(QTYPE_AAAA);
        let pkt = ipv6_dns_packet(self_ip, src_ip, 54321, &dns);
        let payload = dns_query_payload(&pkt, IpAddr::V6(self_ip)).unwrap();
        assert_eq!(payload, &dns[..]);
    }

    #[test]
    fn dns_query_payload_ignores_wrong_dest_or_port() {
        let self_ip = Ipv4Addr::new(100, 64, 0, 1);
        let other = Ipv4Addr::new(100, 64, 0, 2);
        let dns = query(QTYPE_A);
        // dest is not self_ip → not our query, should route to a peer instead.
        let pkt = ipv4_dns_packet(other, Ipv4Addr::new(100, 64, 0, 9), 1234, &dns);
        assert!(dns_query_payload(&pkt, IpAddr::V4(self_ip)).is_none());
    }

    #[test]
    fn build_reply_v4_swaps_endpoints_and_has_valid_ip_checksum() {
        let self_ip = Ipv4Addr::new(100, 64, 0, 1);
        let src_ip = Ipv4Addr::new(100, 64, 0, 9);
        let query_bytes = query(QTYPE_A);
        let req = ipv4_dns_packet(self_ip, src_ip, 54321, &query_bytes);
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
        let answer = respond(&table(ip), &query_bytes).unwrap();

        let reply = build_dns_reply(&req, &answer).unwrap();
        assert_eq!(reply[0] >> 4, 4);
        assert_eq!(&reply[12..16], &self_ip.octets(), "reply src = us");
        assert_eq!(
            &reply[16..20],
            &src_ip.octets(),
            "reply dst = original querier"
        );
        // Recomputing the checksum over the header (incl. the checksum field) must
        // fold to 0 for a valid IPv4 header checksum.
        assert_eq!(ip_checksum(&reply[..20]), 0);
        assert_eq!(
            u16::from_be_bytes([reply[20], reply[21]]),
            UDP_PORT_DNS,
            "src port 53"
        );
        assert_eq!(
            u16::from_be_bytes([reply[22], reply[23]]),
            54321,
            "dst port = original src port"
        );
        assert_eq!(
            &reply[28..],
            &answer[..],
            "payload = respond()'s answer bytes"
        );
    }

    #[test]
    fn build_reply_v6_has_mandatory_valid_udp_checksum() {
        let self_ip: Ipv6Addr = "fd00:a11a::1".parse().unwrap();
        let src_ip: Ipv6Addr = "fd00:a11a::9".parse().unwrap();
        let query_bytes = query(QTYPE_AAAA);
        let req = ipv6_dns_packet(self_ip, src_ip, 54321, &query_bytes);
        let ip = IpAddr::V6("fd00:a11a::dead".parse().unwrap());
        let answer = respond(&table(ip), &query_bytes).unwrap();

        let reply = build_dns_reply(&req, &answer).unwrap();
        assert_eq!(reply[0] >> 4, 6);
        assert_eq!(&reply[8..24], &self_ip.octets(), "reply src = us");
        assert_eq!(
            &reply[24..40],
            &src_ip.octets(),
            "reply dst = original querier"
        );
        assert_eq!(&reply[48..], &answer[..]);

        // A valid IPv6 UDP checksum: recomputing over the pseudo-header + segment
        // (checksum field included as transmitted) folds to 0xFFFF (all-ones), the
        // RFC 1071 "complement of the sum is 0" identity in its non-negated form.
        let orig_dst: [u8; 16] = reply[8..24].try_into().unwrap();
        let orig_src: [u8; 16] = reply[24..40].try_into().unwrap();
        let recomputed = udp6_checksum(&orig_dst, &orig_src, &reply[40..]);
        // udp6_checksum zeroes nothing itself — feeding it the *already-checksummed*
        // segment must fold to 0 (since checksum = !sum, and sum+checksum folds to
        // 0xFFFF, and !0xFFFF == 0) unless the all-ones special case applied.
        assert!(recomputed == 0 || recomputed == 0xFFFF);
    }

    #[test]
    fn dns_query_payload_rejects_short_and_non_udp() {
        assert!(dns_query_payload(&[0x45, 0, 0, 20], IpAddr::V4(Ipv4Addr::LOCALHOST)).is_none());
        let mut tcp_pkt = ipv4_dns_packet(
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(2, 2, 2, 2),
            1234,
            &query(QTYPE_A),
        );
        tcp_pkt[9] = 6; // TCP, not UDP
        assert!(dns_query_payload(&tcp_pkt, IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))).is_none());
    }
}
