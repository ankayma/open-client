//! dns — DNS intercept for F-3 private domain on Android VpnService plumbing.
//! Pure: no I/O. The pump feeds raw IPv6 packets from the TUN and gets response
//! packets to write back. [T:Part C §H.3.6.1, F-3]
//!
//! Strategy:
//!   *.int.ankayma.com in table  → AAAA answer with the node's overlay IP
//!   *.int.ankayma.com not found → NXDOMAIN (private zone, domain removed/revoked)
//!   everything else             → SERVFAIL (Android falls back to its secondary DNS)
//!
//! The VPN builder adds "fd00:a11a::53" as the primary DNS server + a /128 route
//! so queries hit the TUN; secondary "8.8.8.8" handles non-Ankayma SERVFAIL fallback.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr};

const TTL_SECS: u32 = 30; // short — names follow enrollment/revoke
const QTYPE_A: u16 = 1;
const QTYPE_AAAA: u16 = 28;
const RCODE_OK: u8 = 0;
const RCODE_SERVFAIL: u8 = 2;
const RCODE_NXDOMAIN: u8 = 3;

/// Private zone handled by this resolver.
const ANKAYMA_ZONE: &str = ".int.ankayma.com";

// ── DNS wire-format helpers ───────────────────────────────────────────────────

fn parse_qname(buf: &[u8], mut off: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    loop {
        let len = *buf.get(off)? as usize;
        if len == 0 {
            return Some((labels.join("."), off + 1));
        }
        if len & 0xC0 != 0 {
            return None; // compression pointer — not in queries
        }
        let end = off + 1 + len;
        let label = buf.get(off + 1..end)?;
        labels.push(String::from_utf8_lossy(label).to_ascii_lowercase());
        off = end;
    }
}

/// Build a DNS UDP-payload response for an A/AAAA query.
fn build_dns_response(table: &HashMap<String, IpAddr>, query: &[u8]) -> Option<Vec<u8>> {
    if query.len() < 12 || u16::from_be_bytes([query[4], query[5]]) != 1 {
        return None;
    }
    let (name, after_name) = parse_qname(query, 12)?;
    let qtype = u16::from_be_bytes([*query.get(after_name)?, *query.get(after_name + 1)?]);
    let qend = after_name + 4; // QTYPE(2) + QCLASS(2)
    if query.len() < qend || (qtype != QTYPE_A && qtype != QTYPE_AAAA) {
        return None;
    }

    let in_zone = name.ends_with(ANKAYMA_ZONE);

    // Echo header + question section; flip QR/AA.
    let mut resp = query[..qend].to_vec();
    resp[2] = 0x84 | (query[2] & 0x01); // QR=1, AA=1, keep RD
    resp[8..10].copy_from_slice(&[0, 0]); // NSCOUNT
    resp[10..12].copy_from_slice(&[0, 0]); // ARCOUNT (drop EDNS OPT)

    if !in_zone {
        resp[3] = RCODE_SERVFAIL;
        resp[6..8].copy_from_slice(&[0, 0]); // ANCOUNT
        return Some(resp);
    }

    let hit = table.get(&name);
    let answer_ip = hit.filter(|ip| {
        matches!((qtype, ip), (QTYPE_A, IpAddr::V4(_)) | (QTYPE_AAAA, IpAddr::V6(_)))
    });
    resp[3] = if hit.is_some() { RCODE_OK } else { RCODE_NXDOMAIN };
    resp[6..8].copy_from_slice(&(answer_ip.is_some() as u16).to_be_bytes()); // ANCOUNT

    if let Some(ip) = answer_ip {
        resp.extend_from_slice(&[0xC0, 0x0C]); // NAME: pointer to QNAME
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

// ── IPv6/UDP packet construction ──────────────────────────────────────────────

/// RFC 2460 §8.1 + RFC 768: 1's-complement sum over bytes (padding odd byte).
fn ones_sum(data: &[u8]) -> u32 {
    let mut acc: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        acc += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        acc += (data[i] as u32) << 8;
    }
    acc
}

/// UDP/IPv6 checksum over pseudo-header + UDP segment (checksum field must be 0).
fn udp6_checksum(src: &[u8; 16], dst: &[u8; 16], udp_len: u16, udp_seg: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    sum += ones_sum(src);
    sum += ones_sum(dst);
    // Upper-layer packet length: 32-bit, but fits in 16 bits for DNS.
    sum += udp_len as u32;
    sum += 17u32; // next-header = UDP
    sum += ones_sum(udp_seg); // UDP header (checksum=0) + payload
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    let r = !(sum as u16);
    if r == 0 { 0xFFFF } else { r } // RFC 768: 0xFFFF transmitted when result is 0
}

// ── Public intercept entry-point ──────────────────────────────────────────────

/// Try to intercept an outgoing IPv6 UDP packet going to `magic_dns_ip:53`.
/// On match, returns a complete IPv6 UDP response packet to write back to the TUN.
/// Returns `None` if the packet is not a DNS query to our magic IP.
pub fn try_intercept(
    magic_dns_ip: Ipv6Addr,
    table: &HashMap<String, IpAddr>,
    packet: &[u8],
) -> Option<Vec<u8>> {
    // IPv6 (version nibble = 6)
    if packet.first().map(|b| b >> 4) != Some(6) {
        return None;
    }
    // Minimum: IPv6 header (40) + UDP header (8)
    if packet.len() < 48 {
        return None;
    }
    // Next header must be UDP (17)
    if packet[6] != 17 {
        return None;
    }

    // Destination address bytes [24..40]
    let mut dst_buf = [0u8; 16];
    dst_buf.copy_from_slice(&packet[24..40]);
    if Ipv6Addr::from(dst_buf) != magic_dns_ip {
        return None;
    }

    // UDP destination port at offset 42-43 must be 53
    if u16::from_be_bytes([packet[42], packet[43]]) != 53 {
        return None;
    }

    // Client source: IPv6 at [8..24], UDP source port at [40..42]
    let mut src_buf = [0u8; 16];
    src_buf.copy_from_slice(&packet[8..24]);
    let client_port = u16::from_be_bytes([packet[40], packet[41]]);

    let dns_payload = &packet[48..];
    let dns_resp = build_dns_response(table, dns_payload)?;

    // Build IPv6 UDP response: src=magic_dns_ip dst=client, ports swapped.
    let udp_payload_len = dns_resp.len();
    let udp_total = 8u16 + udp_payload_len as u16;
    let magic_octets = magic_dns_ip.octets();

    // UDP segment with checksum=0 for computation
    let mut udp_seg = Vec::with_capacity(udp_total as usize);
    udp_seg.extend_from_slice(&53u16.to_be_bytes()); // src port
    udp_seg.extend_from_slice(&client_port.to_be_bytes()); // dst port
    udp_seg.extend_from_slice(&udp_total.to_be_bytes()); // length
    udp_seg.extend_from_slice(&[0, 0]); // checksum = 0
    udp_seg.extend_from_slice(&dns_resp);

    let cksum = udp6_checksum(&magic_octets, &src_buf, udp_total, &udp_seg);
    udp_seg[6] = (cksum >> 8) as u8;
    udp_seg[7] = (cksum & 0xFF) as u8;

    // IPv6 header (40 bytes) + UDP segment
    let mut pkt = Vec::with_capacity(40 + udp_total as usize);
    pkt.push(0x60); // version=6, traffic class hi=0
    pkt.extend_from_slice(&[0x00, 0x00, 0x00]); // traffic class lo + flow label
    pkt.extend_from_slice(&udp_total.to_be_bytes()); // payload length
    pkt.push(17); // next header = UDP
    pkt.push(64); // hop limit
    pkt.extend_from_slice(&magic_octets); // src = magic DNS IP
    pkt.extend_from_slice(&src_buf); // dst = original client overlay IP
    pkt.extend_from_slice(&udp_seg);

    Some(pkt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    const MAGIC: Ipv6Addr = Ipv6Addr::new(0xfd00, 0xa11a, 0, 0, 0, 0, 0, 0x53);
    const CLIENT: Ipv6Addr = Ipv6Addr::new(0xfd00, 0xa11a, 0x2a2a, 1, 0, 0, 0, 1);

    fn make_dns_query(name: &str, qtype: u16) -> Vec<u8> {
        let mut q = vec![0x12u8, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        for label in name.split('.') {
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
        q.push(0); // null terminator
        q.extend_from_slice(&qtype.to_be_bytes());
        q.extend_from_slice(&[0x00, 0x01]); // QCLASS IN
        q
    }

    fn make_ipv6_udp_pkt(src: Ipv6Addr, dst: Ipv6Addr, sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
        let udp_len = 8u16 + payload.len() as u16;
        let mut pkt = Vec::new();
        pkt.push(0x60); pkt.extend_from_slice(&[0, 0, 0]);
        pkt.extend_from_slice(&udp_len.to_be_bytes());
        pkt.push(17); pkt.push(64);
        pkt.extend_from_slice(&src.octets());
        pkt.extend_from_slice(&dst.octets());
        pkt.extend_from_slice(&sport.to_be_bytes());
        pkt.extend_from_slice(&dport.to_be_bytes());
        pkt.extend_from_slice(&udp_len.to_be_bytes());
        pkt.extend_from_slice(&[0, 0]); // checksum (ignored in test)
        pkt.extend_from_slice(payload);
        pkt
    }

    #[test]
    fn intercepts_aaaa_query_for_ankayma_fqdn() {
        let overlay: IpAddr = "fd00:a11a:2a2a:1::1".parse().unwrap();
        let table = HashMap::from([("demo.personal-123.int.ankayma.com".to_string(), overlay)]);
        let dns_q = make_dns_query("demo.personal-123.int.ankayma.com", QTYPE_AAAA);
        let pkt = make_ipv6_udp_pkt(CLIENT, MAGIC, 12345, 53, &dns_q);

        let resp = try_intercept(MAGIC, &table, &pkt).expect("should intercept");
        // Response is a valid IPv6 packet
        assert_eq!(resp[0] >> 4, 6, "IPv6");
        assert_eq!(resp[6], 17, "UDP");
        // DNS response payload (offset 48) should have RCODE OK, ANCOUNT=1
        let dns = &resp[48..];
        assert_eq!(dns[3] & 0x0F, RCODE_OK);
        assert_eq!(u16::from_be_bytes([dns[6], dns[7]]), 1);
    }

    #[test]
    fn nxdomain_for_unknown_ankayma_fqdn() {
        let table: HashMap<String, IpAddr> = HashMap::new();
        let dns_q = make_dns_query("gone.personal-123.int.ankayma.com", QTYPE_AAAA);
        let pkt = make_ipv6_udp_pkt(CLIENT, MAGIC, 12345, 53, &dns_q);
        let resp = try_intercept(MAGIC, &table, &pkt).expect("should intercept");
        let dns = &resp[48..];
        assert_eq!(dns[3] & 0x0F, RCODE_NXDOMAIN);
        assert_eq!(u16::from_be_bytes([dns[6], dns[7]]), 0);
    }

    #[test]
    fn servfail_for_non_ankayma_domain() {
        let table: HashMap<String, IpAddr> = HashMap::new();
        let dns_q = make_dns_query("google.com", QTYPE_AAAA);
        let pkt = make_ipv6_udp_pkt(CLIENT, MAGIC, 12345, 53, &dns_q);
        let resp = try_intercept(MAGIC, &table, &pkt).expect("should intercept");
        let dns = &resp[48..];
        assert_eq!(dns[3] & 0x0F, RCODE_SERVFAIL);
    }

    #[test]
    fn ignores_packets_to_other_ips() {
        let table: HashMap<String, IpAddr> = HashMap::new();
        let other_ip = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
        let dns_q = make_dns_query("google.com", QTYPE_AAAA);
        let pkt = make_ipv6_udp_pkt(CLIENT, other_ip, 12345, 53, &dns_q);
        assert!(try_intercept(MAGIC, &table, &pkt).is_none());
    }
}
