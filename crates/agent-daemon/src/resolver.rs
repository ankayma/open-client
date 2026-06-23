//! resolver — agent-local private DNS for F-3 branded names (Part C §H.3.6.1).
//! OPEN, intensity Standard. macOS-first (matches the data plane); iOS/Android need
//! NEDNSProxyProvider / VpnService plumbing — `[A]`, deferred like WireGuard-mobile.
//!
//! While the overlay is up, this answers `<label>.<tenant>.<zone>` → the target
//! node's overlay address, from the control plane's mesh-resolve table — so a
//! browser on THIS enrolled device just works on the private name, and the traffic
//! goes direct over the overlay (vendor off the data path, A.1.1). A name not in the
//! table is NXDOMAIN: the private-default + instant-revoke properties come straight
//! from what the control plane is willing to put in the table for this device.
//!
//! Split-DNS, not a global hijack: on macOS a scoped `/etc/resolver/<zone>` file
//! points ONLY the branded zone at us; every other name keeps the system resolver.
//! A minimal hand-rolled responder (A/AAAA, RFC 1035) keeps this dependency-free.

use std::collections::HashMap;
use std::net::{IpAddr, UdpSocket};
use std::sync::{Arc, Mutex};

const TTL_SECS: u32 = 30; // short — names follow enrollment/revoke, don't cache long
const QTYPE_A: u16 = 1;
const QTYPE_AAAA: u16 = 28;
const RCODE_OK: u8 = 0;
const RCODE_NXDOMAIN: u8 = 3;

/// Loopback port the responder listens on (a high port → no privilege needed for
/// the socket itself; the `/etc/resolver` file points here). [T:macOS scoped DNS]
pub const RESOLVER_PORT: u16 = 5354;

/// The live name→overlay-address map, swapped wholesale each refresh cycle.
#[derive(Clone, Default)]
pub struct Resolver {
    table: Arc<Mutex<HashMap<String, IpAddr>>>,
}

impl Resolver {
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the table with the control plane's current view. Names are stored
    /// lowercased, without a trailing dot, to match parsed queries.
    pub fn set(&self, names: impl IntoIterator<Item = (String, IpAddr)>) {
        let map = names
            .into_iter()
            .map(|(n, ip)| (n.trim_end_matches('.').to_ascii_lowercase(), ip))
            .collect();
        *self.table.lock().expect("resolver table poisoned") = map;
    }

    fn snapshot(&self) -> HashMap<String, IpAddr> {
        self.table.lock().expect("resolver table poisoned").clone()
    }
}

/// Walk a QNAME starting at `off`; return (name, offset just past the null label).
/// Rejects compression pointers — queries don't use them, and refusing keeps the
/// parser from following an attacker-crafted loop. `None` on malformed input.
fn parse_qname(buf: &[u8], mut off: usize) -> Option<(String, usize)> {
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

/// Build a response to a single-question A/AAAA query. Returns `None` if the packet
/// is not a query we answer (not 1 question, malformed, or not A/AAAA). Pure.
fn respond(table: &HashMap<String, IpAddr>, query: &[u8]) -> Option<Vec<u8>> {
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
    if qtype != QTYPE_A && qtype != QTYPE_AAAA {
        return None; // leave other types to the system resolver
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

/// Bind the loopback responder and serve forever on a background thread. Errors
/// binding are non-fatal (logged) — the overlay still works, just without name
/// resolution. Returns once the socket is bound (or failed).
pub fn serve(resolver: Resolver) {
    std::thread::spawn(move || {
        let sock = match UdpSocket::bind(("127.0.0.1", RESOLVER_PORT)) {
            Ok(s) => s,
            Err(e) => {
                eprintln!(
                    "resolver: bind 127.0.0.1:{RESOLVER_PORT} failed: {e} (names won't resolve)"
                );
                return;
            }
        };
        let mut buf = [0u8; 1500];
        loop {
            let (n, from) = match sock.recv_from(&mut buf) {
                Ok(x) => x,
                Err(_) => continue,
            };
            if let Some(reply) = respond(&resolver.snapshot(), &buf[..n]) {
                let _ = sock.send_to(&reply, from);
            }
        }
    });
}

/// macOS scoped DNS: route ONLY `<zone>` to our loopback responder, leaving the
/// system resolver for everything else. Requires root (the daemon already is, for
/// utun). No-op off macOS — desktop is macOS-first at this milestone. `[T:macOS resolver(5)]`
#[cfg(target_os = "macos")]
pub fn install_scoped_resolver(zone: &str) {
    let dir = std::path::Path::new("/etc/resolver");
    if let Err(e) = std::fs::create_dir_all(dir) {
        eprintln!("resolver: mkdir /etc/resolver failed: {e}");
        return;
    }
    let body = format!(
        "# ankayma F-3 private DNS (auto-managed)\nnameserver 127.0.0.1\nport {RESOLVER_PORT}\n"
    );
    if let Err(e) = std::fs::write(dir.join(zone), body) {
        eprintln!("resolver: write /etc/resolver/{zone} failed: {e}");
    }
}

#[cfg(target_os = "macos")]
pub fn remove_scoped_resolver(zone: &str) {
    let _ = std::fs::remove_file(format!("/etc/resolver/{zone}"));
}

#[cfg(not(target_os = "macos"))]
pub fn install_scoped_resolver(_zone: &str) {}
#[cfg(not(target_os = "macos"))]
pub fn remove_scoped_resolver(_zone: &str) {}

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
        assert_eq!(off, 17); // 12 + (1+1)+(1+1)+1 null
                             // a compression pointer in the qname is refused.
        let bad = [0xC0u8, 0x0C];
        assert!(parse_qname(&bad, 0).is_none());
    }

    #[test]
    fn answers_a_record_when_present() {
        let ip = IpAddr::V4(Ipv4Addr::new(100, 64, 0, 7));
        let r = respond(&table(ip), &query(QTYPE_A)).unwrap();
        // QR=1, AA=1, RD kept; RCODE 0; ANCOUNT 1.
        assert_eq!(r[2] & 0x80, 0x80, "QR set");
        assert_eq!(r[2] & 0x04, 0x04, "AA set");
        assert_eq!(r[3] & 0x0F, RCODE_OK);
        assert_eq!(u16::from_be_bytes([r[6], r[7]]), 1, "one answer");
        // Answer RDATA = the IPv4 octets at the tail.
        assert_eq!(&r[r.len() - 4..], &[100, 64, 0, 7]);
        // Answer NAME is a pointer back to the question.
        assert_eq!(&r[qend(&r)..qend(&r) + 2], &[0xC0, 0x0C]);
    }

    #[test]
    fn answers_aaaa_record() {
        let ip = IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2));
        let r = respond(&table(ip), &query(QTYPE_AAAA)).unwrap();
        assert_eq!(u16::from_be_bytes([r[6], r[7]]), 1);
        assert_eq!(
            &r[r.len() - 16..],
            &Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2).octets()
        );
    }

    #[test]
    fn nxdomain_for_unknown_name() {
        let empty = HashMap::new();
        let r = respond(&empty, &query(QTYPE_A)).unwrap();
        assert_eq!(r[3] & 0x0F, RCODE_NXDOMAIN, "unknown name = NXDOMAIN");
        assert_eq!(u16::from_be_bytes([r[6], r[7]]), 0, "no answers");
    }

    #[test]
    fn nodata_when_family_mismatches() {
        // name exists as IPv6, but an A query → NODATA (RCODE 0, 0 answers), not NXDOMAIN.
        let ip = IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2));
        let r = respond(&table(ip), &query(QTYPE_A)).unwrap();
        assert_eq!(r[3] & 0x0F, RCODE_OK);
        assert_eq!(u16::from_be_bytes([r[6], r[7]]), 0);
    }

    #[test]
    fn ignores_non_address_types_and_malformed() {
        assert!(respond(&table(IpAddr::V4(Ipv4Addr::LOCALHOST)), &query(15 /* MX */)).is_none());
        assert!(respond(&HashMap::new(), &[0u8; 4]).is_none());
    }

    // End of the (echoed) question section in a response = where the answer begins.
    fn qend(resp: &[u8]) -> usize {
        let (_n, after) = parse_qname(resp, 12).unwrap();
        after + 4
    }
}
