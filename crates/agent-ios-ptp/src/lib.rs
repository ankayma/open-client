//! agent-ios-ptp — C ABI over the agent-core packet pump, for the iOS Packet
//! Tunnel Provider (Network Extension). OPEN, intensity **Critical** (FFI boundary).
//!
//! The Swift `NEPacketTunnelProvider` owns the OS-specific parts iOS reserves to
//! the extension: it sets `NEPacketTunnelNetworkSettings` (overlay IP + routes) and
//! hands us the tun **fd** (`packetFlow`'s `tunnelFileDescriptor`). This crate is
//! the thin bridge: parse a resolved config (keys + peers, prepared by the main app
//! and passed through the App Group), bind the UDP socket, and run the shared pump
//! (`agent_core::pump`) over that fd. No control-plane HTTP here — the extension's
//! memory budget is tight, so enroll/peer-refresh stay in the main app. `[T:A.1.9]`
//!
//! ABI (see `include/agent_ios_ptp.h`):
//!   `PtpHandle *ankayma_ptp_start(int32_t fd, const char *config_json);`
//!   `void       ankayma_ptp_stop(PtpHandle *handle);`

use std::collections::HashMap;
use std::ffi::{c_char, CStr, CString};
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex};

use agent_core::domain::PeerInfo;
use agent_core::pump::{self, DnsResponder};
use agent_core::tunnel::StaticSecret;
use serde::Deserialize;

// Provided by the extension (Swift `@_cdecl`):
//  - `ankayma_ptp_log`: forward a pump diagnostic line to NSLog (no stdout in NE).
extern "C" {
    fn ankayma_ptp_log(msg: *const c_char);
}

/// Bridge one pump diagnostic line to the iOS log. `fn(&str)` so it fits
/// `pump::set_log_hook`. Silently drops a line with an interior NUL (never happens
/// for our format strings).
fn ios_pump_log(msg: &str) {
    if let Ok(c) = CString::new(msg) {
        // SAFETY: `c` is a valid NUL-terminated C string, read-only for this call.
        unsafe { ankayma_ptp_log(c.as_ptr()) };
    }
}

// DNS forward targets (`upstream_dns[..]:53`) + the physical interface index for the
// pinned fallback, captured once at start. A DNS query that isn't a private mesh
// name is relayed here so `matchDomains=[""]` (all DNS routed to us) doesn't break
// public resolution.
static DNS_UPSTREAMS: std::sync::OnceLock<Vec<SocketAddr>> = std::sync::OnceLock::new();
static DNS_BOUND_IF: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

/// How long the relay waits for the first upstream answer before giving up and
/// SERVFAIL'ing. Tailscale races UDP for 2s before adding TCP, with a 5s TCP
/// budget `[T:tailscale forwarder.go udpRaceTimeout=2s/tcpQueryTimeout=5s]`; we
/// have no TCP fallback, so sit between the two — long enough for a slow
/// resolver, short enough that the client's own retry (~1s cadence) still finds
/// us answering. `[A]` verify on device: tune if SERVFAILs show up in normal use.
const FORWARD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

/// Pump forward sink (fits `pump::set_dns_forward_hook`): relay a non-private DNS
/// query to the device's upstream resolvers and hand the answer back to the pump.
/// EVERY exit path answers — success → `pump::dns_reply`, any failure/timeout →
/// `pump::dns_fail` (SERVFAIL). Silence is never an option: iOS gives up on a
/// tunnel resolver that doesn't answer and won't use it again until reconnect
/// `[T:Apple-DevForums-114097]`.
///
/// A plain BSD UDP socket egresses the real network from inside a Packet Tunnel
/// Provider — exactly how our WG data socket reaches peers, and how Tailscale
/// forwards on darwin `[T:Tailscale net/netns/netns_darwin.go — IP_BOUND_IF]`.
/// Runs on a short-lived thread so the pump's tx loop never blocks.
fn ios_dns_forward(token: u64, query: &[u8]) {
    let upstreams: &[SocketAddr] = DNS_UPSTREAMS.get().map(Vec::as_slice).unwrap_or(&[]);
    if upstreams.is_empty() {
        ios_pump_log("dns-fwd: no upstream configured — SERVFAIL");
        pump::dns_fail(token);
        return;
    }
    let upstreams = upstreams.to_vec();
    let bound_if = DNS_BOUND_IF.load(std::sync::atomic::Ordering::Relaxed);
    let query = query.to_vec();
    std::thread::spawn(move || {
        if !forward_once(token, &query, &upstreams, bound_if) {
            pump::dns_fail(token); // SERVFAIL — never silence
        }
    });
}

/// One forward round-trip: fan the query out to ALL upstreams from one socket
/// (first valid answer wins — Tailscale races its resolvers the same way
/// `[T:tailscale forwarder.go forwardWithDestChan — one goroutine per resolver,
/// first success wins]`), then wait up to `FORWARD_TIMEOUT` for a reply whose
/// source and transaction id match. Returns true iff a reply was delivered.
fn forward_once(token: u64, query: &[u8], upstreams: &[SocketAddr], bound_if: u32) -> bool {
    // The tunnel installs NO default IPv4 route (only the overlay + the DNS-carrier
    // /24), so a socket to a public resolver egresses via the OS's physical default
    // route WITHOUT pinning. Pinning to a heuristically-picked interface
    // (`physicalInterfaceIndex`) can pick one with no route to the upstream ⟹
    // ENETUNREACH (observed on-device 2026-07-03: if#20 reached WG peers but not
    // 1.1.1.1). Tailscale binds to the *default-route* interface via an AF_ROUTE
    // lookup and, when that lookup fails, sends UNBOUND rather than guessing
    // `[T:Tailscale netns_darwin.go — on getInterfaceIndex error "return nil",
    // dial proceeds unbound]`. So: unpinned first, pinned as the fallback.
    let send = |pin: bool| -> std::io::Result<UdpSocket> {
        let sock = UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], 0)))?;
        if pin {
            bind_socket_to_interface(&sock, bound_if);
        }
        sock.set_read_timeout(Some(FORWARD_TIMEOUT))?;
        let mut sent = 0usize;
        for up in upstreams {
            match sock.send_to(query, up) {
                Ok(_) => sent += 1,
                Err(e) => ios_pump_log(&format!("dns-fwd: send token={token} → {up} failed: {e}")),
            }
        }
        if sent == 0 {
            return Err(std::io::Error::other("no upstream reachable"));
        }
        Ok(sock)
    };
    let sock = match send(false) {
        Ok(s) => s,
        Err(e) => {
            ios_pump_log(&format!(
                "dns-fwd: token={token} unpinned send FAILED ({e}) — retrying pinned if#{bound_if}"
            ));
            match send(true) {
                Ok(s) => s,
                Err(e2) => {
                    ios_pump_log(&format!(
                        "dns-fwd: token={token} pinned send FAILED too: {e2}"
                    ));
                    return false;
                }
            }
        }
    };
    let deadline = std::time::Instant::now() + FORWARD_TIMEOUT;
    let mut buf = [0u8; 1500];
    loop {
        match sock.recv_from(&mut buf) {
            Ok((n, from)) => {
                // Accept only a reply from a queried upstream whose transaction id
                // matches the query (basic off-path-spoof + cross-talk hygiene;
                // the OS random source port does the heavy lifting). `[T:RFC-5452§4]`
                let id_ok = n >= 2 && query.len() >= 2 && buf[..2] == query[..2];
                if id_ok && upstreams.contains(&from) {
                    ios_pump_log(&format!("dns-fwd: reply token={token} {n}B ← {from}"));
                    pump::dns_reply(token, &buf[..n]);
                    return true;
                }
                ios_pump_log(&format!(
                    "dns-fwd: token={token} ignored {n}B from {from} (id/source mismatch)"
                ));
            }
            Err(e) => {
                ios_pump_log(&format!("dns-fwd: recv token={token} FAILED: {e}"));
                return false;
            }
        }
        if std::time::Instant::now() >= deadline {
            ios_pump_log(&format!("dns-fwd: token={token} timeout"));
            return false;
        }
    }
}

// (dns_egress_selftest removed 2026-07-04 — the diagnostic served its purpose: the
// forward path is validated end-to-end on device; see
// docs/f3-ios-dns-forwarding-resolver.md "on-device validation".)

/// One private branded name the main app already resolved (`GET /api/v1/mesh/resolve`)
/// and handed in alongside the tunnel config. `[T: f3-privdomain-ios-plan.md Phase 1]`
#[derive(Deserialize)]
struct ResolveEntry {
    fqdn: String,
    overlay_ip: String,
}

/// Resolved tunnel config handed in from the app (via the App Group). Connection
/// metadata + this node's key only — no business payload. `[T:A.1.1]`
#[derive(Deserialize)]
struct Config {
    /// This node's WireGuard private key, base64 (32 bytes).
    private_key_b64: String,
    /// This node's overlay address (control-plane assigned; v4 or v6).
    overlay_ip: String,
    /// UDP port the mesh shares. `[T:wg(8)]` default 51820.
    #[serde(default = "default_port")]
    listen_port: u16,
    /// Peers to dial, already fetched by the app from the control plane.
    #[serde(default)]
    peers: Vec<PeerInfo>,
    /// F-3 private-DNS zone this device may resolve names under (e.g.
    /// `int.ankayma.com`). `None` when the resolve table couldn't be fetched
    /// (private-default: no table = no private names). Read only once at start —
    /// the "reconnect to see new devices/services" model (Phase 1).
    #[serde(default)]
    zone: Option<String>,
    /// Magic DNS address the responder answers on. iOS will NOT route a query
    /// addressed to the tunnel's own overlay IP back into the packet flow, so the
    /// app hands us a DISTINCT in-overlay address (same /64, host `::53`) that it
    /// also adds to the tunnel's included routes + sets as the DNS server. Queries
    /// then arrive here as ordinary packets. Falls back to `overlay_ip` when
    /// absent (older app). `[T: Tailscale-style magic DNS]`
    #[serde(default)]
    dns_ip: Option<String>,
    /// The device's real upstream DNS servers (read by the app via `res_ninit`
    /// BEFORE the tunnel came up). Queries for names NOT in `resolve` are forwarded
    /// to `upstream_dns[0]` so `matchDomains=[""]` doesn't break public DNS. Empty
    /// ⟹ authoritative-only (private names work, public names NXDOMAIN).
    #[serde(default)]
    upstream_dns: Vec<String>,
    /// The resolved names themselves, already fetched by the app.
    #[serde(default)]
    resolve: Vec<ResolveEntry>,
}

fn default_port() -> u16 {
    51820
}

/// Validated config, ready to drive the pump. Kept separate from socket/thread
/// setup so it is unit-testable without binding ports or spawning threads.
struct Prepared {
    static_private: StaticSecret,
    self_overlay: IpAddr,
    listen_port: u16,
    peers: Vec<PeerInfo>,
    /// `None` when the config carried no zone (nothing to answer for).
    dns: Option<DnsResponder>,
    /// Upstream resolvers for the forward relay (`upstream_dns`, parsed). All of
    /// them are raced per query — Tailscale-style — so one dead/blocked public
    /// resolver doesn't take the whole forward path down.
    upstreams: Vec<SocketAddr>,
}

/// Parse `upstream_dns` entries (bare IPs) into `ip:53` targets, dropping
/// unparseable ones. DNS is UDP/53. `[T:RFC-1035§4.2.1]`
fn parse_upstreams(entries: &[String]) -> Vec<SocketAddr> {
    entries
        .iter()
        .filter_map(|s| s.parse::<IpAddr>().ok())
        .map(|ip| SocketAddr::new(ip, 53))
        .collect()
}

/// Parse + validate the JSON config: decode the private key, parse the overlay IP.
fn prepare(config_json: &str) -> Result<Prepared, String> {
    let cfg: Config = serde_json::from_str(config_json).map_err(|e| format!("config json: {e}"))?;
    let self_overlay: IpAddr = cfg
        .overlay_ip
        .parse()
        .map_err(|_| format!("bad overlay_ip: {}", cfg.overlay_ip))?;
    let key = agent_core::key_bytes_from_b64(&cfg.private_key_b64)
        .map_err(|e| format!("private key: {e:?}"))?;
    // Where the responder listens: the magic DNS IP the app assigned (routed into
    // the tunnel), NOT self_overlay (iOS won't deliver a query to the interface's
    // own address). Fall back to self_overlay for an older app that omits it.
    let dns_addr: IpAddr = cfg
        .dns_ip
        .as_deref()
        .and_then(|s| s.parse().ok())
        .unwrap_or(self_overlay);
    // Forward non-private names (matchDomains=[""] routes ALL DNS here) to the
    // device's upstreams via the BSD-socket relay — enabled when the app supplied
    // at least one parseable upstream resolver.
    let upstreams = parse_upstreams(&cfg.upstream_dns);
    let forward = !upstreams.is_empty();
    let dns = cfg.zone.map(|_| {
        let table: HashMap<String, IpAddr> = cfg
            .resolve
            .iter()
            .filter_map(|n| n.overlay_ip.parse().ok().map(|ip| (n.fqdn.clone(), ip)))
            .collect();
        DnsResponder {
            self_ip: dns_addr,
            table: Arc::new(Mutex::new(table)),
            forward,
        }
    });
    Ok(Prepared {
        static_private: StaticSecret::from(key),
        self_overlay,
        listen_port: cfg.listen_port,
        peers: cfg.peers,
        dns,
        upstreams,
    })
}

/// Opaque handle returned to Swift. Holds the shared data-plane state alive for the
/// tunnel's lifetime (the pump threads hold their own clones).
pub struct PtpHandle {
    _udp: Arc<UdpSocket>,
    _peers: pump::Peers,
}

/// Pin the pump's UDP socket to the physical interface (`IP_BOUND_IF`/`IPV6_BOUND_IF`)
/// so its packets egress WiFi/cellular instead of being swallowed by our own tunnel.
/// Without this the extension's socket `sendto` SUCCEEDS but the packet never leaves
/// the device — the peer sees nothing, the socket receives nothing (diagnosed on
/// device 2026-07-03; the exact fix wireguard-apple uses). `bound_if == 0` skips it.
/// `[T:Darwin IP_BOUND_IF=25/IPV6_BOUND_IF=125; wireguard-apple]`
fn bind_socket_to_interface(sock: &UdpSocket, bound_if: u32) {
    if bound_if == 0 {
        ios_pump_log("bound_if=0 — socket NOT pinned to a physical interface");
        return;
    }
    use std::os::unix::io::AsRawFd;
    const IP_BOUND_IF: libc::c_int = 25;
    const IPV6_BOUND_IF: libc::c_int = 125;
    let fd = sock.as_raw_fd();
    let idx = bound_if;
    // SAFETY: setsockopt with a valid fd + a 4-byte u32 option value.
    let r4 = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            IP_BOUND_IF,
            &idx as *const u32 as *const libc::c_void,
            std::mem::size_of::<u32>() as libc::socklen_t,
        )
    };
    let r6 = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IPV6,
            IPV6_BOUND_IF,
            &idx as *const u32 as *const libc::c_void,
            std::mem::size_of::<u32>() as libc::socklen_t,
        )
    };
    ios_pump_log(&format!(
        "socket pinned to if#{idx} (IP_BOUND_IF rc={r4}, IPV6_BOUND_IF rc={r6})"
    ));
}

fn start_inner(fd: i32, config_json: &str, bound_if: u32) -> Result<Box<PtpHandle>, String> {
    // Route pump diagnostics to NSLog + non-private DNS forwards to our BSD-socket
    // relay (idempotent). The relay pins to the SAME physical interface as the WG
    // socket, so store the index before any query can arrive.
    DNS_BOUND_IF.store(bound_if, std::sync::atomic::Ordering::Relaxed);
    pump::set_log_hook(ios_pump_log);
    pump::set_dns_forward_hook(ios_dns_forward);
    let p = prepare(config_json)?;
    let _ = DNS_UPSTREAMS.set(p.upstreams.clone());
    let udp = Arc::new(
        UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], p.listen_port)))
            .map_err(|e| format!("bind udp/{}: {e}", p.listen_port))?,
    );
    // Pin to the physical interface BEFORE any send (see fn doc). `[T:wireguard-apple]`
    bind_socket_to_interface(&udp, bound_if);
    let peers: pump::Peers = Arc::new(Mutex::new(Vec::new()));
    let index = Arc::new(Mutex::new(0u32));

    // Routes are NOT added here — iOS installs them via NEPacketTunnelNetworkSettings
    // in Swift before this call. We only build the Tunns + kick handshakes.
    // PersistentKeepalive=25s unconditionally: an iPhone/iPad on WiFi or cellular is
    // behind NAT (home router / carrier CGNAT) in every practical deployment. `[A]`
    // verify: revisit if a device with a public IPv4 ever shows up in the fleet.
    pump::add_tunn_peers(
        &peers,
        &index,
        &p.static_private,
        p.self_overlay,
        &p.peers,
        &udp,
        Some(25),
    );

    let tun = agent_core::tundev::TunHandle::Fd(fd);
    // relay = None: NAT-fallback relay not activated yet (Decision D-T1) — direct-UDP
    // only, unchanged behaviour, until the control plane distributes a relay endpoint.
    pump::spawn_tx(tun.clone(), udp.clone(), peers.clone(), None, p.dns);
    pump::spawn_rx(tun, udp.clone(), peers.clone());
    pump::spawn_timers(
        udp.clone(),
        peers.clone(),
        p.static_private.clone(),
        index.clone(),
        None,
    );

    Ok(Box::new(PtpHandle {
        _udp: udp,
        _peers: peers,
    }))
}

/// Start the WireGuard packet pump over `fd` (the Packet Tunnel Provider's utun fd)
/// using a JSON config. Returns an opaque handle to pass to `ankayma_ptp_stop`, or
/// null on error (details logged to stderr / the device console).
///
/// # Safety
/// `config_json` must be a valid NUL-terminated UTF-8 C string for the duration of
/// the call. `fd` must be an open tun fd that stays valid until `ankayma_ptp_stop`.
#[no_mangle]
pub unsafe extern "C" fn ankayma_ptp_start(
    fd: i32,
    config_json: *const c_char,
    bound_if: u32,
) -> *mut PtpHandle {
    if config_json.is_null() {
        return std::ptr::null_mut();
    }
    let s = match CStr::from_ptr(config_json).to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    match start_inner(fd, s, bound_if) {
        Ok(h) => Box::into_raw(h),
        Err(e) => {
            eprintln!("ankayma_ptp_start: {e}");
            std::ptr::null_mut()
        }
    }
}

/// Stop the tunnel and free the handle. Null is a no-op.
///
/// TODO[A]: the pump threads currently stop only when the extension process is torn
/// down by iOS on `stopTunnel` (the normal Network Extension lifecycle). Thread a
/// cancellation token through `agent_core::pump` for a clean in-process stop — verify
/// under a start/stop soak on device.
///
/// # Safety
/// `handle` must be a pointer returned by `ankayma_ptp_start` and not already freed;
/// it must not be used after this call.
#[no_mangle]
pub unsafe extern "C" fn ankayma_ptp_stop(handle: *mut PtpHandle) {
    if handle.is_null() {
        return;
    }
    drop(Box::from_raw(handle));
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_core::WgKeypair;

    fn valid_key_b64() -> String {
        // A real 32-byte X25519 key, base64 — exercises `key_bytes_from_b64`.
        WgKeypair::generate().private_b64
    }

    #[test]
    fn prepare_defaults_port_and_empty_peers() {
        let json = format!(
            r#"{{"private_key_b64":"{}","overlay_ip":"10.0.0.5"}}"#,
            valid_key_b64()
        );
        let p = prepare(&json).expect("valid config");
        assert_eq!(p.listen_port, 51820); // default
        assert!(p.peers.is_empty());
        assert_eq!(p.self_overlay, "10.0.0.5".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn prepare_rejects_bad_overlay_and_bad_key() {
        let bad_overlay = format!(
            r#"{{"private_key_b64":"{}","overlay_ip":"not-an-ip"}}"#,
            valid_key_b64()
        );
        assert!(prepare(&bad_overlay).is_err());

        let bad_key = r#"{"private_key_b64":"@@notbase64@@","overlay_ip":"10.0.0.5"}"#;
        assert!(prepare(bad_key).is_err());
    }

    #[test]
    fn prepare_parses_peers_and_port() {
        let json = format!(
            r#"{{"private_key_b64":"{}","overlay_ip":"10.0.0.5","listen_port":51821,
                 "peers":[{{"node_id":"n1","public_key":"{}","overlay_ip":"10.0.0.6","hostname":"h1","endpoint":"1.2.3.4:51820"}}]}}"#,
            valid_key_b64(),
            valid_key_b64()
        );
        let p = prepare(&json).expect("valid config with a peer");
        assert_eq!(p.listen_port, 51821);
        assert_eq!(p.peers.len(), 1);
        assert_eq!(p.peers[0].overlay_ip, "10.0.0.6");
    }

    #[test]
    fn parse_upstreams_keeps_valid_ips_and_drops_garbage() {
        let ups = parse_upstreams(&[
            "1.1.1.1".to_string(),
            "not-an-ip".to_string(),
            "8.8.8.8".to_string(),
        ]);
        assert_eq!(
            ups,
            vec![
                "1.1.1.1:53".parse::<SocketAddr>().unwrap(),
                "8.8.8.8:53".parse::<SocketAddr>().unwrap(),
            ],
            "all parseable upstreams kept (raced per query), garbage dropped"
        );
        assert!(parse_upstreams(&[]).is_empty());
    }

    #[test]
    fn prepare_with_upstreams_enables_forwarding() {
        let json = format!(
            r#"{{"private_key_b64":"{}","overlay_ip":"10.0.0.5","zone":"int.ankayma.com",
                 "upstream_dns":["1.1.1.1","8.8.8.8"]}}"#,
            valid_key_b64()
        );
        let p = prepare(&json).expect("valid config");
        assert_eq!(p.upstreams.len(), 2);
        assert!(p.dns.expect("zone present").forward, "forward flag set");
    }

    #[test]
    fn prepare_without_zone_has_no_dns_responder() {
        let json = format!(
            r#"{{"private_key_b64":"{}","overlay_ip":"10.0.0.5"}}"#,
            valid_key_b64()
        );
        let p = prepare(&json).expect("valid config");
        assert!(p.dns.is_none(), "no zone in config = no DNS interception");
    }

    #[test]
    fn prepare_with_zone_builds_dns_table_from_resolve() {
        let json = format!(
            r#"{{"private_key_b64":"{}","overlay_ip":"10.0.0.5","zone":"int.ankayma.com",
                 "resolve":[{{"fqdn":"macmini.int.ankayma.com","overlay_ip":"10.0.0.9"}},
                            {{"fqdn":"bad.int.ankayma.com","overlay_ip":"not-an-ip"}}]}}"#,
            valid_key_b64()
        );
        let p = prepare(&json).expect("valid config with a zone");
        let dns = p.dns.expect("zone present = DnsResponder built");
        assert_eq!(dns.self_ip, "10.0.0.5".parse::<IpAddr>().unwrap());
        let table = dns.table.lock().unwrap();
        assert_eq!(table.len(), 1, "unparseable resolve entry dropped");
        assert_eq!(
            table.get("macmini.int.ankayma.com"),
            Some(&"10.0.0.9".parse::<IpAddr>().unwrap())
        );
    }
}
