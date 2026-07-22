//! resolver — agent-local private DNS for F-3 branded names (Part C §H.3.6.1).
//! OPEN, intensity Standard. macOS-first (matches the data plane); iOS answers on
//! the tun fd itself instead (`agent_core::pump::DnsResponder`, no OS split-DNS
//! hook available there) — see `F-3 private-DNS`.
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
//! The wire-format responder itself (`parse_qname`/`respond`) lives in
//! `agent_core::dns` — shared verbatim with the iOS tun-fd responder — this module
//! just owns the macOS-specific transport (loopback socket + `/etc/resolver`).

use std::collections::HashMap;
use std::net::{IpAddr, UdpSocket};
use std::sync::{Arc, Mutex};

use agent_core::dns::respond;

/// Loopback port the responder listens on. macOS/Linux: a high port (no privilege,
/// and `/etc/resolver` can point at a custom port). Windows: **53**, because an NRPT
/// rule can only name a nameserver IP — never a port — so the elevated daemon must
/// bind loopback:53 there for the rule to reach us. [T:macOS scoped DNS; Windows NRPT]
#[cfg(windows)]
pub const RESOLVER_PORT: u16 = 53;
#[cfg(not(windows))]
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

/// Windows scoped DNS via NRPT: point ONLY the `.<zone>` namespace at our loopback
/// responder, leaving the system resolver for every other name. NRPT carries no port,
/// so the responder binds :53 (RESOLVER_PORT on Windows). Requires admin (the daemon
/// already is, for Wintun). Delete-first for idempotency across restarts.
/// `[T:Windows NRPT / Add-DnsClientNrptRule]`
#[cfg(windows)]
pub fn install_scoped_resolver(zone: &str) {
    let ns = format!(".{zone}");
    remove_scoped_resolver(zone); // clear any stale rule for this namespace first
    let ps = format!(
        "Add-DnsClientNrptRule -Namespace '{ns}' -NameServers '127.0.0.1' -Comment 'ankayma F-3'"
    );
    if let Err(e) = run_ps(&ps) {
        eprintln!("resolver: Add-DnsClientNrptRule {ns} failed: {e} (names won't resolve)");
    }
}

#[cfg(windows)]
pub fn remove_scoped_resolver(zone: &str) {
    let ns = format!(".{zone}");
    let ps = format!(
        "Get-DnsClientNrptRule | Where-Object {{ $_.Namespace -eq '{ns}' }} | \
         Remove-DnsClientNrptRule -Force -ErrorAction SilentlyContinue"
    );
    let _ = run_ps(&ps);
}

#[cfg(windows)]
fn run_ps(script: &str) -> std::io::Result<()> {
    let status = std::process::Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(std::io::Error::other(format!("powershell exited {status}")))
    }
}

#[cfg(not(any(target_os = "macos", windows)))]
pub fn install_scoped_resolver(_zone: &str) {}
#[cfg(not(any(target_os = "macos", windows)))]
pub fn remove_scoped_resolver(_zone: &str) {}

// Wire-format tests (parse_qname/respond) live with the implementation now, in
// `agent_core::dns`. What's left here — `Resolver::set` normalization and the
// `serve()`/`/etc/resolver` transport — is macOS-daemon-specific.
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn set_lowercases_and_strips_trailing_dot() {
        let r = Resolver::new();
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        r.set([("MacMini.INT.Ankayma.COM.".to_string(), ip)]);
        let snap = r.snapshot();
        assert_eq!(snap.get("macmini.int.ankayma.com"), Some(&ip));
        assert!(!snap.contains_key("MacMini.INT.Ankayma.COM."));
    }

    #[test]
    fn set_replaces_the_whole_table() {
        let r = Resolver::new();
        let ip1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        r.set([("a.zone".to_string(), ip1)]);
        r.set([("b.zone".to_string(), ip2)]); // second call wholesale-replaces, doesn't merge
        let snap = r.snapshot();
        assert_eq!(snap.len(), 1);
        assert!(!snap.contains_key("a.zone"));
        assert_eq!(snap.get("b.zone"), Some(&ip2));
    }
}
