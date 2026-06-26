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

use std::ffi::{c_char, CStr};
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex};

use agent_core::domain::PeerInfo;
use agent_core::pump;
use agent_core::tunnel::StaticSecret;
use serde::Deserialize;

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
    Ok(Prepared {
        static_private: StaticSecret::from(key),
        self_overlay,
        listen_port: cfg.listen_port,
        peers: cfg.peers,
    })
}

/// Opaque handle returned to Swift. Holds the shared data-plane state alive for the
/// tunnel's lifetime (the pump threads hold their own clones).
pub struct PtpHandle {
    _udp: Arc<UdpSocket>,
    _peers: pump::Peers,
}

fn start_inner(fd: i32, config_json: &str) -> Result<Box<PtpHandle>, String> {
    let p = prepare(config_json)?;
    let udp = Arc::new(
        UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], p.listen_port)))
            .map_err(|e| format!("bind udp/{}: {e}", p.listen_port))?,
    );
    let peers: pump::Peers = Arc::new(Mutex::new(Vec::new()));
    let index = Arc::new(Mutex::new(0u32));

    // Routes are NOT added here — iOS installs them via NEPacketTunnelNetworkSettings
    // in Swift before this call. We only build the Tunns + kick handshakes.
    pump::add_tunn_peers(
        &peers,
        &index,
        &p.static_private,
        p.self_overlay,
        &p.peers,
        &udp,
    );

    pump::spawn_tx(fd, udp.clone(), peers.clone());
    pump::spawn_rx(fd, udp.clone(), peers.clone());
    pump::spawn_timers(udp.clone(), peers.clone());

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
pub unsafe extern "C" fn ankayma_ptp_start(fd: i32, config_json: *const c_char) -> *mut PtpHandle {
    if config_json.is_null() {
        return std::ptr::null_mut();
    }
    let s = match CStr::from_ptr(config_json).to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    match start_inner(fd, s) {
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
}
