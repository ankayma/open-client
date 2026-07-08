//! Windows Wintun data-plane pump — parallel to `pump` (fd-based, Unix-only).
//!
//! `pump.rs` uses `read_packet(fd, …)` / `write_packet(fd, …)` over a Unix fd.
//! Wintun on Windows doesn't expose an fd: it uses a ring-buffer session with a
//! kernel-provided HANDLE as the read-wake event. This module provides the same
//! three threads (`spawn_tx`, `spawn_rx`, `spawn_timers` is shared from `pump`)
//! but reads/writes through the `wintun::Session` API instead. `[T:A.1.9]`
//!
//! Lives in `agent-core` so it can access `pub(crate)` items from `pump.rs`
//! (cross-crate `pub(crate)` does not work). Gated `#[cfg(target_os = "windows")]`
//! so it is not compiled or linked on macOS/Linux/iOS. `[T:A.1.9]`

#![cfg(target_os = "windows")]

use std::net::UdpSocket;
use std::sync::Arc;

use crate::dataplane;
use crate::pump::{Peers, MTU};
use crate::tunnel::TunnResult;

/// tun → encapsulate → UDP. Reads bare IP packets from Wintun ring buffer.
pub fn spawn_tx(session: Arc<wintun::Session>, udp: Arc<UdpSocket>, peers: Peers) {
    std::thread::spawn(move || {
        let mut enc = vec![0u8; MTU + 80];
        loop {
            // Block until the kernel ring buffer has a packet ready. Returns
            // Err only on session teardown. `[T:wintun-crate receive_blocking]`
            let pkt_handle = match session.receive_blocking() {
                Ok(p) => p,
                Err(_) => break,
            };
            let pkt = pkt_handle.bytes();
            if pkt.is_empty() {
                continue;
            }
            let Some(dst) = dataplane::packet_dst(pkt) else {
                continue;
            };
            let Some(entry) = crate::pump::peer_by_overlay(&peers, dst) else {
                continue;
            };
            let mut tunn = entry.tunn.lock().expect("tunn lock");
            match tunn.encapsulate(pkt, &mut enc) {
                TunnResult::WriteToNetwork(out) => {
                    if let Some(ep) = entry.endpoint() {
                        let _ = udp.send_to(out, ep);
                    }
                }
                TunnResult::Err(e) => eprintln!("wintun encapsulate error: {e:?}"),
                _ => {}
            }
            // pkt_handle is released here (ring-buffer slot freed) [T:wintun-crate]
        }
    });
}

/// UDP → decapsulate → tun. Writes bare IP packets into the Wintun send ring.
pub fn spawn_rx(session: Arc<wintun::Session>, udp: Arc<UdpSocket>, peers: Peers) {
    std::thread::spawn(move || {
        let mut datagram = [0u8; 2048];
        let mut out = [0u8; 2048];
        loop {
            let (n, src) = match udp.recv_from(&mut datagram) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("wintun udp recv error: {e}");
                    break;
                }
            };
            let candidates: Vec<_> = match crate::pump::peer_by_source(&peers, src) {
                Some(e) => vec![e],
                None => peers.lock().expect("peers lock").iter().cloned().collect(),
            };
            'outer: for entry in candidates {
                let mut tunn = entry.tunn.lock().expect("tunn lock");
                let mut res = tunn.decapsulate(Some(src.ip()), &datagram[..n], &mut out);
                if matches!(res, TunnResult::Err(_)) {
                    continue;
                }
                entry.set_endpoint(src);
                loop {
                    match res {
                        TunnResult::WriteToNetwork(pkt) => {
                            let _ = udp.send_to(pkt, src);
                            res = tunn.decapsulate(None, &[], &mut out);
                        }
                        TunnResult::WriteToTunnelV4(pkt, _) | TunnResult::WriteToTunnelV6(pkt, _) => {
                            write_to_wintun(&session, pkt);
                            break 'outer;
                        }
                        _ => break 'outer,
                    }
                }
            }
        }
    });
}

/// Write `pkt` into the Wintun send ring.
/// `allocate_send_packet` requires `&Arc<Session>` (wintun 0.5.1 API).
/// Drop silently on ring-full. [A verified-on-windows]
fn write_to_wintun(session: &Arc<wintun::Session>, pkt: &[u8]) {
    let len = match u16::try_from(pkt.len()) {
        Ok(n) => n,
        Err(_) => return,
    };
    if let Ok(mut wp) = session.allocate_send_packet(len) {
        wp.bytes_mut().copy_from_slice(pkt);
        session.send_packet(wp);
    }
}
