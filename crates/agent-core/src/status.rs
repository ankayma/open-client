//! Data-plane status snapshot shared by the desktop daemon and the iOS Packet Tunnel
//! extension. The GUI reads this JSON for the F-5 path-proof panel: per-peer WireGuard
//! handshake age, byte counters, and direct-vs-relay. One format, one writer, one
//! heartbeat — so every platform surfaces the same live evidence. Metadata only — never
//! tunnel payload. [T:A.1.1]

use crate::pump::Peers;
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// One peer's live data-plane stats, as read from its boringtun `Tunn`.
#[derive(Serialize)]
pub struct StatusPeer {
    pub hostname: String,
    pub overlay_ip: String,
    pub endpoint: Option<String>,
    /// Endpoint known ⇒ direct WireGuard (no relay). Flips when a NAT relay lands
    /// (A.1.12). [T:A.1.1]
    pub direct: bool,
    /// Seconds since the last WireGuard handshake, or absent if none yet.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_handshake_secs: Option<u64>,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
}

/// The full snapshot. `updated_at` lets the GUI treat a stale file as "down".
#[derive(Serialize)]
pub struct DataplaneStatus {
    pub pid: u32,
    pub node_id: String,
    pub overlay_ip: String,
    pub listen_port: u16,
    pub updated_at: u64,
    pub peers: Vec<StatusPeer>,
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Snapshot the live peer stats into `path` (best-effort; a write error never fails the
/// data plane). Creates the parent dir if missing. [T:F-5 handshake age]
pub fn write_status(path: &Path, node_id: &str, overlay_ip: &str, listen_port: u16, peers: &Peers) {
    let list: Vec<StatusPeer> = peers
        .lock()
        .expect("peers lock")
        .iter()
        .map(|p| {
            let ep = p.endpoint();
            let (hs, tx, rx) = p.stats();
            StatusPeer {
                hostname: p.peer.hostname.clone(),
                overlay_ip: p.peer.overlay_ip.to_string(),
                endpoint: ep.map(|e| e.to_string()),
                direct: ep.is_some(),
                last_handshake_secs: hs.map(|d| d.as_secs()),
                tx_bytes: tx as u64,
                rx_bytes: rx as u64,
            }
        })
        .collect();
    let status = DataplaneStatus {
        pid: std::process::id(),
        node_id: node_id.to_string(),
        overlay_ip: overlay_ip.to_string(),
        listen_port,
        updated_at: now_secs(),
        peers: list,
    };
    if let Ok(json) = serde_json::to_vec(&status) {
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let _ = std::fs::write(path, json);
    }
}

/// Spawn a background heartbeat that rewrites the snapshot every `interval`, so the GUI's
/// path-proof stays fresh (handshake age, byte counters) between roster changes — on EVERY
/// platform. A plain std thread + sleep: no async-runtime assumption, so it runs equally
/// inside the desktop daemon (tokio) and the iOS Network Extension (no tokio). It lives for
/// the process lifetime; `peers` is an `Arc` clone, so it observes every add/remove the pump
/// makes. [T:F-5 handshake age]
pub fn spawn_status_heartbeat(
    path: PathBuf,
    node_id: String,
    overlay_ip: String,
    listen_port: u16,
    peers: Peers,
    interval: Duration,
) {
    std::thread::spawn(move || loop {
        std::thread::sleep(interval);
        write_status(&path, &node_id, &overlay_ip, listen_port, &peers);
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[test]
    fn writes_snapshot_and_creates_parent_dir() {
        let peers: Peers = Arc::new(Mutex::new(Vec::new()));
        // A nested, not-yet-existing dir proves write_status creates the parent.
        let dir =
            std::env::temp_dir().join(format!("ankayma-status-{}/nested", std::process::id()));
        let path = dir.join("agent-status.json");
        write_status(&path, "node_test", "fd00::2", 51820, &peers);

        let bytes = std::fs::read(&path).expect("status file written");
        let v: serde_json::Value = serde_json::from_slice(&bytes).expect("valid json");
        assert_eq!(v["node_id"], "node_test");
        assert_eq!(v["listen_port"], 51820);
        assert_eq!(v["overlay_ip"], "fd00::2");
        assert!(v["peers"].as_array().expect("peers array").is_empty());
        assert!(v["updated_at"].as_u64().is_some(), "updated_at stamped");

        let _ = std::fs::remove_dir_all(
            std::env::temp_dir().join(format!("ankayma-status-{}", std::process::id())),
        );
    }
}
