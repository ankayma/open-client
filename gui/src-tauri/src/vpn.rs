//! VPN bridge — frontend connect/disconnect/status for iOS. The JS layer invokes
//! these commands; on iOS they call into the Swift `TunnelManager` over a C ABI
//! (gui/src-tauri/ios/AppSupport/VpnBridge.swift), which installs the Packet Tunnel
//! and starts the extension. On desktop the privileged `agent` daemon owns the
//! tunnel, so these are not used. [T:A.1.9]

use serde::Serialize;
use tauri::State;

use crate::AppState;

#[cfg(target_os = "ios")]
mod ffi {
    use std::os::raw::c_char;
    // Resolved at app link time against the @_cdecl functions in VpnBridge.swift
    // (same app binary). [T:A.1.9]
    extern "C" {
        pub fn ankayma_vpn_connect(config_json: *const c_char) -> i32;
        pub fn ankayma_vpn_disconnect();
        pub fn ankayma_vpn_status() -> i32;
        pub fn ankayma_vpn_prime();
        // Open an external URL in Safari (OpenUrlBridge.swift). 0 = dispatched,
        // -1 = unparseable URL. [T:A.1.9]
        pub fn ankayma_open_url(url: *const c_char) -> i32;
    }
}

/// Open an external URL in the system browser via the Swift `UIApplication.open`
/// C-ABI bridge (iOS). The `open` crate used on desktop no-ops here. Used for the
/// GitHub OAuth start + branded-name links. [T:A.1.9]
#[cfg(target_os = "ios")]
pub fn open_external_url(url: &str) -> Result<(), String> {
    let c = std::ffi::CString::new(url).map_err(|e| e.to_string())?;
    // SAFETY: `c` is a valid NUL-terminated C string, read only for this call.
    let rc = unsafe { ffi::ankayma_open_url(c.as_ptr()) };
    if rc == 0 {
        Ok(())
    } else {
        Err(format!("could not open url (code {rc})"))
    }
}

/// Android: open a URL via an ACTION_VIEW intent (the `open` crate no-ops here too).
#[cfg(target_os = "android")]
pub fn open_external_url(url: &str) -> Result<(), String> {
    crate::vpn_android::open_url(url)
}

/// NEVPNStatus rawValue → a stable string for the UI.
#[cfg(target_os = "ios")]
fn status_string(code: i32) -> &'static str {
    match code {
        1 => "disconnected",
        2 => "connecting",
        3 => "connected",
        4 => "reasserting",
        5 => "disconnecting",
        _ => "invalid",
    }
}

#[derive(Serialize)]
pub struct VpnStatus {
    pub status: String,
    /// Peers in the roster handed to the tunnel (0 when disconnected). Real count,
    /// not the old hard-coded 0 the iOS UI used to show.
    pub peer_count: usize,
}

/// Build the resolved tunnel config JSON for the extension from the enrolled node,
/// plus (best-effort) the tenant's F-3 resolve table so the extension can answer
/// private names itself — iOS has no OS-level split-DNS hook, unlike the macOS/
/// Linux daemon's `/etc/resolver/<zone>`. Shape matches `agent-ios-ptp`'s `Config`
/// (private key + overlay + peers + zone + resolve). [T:A.1.1, f3-privdomain-ios-plan.md Phase 1]
///
/// The resolve table is fetched fresh on every `connect` (not cached) — the
/// documented model is "reconnect to see new devices/services", matching how a
/// user must toggle the tunnel to pick up config changes. A fetch failure (e.g.
/// offline enrollment check) just omits `zone`/`resolve`; it never blocks connect.
#[cfg(any(target_os = "ios", target_os = "android"))]
async fn build_config(state: &AppState) -> Result<String, String> {
    let (private_b64, overlay_ip, node_id, enroll_peers) = {
        let guard = state.node.lock().expect("node lock poisoned");
        let node = guard.as_ref().ok_or("not enrolled yet")?;
        (
            node.private_b64.clone(),
            node.overlay_ip.clone(),
            node.node_id.clone(),
            node.peers.clone(),
        )
    };
    // The enroll response's peer list is a point-in-time snapshot and, for a
    // freshly enrolled node, is often empty — which stranded the iOS tunnel with
    // "0 peers" and no route to anything (2026-07-03). The desktop daemon avoids
    // this by re-fetching the full roster on `agent up` + every SSE cycle; the
    // Packet Tunnel has no such loop, so fetch the current roster HERE and hand
    // the complete peer set to the extension. Self is dropped (it's the tun
    // address, not a dialable peer). Falls back to the enroll snapshot on error.
    let peers: Vec<agent_core::domain::PeerInfo> = match state.token() {
        Some(tok) => {
            match agent_core::adapters::peers(&state.http, &state.regional_base_url(), &tok).await {
                Ok(list) => list
                    .into_iter()
                    .filter(|p| p.overlay_ip != overlay_ip)
                    .collect(),
                Err(_) => enroll_peers,
            }
        }
        None => enroll_peers,
    };
    // Reflect the ACTUAL roster handed to the tunnel back into app state so the UI
    // shows the real peer count instead of the empty enroll snapshot (the iOS
    // status path had no other source and hard-coded "0 peers").
    if let Some(n) = state.node.lock().expect("node lock poisoned").as_mut() {
        n.peers = peers.clone();
    }
    let (zone, resolve): (Option<String>, Vec<serde_json::Value>) = match state.token() {
        Some(tok) => {
            match agent_core::adapters::resolve_subdomains(
                &state.http,
                &state.regional_base_url(),
                &tok,
            )
            .await
            {
                Ok(t) => {
                    let names = t
                        .names
                        .iter()
                        .map(|n| serde_json::json!({"fqdn": n.fqdn, "overlay_ip": n.overlay_ip}))
                        .collect();
                    (Some(t.zone), names)
                }
                Err(_) => (None, Vec::new()), // private-default: no table = no private names
            }
        }
        None => (None, Vec::new()),
    };
    // Where the extension should write the data-plane status snapshot: iOS hands it the App
    // Group container path (so this app — a separate process — can read it for the F-5
    // path-proof panel); other platforms don't run this Packet Tunnel extension. [T:F-5]
    let status_path: Option<String> = {
        #[cfg(target_os = "ios")]
        {
            Some(crate::status_snapshot_path().to_string_lossy().to_string())
        }
        #[cfg(not(target_os = "ios"))]
        {
            None
        }
    };
    let cfg = serde_json::json!({
        "private_key_b64": private_b64,
        "overlay_ip": overlay_ip,
        "node_id": node_id,
        "status_path": status_path,
        "listen_port": 51820u16,
        "peers": peers,
        "zone": zone,
        "dns_ip": magic_dns_ip(&overlay_ip),
        // Upstreams for the pump's forwarding resolver (matchDomains=[""] routes ALL
        // DNS to us; non-private names must be delegated or every site breaks). The
        // relay races ALL entries per query, first answer wins — one dead/blocked
        // public resolver must not take the forward path down (Tailscale races its
        // upstreams the same way [T:tailscale forwarder.go]). v1 uses public
        // resolvers for stability; reading the device's OWN resolvers via res_ninit
        // is the documented refinement (docs/f3-ios-dns-forwarding-resolver.md).
        // TODO[A]: res_ninit upstream.
        "upstream_dns": ["1.1.1.1", "8.8.8.8"],
        "resolve": resolve,
    });
    serde_json::to_string(&cfg).map_err(|e| e.to_string())
}

/// The tunnel-local DNS server address for iOS. Deliberately **IPv4**: iOS does NOT
/// reliably route DNS to an IPv6 server inside a Packet Tunnel (Apple-forums "IPv6
/// DNS Queries Not Resolving"), and matchDomains only works when the server is
/// reachable — an IPv4 server in the tunnel's IPv4 included routes is the pattern
/// that actually works. Safari still gets AAAA (the peer's IPv6 overlay) back and
/// connects over IPv6, so the overlay stays IPv6-only.
///
/// `100.100.100.53`, NOT Tailscale's `100.100.100.100`: a phone commonly has 2-3
/// VPNs installed, and reusing another vendor's magic-DNS address is a needless
/// collision. Still in `100.64.0.0/10` (RFC 6598 CGNAT — never routed on the public
/// internet, so it can't shadow a real site), just a distinct host.
/// `[T:RFC-6598; Apple-forums NEDNSSettings; avoid Tailscale 100.100.100.100]`
#[cfg(target_os = "ios")]
const MAGIC_DNS_IP: &str = "100.100.100.53";
// Android — unlike iOS — reliably routes DNS to an IPv6 server inside the TUN, so it
// self-addresses the responder on the IPv6 overlay magic-DNS the VpnService adds as
// its DNS server + /128 route. [T:F-3 android — verified Chrome loads PrivDomain]
#[cfg(target_os = "android")]
const MAGIC_DNS_IP: &str = "fd00:a11a::53";

#[cfg(any(target_os = "ios", target_os = "android"))]
fn magic_dns_ip(_overlay_ip: &str) -> Option<String> {
    Some(MAGIC_DNS_IP.to_string())
}

/// Enroll on the control plane (reusing the shared connect flow), build the resolved
/// config, and start the iOS Packet Tunnel.
#[tauri::command]
pub async fn vpn_connect(state: State<'_, AppState>) -> Result<(), String> {
    #[cfg(target_os = "ios")]
    {
        crate::connect_inner(&state).await?;
        let config = build_config(&state).await?;
        let c = std::ffi::CString::new(config).map_err(|e| e.to_string())?;
        // SAFETY: `c` is a valid NUL-terminated C string, read only for this call.
        let rc = unsafe { ffi::ankayma_vpn_connect(c.as_ptr()) };
        if rc != 0 {
            return Err(format!("vpn connect rejected (code {rc})"));
        }
        Ok(())
    }
    #[cfg(target_os = "android")]
    {
        // Same flow as iOS: enroll on the control plane, build the resolved config,
        // then hand it to AnkaymaVpnService (which owns the TUN fd + runs the pump).
        crate::connect_inner(&state).await?;
        let config = build_config(&state).await?;
        crate::vpn_android::start_service(&config)?;
        Ok(())
    }
    #[cfg(not(any(target_os = "ios", target_os = "android")))]
    {
        let _ = &state;
        Err("vpn_connect is mobile-only; desktop uses the agent daemon".into())
    }
}

/// Stop the iOS tunnel.
#[tauri::command]
pub fn vpn_disconnect() -> Result<(), String> {
    #[cfg(target_os = "ios")]
    {
        // SAFETY: no arguments; the Swift side is a fire-and-forget stop.
        unsafe { ffi::ankayma_vpn_disconnect() };
        Ok(())
    }
    #[cfg(target_os = "android")]
    {
        crate::vpn_android::stop_service()
    }
    #[cfg(not(any(target_os = "ios", target_os = "android")))]
    {
        Err("vpn_disconnect is mobile-only".into())
    }
}

/// Current tunnel status for the UI, including the real peer count from the
/// roster last handed to the tunnel (`build_config` writes it into app state).
#[tauri::command]
pub fn vpn_status(state: State<'_, AppState>) -> VpnStatus {
    let peer_count = state
        .node
        .lock()
        .expect("node lock poisoned")
        .as_ref()
        .map(|n| n.peers.len())
        .unwrap_or(0);
    #[cfg(target_os = "ios")]
    {
        // SAFETY: returns a cached integer; no pointers involved.
        let code = unsafe { ffi::ankayma_vpn_status() };
        VpnStatus {
            status: status_string(code).to_string(),
            peer_count,
        }
    }
    #[cfg(target_os = "android")]
    {
        let status = if crate::vpn_android::VPN_RUNNING.load(std::sync::atomic::Ordering::Relaxed) {
            "connected"
        } else {
            "disconnected"
        };
        VpnStatus {
            status: status.to_string(),
            peer_count,
        }
    }
    #[cfg(not(any(target_os = "ios", target_os = "android")))]
    {
        VpnStatus {
            status: "unsupported".to_string(),
            peer_count,
        }
    }
}

/// Start tracking the installed tunnel's status — call once on app launch (iOS).
#[cfg(target_os = "ios")]
pub fn prime() {
    // SAFETY: no arguments.
    unsafe { ffi::ankayma_vpn_prime() };
}
