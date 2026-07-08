//! VPN bridge — frontend connect/disconnect/status for iOS and Android.
//! iOS: calls into the Swift TunnelManager over C ABI (VpnBridge.swift / Packet Tunnel).
//! Android: calls into AnkaymaVpnService (Kotlin VpnService) via JNI (vpn_android.rs).
//! Desktop: the privileged agent daemon owns the tunnel; these commands are unused.
//! [T:A.1.9]

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
}

/// Build the resolved tunnel config JSON for the VPN extension from the enrolled node.
/// Shape matches `agent-ios-ptp`'s `Config` (private key + overlay + peers). [T:A.1.1]
/// Used on iOS (Packet Tunnel) and Android (AnkaymaVpnService).
#[cfg(any(target_os = "ios", target_os = "android"))]
fn build_config(state: &AppState) -> Result<String, String> {
    let guard = state.node.lock().expect("node lock poisoned");
    let node = guard.as_ref().ok_or("not enrolled yet")?;
    let cfg = serde_json::json!({
        "private_key_b64": node.private_b64,
        "overlay_ip": node.overlay_ip,
        "listen_port": 51820u16,
        "peers": node.peers,
    });
    serde_json::to_string(&cfg).map_err(|e| e.to_string())
}

/// Enroll on the control plane, build the resolved config, and start the platform VPN.
#[tauri::command]
pub async fn vpn_connect(state: State<'_, AppState>) -> Result<(), String> {
    #[cfg(target_os = "ios")]
    {
        crate::connect_inner(&state).await?;
        let config = build_config(&state)?;
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
        use agent_core::adapters;
        crate::connect_inner(&state).await?;

        // F-3: fetch my_access to build fqdn→overlay_ip DNS records for the interceptor.
        let tok = state.token().ok_or("not signed in")?;
        let access = adapters::my_access(&state.http, &state.base_url, &tok)
            .await
            .unwrap_or_else(|_| agent_core::domain::MyAccess {
                principal: String::new(),
                role: String::new(),
                services: vec![],
            });

        let config_str = {
            let guard = state.node.lock().expect("node lock poisoned");
            let node = guard.as_ref().ok_or("not enrolled")?;

            // peer hostname → overlay_ip string (for DNS mapping)
            let peer_map: std::collections::HashMap<&str, &str> = node
                .peers
                .iter()
                .map(|p| (p.hostname.as_str(), p.overlay_ip.as_str()))
                .collect();

            let dns_records: Vec<serde_json::Value> = access
                .services
                .iter()
                .filter_map(|svc| {
                    peer_map.get(svc.node.as_str()).map(|ip| {
                        serde_json::json!({"fqdn": svc.fqdn, "overlay_ip": ip})
                    })
                })
                .collect();

            let cfg = serde_json::json!({
                "private_key_b64": node.private_b64,
                "overlay_ip": node.overlay_ip,
                "listen_port": 51820u16,
                "peers": node.peers,
                "dns_records": dns_records,
            });
            serde_json::to_string(&cfg).map_err(|e| e.to_string())?
        };

        crate::vpn_android::start_service(&config_str)?;
        Ok(())
    }
    #[cfg(not(any(target_os = "ios", target_os = "android")))]
    {
        let _ = &state;
        Err("vpn_connect is mobile-only; desktop uses the agent daemon".into())
    }
}

/// Stop the platform VPN tunnel.
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

/// Current tunnel status for the UI.
#[tauri::command]
pub fn vpn_status() -> VpnStatus {
    #[cfg(target_os = "ios")]
    {
        // SAFETY: returns a cached integer; no pointers involved.
        let code = unsafe { ffi::ankayma_vpn_status() };
        VpnStatus {
            status: status_string(code).to_string(),
        }
    }
    #[cfg(target_os = "android")]
    {
        let running = crate::vpn_android::VPN_RUNNING.load(std::sync::atomic::Ordering::Relaxed);
        VpnStatus {
            status: if running { "connected" } else { "disconnected" }.to_string(),
        }
    }
    #[cfg(not(any(target_os = "ios", target_os = "android")))]
    {
        VpnStatus {
            status: "unsupported".to_string(),
        }
    }
}

/// Start tracking the installed tunnel's status — call once on app launch (iOS).
#[cfg(target_os = "ios")]
pub fn prime() {
    // SAFETY: no arguments.
    unsafe { ffi::ankayma_vpn_prime() };
}
