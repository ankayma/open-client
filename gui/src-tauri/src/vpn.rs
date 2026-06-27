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

/// Build the resolved tunnel config JSON for the extension from the enrolled node.
/// Shape matches `agent-ios-ptp`'s `Config` (private key + overlay + peers). [T:A.1.1]
#[cfg(target_os = "ios")]
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

/// Enroll on the control plane (reusing the shared connect flow), build the resolved
/// config, and start the iOS Packet Tunnel.
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
    #[cfg(not(target_os = "ios"))]
    {
        let _ = &state;
        Err("vpn_connect is iOS-only; desktop uses the agent daemon".into())
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
    #[cfg(not(target_os = "ios"))]
    {
        Err("vpn_disconnect is iOS-only".into())
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
    #[cfg(not(target_os = "ios"))]
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
