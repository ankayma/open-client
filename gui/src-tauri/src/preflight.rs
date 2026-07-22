//! Unified cross-platform pre-flight permission gate.
//!
//! Every platform needs some OS permission before the tunnel can come up, and each
//! asks for it differently:
//!   - macOS: approve the `com.ankayma.helper` LaunchDaemon (System Settings >
//!     General > Login Items & Extensions > App Background Activity).
//!   - iOS: allow the VPN configuration ("Ankayma would like to add VPN
//!     Configurations"), via NETunnelProviderManager.saveToPreferences.
//!   - Android: grant the VpnService consent dialog (VpnService.prepare).
//!   - Windows: UAC elevation is per-connect and can't be pre-acquired; Linux
//!     likewise. These report `ready = true` and show no gate — the standard OS
//!     prompt still appears at connect, unchanged.
//!
//! The UI calls `preflight_status` right after sign-in and gates the Connect button
//! on `ready`; if not ready it shows the onboarding card and calls `preflight_request`,
//! then polls `preflight_status` until the user grants it. This moves the permission
//! ask to setup time (like the iOS "Allow VPN" prompt) instead of surfacing it as a
//! Connect-time error. [T:A.1.7 helper, A.1.9 vpn]

use serde::Serialize;

/// A stable platform tag for the UI (drives which copy the card shows).
#[cfg(target_os = "macos")]
const PLATFORM: &str = "macos";
#[cfg(target_os = "ios")]
const PLATFORM: &str = "ios";
#[cfg(target_os = "android")]
const PLATFORM: &str = "android";
#[cfg(target_os = "windows")]
const PLATFORM: &str = "windows";
#[cfg(target_os = "linux")]
const PLATFORM: &str = "linux";
#[cfg(not(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "android",
    target_os = "windows",
    target_os = "linux"
)))]
const PLATFORM: &str = "unknown";

#[derive(Serialize)]
pub struct PreflightStatus {
    /// True when the tunnel's OS permission is already granted (or none is needed on
    /// this platform) — the Connect button is safe to enable and no gate is shown.
    pub ready: bool,
    /// Which permission this platform needs, so the card picks the right copy:
    /// "helper" (macOS daemon), "vpn" (iOS/Android VPN consent), or "none".
    pub kind: &'static str,
    pub platform: &'static str,
}

/// Read-only: is the tunnel's OS permission already granted? Never prompts or
/// mutates state — safe for the UI to poll on a timer.
#[tauri::command]
pub fn preflight_status() -> PreflightStatus {
    #[cfg(target_os = "macos")]
    {
        PreflightStatus {
            ready: crate::helper_ipc::preflight_ready(),
            kind: "helper",
            platform: PLATFORM,
        }
    }
    #[cfg(target_os = "ios")]
    {
        PreflightStatus {
            ready: crate::vpn::preflight_ready(),
            kind: "vpn",
            platform: PLATFORM,
        }
    }
    #[cfg(target_os = "android")]
    {
        PreflightStatus {
            ready: crate::vpn_android::vpn_permission_ready(),
            kind: "vpn",
            platform: PLATFORM,
        }
    }
    // Windows/Linux (and anything else): no pre-acquirable permission — the connect
    // path still prompts (UAC / pkexec) exactly as before. No gate shown.
    #[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "android")))]
    {
        PreflightStatus {
            ready: true,
            kind: "none",
            platform: PLATFORM,
        }
    }
}

/// Request the tunnel's OS permission now (fired from the onboarding card, before the
/// first Connect). Fire-and-forget with respect to the user's decision: it kicks off
/// the platform's consent flow (and, on macOS, deep-links to the settings switch);
/// the card then polls `preflight_status` until it flips to ready. Not an error when
/// the user still has to act — only a genuine API failure returns `Err`.
#[tauri::command]
pub fn preflight_request() -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        crate::helper_ipc::preflight_request()
    }
    #[cfg(target_os = "ios")]
    {
        crate::vpn::preflight_request()
    }
    #[cfg(target_os = "android")]
    {
        crate::vpn_android::request_vpn_permission()
    }
    #[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "android")))]
    {
        Ok(())
    }
}
