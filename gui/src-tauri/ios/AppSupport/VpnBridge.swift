// VpnBridge — C ABI that the app's Rust layer (gui/src-tauri/src/vpn.rs) calls to
// drive the VPN from the Tauri/JS frontend. Symmetric to agent-ios-ptp (Rust→Swift
// this time): plain @_cdecl C functions, no Tauri/SwiftRs Swift package needed, so
// it compiles as part of the app target and the Rust `extern "C"` resolves at link.
// All real work is in TunnelManager. [T:A.1.9]

import Foundation
import UIKit

/// This device's name for enrollment (e.g. "iPhone", or the user-assigned name when
/// the device-name entitlement is granted). Copied into `buf` (max `len` incl NUL).
/// iOS's `gethostname(2)` returns "localhost" in the sandbox, so the Rust layer fell
/// back to a hard-coded "ankayma-desktop" on every phone — this gives the real name.
@_cdecl("ankayma_device_name")
public func ankayma_device_name(_ buf: UnsafeMutablePointer<CChar>, _ len: Int) {
    let name = UIDevice.current.name
    name.withCString { src in
        _ = strlcpy(buf, src, len)
    }
}

/// The App Group container path — the shared sandbox the app AND the Packet Tunnel
/// extension both reach. The Rust layer joins "agent-status.json" onto it: the extension
/// writes the data-plane status snapshot there and the app reads it for the F-5 path-proof
/// panel (the two are separate processes, so a shared file is the only bridge). Copied into
/// `buf` (max `len` incl NUL); left EMPTY when the container is unavailable so Rust falls
/// back gracefully. Must use the same App Group id as TunnelManager/PacketTunnelProvider.
@_cdecl("ankayma_app_group_dir")
public func ankayma_app_group_dir(_ buf: UnsafeMutablePointer<CChar>, _ len: Int) {
    guard len > 0 else { return }
    buf[0] = 0
    guard let url = FileManager.default.containerURL(
        forSecurityApplicationGroupIdentifier: "group.com.ankayma.app"
    ) else { return }
    url.path.withCString { src in
        _ = strlcpy(buf, src, len)
    }
}

/// Start the tunnel with a resolved config JSON (NUL-terminated UTF-8). Returns 0 if
/// accepted, -1 on a decoding error. The async install/start runs fire-and-forget;
/// progress + failures surface through `ankayma_vpn_status` and the device console.
@_cdecl("ankayma_vpn_connect")
public func ankayma_vpn_connect(_ configJSON: UnsafePointer<CChar>) -> Int32 {
    let json = String(cString: configJSON)
    TunnelManager.shared.connect(configJSON: json) { error in
        if let error = error {
            NSLog("ankayma_vpn_connect failed: \(error.localizedDescription)")
        }
    }
    return 0
}

/// Stop the tunnel (fire-and-forget).
@_cdecl("ankayma_vpn_disconnect")
public func ankayma_vpn_disconnect() {
    TunnelManager.shared.disconnect { error in
        if let error = error {
            NSLog("ankayma_vpn_disconnect failed: \(error.localizedDescription)")
        }
    }
}

/// Current status as an NEVPNStatus rawValue (0=invalid … 3=connected). Synchronous:
/// reads the cached value the status observer keeps up to date.
@_cdecl("ankayma_vpn_status")
public func ankayma_vpn_status() -> Int32 {
    return TunnelManager.shared.cachedStatusCode
}

/// Start tracking the installed tunnel's status (call once on app launch so the UI
/// reflects reality before the user taps connect).
@_cdecl("ankayma_vpn_prime")
public func ankayma_vpn_prime() {
    TunnelManager.shared.primeStatus()
}

/// Pre-flight: 1 if the VPN configuration is already installed (the user allowed the
/// "add VPN Configurations" dialog), else 0. Reads the cached flag primeStatus /
/// installConfiguration keep current, so the Rust side can poll it synchronously.
@_cdecl("ankayma_vpn_has_config")
public func ankayma_vpn_has_config() -> Int32 {
    return TunnelManager.shared.cachedHasConfig ? 1 : 0
}

/// Pre-flight: install the VPN configuration now (bind + saveToPreferences, WITHOUT
/// starting the tunnel), firing the iOS permission dialog at onboarding instead of at
/// the first connect. Fire-and-forget; readiness surfaces via ankayma_vpn_has_config.
@_cdecl("ankayma_vpn_install_config")
public func ankayma_vpn_install_config() -> Int32 {
    TunnelManager.shared.installConfiguration { error in
        if let error = error {
            NSLog("ankayma_vpn_install_config failed: \(error.localizedDescription)")
        }
    }
    return 0
}
