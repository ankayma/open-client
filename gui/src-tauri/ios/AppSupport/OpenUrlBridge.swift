// OpenUrlBridge — C ABI that the app's Rust layer (gui/src-tauri/src/vpn.rs) calls to
// open an external URL in the system browser. Symmetric to VpnBridge: plain @_cdecl C
// functions, no Tauri/SwiftRs Swift package needed, so it compiles as part of the app
// target and the Rust `extern "C"` resolves at link. The `open` crate used on desktop
// no-ops on iOS, so the GitHub OAuth "Continue with GitHub" button routes here. [T:A.1.9]

import UIKit

/// Open `urlC` (NUL-terminated UTF-8) in the system browser. Returns 0 once the open is
/// dispatched, -1 if the bytes don't parse into a URL. `UIApplication.open` must run on
/// the main thread, so hop there. [T:UIKit-UIApplication.open(_:options:completionHandler:)]
@_cdecl("ankayma_open_url")
public func ankayma_open_url(_ urlC: UnsafePointer<CChar>) -> Int32 {
    let s = String(cString: urlC)
    guard let url = URL(string: s) else { return -1 }
    DispatchQueue.main.async {
        UIApplication.shared.open(url, options: [:], completionHandler: nil)
    }
    return 0
}
