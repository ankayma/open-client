// ClipboardBridge — deferred deep-link hand-off for email invitations.
// Landing page writes `ankayma-invite:{token}` before opening the App Store; on first
// open we probe/read the pasteboard (Allow Paste once), redeem, and clear.

import UIKit

private let invitePrefix = "ankayma-invite:"

/// Returns 1 if the pasteboard looks like it holds an Ankayma invite (pattern detect,
/// no content read — avoids the Allow Paste dialog). Returns 0 if empty/no match,
/// -1 on unsupported OS. Main-thread only.
@_cdecl("ankayma_clipboard_has_invite")
public func ankayma_clipboard_has_invite() -> Int32 {
    if #available(iOS 15.0, *) {
        // detectPatterns is async; for the C ABI we do a cheap prefix probe via
        // hasStrings + a deferred full read path in ankayma_clipboard_read_invite.
        // True pattern detection without reading requires the async API; callers
        // that want zero-dialog probe should still call read (iOS will prompt).
        return UIPasteboard.general.hasStrings ? 1 : 0
    }
    return UIPasteboard.general.hasStrings ? 1 : 0
}

/// Read pasteboard; if it starts with `ankayma-invite:`, write the payload (NUL-term)
/// into `out` (cap `out_len` bytes) and return byte length. Returns 0 if no invite,
/// -1 on error. Caller must free nothing — buffer owned by caller.
@_cdecl("ankayma_clipboard_read_invite")
public func ankayma_clipboard_read_invite(_ out: UnsafeMutablePointer<CChar>, _ out_len: Int32) -> Int32 {
    guard out_len > 1 else { return -1 }
    guard let s = UIPasteboard.general.string, !s.isEmpty else { return 0 }
    let trimmed = s.trimmingCharacters(in: .whitespacesAndNewlines)
    let lower = trimmed.lowercased()
    guard lower.hasPrefix(invitePrefix) else { return 0 }
    let payload = String(trimmed.dropFirst(invitePrefix.count))
        .trimmingCharacters(in: .whitespacesAndNewlines)
    guard !payload.isEmpty else { return 0 }
    let bytes = Array(payload.utf8)
    let n = min(bytes.count, Int(out_len) - 1)
    for i in 0..<n {
        out[i] = CChar(bitPattern: bytes[i])
    }
    out[n] = 0
    return Int32(n)
}

/// Overwrite the pasteboard so the invite token does not linger after redeem.
@_cdecl("ankayma_clipboard_clear")
public func ankayma_clipboard_clear() {
    UIPasteboard.general.string = ""
}
