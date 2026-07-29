//! Deferred deep-link InviteResolver — first-run channels for email invitations.
//! Order: (Android) Install Referrer → clipboard `ankayma-invite:` → None (UI asks).

use serde::Serialize;

const INVITE_PREFIX: &str = "ankayma-invite:";

#[derive(Debug, Clone, Serialize)]
pub struct DeferredInvite {
    pub token: String,
    pub method: String,
}

/// Parse a payload that is KNOWN to be an invite channel (Play Install Referrer, or a
/// clipboard entry already confirmed to carry our prefix). Accepts:
/// - `ankayma-invite:{token}`
/// - `invite={token}` (Play Install Referrer form)
/// - raw token / short code
///
/// The bare token/short-code form makes this too permissive for a general clipboard read
/// — see `parse_clipboard_invite`.
#[allow(dead_code)] // used on ios/android; kept public for unit tests on all targets
pub fn parse_invite_payload(raw: &str) -> Option<String> {
    let t = raw.trim();
    if t.is_empty() {
        return None;
    }
    let lower = t.to_ascii_lowercase();
    if let Some(rest) = lower.strip_prefix(INVITE_PREFIX) {
        let payload = t[t.len() - rest.len()..].trim();
        return (!payload.is_empty()).then(|| payload.to_string());
    }
    // Play referrer is often `invite%3D…` already decoded by the API to `invite=…`,
    // possibly among other `&`-joined keys.
    for part in t.split('&') {
        let part = part.trim();
        let pl = part.to_ascii_lowercase();
        if let Some(v) = pl.strip_prefix("invite=") {
            let payload = part[part.len() - v.len()..].trim();
            if !payload.is_empty() {
                return Some(payload.to_string());
            }
        }
    }
    // Raw hex token (32) or short code (6–12).
    if (t.len() == 32 && t.chars().all(|c| c.is_ascii_hexdigit()))
        || (t.len() >= 6 && t.len() <= 12 && t.chars().all(|c| c.is_ascii_alphanumeric()))
    {
        return Some(t.to_string());
    }
    None
}

/// Parse a payload read from the SYSTEM CLIPBOARD. Requires the `ankayma-invite:` prefix.
///
/// The clipboard belongs to the user, not to us: whatever they last copied is in there,
/// and on first launch we read it without being asked to. `parse_invite_payload` also
/// accepts a bare 6–12 character alphanumeric string as a short code, which describes an
/// enormous amount of ordinary text — a password, an order number, a name. Accepting those
/// meant a user who had copied anything at all before installing got their clipboard
/// treated as an invite, auto-redeemed, and was greeted by "the invite may have expired"
/// on the very first screen — plus we wiped what they had copied.
///
/// The prefix is what the landing page writes, so requiring it costs the real flow nothing
/// and makes a false positive essentially impossible. iOS already enforced this; Android
/// did not, so the two platforms disagreed about the same channel.
#[allow(dead_code)] // used on android; kept compiled for unit tests on all targets
pub fn parse_clipboard_invite(raw: &str) -> Option<String> {
    let t = raw.trim();
    if !t.to_ascii_lowercase().starts_with(INVITE_PREFIX) {
        return None;
    }
    parse_invite_payload(t)
}

#[cfg(target_os = "ios")]
mod ios_clip {
    use super::*;
    use std::os::raw::c_char;

    extern "C" {
        fn ankayma_clipboard_has_invite() -> i32;
        fn ankayma_clipboard_read_invite(out: *mut c_char, out_len: i32) -> i32;
        fn ankayma_clipboard_clear();
    }

    pub fn read_invite() -> Option<DeferredInvite> {
        // Soft probe — empty pasteboard → skip without prompting when possible.
        let has = unsafe { ankayma_clipboard_has_invite() };
        if has == 0 {
            return None;
        }
        let mut buf = [0i8; 512];
        let n = unsafe { ankayma_clipboard_read_invite(buf.as_mut_ptr(), buf.len() as i32) };
        if n <= 0 {
            return None;
        }
        let s = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) }
            .to_string_lossy()
            .to_string();
        let token = parse_invite_payload(&format!("{INVITE_PREFIX}{s}"))
            .or_else(|| parse_invite_payload(&s))?;
        Some(DeferredInvite {
            token,
            method: "clipboard".into(),
        })
    }

    pub fn clear() {
        unsafe { ankayma_clipboard_clear() };
    }
}

#[cfg(target_os = "android")]
mod android_channels {
    use super::*;

    /// Install Referrer string cached by Kotlin at first launch (see InstallReferrerHelper).
    pub fn take_install_referrer() -> Option<DeferredInvite> {
        let raw = crate::vpn_android::take_install_referrer()?;
        let token = parse_invite_payload(&raw)?;
        Some(DeferredInvite {
            token,
            method: "referrer".into(),
        })
    }

    pub fn read_clipboard_invite() -> Option<DeferredInvite> {
        let raw = crate::vpn_android::read_clipboard_text()?;
        // Prefix required — the clipboard is the user's, and anything else in it is not
        // ours to interpret. Matches the iOS bridge, which has always required it.
        let token = parse_clipboard_invite(&raw)?;
        Some(DeferredInvite {
            token,
            method: "clipboard".into(),
        })
    }

    pub fn clear_clipboard() {
        crate::vpn_android::clear_clipboard();
    }
}

/// Resolve a deferred email invite on first welcome show.
/// Returns None quickly when no channel has a credential.
pub fn resolve_deferred_invite() -> Option<DeferredInvite> {
    #[cfg(target_os = "android")]
    {
        if let Some(inv) = android_channels::take_install_referrer() {
            return Some(inv);
        }
        if let Some(inv) = android_channels::read_clipboard_invite() {
            android_channels::clear_clipboard();
            return Some(inv);
        }
        return None;
    }

    #[cfg(target_os = "ios")]
    {
        if let Some(inv) = ios_clip::read_invite() {
            ios_clip::clear();
            return Some(inv);
        }
        return None;
    }

    #[cfg(not(any(target_os = "ios", target_os = "android")))]
    {
        // Desktop: no Install Referrer; clipboard hand-off is rare (return-to-tab
        // is the primary path). Soft-read via arboard if available later — for now
        // the welcome UI accepts short code / paste manually.
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_clipboard_prefix() {
        assert_eq!(
            parse_invite_payload("ankayma-invite:abcDEF12"),
            Some("abcDEF12".into())
        );
    }

    #[test]
    fn parses_referrer_form() {
        assert_eq!(
            parse_invite_payload("utm_source=x&invite=deadbeefcafebabe"),
            Some("deadbeefcafebabe".into())
        );
    }

    #[test]
    fn parses_short_code() {
        assert_eq!(parse_invite_payload("AB23CD45"), Some("AB23CD45".into()));
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_invite_payload("hello world").is_none());
        assert!(parse_invite_payload("").is_none());
    }

    // A clipboard read must require our prefix. Everything below is ordinary text a user
    // could plausibly have copied before installing; treating any of it as an invite would
    // auto-redeem, fail, and greet them with an error on the first screen they ever see.
    #[test]
    fn clipboard_requires_the_invite_prefix() {
        for ordinary in [
            "Hoadon2026",                       // an order/invoice reference
            "password1",                        // a password
            "AB23CD45",                         // valid short-code SHAPE, but not ours to assume
            "deadbeefcafebabedeadbeefcafebabe", // valid token shape, same problem
            "Nguyen Van A",
            "",
        ] {
            assert!(
                parse_clipboard_invite(ordinary).is_none(),
                "clipboard content {ordinary:?} must not be taken for an invite"
            );
        }
    }

    #[test]
    fn clipboard_accepts_what_the_landing_page_writes() {
        assert_eq!(
            parse_clipboard_invite("ankayma-invite:abcDEF12"),
            Some("abcDEF12".into())
        );
        // Case-insensitive prefix, surrounding whitespace tolerated.
        assert_eq!(
            parse_clipboard_invite("  Ankayma-Invite:AB23CD45  "),
            Some("AB23CD45".into())
        );
    }

    // The referrer channel is unaffected: Play hands us `invite=…` directly, and that
    // string never came from the user's clipboard.
    #[test]
    fn referrer_channel_still_accepts_bare_forms() {
        assert_eq!(
            parse_invite_payload("utm_source=x&invite=deadbeefcafebabe"),
            Some("deadbeefcafebabe".into())
        );
    }
}
