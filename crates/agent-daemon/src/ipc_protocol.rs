//! ipc_protocol — the named-pipe wire format + the pure identity-authorization
//! decision for `win_ipc` (Change 2 of the Windows daemon lifecycle decision,
//! `docs/windows-daemon-lifecycle-decision.md`). Deliberately **not**
//! `#[cfg(windows)]`: kept cross-platform so its parsing/decision logic is
//! unit-tested on every CI platform, not just Windows — only the actual named
//! pipe transport and Win32 identity extraction (which call into this module)
//! live in `win_ipc.rs`, gated to Windows — so on a non-Windows build, this
//! module's public API is legitimately exercised only by its own `tests`
//! (`cargo clippy` without `--tests` doesn't count that as "used"; expected,
//! not a bug).

#![cfg_attr(not(windows), allow(dead_code))]

use serde::{Deserialize, Serialize};

/// One line of request JSON from the GUI over the pipe.
#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(tag = "cmd", rename_all = "lowercase")]
pub enum Request {
    Connect {
        token: String,
        control_plane: String,
    },
    Disconnect,
    Status,
}

/// One line of response JSON back to the GUI.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct Response {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connected: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl Response {
    /// Every real reply carries a `connected` state — `Connect`/`Disconnect`/
    /// `Status` all resolve to `Idle` or `Connected`, so there is no
    /// bare-`{"ok":true}` reply any handler actually produces. (A confirmed-on-
    /// real-Windows-build lesson: an earlier bare `ok()` constructor compiled
    /// clean on macOS but showed up as genuine dead code — unused by any
    /// production caller, only by its own test — the moment this crate was
    /// actually built for `target_os = "windows"`.)
    pub fn ok_status(connected: bool) -> Self {
        Response {
            ok: true,
            connected: Some(connected),
            error: None,
        }
    }

    pub fn err(msg: impl Into<String>) -> Self {
        Response {
            ok: false,
            connected: None,
            error: Some(msg.into()),
        }
    }
}

/// Parse one newline-delimited request line. `None` on malformed JSON — the
/// caller replies with `Response::err` rather than closing the connection, so a
/// GUI/protocol version mismatch is diagnosable instead of a silent hang.
pub fn parse_request(line: &str) -> Option<Request> {
    serde_json::from_str(line.trim()).ok()
}

pub fn encode_response(resp: &Response) -> String {
    // `Response` is a fixed, hand-written struct with no untrusted/recursive
    // input — serialization cannot fail in practice; `unwrap_or_default` keeps
    // this infallible for callers without a hidden panic path.
    serde_json::to_string(resp).unwrap_or_default()
}

/// Pure authorization decision, pulled out of the Win32 impersonation/session
/// lookup in `win_ipc.rs` so it's unit-testable without a real named pipe or
/// WinAPI: a `Connect` message carries a bearer session token in-band to a
/// LocalSystem-privileged daemon, so only the session currently on the console
/// (mirrors Tailscale's `checkConnIdentityLocked()` — "only one local user's
/// session at a time") is authorized. `0xFFFFFFFF` is WTS's documented
/// "no active console session" sentinel — never authorize against it.
/// `[T:Win32 WTSGetActiveConsoleSessionId — MS-RDPBCGR / docs.microsoft.com]`
pub fn session_authorized(client_session_id: u32, active_console_session_id: u32) -> bool {
    active_console_session_id != u32::MAX && client_session_id == active_console_session_id
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_connect_with_fields() {
        let req = parse_request(
            r#"{"cmd":"connect","token":"tok-a","control_plane":"https://cp.example"}"#,
        )
        .expect("valid connect");
        assert_eq!(
            req,
            Request::Connect {
                token: "tok-a".into(),
                control_plane: "https://cp.example".into(),
            }
        );
    }

    #[test]
    fn parses_disconnect_and_status() {
        assert_eq!(
            parse_request(r#"{"cmd":"disconnect"}"#).unwrap(),
            Request::Disconnect
        );
        assert_eq!(
            parse_request(r#"{"cmd":"status"}"#).unwrap(),
            Request::Status
        );
    }

    #[test]
    fn rejects_malformed_json_instead_of_panicking() {
        assert!(parse_request("not json").is_none());
        assert!(parse_request(r#"{"cmd":"bogus"}"#).is_none());
        assert!(parse_request(r#"{"cmd":"connect"}"#).is_none()); // missing fields
    }

    #[test]
    fn trims_the_trailing_newline_from_a_buffered_line() {
        assert_eq!(
            parse_request("{\"cmd\":\"status\"}\n").unwrap(),
            Request::Status
        );
    }

    #[test]
    fn encodes_status_response() {
        assert_eq!(
            encode_response(&Response::ok_status(true)),
            r#"{"ok":true,"connected":true}"#
        );
        assert_eq!(
            encode_response(&Response::ok_status(false)),
            r#"{"ok":true,"connected":false}"#
        );
        assert_eq!(
            encode_response(&Response::err("not authorized")),
            r#"{"ok":false,"error":"not authorized"}"#
        );
    }

    #[test]
    fn session_authorization_matches_only_the_active_console_session() {
        assert!(session_authorized(3, 3));
        assert!(
            !session_authorized(3, 4),
            "a different session must be rejected"
        );
        assert!(
            !session_authorized(0xFFFF_FFFF, 0xFFFF_FFFF),
            "never authorize against the 'no active console session' sentinel"
        );
    }
}
