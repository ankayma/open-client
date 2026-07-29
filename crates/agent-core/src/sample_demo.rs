//! "Publish a sample demo" — a one-click F0 onboarding shortcut. macOS ships
//! no trustworthy zero-install static server anymore (Ruby/PHP gone,
//! `python3` pops an Xcode CLT install prompt), so the agent serves its own
//! bundled page: `include_str!` embeds the HTML at compile time (no external
//! asset, no new dependency), and this is a minimal loopback HTTP responder
//! for it — reusing the SAME `tokio::net::TcpListener` the rest of the data
//! plane already depends on. The existing F-3 auto-TLS relay (`tls_relay.rs`)
//! picks this up exactly like any other subdomain target; nothing here talks
//! TLS, ACME, or SNI.
//!
//! **Daemon-only, fixed port** `[fix 2026-07-29]`: this used to bind an
//! OS-assigned ephemeral port from whichever process called
//! `ensure_running()` first — in practice the GUI, since that's where the
//! "Publish" button lives. That breaks on the next GUI restart: `PORT` is a
//! `static`, reset per-process, so a fresh GUI process binds a NEW random
//! port while the control-plane subdomain record (set once, on first
//! publish — there's no update endpoint) keeps pointing the relay at the OLD
//! one. The relay itself lives in the `agent` daemon (long-lived, root,
//! auto-respawned by the privileged helper) — this responder now lives there
//! too, on a FIXED port, so the port the daemon binds always matches the one
//! already on file at the control plane, independent of how often the GUI
//! window gets quit/reopened. The daemon calls `ensure_running()` once,
//! unconditionally, at startup (`agent-daemon/src/up.rs`); the GUI's
//! "Publish" command only registers the control-plane subdomain mapping, it
//! doesn't bind anything itself (see `configured_port`).

use std::sync::OnceLock;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const HTML: &str = include_str!("../assets/sample-demo.html");

/// The fixed port, high enough to avoid the common local-dev range
/// (3000/5173/8000/8080/8888/9000...), overridable via
/// `ANKAYMA_SAMPLE_DEMO_PORT` for the rare host where it's already taken —
/// same escape hatch pattern as `tls_relay::relay_https_port`.
/// `[A: the exact number is arbitrary — the only requirement is "same value
/// every run"; a taken port logs clearly from `ensure_running` below rather
/// than failing silently]`
pub fn configured_port() -> u16 {
    std::env::var("ANKAYMA_SAMPLE_DEMO_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(47990)
}

/// `None` once resolved if the bind failed — cached so a taken port doesn't
/// retry-storm on every subdomain resync cycle.
static PORT: OnceLock<Option<u16>> = OnceLock::new();

/// Ensure the responder is bound and listening on `configured_port()`. Call
/// from the daemon's startup path (see module doc — NOT the GUI). Idempotent
/// and safe to call every resync cycle. A bind failure is logged and returns
/// `None` — not fatal, the rest of the daemon must keep running even if this
/// one feature can't claim its port on this host.
pub fn ensure_running() -> Option<u16> {
    *PORT.get_or_init(|| {
        let port = configured_port();
        let std_listener = match std::net::TcpListener::bind(("127.0.0.1", port)) {
            Ok(l) => l,
            Err(e) => {
                eprintln!(
                    "sample-demo responder: bind 127.0.0.1:{port} failed: {e} — sample demo \
                     unavailable this run (set ANKAYMA_SAMPLE_DEMO_PORT to use a free port)"
                );
                return None;
            }
        };
        if let Err(e) = std_listener.set_nonblocking(true) {
            eprintln!("sample-demo responder: set_nonblocking failed: {e}");
            return None;
        }
        // The port actually bound — same as `port` unless `configured_port()`
        // returned 0 (test-only escape hatch: "OS-assigned", see the test
        // below).
        let bound_port = match std_listener.local_addr() {
            Ok(addr) => addr.port(),
            Err(e) => {
                eprintln!("sample-demo responder: read bound port failed: {e}");
                return None;
            }
        };
        let listener = match TcpListener::from_std(std_listener) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("sample-demo responder: adopt into tokio failed: {e}");
                return None;
            }
        };
        tokio::spawn(accept_loop(listener));
        Some(bound_port)
    })
}

async fn accept_loop(listener: TcpListener) {
    loop {
        match listener.accept().await {
            Ok((stream, _peer)) => {
                tokio::spawn(serve_one(stream));
            }
            Err(e) => {
                eprintln!("sample-demo responder: accept failed: {e}");
            }
        }
    }
}

/// Answer one connection: this is a single static page, so the request is
/// drained (best-effort, bounded) without parsing method/path — every request
/// gets the same 200 response. Always serves once bound: "unpublish" removes
/// the control-plane subdomain mapping, so no name routes here anymore —
/// nothing outside the host could dial this loopback port directly either
/// way, so there's no separate on/off switch to keep in sync.
async fn serve_one(mut stream: TcpStream) {
    let mut buf = [0u8; 1024];
    let _ = stream.read(&mut buf).await;

    let body = HTML.as_bytes();
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    if stream.write_all(head.as_bytes()).await.is_ok() {
        let _ = stream.write_all(body).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn get(port: u16) -> String {
        let mut stream = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect to sample-demo responder");
        stream
            .write_all(b"GET / HTTP/1.1\r\nHost: demo.test\r\n\r\n")
            .await
            .expect("write request");
        let mut buf = Vec::new();
        // The responder always closes the connection (Connection: close), so
        // read-to-end is a valid way to wait for the full response.
        stream.read_to_end(&mut buf).await.expect("read response");
        String::from_utf8(buf).expect("response is valid utf-8")
    }

    #[tokio::test]
    async fn serves_the_bundled_page_on_the_configured_port() {
        // "0" = OS-assigned — isolates this test's port from the real fixed
        // default (47990) so it doesn't fight a real daemon, or another test
        // binary running in parallel, for the same port.
        std::env::set_var("ANKAYMA_SAMPLE_DEMO_PORT", "0");
        let port = ensure_running().expect("bind must succeed in test env");

        let resp = get(port).await;
        assert!(resp.starts_with("HTTP/1.1 200 OK"), "got: {resp}");
        assert!(resp.contains("Content-Type: text/html"), "got: {resp}");
        assert!(
            resp.contains("Private preview"),
            "bundled HTML must be in the body: {resp}"
        );

        // Re-publish (a second "Add demo" click, or a resync) must resume
        // serving on the SAME port — no rebind.
        let port2 = ensure_running().expect("second call must reuse the cached bind");
        assert_eq!(port, port2, "the listener must be reused, not rebound");
        let resp = get(port2).await;
        assert!(resp.starts_with("HTTP/1.1 200 OK"), "got: {resp}");
    }
}
