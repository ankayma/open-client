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
//! Runs in-process wherever it's called from (GUI or daemon) — `127.0.0.1` is
//! shared across every process on the host regardless of privilege level, so
//! it doesn't matter which process binds it as long as it stays alive for the
//! FQDN to keep resolving.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const HTML: &str = include_str!("../assets/sample-demo.html");

static PORT: OnceLock<u16> = OnceLock::new();
/// Whether the responder answers requests right now. Publish sets this back to
/// true (covers re-publish after an unpublish); unpublish flips it off. Kept
/// separate from binding the socket: unbinding a live port and rebinding later
/// races the OS handing the same port to someone else in between, so instead
/// the listener stays open for the process lifetime and simply stops
/// answering — no attacker-reachable behavior change either way, since this
/// is a loopback-only listener nothing outside the host can dial directly.
static ENABLED: AtomicBool = AtomicBool::new(false);

/// Ensure the responder is bound and listening, returning its port. Idempotent:
/// the first call binds an OS-assigned ephemeral port and spawns the accept
/// loop; every later call (a second "Publish" click, a resync) just returns
/// the same port. Must be called from within a Tokio runtime (a Tauri command
/// or the daemon's async context both qualify).
pub fn ensure_running() -> u16 {
    let port = *PORT.get_or_init(|| {
        let std_listener = std::net::TcpListener::bind(("127.0.0.1", 0))
            .expect("bind loopback sample-demo listener");
        std_listener
            .set_nonblocking(true)
            .expect("set sample-demo listener nonblocking");
        let port = std_listener
            .local_addr()
            .expect("read sample-demo listener port")
            .port();
        let listener =
            TcpListener::from_std(std_listener).expect("adopt sample-demo listener into tokio");
        tokio::spawn(accept_loop(listener));
        port
    });
    ENABLED.store(true, Ordering::Relaxed);
    port
}

/// Stop answering requests (called on unpublish). Does not close the socket —
/// see `ENABLED` doc comment above.
pub fn set_enabled(enabled: bool) {
    ENABLED.store(enabled, Ordering::Relaxed);
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
/// gets the same 200 response.
async fn serve_one(mut stream: TcpStream) {
    let mut buf = [0u8; 1024];
    let _ = stream.read(&mut buf).await;

    if !ENABLED.load(Ordering::Relaxed) {
        let _ = stream
            .write_all(b"HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n")
            .await;
        return;
    }

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
    async fn serves_the_bundled_page_then_stops_on_disable() {
        let port = ensure_running();
        assert_ne!(port, 0, "OS must have assigned a real ephemeral port");

        let resp = get(port).await;
        assert!(resp.starts_with("HTTP/1.1 200 OK"), "got: {resp}");
        assert!(resp.contains("Content-Type: text/html"), "got: {resp}");
        assert!(
            resp.contains("Private preview"),
            "bundled HTML must be in the body: {resp}"
        );

        set_enabled(false);
        let resp = get(port).await;
        assert!(
            resp.starts_with("HTTP/1.1 404"),
            "disabled responder must stop serving the page: {resp}"
        );

        // Re-publish (a second "Add demo" click) must resume serving on the
        // SAME port — no rebind.
        let port2 = ensure_running();
        assert_eq!(port, port2, "the listener must be reused, not rebound");
        let resp = get(port2).await;
        assert!(resp.starts_with("HTTP/1.1 200 OK"), "got: {resp}");
    }
}
