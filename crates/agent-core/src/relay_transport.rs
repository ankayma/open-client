//! relay_transport — DERP-style relay path for the WireGuard data plane. OPEN.
//!
//! The NAT-fallback for two peers that cannot reach each other directly. It carries
//! WireGuard **ciphertext only** — the relay never decrypts `[T:A.1.4]`; this module
//! just wraps outbound ciphertext in a `Send{dst=peer_pubkey}` frame and unwraps
//! inbound `Recv{src,payload}` back into bytes the pump hands to boringtun's
//! `decapsulate`. Addressing is by WireGuard public key, exactly like the relay.
//!
//! Transport model `[T: Decision D-T1, part-d-transport-connectivity §5 — Tailscale-lite]`:
//! a connection begins over the relay (guaranteed reachability) and is *upgraded* to a
//! direct path by hole-punching (G-2 STUN + G-3 SSE signalling) when that succeeds; the
//! relay then becomes a best-effort fallback. This module owns only the relay leg.
//!
//! Sync (std `TcpStream` + one reader thread) to match the pump's thread model — the
//! same shape proven end-to-end against the real relay server (docker, two boringtun
//! peers on isolated networks). The wire codec is the first-party `relay-core` crate
//! (SSOT = relay repo), so client and relay can never disagree on the frame format.

use std::io::{self, BufReader};
use std::net::TcpStream;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex, Weak};
use std::thread;
use std::time::Duration;

use relay_core::frame::{Frame, Key};

/// Idle window before the leg probes liveness with a `Ping`. A roamed/dead TCP
/// connection (WiFi↔4G, sleep-wake) usually blocks silently rather than erroring, so we
/// poke it: a failed `Ping` write means the socket is gone and the supervisor rebuilds
/// the leg. Generous enough that a whole small frame arrives inside one window (a
/// mid-frame timeout just drops one relayed datagram — WG retransmits). `[T:G-7]`
const READ_TIMEOUT: Duration = Duration::from_secs(20);
/// Reconnect backoff bounds (capped exponential). Fast first retry so a brief roam heals
/// in well under a second; capped so a truly-down relay isn't hammered. `[A]`
const BACKOFF_MIN: Duration = Duration::from_millis(500);
const BACKOFF_MAX: Duration = Duration::from_secs(30);

/// Optional connect override for the relay TCP leg. On a full-tunnel platform (Android:
/// VpnService routes 0.0.0.0/0 + ::/0) a plain socket to the relay would loop back into our
/// OWN VPN and be black-holed, so the platform must create the socket, bind it to the
/// underlying non-VPN network, THEN connect. Android installs a hook that does exactly that
/// (the per-socket bypass Tailscale's `netns_android` `controlC` and Firezone's
/// `protected_tcp_socket_factory` both use). It runs on EVERY dial, so the supervisor's
/// reconnects re-bind the fresh socket too — the bypass is one-shot per fd, not sticky
/// across a WiFi↔cellular roam. Unset (desktop/iOS, whose tunnels install no default route
/// so the relay egresses unpinned) → plain `TcpStream::connect`.
/// `[T:research Firezone protected_tcp_socket_factory / Tailscale netns_android.go 2026-07-21]`
static CONNECT_HOOK: std::sync::OnceLock<fn(&str) -> io::Result<TcpStream>> =
    std::sync::OnceLock::new();

/// Install the relay connect override (see `CONNECT_HOOK`). Idempotent; set once at startup
/// before the first `RelayClient::connect`.
pub fn set_connect_hook(f: fn(&str) -> io::Result<TcpStream>) {
    let _ = CONNECT_HOOK.set(f);
}

/// One inbound ciphertext delivery from the relay: `src` is the peer's WireGuard
/// public key (a precise sender identity — better than the UDP path's IP guess),
/// `payload` is the opaque WireGuard ciphertext to feed into `Tunn::decapsulate`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayInbound {
    pub src: Key,
    pub payload: Vec<u8>,
}

/// A relay leg that survives network changes: a registered connection to one relay,
/// addressed by this node's WireGuard public key. A supervisor thread keeps the leg up —
/// when the TCP connection dies (WiFi↔4G roam, sleep-wake, relay restart) it reconnects
/// and re-registers, feeding the SAME inbound channel throughout, so the pump's relay
/// ingress never has to be re-wired. `[T:G-7 network-change]`
#[derive(Clone)]
pub struct RelayClient {
    inner: Arc<Inner>,
}

struct Inner {
    addr: String,
    pubkey: Key,
    auth: Vec<u8>,
    /// Write half of the CURRENT connection; `None` while (re)connecting. `send` writes
    /// here best-effort and clears it on a write error so the supervisor rebuilds the leg.
    tx: Mutex<Option<TcpStream>>,
}

impl RelayClient {
    /// Connect to `relay_addr`, register under `my_pubkey` via `ClientHello`, and wait
    /// for `ServerHello`. `auth` is the opaque membership proof (the node's service
    /// token) — the relay forwards it to the control-plane verify hook and never parses
    /// it here `[T:A.1.6]`. A relay that fails membership verification never answers
    /// `ServerHello`, so a refused hello surfaces as a fail-closed error.
    ///
    /// The FIRST connect is fail-closed: its error propagates so the caller falls back to
    /// direct-only. Once a leg is up, the supervisor auto-reconnects it forever (until
    /// this `RelayClient` and the returned receiver are dropped).
    ///
    /// Returns the client (for sending) and the inbound channel (for the pump's relay
    /// ingress thread to drain into `decapsulate`).
    pub fn connect(
        relay_addr: &str,
        my_pubkey: Key,
        auth: Vec<u8>,
    ) -> io::Result<(RelayClient, Receiver<RelayInbound>)> {
        let (write_half, reader) = dial(relay_addr, my_pubkey, &auth)?;
        let inner = Arc::new(Inner {
            addr: relay_addr.to_string(),
            pubkey: my_pubkey,
            auth,
            tx: Mutex::new(Some(write_half)),
        });
        let (itx, irx) = mpsc::channel();
        // Supervise via a Weak handle: when the pump drops the RelayClient (agent
        // shutdown), the Weak stops upgrading and the supervisor exits — no leaked
        // reconnect loop.
        let weak = Arc::downgrade(&inner);
        thread::spawn(move || supervise(weak, reader, itx));
        Ok((RelayClient { inner }, irx))
    }

    /// Forward WireGuard `ciphertext` to peer `dst` (its WG public key) via the relay.
    /// Best-effort, UDP semantics `[T:A.1.4]`: a write error is dropped (and clears the
    /// dead write half so the supervisor reconnects) rather than surfaced — the inner
    /// WireGuard session retransmits on its own timer, so a lost relayed datagram costs
    /// at most one handshake RTT, never a torn tunnel.
    pub fn send(&self, dst: Key, ciphertext: &[u8]) {
        let Ok(mut g) = self.inner.tx.lock() else {
            return;
        };
        if let Some(s) = g.as_mut() {
            let frame = Frame::Send {
                dst,
                payload: ciphertext.to_vec(),
            };
            if frame.write_to(s).is_err() {
                *g = None; // dead → supervisor reconnects
            }
        }
    }
}

/// One TCP dial + `ClientHello`/`ServerHello` handshake. Returns the write half and a
/// buffered reader with a read timeout set (so an idle-but-dead leg is probed, not
/// blocked on forever). A refused hello is fail-closed (`PermissionDenied`).
fn dial(addr: &str, pubkey: Key, auth: &[u8]) -> io::Result<(TcpStream, BufReader<TcpStream>)> {
    // Full-tunnel platforms register a connect override that binds the socket off the VPN
    // before connecting (see CONNECT_HOOK); everyone else dials directly.
    let stream = match CONNECT_HOOK.get() {
        Some(connect) => connect(addr)?,
        None => TcpStream::connect(addr)?,
    };
    stream.set_nodelay(true).ok();
    let read_half = stream.try_clone()?;
    read_half.set_read_timeout(Some(READ_TIMEOUT)).ok();
    let mut reader = BufReader::new(read_half);
    Frame::ClientHello {
        pubkey,
        auth: auth.to_vec(),
    }
    .write_to(&mut &stream)?;
    match Frame::read_from(&mut reader)? {
        Frame::ServerHello => {}
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "relay refused hello (fail-closed: membership not verified)",
            ))
        }
    }
    Ok((stream, reader))
}

/// Why a receive pass ended: the pump is gone (stop supervising) vs the connection died
/// (reconnect).
enum RecvExit {
    PumpGone,
    ConnectionDead,
}

/// Supervisor: drain the current connection, and when it dies, reconnect with capped
/// exponential backoff — forever, until the pump (Receiver) or the RelayClient (Weak) is
/// gone. The inbound `Sender` is held here across reconnects, so the pump's ingress
/// channel stays open the whole time.
fn supervise(inner: Weak<Inner>, first_reader: BufReader<TcpStream>, out: Sender<RelayInbound>) {
    let mut reader = first_reader;
    let mut backoff = BACKOFF_MIN;
    loop {
        match recv_loop(&mut reader, &out, &inner) {
            RecvExit::PumpGone => return,
            RecvExit::ConnectionDead => {}
        }
        // Clear the dead write half so `send` stops using it while we rebuild.
        match inner.upgrade() {
            Some(strong) => *strong.tx.lock().expect("relay tx lock") = None,
            None => return, // RelayClient dropped
        }
        // Reconnect loop.
        loop {
            thread::sleep(backoff);
            backoff = (backoff * 2).min(BACKOFF_MAX);
            let Some(strong) = inner.upgrade() else {
                return;
            };
            match dial(&strong.addr, strong.pubkey, &strong.auth) {
                Ok((write_half, rdr)) => {
                    *strong.tx.lock().expect("relay tx lock") = Some(write_half);
                    reader = rdr;
                    backoff = BACKOFF_MIN;
                    break;
                }
                Err(_) => continue, // keep retrying (relay may be briefly down)
            }
        }
    }
}

/// Decode relay frames off one connection, forwarding inbound ciphertext to the pump.
/// On an idle-window timeout, probe the leg with a `Ping`; a failed probe means the
/// socket is dead → reconnect. Returns when the pump drops the receiver (`PumpGone`) or
/// the connection dies (`ConnectionDead`).
fn recv_loop(
    reader: &mut BufReader<TcpStream>,
    out: &Sender<RelayInbound>,
    inner: &Weak<Inner>,
) -> RecvExit {
    loop {
        match Frame::read_from(reader) {
            Ok(Frame::Recv { src, payload }) => {
                if out.send(RelayInbound { src, payload }).is_err() {
                    return RecvExit::PumpGone;
                }
            }
            // The peer we addressed has no live relay registration. Nothing to do at
            // the relay layer — a direct/hole-punched path may still exist, and WG
            // retransmits regardless. Dropping matches UDP semantics.
            Ok(Frame::PeerGone { .. }) => {}
            // ServerHello (already consumed at dial), Ping/Pong, or anything else:
            // not payload-bearing for the pump.
            Ok(_) => {}
            Err(e) if is_idle_timeout(&e) => {
                // Idle window elapsed with no bytes: probe liveness with a Ping over the
                // write half. Success → still connected; failure (or RelayClient gone) →
                // rebuild the leg.
                let Some(strong) = inner.upgrade() else {
                    return RecvExit::PumpGone;
                };
                let mut g = strong.tx.lock().expect("relay tx lock");
                // Ping over the write half: success → still connected; failure (or no
                // write half) → the leg is dead, rebuild it.
                let dead = match g.as_mut() {
                    Some(s) => Frame::Ping.write_to(s).is_err(),
                    None => true,
                };
                if dead {
                    *g = None;
                    return RecvExit::ConnectionDead;
                }
            }
            Err(_) => return RecvExit::ConnectionDead, // relay connection closed
        }
    }
}

/// A read timeout (idle window) surfaces as `WouldBlock` or `TimedOut` depending on the
/// platform — both mean "no bytes this window", not a broken connection.
fn is_idle_timeout(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tunnel::{handshake_established, make_tunn, PublicKey, StaticSecret, TunnResult};
    use std::collections::HashMap;
    use std::net::TcpListener;
    use std::time::Duration;

    const RECV: Duration = Duration::from_secs(5);

    /// Minimal in-process relay: registers each `ClientHello` pubkey and routes
    /// `Send{dst}` → `Recv{src}` to the destination's connection. A test double for
    /// the real relay-server (proven separately, end-to-end in docker); this exercises
    /// the REAL `relay-core` wire codec, so it pins client↔relay frame compatibility.
    fn mock_relay() -> String {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let table: Arc<Mutex<HashMap<Key, TcpStream>>> = Arc::new(Mutex::new(HashMap::new()));
        thread::spawn(move || {
            for conn in l.incoming() {
                let Ok(stream) = conn else { continue };
                let table = Arc::clone(&table);
                thread::spawn(move || {
                    let mut reader = BufReader::new(stream.try_clone().unwrap());
                    let me = match Frame::read_from(&mut reader) {
                        Ok(Frame::ClientHello { pubkey, .. }) => pubkey,
                        _ => return,
                    };
                    {
                        let mut w = stream.try_clone().unwrap();
                        Frame::ServerHello.write_to(&mut w).unwrap();
                    }
                    table
                        .lock()
                        .unwrap()
                        .insert(me, stream.try_clone().unwrap());
                    loop {
                        match Frame::read_from(&mut reader) {
                            Ok(Frame::Send { dst, payload }) => {
                                if let Some(peer) = table.lock().unwrap().get_mut(&dst) {
                                    let _ = Frame::Recv { src: me, payload }.write_to(peer);
                                }
                            }
                            Ok(_) => {}
                            Err(_) => break,
                        }
                    }
                });
            }
        });
        addr.to_string()
    }

    /// Minimal IPv4 packet carrying `msg` — boringtun surfaces a decrypted payload as
    /// `WriteToTunnelV4` only when the version nibble is 4 (mirrors tunnel.rs's test).
    fn ip_pkt(msg: &[u8]) -> Vec<u8> {
        let mut p = vec![
            0x45, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 100, 64, 0, 1,
            100, 64, 0, 2,
        ];
        let total = (20 + msg.len()) as u16;
        p[2] = (total >> 8) as u8;
        p[3] = (total & 0xff) as u8;
        p.extend_from_slice(msg);
        p
    }

    /// Two boringtun peers complete a REAL WireGuard handshake and exchange an
    /// encrypted application packet — with NO direct socket between them, every byte
    /// crosses the relay. This is the client half of the docker demo, in-repo.
    #[test]
    fn wireguard_roundtrip_entirely_through_relay() {
        let addr = mock_relay();

        // Obvious fake keys (leak-safe): seed byte repeated 32×.
        let a_priv = StaticSecret::from([0x11u8; 32]);
        let a_pub = PublicKey::from(&a_priv);
        let b_priv = StaticSecret::from([0x22u8; 32]);
        let b_pub = PublicKey::from(&b_priv);

        let (a, a_in) = RelayClient::connect(&addr, a_pub.to_bytes(), b"proof-a".to_vec()).unwrap();
        let (b, b_in) = RelayClient::connect(&addr, b_pub.to_bytes(), b"proof-b".to_vec()).unwrap();

        let mut ta = make_tunn(a_priv, b_pub, 1, None);
        let mut tb = make_tunn(b_priv, a_pub, 2, None);
        let mut buf = [0u8; 2048];
        let mut out = [0u8; 2048];

        // A → handshake initiation → relay → B.
        let init = match ta.format_handshake_initiation(&mut buf, false) {
            TunnResult::WriteToNetwork(p) => p.to_vec(),
            _ => panic!("A should emit a handshake initiation"),
        };
        a.send(b_pub.to_bytes(), &init);

        // B receives it via the relay, decapsulates → handshake response → relay → A.
        let got = b_in.recv_timeout(RECV).expect("B receives init via relay");
        assert_eq!(
            got.src,
            a_pub.to_bytes(),
            "relay reports the true WG sender"
        );
        let resp = match tb.decapsulate(None, &got.payload, &mut out) {
            TunnResult::WriteToNetwork(p) => p.to_vec(),
            _ => panic!("B should emit a handshake response"),
        };
        b.send(a_pub.to_bytes(), &resp);

        // A consumes the response → session established.
        let got = a_in
            .recv_timeout(RECV)
            .expect("A receives response via relay");
        let _ = ta.decapsulate(None, &got.payload, &mut out);
        assert!(
            handshake_established(&ta),
            "handshake must complete over the relay"
        );

        // A encrypts an application packet → relay → B decrypts back to the plaintext.
        let data = match ta.encapsulate(&ip_pkt(b"HELLO-OVER-RELAY"), &mut buf) {
            TunnResult::WriteToNetwork(p) => p.to_vec(),
            _ => panic!("A should emit an encrypted data packet"),
        };
        a.send(b_pub.to_bytes(), &data);

        let got = b_in.recv_timeout(RECV).expect("B receives data via relay");
        match tb.decapsulate(None, &got.payload, &mut out) {
            TunnResult::WriteToTunnelV4(pkt, _) => {
                assert_eq!(
                    &pkt[20..],
                    b"HELLO-OVER-RELAY",
                    "decrypted plaintext matches"
                );
            }
            _ => panic!("B should decrypt the app packet"),
        }
    }

    /// G-7: the relay server drops the first connection right after the handshake (a
    /// stand-in for a WiFi↔4G roam killing the TCP leg). The supervisor must reconnect,
    /// re-register, and deliver a frame sent on the SECOND connection to the SAME inbound
    /// channel — proving the leg self-heals without the pump re-wiring anything.
    #[test]
    fn relay_leg_reconnects_after_the_connection_drops() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap().to_string();
        thread::spawn(move || {
            // Connection #1: read ClientHello, answer ServerHello, then kill it.
            let (s1, _) = l.accept().unwrap();
            let mut r1 = BufReader::new(s1.try_clone().unwrap());
            let _ = Frame::read_from(&mut r1); // ClientHello
            Frame::ServerHello.write_to(&mut &s1).unwrap();
            drop(r1);
            drop(s1); // roam: the leg dies

            // Connection #2 (the reconnect): re-register, then deliver a payload.
            let (s2, _) = l.accept().unwrap();
            let mut r2 = BufReader::new(s2.try_clone().unwrap());
            let _ = Frame::read_from(&mut r2); // ClientHello again
            let mut w = &s2;
            Frame::ServerHello.write_to(&mut w).unwrap();
            Frame::Recv {
                src: [0x33u8; 32],
                payload: b"AFTER-RECONNECT".to_vec(),
            }
            .write_to(&mut w)
            .unwrap();
            thread::sleep(Duration::from_secs(2)); // hold the conn open
        });

        let (_client, inbound) =
            RelayClient::connect(&addr, [0x11u8; 32], b"proof".to_vec()).unwrap();
        // First leg is dropped by the server → supervisor reconnects (≥500ms backoff) →
        // the payload sent on connection #2 arrives on the unchanged inbound channel.
        let got = inbound
            .recv_timeout(Duration::from_secs(10))
            .expect("frame delivered after the leg reconnected");
        assert_eq!(got.payload, b"AFTER-RECONNECT");
        assert_eq!(got.src, [0x33u8; 32]);
    }
}
