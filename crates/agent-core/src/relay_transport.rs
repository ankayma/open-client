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
use std::sync::{Arc, Mutex};
use std::thread;

use relay_core::frame::{Frame, Key};

/// One inbound ciphertext delivery from the relay: `src` is the peer's WireGuard
/// public key (a precise sender identity — better than the UDP path's IP guess),
/// `payload` is the opaque WireGuard ciphertext to feed into `Tunn::decapsulate`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayInbound {
    pub src: Key,
    pub payload: Vec<u8>,
}

/// A live relay leg: a registered connection to one relay, addressed by this node's
/// WireGuard public key. Clone-cheap (shares the write half); the reader thread feeds
/// a channel the pump drains.
#[derive(Clone)]
pub struct RelayClient {
    tx: Arc<Mutex<TcpStream>>,
}

impl RelayClient {
    /// Connect to `relay_addr`, register under `my_pubkey` via `ClientHello`, and wait
    /// for `ServerHello`. `auth` is the opaque membership proof (the node's service
    /// token) — the relay forwards it to the control-plane verify hook and never parses
    /// it here `[T:A.1.6]`. A relay that fails membership verification never answers
    /// `ServerHello`, so a refused hello surfaces as a fail-closed error.
    ///
    /// Returns the client (for sending) and the inbound channel (for the pump's relay
    /// ingress thread to drain into `decapsulate`).
    pub fn connect(
        relay_addr: &str,
        my_pubkey: Key,
        auth: Vec<u8>,
    ) -> io::Result<(RelayClient, Receiver<RelayInbound>)> {
        let stream = TcpStream::connect(relay_addr)?;
        stream.set_nodelay(true).ok();
        let mut reader = BufReader::new(stream.try_clone()?);
        let tx = Arc::new(Mutex::new(stream));

        {
            let mut w = tx.lock().expect("relay tx lock");
            Frame::ClientHello {
                pubkey: my_pubkey,
                auth,
            }
            .write_to(&mut *w)?;
        }
        match Frame::read_from(&mut reader)? {
            Frame::ServerHello => {}
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "relay refused hello (fail-closed: membership not verified)",
                ))
            }
        }

        let (itx, irx) = mpsc::channel();
        thread::spawn(move || recv_loop(reader, itx));
        Ok((RelayClient { tx }, irx))
    }

    /// Forward WireGuard `ciphertext` to peer `dst` (its WG public key) via the relay.
    /// Best-effort, UDP semantics `[T:A.1.4]`: a write error is dropped rather than
    /// surfaced — the inner WireGuard session retransmits on its own timer, so a lost
    /// relayed datagram costs at most one handshake RTT, never a torn tunnel.
    pub fn send(&self, dst: Key, ciphertext: &[u8]) {
        if let Ok(mut w) = self.tx.lock() {
            let _ = Frame::Send {
                dst,
                payload: ciphertext.to_vec(),
            }
            .write_to(&mut *w);
        }
    }
}

/// Decode relay frames off the connection, forwarding inbound ciphertext to the pump.
/// Exits when the channel receiver is dropped or the relay connection closes.
fn recv_loop(mut reader: BufReader<TcpStream>, out: Sender<RelayInbound>) {
    loop {
        match Frame::read_from(&mut reader) {
            Ok(Frame::Recv { src, payload }) => {
                if out.send(RelayInbound { src, payload }).is_err() {
                    break; // pump gone
                }
            }
            // The peer we addressed has no live relay registration. Nothing to do at
            // the relay layer — a direct/hole-punched path may still exist, and WG
            // retransmits regardless. Dropping matches UDP semantics.
            Ok(Frame::PeerGone { .. }) => {}
            // ServerHello (already consumed at connect), Ping/Pong, or anything else:
            // not payload-bearing for the pump.
            Ok(_) => {}
            Err(_) => break, // relay connection closed
        }
    }
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
}
