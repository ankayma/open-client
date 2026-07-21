//! Frame protocol v0 — DERP-style, custom to this relay `[T:Part D §D.9.2]`.
//!
//! Wire format: `[type: u8][body_len: u32 BE][body]`. Clients are addressed by
//! WireGuard public key; payloads are opaque ciphertext the relay never
//! inspects `[T:A.1.4]`.

use std::io::{self, Read, Write};

/// Protocol version, carried in `ClientHello`. The server rejects mismatches.
/// TODO[A]: no negotiation yet — revisit when client integration lands and we
/// know whether rolling upgrades need version skew tolerance.
pub const PROTO_VERSION: u8 = 0;

/// WireGuard public key length — the relay addressing unit `[T:Part D §D.9.2]`.
pub const KEY_LEN: usize = 32;

/// Hard cap on a frame body. A max-size WireGuard datagram fits with room to
/// spare; anything larger is a protocol violation, not a big packet.
/// [A] tune against the client's overlay MTU (1420) once integration exists.
pub const MAX_BODY_LEN: usize = 64 * 1024;

pub type Key = [u8; KEY_LEN];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    /// First frame on a connection. `auth` is an opaque membership proof the
    /// server hands to the control-plane verify hook `[T:Part D §D.9.3]`; its
    /// shape is owned by the control plane and never parsed here (leak-check
    /// rule 2: no CP logic in this repo).
    ClientHello {
        pubkey: Key,
        auth: Vec<u8>,
    },
    /// Server accepts the hello; the client may start sending.
    ServerHello,
    /// Client → server: forward `payload` (ciphertext) to `dst`.
    Send {
        dst: Key,
        payload: Vec<u8>,
    },
    /// Server → client: `payload` (ciphertext) from `src`.
    Recv {
        src: Key,
        payload: Vec<u8>,
    },
    Ping,
    Pong,
    /// Server → client: a peer this client tried to reach is not connected.
    PeerGone {
        peer: Key,
    },
}

const T_CLIENT_HELLO: u8 = 1;
const T_SERVER_HELLO: u8 = 2;
const T_SEND: u8 = 3;
const T_RECV: u8 = 4;
const T_PING: u8 = 5;
const T_PONG: u8 = 6;
const T_PEER_GONE: u8 = 7;

impl Frame {
    fn type_id(&self) -> u8 {
        match self {
            Frame::ClientHello { .. } => T_CLIENT_HELLO,
            Frame::ServerHello => T_SERVER_HELLO,
            Frame::Send { .. } => T_SEND,
            Frame::Recv { .. } => T_RECV,
            Frame::Ping => T_PING,
            Frame::Pong => T_PONG,
            Frame::PeerGone { .. } => T_PEER_GONE,
        }
    }

    fn body(&self) -> Vec<u8> {
        match self {
            Frame::ClientHello { pubkey, auth } => {
                let mut b = Vec::with_capacity(1 + KEY_LEN + auth.len());
                b.push(PROTO_VERSION);
                b.extend_from_slice(pubkey);
                b.extend_from_slice(auth);
                b
            }
            Frame::ServerHello | Frame::Ping | Frame::Pong => Vec::new(),
            Frame::Send { dst: key, payload } | Frame::Recv { src: key, payload } => {
                let mut b = Vec::with_capacity(KEY_LEN + payload.len());
                b.extend_from_slice(key);
                b.extend_from_slice(payload);
                b
            }
            Frame::PeerGone { peer } => peer.to_vec(),
        }
    }

    /// Serialize to the wire form `[type][len BE][body]`.
    pub fn encode(&self) -> Vec<u8> {
        let body = self.body();
        debug_assert!(body.len() <= MAX_BODY_LEN);
        let mut out = Vec::with_capacity(5 + body.len());
        out.push(self.type_id());
        out.extend_from_slice(&(body.len() as u32).to_be_bytes());
        out.extend_from_slice(&body);
        out
    }

    /// Validate a 5-byte header and return the declared body length. The
    /// MAX_BODY_LEN guard lives here so the sync and async readers share it.
    pub fn parse_header(header: &[u8; 5]) -> io::Result<usize> {
        let len = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
        if len > MAX_BODY_LEN {
            return Err(invalid(format!("frame body {len} exceeds {MAX_BODY_LEN}")));
        }
        Ok(len)
    }

    /// Decode from type byte + already-read body. Pure (no I/O) so every
    /// transport — sync `read_from`, async reader in relay-server — validates
    /// identically.
    pub fn parse(type_byte: u8, body: Vec<u8>) -> io::Result<Frame> {
        match type_byte {
            T_CLIENT_HELLO => {
                if body.len() < 1 + KEY_LEN {
                    return Err(invalid("ClientHello too short"));
                }
                if body[0] != PROTO_VERSION {
                    return Err(invalid(format!(
                        "protocol version {} unsupported (want {PROTO_VERSION})",
                        body[0]
                    )));
                }
                Ok(Frame::ClientHello {
                    pubkey: read_key(&body[1..1 + KEY_LEN]),
                    auth: body[1 + KEY_LEN..].to_vec(),
                })
            }
            T_SERVER_HELLO => expect_empty(&body, Frame::ServerHello),
            T_SEND => {
                let (key, payload) = split_keyed(&body, "Send")?;
                Ok(Frame::Send { dst: key, payload })
            }
            T_RECV => {
                let (key, payload) = split_keyed(&body, "Recv")?;
                Ok(Frame::Recv { src: key, payload })
            }
            T_PING => expect_empty(&body, Frame::Ping),
            T_PONG => expect_empty(&body, Frame::Pong),
            T_PEER_GONE => {
                if body.len() != KEY_LEN {
                    return Err(invalid("PeerGone body must be exactly one key"));
                }
                Ok(Frame::PeerGone {
                    peer: read_key(&body),
                })
            }
            t => Err(invalid(format!("unknown frame type {t}"))),
        }
    }

    pub fn write_to<W: Write>(&self, w: &mut W) -> io::Result<()> {
        w.write_all(&self.encode())
    }

    pub fn read_from<R: Read>(r: &mut R) -> io::Result<Frame> {
        let mut header = [0u8; 5];
        r.read_exact(&mut header)?;
        let len = Frame::parse_header(&header)?;
        let mut body = vec![0u8; len];
        r.read_exact(&mut body)?;
        Frame::parse(header[0], body)
    }
}

fn split_keyed(body: &[u8], what: &str) -> io::Result<(Key, Vec<u8>)> {
    if body.len() < KEY_LEN {
        return Err(invalid(format!("{what} body shorter than one key")));
    }
    Ok((read_key(&body[..KEY_LEN]), body[KEY_LEN..].to_vec()))
}

fn expect_empty(body: &[u8], frame: Frame) -> io::Result<Frame> {
    if body.is_empty() {
        Ok(frame)
    } else {
        Err(invalid("frame carries an unexpected body"))
    }
}

fn read_key(slice: &[u8]) -> Key {
    let mut k = [0u8; KEY_LEN];
    k.copy_from_slice(slice);
    k
}

fn invalid(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn roundtrip(f: Frame) {
        let mut buf = Vec::new();
        f.write_to(&mut buf).unwrap();
        let back = Frame::read_from(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(f, back);
    }

    #[test]
    fn roundtrip_all_variants() {
        roundtrip(Frame::ClientHello {
            pubkey: [0xAA; 32],
            auth: b"opaque-proof".to_vec(),
        });
        roundtrip(Frame::ServerHello);
        roundtrip(Frame::Send {
            dst: [0xBB; 32],
            payload: vec![1, 2, 3],
        });
        roundtrip(Frame::Recv {
            src: [0xCC; 32],
            payload: vec![],
        });
        roundtrip(Frame::Ping);
        roundtrip(Frame::Pong);
        roundtrip(Frame::PeerGone { peer: [0xDD; 32] });
    }

    /// DRIFT GUARD — the exact v0 wire bytes, shared verbatim with the relay-server
    /// repo's identical test. This crate is a vendored copy; if the encoding here ever
    /// changes, THIS test (and its twin in the SSOT repo) must change in lockstep — a
    /// silent divergence means the client and the relay disagree on the wire, which no
    /// roundtrip test on one side alone can catch. Bytes are built structurally (not a
    /// hex blob) so the layout is legible: `[type][len u32 BE][body]`. `[T:D.9.5 rule 4]`
    #[test]
    fn golden_wire_vector_send() {
        let f = Frame::Send {
            dst: [0xBB; 32],
            payload: vec![0x01, 0x02, 0x03],
        };
        let mut expected = vec![T_SEND, 0x00, 0x00, 0x00, 0x23]; // type=3, body_len=35 BE
        expected.extend_from_slice(&[0xBB; 32]); // dst key
        expected.extend_from_slice(&[0x01, 0x02, 0x03]); // payload
        assert_eq!(f.encode(), expected, "Send wire layout is the v0 contract");
    }

    /// DRIFT GUARD (twin of the above) — `ClientHello`, the one body that carries the
    /// PROTO_VERSION byte, so this pins the version's on-wire position too.
    #[test]
    fn golden_wire_vector_client_hello() {
        let f = Frame::ClientHello {
            pubkey: [0xAA; 32],
            auth: vec![0x78], // "x"
        };
        let mut expected = vec![T_CLIENT_HELLO, 0x00, 0x00, 0x00, 0x22]; // type=1, body_len=34 BE
        expected.push(PROTO_VERSION); // version byte leads the body
        expected.extend_from_slice(&[0xAA; 32]); // pubkey
        expected.push(0x78); // auth
        assert_eq!(
            f.encode(),
            expected,
            "ClientHello wire layout (incl. version byte) is the v0 contract"
        );
    }

    #[test]
    fn rejects_oversized_body() {
        let mut buf = vec![T_SEND];
        buf.extend_from_slice(&((MAX_BODY_LEN as u32) + 1).to_be_bytes());
        let err = Frame::read_from(&mut Cursor::new(&buf)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn rejects_wrong_version() {
        let f = Frame::ClientHello {
            pubkey: [0xAA; 32],
            auth: vec![],
        };
        let mut buf = Vec::new();
        f.write_to(&mut buf).unwrap();
        buf[5] = PROTO_VERSION + 1; // version byte = first body byte
        let err = Frame::read_from(&mut Cursor::new(&buf)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn rejects_truncated_frame() {
        let f = Frame::Send {
            dst: [0xBB; 32],
            payload: vec![9; 8],
        };
        let mut buf = Vec::new();
        f.write_to(&mut buf).unwrap();
        buf.truncate(buf.len() - 1);
        let err = Frame::read_from(&mut Cursor::new(&buf)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn rejects_unknown_type() {
        let mut buf = vec![0x7F];
        buf.extend_from_slice(&0u32.to_be_bytes());
        let err = Frame::read_from(&mut Cursor::new(&buf)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}
