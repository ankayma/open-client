//! relay-core — pure, dep-free relay protocol primitives: frame codec and rate
//! limiting.
//!
//! **Vendored** `[T:Part D §D.9.5 rule 3]`: this is an embedded copy of the relay-server
//! repo's `relay-core` (its SSOT). The agent embeds it so the PUBLIC client builds
//! standalone — no cross-repo path-dep. Keep byte-compatible with the SSOT; the golden
//! wire-vector test in `frame` guards drift on both sides.
//!
//! Boundary `[T:Part D §D.9.5]`: this crate lives in a PUBLIC repo. It must never
//! contain control-plane logic. The relay addresses clients by WireGuard public key and
//! forwards opaque ciphertext only `[T:A.1.4]` — no crypto primitives live here by design.
//!
//! Runtime-agnostic on purpose: `frame` encodes/decodes to/from bytes and does no I/O,
//! so the async runtime + routing live in relay-server. Keeps this crate free of tokio
//! (small TCB for the auditor, per D.9.1).

pub mod frame;
pub mod limit;
