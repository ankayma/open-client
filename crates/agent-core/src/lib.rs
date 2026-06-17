//! `agent-core` — Deployable 1 · Data Plane / Tunneling (Part B §B.3.4). OPEN.
//! Hexagonal architecture per Part A §A.3.1.
pub mod adapters; // concrete impls of ports
pub mod application; // use cases, orchestration
pub mod domain; // pure business logic, no I/O
pub mod ports; // trait interfaces for external systems

// Node identity = a WireGuard keypair (Part B §B.1.1 `Node`). Surface the crypto
// primitive through agent-core so entrypoints (cli/daemon/GUI) depend on the
// lib, not on `crypto` directly (keeps the A.3.1 hexagonal seam). [T:A.3.1]
pub use crypto::{KeyError, WgKeypair};
