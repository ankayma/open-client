//! `agent-core` — Deployable 1 · Data Plane / Tunneling (Part B §B.3.4). OPEN.
//! Hexagonal architecture per Part A §A.3.1.
pub mod adapters; // concrete impls of ports
pub mod application; // use cases, orchestration
pub mod dataplane; // overlay peer model + packet routing helpers (testable)
pub mod dns; // DNS intercept for Android F-3 private domain (pure, no I/O)
pub mod domain; // pure business logic, no I/O
pub mod oidc; // CI OIDC token fetch for secretless deploy (B-3)
pub mod ports; // trait interfaces for external systems
pub mod pump; // reusable WireGuard packet pump over a tun fd (daemon + iOS extension)
// Windows-specific pump: same tx/rx logic but over Wintun ring buffers, not an fd.
// Lives in agent-core (not agent-daemon) so it can use pub(crate) items in pump.rs.
// [T:A.1.9] gated windows-only; compile-excluded on macOS/Linux/iOS.
#[cfg(target_os = "windows")]
pub mod pump_wintun;
pub mod tundev; // fd-level tun packet I/O (per-platform framing; macOS+iOS shared)
pub mod tunnel; // WireGuard data-plane engine (boringtun)

// Node identity = a WireGuard keypair (Part B §B.1.1 `Node`). Surface the crypto
// primitive through agent-core so entrypoints (cli/daemon/GUI) depend on the
// lib, not on `crypto` directly (keeps the A.3.1 hexagonal seam). [T:A.3.1]
pub use crypto::{key_bytes_from_b64, KeyError, WgKeypair};

// Re-export the HTTP client type so GUI/daemon share one client and never talk
// to the control plane except through this crate's adapters. [T:A.1.1]
pub use reqwest;
