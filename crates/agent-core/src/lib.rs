//! `agent-core` — Deployable 1 · Data Plane / Tunneling (Part B §B.3.4). OPEN.
//! Hexagonal architecture per Part A §A.3.1.
pub mod adapters; // concrete impls of ports
pub mod application; // use cases, orchestration
pub mod dataplane; // overlay peer model + packet routing helpers (testable)
pub mod dns; // F-3 private-DNS responder + raw IP/UDP framing (daemon + iOS extension)
pub mod domain; // pure business logic, no I/O
pub mod machine_key; // stable per-device identity proven at enrollment (Ed25519)
pub mod oidc; // CI OIDC token fetch for secretless deploy (B-3)
pub mod ports; // trait interfaces for external systems
pub mod pump; // reusable WireGuard packet pump over a tun fd (daemon + iOS extension)
pub mod ssh_client; // F-2 NoKeySSH client transport (russh) — CLI + GUI + iOS terminal
pub mod ssh_grant; // F-2 root-elevation grant (Ed25519 sign/verify) — CP issues, node verifies
pub mod ssh_server; // F-2 NoKeySSH embedded server (russh + PTY) — runs on target nodes
pub mod status; // data-plane status snapshot + heartbeat (daemon + iOS extension) → GUI path-proof
pub mod tundev; // fd-level tun packet I/O (per-platform framing; macOS+iOS shared)
pub mod tunnel; // WireGuard data-plane engine (boringtun)

// Node identity = a WireGuard keypair (Part B §B.1.1 `Node`). Surface the crypto
// primitive through agent-core so entrypoints (cli/daemon/GUI) depend on the
// lib, not on `crypto` directly (keeps the A.3.1 hexagonal seam). [T:A.3.1]
pub use crypto::{key_bytes_from_b64, KeyError, WgKeypair};

// Layer 2 node-cert utilities (expiry warning, post-enroll chain sanity check)
// — same seam rule as above. [T:part-d-layer2-cert-infrastructure.md §H.2]
pub use crypto::cert;

// Re-export the HTTP client type so GUI/daemon share one client and never talk
// to the control plane except through this crate's adapters. [T:A.1.1]
pub use reqwest;

/// Home base for `~/.ankayma/…` — the single resolver every entrypoint (cli, daemon,
/// GUI) must use so they agree on one state dir per platform. HOME on unix;
/// USERPROFILE on Windows (HOME is usually unset there); `.` (CWD) only as a last
/// resort. Duplicating this per crate is what let the daemon get the USERPROFILE
/// fallback while the GUI kept reading an empty HOME and persisting identity to a
/// relative `.ankayma` under an unwritable CWD. Keep it here, call it everywhere.
/// [T:A.1.3; part-d-node-identity-device-binding.md §H.7 1.5]
pub fn home_root() -> String {
    std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_else(|_| ".".into())
}
