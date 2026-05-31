# client — P2P Zero Trust Platform (OPEN)

**OPEN repo** (Part D §D.2, §D.4). Mô hình Tailscale: client open, control-plane closed.
Contains: mesh agent (Deployable 1), CLI, Client UI (Deployable 5 — Tauri GUI + web admin),
and shared OPEN protocol/domain crates (the agent↔control-plane contract).

License: **TBD** (Part D §D.7). Governance: blueprint Part A/B/C/D.

## Layout
```
crates/   domain-core proto crypto ledger-client agent-core agent-daemon cli
gui/      Tauri 2 shell (src-tauri) — scaffold at milestone 1.1
frontend/ web-tech UI (shared / app-gui / app-admin) — framework TBD
```

## Build
```
cargo check          # Rust crates
```
