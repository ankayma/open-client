# Architecture — client/ (OPEN)

> **SSOT pointer, không phải bản sao** `[T per P.5 + Part D §D.4]`: file này **trỏ** vào blueprint theo tên + section. Nguồn chân lý là Part 0/A/B/C/D trong doc repo `workspace/`. Khi xung đột: **Part A invariant > quyết định ở đây**.

## Repo này là gì

Phần **OPEN** của P2P Zero Trust Platform (mô hình Tailscale: client open, control-plane closed — Part D §D.2). Chứa code chạy trên/cho thiết bị customer + contract agent↔control-plane.

**Deployable units ở repo này** (Part D §D.1.3):
- **#1 Mesh Agent** (5 platform) — chạy trên customer node. OPEN per A.1.4.
- **#5 Client UI** — desktop+mobile GUI (Tauri 2, D.3) + web admin console frontend.
- **CLI** — crate mỏng trong workspace (không phải deployable độc lập).

**KHÔNG** thuộc repo này (sống ở `control-plane/` private): broker, identity, policy, audit, lifecycle, edge, WAF/DLP inspection, tier-feature-set, billing, detection/ML (Part D §D.2 CLOSED).

## Crate map → bounded context (Part B §B.3, Part D §D.1.5)

| Crate | Vai trò | Open/closed |
|---|---|---|
| `domain-core` | entity types (gồm `product_line`) | OPEN (shared contract) |
| `proto` | gRPC Agent API + REST Admin API (Part B §B.5) | OPEN (shared contract) |
| `crypto` | crypto primitives | OPEN |
| `ledger-client` | append-only ledger client side (A.1.8) | OPEN |
| `agent-core` | lib lõi agent — **lib độc lập** để framework swappable (D.3.1) | OPEN |
| `agent-daemon` | process daemon (NFR A.4.1) | OPEN |
| `cli` | CLI shell trên agent-core | OPEN |
| `gui/src-tauri` | Tauri 2 shell — scaffold tại milestone 1.1 (`cargo tauri init`) | OPEN (thin) |
| `frontend/{shared,app-gui,app-admin}` | web-tech UI tái dùng cho GUI + web admin (D.3.2) | OPEN |

> `proto` + `domain-core` = contract dùng chung; `control-plane/` depends ngược vào chúng (D.4). Đổi contract = đổi cả hai phía → cần human review kỹ.

## Binding invariants index (full text trong Part A §A.1.x)

A.1.1 data/control tách tuyệt đối · A.1.4 agent OPEN auditable · A.1.9 single codebase (PL = deploy dim, không fork code — D.1.2) · A.1.20 capability negotiation (agent cũ graceful degrade) · A.1.21 supply-chain (pin dep, no dynamic plugin) · A.3.1 hexagonal 1-component-1-crate · A.4.1 agent-daemon NFR (<100MB — **không** áp cho GUI).

## UI framework

**Tauri 2** cho Phase 1-2 (Part D §D.3). Flutter là P.8-trigger reassess nếu consumer-mobile-polish chứng minh là viral lever (D.3.3). Vì agent-core là lib riêng, swap shell rẻ — đừng couple business logic vào GUI layer.

## Build & test

```bash
cargo fmt --check
cargo clippy -- -D warnings
cargo check
cargo test
# GUI (sau milestone 1.1): cargo tauri dev   (cần Tauri toolchain)
# frontend: theo frontend/README khi framework chốt (D.3.2 TBD)
```

## License
**TBD** (Part D §D.7) — chốt trước khi public repo. Hiện `Cargo.toml` để `license = "TBD"`.
