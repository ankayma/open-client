# Ankayma — Sovereign Zero-Trust Mesh (OPEN client)

**Ankayma** is a **sovereign identity-aware zero-trust mesh**: the vendor *cannot decrypt* customer data, and customers can **verify that themselves** rather than taking the vendor's word for it `[T per brand-positioning + A.1.4]`.

Unlike Cloudflare / Zscaler / Tailscale — where customer traffic flows through the vendor's own infrastructure — Ankayma **strictly separates the data plane from the control plane**, so customer business data *never* transits Ankayma infrastructure. This sovereignty is **structural, not a configuration setting** `[T per A.1.1 + P.7]`.

This repo is the **OPEN half** of Ankayma, following the *Tailscale model*: **open client, closed control plane** `[T per Part D §D.2]`. Everything that runs on the customer's machine lives here and is auditable; control-plane logic (broker / identity / policy / audit / edge / billing / ML) lives in a separate private repo and is *never* committed here `[T per A.1.4 + P.7]`.

> **SSOT** `[T per P.5 + P.9]`: the source of truth is the **blueprint** (Part 0/A/B/C/D) + brand-positioning. This README and [`ARCHITECTURE.md`](./ARCHITECTURE.md) *reference* those documents by name + section — they do not copy content. When code conflicts with a Part A invariant, **Part A wins**.

---

## 1. Three brand pillars

Every architectural decision here serves three brand pillars (`[T per brand-positioning]`):

1. **Sovereignty is the core** — data plane separated from control plane (A.1.1); vendor cannot decrypt (A.1.4); per-tenant isolation with a separate root key per Product Line (A.1.23/A.1.18). This is the moat — the hub-spoke model competitors use cannot replicate it without rebuilding from the foundation.
2. **Honesty is the trust differentiator** — every gap and unverified claim is disclosed publicly with its current status, instead of marketing "unhackable" `[T per P.3]`. Security and compliance teams *reward* honesty.
3. **Augments, does not replace** — enable security without disrupting existing systems; layer identity-aware overlay on top of customers' existing investments `[T per P.4]`.

---

## 2. What this repo is

Ankayma has two code repos `[T per Part D §D.4]`:

| Repo | Contents | Status |
|---|---|---|
| **open-client** (this repo) | mesh agent + CLI + Client UI + shared OPEN contract | **PUBLIC** from Day 1 |
| control-plane | broker, identity, policy, audit, edge, billing, ML | private |

**Deployable units here** `[T per Part D §D.1.3]`:

1. **Mesh Agent** — WireGuard data-plane agent, 5 platforms (Linux / macOS / Windows / iOS / Android). Runs on customer nodes.
2. **Client UI** — desktop + mobile GUI (Tauri 2) + web admin console frontend.
3. **CLI** — management tool built on `agent-core` (not a standalone unit).

An **OPEN, auditable** agent is how Ankayma proves sovereignty: customers read and verify the code running on their nodes rather than trusting the vendor `[T per A.1.4 + P.7]`.

---

## 3. One brand, two product lines

One umbrella brand (Ankayma) covers **two fully separated product lines** — each with its own root key / infrastructure / threat model `[T per P.6 + brand-positioning]`. But **one codebase**: PL is a *deployment dimension*, not a code-split axis — no forking crates by PL `[T per A.1.9 + Part D §D.1.2]`.

| Line | Tier | Features | Infra | Namespace | Role |
|---|---|---|---|---|---|
| **Personal** | Tier A | F0 · F0-Plus · F1 Starter | shared (logical isolation) | `personal.tenant.<id>.>` | acquisition funnel + credibility proof |
| **Enterprise** | Tier B | F1 Growth · F2 Growth · F3 Enterprise | dedicated NATS + RDS from Day 1 (A.1.23) | `enterprise.tenant.<id>.>` | revenue engine + moat |

- Every entity/subject carries `product_line` + `tenant_id` from Day 1 `[T per A.1.11 + A.3.6]`.
- *F1 Starter ≠ F1 Growth* — same number, different PL, different infra.
- Cross-PL = create a new `Customer`, **not** a tier transition `[T per A.1.14 + Part B §B.1.1]`.

**Entity hierarchy** (Part B §B.1.1): `Organization`* → `Customer` (billing, 1 PL) → `Tenant` (technical isolation, 1 NATS Account) → `Workspace`* → `Node` / `User`. (`Organization`/`Workspace` = governance layer **not yet implemented** — see §7.)

---

## 4. Structure

```
crates/
  domain-core     shared entity types (Customer, Tenant, Node, ProductLine…) — agent-side scope
  proto           gRPC Agent API + REST Admin API contract types (B.5.1 / B.5.2)
  crypto          crypto primitives — intensity Critical, cite every primitive
  ledger-client   append-only ledger client-side verify (A.1.8)
  agent-core      agent core lib — independent lib so the framework is swappable (D.3.1)
  agent-daemon    process daemon → bin `agent` (+ `agent-nc-escrow`, feature key-escrow-build)
  cli             CLI shell on agent-core → bin `mesh`
gui/
  src-tauri       Tauri 2 shell — scaffolded at milestone 1.1
frontend/
  shared          web-tech UI shared across GUI + web admin
  app-gui         desktop + mobile GUI frontend
  app-admin       web admin console frontend
docs/             invariant-trace · concept-trace · qc-discipline · phase-completion-checklist · public site (index/honest-limits/privacy/terms)
```

**Hexagonal (A.3.1)** `[T per A.3.1 + Part D §D.1.5]`: each major component is one crate with a port/adapter seam. The 11 bounded contexts (Part B §B.3) are the seams for future microservice extraction — domain must not leak across crates.

**Shared contract** = `proto` + `domain-core`: the control plane depends inward on these two crates. Changing the contract changes both sides → **requires careful human review** `[T per Part D §D.4]`. Crate-to-bounded-context mapping: [`ARCHITECTURE.md`](./ARCHITECTURE.md) §H.2.

---

## 5. Binding invariants (violation = STOP, flag to human)

Full text in Part A §A.1; index + code consequences in [`ARCHITECTURE.md`](./ARCHITECTURE.md) §H.3.

| ID | Summary | Code consequence |
|---|---|---|
| **A.1.1** | data plane ≠ control plane | no control-plane logic inside the agent |
| **A.1.4** | agent OPEN, customer-auditable | keep `agent-core` as an independent, auditable lib |
| **A.1.9** | single codebase, no Tier A vs Tier B fork | PL = deploy dimension, not a crate-split axis |
| **A.1.11** | per-PL namespace from Day 1 | every entity/subject carries `product_line` + `tenant_id` |
| **A.1.20** | agent update + capability negotiation | old agents degrade gracefully; rollback is safe |
| **A.1.21** | supply-chain integrity | pin dep versions, no dynamic plugins, signed commits + Cosign |
| **A.1.23** | per-PL infra isolation | leave room for per-PL config; do not hardcode single-PL assumptions |
| **A.1.24** | Org/Workspace = governance, not isolation | do not model Org/Workspace as infra isolation boundaries |
| **A.3.1** | hexagonal, one component = one crate | maintain port/adapter seams |
| **A.4.1** | agent-daemon NFR `[A]` (latency, <100 MB) | GUI numbers do not count against this budget; A.4 not yet measured |

---

## 6. Current scope — Milestone 1.1 (Founding skeleton)

Scope gate (P.8): only build what the current Part C milestone authorizes. **Do not** pre-build future phases `[T per Part C §H.3.1 + §H.7.2]`.

**Building now**: Rust workspace + WireGuard agent core (5-platform compile) · Tauri 2 UI shell · Personal Provisioning CA skeleton (SingleCustodian, ceremony rehearsed once non-prod) · CI/CD baseline (hosted CI + Cosign) · Enterprise PL skeleton **in code** (namespace + schema + ceremony procedure, **ZERO infra**) · client repos public Day 1.

**Not building (anti-pattern guard P.8)**: Phase 2 infra (Shamir ceremony, dedicated NATS/RDS) · `Organization`/`Workspace`/delegation (A.1.24, waiting for trigger L_subsidiary) · F3 capability (HSM / Conf VM / BYOK, waiting for F3 customer) · "Enterprise-*" parallel crates (direct A.1.9 violation).

> Completion criteria + CI gates: [`docs/phase-completion-checklist-1.1.md`](./docs/phase-completion-checklist-1.1.md).

---

## 7. What Ankayma is NOT (anti-positioning, P.3)

Epistemic honesty — do not read more into this repo than it actually commits to `[T per P.3]`:

- **NOT** "unhackable" / fear-based positioning. Let the architecture and the public weakness table (A.1.12) speak for themselves.
- **NOT** price-led; positioning is about *structure*.
- **NOT** generic SASE / consumer VPN / SOC-as-a-service.
- **NOT** "dedicated infra Day 1" in the sense of physical-machine-per-customer or Confidential VM — F3 capability (HSM, Conf VM, BYOK) **is not yet built**, activated by trigger (P.8).
- **NFR not yet measured**: all of A.4 = `[A]`; Tauri 2 mobile "stable but not yet first-class". Do not quote NFR numbers as guaranteed.

---

## 8. Build & test

```bash
cargo fmt --check
cargo clippy -- -D warnings
cargo check
cargo test
# GUI: cargo tauri dev   (requires Tauri toolchain)
# frontend: see frontend/README.md
```

Toolchain: Rust stable (version will be pinned before production — A.1.21). Before marking anything done: run all four commands above and **report the real output** — if it fails, say so `[T per P.3]`. See [`CONTRIBUTING.md`](./CONTRIBUTING.md) for the Definition of Done.

---

## 9. Governance & status

- **Working model**: Claude Code authoring, human review + QC test. Workflow in [`CONTRIBUTING.md`](./CONTRIBUTING.md).
- **License**: **Elastic License 2.0 (ELv2)** (see [`LICENSE`](./LICENSE) + [`NOTICE`](./NOTICE)) `[T per Part D §D.7 — owner-chosen 2026-06-17; switched Apache-2.0 → ELv2 2026-07-10]`. Source-available: use, copy, modify, and distribute freely, but you may not offer it to third parties as a hosted or managed service. Includes a patent grant. Contributions submitted to this repo default to ELv2.
- **Frontend framework**: Svelte (SvelteKit + Tauri webview).

> Read before editing code: [`ARCHITECTURE.md`](./ARCHITECTURE.md) (crate map + invariant index) → then the relevant blueprint section.
