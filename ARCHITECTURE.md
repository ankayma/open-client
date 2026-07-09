# Architecture — client/ (OPEN)

> **Scope**: crate map · deployable units · open/closed boundary · binding invariants index · current scope.
> **SSOT** `[T per P.5 + Part D §D.4]`: this file **points** to the blueprint by *name + section* (Part 0/A/B/C/D in `workspace/`), does not copy content. Code conflicting with a Part A invariant → **Part A wins**.
>
> **How to read** (inverted pyramid, D-00 §4):
> - **[H] — For coder/owner: understand & make decisions.** Reading all of [H] is enough to write the first line of code correctly. At the end of [H] is **"Owner's responsibilities"** gathering decisions that humans must own.
> - **[R] — Verification section** (at the end): traces each crate/decision back to Part A/B/C/D, T/A markings, `[A]` list, log. Can be skipped when reading quickly.

-----
-----

# [H] — For coder/owner

## H.0 — Executive summary

This repo = **the OPEN portion** of the P2P Zero Trust Platform (exact Tailscale model — client open, control-plane closed) `[T per Part D §D.2 + Tailscale precedent]`. Contains **3 units**: Mesh Agent (5 platforms) + Client UI (Tauri 2 + web admin frontend) + CLI. Every crate in this repo = OPEN; control-plane logic (broker/identity/policy/audit/edge/ML/billing) lives in the private `control-plane/` — *never* commit it here `[T per A.1.4 + Part D §D.4]`.

**Four load-bearing commitments:**
1. **Single codebase serving 2 Product Lines** (Personal Tier A + Enterprise Tier B) via deployment config, no crate forking `[T per A.1.9 + Part D §D.1.2]`.
2. **Hexagonal, each major component = 1 crate** — port/adapter seams maintain the boundary of 11 bounded contexts (B.3.x), seams split into microservices later `[T per A.3.1 + Part D §D.1.5/1.6]`.
3. **Agent OPEN auditable** — customers audit code running on their nodes; this is part of the moat `[T per A.1.4 + P.7]`. Open-source rollout from Day 1 (milestone 1.1/1.2) `[T per Part C §H.1.4]`.
4. **Scope gate (P.8)** — only build what the current Part C milestone authorizes; DO NOT pre-build Phase 2 infra / Org/Workspace (A.1.24) / F3 capabilities (HSM/Conf VM/BYOK) before the trigger `[T per Part C §H.7.2 anti-pattern]`.

> ⚠️ **Epistemic honesty**: license = Apache-2.0 `[T per owner 2026-06-17]`; all NFR A.4 = `[A]` unmeasured (owner confirmed Part A H.7 #5); Tauri 2 mobile is "stable but not yet first-class" `[T per Tauri team, Part D §D.3.2]` — reassess trigger if consumer-mobile-polish becomes a viral lever.

-----

## H.1 — What this repo is and is not

**Deployable units in this repo** `[T per Part D §D.1.3]`:

| # | Unit | Runs where | Bounded context | Milestone |
|---|---|---|---|---|
| 1 | **Mesh Agent** (5 platforms: Linux/macOS/Windows/iOS/Android) | Customer node | B.3.4 Data Plane + Agent API client | 1.1 core, 1.2 broker integration |
| 5 | **Client UI** (desktop+mobile GUI + web admin console frontend) | Customer device + browser | UI layer | 1.1 "hello world" |
| — | **CLI** (auxiliary, not standalone) | Customer machine | A.2.1 management | 1.1 skeleton |

**NOT in this repo** (lives in private `control-plane/`) `[T per Part D §D.2 + §D.4]`:
broker · identity · policy · audit · lifecycle · edge channel · WAF/DLP inspection sidecar · tier-feature-set · billing · detection/ML. If in doubt whether something belongs to control-plane → it does **not** belong here.

**Product Line** `[T per A.1.9 + Part B §B.1.1]`:
- **Personal (Tier A)** — F0, F0-Plus, F1 Starter. Shared infra (logical isolation). Namespace `personal.tenant.<id>.>`.
- **Enterprise (Tier B)** — F1 Growth, F2 Growth, F3 Enterprise. Dedicated NATS Account + RDS schema from Day 1 (A.1.23). Namespace `enterprise.tenant.<id>.>`.
- *F1 Starter ≠ F1 Growth* — same number, different PL, different infra. Cross-PL migration = create a new `Customer` (Part B §B.1.8), not a tier transition `[T per Part A §A.1.14 + Part B §B.1.1]`.

-----

## H.2 — Crate map → bounded context

| Crate | Role | Layer (A.3.1) | Open/closed |
|---|---|---|---|
| `domain-core` | shared entity types (`Customer`, `Tenant`, `Node`, `ProductLine` discriminator…) — agent-side scope | domain | OPEN (shared contract) |
| `proto` | gRPC Agent API (B.5.1) + REST Admin API contract types (B.5.2) | ports/contract | OPEN (shared contract) |
| `crypto` | crypto primitives (cite every primitive `[T per source]` — intensity Critical) | adapter | OPEN |
| `ledger-client` | append-only ledger verify client-side (A.1.8) | adapter | OPEN |
| `agent-core` | agent core lib — **standalone lib** so the framework is swappable (D.3.1) | domain + application + ports | OPEN |
| `agent-daemon` | process daemon (NFR A.4.1) | adapter/entrypoint | OPEN |
| `cli` | CLI shell on top of agent-core | adapter/entrypoint | OPEN |
| `gui/src-tauri` | Tauri 2 shell — scaffolded at milestone 1.1 (`cargo tauri init`) | adapter/entrypoint | OPEN (thin) |
| `frontend/{shared,app-gui,app-admin}` | reusable web-tech UI for GUI + web admin (D.3.2) | adapter/entrypoint | OPEN |

**Shared contract**: `proto` + `domain-core` — `control-plane/` depends inversely on them `[T per Part D §D.4]`. Changing the contract = changing both sides → **requires careful human review**.

> **A.1.24 deferred**: `Organization` / `Workspace` (Part B §B.1.1, ratified owner 2026-06-05) is a **governance layer not yet implemented**. Construct is gated by trigger `L_subsidiary`, milestone 2.3/3.3 `[T per Part C §H.6]`. DO NOT pre-add to `domain-core` at milestone 1.1 — anti-pattern Part C §H.7.2 ("pre-build Org/Workspace/delegation before L_subsidiary").

-----

## H.3 — Binding invariants index (full text in Part A §A.1.x)

Violating any of these = **STOP, report to human** (amend Part A first, do not decide unilaterally). Full text Part A `[T per Part A §A.1]`.

| ID | 1-line summary | Coding consequence |
|---|---|---|
| **A.1.1** | data plane ≠ control plane, absolute separation | do not embed control-plane logic in the agent |
| **A.1.4** | agent OPEN, customers can audit | keep agent-core as a standalone auditable lib |
| **A.1.9** | single codebase, DO NOT fork Personal Tier A vs Enterprise Tier B | PL = deployment dimension, not a code split axis (D.1.2) |
| **A.1.11** | namespace per-PL from Day 1 (`<pl>.tenant.<id>.>`) | every entity/subject carries `product_line` + `tenant_id` (A.3.6) |
| **A.1.20** | agent update + capability negotiation (D.1.7) | old agent graceful degradation; safe rollback; force-upgrade per SLO |
| **A.1.21** | supply-chain integrity | pin dep versions, do not add dependencies arbitrarily, no dynamic plugin, signed commit + Cosign artifact |
| **A.1.23** | per-PL infra isolation: Tier A shared / Tier B dedicated NATS+RDS from Day 1; F3 Conf VM = trigger Phase 3 | code accommodates per-PL deployment config; do not hardcode single-PL |
| **A.1.24** | `Organization` + `Workspace` = governance layer, NOT isolation | do not model Org/Workspace as infrastructure isolation; Org cross-PL is forbidden; "changing domain = enroll new node under target TenantCA" |
| **A.3.1** | hexagonal, each component = 1 crate | maintain port/adapter seams; do not merge crates across boundaries |
| **A.4.1** | agent-daemon NFR `[A]` (latency, <100MB) | GUI figures do **not** count against this budget (D.3.2); all A.4 = `[A]` unmeasured |

-----

## H.4 — Settled Part D decisions (re-stated for coder)

| Decision | Choice | Source | Reassess |
|---|---|---|---|
| Open/closed boundary | Open client + closed control-plane (Tailscale model) | Part D §D.2 | none — derived from A.1.4 + P.7 |
| Client UI framework Phase 1-2 | **Tauri 2** | Part D §D.3 (resolved at Part C §H.8.5 #1) | P.8 trigger: if consumer-mobile-polish becomes a viral lever → Flutter mobile shell (D.3.3) |
| Repo structure | 2 code repos (open client / closed control-plane) + shared open crates | Part D §D.4 | none |
| OS rollout timing | client repos public from Day 1 (milestone 1.1) | Part C §H.1.4 + Part D §D.5 | none |
| Frontend framework (React/Svelte/Vue) | **TBD per team** | Part D §D.7 + frontend/README | finalized when scaffolding frontend at milestone 1.1 |
| License (workspace) | **Apache-2.0** (owner-chosen 2026-06-17) | Part D §D.7 | finalized — open-code spirit, patent grant |

-----

## H.5 — Current scope: Milestone 1.1 (Founding skeleton)

**Entry**: vendor founding. **Allocation**: ~95% Tier A / ~5% Tier B `[T per Part C §H.1.3]`.

**Built** `[T per Part C §H.3.1]`:
- Rust workspace + WireGuard mesh agent core (5 platform compile)
- Tauri 2 UI shell ("hello world" mobile+desktop)
- Personal Provisioning CA skeleton (SingleCustodian, ceremony rehearsed **once** non-prod)
- CI/CD baseline (hosted CI + Cosign)
- **Enterprise PL skeleton in code** — namespace, schema, ceremony procedure written. **ZERO infra**, overhead <10% effort
- Client repos **public** from Day 1

**Completion** `[T per Part C §H.3.1]`:
- 5 platforms compile + CI sign
- Personal ceremony rehearsed
- Enterprise CI staging deploy success (target ≥80% / 4-week synthetic check at milestone 1.4 — Phase 1→2 transition risk mitigation)
- Honesty: Enterprise skeleton clearly marked "skeleton-only", no overpromising

**Anti-pattern guard (P.8)** `[T per Part C §H.7.2]`:
- DO NOT pre-build Phase 2 infra (Shamir 2-of-3 ceremony, dedicated NATS/RDS) Day 1 — idle infra ~$5-15K/mo
- DO NOT pre-build Org/Workspace/delegation (A.1.24) before trigger L_subsidiary
- DO NOT pre-build F3 capabilities (HSM, Conf VM, BYOK, TEE broker, session recording) before F3 customer (L4)
- DO NOT create parallel "Enterprise-*" crates (direct violation of A.1.9)

-----

## H.6 — Build & test

```bash
cargo fmt --check
cargo clippy -- -D warnings
cargo check
cargo test
# GUI (after milestone 1.1 scaffold): cargo tauri dev   (requires Tauri toolchain)
# frontend: see frontend/README when framework is finalized (D.3.2 TBD)
```

Before reporting "done" to the human: run all 4 commands above. Report results **honestly** — if tests fail, say so and include the output `[T per P.3]`.

-----

## H.7 — Owner's responsibilities: decisions & assumptions that need ownership

> Returned to owner (D-00 §3). Each item below *may appear* to be already settled but is in fact a **decision that humans must make** or an **unverified assumption**.

1. **License = Apache-2.0** `[T per Part D §D.7 — owner-chosen 2026-06-17]` — open-code spirit for the client portion, permissive + explicit patent grant (appropriate for security/crypto products). `Cargo.toml` (workspace + `gui/src-tauri`) sets `license = "Apache-2.0"`; see `LICENSE` + `NOTICE`. Contributions default to Apache-2.0 §5.
2. **Frontend framework** — TBD per team (Part D §D.7); finalized when scaffolding frontend at milestone 1.1. Options: React / Svelte / Vue (Tauri webview-agnostic).
3. **NFR A.4 figures are `[A]` unmeasured** — owner confirmed 2026-06-05 (Part A H.7 #5). Do not quote NFR figures in customer-facing docs as guaranteed; any subset included in contracts (e.g. uptime SLO) requires legal/ops sign-off.
4. **Tauri mobile reassess trigger** — Part D §D.3.3. *Missing*: concrete definition of "consumer-mobile-polish becomes a viral lever" (mobile signup rate? install rate? mobile DAU/total?) — owner must own the trigger threshold.
5. **A.1.24 construct timing** — Part C §H.6 states "rollout milestone 2.3/3.3 gated by L_subsidiary"; *the L_subsidiary threshold is left blank — it comes from business trajectory/GTM, not invented in Part C*. Owner must affirm that the client repo MUST NOT pre-add `Organization`/`Workspace` types until the trigger fires.

-----
-----

# [R] — Verification section

## R1 — Crate/decision trace → blueprint

| Element | Governed by |
|---|---|
| 3 deployable units (#1 + #5 + CLI) | Part D §D.1.3 |
| 2-PL served by 1 codebase | Part A §A.1.9, A.1.11, A.1.23; Part B §B.1.1; Part D §D.1.2 |
| Open client + closed control-plane | Part A §A.1.4; Part D §D.2; P.7; Tailscale precedent |
| Hexagonal 1-component-1-crate | Part A §A.3.1; Part D §D.1.5 |
| 11 bounded contexts = service split seam | Part B §B.3; Part D §D.1.5/1.6 |
| Tauri 2 Phase 1-2 | Part D §D.3 (resolved at Part C §H.8.5 #1) |
| 2 code repos (open/closed) | Part D §D.4 |
| Open-source Day 1 (milestone 1.1) | Part A §A.1.4; Part C §H.1.4; Part D §D.5 |
| Milestone 1.1 scope + completion | Part C §H.3.1 |
| Anti-pattern guards | Part C §H.7.2 |
| `Organization` / `Workspace` deferred construct | Part A §A.1.24 (ratified); Part B §B.1.1 + §B.3.7 (statement); Part C §H.6 (timing) |
| Agent update + capability negotiation | Part A §A.1.20; Part B §B.3.10 → §B.3.3 interaction; Part D §D.1.7 |
| Single CI + Cosign artifact | Part A §A.1.19, A.1.21; Part B §B.3.10 |

## R2 — T/A markings

- **`[T]` (structural / citable source)**: all invariants named in H.3 — full text Part A; open/closed boundary derived from A.1.4 + Tailscale precedent; Tauri 2 stable since 02-10-2024 + footprint numbers (Part D §D.3.2 sources).
- **`[A]` (target/aspirational, unverified / decision not yet settled)**:
  - License (D.7) — pending owner decision.
  - Frontend framework — pending team decision when scaffolding.
  - All A.4 NFR (Part A H.7 #5 — owner confirmed no measurement).
  - WAF sidecar open-candidate (Part D §D.2 honest gap) — finalized when WAF is built at milestone 1.2.
  - "Tauri mobile sufficient for Phase 1 GUI scope" — `[A]` per Part D §D.3.2 (mobile "stable but not yet first-class").
  - Tauri mobile reassess threshold — pending owner.
- **`[A risk-accepted, owned]`**: A.1.24 construct deferred-by-trigger (Part A H.7 #12c); pre-build = anti-pattern.

## R3 — `[A]` list (this file)

1. License workspace — H.7 #1.
2. Frontend framework — H.7 #2.
3. NFR A.4 numbers (latency, memory, scale) whenever they appear in code/doc — H.7 #3.
4. Tauri mobile fitness for Phase 1 GUI — anchored at Part D §D.3.2; reassess trigger H.7 #4.
5. WAF crate location (control-plane vs open-candidate) — Part D §D.2 honest gap.
6. `Organization` / `Workspace` construct timing — H.7 #5; gate L_subsidiary (Part C §H.6.2).
7. Citation-resolve linter in CI — deferred to milestone 1.1 CI (Part D §D.6 Q2; CLAUDE.md T/A section).

## R4 — What this file does NOT assert

- Does NOT set new invariants — that is Part A's domain; conflicts → Part A wins (header).
- Does NOT define new domain entities — that is Part B's domain; `domain-core` follows §B.1 vocabulary.
- Does NOT define timing/milestones — that is Part C's domain; H.5 only re-states milestone 1.1 for the coder.
- Does NOT define implementation choices — that is Part D's domain; H.4 only re-states settled decisions.
- Does NOT assert that NFRs will be met (A.4 = `[A]` unmeasured).
- Does NOT assert that `Organization`/`Workspace` has been built (A.1.24 construct = Part C `[A]`).
- Does NOT assert that license/frontend framework is finalized.

## R5 — Sources, relationships, log

- **File relationships**: points to Part 0/A/B/C/D in `workspace/`; coordinates with `CLAUDE.md` (session behavior rules) + `CONTRIBUTING.md` (commit/PR workflow) + `README.md` (one-pager) + `docs/` (4 files trace/discipline/checklist — pace-layer split per P.5).
- **Register**: framing EN; identifier/crate name/term-of-art EN.
- **Update history**:
  - **init** (skeleton, commit `56c5191`): crate map + binding index + UI framework + build/test + license.
  - **blueprint sync** (2026-06-11): added A.1.11/A.1.23/A.1.24 to index; clarified Tier A/B naming + F1 Starter ≠ F1 Growth; expanded milestone 1.1 scope (5 platforms, Personal CA skeleton, Cosign, Enterprise PL skeleton); noted A.1.24 deferred in crate map.
  - **reflow H/R** (2026-06-11): split [H]/[R]; promoted "Owner's responsibilities" section (license, frontend framework, NFR commitment scope, Tauri mobile trigger, A.1.24 timing); T/A markings explicit; trace table R1 + `[A]` list R3.
  - **+R6 coverage overview** (2026-06-11): added R6 invariant coverage status; pointed detail to `INVARIANT-COVERAGE.md` (derived principle list + matrix of 24 invariants + Part B concepts + gap close before exit milestone).
  - **+refactor docs/ per CP structure** (2026-06-11): derived P.5 (pace layer) + P.8 (archival per milestone) → split into 4 files: `invariant-trace.md` (pace 5y) + `concept-trace.md` (pace 3-5y) + `qc-discipline.md` (pace stable) + `phase-completion-checklist-1.1.md` (pace 6-18mo, archival). Deleted `INVARIANT-COVERAGE.md` (root) + `docs/QC-GATES.md` (merged); content divided by pace-layer. R6 + R5 pointers updated.

## R6 — Invariant coverage (overview)

**Snapshot 2026-06-11 · milestone 1.1 Founding skeleton:**

| Status | Count (24 invariants A.1.x) | Meaning |
|---|---|---|
| ✅ structural-land / NA-correct | **9** | Structure enforces directly OR NA-for-client + client does not leak violating logic |
| 🟡 contract/skeleton/pending | **15** | Structure permits; awaiting milestone 1.2-1.4 to close implementation |
| ⛔ structurally blocked | **0** | None are structurally blocked — the most important thing |

**4-category coverage** (each invariant falls into 1 group) `[T per A.1.4 + Part D §D.2]`:
- **STRUCTURAL-in-client** — code repo enforces directly
- **CONTRACT-enables** — `proto`/`domain-core` provides contracts for control-plane to enforce
- **DEFERRED-to-deployment** — code supports both PLs; runtime config decides
- **NA-for-client** — control-plane scope; client does not touch (verify does NOT leak)

**Method**: derived from principle list (P.1-P.8) → structural commitment → invariant landing. Verification is at the *structural-permission* level (P.1), not runtime-verified.

**6 gaps structurally not yet closed before exit milestone 1.1**: `ProductLine` discriminator · `proto` subject namespace template · Tier enum no-soft-fallback · CI Cosign sign · T/A linter (defer `[A]`) · Enterprise CI staging deploy ≥80% / 4-week (gate milestone 1.4).

**A.1.24 status = ✅ structurally deferred (correct)**. DO NOT pre-add `Organization`/`Workspace` to "close the gap" — anti-pattern Part C §H.7.2.

→ **`docs/` (4 files, split by pace layer P.5)**:
- [`docs/invariant-trace.md`](./docs/invariant-trace.md) — pace 5y · status of 24 Part A invariants + principle-driven derivation.
- [`docs/concept-trace.md`](./docs/concept-trace.md) — pace 3-5y · Part B B.1/B.3/B.4/B.5/B.6 → crate map + placement rules.
- [`docs/qc-discipline.md`](./docs/qc-discipline.md) — pace stable · 4 test layers + QC marker convention + STOP semantics.
- [`docs/phase-completion-checklist-1.1.md`](./docs/phase-completion-checklist-1.1.md) — pace 6-18mo · 3 gates + invariant→test mapping + scope gate + CI G1-G9 specific to milestone 1.1. **Archive on exit**, create `-1.2.md`.

-----
