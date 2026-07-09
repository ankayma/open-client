# Phase Completion Checklist — Milestone 1.1 (Founding Skeleton)

> **Scope**: 3 gates (Built / Completion / Honesty) + invariant→test mapping + specific gap list for milestone 1.1 per Part C §H.3.1. Frozen artifact — *archive on exit 1.1*.
> **Pace layer** `[T per P.5]`: phase = 6-18 months, milestone = smaller unit. This file is frozen per milestone; exit 1.1 = create `phase-completion-checklist-1.2.md` for the next milestone.
> **Relations**:
> - Methodology + marker convention stable → `docs/qc-discipline.md`
> - Status of 24 invariants → `docs/invariant-trace.md`
> - Map Part B concept → `docs/concept-trace.md`
>
> **Snapshot**: 2026-06-11 · milestone 1.1 ACTIVE. Reference: Part C §H.3.1.
>
> **How to read** (D-00 §4): [H] 3 gates + mapping + gap + CI gate; [R] derivation, T/A, log.

-----
-----

# [H] — For coder/owner

## H.0 — Summary — key decisions

**Milestone 1.1 WIG** (Part C §H.3.1): "From 0 to architectural foundation capable of supporting all 5 platforms and Enterprise activation by loop completion."

**Allocation** (Part C §H.1.3): ~95% Tier A / ~5% Tier B.

**3 gate exit milestone 1.1** (per Part C §H.2.1 "4 types" — eng team accountable for 3):

1. **Gate A — Built list** (Type 1 trigger + Type 3 scoreboard): 5 platform compile + Tauri 2 UI shell + Personal CA skeleton + CI/CD baseline + Enterprise PL skeleton in code (ZERO infra).
2. **Gate B — Completion criteria** (Type 1 trigger): 5 platform compile + CI sign + Personal ceremony rehearsed + Enterprise CI staging deploy success (≥80%/4 weeks gate at milestone 1.4).
3. **Gate C — Honesty** (Type 4): Enterprise skeleton clearly marked "skeleton-only"; A.1.12 compromise updated if discovered within milestone; T/A marking honest.

**Type 2 hypothesis** (Part C §H.3.1: "minimal pre-market") = owner + business scope, not verified by test code.

**Exit semantics**: all 3 gates L3+ → advance to milestone 1.2. Any gate L0 → STOP. Pattern: `docs/qc-discipline.md` H.1.

-----

## H.1 — Gate A: Built list (Part C §H.3.1)

| Item | Status | Test verify | Marker |
|---|---|---|---|
| Rust workspace + WireGuard mesh agent core | 🟡 skeleton (skeleton crates exist; WireGuard impl pending) | Layer 1 compile + Layer 2 unit | — |
| 5 platform compile (Linux/macOS/Windows/iOS/Android) | 🟡 pending CI matrix | Layer 1 `cargo check --target=<5>` | `QC[1.1]` per platform target |
| Tauri 2 UI shell "hello world" mobile+desktop | 🟡 pending `cargo tauri init` | Layer 1 compile `gui/src-tauri` | `QC[1.1]` |
| Client repos public from Day 1 (agent core + CLI + UI) | ✅ done (repo public commit) | Layer 3 invariant A.1.4 (workspace license + no `*.proprietary`) | `QC[1.1] QC-invariant[A.1.4]` |
| Personal Provisioning CA skeleton (SingleCustodian, ceremony rehearsed once non-prod) | 🟡 skeleton + ceremony not yet rehearsed | Artifact: signed ceremony log (offline) | `QC[1.1]` artifact-based, not cargo test |
| CI/CD baseline (hosted CI + Cosign) | 🟡 pending CI setup | Layer 3 invariant A.1.19 (CI workflow file declares Cosign step) | `QC[1.1] QC-invariant[A.1.19]` |
| Enterprise PL skeleton (namespace, schema, ceremony procedure written — ZERO infra, overhead <10%) | 🟡 pending namespace + schema + ceremony procedure | Layer 4 contract `enterprise.tenant.<id>.>` template; Layer 3 invariant scope gate (NO infra provisioning code) | `QC[1.1] QC-invariant[A.1.11]` + `QC-scope[Part C §H.7.2]` |

-----

## H.2 — Gate B: Mapping invariant → test (milestone 1.1 subset)

Only tests that must pass *before exiting milestone 1.1* — subset from `invariant-trace.md`. Mandatory pattern per `qc-discipline.md` H.2 Layer 3.

| Invariant | Test assertion (1 line) | Test file | Marker |
|---|---|---|---|
| **A.1.1** data/control separation | `agent-core` does not import NATS payload type for user data | `crates/agent-core/tests/invariant_a_1_1.rs` | `QC[1.1] QC-invariant[A.1.1]` |
| **A.1.4** agent OPEN | Workspace `license` declared (not empty); no `*.proprietary` file | `tests/invariant_a_1_4.rs` (workspace root) | `QC[1.1] QC-invariant[A.1.4]` |
| **A.1.9** single codebase | Workspace 1 root Cargo.toml; NO crate name containing `personal`/`enterprise` | `crates/domain-core/tests/invariant_a_1_9.rs` | `QC[1.1] QC-invariant[A.1.9]` |
| **A.1.10** tier-aware | `NodeTier`/`CommercialTier` is a Rust enum (no `Option<...>` fallback) | `crates/domain-core/tests/invariant_a_1_10.rs` | `QC[1.1] QC-invariant[A.1.10]` |
| **A.1.11** namespace per-PL | `proto` const template `{}.tenant.{}.>` accepts exactly 2 PL prefixes; entity carries `(product_line, tenant_id)` | `crates/proto/tests/invariant_a_1_11.rs` | `QC[1.1] QC-invariant[A.1.11]` |
| **A.1.19** release lifecycle | CI workflow file declares Cosign sign step; N-2 backwards-compat matrix declared | `tests/invariant_a_1_19.rs` | `QC[1.1] QC-invariant[A.1.19]` |
| **A.1.21** supply-chain | `Cargo.lock` committed; NO dep `git=`; workspace.dependencies path-only; no dynamic load | `tests/invariant_a_1_21.rs` | `QC[1.1] QC-invariant[A.1.21]` |
| **A.1.23** per-PL infra isolation (contract) | Subject template + entity field `product_line` enforced at compile time | (same A.1.11 file) | `QC[1.1] QC-invariant[A.1.23]` |
| **A.1.24** Org/Workspace deferred (negative) | NO type `Organization`/`Workspace` in `domain-core` | `crates/domain-core/tests/invariant_a_1_24.rs` | `QC[1.1] QC-invariant[A.1.24] QC-scope[Part C §H.7.2]` |
| **A.3.1** hexagonal | `agent-core` has 4 modules `domain`/`application`/`ports`/`adapters`; imports do not cross-context | `crates/agent-core/tests/invariant_a_3_1.rs` | `QC[1.1] QC-invariant[A.3.1]` |

**Defer to milestone 1.2** (broker integration): A.1.2 (need-to-know), A.1.5 (selective overlay), A.1.6 (fail-closed), A.1.7 (JIT), A.1.18 (cross-PL TLS verify), A.1.20 (capability negotiation), A.1.22 (enrollment ceremony) — tests exist but marker `QC[1.2]`.

-----

## H.3 — Gate B (cont.): Mapping concept → contract test (milestone 1.1 subset)

| Concept | Test | File | Marker |
|---|---|---|---|
| `ProductLine` enum | Exactly 2 variants `Personal`/`Enterprise`; serialize stable | `crates/domain-core/tests/contract_b_1_1_product_line.rs` | `QC[1.1] QC-concept[B.1.1]` |
| `Customer`/`Tenant` | Field shape: `Customer.product_line: ProductLine`; `Tenant.(customer_id, product_line, tenant_id)` | `crates/domain-core/tests/contract_b_1_1_tenant.rs` | `QC[1.1] QC-concept[B.1.1]` |
| `NodeTier` 1-4 | Exactly 4 variants, ordering preserved | `crates/domain-core/tests/contract_b_1_4_node_tier.rs` | `QC[1.1] QC-concept[B.1.4]` |
| Agent API gRPC service skeleton | `AgentControl` service exists; 10 RPC method signatures defined (full impl 1.2) | `crates/proto/tests/contract_b_5_1_agent_api.rs` | `QC[1.1] QC-concept[B.5.1]` |
| NATS subject namespace template | `{pl}.tenant.{tid}.{audit\|event\|policy\|intent}.*`; 2 PL prefixes | (same A.1.11 file) | `QC[1.1] QC-concept[B.6.3]` |
| **NA-client negative**: lifecycle/vendor/WAF/edge | Grep absence — NO corresponding module/type present | `tests/contract_na_client.rs` | `QC[1.1] QC-concept[B.3.5/8/9/11]` |

-----

## H.4 — Gate B (cont.): Scope gate test (anti-pre-build per Part C §H.7.2)

| Anti-pattern | Test | File | Marker |
|---|---|---|---|
| Pre-build Org/Workspace before L_subsidiary | Assert NO type `Organization`/`Workspace`; NO file `org_*.rs`/`workspace_*.rs` | `tests/scope_gate_no_org_workspace.rs` | `QC[1.1] QC-scope[Part C §H.7.2]` |
| Pre-build F3 capability | Assert NO module `hsm`/`confidential_vm`/`byok`/`hyok`/`tee_broker`/`session_recording` | `tests/scope_gate_no_f3_capability.rs` | `QC[1.1] QC-scope[Part C §H.7.2]` |
| Pre-build Phase 2 infra Day 1 | Assert NO module `shamir_2of3`/`enterprise_nats_provisioning` in client (Phase 2 infra = control-plane scope) | `tests/scope_gate_no_phase2_infra.rs` | `QC[1.1] QC-scope[Part C §H.7.2]` |
| Create "Enterprise-*" / "Personal-*" crates in parallel | (same A.1.9 test) | — | — |

When `L_subsidiary` fires (milestone 2.3/3.3) → archive old scope gate test + add type `Organization`/`Workspace` → contract test "type exists" replaces it (loop closure).

-----

## H.5 — CI gate per milestone 1.1

CI red if any gate below fails:

| Gate | Check | Reference |
|---|---|---|
| G1 | `cargo fmt --check` pass | CLAUDE.md §Workflow |
| G2 | `cargo clippy -- -D warnings` pass | CLAUDE.md §Workflow |
| G3 | `cargo check --target=<5 platforms>` pass (Layer 1) | Part C §H.3.1 |
| G4 | `cargo test --workspace` pass (Layers 2-4) | Part C §H.3.1 |
| G5 | Each A.1.x in H.2 has test pass + marker `QC[1.1] QC-invariant[...]` | `qc-discipline.md` H.6 |
| G6 | Each concept in H.3 has contract test pass + marker `QC[1.1] QC-concept[...]` | `qc-discipline.md` H.6 |
| G7 | Scope gate test H.4 pass | Part C §H.7.2 |
| G8 | Cosign sign artifact produced + verify | A.1.19 + A.1.21 |
| G9 | Personal CA ceremony rehearsed (artifact: signed log offline) | Part C §H.3.1 |
| **G10 (defer 1.4)** | Enterprise CI staging deploy ≥80%/4 weeks | Part C §H.3.4 (Phase 1→2 risk mitigation) |

**G1-G9 at milestone 1.1; G10 at milestone 1.4**. Test failure at any G = not "done"; honestly report failure with output in PR/commit message (P.3).

-----

## H.6 — Gaps not yet closed (derived from principles, prioritize before exit)

| # | Gap | Enforcing principle | Affected invariant | Action |
|---|---|---|---|---|
| 1 | `ProductLine` discriminator not yet defined in `domain-core` | P.6 | A.1.9, A.1.11, A.3.6 — not enforced at compile time | Add `enum ProductLine { Personal, Enterprise }` |
| 2 | `proto` missing subject namespace template | P.6 | A.1.11 | Define const/macro `<pl>.tenant.<id>.>` |
| 3 | Tier enum not yet hard-coded with no-soft-fallback | P.2 | A.1.10 | Rust type enforces `NodeTier`/`CommercialTier` |
| 4 | CI Cosign sign not yet set up | P.2 | A.1.19, A.1.21 | Milestone 1.1 requires "CI sign" to be complete |
| 5 | T/A citation-resolve linter deferred to milestone 1.1 CI | P.3 | A.1.12 enforced at code level | `[A]` accepted — awaiting Part D §D.6 Q2 CI |
| 6 | Enterprise CI staging deploy ≥80%/4 weeks | P.8 | A.1.18, A.1.23 ("Day 1 = operate Enterprise PL") | Gate at milestone 1.4 (Part C §H.3.4) |

**Anti-gap (do not self-fix)**: A.1.24 deferred = correct. Do NOT pre-add `Organization`/`Workspace` to "close the gap" — anti-pattern Part C §H.7.2.

-----

## H.7 — Owner actions

1. **Ratify gate exit semantics** — 3 gates (Built / Completion / Honesty) are sufficient for eng team accountability at milestone 1.1. Owner signs off that Type 2 hypothesis (market signal) belongs to owner+business scope, not eng gate.
2. **Confirm CI threshold** — G1-G9 sufficient for exit 1.1; G10 ratified for gate 1.4 Phase 1→2 readiness.
3. **Gap close priority** — 6 gaps in H.6 prioritized before exiting milestone 1.1; item #5 (linter) accepted as deferred (`[A]`).
4. **Exit milestone 1.1**: archive this file → create `phase-completion-checklist-1.2.md`. Pointer at end of file ↓.

-----

## H.8 — Loop closure: exit milestone 1.1

**When all 3 gates (A/B/C) are L3+ and CI G1-G9 pass**:

1. Refresh `docs/invariant-trace.md` — 🟡 → ✅ for invariants that have tests passing.
2. Refresh `docs/concept-trace.md` — 🟡 → ✅ for concepts that have contract tests passing.
3. Archive this file: rename `phase-completion-checklist-1.1.md` → `phase-completion-checklist-1.1.ARCHIVED.md` (keeps snapshot frozen).
4. Create `phase-completion-checklist-1.2.md` for milestone 1.2 (WIG: F0 viral launch — Part C §H.3.2).
5. Update ARCHITECTURE.md R6 + CLAUDE.md "Read before writing" pointer → checklist 1.2.

Reference Part C §H.3.5 for conditions to transition Phase 1 → Phase 2 (requires *milestone 1.4 + Enterprise interest signal*; not calendar-driven).

-----
-----

# [R] — Verification section

## R1 — Derivation from principles and Part C

| Decision | Enforcing principle | Part C reference |
|---|---|---|
| 3 gates (Built/Completion/Honesty) | Part C §H.2.1 4 types; eng accountable for 3 | §H.2.1 |
| Type 2 hypothesis separated from eng gate | P.5 three layers (eng layer vs business layer) | §H.2.1 |
| Invariant→test mapping subset for 1.1 | P.8 trigger-based (only test what is needed for the current milestone) | §H.7.2 |
| Scope gate test = fail-fast anti-pattern test | P.8 + Part C §H.7.2 | §H.7.2 |
| G10 (Enterprise CI staging) deferred to 1.4 | P.8 (gate at Phase 1 exit, not 1.1) | §H.3.4 |
| Archive on exit (loop closure) | Part C §H.7.3 "Roadmap is a derived state" | §H.7.3 |
| File frozen per milestone | P.5 pace layer (phase = 6-18mo) | §H.2 |

## R2 — T/A markings

- **`[T]`**: Milestone 1.1 WIG + Built list + Completion = Part C §H.3.1 quoted verbatim in H.0/H.1; gate semantics = Part C §H.2.1 rubric.
- **`[A]`**: 6 gaps H.6 — implementation pending; coverage threshold (1 test per invariant STRUCTURAL) = `qc-discipline.md` H.6 proposal; G10 timing milestone 1.4 = Part C §H.3.4 plan.
- **`[A risk-accepted, owned]`**: T/A linter deferred to 1.1 CI (gap #5); Personal CA ceremony non-prod rehearsal sufficient for 1.1 (production ceremony = milestone 2.1 trigger-activated).

## R3 — Log

- **init** (2026-06-11): milestone 1.1 checklist generated from `docs/QC-GATES.md` (deleted) H.7 + `INVARIANT-COVERAGE.md` (deleted) H.5 during refactor to CP structure. 3 gates + mapping subset (10 invariant tests + 6 concept tests + 3 scope gate tests) + CI G1-G9 + 6 gaps. Frozen per milestone — archive on exit 1.1.

-----
