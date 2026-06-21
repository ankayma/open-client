# Phase Completion Checklist — Milestone 1.1 (Founding Skeleton)

> **Scope**: 3 gate (Built / Completion / Honesty) + mapping invariant→test + gap list cụ thể cho milestone 1.1 per Part C §H.3.1. Frozen artifact — *archive khi exit 1.1*.
> **Pace layer** `[T per P.5]`: phase = 6-18 tháng, milestone = đơn vị nhỏ hơn. File này frozen per milestone; exit 1.1 = tạo `phase-completion-checklist-1.2.md` cho milestone tiếp theo.
> **Quan hệ**:
> - Methodology + marker convention stable → `docs/qc-discipline.md`
> - Trạng thái 24 invariant → `docs/invariant-trace.md`
> - Map Part B concept → `docs/concept-trace.md`
>
> **Snapshot**: 2026-06-11 · milestone 1.1 ACTIVE. Reference: Part C §H.3.1.
>
> **Cách đọc** (D-00 §4): [H] 3 gate + mapping + gap + CI gate; [R] suy dẫn, T/A, log.

-----
-----

# [H] — Dành cho coder/owner

## H.0 — Tóm tắt chốt trước

**Milestone 1.1 WIG** (Part C §H.3.1): "From 0 to architectural foundation capable of supporting all 5 platforms and Enterprise activation by loop completion."

**Phân bổ** (Part C §H.1.3): ~95% Tier A / ~5% Tier B.

**3 gate exit milestone 1.1** (theo Part C §H.2.1 "4 loại" — eng team accountable cho 3):

1. **Gate A — Built list** (Loại 1 trigger + Loại 3 scoreboard): 5 platform compile + Tauri 2 UI shell + Personal CA skeleton + CI/CD baseline + Enterprise PL skeleton in code (ZERO infra).
2. **Gate B — Completion criteria** (Loại 1 trigger): 5 platform compile + CI sign + Personal ceremony rehearsed + Enterprise CI staging deploy success (≥80%/4 tuần gate ở milestone 1.4).
3. **Gate C — Honesty** (Loại 4): Enterprise skeleton ghi rõ "skeleton-only"; compromise A.1.12 update nếu phát hiện trong milestone; T/A marking trung thực.

**Loại 2 hypothesis** (Part C §H.3.1: "minimal pre-market") = owner + business scope, không verify bằng test code.

**Exit semantics**: cả 3 gate L3+ → advance milestone 1.2. Bất kỳ gate L0 → STOP. Pattern: `docs/qc-discipline.md` H.1.

-----

## H.1 — Gate A: Built list (Part C §H.3.1)

| Hạng mục | Trạng thái | Test verify | Marker |
|---|---|---|---|
| Rust workspace + WireGuard mesh agent core | 🟡 skeleton (skeleton crates đã có; WireGuard impl pending) | Lớp 1 compile + Lớp 2 unit | — |
| 5 platform compile (Linux/macOS/Windows/iOS/Android) | 🟡 pending CI matrix | Lớp 1 `cargo check --target=<5>` | `QC[1.1]` per platform target |
| Tauri 2 UI shell "hello world" mobile+desktop | 🟡 pending `cargo tauri init` | Lớp 1 compile `gui/src-tauri` | `QC[1.1]` |
| Client repos public từ Day 1 (agent core + CLI + UI) | ✅ done (repo public commit) | Lớp 3 invariant A.1.4 (workspace license + no `*.proprietary`) | `QC[1.1] QC-invariant[A.1.4]` |
| Personal Provisioning CA skeleton (SingleCustodian, ceremony rehearsed once non-prod) | 🟡 skeleton + ceremony chưa rehearsed | Artifact: signed ceremony log (offline) | `QC[1.1]` artifact-based, không cargo test |
| CI/CD baseline (hosted CI + Cosign) | 🟡 pending CI setup | Lớp 3 invariant A.1.19 (CI workflow file declare Cosign step) | `QC[1.1] QC-invariant[A.1.19]` |
| Enterprise PL skeleton (namespace, schema, ceremony procedure viết — ZERO infra, overhead <10%) | 🟡 pending namespace + schema + ceremony procedure | Lớp 4 contract `enterprise.tenant.<id>.>` template; Lớp 3 invariant scope gate (KHÔNG có infra provisioning code) | `QC[1.1] QC-invariant[A.1.11]` + `QC-scope[Part C §H.7.2]` |

-----

## H.2 — Gate B: Mapping invariant → test (milestone 1.1 subset)

Chỉ test cần pass *trước exit milestone 1.1* — subset từ `invariant-trace.md`. Pattern bắt buộc per `qc-discipline.md` H.2 Lớp 3.

| Invariant | Test assertion (1 dòng) | File test | Marker |
|---|---|---|---|
| **A.1.1** data/control tách | `agent-core` không import NATS payload type cho user data | `crates/agent-core/tests/invariant_a_1_1.rs` | `QC[1.1] QC-invariant[A.1.1]` |
| **A.1.4** agent OPEN | Workspace `license` declared (not empty); no `*.proprietary` file | `tests/invariant_a_1_4.rs` (workspace root) | `QC[1.1] QC-invariant[A.1.4]` |
| **A.1.9** single codebase | Workspace 1 root Cargo.toml; KHÔNG crate name chứa `personal`/`enterprise` | `crates/domain-core/tests/invariant_a_1_9.rs` | `QC[1.1] QC-invariant[A.1.9]` |
| **A.1.10** tier-aware | `NodeTier`/`CommercialTier` là Rust enum (no `Option<...>` fallback) | `crates/domain-core/tests/invariant_a_1_10.rs` | `QC[1.1] QC-invariant[A.1.10]` |
| **A.1.11** namespace per-PL | `proto` const template `{}.tenant.{}.>` chấp nhận đúng 2 PL prefix; entity carry `(product_line, tenant_id)` | `crates/proto/tests/invariant_a_1_11.rs` | `QC[1.1] QC-invariant[A.1.11]` |
| **A.1.19** release lifecycle | CI workflow file declare Cosign sign step; N-2 backwards-compat matrix declared | `tests/invariant_a_1_19.rs` | `QC[1.1] QC-invariant[A.1.19]` |
| **A.1.21** supply-chain | `Cargo.lock` committed; KHÔNG dep `git=`; workspace.dependencies path-only; no dynamic load | `tests/invariant_a_1_21.rs` | `QC[1.1] QC-invariant[A.1.21]` |
| **A.1.23** per-PL infra isolation (contract) | Subject template + entity field `product_line` enforce ở compile time | (cùng A.1.11 file) | `QC[1.1] QC-invariant[A.1.23]` |
| **A.1.24** Org/Workspace deferred (negative) | KHÔNG có type `Organization`/`Workspace` trong `domain-core` | `crates/domain-core/tests/invariant_a_1_24.rs` | `QC[1.1] QC-invariant[A.1.24] QC-scope[Part C §H.7.2]` |
| **A.3.1** hexagonal | `agent-core` có 4 module `domain`/`application`/`ports`/`adapters`; imports không cross-context | `crates/agent-core/tests/invariant_a_3_1.rs` | `QC[1.1] QC-invariant[A.3.1]` |

**Defer milestone 1.2** (broker integration): A.1.2 (need-to-know), A.1.5 (selective overlay), A.1.6 (fail-closed), A.1.7 (JIT), A.1.18 (cross-PL TLS verify), A.1.20 (capability negotiation), A.1.22 (enrollment ceremony) — test có nhưng marker `QC[1.2]`.

-----

## H.3 — Gate B (cont.): Mapping concept → contract test (milestone 1.1 subset)

| Concept | Test | File | Marker |
|---|---|---|---|
| `ProductLine` enum | Đúng 2 variant `Personal`/`Enterprise`; serialize stable | `crates/domain-core/tests/contract_b_1_1_product_line.rs` | `QC[1.1] QC-concept[B.1.1]` |
| `Customer`/`Tenant` | Field shape: `Customer.product_line: ProductLine`; `Tenant.(customer_id, product_line, tenant_id)` | `crates/domain-core/tests/contract_b_1_1_tenant.rs` | `QC[1.1] QC-concept[B.1.1]` |
| `NodeTier` 1-4 | Đúng 4 variant, ordering preserved | `crates/domain-core/tests/contract_b_1_4_node_tier.rs` | `QC[1.1] QC-concept[B.1.4]` |
| Agent API gRPC service skeleton | `AgentControl` service exists; 10 RPC method signature defined (full impl 1.2) | `crates/proto/tests/contract_b_5_1_agent_api.rs` | `QC[1.1] QC-concept[B.5.1]` |
| NATS subject namespace template | `{pl}.tenant.{tid}.{audit\|event\|policy\|intent}.*`; 2 PL prefix | (cùng A.1.11 file) | `QC[1.1] QC-concept[B.6.3]` |
| **NA-client negative**: lifecycle/vendor/WAF/edge | Grep absence — KHÔNG có module/type tương ứng | `tests/contract_na_client.rs` | `QC[1.1] QC-concept[B.3.5/8/9/11]` |

-----

## H.4 — Gate B (cont.): Scope gate test (anti-pre-build per Part C §H.7.2)

| Anti-pattern | Test | File | Marker |
|---|---|---|---|
| Pre-build Org/Workspace trước L_subsidiary | Assert KHÔNG có type `Organization`/`Workspace`; KHÔNG file `org_*.rs`/`workspace_*.rs` | `tests/scope_gate_no_org_workspace.rs` | `QC[1.1] QC-scope[Part C §H.7.2]` |
| Pre-build F3 capability | Assert KHÔNG module `hsm`/`confidential_vm`/`byok`/`hyok`/`tee_broker`/`session_recording` | `tests/scope_gate_no_f3_capability.rs` | `QC[1.1] QC-scope[Part C §H.7.2]` |
| Pre-build Phase 2 infra Day 1 | Assert KHÔNG module `shamir_2of3`/`enterprise_nats_provisioning` ở client (Phase 2 infra = control-plane scope) | `tests/scope_gate_no_phase2_infra.rs` | `QC[1.1] QC-scope[Part C §H.7.2]` |
| Tạo crate "Enterprise-*" / "Personal-*" song song | (cùng A.1.9 test) | — | — |

Khi `L_subsidiary` fire (milestone 2.3/3.3) → archive scope gate test cũ + add type `Organization`/`Workspace` → contract test "có type" thay vào (loop closure).

-----

## H.5 — CI gate per milestone 1.1

CI red nếu bất kỳ gate dưới fail:

| Gate | Check | Reference |
|---|---|---|
| G1 | `cargo fmt --check` pass | CLAUDE.md §Workflow |
| G2 | `cargo clippy -- -D warnings` pass | CLAUDE.md §Workflow |
| G3 | `cargo check --target=<5 platforms>` pass (Lớp 1) | Part C §H.3.1 |
| G4 | `cargo test --workspace` pass (Lớp 2-4) | Part C §H.3.1 |
| G5 | Mỗi A.1.x trong H.2 có test pass + marker `QC[1.1] QC-invariant[...]` | `qc-discipline.md` H.6 |
| G6 | Mỗi concept trong H.3 có contract test pass + marker `QC[1.1] QC-concept[...]` | `qc-discipline.md` H.6 |
| G7 | Scope gate test H.4 pass | Part C §H.7.2 |
| G8 | Cosign sign artifact produced + verify | A.1.19 + A.1.21 |
| G9 | Personal CA ceremony rehearsed (artifact: signed log offline) | Part C §H.3.1 |
| **G10 (defer 1.4)** | Enterprise CI staging deploy ≥80%/4 tuần | Part C §H.3.4 (Phase 1→2 risk mitigation) |

**G1-G9 ở milestone 1.1; G10 ở milestone 1.4**. Test fail ở bất kỳ G nào = không "done"; report trung thực fail kèm output trong PR/commit message (P.3).

-----

## H.6 — Gap chưa close (suy theo principle, ưu tiên trước exit)

| # | Gap | Principle ép | Invariant ảnh hưởng | Action |
|---|---|---|---|---|
| 1 | `ProductLine` discriminator chưa định nghĩa trong `domain-core` | P.6 | A.1.9, A.1.11, A.3.6 — không enforce compile time | Add `enum ProductLine { Personal, Enterprise }` |
| 2 | `proto` chưa có subject namespace template | P.6 | A.1.11 | Define const/macro `<pl>.tenant.<id>.>` |
| 3 | Tier enum chưa hard-code no-soft-fallback | P.2 | A.1.10 | Rust type ép `NodeTier`/`CommercialTier` |
| 4 | CI Cosign sign chưa setup | P.2 | A.1.19, A.1.21 | Milestone 1.1 đòi "CI sign" hoàn thành |
| 5 | T/A citation-resolve linter defer milestone 1.1 CI | P.3 | A.1.12 enforce mức code | `[A]` chấp nhận — chờ Part D §D.6 Q2 CI |
| 6 | Enterprise CI staging deploy ≥80%/4 tuần | P.8 | A.1.18, A.1.23 ("Day 1 = vận hành Enterprise PL") | Gate ở milestone 1.4 (Part C §H.3.4) |

**Anti-gap (đừng tự sửa)**: A.1.24 deferred = đúng. KHÔNG pre-add `Organization`/`Workspace` để "close gap" — anti-pattern Part C §H.7.2.

-----

## H.7 — Việc của owner

1. **Ratify gate exit semantics** — 3 gate (Built / Completion / Honesty) đủ cho eng team accountability ở milestone 1.1. Owner đứng tên rằng Loại 2 hypothesis (market signal) thuộc owner+business scope, không phải eng gate.
2. **Confirm CI threshold** — G1-G9 đủ cho exit 1.1; G10 ratify cho gate 1.4 Phase 1→2 readiness.
3. **Gap close priority** — 6 gap H.6 ưu tiên trước exit milestone 1.1; mục #5 (linter) chấp nhận defer (`[A]`).
4. **Exit milestone 1.1**: archive file này → tạo `phase-completion-checklist-1.2.md`. Pointer cuối file ↓.

-----

## H.8 — Loop closure: exit milestone 1.1

**Khi cả 3 gate (A/B/C) L3+ và CI G1-G9 pass**:

1. Refresh `docs/invariant-trace.md` — 🟡 → ✅ cho invariant đã có test pass.
2. Refresh `docs/concept-trace.md` — 🟡 → ✅ cho concept đã có contract test pass.
3. Archive file này: rename `phase-completion-checklist-1.1.md` → `phase-completion-checklist-1.1.ARCHIVED.md` (giữ snapshot frozen).
4. Tạo `phase-completion-checklist-1.2.md` cho milestone 1.2 (WIG: F0 viral launch — Part C §H.3.2).
5. Update ARCHITECTURE.md R6 + CLAUDE.md "Đọc trước khi viết" pointer → checklist 1.2.

Reference Part C §H.3.5 cho điều kiện chuyển Phase 1 → Phase 2 (cần *milestone 1.4 + Enterprise interest signal*; không calendar-driven).

-----
-----

# [R] — Phần kiểm chứng

## R1 — Suy dẫn về principle list + Part C

| Decision | Principle ép | Part C reference |
|---|---|---|
| 3 gate (Built/Completion/Honesty) | Part C §H.2.1 4 loại; eng accountable cho 3 | §H.2.1 |
| Loại 2 hypothesis tách khỏi eng gate | P.5 three layers (eng layer vs business layer) | §H.2.1 |
| Mapping invariant→test subset cho 1.1 | P.8 trigger-based (chỉ test cần cho milestone hiện tại) | §H.7.2 |
| Scope gate test = test fail-fast anti-pattern | P.8 + Part C §H.7.2 | §H.7.2 |
| G10 (Enterprise CI staging) defer 1.4 | P.8 (gate ở exit Phase 1, không 1.1) | §H.3.4 |
| Archive khi exit (loop closure) | Part C §H.7.3 "Roadmap là trạng thái phái sinh" | §H.7.3 |
| File frozen per milestone | P.5 pace layer (phase = 6-18mo) | §H.2 |

## R2 — T/A markings

- **`[T]`**: Milestone 1.1 WIG + Built list + Completion = Part C §H.3.1 quote verbatim ở H.0/H.1; gate semantics = Part C §H.2.1 rubric.
- **`[A]`**: 6 gap H.6 — implementation pending; coverage threshold (1 test per invariant STRUCTURAL) = `qc-discipline.md` H.6 đề xuất; G10 timing milestone 1.4 = Part C §H.3.4 plan.
- **`[A risk-accepted, owned]`**: T/A linter defer 1.1 CI (gap #5); Personal CA ceremony non-prod rehearsal đủ cho 1.1 (production ceremony = milestone 2.1 trigger-activated).

## R3 — Log

- **init** (2026-06-11): milestone 1.1 checklist sinh ra từ `docs/QC-GATES.md` (xoá) H.7 + `INVARIANT-COVERAGE.md` (xoá) H.5 khi refactor sang CP structure. 3 gate + mapping subset (10 invariant test + 6 concept test + 3 scope gate test) + CI G1-G9 + 6 gap. Frozen per milestone — archive khi exit 1.1.

-----
