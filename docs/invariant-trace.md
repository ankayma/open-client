# Invariant Trace — client/ vs Part A

> **Scope**: status of 24 Part A invariants (A.1.1-A.1.24) + pattern A.3 + NFR A.4 + trust map A.5 in the client/ architecture; derived from principle list P.1-P.8.
> **Pace layer** `[T per P.5]`: invariant = 5-year stable; this file refreshes the **status snapshot** on every PR that touches an invariant test.
> **Relations**:
> - Concept Part B → `docs/concept-trace.md`
> - Verification mechanism (test methodology + marker) → `docs/qc-discipline.md`
> - Gate per milestone → `docs/phase-completion-checklist-<X.Y>.md`
>
> **Snapshot**: 2026-06-11 · milestone 1.1 Founding skeleton.
>
> **How to read** (D-00 §4): [H] status + derivation; [R] method, T/A, log.

-----
-----

# [H] — For coder/owner

## H.0 — Summary up front

**Verification level** = *structural-permission* (P.1), not runtime-verified. An invariant `✅` at the milestone skeleton means: structure enforces directly OR NA-for-client + client does not leak violating logic. `🟡` = structure permits, runtime implementation pending. `⛔` = structure is blocking — must STOP + amend.

**Snapshot 2026-06-11** (24 invariant A.1.x):

| Status | Count | Meaning |
|---|---|---|
| ✅ structural-land / NA-correct | **9** | Structure enforces directly OR NA-for-client + no leak |
| 🟡 contract/skeleton/pending | **15** | Structure permits; awaiting milestones 1.2-1.4 to close implementation |
| ⛔ structurally blocked | **0** | None are blocked by structure |

-----

## H.1 — Scope classification: 4 coverage groups

Part A speaks to THE WHOLE SYSTEM. Client is the OPEN slice. Each invariant falls into 1 of 4 groups `[T per A.1.4 + Part D §D.2]`:

| Group | Meaning | How to verify |
|---|---|---|
| **STRUCTURAL-in-client** | Code repo enforces directly | Read crate seam + adapter |
| **CONTRACT-enables** | Client defines contract for control-plane to enforce | Read `proto` + `domain-core` |
| **DEFERRED-to-deployment** | Code supports both PLs, runtime config decides | Cargo workspace + feature flag |
| **NA-for-client** | Control-plane scope; client does not touch | Verify NO module leaks control-plane logic |

> ⚠️ **Error to avoid**: labeling an invariant "✅" just because it *does not appear in client/*. NA-for-client is only ✅ when (a) it is genuinely control-plane scope **and** (b) the client structurally does not leak violating logic.

-----

## H.2 — Derivation from principle list

Each structural commitment in client/ is *derivable* from one or more principles:

| Principle | Condensed statement | Structural commitment in client/ | Invariants that land |
|---|---|---|---|
| **P.1** | Architecture absorbs execution | Hexagonal (D.1.5): 1 crate / 1 bounded context; port/adapter seam | A.3.1 (direct); A.3.4 defense-in-depth at the architectural level |
| **P.2** | Strict admission | Tier = hard enum in `domain-core` (no soft fallback); ceremony rehearsed milestone 1.1; NO `--skip-verification` flag | A.1.10 tier absolute; A.1.18 ceremony-based; A.1.22 enrollment ceremony |
| **P.3** | Honest gap | T/A marking convention; "Owner responsibilities" surface | A.1.12 honesty |
| **P.4** | Compose not replace | Port (`agent-core/ports.rs`) for swapping adapters; agent-core lib is independent → swap GUI | A.1.5 selective overlay; A.3.7 patterns A/B/C |
| **P.5** | Three layers of specificity | ARCHITECTURE.md points to blueprint by name+section, does not copy | SSOT discipline |
| **P.6** | Product Portfolio (2 PL) | Single workspace; `ProductLine` discriminator; deployment config per-PL | A.1.9 single codebase; A.1.11 namespace per-PL; A.1.14 lifecycle per-PL ledger (contract); A.1.23 per-PL infra (deferred); A.1.24 Org scoped 1 PL; A.3.8 PL composition |
| **P.7** | PLG + Architecture Moat | Repo PUBLIC from Day 1; agent-core auditable; control-plane closed | A.1.4 trust crypto + open client; Tailscale model |
| **P.8** | Trigger-Based Activation | Scope gate — DO NOT pre-add Org/Workspace/F3/Conf VM crate; Enterprise skeleton (ZERO infra) | A.1.18 "Day 1 = operating the Enterprise PL"; A.1.23 dedicated infra trigger-activated; A.1.24 construct deferred-by-trigger |

**Reading in reverse**: an invariant is "satisfied" if (a) the principle that drives it is structurally committed in client/, **OR** (b) NA for client + no leak.

-----

## H.3 — Coverage matrix Part A (A.1.1-A.1.24)

| Invariant | Enforcing principle | Group | Where satisfied / NA reason | Status 1.1 |
|---|---|---|---|---|
| A.1.1 data/control separated | P.1, P.4 | STRUCTURAL | `agent-core` has no module sending user payload over NATS | ✅ structural (skeleton) |
| A.1.2 need-to-know | P.1 | STRUCTURAL (partial) | Agent does NOT cache peer list; broker decision JIT | 🟡 pending broker (1.2) |
| A.1.3 identity-based | P.1 | CONTRACT | `proto.SubmitIntent(Intent{identity_claim})` | 🟡 contract skeleton |
| A.1.4 agent OPEN | P.7, P.1 | STRUCTURAL | Repo PUBLIC from Day 1; `crypto` intensity Critical | ✅ structural |
| A.1.5 selective overlay | P.4 | STRUCTURAL | Agent enable Path 2; Path 1 untouched; patterns A/B/C | 🟡 pending Path 2 impl |
| A.1.6 fail-closed default | P.1, P.2 | STRUCTURAL | Broker unreachable → no new tunnel; existing TTL expire | 🟡 pending broker client |
| A.1.7 JIT lazy tunnel | P.1 | STRUCTURAL | Agent TTL 15min + idle timeout 5-10min | 🟡 pending tunnel manager |
| A.1.8 append-only ledger | P.1 | CONTRACT | `ledger-client` verify hash-chain | 🟡 skeleton |
| A.1.9 single codebase | P.6 | STRUCTURAL | 1 Cargo workspace; `ProductLine` discriminator | ✅ structural |
| A.1.10 tier-aware | P.2 | STRUCTURAL | Tier = enum (no soft fallback) | 🟡 enum not fully defined yet |
| A.1.11 federation-ready namespace | P.6 | CONTRACT | `proto` subject `<pl>.tenant.<id>.>`; entity carries `product_line+tenant_id` | 🟡 skeleton |
| A.1.12 honesty | P.3 | STRUCTURAL | T/A marking + "Owner responsibilities" surface | ✅ structural |
| A.1.13 operational policy ledger | P.1 | NA-client | Control-plane owns | ✅ NA (no leak) |
| A.1.14 customer lifecycle ledger per-PL | P.6 | NA-client | Control-plane vendor-signed | ✅ NA |
| A.1.15 admin first-class | P.1, P.2 | CONTRACT | `proto.SubmitAdminAccessIntent`; `AdminPersona`/`AdminAccessPolicy` | 🟡 contract skeleton |
| A.1.16 vendor role per-PL | P.6 | NA-client | Control-plane | ✅ NA |
| A.1.17 control plane access matrix | P.1 | NA-client | Control-plane | ✅ NA |
| A.1.18 vendor root key custody per-PL | P.2, P.6, P.8 | DEFERRED + CONTRACT | Personal CA skeleton + ceremony rehearsed 1.1 (non-prod); Enterprise = 2.1; client verifies cert chain via `crypto` | 🟡 Personal rehearsed-only |
| A.1.19 release lifecycle | P.1, P.8 | STRUCTURAL (CI/CD) | Hosted CI + Cosign baseline; N-2 backwards compat | 🟡 pending CI setup |
| A.1.20 agent update + capability negotiation | P.1 | STRUCTURAL | `agent-daemon` rollback + N-1 binary; capability flag | 🟡 pending |
| A.1.21 supply-chain | P.1, P.2 | STRUCTURAL | Pin dep `Cargo.toml`; Cosign verify; no dynamic plugin | 🟡 partial (no Cosign verify yet) |
| A.1.22 critical node enrollment | P.2 | CONTRACT | `proto.Enroll(EnrollmentCompletion)`; hardware attestation field; 3-party sig | 🟡 contract skeleton |
| A.1.23 per-PL infra isolation | P.6, P.8 | DEFERRED + CONTRACT | Namespace per-PL in `proto`; runtime config | 🟡 contract OK; deploy config TBD |
| A.1.24 Org/Workspace governance | P.6, P.8 | DEFERRED (Part C `[A]`) | DO NOT pre-add types to `domain-core` (anti-pattern Part C §H.7.2) | ✅ structurally deferred (correct) |

**Total**: 9 ✅ + 15 🟡 + 0 ⛔ = 24.

-----

## H.4 — A.3 pattern + A.4 NFR + A.5 trust map

| Element | Group | Location | Status |
|---|---|---|---|
| A.3.1 hexagonal 1-crate-1-component | STRUCTURAL | Crate map ARCHITECTURE.md H.2 | ✅ |
| A.3.2 event-driven control plane | NA-client + CONTRACT | Agent publish event via `proto` | 🟡 |
| A.3.3 JIT lazy | = A.1.7 | = A.1.7 | 🟡 |
| A.3.4 defense-in-depth | STRUCTURAL (architectural) | Design ≥2 layer per threat | ✅ |
| A.3.5 append-only as truth | = A.1.8 | = A.1.8 | 🟡 |
| A.3.6 tenant+PL scoped namespace | = A.1.11 | = A.1.11 | 🟡 |
| A.3.7 selective overlay | = A.1.5 | = A.1.5 | 🟡 |
| A.3.8 PL composition | STRUCTURAL | Single workspace + `ProductLine` | ✅ |
| **A.4 (all sub-targets)** | — | `[A]` not yet measured (owner Part A H.7 #5); A.4.1 <100MB applies to the mesh-agent unit, not the GUI | 🟡 `[A]` |
| **A.5 trust map** | STRUCTURAL + CONTRACT | Client embodies "Mesh agent on node" trust assumption (Part A §A.5.2) + per-PL trust chain (cert verify cross-PL fails at TLS per Part B §B.5.1) | 🟡 partial |

**A.2 in-scope alignment**: Mesh agent (5 platform) + Client UI cross-platform + CLI + API automation = explicit in-scope per Part A §A.2.1. ✅

-----

## H.5 — Owner responsibilities

1. **Ratify methodology** — 4-category coverage + principle-derived. Owner signs off that "NA-for-client" is the correct judgment (A.1.13/14/16/17 belong to control-plane).
2. **Update cadence** — this file refreshes on exit from each milestone (1.2 broker, 1.3 monetization, 1.4 team tier + Phase 2 readiness). 🟡 → ✅ when structural commit + test pass (mechanism in `qc-discipline.md`).
3. **NFR A.4 commitment scope** — the A.4 subset (uptime SLO, force-upgrade window A.1.20) will go into customer contracts — do *NOT* quote numbers from this file as already-guaranteed (Part A H.7 #5).
4. **A.1.24 deferred = correct** — owner signs off on NOT pre-adding `Organization`/`Workspace` to "close the gap" (anti-pattern Part C §H.7.2).

-----
-----

# [R] — Verification section

## R1 — Method

**Verification level**: structural-permission (P.1), not runtime-verified. ✅ at the milestone skeleton means code/structure enforces directly OR NA + no leak. 🟡 = structure permits, implementation pending. ⛔ = structure blocks → STOP + amend.

**Derivation tracing to Part 0**: the "Enforcing principle" column in H.3 = trace to P.1-P.8. Structural commitment with no principle backing = `[A?]` awaiting verification.

**Mechanism to transition 🟡 → ✅**: invariant test passes per pattern `docs/qc-discipline.md` H.2 Layer 3 + marker `QC-invariant[A.1.x]`.

## R2 — T/A markings

- **`[T]`**: 24 Part A invariant statement (full text Part A §A.1); principle P.1-P.8 (Part 0 §1); Tailscale model (Part D §D.2 + Part 0 Case Study 1).
- **`[A]`**: 15 items 🟡 — structure permits, implementation pending; NFR A.4 numbers (Part A H.7 #5).
- **`[A risk-accepted, owned]`**: A.1.24 construct deferred (Part A H.7 #12c); Personal PL SingleCustodian forever (Part A H.7 #1).

## R3 — Log

- **init** (2026-06-11): reviewed 24 invariants + A.3/A.4/A.5; derived from P.1-P.8; matrix 9 ✅ / 15 🟡 / 0 ⛔. Snapshot milestone 1.1 Founding skeleton. Born from `INVARIANT-COVERAGE.md` (deleted) during refactor to CP structure.

-----
