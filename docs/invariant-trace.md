# Invariant Trace — client/ vs Part A

> **Scope**: trạng thái 24 invariant Part A (A.1.1-A.1.24) + pattern A.3 + NFR A.4 + trust map A.5 trong kiến trúc client/; suy dẫn từ principle list P.1-P.8.
> **Pace layer** `[T per P.5]`: invariant = 5 năm stable; file này refresh **status snapshot** mỗi PR đụng invariant test.
> **Quan hệ**:
> - Concept Part B → `docs/concept-trace.md`
> - Cơ chế verify (test methodology + marker) → `docs/qc-discipline.md`
> - Gate per milestone → `docs/phase-completion-checklist-<X.Y>.md`
>
> **Snapshot**: 2026-06-11 · milestone 1.1 Founding skeleton.
>
> **Cách đọc** (D-00 §4): [H] trạng thái + suy dẫn; [R] method, T/A, log.

-----
-----

# [H] — Dành cho coder/owner

## H.0 — Tóm tắt chốt trước

**Verification level** = *structural-permission* (P.1), không phải runtime-verified. Một invariant `✅` ở milestone skeleton nghĩa: cấu trúc enforce trực tiếp HOẶC NA-for-client + client không leak logic xâm phạm. `🟡` = cấu trúc cho phép, runtime implementation pending. `⛔` = cấu trúc đang chặn — phải STOP + amend.

**Snapshot 2026-06-11** (24 invariant A.1.x):

| Trạng thái | Số | Nghĩa |
|---|---|---|
| ✅ structural-land / NA-correct | **9** | Cấu trúc enforce trực tiếp HOẶC NA-for-client + không leak |
| 🟡 contract/skeleton/pending | **15** | Cấu trúc cho phép; chờ milestone 1.2-1.4 close implementation |
| ⛔ structurally blocked | **0** | Không có cái nào bị kiến trúc chặn |

-----

## H.1 — Phân loại scope: 4 nhóm coverage

Part A nói TOÀN HỆ. Client là OPEN slice. Mỗi invariant rơi vào 1 trong 4 nhóm `[T per A.1.4 + Part D §D.2]`:

| Nhóm | Nghĩa | Verify thế nào |
|---|---|---|
| **STRUCTURAL-in-client** | Code repo enforce trực tiếp | Đọc crate seam + adapter |
| **CONTRACT-enables** | Client định nghĩa contract để control-plane enforce | Đọc `proto` + `domain-core` |
| **DEFERRED-to-deployment** | Code support cả 2 PL, runtime config quyết | Cargo workspace + feature flag |
| **NA-for-client** | Control-plane scope; client không touch | Verify KHÔNG có module nào leak control-plane logic |

> ⚠️ **Lỗi phải tránh**: dán nhãn "✅" cho invariant chỉ vì *không xuất hiện trong client/*. NA-for-client chỉ ✅ khi (a) đúng là control-plane scope **và** (b) client structurally không leak logic xâm phạm.

-----

## H.2 — Suy dẫn từ principle list

Mỗi structural commitment trong client/ là *suy được* từ một/nhiều principle:

| Principle | Phát biểu rút gọn | Structural commitment trong client/ | Invariant land được |
|---|---|---|---|
| **P.1** | Kiến trúc hấp thụ thực thi | Hexagonal (D.1.5): 1 crate / 1 bounded context; port/adapter seam | A.3.1 (direct); A.3.4 defense-in-depth ở architectural mức |
| **P.2** | Strict admission | Tier = enum cứng `domain-core` (no soft fallback); ceremony rehearsed milestone 1.1; KHÔNG `--skip-verification` flag | A.1.10 tier absolute; A.1.18 ceremony-based; A.1.22 enrollment ceremony |
| **P.3** | Honest gap | T/A marking convention; "Việc của owner" surface | A.1.12 honesty |
| **P.4** | Compose not replace | Port (`agent-core/ports.rs`) cho swap adapter; agent-core lib độc lập → swap GUI | A.1.5 selective overlay; A.3.7 patterns A/B/C |
| **P.5** | Three layers of specificity | ARCHITECTURE.md trỏ blueprint theo tên+section, không copy | SSOT discipline |
| **P.6** | Product Portfolio (2 PL) | Single workspace; `ProductLine` discriminator; deployment config per-PL | A.1.9 single codebase; A.1.11 namespace per-PL; A.1.14 lifecycle per-PL ledger (contract); A.1.23 per-PL infra (deferred); A.1.24 Org scoped 1 PL; A.3.8 PL composition |
| **P.7** | PLG + Architecture Moat | Repo PUBLIC từ Day 1; agent-core auditable; control-plane closed | A.1.4 trust crypto + open client; Tailscale model |
| **P.8** | Trigger-Based Activation | Scope gate — KHÔNG pre-add Org/Workspace/F3/Conf VM crate; Enterprise skeleton (ZERO infra) | A.1.18 "Day 1 = vận hành Enterprise PL"; A.1.23 dedicated infra trigger-activated; A.1.24 construct deferred-by-trigger |

**Đọc ngược lại**: invariant được "đáp ứng" nếu (a) principle dẫn nó được structurally commit trong client/, **HOẶC** (b) NA cho client + không leak.

-----

## H.3 — Coverage matrix Part A (A.1.1-A.1.24)

| Invariant | Principle ép | Nhóm | Vị trí đáp ứng / lý do NA | Trạng thái 1.1 |
|---|---|---|---|---|
| A.1.1 data/control tách | P.1, P.4 | STRUCTURAL | `agent-core` không có module gửi user payload qua NATS | ✅ structural (skeleton) |
| A.1.2 need-to-know | P.1 | STRUCTURAL (partial) | Agent KHÔNG cache peer list; broker decision JIT | 🟡 pending broker (1.2) |
| A.1.3 identity-based | P.1 | CONTRACT | `proto.SubmitIntent(Intent{identity_claim})` | 🟡 contract skeleton |
| A.1.4 agent OPEN | P.7, P.1 | STRUCTURAL | Repo PUBLIC từ Day 1; `crypto` intensity Critical | ✅ structural |
| A.1.5 selective overlay | P.4 | STRUCTURAL | Agent enable Path 2; Path 1 untouched; patterns A/B/C | 🟡 pending Path 2 impl |
| A.1.6 fail-closed default | P.1, P.2 | STRUCTURAL | Broker unreachable → no new tunnel; existing TTL expire | 🟡 pending broker client |
| A.1.7 JIT lazy tunnel | P.1 | STRUCTURAL | Agent TTL 15min + idle timeout 5-10min | 🟡 pending tunnel manager |
| A.1.8 append-only ledger | P.1 | CONTRACT | `ledger-client` verify hash-chain | 🟡 skeleton |
| A.1.9 single codebase | P.6 | STRUCTURAL | 1 Cargo workspace; `ProductLine` discriminator | ✅ structural |
| A.1.10 tier-aware | P.2 | STRUCTURAL | Tier = enum (no soft fallback) | 🟡 enum chưa định nghĩa đầy đủ |
| A.1.11 federation-ready namespace | P.6 | CONTRACT | `proto` subject `<pl>.tenant.<id>.>`; entity mang `product_line+tenant_id` | 🟡 skeleton |
| A.1.12 honesty | P.3 | STRUCTURAL | T/A marking + "Việc của owner" surface | ✅ structural |
| A.1.13 operational policy ledger | P.1 | NA-client | Control-plane owns | ✅ NA (không leak) |
| A.1.14 customer lifecycle ledger per-PL | P.6 | NA-client | Control-plane vendor-signed | ✅ NA |
| A.1.15 admin first-class | P.1, P.2 | CONTRACT | `proto.SubmitAdminAccessIntent`; `AdminPersona`/`AdminAccessPolicy` | 🟡 contract skeleton |
| A.1.16 vendor role per-PL | P.6 | NA-client | Control-plane | ✅ NA |
| A.1.17 control plane access matrix | P.1 | NA-client | Control-plane | ✅ NA |
| A.1.18 vendor root key custody per-PL | P.2, P.6, P.8 | DEFERRED + CONTRACT | Personal CA skeleton + ceremony rehearsed 1.1 (non-prod); Enterprise = 2.1; client verify cert chain qua `crypto` | 🟡 Personal rehearsed-only |
| A.1.19 release lifecycle | P.1, P.8 | STRUCTURAL (CI/CD) | Hosted CI + Cosign baseline; N-2 backwards compat | 🟡 pending CI setup |
| A.1.20 agent update + capability negotiation | P.1 | STRUCTURAL | `agent-daemon` rollback + N-1 binary; capability flag | 🟡 pending |
| A.1.21 supply-chain | P.1, P.2 | STRUCTURAL | Pin dep `Cargo.toml`; Cosign verify; no dynamic plugin | 🟡 partial (no Cosign verify yet) |
| A.1.22 critical node enrollment | P.2 | CONTRACT | `proto.Enroll(EnrollmentCompletion)`; hardware attestation field; 3-party sig | 🟡 contract skeleton |
| A.1.23 per-PL infra isolation | P.6, P.8 | DEFERRED + CONTRACT | Namespace per-PL trong `proto`; runtime config | 🟡 contract OK; deploy config TBD |
| A.1.24 Org/Workspace governance | P.6, P.8 | DEFERRED (Part C `[A]`) | KHÔNG pre-add type vào `domain-core` (anti-pattern Part C §H.7.2) | ✅ structurally deferred (đúng) |

**Tổng**: 9 ✅ + 15 🟡 + 0 ⛔ = 24.

-----

## H.4 — A.3 pattern + A.4 NFR + A.5 trust map

| Element | Nhóm | Vị trí | Trạng thái |
|---|---|---|---|
| A.3.1 hexagonal 1-crate-1-component | STRUCTURAL | Crate map ARCHITECTURE.md H.2 | ✅ |
| A.3.2 event-driven control plane | NA-client + CONTRACT | Agent publish event via `proto` | 🟡 |
| A.3.3 JIT lazy | = A.1.7 | = A.1.7 | 🟡 |
| A.3.4 defense-in-depth | STRUCTURAL (architectural) | Design ≥2 layer per threat | ✅ |
| A.3.5 append-only as truth | = A.1.8 | = A.1.8 | 🟡 |
| A.3.6 tenant+PL scoped namespace | = A.1.11 | = A.1.11 | 🟡 |
| A.3.7 selective overlay | = A.1.5 | = A.1.5 | 🟡 |
| A.3.8 PL composition | STRUCTURAL | Single workspace + `ProductLine` | ✅ |
| **A.4 (mọi sub-target)** | — | `[A]` chưa đo (owner Part A H.7 #5); A.4.1 <100MB áp mesh-agent unit, không phải GUI | 🟡 `[A]` |
| **A.5 trust map** | STRUCTURAL + CONTRACT | Client embodies "Mesh agent on node" trust assumption (Part A §A.5.2) + per-PL trust chain (cert verify cross-PL fail ở TLS per Part B §B.5.1) | 🟡 partial |

**A.2 in-scope alignment**: Mesh agent (5 platform) + Client UI cross-platform + CLI + API automation = explicit in-scope per Part A §A.2.1. ✅

-----

## H.5 — Việc của owner

1. **Ratify methodology** — 4-category coverage + principle-derived. Owner đứng tên "NA-for-client" là phán xét đúng (A.1.13/14/16/17 thuộc control-plane).
2. **Update cadence** — file này refresh khi exit mỗi milestone (1.2 broker, 1.3 monetization, 1.4 team tier + Phase 2 readiness). 🟡 → ✅ khi structural commit + test pass (cơ chế ở `qc-discipline.md`).
3. **NFR A.4 commitment scope** — subset A.4 (uptime SLO, force-upgrade window A.1.20) sẽ vào hợp đồng khách — *KHÔNG* được quote số từ file này như đã-bảo-đảm (Part A H.7 #5).
4. **A.1.24 deferred = đúng** — owner đứng tên KHÔNG pre-add `Organization`/`Workspace` để "close gap" (anti-pattern Part C §H.7.2).

-----
-----

# [R] — Phần kiểm chứng

## R1 — Method

**Verification level**: structural-permission (P.1), không phải runtime-verified. ✅ ở milestone skeleton nghĩa code/structure enforce trực tiếp HOẶC NA + không leak. 🟡 = cấu trúc cho phép, implementation pending. ⛔ = cấu trúc chặn → STOP + amend.

**Suy dẫn truy tới Part 0**: cột "Principle ép" trong H.3 = trace tới P.1-P.8. Structural commitment không có principle backing = `[A?]` chờ verify.

**Cơ chế chuyển 🟡 → ✅**: invariant test pass theo pattern `docs/qc-discipline.md` H.2 Lớp 3 + marker `QC-invariant[A.1.x]`.

## R2 — T/A markings

- **`[T]`**: 24 Part A invariant statement (full text Part A §A.1); principle P.1-P.8 (Part 0 §1); Tailscale model (Part D §D.2 + Part 0 Case Study 1).
- **`[A]`**: 15 mục 🟡 — structure permits, implementation pending; NFR A.4 numbers (Part A H.7 #5).
- **`[A risk-accepted, owned]`**: A.1.24 construct deferred (Part A H.7 #12c); Personal PL SingleCustodian forever (Part A H.7 #1).

## R3 — Log

- **init** (2026-06-11): rà 24 invariant + A.3/A.4/A.5; suy dẫn P.1-P.8; matrix 9 ✅ / 15 🟡 / 0 ⛔. Snapshot milestone 1.1 Founding skeleton. Sinh ra từ `INVARIANT-COVERAGE.md` (xoá) khi refactor sang CP structure.

-----
