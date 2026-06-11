# Architecture — client/ (OPEN)

> **Scope**: crate map · deployable units · open/closed boundary · binding invariants index · scope hiện tại.
> **SSOT** `[T per P.5 + Part D §D.4]`: file này **trỏ** vào blueprint theo *tên + section* (Part 0/A/B/C/D ở `workspace/`), không copy nội dung. Code mâu thuẫn Part A invariant → **Part A thắng**.
>
> **Cách đọc** (kim tự tháp ngược, D-00 §4):
> - **[H] — Dành cho coder/owner: hiểu & ra quyết định.** Đọc hết [H] là đủ để viết dòng code đầu tiên đúng. Cuối [H] có **"Việc của owner"** gom quyết định human phải đứng tên.
> - **[R] — Phần kiểm chứng** (cuối): truy vết từng crate/quyết định về Part A/B/C/D, T/A markings, danh sách `[A]`, log. Đọc nhanh có thể bỏ qua.

-----
-----

# [H] — Dành cho coder/owner

## H.0 — Tóm tắt chốt trước

Repo này = **phần OPEN** của P2P Zero Trust Platform (mô hình Tailscale chính xác — client open, control-plane closed) `[T per Part D §D.2 + Tailscale precedent]`. Chứa **3 unit**: Mesh Agent (5 platform) + Client UI (Tauri 2 + web admin frontend) + CLI. Mọi crate ở repo này = OPEN; logic control-plane (broker/identity/policy/audit/edge/ML/billing) sống ở `control-plane/` private — *không bao giờ* commit vào đây `[T per A.1.4 + Part D §D.4]`.

**Bốn cam kết chịu lực:**
1. **Single codebase phục vụ 2 Product Line** (Personal Tier A + Enterprise Tier B) qua deployment config, không fork crate `[T per A.1.9 + Part D §D.1.2]`.
2. **Hexagonal, mỗi major component = 1 crate** — port/adapter seam giữ ranh giới 11 bounded context (B.3.x), seam tách microservice sau `[T per A.3.1 + Part D §D.1.5/1.6]`.
3. **Agent OPEN auditable** — customer audit code chạy trên node của họ; đây là một phần moat `[T per A.1.4 + P.7]`. Open-source rollout từ Day 1 (milestone 1.1/1.2) `[T per Part C §H.1.4]`.
4. **Scope gate (P.8)** — chỉ build cái milestone Part C hiện tại authorize; KHÔNG pre-build Phase 2 infra / Org/Workspace (A.1.24) / F3 capability (HSM/Conf VM/BYOK) trước trigger `[T per Part C §H.7.2 anti-pattern]`.

> ⚠️ **Trung thực epistemic**: license = TBD `[A pending owner — H.5 #1]`; toàn bộ NFR A.4 = `[A]` chưa đo (owner xác nhận Part A H.7 #5); Tauri 2 mobile là "stable nhưng chưa first-class" `[T per Tauri team, Part D §D.3.2]` — reassess trigger nếu consumer-mobile-polish thành viral lever.

-----

## H.1 — Repo là gì, không là gì

**Deployable units ở repo này** `[T per Part D §D.1.3]`:

| # | Unit | Chạy ở đâu | Bounded context | Milestone |
|---|---|---|---|---|
| 1 | **Mesh Agent** (5 platform: Linux/macOS/Windows/iOS/Android) | Customer node | B.3.4 Data Plane + Agent API client | 1.1 core, 1.2 broker integration |
| 5 | **Client UI** (desktop+mobile GUI + web admin console frontend) | Customer device + browser | UI layer | 1.1 "hello world" |
| — | **CLI** (phụ, không độc lập) | Customer machine | A.2.1 management | 1.1 skeleton |

**KHÔNG thuộc repo này** (sống ở `control-plane/` private) `[T per Part D §D.2 + §D.4]`:
broker · identity · policy · audit · lifecycle · edge channel · WAF/DLP inspection sidecar · tier-feature-set · billing · detection/ML. Nghi ngờ một thứ thuộc control-plane → **không** thuộc đây.

**Product Line** `[T per A.1.9 + Part B §B.1.1]`:
- **Personal (Tier A)** — F0, F0-Plus, F1 Starter. Shared infra (logical isolation). Namespace `personal.tenant.<id>.>`.
- **Enterprise (Tier B)** — F1 Growth, F2 Growth, F3 Enterprise. Dedicated NATS Account + RDS schema từ Day 1 (A.1.23). Namespace `enterprise.tenant.<id>.>`.
- *F1 Starter ≠ F1 Growth* — cùng số, khác PL, khác infra. Cross-PL migration = tạo `Customer` mới (Part B §B.1.8), không phải tier transition `[T per Part A §A.1.14 + Part B §B.1.1]`.

-----

## H.2 — Crate map → bounded context

| Crate | Vai trò | Layer (A.3.1) | Open/closed |
|---|---|---|---|
| `domain-core` | shared entity types (`Customer`, `Tenant`, `Node`, `ProductLine` discriminator…) — agent-side scope | domain | OPEN (shared contract) |
| `proto` | gRPC Agent API (B.5.1) + REST Admin API contract types (B.5.2) | ports/contract | OPEN (shared contract) |
| `crypto` | crypto primitives (cite mọi primitive `[T per source]` — intensity Critical) | adapter | OPEN |
| `ledger-client` | append-only ledger verify client-side (A.1.8) | adapter | OPEN |
| `agent-core` | lib lõi agent — **lib độc lập** để framework swappable (D.3.1) | domain + application + ports | OPEN |
| `agent-daemon` | process daemon (NFR A.4.1) | adapter/entrypoint | OPEN |
| `cli` | CLI shell trên agent-core | adapter/entrypoint | OPEN |
| `gui/src-tauri` | Tauri 2 shell — scaffold tại milestone 1.1 (`cargo tauri init`) | adapter/entrypoint | OPEN (thin) |
| `frontend/{shared,app-gui,app-admin}` | web-tech UI tái dùng cho GUI + web admin (D.3.2) | adapter/entrypoint | OPEN |

**Shared contract**: `proto` + `domain-core` — `control-plane/` depends ngược vào chúng `[T per Part D §D.4]`. Đổi contract = đổi cả hai phía → **cần human review kỹ**.

> **A.1.24 deferred**: `Organization` / `Workspace` (Part B §B.1.1, ratified owner 2026-06-05) là **governance layer chưa implement**. Construct gate bởi trigger `L_subsidiary`, milestone 2.3/3.3 `[T per Part C §H.6]`. KHÔNG pre-add vào `domain-core` ở milestone 1.1 — anti-pattern Part C §H.7.2 ("pre-build Org/Workspace/delegation trước L_subsidiary").

-----

## H.3 — Binding invariants index (full text trong Part A §A.1.x)

Vi phạm bất kỳ cái nào = **STOP, báo human** (amend Part A trước, không tự quyết). Full text Part A `[T per Part A §A.1]`.

| ID | Tóm tắt 1 dòng | Hệ quả khi code |
|---|---|---|
| **A.1.1** | data plane ≠ control plane, tách tuyệt đối | không nhét logic control-plane vào agent |
| **A.1.4** | agent OPEN, customer audit được | giữ agent-core là lib độc lập, auditable |
| **A.1.9** | single codebase, KHÔNG fork Personal Tier A vs Enterprise Tier B | PL = deploy dim, không phải trục chia code (D.1.2) |
| **A.1.11** | namespace per-PL từ Day 1 (`<pl>.tenant.<id>.>`) | mọi entity/subject mang `product_line` + `tenant_id` (A.3.6) |
| **A.1.20** | agent update + capability negotiation (D.1.7) | agent cũ graceful degrade; rollback an toàn; force-upgrade theo SLO |
| **A.1.21** | supply-chain integrity | pin dep version, không thêm dep tùy tiện, no dynamic plugin, signed commit + Cosign artifact |
| **A.1.23** | per-PL infra isolation: Tier A shared / Tier B dedicated NATS+RDS từ Day 1; F3 Conf VM = trigger Phase 3 | code để chỗ cho per-PL deployment config; không hardcode single-PL |
| **A.1.24** | `Organization` + `Workspace` = governance layer, KHÔNG isolation | đừng mô hình Org/Workspace như cô lập hạ tầng; cấm Org cross-PL; "đổi domain = enroll node mới dưới TenantCA đích" |
| **A.3.1** | hexagonal, mỗi component = 1 crate | giữ port/adapter seam; không hợp nhất crate qua boundary |
| **A.4.1** | agent-daemon NFR `[A]` (latency, <100MB) | con số GUI **không** tính vào budget này (D.3.2); toàn bộ A.4 = `[A]` chưa đo |

-----

## H.4 — Quyết định Part D đã chốt (re-state cho coder)

| Quyết định | Chọn | Nguồn | Reassess |
|---|---|---|---|
| Open/closed boundary | Open client + closed control-plane (Tailscale model) | Part D §D.2 | none — derive từ A.1.4 + P.7 |
| Client UI framework Phase 1-2 | **Tauri 2** | Part D §D.3 (resolved at Part C §H.8.5 #1) | P.8 trigger: nếu consumer-mobile-polish thành viral lever → Flutter mobile shell (D.3.3) |
| Repo structure | 2 code repo (open client / closed control-plane) + shared open crates | Part D §D.4 | none |
| OS rollout timing | client repos public từ Day 1 (milestone 1.1) | Part C §H.1.4 + Part D §D.5 | none |
| Frontend framework (React/Svelte/Vue) | **TBD per team** | Part D §D.7 + frontend/README | chốt khi scaffold frontend ở milestone 1.1 |
| License (workspace) | **TBD** | Part D §D.7 | chốt trước public — H.5 #1 |

-----

## H.5 — Current scope: Milestone 1.1 (Founding skeleton)

**Entry**: vendor founding. **Allocation**: ~95% Tier A / ~5% Tier B `[T per Part C §H.1.3]`.

**Built** `[T per Part C §H.3.1]`:
- Rust workspace + WireGuard mesh agent core (5 platform compile)
- Tauri 2 UI shell ("hello world" mobile+desktop)
- Personal Provisioning CA skeleton (SingleCustodian, ceremony rehearsed **once** non-prod)
- CI/CD baseline (hosted CI + Cosign)
- **Enterprise PL skeleton in code** — namespace, schema, ceremony procedure viết. **ZERO infra**, overhead <10% effort
- Client repos **public** từ Day 1

**Completion** `[T per Part C §H.3.1]`:
- 5 platforms compile + CI sign
- Personal ceremony rehearsed
- Enterprise CI staging deploy success (target ≥80%/4 tuần synthetic check ở milestone 1.4 — Phase 1→2 transition risk mitigation)
- Honesty: Enterprise skeleton ghi rõ "skeleton-only", không overpromise

**Anti-pattern guard (P.8)** `[T per Part C §H.7.2]`:
- KHÔNG pre-build Phase 2 infra (Shamir 2-of-3 ceremony, dedicated NATS/RDS) Day 1 — idle infra ~$5-15K/mo
- KHÔNG pre-build Org/Workspace/delegation (A.1.24) trước trigger L_subsidiary
- KHÔNG pre-build F3 capability (HSM, Conf VM, BYOK, TEE broker, session recording) trước F3 customer (L4)
- KHÔNG tạo crate "Enterprise-*" song song (vi phạm A.1.9 trực tiếp)

-----

## H.6 — Build & test

```bash
cargo fmt --check
cargo clippy -- -D warnings
cargo check
cargo test
# GUI (sau milestone 1.1 scaffold): cargo tauri dev   (cần Tauri toolchain)
# frontend: theo frontend/README khi framework chốt (D.3.2 TBD)
```

Trước khi báo "done" với human: chạy đủ 4 lệnh trên. Report kết quả **trung thực** — test fail thì nói fail kèm output `[T per P.3]`.

-----

## H.7 — Việc của owner: quyết định & giả định cần đứng tên

> Phần trả về owner (D-00 §3). Mỗi mục dưới *có thể* phát biểu như đã-chốt nhưng thực ra là **quyết định human phải ra** hoặc **giả định chưa kiểm chứng**.

1. **License = TBD** (Part D §D.7) — phải chốt **trước public** repo public hoá thật. Options: MIT / Apache-2.0 / BSL source-available. Hiện `Cargo.toml` để `license = "TBD"`. *Thiếu*: market signal về expectation của dev community vs enterprise audit.
2. **Frontend framework** — TBD per team (Part D §D.7); chốt khi scaffold frontend ở milestone 1.1. Options: React / Svelte / Vue (Tauri webview-agnostic).
3. **NFR A.4 con số là `[A]` chưa đo** — owner xác nhận 2026-06-05 (Part A H.7 #5). Đừng quote số NFR vào doc khách như đã-bảo-đảm; subset đi vào hợp đồng (vd uptime SLO) cần legal/ops sign-off.
4. **Tauri mobile reassess trigger** — Part D §D.3.3. *Thiếu*: định nghĩa "consumer-mobile-polish thành viral lever" cụ thể (mobile signup rate? install rate? mobile DAU/total?) — owner đứng tên trigger threshold.
5. **A.1.24 construct timing** — Part C §H.6 nói "rollout milestone 2.3/3.3 gate bởi L_subsidiary"; *ngưỡng L_subsidiary để trống — đến từ business trajectory/GTM, không bốc số ở Part C*. Owner đứng tên rằng client repo KHÔNG được pre-add `Organization`/`Workspace` type cho tới khi trigger fire.

-----
-----

# [R] — Phần kiểm chứng

## R1 — Truy vết crate/quyết định → blueprint

| Element | Bị quản bởi |
|---|---|
| 3 deployable units (#1 + #5 + CLI) | Part D §D.1.3 |
| 2-PL phục vụ 1 codebase | Part A §A.1.9, A.1.11, A.1.23; Part B §B.1.1; Part D §D.1.2 |
| Open client + closed control-plane | Part A §A.1.4; Part D §D.2; P.7; Tailscale precedent |
| Hexagonal 1-component-1-crate | Part A §A.3.1; Part D §D.1.5 |
| 11 bounded context = seam tách service | Part B §B.3; Part D §D.1.5/1.6 |
| Tauri 2 Phase 1-2 | Part D §D.3 (resolved at Part C §H.8.5 #1) |
| 2 code repo (open/closed) | Part D §D.4 |
| Open-source Day 1 (milestone 1.1) | Part A §A.1.4; Part C §H.1.4; Part D §D.5 |
| Milestone 1.1 scope + completion | Part C §H.3.1 |
| Anti-pattern guards | Part C §H.7.2 |
| `Organization` / `Workspace` deferred construct | Part A §A.1.24 (ratified); Part B §B.1.1 + §B.3.7 (statement); Part C §H.6 (timing) |
| Agent update + capability negotiation | Part A §A.1.20; Part B §B.3.10 → §B.3.3 interaction; Part D §D.1.7 |
| Single CI + Cosign artifact | Part A §A.1.19, A.1.21; Part B §B.3.10 |

## R2 — T/A markings

- **`[T]` (cấu trúc / nguồn cite được)**: tất cả invariant gọi tên trong H.3 — full text Part A; open/closed boundary derive từ A.1.4 + Tailscale precedent; Tauri 2 stable từ 02-10-2024 + footprint numbers (Part D §D.3.2 sources).
- **`[A]` (đích nhắm, chưa kiểm chứng / quyết định chưa chốt)**:
  - License (D.7) — pending owner decision.
  - Frontend framework — pending team decision khi scaffold.
  - Toàn bộ A.4 NFR (Part A H.7 #5 — owner xác nhận no measurement).
  - WAF sidecar open-candidate (Part D §D.2 honest gap) — chốt khi build WAF ở milestone 1.2.
  - "Tauri mobile đủ cho Phase 1 GUI scope" — `[A]` per Part D §D.3.2 (mobile "stable nhưng chưa first-class").
  - Tauri mobile reassess threshold — pending owner.
- **`[A risk-accepted, owned]`**: A.1.24 construct deferred-by-trigger (Part A H.7 #12c); pre-build = anti-pattern.

## R3 — Danh sách `[A]` (file này)

1. License workspace — H.7 #1.
2. Frontend framework — H.7 #2.
3. NFR A.4 numbers (latency, memory, scale) khi xuất hiện trong code/doc — H.7 #3.
4. Tauri mobile fitness cho Phase 1 GUI — gắn ở Part D §D.3.2; reassess trigger H.7 #4.
5. WAF crate location (control-plane vs open-candidate) — Part D §D.2 honest gap.
6. `Organization` / `Workspace` construct timing — H.7 #5; gate L_subsidiary (Part C §H.6.2).
7. Citation-resolve linter trong CI — defer milestone 1.1 CI (Part D §D.6 Q2; CLAUDE.md T/A section).

## R4 — Những điều file này KHÔNG khẳng định

- KHÔNG đặt invariant mới — đó là Part A; mâu thuẫn → Part A thắng (header).
- KHÔNG định domain entity mới — đó là Part B; `domain-core` follow §B.1 vocabulary.
- KHÔNG định timing/milestone — đó là Part C; H.5 chỉ re-state milestone 1.1 cho coder.
- KHÔNG định implementation choice — đó là Part D; H.4 chỉ re-state quyết định đã chốt.
- KHÔNG khẳng định NFR sẽ đạt được (A.4 = `[A]` chưa đo).
- KHÔNG khẳng định `Organization`/`Workspace` đã build (A.1.24 construct = Part C `[A]`).
- KHÔNG khẳng định license/frontend framework đã chốt.

## R5 — Nguồn, quan hệ, log

- **Quan hệ file**: trỏ Part 0/A/B/C/D ở `workspace/`; điều phối với `CLAUDE.md` (luật hành vi session) + `CONTRIBUTING.md` (commit/PR workflow) + `README.md` (one-pager) + `docs/` (4 file trace/discipline/checklist — pace-layer split per P.5).
- **Register**: framing VN; identifier/crate name/term-of-art EN.
- **Update history**:
  - **init** (skeleton, commit `56c5191`): crate map + binding index + UI framework + build/test + license.
  - **blueprint sync** (2026-06-11): thêm A.1.11/A.1.23/A.1.24 vào index; làm rõ Tier A/B naming + F1 Starter ≠ F1 Growth; mở rộng milestone 1.1 scope (5 platforms, Personal CA skeleton, Cosign, Enterprise PL skeleton); ghi A.1.24 deferred ở crate map.
  - **reflow H/R** (2026-06-11): tách [H]/[R]; rút "Việc của owner" lên (license, frontend framework, NFR commitment scope, Tauri mobile trigger, A.1.24 timing); T/A markings explicit; trace table R1 + `[A]` list R3.
  - **+R6 coverage overview** (2026-06-11): thêm R6 trạng thái invariant coverage; trỏ chi tiết vào `INVARIANT-COVERAGE.md` (suy dẫn principle list + matrix 24 invariant + Part B concept + gap close trước exit milestone).
  - **+refactor docs/ theo CP structure** (2026-06-11): suy dẫn P.5 (pace layer) + P.8 (archival per milestone) → tách 4 file: `invariant-trace.md` (pace 5y) + `concept-trace.md` (pace 3-5y) + `qc-discipline.md` (pace stable) + `phase-completion-checklist-1.1.md` (pace 6-18mo, archival). Xoá `INVARIANT-COVERAGE.md` (root) + `docs/QC-GATES.md` (gộp); chia nội dung theo pace-layer. R6 + R5 pointer cập nhật.

## R6 — Invariant coverage (overview)

**Snapshot 2026-06-11 · milestone 1.1 Founding skeleton:**

| Trạng thái | Số (24 invariant A.1.x) | Nghĩa |
|---|---|---|
| ✅ structural-land / NA-correct | **9** | Cấu trúc enforce trực tiếp HOẶC NA-for-client + client không leak logic xâm phạm |
| 🟡 contract/skeleton/pending | **15** | Cấu trúc cho phép; chờ milestone 1.2-1.4 close implementation |
| ⛔ structurally blocked | **0** | Không có cái nào bị kiến trúc chặn — điều quan trọng nhất |

**4-category coverage** (mỗi invariant rơi vào 1 nhóm) `[T per A.1.4 + Part D §D.2]`:
- **STRUCTURAL-in-client** — code repo enforce trực tiếp
- **CONTRACT-enables** — `proto`/`domain-core` cung cấp contract để control-plane enforce
- **DEFERRED-to-deployment** — code support cả 2 PL; runtime config quyết
- **NA-for-client** — control-plane scope; client không touch (verify KHÔNG leak)

**Method**: suy dẫn từ principle list (P.1-P.8) → structural commitment → invariant land. Verification ở mức *structural-permission* (P.1), không phải runtime-verified.

**6 gap structurally chưa close trước exit milestone 1.1**: `ProductLine` discriminator · `proto` subject namespace template · Tier enum no-soft-fallback · CI Cosign sign · T/A linter (defer `[A]`) · Enterprise CI staging deploy ≥80%/4 tuần (gate milestone 1.4).

**Trạng thái A.1.24 = ✅ structurally deferred (đúng)**. KHÔNG pre-add `Organization`/`Workspace` để "close gap" — anti-pattern Part C §H.7.2.

→ **`docs/` (4 file, tách theo pace layer P.5)**:
- [`docs/invariant-trace.md`](./docs/invariant-trace.md) — pace 5y · trạng thái 24 invariant Part A + suy dẫn principle-driven.
- [`docs/concept-trace.md`](./docs/concept-trace.md) — pace 3-5y · Part B B.1/B.3/B.4/B.5/B.6 → crate map + quy tắc placement.
- [`docs/qc-discipline.md`](./docs/qc-discipline.md) — pace stable · 4 lớp test + QC marker convention + STOP semantics.
- [`docs/phase-completion-checklist-1.1.md`](./docs/phase-completion-checklist-1.1.md) — pace 6-18mo · 3 gate + mapping invariant→test + scope gate + CI G1-G9 cụ thể milestone 1.1. **Archive khi exit**, tạo `-1.2.md`.

-----
