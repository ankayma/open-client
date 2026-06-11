# client/ — Session behavior khi Claude code repo OPEN

Repo này **PUBLIC** (Part D §D.2/§D.4, mô hình Tailscale). Coding do Claude làm 100%; human review + QC test. File này là luật hành vi cho mọi coding session ở đây.

> **SSOT** `[T per P.5 + Part D header]`: blueprint (Part 0/A/B/C/D trong doc repo `workspace/`) là nguồn chân lý. File này + `ARCHITECTURE.md` chỉ **trỏ theo tên + section**, không copy nội dung. Code mâu thuẫn Part A invariant → **Part A thắng**, STOP và báo human (amend Part A trước), không tự quyết.

## Golden rule (PUBLIC repo)

**Không bao giờ commit IP closed vào repo này** `[T per A.1.4 + P.6]`: logic control-plane (broker/identity/policy/audit/edge/ML/billing), secret/khóa thật, customer data, hay nội bộ Part A/B của control-plane. Repo này chỉ chứa: mesh agent (Deployable 1), CLI, Client UI (Deployable 5), shared OPEN protocol/domain crates. Nghi ngờ một thứ thuộc control-plane → nó **không** thuộc đây.

## Đọc trước khi viết dòng code đầu tiên

1. `ARCHITECTURE.md` (repo này) — crate map, deployable, open/closed boundary, **binding invariants index** + R6 coverage overview.
   - Khi cần verify (tách theo pace layer P.5): `docs/invariant-trace.md` (24 invariant Part A status) · `docs/concept-trace.md` (Part B B.1/B.3/B.4 → crate map) · `docs/qc-discipline.md` (4 lớp test + QC marker + STOP semantics) · `docs/phase-completion-checklist-<milestone>.md` (3 gate + mapping + CI G1-G9 cụ thể; archive khi exit).
2. Blueprint (nếu có `../../workspace/` trên máy maintainer) — đọc đúng section, không đọc tràn:
   - `../../workspace/02-architecture/invariants/part-a-foundation.md` §H.2 — các invariant trong index dưới đây (hard constraint).
   - `../../workspace/02-architecture/invariants/part-b-domain.md` §H.2 (ubiquitous language) + §H.3 (11 bounded context) — SSOT cho entity types trong `domain-core`/`proto`.
   - `../../workspace/02-architecture/phase/part-c-phase-evolution.md` §H.3 (Phase 1 milestone) + §H.6 (A.1.24 rollout) + §H.7.2 (anti-pattern) — **scope gate** (chỉ build cái phase này cho phép).
   - `../../workspace/02-architecture/implementation/part-d-internal-impl.md` §D.1 (unit/crate), §D.2 (open/closed), §D.3 (Tauri).
   - `../../workspace/01-philosophy/vendor-charter/part-0.md` §1 — P.1, P.2, P.8, P.9.
   - `../../workspace/D-disciplines/t-a-coding-core.md` — T/A coding discipline + format `[T:source-id]` (§1,§3); intensity (§7); linter rules (§8). `t-a-coding-p2p.md` §3 (crypto), §6 (platform) = subset agent-relevant. General: `D-02-t-a-discipline.md`.
3. README.md + `Cargo.toml` — crate đã có; đừng đặt lại tên (anti-pattern naming inconsistency).

## Binding constraints (guard — vi phạm = STOP, báo human)

| Invariant | Nghĩa (1 dòng — full text ở Part A) | Hệ quả khi code |
|---|---|---|
| **A.1.1** | data plane ≠ control plane, tách tuyệt đối | không nhét logic control-plane vào agent |
| **A.1.4** | agent OPEN, customer audit được | giữ agent-core là lib độc lập, auditable |
| **A.1.9** | single codebase, **không** fork Personal Tier A vs Enterprise Tier B | PL là deploy dimension, **không** phải trục chia code/crate (D.1.2) |
| **A.1.11** | namespace per-PL từ Day 1 (`<pl>.tenant.<id>.>`) | mọi entity/subject mang `product_line` + `tenant_id` (A.3.6); không global namespace |
| **A.1.20** | agent update + capability negotiation (Part D §D.1.7) | agent cũ phải graceful degrade với feature mới; rollback an toàn; force-upgrade theo SLO |
| **A.1.21** | supply-chain integrity | pin dep version, không thêm dep tùy tiện, không dynamic plugin, signed commit/Cosign artifact |
| **A.1.23** | per-PL infra isolation (Tier A shared / Tier B dedicated từ Day 1) | code phải để chỗ cho per-PL deployment config; không hardcode single-PL assumption |
| **A.1.24** | `Organization` + `Workspace` = governance layer, **không** isolation | đừng mô hình Org/Workspace như cô lập hạ tầng; cấm Org cross-PL; "đổi domain = enroll mới" |
| **A.3.1** | hexagonal, mỗi component = 1 crate | giữ port/adapter seam; không hợp nhất crate qua boundary |
| **A.4.1** | agent-daemon NFR `[A]` (latency, <100MB) | con số GUI **không** tính vào budget này (D.3.2); toàn bộ A.4 là `[A]` chưa đo |

**Scope gate (P.8)** `[T per Part C §H.3.1 + §H.7.2]`: chỉ build cái milestone Part C hiện tại authorize. Không pre-build feature phase sau ("để sẵn cho chắc" = P.8 violation). Anti-pattern Part C §H.7.2: pre-build Org/Workspace/delegation trước trigger L_subsidiary; pre-build F3 capability trước F3 customer.

**Milestone 1.1 — Founding skeleton** (Part C §H.3.1): Rust workspace + WireGuard mesh agent core (5 platforms: Linux/macOS/Windows/iOS/Android); Tauri 2 UI shell ("hello world" mobile+desktop); client repos **public** từ Day 1 (agent core + CLI + UI); Personal Provisioning CA skeleton (SingleCustodian, ceremony rehearsed once non-prod); CI/CD baseline (hosted CI + Cosign); **Enterprise PL skeleton in code** (namespace, schema, ceremony procedure viết — **ZERO infra**, overhead <10% effort). Completion = 5 platforms compile + CI sign + Personal ceremony rehearsed + Enterprise CI staging deploy ≥80%/4 tuần (Phase 1→2 transition risk mitigation, milestone 1.4).

## T/A marking trong code `[T per t-a-coding-core §0-§3 + P.9]`

CLAUDE.md này = "system prompt" tự nạp (thay cho core §1.1 paste-template). Mark mọi quyết định engineering trong code comment:

- **`[T:source-id]`** = có nguồn verify. **Bắt buộc format**: invariant `[T:A.1.4]`, principle `[T:P.7]`, spec `[T:RFC-7855§5.4]`, lib có version `[T:tokio@1.35-spawn_blocking]`. **Bare `[T]` không source = treat như `[A?]`** (core §3.2).
- **`[A]`** = assumption/inference + kèm cách verify ("verify by load test milestone 1.2"). `[A]` = honest gap mức code (P.3).
- **`[A?]`** = chưa verify; **default khi không chắc** (không bao giờ `[T]` by default). Promote → `[A]`/`[T]` sau verify.
- Multi-claim comment → **tách từng claim**. `[A]` tie vào trigger, không vào ngày ("verify post-L1", không "Q3").
- **Pushback rule**: human hỏi `[T]` → cite source (file:line / RFC / invariant) HOẶC downgrade `[A]`. Không defend `[T]` thiếu nguồn.
- **Intensity** (core §7, p2p §3/§6): crypto (`crypto`, `agent-core`) + platform `#[cfg]` = **Critical** (cite mọi primitive/platform doc); core logic = Standard; util/logging = Light; generated `proto` binding = Skip.
- **Enforce**: linter/CI citation-resolve (core §8.1) = **defer milestone 1.1 CI** (D.6 Q2) `[A]`; hiện convention thủ công + human review.

## Discipline khi viết

- **P.2 (không shortcut)**: cấm `--skip-verification`-style flag "tạm thời". Front-load đúng từ đầu.
- **P.3 (honest gap)**: chỗ chưa làm/giả định → `// TODO[A]:` + lý do, không giấu.
- **Crate seam**: 11 bounded context = seam tách service sau (D.1.5). Giữ ranh giới; không leak domain qua crate khác.
- **PL discipline (A.1.9 + A.1.11 + A.1.23)**: code `agent-core`/`proto`/`domain-core` phải support cả Personal (Tier A: F0/F0-Plus/F1 Starter) lẫn Enterprise (Tier B: F1 Growth/F2 Growth/F3 Enterprise) qua **feature flag + config**, không qua fork crate. Cross-PL: trust chain riêng (A.1.18) — agent connect đúng broker per-PL theo node cert; cert verify fail cross-PL ở TLS layer (Part B §B.5.1). `[F1 Starter]` ≠ `[F1 Growth]` — *cùng số, khác PL, khác infra*.
- **A.1.24 discipline**: `Organization`/`Workspace` là Part C [A], **chưa implement**. Đừng pre-add type vào `domain-core` ở milestone 1.1 (anti-pattern Part C §H.7.2). Khi có, Org scoped 1 PL, Workspace logic-trong-Tenant — KHÔNG isolation layer.

## Workflow với human QC

1. Commit nhỏ, focused, một concern/commit — dễ review.
2. Mọi behavior change ship kèm test. Không có test = chưa done.
3. Trước khi báo "done": chạy `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo check`, `cargo test`. Report kết quả **trung thực** — test fail thì nói fail kèm output, đừng tô hồng.
4. Việc cần human quyết (không tự làm): chọn license (D.7), bất cứ thay đổi nào cần amend Part A invariant, build ngoài scope milestone, thêm dependency mới đáng kể.

## Language
Code/identifier/commit subject = English. Giải thích/PR description = Vietnamese (trừ khi human viết English trước).

## Commit
Chỉ commit/push khi human yêu cầu.
