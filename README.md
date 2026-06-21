# Ankayma — Sovereign Zero-Trust Mesh (OPEN client)

**Ankayma** là một **sovereign identity-aware zero-trust mesh**: nhà cung cấp *không giải mã được* dữ liệu của khách, và khách **tự kiểm chứng được điều đó** thay vì phải tin lời hứa `[T per brand-positioning + A.1.4]`.

Khác với Cloudflare / Zscaler / Tailscale — vốn để dữ liệu của khách đi qua hạ tầng của chính họ — Ankayma **tách hẳn data plane khỏi control plane**, nên dữ liệu nghiệp vụ riêng của khách *không bao giờ* đi qua hạ tầng Ankayma. Đây là chủ quyền **gắn vào cấu trúc** `[T per A.1.1 + P.7]`.

Repo này là **phần OPEN** của Ankayma, theo đúng *mô hình Tailscale*: **client mở, control-plane đóng** `[T per Part D §D.2]`. Tất cả thứ chạy trên máy khách hàng đều ở đây và audit được; logic control-plane (broker / identity / policy / audit / edge / billing / ML) sống ở repo riêng, *không bao giờ* commit vào đây `[T per A.1.4 + P.7]`.

> **SSOT** `[T per P.5 + P.9]`: nguồn chân lý là **blueprint** (Part 0/A/B/C/D) + brand-positioning. README chỉ **trỏ** theo *tên + section*, không copy. Code mâu thuẫn invariant Part A → **Part A thắng**.

---

## 1. Ba trụ định vị

Mọi quyết định kiến trúc ở đây phục vụ ba trụ thương hiệu (`[T per brand-positioning]`):

1. **Chủ quyền là lõi** — data plane tách control plane (A.1.1); vendor không giải mã được (A.1.4); cô lập per-tenant + root key riêng mỗi Product Line (A.1.23/A.1.18). Đây là moat — thứ mô hình hub-spoke của đối thủ không sao chép được nếu không xây lại từ nền móng.
2. **Trung thực là khác biệt niềm tin** — mọi khoảng trống / chỗ chưa đo được khai báo công khai kèm trạng thái, thay vì marketing "unhackable" `[T per P.3]`. Đội cybersec/compliance của khách *thưởng* cho trung thực.
3. **Bồi đắp, không thay thế** — bật bảo mật mà không phá hệ đang chạy; overlay identity-aware lên đầu tư sẵn có của khách `[T per P.4]`.

---

## 2. Repo này là gì

Ankayma có hai code repo `[T per Part D §D.4]`:

| Repo | Nội dung | Trạng thái |
|---|---|---|
| **open-client** (repo này) | mesh agent + CLI + Client UI + shared OPEN contract | **PUBLIC** từ Day 1 |
| control-plane | broker, identity, policy, audit, edge, billing, ML | private |

**Deployable units ở đây** `[T per Part D §D.1.3]`:

1. **Mesh Agent** — WireGuard data-plane agent, 5 platform (Linux / macOS / Windows / iOS / Android). Chạy trên node khách.
2. **Client UI** — GUI desktop+mobile (Tauri 2) + web admin console frontend.
3. **CLI** — công cụ quản lý phụ trên `agent-core` (không phải unit độc lập).

Agent **OPEN, auditable** chính là cách Ankayma chứng minh chủ quyền: khách đọc & kiểm chứng code chạy trên node của họ, không phải tin lời vendor `[T per A.1.4 + P.7]`.

---

## 3. Một thương hiệu, hai dòng sản phẩm

Một thương hiệu ô (Ankayma) phủ trên **hai dòng sản phẩm tách biệt hoàn toàn** — mỗi dòng có root key / hạ tầng / threat model riêng `[T per P.6 + brand-positioning]`. Nhưng **một codebase**: PL là *deployment dimension*, không phải trục chia code → không fork crate theo PL `[T per A.1.9 + Part D §D.1.2]`.

| Dòng | Tier | Feature | Infra | Namespace | Vai trò |
|---|---|---|---|---|---|
| **Personal** | Tier A | F0 · F0-Plus · F1 Starter | shared (logical isolation) | `personal.tenant.<id>.>` | phễu thu hút + bằng chứng uy tín |
| **Enterprise** | Tier B | F1 Growth · F2 Growth · F3 Enterprise | dedicated NATS + RDS từ Day 1 (A.1.23) | `enterprise.tenant.<id>.>` | cỗ máy doanh thu + nơi moat nằm |

- Mọi entity/subject mang `product_line` + `tenant_id` từ Day 1 `[T per A.1.11 + A.3.6]`.
- *F1 Starter ≠ F1 Growth* — cùng số, khác PL, khác infra.
- Cross-PL = tạo `Customer` mới, **không** phải tier transition `[T per A.1.14 + Part B §B.1.1]`.

**Entity hierarchy** (Part B §B.1.1): `Organization`* → `Customer` (billing, 1 PL) → `Tenant` (cô lập kỹ thuật, 1 NATS Account) → `Workspace`* → `Node` / `User`. (`Organization`/`Workspace` = governance layer **chưa implement** — xem §7.)

---

## 4. Cấu trúc

```
crates/
  domain-core     shared entity types (Customer, Tenant, Node, ProductLine…) — agent-side scope
  proto           gRPC Agent API + REST Admin API contract types (B.5.1 / B.5.2)
  crypto          crypto primitives — intensity Critical, cite mọi primitive
  ledger-client   append-only ledger verify client-side (A.1.8)
  agent-core      lib lõi agent — lib độc lập để framework swappable (D.3.1)
  agent-daemon    process daemon → bin `agent` (+ `agent-nc-escrow`, feature key-escrow-build)
  cli             CLI shell trên agent-core → bin `mesh`
gui/
  src-tauri       Tauri 2 shell — scaffold tại milestone 1.1
frontend/
  shared          web-tech UI tái dùng cho GUI + web admin
  app-gui         desktop+mobile GUI frontend
  app-admin       web admin console frontend
docs/             public site (GitHub Pages): index · honest-limits · privacy · terms
```

**Hexagonal (A.3.1)** `[T per A.3.1 + Part D §D.1.5]`: mỗi major component = 1 crate, giữ port/adapter seam. 11 bounded context (Part B §B.3) = seam để tách microservice về sau — không leak domain qua crate khác.

**Shared contract** = `proto` + `domain-core`: control-plane depend ngược vào hai crate này. Đổi contract = đổi cả hai phía → **cần human review kỹ** `[T per Part D §D.4]`. Chi tiết crate → bounded context: blueprint Part B §B.3.

---

## 5. Binding invariants (vi phạm = STOP, báo human)

Full text + hệ quả khi code ở blueprint Part A §A.1.

| ID | Tóm tắt | Hệ quả khi code |
|---|---|---|
| **A.1.1** | data plane ≠ control plane | không nhét logic control-plane vào agent |
| **A.1.4** | agent OPEN, customer audit được | giữ `agent-core` là lib độc lập, auditable |
| **A.1.9** | single codebase, không fork Tier A vs Tier B | PL = deploy dim, không phải trục chia crate |
| **A.1.11** | namespace per-PL từ Day 1 | mọi entity/subject mang `product_line` + `tenant_id` |
| **A.1.20** | agent update + capability negotiation | agent cũ graceful degrade; rollback an toàn |
| **A.1.21** | supply-chain integrity | pin dep version, no dynamic plugin, signed commit + Cosign |
| **A.1.23** | per-PL infra isolation | code để chỗ cho per-PL config; không hardcode single-PL |
| **A.1.24** | Org/Workspace = governance, không isolation | không mô hình Org/Workspace như cô lập hạ tầng |
| **A.3.1** | hexagonal, mỗi component = 1 crate | giữ port/adapter seam |
| **A.4.1** | agent-daemon NFR `[A]` (latency, <100MB) | số GUI không tính vào budget này; A.4 chưa đo |

---

## 6. Scope hiện tại — Milestone 1.1 (Founding skeleton)

Scope gate (P.8): chỉ build cái milestone Part C hiện tại authorize. **Không** pre-build phase sau `[T per Part C §H.3.1 + §H.7.2]`.

**Đang build**: Rust workspace + WireGuard agent core (5 platform compile) · Tauri 2 UI shell ("hello world") · Personal Provisioning CA skeleton (SingleCustodian, ceremony rehearsed once non-prod) · CI/CD baseline (hosted CI + Cosign) · Enterprise PL skeleton **in code** (namespace + schema + ceremony procedure, **ZERO infra**) · client repos public Day 1.

**Chưa build (anti-pattern guard P.8)**: Phase 2 infra (Shamir ceremony, dedicated NATS/RDS) · `Organization`/`Workspace`/delegation (A.1.24, chờ trigger L_subsidiary) · F3 capability (HSM / Conf VM / BYOK, chờ F3 customer) · crate "Enterprise-*" song song (vi phạm A.1.9 trực tiếp).

> Chi tiết completion criteria + CI gates: blueprint Part C §H.3 (milestone 1.1).

---

## 7. Ankayma KHÔNG là gì (anti-positioning, P.3)

Trung thực epistemic — đừng đọc nhiều hơn cái repo này thật sự cam kết `[T per P.3]`:

- **KHÔNG** "unhackable" / dọa-dẫm. Để kiến trúc và bảng điểm-yếu công khai (A.1.12) tự nói.
- **KHÔNG** dẫn bằng giá; định vị nói về *cấu trúc*.
- **KHÔNG** generic SASE / consumer VPN / SOC-as-a-service.
- **KHÔNG** "dedicated infra Day 1" theo nghĩa máy-riêng-vật-lý / Confidential VM — F3 capability (HSM, Conf VM, BYOK) **chưa build**, kích hoạt theo trigger (P.8).
- **NFR chưa đo**: toàn bộ A.4 = `[A]`; Tauri 2 mobile "stable nhưng chưa first-class". Đừng quote số NFR như đã-bảo-đảm.

---

## 8. Build & test

```bash
cargo fmt --check
cargo clippy -- -D warnings
cargo check
cargo test
# GUI (sau scaffold milestone 1.1):  cargo tauri dev   # cần Tauri toolchain
# frontend: theo frontend/README khi framework chốt
```

Toolchain: Rust stable (sẽ pin version cụ thể trước production — A.1.21). Trước khi báo "done": chạy đủ 4 lệnh trên, **report output thật** — fail thì nói fail `[T per P.3]`. Xem [`CONTRIBUTING.md`](./CONTRIBUTING.md) cho Definition of Done.

---

## 9. Governance & trạng thái

- **Mô hình làm việc**: Claude code 100%, human review + QC test. Workflow ở [`CONTRIBUTING.md`](./CONTRIBUTING.md).
- **License**: **Apache-2.0** (xem [`LICENSE`](./LICENSE) + [`NOTICE`](./NOTICE)) `[T per Part D §D.7 — owner-chosen 2026-06-17]`. Permissive + patent grant tường minh, hợp tinh thần open client. Contribution submit vào repo này mặc định theo Apache-2.0 §5.
- **Frontend framework**: TBD per team (React / Svelte / Vue — Tauri webview-agnostic).

> Đọc trước khi sửa code: blueprint section liên quan (Part 0/A/B/C/D — SSOT nội bộ).
