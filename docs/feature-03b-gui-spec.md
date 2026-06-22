# Client GUI build-spec — CI/CD policy management (F0)

> Bản dành cho **repo client** (public). Spec để code GUI + CLI phía client.
> Control-plane là **repo riêng (CLOSED)** — bạn chỉ tương tác **qua HTTP API**; không cần (và không có) chi tiết nội bộ của nó. Phần "nội bộ control-plane / storage / ledger" thuộc spec vendor-side, không đặt ở repo public này.
> `[T]` = verify được · `[A]` = giả định · `[A-p]` = pending có đường kiểm.
> Code/identifier = English; giải thích = Vietnamese.
> Repo layout: GUI = `frontend/app-gui` (Svelte 5 + SvelteKit) + `gui/src-tauri` (Tauri 2 command layer) + `crates/agent-core` (adapters/domain). CLI = binary `agent` (`crates/agent-daemon`).

-----

## ⚠️ Guard box (đọc trước — chống hiểu sai)

F0 CI/CD policy management **KHÔNG** được thêm:
1. ❌ "admin agent" riêng để đổi policy.
2. ❌ bắt buộc đổi policy qua GUI.
3. ❌ step-up / re-auth khi đổi policy.
4. ❌ lớp role/RBAC cho F0.

**Lý do**: thiết bị đã enroll (đã đăng nhập) **chính là** danh tính admin (A.1.3). Authorization đã được control-plane giải sẵn bằng session + default-deny (A.1.6) + ledger (A.1.8). GUI là **một mặt tùy chọn ngang hàng CLI**, KHÔNG phải cửa duy nhất. Nếu thấy mình thiết kế "ai được đổi policy" như capability mới → **DỪNG** (đó là team-governance về sau, kéo sai tầng — P.5).

Cái **VẪN giữ** (về *nội dung rule*, không phải *ai/giao diện*): client validate safe-by-default, **fail lúc tạo** — pin `repo` + (`ref` HOẶC `environment`), không wildcard. Default = scope chặt nhất hợp lệ. (Server cũng cưỡng chế việc này — client validate chỉ là UX sớm.)

-----

## Phần 1 — CI/CD policy management GUI (buildable NOW)

Các endpoint control-plane đã live (đã verify e2e trên `cp.ankayma.com`). Đây là phần code được ngay.

### 1.1 API contract (HTTP — đây là toàn bộ thứ client cần biết về control-plane)

Tất cả session-authed: header `Authorization: Bearer <session_token>` (token lấy từ `submit_session_token`).
Base URL mặc định: `https://cp.ankayma.com` (override bằng `ANKAYMA_CONTROL_PLANE`).

| Method · Path | Mục đích | Request body | Response |
|---|---|---|---|
| `POST /api/v1/ci/policy` | Tạo / cập-nhật rule (upsert theo `repo`) | `{issuer, repo, ref, environment?, target_hostname?}` | `200 {ok:true, repo}` · `400` vi phạm safe-by-default / issuer sai · `404` target_hostname không phải node của tenant · `409` repo đã thuộc tenant khác / quota |
| `GET /api/v1/ci/policy` | List rule của tenant | — | `200 {policies:[{repo, issuer, ref, environment, target_hostname, created_at}]}` |
| `DELETE /api/v1/ci/policy/{owner}/{repo}` | Xoá rule (tenant-scoped) | — (repo nằm trong path; nhận cả `owner/name`) | `200 {ok:true, repo}` · `404` nếu không có |
| `GET /api/v1/peers` | List node của tenant (cho target picker) | — | `200 {peers:[{node_id, public_key, overlay_ip, hostname, endpoint?}]}` |

Ghi chú:
- `issuer` ∈ {`"github"`, `"gitlab"`}. `ref` ví dụ `refs/heads/main`. `environment` ví dụ `prod`. `repo` = `owner/name` (github) / `group/project` (gitlab) — luôn có ≥1 dấu `/` (DELETE dùng path catch-all).
- **Edit = re-`POST`** (server upsert theo `repo`). Không có `PUT` riêng.
- **Safe-by-default do server cưỡng chế** (fail-at-create). Client validate (1.3) chỉ để báo lỗi sớm; **đừng** coi client validate là rào an toàn, **đừng** bỏ nó (UX). Khi server `400/409` → hiện **nguyên văn `error`** từ response (đừng giấu).
- Tất cả tenant-scoped: một thiết bị chỉ thấy/sửa policy của tenant mình (server lo; client không cần check).

> **Lấy session token để test thủ công:** đăng nhập GitHub OAuth qua GUI (`sign_in_github` → paste token), token đó dùng làm Bearer cho mọi call ở trên.

### 1.2 Màn hình

**Route `/policies` — "CI/CD Deploy Rules"**
- List mỗi rule: `repo` · `issuer` (badge github/gitlab) · scope (`ref` hoặc `environment`) · `target_hostname` (`—` nếu null) · `created_at`.
- Empty-state: "No deploy rules yet." + nút **"Add rule"** + dòng nhắc CLI tương đương (`agent ci-policy add …`) — củng cố "GUI là một mặt, không phải cửa duy nhất".
- Mỗi row: tap → edit; menu/swipe → delete (confirm dialog).
- Nút **"Add rule"** → `/policies/new`.

**Route `/policies/new` (create) và `/policies/[repo]` (edit) — cùng form**
- Fields:
  - `issuer`: select (github / gitlab). Default github.
  - `repo`: text `owner/name`.
  - **scope**: radio [Ref | Environment] + 1 input. **Đúng MỘT** trong hai (không cả hai trống, không cả hai điền). Default = Ref (scope chặt — branch cụ thể).
  - `target node`: dropdown từ `GET /api/v1/peers` (hiện `hostname`); optional.
- Submit:
  - Client-validate (1.3) → fail thì chặn + hiện lỗi inline, KHÔNG gọi API.
  - Gọi `POST /api/v1/ci/policy`. Server `400/409` → hiện nguyên văn `error`.
  - Thành công → về `/policies`, **re-fetch** list.
- Edit: pre-fill từ list data; submit = re-POST (upsert).

**Delete**: confirm → `DELETE /api/v1/ci/policy/{owner}/{repo}` → re-fetch.

### 1.3 Client-side validation (UX-only, mirror server)

```
function validatePolicyDraft(d):
  errors = []
  if !d.repo || d.repo.includes('*')   → "repo: pin chính xác owner/name, không wildcard"
  if !d.repo.includes('/')             → "repo: dạng owner/name"
  hasRef = d.ref && !d.ref.includes('*')
  hasEnv = d.environment && !d.environment.includes('*')
  if !(hasRef XOR hasEnv)              → "chọn đúng MỘT: ref hoặc environment (không wildcard)"
  if d.issuer not in {github, gitlab}  → "issuer: github | gitlab"
  return errors
```

### 1.4 Tauri commands cần thêm — `gui/src-tauri/src/lib.rs`

Mỗi command lấy `state.token()` (đã có pattern), trả `Result<T, String>`:
```rust
#[tauri::command] async fn list_ci_policies(state) -> Result<Vec<CiPolicy>, String>
#[tauri::command] async fn add_ci_policy(req: CiPolicyDraft, state) -> Result<(), String>
#[tauri::command] async fn delete_ci_policy(repo: String, state) -> Result<(), String>
#[tauri::command] async fn list_nodes(state) -> Result<Vec<PeerBrief>, String>  // reuse GET /peers
```
Đăng ký trong `invoke_handler![…]`. Structs `CiPolicy`/`CiPolicyDraft`/`PeerBrief` = Serialize/Deserialize mirror wire shape ở §1.1.

### 1.5 agent-core adapters cần thêm — `crates/agent-core/src/adapters.rs`

```rust
pub async fn list_ci_policies(http, base_url, session_token) -> Result<Vec<CiPolicy>, ApiError>      // GET, bearer
pub async fn register_ci_policy(http, base_url, session_token, &CiPolicyReq) -> Result<(), ApiError> // POST, bearer
pub async fn delete_ci_policy(http, base_url, session_token, repo: &str) -> Result<(), ApiError>      // DELETE, bearer
// peers(): đã có (adapters::peers) — reuse cho target picker.
```
Domain types `crates/agent-core/src/domain.rs`: `CiPolicy` (Deserialize), `CiPolicyReq` (Serialize). Thêm test parse wire shape (theo mẫu `enroll_response_parses_control_plane_shape`).

### 1.6 frontend wiring — `frontend/app-gui/src/lib/`
- `types.ts`: `CiPolicy`, `CiPolicyDraft`, `PeerBrief`.
- `tauri.ts`: `listCiPolicies()`, `addCiPolicy(d)`, `deleteCiPolicy(repo)`, `listNodes()`.
- Routes `/policies`, `/policies/new`, `/policies/[repo]` theo style `routes/dashboard/+page.svelte` (CSS vars `--c-surface`/`--c-border`/`--c-accent`…).

### 1.7 CLI parity (cùng dữ liệu)
Binary là `agent`. Thêm subcommand `agent ci-policy {add|list|rm}` (dispatch ở `crates/agent-daemon/src/main.rs`, module mới `ci_policy.rs`) gọi cùng adapters §1.5. GUI và CLI ra **cùng dữ liệu** — không cái nào là cửa bắt buộc.

### 1.8 Acceptance (client)
1. Tạo rule hợp lệ (repo+ref+target) → hiện trong list sau re-fetch.
2. Rule wildcard (`repo=you/*` hoặc `ref=*`) → client chặn; nếu bypass client, server `400`, GUI hiện reason.
3. Cả ref lẫn environment trống → chặn.
4. Delete → biến mất khỏi list; gọi lại `GET` xác nhận.
5. Target picker chỉ liệt kê node của tenant mình (từ `/peers`).
6. Mọi thao tác cần session; token sai/thiếu → `401`, GUI mời đăng nhập lại.
7. **Không** có UI role/approve/step-up nào (guard box).

-----

## Phần 2 — node/access view + node description (thiết kế, CHƯA buildable)

Phần này chờ control-plane thêm endpoint (vendor-side, chưa land). Ghi ở đây để client sẵn sàng, **đừng code tới khi endpoint live**.

### 2.1 Chờ control-plane (vendor-side)
- `GET /api/v1/my-access` → "tôi tới được đâu" (server tính, trả tập node + service reachable). **Chưa land.**
- Node `description` (free-text cosmetic) + `PATCH` endpoint để sửa. **Chưa land.**
- Default "node cùng owner reach nhau" đã được owner chốt — nên view Mine sẽ có nội dung ngay khi endpoint có.

### 2.2 View (F0 = chỉ zone **Mine**)
- Trục tổ chức: **Mine / Near / Far**. **F0 single-user ⇒ chỉ Mine** (owner = `You`, expand đầy đủ). Near = team (sau), Far = enterprise (sau).
- Mỗi dòng: neo = tên node (`display_name`) → nhãn owner (`You`) → meta (tier/loại) → **lá hành động = service** (đơn vị bấm-để-connect, pre-fill target).
- Empty-state khi 0 reachable: "Chưa có quyền tới đâu — …" (không phải lỗi; đây là default-deny A.1.6 lúc chưa có rule).
- Server **không** trả tunnel sống; client chỉ render danh sách tĩnh server cho.

### 2.3 node `description` (cosmetic)
- Text tự do, sửa qua `PATCH` (khi endpoint có); hiện ở node detail.
- **Bền** (server lưu DB) — UX "đã lưu" là đúng. Ở F0 **không có** "lịch sử đổi description".

-----

## Data model phía client (cần nhớ khi code)

- GUI **không cache authoritative client-side** — chỉ giữ session token + node state in-memory. Mọi dữ liệu là **projection đọc từ control-plane qua agent-core** (GUI không gọi control-plane trực tiếp — A.1.4).
- **Sau mỗi mutation (add/edit/delete) → re-fetch list.** Đừng dựng state song song dễ drift. Dữ liệu *có* persist — ở phía control-plane, không ở GUI.
- `my-access` (khi có): luôn fetch tươi, không cache. Rỗng = default-deny, không phải lỗi.
- "Lịch sử đổi policy" (xem ai đổi gì) = tính năng sau (cần endpoint riêng từ control-plane); F0 chưa có.

-----

## Out of scope (KHÔNG build ở F0)
- Zone Near/Far, filter/search quy mô → team (Near) / enterprise (Far).
- Policy authoring UI nâng cao (rule tùy biến ngoài CI deploy) → team-tier.
- Audit/lịch sử đổi metadata → enterprise.
- Team RBAC / inventory cấp tenant role-scoped → team-tier (giữ enrollment-level, không query-level).

## Log
- 2026-06-22 — Tạo bản client-safe (chỉ API HTTP + thiết kế GUI/CLI). Phần 1 buildable now (endpoint đã live + verify e2e trên cp.ankayma.com). Phần 2 (my-access + description) chờ endpoint vendor-side. Spec vendor-side đầy đủ (kèm nội bộ control-plane) nằm ở repo control-plane (closed), không đặt ở repo public này.
