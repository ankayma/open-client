# Auth deep-link sign-in — build-spec

> Bản dành cho **repo client** (public) + **phần việc cho control-plane** (repo riêng, CLOSED).
> Mục tiêu: sau khi đăng nhập GitHub trong browser, bấm **"Open Ankayma"** là mở thẳng app **kèm session token** — **không phải copy/paste token thủ công** nữa.
> `[T]` = verify được · `[A]` = giả định · `[A-p]` = pending có đường kiểm.
> Code/identifier = English; giải thích = Vietnamese.
> Repo layout: GUI = `frontend/app-gui` (Svelte 5 + SvelteKit) + `gui/src-tauri` (Tauri 2) + `crates/agent-core`. Control-plane = repo riêng, chỉ chạm qua HTTP + **deep-link URL contract** dưới đây.

-----

## ⚠️ Guard box (đọc trước)

- Đây **KHÔNG** đổi cơ chế auth: vẫn là GitHub OAuth ở control-plane, vẫn cấp **cùng một `session_token`** như hiện tại (validate qua `GET /api/v1/session`). Chỉ đổi **cách giao token từ browser về app**: thay vì hiện ra cho user copy → đẩy qua **custom URL scheme** `ankayma://`.
- **Copy/paste KHÔNG bị xoá** — giữ nguyên làm fallback ("If the app didn't open"). Deep-link là happy-path, không phải đường duy nhất.
- Token vẫn **chỉ sống trong RAM của app** (như hiện tại — `AppState.session`, không persist). Deep-link không thêm chỗ lưu token mới.

-----

## 1. Vấn đề hiện tại

Flow bây giờ (2 màn, thủ công):
1. App `sign_in_github` → mở browser tới `https://cp.ankayma.com/auth/github` (`gui/src-tauri/src/lib.rs:229`). `[T]`
2. Browser xong OAuth → trang hiện **"Signed in as …"** + token + nút **"Open Ankayma"**. Nút này hiện **chưa mở được app** (app chưa đăng ký scheme nào) → user buộc phải copy token.
3. App nhảy sang màn "Paste session token" → user dán → `submit_session_token` validate + lưu (`lib.rs:237`). `[T]`

→ Bỏ bước copy/paste: nút "Open Ankayma" mở `ankayma://auth?token=…`, app nhận token tự động.

-----

## 2. Deep-link URL contract (phần CHUNG — chốt giữa client & control-plane)

**Scheme + shape — đây là toàn bộ hợp đồng:**

```
ankayma://auth?token=<SESSION_TOKEN>
```

- Scheme: `ankayma` (lowercase). Host/path: `auth`. Query param **`token`** = đúng `session_token` mà control-plane đang hiện cho user copy (không đổi định dạng token).
- `token` phải **URL-encoded** (token hiện là hex `[0-9a-f]` nên thực tế không có ký tự đặc biệt, nhưng CP **vẫn nên** `encodeURIComponent` cho chắc). `[A]`
- App parse `token`, validate qua `GET /api/v1/session` (Bearer), giống hệt `submit_session_token`. Token sai/expired → app báo lỗi + rơi về màn paste. `[T]`
- Cùng một URL dùng được trên **desktop (macOS) và mobile (iOS/Android)** — chỉ khác cách OS định tuyến scheme.

-----

## 3. Phần việc CONTROL-PLANE (repo CLOSED) — cần làm

Trang kết quả OAuth (trang hiện "Signed in as …" + token) chỉ cần **1 thay đổi**: cho nút **"Open Ankayma"** trỏ tới deep-link.

**3.1 Nút "Open Ankayma"** — đổi thành anchor mở scheme:

```html
<!-- token = session token vừa cấp; PHẢI encodeURIComponent -->
<a class="btn-primary" href="ankayma://auth?token=ENCODED_TOKEN">Open Ankayma</a>
```

hoặc tự mở ngay khi trang load (UX mượt hơn, vẫn giữ nút làm fallback):

```html
<script>
  const token = "…";                      // server render
  const deeplink = "ankayma://auth?token=" + encodeURIComponent(token);
  // thử mở app tự động; nếu OS không có app, không sao — user bấm nút/copy
  location.href = deeplink;
</script>
```

**3.2 Giữ nguyên** phần hiện token + chữ "If the app didn't open, copy your session token" làm fallback (đề phòng app chưa cài / scheme chưa đăng ký / browser chặn auto-redirect). **Không** bỏ.

**3.3 KHÔNG cần** đổi gì ở `/auth/github`, `/api/v1/session`, hay định dạng token. Không cần `redirect_uri`, không cần loopback. Chỉ là 1 dòng `href` ở trang kết quả.

> Lưu ý cho CP: một số browser chặn `location.href = "custom://"` nếu không do user-gesture. Nên ưu tiên **anchor `<a href>`** (user bấm) làm chính; auto-redirect chỉ là bonus.

-----

## 4. Phần việc CLIENT (repo này) — cần làm

### 4.1 Đăng ký scheme `ankayma://`
- Thêm plugin: `tauri-plugin-deep-link` (v2) — đăng ký scheme + nhận URL. Kèm `tauri-plugin-single-instance` (desktop) để khi đang chạy mà mở deep-link thì **focus instance cũ** + forward URL thay vì mở app thứ 2. `[A]` (single-instance phải là plugin đăng ký **đầu tiên** theo doc Tauri).
- `tauri.conf.json` → `plugins.deep-link.desktop.schemes = ["ankayma"]` (và `mobile` tương ứng). Bundler sẽ tự ghi `CFBundleURLTypes` vào Info.plist (macOS/iOS) + intent-filter (Android). `[A-p]` (verify Info.plist sau khi `cargo tauri build`).
- Capability: thêm `deep-link:default` vào `gui/src-tauri/capabilities/*.json`.

### 4.2 Xử lý URL khi nhận được
- Trong `setup()`: `app.deep_link().on_open_url(|event| { … })`.
- Parse từng URL: scheme == `ankayma`, host == `auth`, lấy query `token`.
- Refactor logic của `submit_session_token` (`lib.rs:237`) ra 1 helper dùng chung `apply_session_token(app, token)`:
  - validate `adapters::session_info` → set `email` + `token` vào `AppState` → `apply_connection_change(app)`.
- Sau khi token OK: `show_main_window(app)` (show + focus) và emit event mới **`signed-in`** mang `AuthState::Authenticated{user}`.

### 4.3 Frontend nhận event
- `frontend/app-gui/src/routes/+layout.svelte`: thêm listener `listen('signed-in', …)` → `auth.set(payload)` + `goto('/dashboard')` (xử lý cả trường hợp deep-link tới **sau** khi `onMount`/`checkAuthState` đã chạy).
- `welcome/+page.svelte`: giữ nguyên màn paste làm fallback. (Tùy chọn: đổi chữ hint thành "Bấm 'Open Ankayma' trong browser — app sẽ tự mở. Không mở được thì dán token bên dưới.")

### 4.4 Verify `[T]`
- macOS: `cargo tauri build --bundles app`, mở 1 lần để LaunchServices ghi nhận scheme, rồi `open "ankayma://auth?token=<token-thật>"` → app focus + vào dashboard, không qua màn paste.
- Token sai: `open "ankayma://auth?token=bad"` → app báo lỗi, rơi về màn paste, không crash.
- Đang chạy sẵn (window ẩn xuống tray) → mở deep-link → focus lại đúng instance (single-instance), không mở app thứ 2.

-----

## 5. Bảo mật / rủi ro (ghi để không quên)

- **Token trong URL scheme**: custom scheme có thể bị app khác trên máy đăng ký trùng (`ankayma://`) và "cướp" URL → đọc được token. Đây là hạn chế cố hữu của custom-scheme deep-link (Tailscale & nhiều app desktop chấp nhận). Chấp nhận cho F0. `[A]`
  - **Nâng cấp về sau (nếu cần chặt hơn)**: theo RFC 8252 — app mở HTTP server loopback `127.0.0.1:<random>`, truyền `redirect_uri=http://127.0.0.1:<port>/cb` cho CP, CP redirect token về loopback. Tránh hijack scheme, nhưng cần CP hỗ trợ `redirect_uri` + app chạy server tạm. **Ngoài phạm vi bản này.**
- Token **không** ghi ra disk/log. Khi log URL (debug) phải **redact** `token` (`ankayma://auth?token=***`).
- App **luôn** validate token với control-plane trước khi tin (đã có sẵn ở `submit_session_token` / `check_auth_state`). Deep-link không bỏ bước validate này.

-----

## 6. Tóm tắt phân chia

| Bên | Việc |
|---|---|
| **Control-plane** (CLOSED) | Trang kết quả OAuth: nút "Open Ankayma" → `href="ankayma://auth?token=<encodeURIComponent(token)>"`. Giữ phần copy-token làm fallback. Không đổi API/token. |
| **Client** (repo này) | Đăng ký scheme `ankayma://` (deep-link + single-instance plugin), xử lý `on_open_url` → validate + lưu token + focus window + emit `signed-in`; frontend listen `signed-in` → goto `/dashboard`. Giữ màn paste làm fallback. |
