
# Hotfix — macOS Dataplane: 3 Gap cần fix

> **Tạo**: 2026-07-01  
> **Scope**: `gui/src-tauri/src/lib.rs` — macOS data plane (daemon WireGuard)  
> **Ưu tiên**: Gap 2 + Gap 3 = bug thật vi phạm A.1.7, fix ngay trước ship. Gap 1 = UX, fix trước public launch.  
> **Không cần owner ratify** — đây là implementation fix, không đổi invariant.

---

## Gap 1 — Admin password popup mỗi lần Connect và Disconnect

### Vấn đề

`bring_up_dataplane` (lib.rs:837) và `stop_dataplane` (lib.rs:885) đều dùng:

```rust
let script = format!("do shell script \"{sh}\" with administrator privileges");
std::process::Command::new("osascript").arg("-e").arg(script)
```

→ macOS hiện **dialog nhập admin password mỗi lần** Connect (start daemon) và Disconnect (kill daemon).  
→ Daemon cần root vì phải tạo `utun` device (WireGuard kernel interface).

### Tại sao sai

`osascript with administrator privileges` là pattern "quick hack" — không phải production pattern. Vấn đề:
- UX tệ: 2 password prompt mỗi cycle Connect/Disconnect
- Không thể automate (CI, scripted reconnect)
- Apple App Store không cho phép `osascript` trong sandboxed app

### Fix đúng: SMAppService + XPC privileged helper

Pattern chuẩn (Tailscale, WireGuard app, tất cả macOS VPN): cài **LaunchDaemon** một lần qua `SMAppService`, giao tiếp qua **XPC**. Sau lần install đầu (1 prompt admin), không cần password nữa.

#### Các file cần tạo / sửa

**1. Tạo `gui/src-tauri/macos/PrivilegedHelper/` — XPC helper target**

```
gui/src-tauri/macos/
└── PrivilegedHelper/
    ├── main.rs          (helper binary — receive XPC, start/stop agent)
    ├── Info.plist       (SMAuthorizedClients: bundle ID của app chính)
    └── launchd.plist    (Label: com.ankayma.helper)
```

`main.rs` của helper:
```rust
// Chạy như root (LaunchDaemon). Nhận 2 lệnh qua XPC:
// - "start": exec agent daemon (thay osascript)
// - "stop": kill agent daemon bằng PID từ agent-status.json
fn main() {
    // xpc_connection_create_mach_service(...)
    // match message["command"] { "start" => start_agent(), "stop" => stop_agent() }
}
```

**2. Sửa `gui/src-tauri/src/lib.rs`**

Thay `bring_up_dataplane` và `stop_dataplane` gọi XPC thay vì osascript:

```rust
// THAY THẾ bring_up_dataplane (lib.rs:825-850)
#[cfg(target_os = "macos")]
fn bring_up_dataplane(agent_bin: &std::path::Path, token: &str, control_plane: &str) -> Result<(), String> {
    // Gửi XPC message tới com.ankayma.helper
    // { "command": "start", "bin": bin_path, "token": token, "control_plane": url }
    xpc_send_start(agent_bin, token, control_plane)
        .map_err(|e| format!("helper XPC start failed: {e}"))
}

// THAY THẾ stop_dataplane (lib.rs:873-898)
#[tauri::command]
async fn stop_dataplane() -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        xpc_send_stop().map_err(|e| e.to_string())
    }
}
```

**3. Sửa `Cargo.toml` — thêm workspace member helper**

```toml
[workspace]
members = [
    "gui/src-tauri",
    "gui/src-tauri/macos/PrivilegedHelper",  # thêm
    ...
]
```

**4. Sửa `gui/src-tauri/tauri.conf.json`**

```json
{
  "bundle": {
    "macOS": {
      "helperBundleIdentifier": "com.ankayma.helper",
      "provisioningProfile": ""
    }
  }
}
```

#### Install flow (1 lần duy nhất)

```rust
// Gọi khi app start lần đầu, hoặc khi helper chưa register
#[cfg(target_os = "macos")]
fn ensure_helper_installed() -> Result<(), String> {
    use system_management::SMAppService;  // crate: service-management
    SMAppService::daemon("com.ankayma.helper")
        .register()  // prompt admin 1 lần, sau đó OS tự manage
        .map_err(|e| format!("helper install failed: {e}"))
}
```

Crate Rust cho SMAppService: [`service-management`](https://crates.io/crates/service-management) hoặc raw `objc2` bindings.

---

## Gap 2 — App Quit không stop daemon (daemon orphan)

### Vấn đề

- `"quit" => app.exit(0)` tại `lib.rs:1396` thoát Tauri process nhưng không chạy bất kỳ cleanup nào.
- Daemon được launch với `&` (detached, lib.rs:835) — là **process độc lập**, tiếp tục chạy vô thời hạn sau khi app thoát.
- **Vi phạm A.1.7**: user quit app = không còn dùng tunnel, nhưng tunnel vẫn sống đến khi reboot.

### Cơ chế fix

Tauri cung cấp `RunEvent::Exit` — event được bắn ngay trước khi process chết, vẫn còn runtime.

**Luồng mới:**
```
app.exit(0)
  → tauri::RunEvent::Exit fired
  → stop_dataplane_inner()   ← cleanup daemon trước khi chết
  → process exit
```

**Hai thay đổi cần làm trong `lib.rs`:**

1. **Tách logic stop ra `stop_dataplane_inner()`** — hàm Rust thường (không phải tauri command), để gọi được từ cả `#[tauri::command] stop_dataplane` lẫn RunEvent handler. Hiện tại logic stop bị nhốt trong command, không gọi được từ nơi khác.

2. **Đổi `.run(...).expect(...)` thành `.build(...).run(|_, event| { ... })`** — hook `RunEvent::Exit` để gọi `stop_dataplane_inner()`. Dùng `block_on` vì tại thời điểm này không còn async runtime sau khi exit.

**Lưu ý:** Sau khi Gap 1 (SMAppService) được fix, `stop_dataplane_inner` gọi XPC thay osascript — không cần password. Gap 2 viết đúng cơ chế, không cần đổi lại khi Gap 1 land.

---

## Gap 3 — Tray Disconnect không stop daemon

### Vấn đề

- `handle_tray_menu` case `"toggle"` disconnect tại `lib.rs:1383` chỉ gọi `disconnect_inner(&state)`.
- `disconnect_inner` chỉ set `state.node = None` trong process memory — **daemon WireGuard vẫn chạy**.
- UI hiện "Disconnected" nhưng tunnel vẫn sống → **vi phạm A.1.7**.
- Dashboard Disconnect làm đúng (gọi cả `stopDataplane()` + `disconnect()`), tray thì không.

### Cơ chế fix

**Luồng sai hiện tại:**
```
tray toggle disconnect
  → disconnect_inner()   ← chỉ clear state.node
  [daemon vẫn chạy]
```

**Luồng đúng sau fix:**
```
tray toggle disconnect
  → stop_dataplane_inner()   ← kill daemon thật
  → disconnect_inner()       ← clear state.node
  [nếu stop fail: vẫn clear state, log warn — không block UX]
```

**Thay đổi cần làm trong `lib.rs`:**

Thêm lệnh gọi `stop_dataplane_inner()` vào `handle_tray_menu` trước `disconnect_inner()`. Stop fail không được block disconnect — vẫn clear state và cập nhật UI, chỉ log warn.

**Dependency:** Gap 3 cần `stop_dataplane_inner` đã được tách ra (bước đầu của Gap 2). Làm 2 gap trong cùng 1 PR.

---

## Thứ tự thực hiện

| Thứ tự | Gap | Lý do ưu tiên |
|---|---|---|
| **1 — làm ngay** | Gap 3 (tray disconnect) | 3 dòng code, fix A.1.7 violation, zero dependency |
| **2 — làm ngay** | Gap 2 (quit cleanup) | ~20 dòng, fix A.1.7 violation + orphan daemon |
| **3 — trước ship** | Gap 1 (SMAppService) | Lớn hơn (helper binary mới), nhưng bắt buộc trước App Store |

Gap 3 và Gap 2 **không phụ thuộc Gap 1** — có thể fix ngay với osascript hiện tại, sau đó Gap 1 thay thế bên dưới mà không cần đổi logic.

---

## File cần đụng tới

| File | Gap |
|---|---|
| `gui/src-tauri/src/lib.rs` | Gap 2, Gap 3 (và Gap 1 phần gọi XPC) |
| `gui/src-tauri/macos/PrivilegedHelper/main.rs` | Gap 1 (tạo mới) |
| `gui/src-tauri/macos/PrivilegedHelper/Info.plist` | Gap 1 (tạo mới) |
| `gui/src-tauri/macos/PrivilegedHelper/launchd.plist` | Gap 1 (tạo mới) |
| `Cargo.toml` (workspace root) | Gap 1 |
| `gui/src-tauri/tauri.conf.json` | Gap 1 |

---

## Status — shipped 2026-07-01 (commit `38d9d98`)

Cả 3 gap đã fix, cùng 1 commit (Gap 2/3 dùng chung `stop_dataplane_inner` với Gap 1 nên tách commit không có lợi).

**Gap 2 + Gap 3**: đúng như plan — tách `stop_dataplane_inner()`, gọi từ tray toggle-disconnect và từ `tauri::RunEvent::Exit`.

**Gap 1**: đổi hướng so với plan gốc — dùng **Unix domain socket** (`/var/run/com.ankayma.helper.sock`, peer-uid + home-dir-ownership authorization) thay vì XPC literal. Lý do: crate XPC Rust duy nhất còn được maintain (`xpc-connection`) đã cũ (2018) và chỉ hỗ trợ client-side, muốn làm listener-side daemon phải tự viết FFI libxpc từ đầu. Cùng property bảo mật (chỉ GUI của đúng user mới điều khiển được daemon), rủi ro implementation thấp hơn nhiều. Dùng crate `smappservice-rs` (wrap `SMAppService`) để register/check-status daemon.

Bundle layout thực tế: helper binary tại `Contents/MacOS/ankayma-helper`, plist tại `Contents/Library/LaunchDaemons/com.ankayma.helper.plist` (dùng key `BundleProgram` — relative path trong bundle — thay vì `Program` tuyệt đối, để chạy được bất kể app cài ở đâu).

### Live-tested trên máy thật, phát hiện 2 bug thật (không chỉ code review)

1. **`smappservice-rs` 0.1.3 map sai error code**: enum `ServiceManagementError` của crate dùng lại numeric code của `SMErrors.h` (API `SMJobBless` cũ), không khớp với code thật mà `SMAppService` (API mới) trả về — lần register thứ 2 (daemon đã Enabled) trả về `Unknown(1)` thay vì `AlreadyRegistered` mà crate map, khiến Connect báo lỗi giả "register helper daemon: unknown error 1". **Fix**: check `svc.status()` trước khi gọi `register()`, không dựa vào match error variant.
2. **Daemon cũ (orphan từ osascript trước đây) không chết với SIGTERM**: `libc::kill(pid, SIGTERM)` trả về thành công nhưng process vẫn sống. Nguyên nhân: `crates/agent-daemon/src/up.rs` chỉ handle `tokio::signal::ctrl_c()` (SIGINT), không có handler SIGTERM nào cả — có khả năng authorization trampoline của `osascript ... with administrator privileges` để lại SIGTERM bị ignore qua `exec()`. **Fix**: sau SIGTERM, verify bằng `kill(pid, 0)` sau 500ms, escalate SIGKILL nếu vẫn còn sống.

### Việc còn tồn đọng — cần QC sau lần reboot/logout tự nhiên tiếp theo

Sau khi rebuild binary helper + cài lại `.app`, `sudo launchctl kickstart -k system/com.ankayma.helper` **không** làm daemon đang chạy nạp lại binary mới (pid không đổi trước/sau). Do đó nhánh SIGTERM-verify-SIGKILL-escalation trong `stop_agent()` (main.rs) **chưa được re-verify sống** với daemon build cuối — chỉ mới verify logic + đã confirm daemon cũ (build trước fix) không tự chết với SIGTERM đúng như dự đoán. Việc reload LaunchDaemon tin cậy nhất là reboot/logout (không ép máy làm giữa chừng session này).

**QC checklist khi có dịp reboot**: Connect → Disconnect qua tray → Disconnect qua UI → Quit app (Cmd+Q) — mỗi lần xác nhận `ps aux | grep 'agent up'` không còn process nào sống sót, và `/var/log/ankayma/helper.log` (trước 2026-07-02: `/tmp/ankayma-helper.log`) log đúng nhánh (kill thành công hay phải escalate SIGKILL).
