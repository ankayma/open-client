# Hotfix — macOS Dataplane: 3 Gaps to Fix

> **Created**: 2026-07-01  
> **Scope**: `gui/src-tauri/src/lib.rs` — macOS data plane (daemon WireGuard)  
> **Priority**: Gap 2 + Gap 3 = real bugs violating A.1.7, fix immediately before ship. Gap 1 = UX, fix before public launch.  
> **No owner ratification needed** — this is an implementation fix, not an invariant change.

---

## Gap 1 — Admin password popup on every Connect and Disconnect

### Problem

`bring_up_dataplane` (lib.rs:837) and `stop_dataplane` (lib.rs:885) both use:

```rust
let script = format!("do shell script \"{sh}\" with administrator privileges");
std::process::Command::new("osascript").arg("-e").arg(script)
```

→ macOS shows an **admin password dialog on every** Connect (start daemon) and Disconnect (kill daemon).  
→ The daemon needs root because it must create a `utun` device (WireGuard kernel interface).

### Why this is wrong

`osascript with administrator privileges` is a "quick hack" pattern — not a production pattern. Problems:
- Poor UX: 2 password prompts per Connect/Disconnect cycle
- Cannot be automated (CI, scripted reconnect)
- Apple App Store does not allow `osascript` in sandboxed apps

### Correct fix: SMAppService + XPC privileged helper

Standard pattern (Tailscale, WireGuard app, all macOS VPN apps): install a **LaunchDaemon** once via `SMAppService`, communicate via **XPC**. After the initial install (1 admin prompt), no more passwords needed.

#### Files to create / modify

**1. Create `gui/src-tauri/macos/PrivilegedHelper/` — XPC helper target**

```
gui/src-tauri/macos/
└── PrivilegedHelper/
    ├── main.rs          (helper binary — receive XPC, start/stop agent)
    ├── Info.plist       (SMAuthorizedClients: bundle ID of the main app)
    └── launchd.plist    (Label: com.ankayma.helper)
```

`main.rs` of the helper:
```rust
// Runs as root (LaunchDaemon). Receives 2 commands via XPC:
// - "start": exec agent daemon (replaces osascript)
// - "stop": kill agent daemon by PID from agent-status.json
fn main() {
    // xpc_connection_create_mach_service(...)
    // match message["command"] { "start" => start_agent(), "stop" => stop_agent() }
}
```

**2. Modify `gui/src-tauri/src/lib.rs`**

Replace `bring_up_dataplane` and `stop_dataplane` to call XPC instead of osascript:

```rust
// REPLACE bring_up_dataplane (lib.rs:825-850)
#[cfg(target_os = "macos")]
fn bring_up_dataplane(agent_bin: &std::path::Path, token: &str, control_plane: &str) -> Result<(), String> {
    // Send XPC message to com.ankayma.helper
    // { "command": "start", "bin": bin_path, "token": token, "control_plane": url }
    xpc_send_start(agent_bin, token, control_plane)
        .map_err(|e| format!("helper XPC start failed: {e}"))
}

// REPLACE stop_dataplane (lib.rs:873-898)
#[tauri::command]
async fn stop_dataplane() -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        xpc_send_stop().map_err(|e| e.to_string())
    }
}
```

**3. Modify `Cargo.toml` — add workspace member helper**

```toml
[workspace]
members = [
    "gui/src-tauri",
    "gui/src-tauri/macos/PrivilegedHelper",  # add
    ...
]
```

**4. Modify `gui/src-tauri/tauri.conf.json`**

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

#### Install flow (one time only)

```rust
// Called when app starts for the first time, or when helper is not yet registered
#[cfg(target_os = "macos")]
fn ensure_helper_installed() -> Result<(), String> {
    use system_management::SMAppService;  // crate: service-management
    SMAppService::daemon("com.ankayma.helper")
        .register()  // prompt admin once, then OS manages it automatically
        .map_err(|e| format!("helper install failed: {e}"))
}
```

Rust crate for SMAppService: [`service-management`](https://crates.io/crates/service-management) or raw `objc2` bindings.

---

## Gap 2 — App Quit does not stop daemon (daemon orphan)

### Problem

- `"quit" => app.exit(0)` at `lib.rs:1396` exits the Tauri process without running any cleanup.
- The daemon is launched with `&` (detached, lib.rs:835) — it is an **independent process** that keeps running indefinitely after the app exits.
- **Violates A.1.7**: user quit app = no longer using the tunnel, but the tunnel stays alive until reboot.

### Fix mechanism

Tauri provides `RunEvent::Exit` — an event fired just before the process dies, while the runtime is still available.

**New flow:**
```
app.exit(0)
  → tauri::RunEvent::Exit fired
  → stop_dataplane_inner()   ← clean up daemon before dying
  → process exit
```

**Two changes needed in `lib.rs`:**

1. **Extract stop logic into `stop_dataplane_inner()`** — a plain Rust function (not a tauri command), so it can be called from both `#[tauri::command] stop_dataplane` and the RunEvent handler. Currently the stop logic is locked inside the command and cannot be called from elsewhere.

2. **Change `.run(...).expect(...)` to `.build(...).run(|_, event| { ... })`** — hook `RunEvent::Exit` to call `stop_dataplane_inner()`. Use `block_on` since at this point the async runtime is no longer available after exit.

**Note:** After Gap 1 (SMAppService) is fixed, `stop_dataplane_inner` will call XPC instead of osascript — no password needed. Gap 2 implements the correct mechanism and does not need to change when Gap 1 lands.

---

## Gap 3 — Tray Disconnect does not stop daemon

### Problem

- `handle_tray_menu` case `"toggle"` disconnect at `lib.rs:1383` only calls `disconnect_inner(&state)`.
- `disconnect_inner` only sets `state.node = None` in process memory — **the WireGuard daemon keeps running**.
- UI shows "Disconnected" but the tunnel is still alive → **violates A.1.7**.
- Dashboard Disconnect does this correctly (calls both `stopDataplane()` + `disconnect()`), tray does not.

### Fix mechanism

**Current incorrect flow:**
```
tray toggle disconnect
  → disconnect_inner()   ← only clears state.node
  [daemon still running]
```

**Correct flow after fix:**
```
tray toggle disconnect
  → stop_dataplane_inner()   ← actually kills the daemon
  → disconnect_inner()       ← clears state.node
  [if stop fails: still clear state, log warn — do not block UX]
```

**Change needed in `lib.rs`:**

Add a call to `stop_dataplane_inner()` in `handle_tray_menu` before `disconnect_inner()`. Stop failure must not block disconnect — still clear state and update UI, only log warn.

**Dependency:** Gap 3 requires `stop_dataplane_inner` to have been extracted (first step of Gap 2). Do both gaps in the same PR.

---

## Implementation order

| Order | Gap | Priority reason |
|---|---|---|
| **1 — do immediately** | Gap 3 (tray disconnect) | 3 lines of code, fixes A.1.7 violation, zero dependency |
| **2 — do immediately** | Gap 2 (quit cleanup) | ~20 lines, fixes A.1.7 violation + orphan daemon |
| **3 — before ship** | Gap 1 (SMAppService) | Larger (new helper binary), but required before App Store |

Gap 3 and Gap 2 **do not depend on Gap 1** — they can be fixed immediately with the existing osascript, then Gap 1 replaces the underlying mechanism without changing the logic.

---

## Files to touch

| File | Gap |
|---|---|
| `gui/src-tauri/src/lib.rs` | Gap 2, Gap 3 (and Gap 1 XPC call part) |
| `gui/src-tauri/macos/PrivilegedHelper/main.rs` | Gap 1 (create new) |
| `gui/src-tauri/macos/PrivilegedHelper/Info.plist` | Gap 1 (create new) |
| `gui/src-tauri/macos/PrivilegedHelper/launchd.plist` | Gap 1 (create new) |
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
