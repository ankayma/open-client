# iOS App Store — Release Prep Checklist (Ankayma client)

> **Mục đích.** Chuẩn bị deploy `com.ankayma.app` (Tauri 2) lên **iOS App Store**. Tài liệu
> này tách rõ việc **làm được ngay (không cần cert/membership)** vs **cần gia hạn + cert**,
> và nêu **rào kiến trúc** (Network Extension) phải giải trước khi App Store khả thi.
>
> **Trạng thái (2026-06-26):** `[B — built]`. Membership **đã gia hạn**; Network Extension
> đã **implement + build cho iOS sim** (BUILD SUCCEEDED). Còn lại = bridge JS→Swift +
> build trên device + App Store review (5.4). Xem **§5 Implementation status** + **§6 Runbook**.

---

## 0. TL;DR membership hết hạn

- **Compile/bundle artifact:** KHÔNG cần membership → build unsigned được ngay.
- **Ký + provisioning + upload App Store:** CẦN membership active + Apple Distribution cert
  + provisioning profile. Hết hạn ⇒ không tạo được cert/profile mới, App Store Connect chặn.
- **Kết luận:** có thể chờ tới lúc deploy mới gia hạn — nhưng "lúc deploy" = *gia hạn trước →
  generate cert/profile → mới ký + upload*. Có độ trễ; làm sớm để không kẹt.

---

## 1. Làm được NGAY — không cần cert/membership

> Đây là phần "chuẩn bị compile" — chạy được kể cả khi membership hết hạn.

- [ ] Cài **full Xcode** (App Store) + `sudo xcode-select -s /Applications/Xcode.app` + `xcodebuild -license accept`.
      *(Máy hiện chỉ có CLT — `xcodebuild -version` rỗng. iOS build bắt buộc full Xcode.)*
- [ ] Cài Tauri CLI: `cargo install tauri-cli --version "^2"` *(hiện thiếu `cargo-tauri`)*.
- [ ] Thêm rust target iOS: `rustup target add aarch64-apple-ios aarch64-apple-ios-sim`.
- [ ] `cd gui/src-tauri && cargo tauri ios init` → sinh project Xcode ở `gen/apple/`
      *(hiện `gen/` chỉ có `schemas/`, chưa init)*.
- [ ] `cargo check --target aarch64-apple-ios -p agent-core -p agent-daemon` — xác nhận
      data-plane compile cho iOS *(5-platform compile còn 🟡 pending — phase-completion-checklist-1.1)*.
- [ ] Xác nhận frontend (`frontend/app-gui`) render được trên WebView mobile (UI hiện desktop-shaped 1040×720).
- [ ] Verify deep-link scheme `ankayma` ghi đúng `CFBundleURLTypes` trong Info.plist sau init
      *(auth-deeplink-signin-spec.md §mobile `[A-p]`)*.

## 2. RÀO KIẾN TRÚC phải giải trước (độc lập với cert) ⚠️

> Đây là blocker thật, không phải thủ tục. Không có cert nào gỡ được phần này.

- **iOS không cho mở TUN tùy tiện.** boringtun phải chạy trong **Network Extension —
  Packet Tunnel Provider** (`NEPacketTunnelProvider`), nhận file descriptor utun từ
  `packetFlow`. Đây đúng mô hình app WireGuard chính chủ trên iOS (wireguard-go trong extension).
- **Cần thêm:** một **app-extension target** native (Swift) bọc boringtun qua FFI; entitlement
  `com.apple.developer.networking.networkextension` (packet-tunnel) — **phải xin Apple duyệt**;
  app group để app ↔ extension chia sẻ config.
- **Tauri KHÔNG tự sinh extension này** — phải thêm tay vào `gen/apple/` sau `ios init`.
- **Quyết định cần owner:** (a) làm Packet Tunnel Provider bọc boringtun, hay (b) tách bản iOS
  dùng `NEVPNManager`/on-demand khác kiến trúc desktop. Ảnh hưởng A.1.9 (5-platform same stack).

## 3. CẦN GIA HẠN + CERT (cổng deploy)

> Chỉ làm được sau khi **Account Holder gia hạn** Apple Developer Program.

- [ ] **Gia hạn membership** (ảnh: cần role *Account Holder* sign in + renew).
- [ ] **Trader status (EU DSA)** — ảnh cảnh báo phải khai trước 2025-02-17 nếu phân phối EU;
      đã quá hạn → khai ở Business section trước khi submit, nếu không app bị gỡ ở EU.
- [ ] Register **App ID** `com.ankayma.app` + bật capability **Network Extensions** (+ App Groups).
- [ ] Tạo **Apple Distribution** certificate.
- [ ] Tạo **App Store provisioning profile** cho app + (nếu dùng) profile cho **Packet Tunnel
      Provider extension**.
- [ ] App Store Connect: tạo app record (bundle `com.ankayma.app`), điền metadata/privacy.
- [ ] Ký + build: `scripts/release-ios.sh` (export-method `app-store-connect`).
- [ ] Upload: Transporter hoặc App Store Connect API key (`xcrun altool`/notarytool path).

## 4. Cert/secret — env (KHÔNG commit)

Giống `release-macos.sh`: credential đọc từ **environment**, không hard-code.

| Env | Ý nghĩa |
|---|---|
| `APPLE_DEVELOPMENT_TEAM` | 10-char Team ID |
| `APPLE_API_KEY` / `APPLE_API_ISSUER` / `APPLE_API_KEY_PATH` | App Store Connect API key (upload, preferred) |
| (Xcode keychain) | Apple Distribution cert + provisioning profile đã cài |

---

## 5. Implementation status — Network Extension (đã build 2026-06-26)

Owner chốt hướng **(a) Packet Tunnel Provider bọc boringtun** (giữ A.1.9, 1 core Rust).
Đã implement + verify (compile/typecheck/link, chưa chạy trên device):

| # | Việc | Verify | Vị trí |
|---|---|---|---|
| 1 | Tách packet-pump tái dùng (tx/rx/timer + demux) ra `agent-core` | ✅ test + iOS compile, macOS không regress | `agent-core::{pump,tundev}` |
| 2 | FFI staticlib `ankayma_ptp_start/stop` bọc pump | ✅ 3 test + build `aarch64-apple-ios` | `crates/agent-ios-ptp` (+ `include/agent_ios_ptp.h`) |
| 3 | Swift `PacketTunnelProvider` (lấy utun fd, set network settings, gọi FFI) | ✅ `swiftc -typecheck` iOS 26 SDK | `gui/src-tauri/ios/PacketTunnel/` |
| 4 | Extension target + entitlements (NE packet-tunnel + App Group) + link FFI | ✅ `xcodebuild -target …PacketTunnel`: **BUILD SUCCEEDED** (sim) | `scripts/ios-postinit.sh` + `ios/PacketTunnel.target.yml` |
| 5 | App `TunnelManager` (NETunnelProviderManager install + start/stop + config→App Group) | ✅ typecheck, wired vào app target | `gui/src-tauri/ios/AppSupport/TunnelManager.swift` |

**Provisioning đã có** (portal 2026-06-26): App ID `com.ankayma.app` + `com.ankayma.app.tunnel`,
App Group `group.com.ankayma.app`, cả 2 bật Network Extensions + App Groups. Team `8UF87JS6WW`.

**Còn lại (chưa làm — cần device/Apple):**
- **Bridge JS→Rust→Swift**: Tauri mobile plugin để frontend gọi connect/disconnect. Rust command
  dùng `agent-core` (enroll + GET /peers) dựng config JSON → gọi `TunnelManager.connect(configJSON:)`
  qua Swift Plugin. Cần `cargo tauri ios build` + device để verify runtime.
- Build trên device, TestFlight, App Store review (§6).

> Lưu ý quy trình: `gen/apple/` bị regenerate + gitignore → sau mỗi `cargo tauri ios init` phải
> chạy `scripts/ios-postinit.sh` để áp lại extension target + entitlements (idempotent).

## 6. Runbook — build device → TestFlight → App Store

> Cổng cần **device thật + signing + Apple review** — không tự động hoá headless được.

1. **Provisioning profiles** (Xcode managed signing, hoặc portal): app `com.ankayma.app` +
   extension `com.ankayma.app.tunnel`, mỗi cái gắn Network Extensions + App Groups capability.
   Set `DEVELOPMENT_TEAM=8UF87JS6WW` (đã trong project.yml).
2. **Bridge + frontend** (phần "còn lại" §5) trước khi build device, nếu không app chỉ có UI,
   không bấm connect được.
3. **Build:** `cd gui/src-tauri && cargo tauri ios init && bash ../../scripts/ios-postinit.sh`
   rồi `cargo tauri ios build` (ký bằng cert/profile ở keychain). Ra `.ipa`.
4. **Upload:** Transporter, hoặc App Store Connect API key (`xcrun altool`/`scripts/release-ios.sh`).
5. **App Store Connect:** tạo app record `com.ankayma.app`, điền metadata + **privacy** (đã có
   ankayma.com/privacy.html), khai **Trader status (EU DSA)**, encryption export.
6. **Guideline 5.4 (VPN):** submit bằng **tài khoản tổ chức** (✅ VIET NAM ADVANCED SOFTWARE
   COMPANY LIMITED), app **tự** cung cấp VPN qua NetworkExtension (✅), khai data collection,
   không bán/chia dữ liệu VPN. Reviewer **test tunnel chạy thật** → cần bridge + device xong.

---

### Log
- 2026-06-25 — Tạo prep checklist. Target = iOS App Store (owner chốt). Build chưa chạy
  (membership expired). Flag rào Network Extension (boringtun → Packet Tunnel Provider).
  Tham chiếu: scripts/release-ios.sh, scripts/release-macos.sh (mẫu env-driven),
  phase-completion-checklist-1.1.md (5-platform 🟡), auth-deeplink-signin-spec.md.
- 2026-06-26 — Membership gia hạn. Owner chốt hướng (a). Implement Network Extension
  end-to-end (task 1→5): agent-core pump + agent-ios-ptp FFI + Swift provider + extension
  target + app TunnelManager. Extension BUILD SUCCEEDED (sim). Còn bridge JS↔Swift + device +
  App Store 5.4. Provisioning (2 App ID + App Group) đã tạo. Thêm §5/§6.
