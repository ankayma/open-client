# iOS App Store — Release Prep Checklist (Ankayma client)

> **Mục đích.** Chuẩn bị deploy `com.ankayma.app` (Tauri 2) lên **iOS App Store**. Tài liệu
> này tách rõ việc **làm được ngay (không cần cert/membership)** vs **cần gia hạn + cert**,
> và nêu **rào kiến trúc** (Network Extension) phải giải trước khi App Store khả thi.
>
> **Trạng thái:** `[A — prep]`. Build thật chưa chạy (chờ owner gia hạn membership + cấp cert).
> **Bối cảnh:** Apple Developer Program **membership đã hết hạn** (ảnh chụp 2026-06-25) —
> chặn ký/notarize/upload, **không** chặn compile.

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

### Log
- 2026-06-25 — Tạo prep checklist. Target = iOS App Store (owner chốt). Build chưa chạy
  (membership expired). Flag rào Network Extension (boringtun → Packet Tunnel Provider).
  Tham chiếu: scripts/release-ios.sh, scripts/release-macos.sh (mẫu env-driven),
  phase-completion-checklist-1.1.md (5-platform 🟡), auth-deeplink-signin-spec.md.
