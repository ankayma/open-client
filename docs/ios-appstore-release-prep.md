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

## 7. Owner checklist — App Store Connect submission (2026-06-30)

> Code-side đã xong (Network Extension entitlement ✅, bridge JS↔Swift ✅, `PrivacyInfo.xcprivacy`
> ✅ commit `5c250ea`, version sync ✅ commit `ef6725a` — xem §5/§6 + `part-d-infrastructure.md`
> §7). 7 việc dưới đây **chỉ làm được trên web Apple Developer / App Store Connect bằng tài
> khoản Account Holder/Admin** — tool không tự động hoá được. Làm theo thứ tự (2 → 6 là chuỗi
> phụ thuộc; 1/3/4/5 làm song song lúc chờ).

### 7.1 Distribution provisioning profile

Hiện chỉ có **Development** profile (`get-task-allow: true`). Cần **App Store Distribution**
profile cho cả 2 App ID. Cách nhanh nhất — để Xcode tự lo:

1. `open gui/src-tauri/gen/apple/ankayma-gui.xcodeproj` (chạy `scripts/ios-postinit.sh` trước
   nếu vừa `cargo tauri ios init` lại).
2. Chọn target **ankayma-gui_iOS** → tab **Signing & Capabilities** → Team =
   **VIET NAM ADVANCED SOFTWARE** (`8UF87JS6WW`, KHÔNG phải Personal Team) → tick
   **Automatically manage signing**. Lặp lại cho target **ankayma-gui_PacketTunnel**.
3. Trên thanh device chọn **"Any iOS Device (arm64)"** (không phải simulator).
4. **Product → Archive**. Lần đầu archive với team đúng + automatic signing, Xcode tự tạo
   **Apple Distribution** certificate + **App Store** provisioning profile cho cả 2 App ID nếu
   chưa có — không cần làm tay trên portal.

Nếu automatic signing báo lỗi (vd "no account with App Store Distribution capability"), làm tay:
`developer.apple.com` → **Certificates, IDs & Profiles** (nhớ đổi team selector sang
VIET NAM ADVANCED SOFTWARE trước) → **Certificates → +** → *Apple Distribution* → tạo CSR qua
**Keychain Access → Certificate Assistant → Request a Certificate from a CA** → upload → download
cert → double-click cài vào Keychain. Rồi **Profiles → +** → *App Store* (mục Distribution) →
chọn App ID `com.ankayma.app` → chọn cert Distribution vừa tạo → đặt tên → Generate → Download →
double-click cài. Lặp lại cho `com.ankayma.app.tunnel`.

> ⚠️ Rủi ro đã thấy trong `gen/apple/project.yml` (file generated, không phải source của ta):
> `CODE_SIGN_IDENTITY: "iPhone Developer"` bị set cứng cho **mọi** config (không tách Debug/
> Release) — nếu Xcode không tự override sang `Apple Distribution` khi Archive (Automatic
> signing thường override được), build Release sẽ ký nhầm bằng cert Development. Nếu Archive
> báo "profile doesn't match the entitlements"/"wrong signing identity", đây là nghi phạm đầu
> tiên — confirm bằng cách mở Signing & Capabilities lúc Archive xem identity thật là gì.

### 7.2 App Store Connect — app record + metadata + screenshots + age rating

1. `appstoreconnect.apple.com` → **My Apps → "+" → New App**. Platform iOS, Name **"Ankayma"**
   (check trùng tên trước), Primary language English (hoặc Vietnamese nếu owner muốn thị trường
   VN trước), Bundle ID chọn **`com.ankayma.app`** (đã đăng ký sẵn), SKU tự đặt (vd
   `ankayma-ios-001`), User Access Full Access → Create.
2. **App Information**: Category gợi ý *Utilities* hoặc *Productivity* (VPN thường để Utilities).
3. **Pricing and Availability**: Free (hay theo tier F0/F1 — billing chưa live nên để Free trước,
   sửa sau khi Stripe milestone 1.3 xong).
4. **App Store tab → 1.0 Prepare for Submission**:
   - **Description** (draft tiếng Anh — owner sửa lại giọng văn trước khi submit, đừng paste
     y nguyên):
     ```
     Ankayma connects your devices into a private, encrypted mesh — no port-forwarding,
     no manual WireGuard config, no servers to manage.

     • One-tap connect — sign in, tap Connect, you're on the mesh.
     • True peer-to-peer — traffic flows directly between your devices over WireGuard,
       encrypted end-to-end. We never see the content of your tunnel.
     • Cross-platform — macOS, Linux, Windows, iOS, and Android share the same mesh.
     • Built on WireGuard — the modern, audited VPN protocol, not custom crypto.

     Ankayma is for developers, remote teams, and anyone who wants to reach their own
     devices — a home server, a NAS, a laptop — securely from anywhere, without exposing
     them to the public internet.

     Sign-in required (GitHub account) to enroll devices into your mesh.
     ```
   - **Keywords** (draft, ≤100 ký tự tổng): `vpn,mesh,wireguard,private network,remote access,
     encrypted,devops,self-hosted` — **không** dùng tên đối thủ cạnh tranh làm keyword (rủi ro
     trademark/keyword-stuffing reject), owner tự cân nhắc thêm bớt.
   - **Support URL**: `https://ankayma.com` (hoặc trang support riêng nếu có).
     **Marketing URL**: tuỳ chọn.
   - **Screenshots** — bắt buộc ≥3 ảnh cho size lớn nhất (hiện Apple yêu cầu 6.9"/6.7" iPhone;
     app có hỗ trợ iPad — `UISupportedInterfaceOrientations~ipad` trong Info.plist — nên cũng
     cần bộ iPad 13"/12.9"). Lấy nhanh qua Simulator, không cần device thật:
     ```bash
     xcrun simctl list devicetypes | grep -i "iPhone 16 Pro Max\|iPad Pro"
     open -a Simulator   # boot iPhone 16 Pro Max (hoặc đời mới nhất 6.9")
     # chạy app trong simulator (cargo tauri ios dev, target = simulator), chụp từng màn:
     xcrun simctl io booted screenshot ~/Desktop/shot-welcome.png
     ```
     Chụp tối thiểu: Welcome/Sign-in, Dashboard khi Connected (hiện overlay IP/node), danh sách
     device. Lặp lại cho iPad.
   - **Age Rating**: Edit → trả lời questionnaire — VPN app không nội dung người lớn/cờ bạc/bạo
     lực, "Unrestricted Web Access" chọn **No** (Tauri WebView chỉ render UI nội bộ, không phải
     trình duyệt cho user) → kết quả thường ra **4+**.

### 7.3 Export compliance (encryption — ECCN)

Hỏi lúc upload build hoặc ở **App Store Connect → app → version đang chuẩn bị → App Encryption
Documentation**. Ankayma dùng WireGuard (ChaCha20Poly1305/Curve25519) — thuật toán mã hoá chuẩn,
công khai, không tự phát triển. Luồng câu hỏi điển hình (đa số app VPN dùng WireGuard/IPSec chọn
như sau, nhưng **đây không phải tư vấn pháp lý** — owner/legal tự quyết, đặc biệt vì pháp nhân là
**công ty Việt Nam** chứ không phải Mỹ nên áp dụng EAR có thể khác case-by-case):
- "Does your app use encryption?" → **Yes**.
- "Does your app qualify for any of the exemptions provided in Category 5, Part 2 of the EAR?"
  → phần lớn app dùng thuật toán mã hoá chuẩn/công khai (không phải tự chế, không nhắm chính phủ/
  quân sự) chọn **Yes — qualifies (mass market / standard encryption)**.
- Nếu chọn Yes-exempt, ASC thường không bắt nộp CCATS, chỉ lưu tự khai (self-classification).
- **Việc owner nên làm thêm** (ngoài ASC): xác nhận có cần nộp **annual self-classification
  report** cho US BIS không (áp dụng nếu xuất khẩu từ Mỹ theo License Exception TSU 740.13(e)) —
  hỏi luật sư/đơn vị tư vấn xuất khẩu nếu muốn chắc chắn, nhất là vì pháp nhân VN.

### 7.4 EU DSA Trader status

Bắt buộc từ 2024 nếu app phân phối ở EU. Vị trí trong App Store Connect hay đổi UI — tìm theo từ
khoá **"Trader"** trong mục **Business**/**Agreements, Tax, and Banking**, hoặc banner nhắc ngay
khi mở app record nếu chưa khai. Nội dung cần điền (owner tự quyết, vì đây là dữ liệu pháp nhân
thật, sẽ **hiển thị công khai cho user EU**):
- Trạng thái: **Trader** (vì Ankayma là sản phẩm của một pháp nhân — VIET NAM ADVANCED SOFTWARE
  COMPANY LIMITED — không phải cá nhân làm app nghiệp dư).
- Tên pháp nhân, địa chỉ đăng ký kinh doanh, email + số điện thoại liên hệ (sẽ public).
- Nếu công ty **không có hiện diện tại EU**, mục DSA yêu cầu cân nhắc thêm "EU representative"
  hoặc giới hạn phân phối ngoài EU để tránh nghĩa vụ Trader đầy đủ — đây là quyết định kinh
  doanh, không phải kỹ thuật, owner tự chọn.

### 7.5 Build cho App Store Connect

Sau khi §7.1 (Distribution profile) xong:

```bash
cd gui/src-tauri
export APPLE_DEVELOPMENT_TEAM=8UF87JS6WW
export PATH="$HOME/.cargo/bin:$PATH"
cargo tauri ios build --export-method app-store-connect
```

Ra `.ipa` ở `gen/apple/build/arm64/*.ipa` (đường dẫn chính xác in ra cuối log build). Nếu lỗi
ký (xem cảnh báo §7.1), mở Xcode build Archive bằng tay thay vì CLI.

**Validate trước khi upload** (bắt được lỗi privacy manifest/capability sớm, đỡ bị ASC reject
sau khi đã upload): Xcode → **Window → Organizer → Archives** → chọn archive vừa tạo (archive
cũng được lưu khi build qua `cargo tauri ios build`, hoặc tự **Product → Archive** trong Xcode)
→ **Validate App** → chọn App Store Connect distribution → chạy xong sửa lỗi nếu có, validate
lại tới khi sạch.

### 7.6 Upload

Cách đỡ vướng nhất (không cần escalate quyền ASC API key):
- **Xcode Organizer** → sau Validate App thành công → **Distribute App → App Store Connect →
  Upload**. Dùng Apple ID đăng nhập sẵn trong Xcode, không cần API key.
- Hoặc **Transporter.app** (free, Mac App Store): kéo `.ipa` vào, đăng nhập Apple ID (2FA) → Deliver.
- Nếu muốn CLI/automation (`xcrun altool`/`scripts/release-ios.sh`): key hiện có (`THT92BMM4Y`)
  là **read-only** (App Manager/Admin role mới upload được) → cần tạo key mới: **App Store
  Connect → Users and Access → Integrations → App Store Connect API → Generate API Key**, role
  **App Manager** trở lên. `.p8` chỉ tải được **1 lần** lúc tạo — lưu ngay vào `~/.private/`.

> **Verified 2026-06-30**: build → sign → validate → upload chạy được **full vòng thật** trên
> máy founder, ra kết quả "Ankayma 0.1.0 (0.1.0) uploaded". §7.1 (Distribution profile) +
> §7.2 (app record) đều được **Xcode tự tạo** trong lúc Validate/Distribute — không cần làm tay
> trên portal/ASC như mô tả gốc bên dưới (giữ lại làm phương án dự phòng nếu auto-create lỗi).

### 7.7 Sau khi build lên App Store Connect

Vào **TestFlight** trước (build tự xuất hiện sau vài phút xử lý) — tự test bằng chính account
+ device thật trước khi "Submit for Review". Khi submit, đính kèm note cho reviewer
(**App Review Information**) trỏ tới cách đăng nhập (paste reviewer token, §7.4 của
`part-d-infrastructure.md`, hoặc field "Notes": *"Tap 'Paste session token', use: <token>"*).

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
- 2026-06-30 — Bridge JS↔Swift + device build xong (xem `part-d-infrastructure.md` §6-7).
  Code-side blockers đóng: version sync extension (commit `ef6725a`), `PrivacyInfo.xcprivacy`
  app+extension dựa trên scan symbol thật `nm -u` (commit `5c250ea`). Thêm **§7 owner
  checklist** — 7 việc còn lại chỉ làm được trên Apple Developer/App Store Connect web (không
  tự động hoá được): Distribution profile, app record + metadata/screenshot/age-rating, export
  compliance (ECCN), EU DSA Trader status, build `--export-method app-store-connect` +
  Validate App, upload, post-upload TestFlight + reviewer note.
- 2026-06-30 (sau) — **Chạy thật pipeline §7.5-7.6 trên máy founder, end-to-end thành công**:
  Validate App PASS, Distribute App → Upload → "Ankayma 0.1.0 (0.1.0) uploaded". App record +
  Distribution profile được **Xcode tự tạo**, không cần làm tay. 4 gotcha thật gặp khi build,
  đều đã fix trong code (không phải chỉ ghi chú):
  1. Xcode (mở GUI, không qua terminal) không thấy `~/.cargo/bin` → `cargo`/`rustc`/
     `cargo-tauri` not found trong build script. Fix máy-cục-bộ (không phải code): symlink
     3 binary đó vào `/usr/local/bin` (PATH mặc định mọi process macOS thấy được).
  2. `scripts/ios-postinit.sh` chỉ patch `gen/apple/project.yml` **nếu extension target chưa
     có** — sửa `ios/PacketTunnel.target.yml` (vd thêm `CFBundleShortVersionString`) sau khi
     target đã từng được apply **không có tác dụng** tới khi `rm -rf gen/apple &&
     cargo tauri ios init` lại từ đầu. Không phải bug cần fix script (regenerate-từ-đầu là
     quy trình đúng đã ghi ở §5 "Lưu ý quy trình"), nhưng dễ quên — đã trả giá 1 lần build.
  3. App build báo `cargo: command not found`/sau đó `Connection refused` từ
     `cargo tauri ios xcode-script` nếu Archive bằng tay trong Xcode (Product → Archive) thay
     vì qua CLI `cargo tauri ios build` — script đó là **client** nối ngược về WebSocket server
     mà chỉ CLI khởi động. Phải dùng CLI, Xcode chỉ dùng để set Team/Capabilities.
  4. `tauri.conf.json` có `bundle.externalBin: ["../../target/release/agent"]` áp dụng cho
     **mọi platform** — nhưng sidecar `agent` daemon chỉ macOS/Linux/Windows
     (`bring_up_dataplane` đã `#[cfg(target_os = "macos")]`), iOS dùng Packet Tunnel Provider
     thay thế → build iOS đòi `agent-aarch64-apple-ios` không tồn tại. **Fix code thật**:
     thêm `gui/src-tauri/tauri.ios.conf.json` override `externalBin: []` cho riêng iOS
     (commit `43711b8`, Tauri 2 tự merge file theo platform).
  Còn lại trước Submit for Review: app icon thật (đang placeholder), export compliance
  (đang trả lời dialog ASC), metadata/screenshot/age-rating, EU DSA Trader status.
