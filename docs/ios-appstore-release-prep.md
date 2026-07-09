# iOS App Store — Release Prep Checklist (Ankayma client)

> **Purpose.** Prepare `com.ankayma.app` (Tauri 2) for deployment to the **iOS App Store**. This
> document clearly separates work **doable now (no cert/membership needed)** vs **requires renewal
> + cert**, and calls out the **architectural blocker** (Network Extension) that must be resolved
> before App Store is viable.
>
> **Status (2026-06-26):** `[B — built]`. Membership **renewed**; Network Extension
> **implemented + built for iOS sim** (BUILD SUCCEEDED). Remaining = JS→Swift bridge +
> device build + App Store review (5.4). See **§5 Implementation status** + **§6 Runbook**.

---

## 0. TL;DR membership expired

- **Compile/bundle artifact:** NO membership needed → can build unsigned immediately.
- **Sign + provisioning + upload to App Store:** REQUIRES active membership + Apple Distribution cert
  + provisioning profile. Expired ⇒ cannot create new cert/profile, App Store Connect blocks.
- **Conclusion:** you can wait until deploy to renew — but "deploy time" = *renew first →
  generate cert/profile → then sign + upload*. There is lead time; do this early to avoid getting stuck.

---

## 1. Doable NOW — no cert/membership needed

> This is the "compile prep" section — can be done even when membership is expired.

- [ ] Install **full Xcode** (App Store) + `sudo xcode-select -s /Applications/Xcode.app` + `xcodebuild -license accept`.
      *(Machine currently has only CLT — `xcodebuild -version` returns empty. iOS builds require full Xcode.)*
- [ ] Install Tauri CLI: `cargo install tauri-cli --version "^2"` *(currently missing `cargo-tauri`)*.
- [ ] Add iOS Rust targets: `rustup target add aarch64-apple-ios aarch64-apple-ios-sim`.
- [ ] `cd gui/src-tauri && cargo tauri ios init` → generates Xcode project at `gen/apple/`
      *(currently `gen/` only has `schemas/`, not yet init'd)*.
- [ ] `cargo check --target aarch64-apple-ios -p agent-core -p agent-daemon` — confirm
      data-plane compiles for iOS *(5-platform compile still 🟡 pending — phase-completion-checklist-1.1)*.
- [ ] Confirm frontend (`frontend/app-gui`) renders correctly in mobile WebView (UI currently desktop-shaped 1040×720).
- [ ] Verify deep-link scheme `ankayma` is correctly written to `CFBundleURLTypes` in Info.plist after init
      *(auth-deeplink-signin-spec.md §mobile `[A-p]`)*.

## 2. ARCHITECTURAL BLOCKERS to resolve first (independent of cert) ⚠️

> These are real blockers, not procedural ones. No cert can fix this.

- **iOS does not allow opening TUN devices freely.** boringtun must run inside a **Network Extension —
  Packet Tunnel Provider** (`NEPacketTunnelProvider`), receiving the utun file descriptor from
  `packetFlow`. This matches the official WireGuard iOS app model (wireguard-go inside the extension).
- **Required additions:** a native (Swift) **app-extension target** wrapping boringtun via FFI; entitlement
  `com.apple.developer.networking.networkextension` (packet-tunnel) — **must be approved by Apple**;
  app group for app ↔ extension config sharing.
- **Tauri does NOT auto-generate this extension** — must be added manually to `gen/apple/` after `ios init`.
- **Decision required from owner:** (a) implement Packet Tunnel Provider wrapping boringtun, or (b) make
  the iOS build a separate variant using `NEVPNManager`/on-demand with a different architecture from
  desktop. Impacts A.1.9 (5-platform same stack).

## 3. REQUIRES RENEWAL + CERT (deploy gate)

> Only possible after the **Account Holder renews** Apple Developer Program.

- [ ] **Renew membership** (requires *Account Holder* role to sign in + renew).
- [ ] **Trader status (EU DSA)** — a warning indicates this must be declared before 2025-02-17 for EU
      distribution; deadline passed → declare in the Business section before submission, otherwise the
      app will be removed from EU.
- [ ] Register **App ID** `com.ankayma.app` + enable capability **Network Extensions** (+ App Groups).
- [ ] Create an **Apple Distribution** certificate.
- [ ] Create an **App Store provisioning profile** for the app + (if used) a profile for the **Packet Tunnel
      Provider extension**.
- [ ] App Store Connect: create app record (bundle `com.ankayma.app`), fill in metadata/privacy.
- [ ] Sign + build: `scripts/release-ios.sh` (export-method `app-store-connect`).
- [ ] Upload: Transporter or App Store Connect API key (`xcrun altool`/notarytool path).

## 4. Cert/secret — env (DO NOT commit)

Like `release-macos.sh`: credentials read from **environment**, not hard-coded.

| Env | Meaning |
|---|---|
| `APPLE_DEVELOPMENT_TEAM` | 10-char Team ID |
| `APPLE_API_KEY` / `APPLE_API_ISSUER` / `APPLE_API_KEY_PATH` | App Store Connect API key (upload, preferred) |
| (Xcode keychain) | Apple Distribution cert + provisioning profile already installed |

---

## 5. Implementation status — Network Extension (built 2026-06-26)

Owner confirmed approach **(a) Packet Tunnel Provider wrapping boringtun** (preserves A.1.9, single Rust core).
Implemented + verified (compile/typecheck/link, not yet run on device):

| # | Task | Verify | Location |
|---|---|---|---|
| 1 | Extract reusable packet-pump (tx/rx/timer + demux) into `agent-core` | ✅ test + iOS compile, macOS no regression | `agent-core::{pump,tundev}` |
| 2 | FFI staticlib `ankayma_ptp_start/stop` wrapping pump | ✅ 3 test + build `aarch64-apple-ios` | `crates/agent-ios-ptp` (+ `include/agent_ios_ptp.h`) |
| 3 | Swift `PacketTunnelProvider` (gets utun fd, sets network settings, calls FFI) | ✅ `swiftc -typecheck` iOS 26 SDK | `gui/src-tauri/ios/PacketTunnel/` |
| 4 | Extension target + entitlements (NE packet-tunnel + App Group) + link FFI | ✅ `xcodebuild -target …PacketTunnel`: **BUILD SUCCEEDED** (sim) | `scripts/ios-postinit.sh` + `ios/PacketTunnel.target.yml` |
| 5 | App `TunnelManager` (NETunnelProviderManager install + start/stop + config→App Group) | ✅ typecheck, wired into app target | `gui/src-tauri/ios/AppSupport/TunnelManager.swift` |

**Provisioning already done** (portal 2026-06-26): App ID `com.ankayma.app` + `com.ankayma.app.tunnel`,
App Group `group.com.ankayma.app`, both with Network Extensions + App Groups enabled. Team `8UF87JS6WW`.

**Remaining (not yet done — requires device/Apple):**
- **JS→Rust→Swift bridge**: Tauri mobile plugin for the frontend to call connect/disconnect. Rust command
  uses `agent-core` (enroll + GET /peers) to build config JSON → calls `TunnelManager.connect(configJSON:)`
  via Swift Plugin. Requires `cargo tauri ios build` + device to verify at runtime.
- Device build, TestFlight, App Store review (§6).

> Process note: `gen/apple/` is regenerated + gitignored → after each `cargo tauri ios init`, run
> `scripts/ios-postinit.sh` to re-apply extension target + entitlements (idempotent).

## 6. Runbook — build device → TestFlight → App Store

> This gate requires a **real device + signing + Apple review** — cannot be automated headlessly.

1. **Provisioning profiles** (Xcode managed signing, or portal): app `com.ankayma.app` +
   extension `com.ankayma.app.tunnel`, each with Network Extensions + App Groups capability.
   Set `DEVELOPMENT_TEAM=8UF87JS6WW` (already in project.yml).
2. **Bridge + frontend** (the "remaining" part of §5) before the device build, otherwise the app
   is UI-only and the connect button does nothing.
3. **Build:** `cd gui/src-tauri && cargo tauri ios init && bash ../../scripts/ios-postinit.sh`
   then `cargo tauri ios build` (signs using cert/profile in keychain). Produces `.ipa`.
4. **Upload:** Transporter, or App Store Connect API key (`xcrun altool`/`scripts/release-ios.sh`).
5. **App Store Connect:** create app record `com.ankayma.app`, fill in metadata + **privacy** (ankayma.com/privacy.html
   already exists), declare **Trader status (EU DSA)**, encryption export.
6. **Guideline 5.4 (VPN):** submit using an **organizational account** (✅ VIET NAM ADVANCED SOFTWARE
   COMPANY LIMITED), app **itself** provides VPN via NetworkExtension (✅), declare data collection,
   do not sell/share VPN data. Reviewer will **test the live tunnel** → bridge + device must be done first.

---

## 7. Owner checklist — App Store Connect submission (2026-06-30)

> Code-side complete (Network Extension entitlement ✅, JS↔Swift bridge ✅, `PrivacyInfo.xcprivacy`
> ✅ commit `5c250ea`, version sync ✅ commit `ef6725a` — see §5/§6 + `part-d-infrastructure.md`
> §7). The 7 tasks below **can only be done on the Apple Developer / App Store Connect web using an
> Account Holder/Admin account** — cannot be automated by tooling. Follow the order (2 → 6 is a
> dependency chain; 1/3/4/5 can be done in parallel while waiting).

### 7.1 Distribution provisioning profile

Currently only a **Development** profile exists (`get-task-allow: true`). Need an **App Store Distribution**
profile for both App IDs. Fastest approach — let Xcode handle it:

1. `open gui/src-tauri/gen/apple/ankayma-gui.xcodeproj` (run `scripts/ios-postinit.sh` first
   if you just re-ran `cargo tauri ios init`).
2. Select target **ankayma-gui_iOS** → **Signing & Capabilities** tab → Team =
   **VIET NAM ADVANCED SOFTWARE** (`8UF87JS6WW`, NOT Personal Team) → tick
   **Automatically manage signing**. Repeat for target **ankayma-gui_PacketTunnel**.
3. In the device bar select **"Any iOS Device (arm64)"** (not simulator).
4. **Product → Archive**. First archive with correct team + automatic signing, Xcode auto-creates
   the **Apple Distribution** certificate + **App Store** provisioning profile for both App IDs if
   they don't exist — no manual portal steps needed.

If automatic signing reports an error (e.g. "no account with App Store Distribution capability"), do it manually:
`developer.apple.com` → **Certificates, IDs & Profiles** (remember to switch the team selector to
VIET NAM ADVANCED SOFTWARE first) → **Certificates → +** → *Apple Distribution* → create a CSR via
**Keychain Access → Certificate Assistant → Request a Certificate from a CA** → upload → download
cert → double-click to install in Keychain. Then **Profiles → +** → *App Store* (under Distribution) →
select App ID `com.ankayma.app` → select the Distribution cert just created → name it → Generate → Download →
double-click to install. Repeat for `com.ankayma.app.tunnel`.

> ⚠️ Known risk in `gen/apple/project.yml` (a generated file, not our source):
> `CODE_SIGN_IDENTITY: "iPhone Developer"` is hard-coded for **all** configurations (not split by Debug/
> Release) — if Xcode does not override to `Apple Distribution` at Archive time (Automatic
> signing usually overrides this), the Release build will be signed incorrectly with the Development cert.
> If Archive reports "profile doesn't match the entitlements"/"wrong signing identity", this is the first
> suspect — confirm by opening Signing & Capabilities during Archive to see what the actual identity is.

### 7.2 App Store Connect — app record + metadata + screenshots + age rating

1. `appstoreconnect.apple.com` → **My Apps → "+" → New App**. Platform iOS, Name **"Ankayma"**
   (check for name conflicts first), Primary language English (or Vietnamese if owner wants VN market
   first), Bundle ID select **`com.ankayma.app`** (already registered), SKU set freely (e.g.
   `ankayma-ios-001`), User Access Full Access → Create.
2. **App Information**: Recommended category is *Utilities* or *Productivity* (VPN apps are typically listed under Utilities).
3. **Pricing and Availability**: Free (or per F0/F1 tier — billing not yet live so leave as Free for now,
   update after Stripe milestone 1.3 is done).
4. **App Store tab → 1.0 Prepare for Submission**:
   - **Description** (English draft — owner should revise the wording before submitting, do not paste verbatim):

     > ⚠️ **Guideline 2.3.10** — metadata **must not name third-party platforms**. Submission
     > 1.1.1 (2026-07) was rejected because the cross-platform bullet said "Android". Don't list
     > OS names in the description (including desktop — the reviewer reads "third-party
     > platforms" more broadly than "other mobile platforms" in the guideline text). Describe
     > capabilities, not a list of OSes.

     ```
     Ankayma connects your devices into a private, encrypted mesh — no port-forwarding,
     no manual WireGuard config, no servers to manage.

     • One-tap connect — sign in, tap Connect, you're on the mesh.
     • True peer-to-peer — traffic flows directly between your devices over WireGuard,
       encrypted end-to-end. We never see the content of your tunnel.
     • Every device, one mesh — your phone, your laptop, and your servers reach each
       other by name, wherever they are.
     • Built on WireGuard — the modern, audited VPN protocol, not custom crypto.

     Ankayma is for developers, remote teams, and anyone who wants to reach their own
     devices — a home server, a NAS, a laptop — securely from anywhere, without exposing
     them to the public internet.

     Sign-in required (GitHub account) to enroll devices into your mesh.
     ```
   - **Keywords** (draft, ≤100 characters total): `vpn,mesh,wireguard,private network,remote access,
     encrypted,devops,self-hosted` — **do not** use competitor names as keywords (risk of
     trademark/keyword-stuffing rejection), owner decides what to add or remove.
   - **Support URL**: `https://ankayma.com` (or a dedicated support page if available).
     **Marketing URL**: optional.
   - **Screenshots** — at least ≥3 required for the largest size (currently Apple requires 6.9"/6.7" iPhone;
     the app supports iPad — `UISupportedInterfaceOrientations~ipad` in Info.plist — so an iPad 13"/12.9"
     set is also needed). Capture quickly via Simulator, no real device required:
     ```bash
     xcrun simctl list devicetypes | grep -i "iPhone 16 Pro Max\|iPad Pro"
     open -a Simulator   # boot iPhone 16 Pro Max (or latest 6.9" model)
     # run app in simulator (cargo tauri ios dev, target = simulator), capture each screen:
     xcrun simctl io booted screenshot ~/Desktop/shot-welcome.png
     ```
     Minimum screenshots: Welcome/Sign-in, Dashboard when Connected (showing overlay IP/node), device list.
     Repeat for iPad.
   - **Age Rating**: Edit → answer the questionnaire — VPN app has no adult content/gambling/violence,
     "Unrestricted Web Access" select **No** (Tauri WebView only renders internal UI, not a user-facing
     browser) → result is typically **4+**.

### 7.3 Export compliance (encryption — ECCN)

Asked during the build upload or at **App Store Connect → app → version being prepared → App Encryption
Documentation**. Ankayma uses WireGuard (ChaCha20Poly1305/Curve25519) — standard, publicly documented
encryption algorithms, not developed in-house. Typical question flow (most VPN apps using WireGuard/IPSec
answer as follows, but **this is not legal advice** — owner/legal decides, especially since the legal entity
is a **Vietnamese company** not a US one, so EAR applicability may differ case-by-case):
- "Does your app use encryption?" → **Yes**.
- "Does your app qualify for any of the exemptions provided in Category 5, Part 2 of the EAR?"
  → most apps using standard/public encryption algorithms (not custom-built, not targeting government/
  military) answer **Yes — qualifies (mass market / standard encryption)**.
- If Yes-exempt is selected, ASC typically does not require CCATS submission, only stores the self-classification.
- **Additional action for owner** (beyond ASC): confirm whether an **annual self-classification
  report** to US BIS is required (applies if exporting from the US under License Exception TSU 740.13(e)) —
  consult a lawyer/export compliance advisor if certainty is needed, especially given the VN legal entity.

### 7.4 EU DSA Trader status

Required from 2024 if the app is distributed in the EU. The location in App Store Connect may change UI —
search for the keyword **"Trader"** under **Business**/**Agreements, Tax, and Banking**, or look for the
banner that appears when opening an app record if not yet declared. Fields to fill in (owner decides, as
this is real legal entity data that will be **publicly visible to EU users**):
- Status: **Trader** (because Ankayma is a product of a legal entity — VIET NAM ADVANCED SOFTWARE
  COMPANY LIMITED — not an individual hobbyist app developer).
- Legal entity name, registered business address, contact email + phone number (will be public).
- If the company **has no EU presence**, DSA requires consideration of an "EU representative"
  or restricting distribution outside the EU to avoid full Trader obligations — this is a business
  decision, not a technical one, owner's call.

### 7.5 Build for App Store Connect

After §7.1 (Distribution profile) is done:

```bash
cd gui/src-tauri
export APPLE_DEVELOPMENT_TEAM=8UF87JS6WW
export PATH="$HOME/.cargo/bin:$PATH"
cargo tauri ios build --export-method app-store-connect
```

Produces `.ipa` at `gen/apple/build/arm64/*.ipa` (exact path printed at the end of the build log). If
signing fails (see §7.1 warning), build Archive manually in Xcode instead of CLI.

**Validate before uploading** (catches privacy manifest/capability errors early, avoids ASC rejection
after upload): Xcode → **Window → Organizer → Archives** → select the archive just created (archive
is also saved when building via `cargo tauri ios build`, or manually via **Product → Archive** in Xcode)
→ **Validate App** → select App Store Connect distribution → fix any errors found, re-validate until clean.

### 7.6 Upload

The least complicated approach (no need to escalate ASC API key permissions):
- **Xcode Organizer** → after Validate App succeeds → **Distribute App → App Store Connect →
  Upload**. Uses Apple ID already signed in to Xcode, no API key needed.
- Or **Transporter.app** (free, Mac App Store): drag in the `.ipa`, sign in with Apple ID (2FA) → Deliver.
- For CLI/automation (`xcrun altool`/`scripts/release-ios.sh`): the current key (`THT92BMM4Y`)
  is **read-only** (App Manager/Admin role required for upload) → create a new key: **App Store
  Connect → Users and Access → Integrations → App Store Connect API → Generate API Key**, role
  **App Manager** or higher. The `.p8` can only be downloaded **once** at creation time — save it immediately to `~/.private/`.

> **Verified 2026-06-30**: build → sign → validate → upload ran **a full real end-to-end** on
> the founder's machine, producing "Ankayma 0.1.0 (0.1.0) uploaded". §7.1 (Distribution profile) +
> §7.2 (app record) were both **auto-created by Xcode** during Validate/Distribute — no manual
> portal/ASC steps needed as described in the original below (retained as a fallback if auto-create fails).

### 7.7 After uploading to App Store Connect

Go to **TestFlight** first (build appears automatically after a few minutes of processing) — self-test
with your own account + real device before "Submit for Review". When submitting, attach a note for the
reviewer (**App Review Information**) pointing to how to sign in (paste a reviewer token, §7.4 of
`part-d-infrastructure.md`, or in the "Notes" field: *"Tap 'Paste session token', use: <token>"*).

---

## 8. SUBMIT-DAY RUNBOOK (2026-07-05) — làm theo thứ tự

> **Verdict readiness**: **Server-side + demo READY 100%** (demo-tenant riêng live, node + service demo Open/SSH được, isolation verify sạch — chi tiết + credentials ở workspace private `part-d-infrastructure.md §7.4b`). **Chặn còn lại = build nào submit + metadata ASC (owner-side).**

### 8.0 QUYẾT ĐỊNH build — chọn 1 (đọc trước)

Build `Ankayma 0.1.0` đã upload 2026-06-30 **CŨ HƠN** F-2 SSH / F-3 / toàn bộ UI 2026-07-05 (những cái vừa test trên iPhone). Các thay đổi 2026-07-05 **chưa commit, chưa build vào iOS**.

- **Phương án NHANH (submit hôm nay, build cũ)**: dùng luôn build 0.1.0 đã upload. VPN connect + token-signin + isolation demo hoạt động (đủ qua review 5.4). **Nhược**: reviewer thấy app thiếu SSH/Open/UI mới; app lên store là bản cũ, phải update sau. Reviewer note phải mô tả welcome **bản cũ** ("Paste session token").
- **Phương án ĐÚNG (khớp cái vừa validate, +1–2h Xcode)**: commit client 2026-07-05 → rebuild iOS → archive → validate → upload build mới → submit. Reviewer test đúng trải nghiệm demo (Open trang mock + SSH). **Khuyến nghị nếu kịp giờ.**

Nếu chọn ĐÚNG: trước khi build, commit các thay đổi client (Claude làm khi owner OK): services layout+SSH+filter+CI chip, PathChain ledger+mask IP, welcome 4-card+QR+2cột, devices SSH style, window min-width, tabbar reserve.

### 8.1 REVIEWER INFO (điền vào App Store Connect → App Review Information → Sign-In)

> **User name + Password (token) = lấy từ workspace PRIVATE** `part-d-infrastructure.md §7.4b` (token demo-tenant, KHÔNG commit vào repo public này). Dùng **token demo-tenant**, KHÔNG dùng token tenant-chính (lộ node riêng).

- **Sign-in required**: ✅ bật.
- **User name / Password**: → dán từ `part-d-infrastructure.md §7.4b` (private).
- **Notes** (khớp UI **build mới** — nếu submit build cũ, sửa "Enter a token instead" → "Paste session token"):
  ```
  This app does not use a traditional username/password login. On the Welcome
  screen, tap "Enter a token instead" (text link below "Continue with GitHub"),
  paste the value from the Password field above, then tap "Sign in".

  After sign-in, tap the large Connect button to bring up the VPN tunnel. You can
  then tap "Open" on the "api" service to load a page reached privately over the
  mesh, or "SSH" to open an in-app terminal to the demo server.
  ```

### 8.2 Checklist submit (đánh dấu khi xong)

1. [ ] (nếu phương án ĐÚNG) Commit client 2026-07-05 + `cargo tauri ios build --export-method app-store-connect` (§7.5) → Validate (§7.5) → Upload (§7.6) → chờ ASC xử lý (vài phút).
2. [ ] App record + metadata §7.2: description (draft §7.2, owner sửa giọng), keywords, Support URL `https://ankayma.com`, **screenshots ≥3** (6.9" iPhone + iPad — chụp Simulator: Welcome, Connected, Services/Devices), Age Rating (→4+).
3. [ ] Export compliance §7.3: Encryption = Yes, qualifies exemption (standard/mass-market).
4. [ ] EU DSA Trader §7.4: khai pháp nhân (hoặc giới hạn phân phối ngoài EU).
5. [ ] **App Review Information** §8.1: dán reviewer user/password/notes ở trên.
6. [ ] Chọn build (0.1.0 cũ hoặc build mới vừa upload) cho version.
7. [ ] TestFlight self-test: tự paste token demo → connect → Open/SSH OK trên device.
8. [ ] **Submit for Review**.

### 8.3 SAU KHI REVIEW XONG — teardown demo (đừng quên)

Xoá demo-tenant + node demo để không rác — lệnh teardown đầy đủ ở workspace private `part-d-infrastructure.md §7.4b`.

---

### Log
- 2026-06-25 — Created prep checklist. Target = iOS App Store (owner confirmed). Build not yet running
  (membership expired). Flagged Network Extension blocker (boringtun → Packet Tunnel Provider).
  References: scripts/release-ios.sh, scripts/release-macos.sh (env-driven template),
  phase-completion-checklist-1.1.md (5-platform 🟡), auth-deeplink-signin-spec.md.
- 2026-06-26 — Membership renewed. Owner confirmed approach (a). Implemented Network Extension
  end-to-end (tasks 1→5): agent-core pump + agent-ios-ptp FFI + Swift provider + extension
  target + app TunnelManager. Extension BUILD SUCCEEDED (sim). Remaining: JS↔Swift bridge + device +
  App Store 5.4. Provisioning (2 App IDs + App Group) created. Added §5/§6.
- 2026-06-30 — JS↔Swift bridge + device build done (see `part-d-infrastructure.md` §6-7).
  Code-side blockers closed: version sync extension (commit `ef6725a`), `PrivacyInfo.xcprivacy`
  app+extension based on real symbol scan `nm -u` (commit `5c250ea`). Added **§7 owner
  checklist** — 7 remaining tasks that can only be done on the Apple Developer/App Store Connect web
  (cannot be automated): Distribution profile, app record + metadata/screenshot/age-rating, export
  compliance (ECCN), EU DSA Trader status, build `--export-method app-store-connect` +
  Validate App, upload, post-upload TestFlight + reviewer note.
- 2026-06-30 (later) — **Ran §7.5-7.6 pipeline on founder's machine, end-to-end success**:
  Validate App PASS, Distribute App → Upload → "Ankayma 0.1.0 (0.1.0) uploaded". App record +
  Distribution profile were **auto-created by Xcode**, no manual steps needed. 4 real gotchas
  encountered during build, all fixed in code (not just noted):
  1. Xcode (opened via GUI, not terminal) does not see `~/.cargo/bin` → `cargo`/`rustc`/
     `cargo-tauri` not found in build script. Local machine fix (not a code fix): symlink
     those 3 binaries into `/usr/local/bin` (the default PATH all macOS processes see).
  2. `scripts/ios-postinit.sh` only patches `gen/apple/project.yml` **if the extension target does
     not already exist** — editing `ios/PacketTunnel.target.yml` (e.g. adding `CFBundleShortVersionString`)
     after the target has been applied before **has no effect** until `rm -rf gen/apple &&
     cargo tauri ios init` is re-run from scratch. Not a script bug to fix (regenerating from
     scratch is the correct process documented in §5 "Process note"), but easy to forget — paid
     for this with one build.
  3. App build reports `cargo: command not found` / then `Connection refused` from
     `cargo tauri ios xcode-script` if Archive is done manually in Xcode (Product → Archive) instead
     of via CLI `cargo tauri ios build` — that script is a **client** that connects back to a
     WebSocket server that only the CLI starts. Must use the CLI; Xcode is only for setting Team/Capabilities.
  4. `tauri.conf.json` has `bundle.externalBin: ["../../target/release/agent"]` applied to
     **all platforms** — but the `agent` daemon sidecar is macOS/Linux/Windows only
     (`bring_up_dataplane` is already `#[cfg(target_os = "macos")]`), iOS uses the Packet Tunnel Provider
     instead → iOS build requires `agent-aarch64-apple-ios` which does not exist. **Real code fix**:
     add `gui/src-tauri/tauri.ios.conf.json` overriding `externalBin: []` for iOS only
     (commit `43711b8`, Tauri 2 auto-merges the file by platform).
  Remaining before Submit for Review: real app icon (currently placeholder), export compliance
  (answering ASC dialog), metadata/screenshot/age-rating, EU DSA Trader status.
