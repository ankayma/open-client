# iOS build — verification checklist

Run this **after every `cargo tauri ios build`**, before installing on a device or
submitting to App Store Connect. Each item below has burned a real build at least once
(swirl icon shipped to ASC, deep links dead, App Store rejects 90171 / 90683). The
generated Xcode project lives in `gui/src-tauri/gen/apple/` and is **git-ignored** — it is
regenerated from scratch by `cargo tauri ios init`, so every customisation must come back
through `scripts/ios-postinit.sh` on each build. Never hand-edit `gen/apple`; it does not survive.

## Build command (reference)

```bash
cd gui/src-tauri
rm -rf gen/apple                                     # MANDATORY if ios/PacketTunnel.target.yml
                                                     # or project info changed — init won't overwrite
APPLE_DEVELOPMENT_TEAM=8UF87JS6WW cargo tauri ios init
bash ../../scripts/ios-postinit.sh                   # re-injects everything below + regenerates the icon
APPLE_DEVELOPMENT_TEAM=8UF87JS6WW cargo tauri ios build --export-method debugging
```

`--export-method`: `debugging` (USB device test) · `release-testing` (TestFlight/ad-hoc) ·
`app-store-connect` (submit). Team `8UF87JS6WW`, NOT the Personal team.

## Checklist

| # | Check | Why it matters | Expected |
|---|---|---|---|
| 1 | **App version** = intended | ASC rejects a re-used CFBundleVersion; stale version = wrong build shipped | `CFBundleShortVersionString` + `CFBundleVersion` both = target (e.g. `1.1.5`) |
| 2 | **Extension version == app version** | Apple rejects a PacketTunnel extension whose version diverges from the host app | `AnkaymaTunnel.appex` version == app version |
| 3 | **AppIcon = "An"** (not the swirl) | `cargo tauri ios init` seeds a stale swirl icon; postinit must regen from `icons/icon_source.png` | `AppIcon*.png` present, teal cursive "An" |
| 4 | **`ankayma://` URL scheme** | Invite deep links (`cp.ankayma.com/join` → `ankayma://…`) must open the app; missing = Safari "address is invalid" | `CFBundleURLSchemes` contains `ankayma` |
| 5 | **`NSCameraUsageDescription`** | In-app QR scanner needs it; App Store rejects a camera app without it (90683) | key present with a usage string |
| 6 | **No `*.a` static lib in bundle** | A `libapp.a` / `libagent_ios_ptp.a` copied into the bundle = App Store validation 90171 | `find <app> -name '*.a'` is EMPTY |
| 7 | **PacketTunnel extension embedded** | The VPN data plane runs in this extension; missing = no tunnel | `PlugIns/AnkaymaTunnel.appex` present |

## Ready-to-run verifier (paste after build)

```bash
IPA=gui/src-tauri/gen/apple/build/arm64/Ankayma.ipa
rm -rf /tmp/ipa_verify && mkdir -p /tmp/ipa_verify && unzip -q "$IPA" -d /tmp/ipa_verify
APP=$(ls -d /tmp/ipa_verify/Payload/*.app | head -1)
echo "keys      : $(plutil -p "$APP/Info.plist" | grep -c '=>')  (a real plist has ~50+, not 4)"
echo "version   : $(plutil -p "$APP/Info.plist" | grep -m1 ShortVersion)"
echo "scheme    : $(plutil -p "$APP/Info.plist" | grep -c ankayma)  (>0 = ankayma:// registered)"
echo "camera    : $(plutil -p "$APP/Info.plist" | grep -c NSCameraUsageDescription)  (must be 1)"
echo "staticlib : $(find "$APP" -name '*.a' | wc -l | tr -d ' ')  (MUST be 0 — else 90171)"
echo "extension : $(ls "$APP/PlugIns" 2>/dev/null)  (want AnkaymaTunnel.appex)"
echo "appicon   : $(ls "$APP" | grep -c -i appicon)  (>0)"
```

## Gotchas that cost real builds

- **NEVER verify with `plutil -extract KEY fmt FILE` without `-o -`.** `plutil -extract` writes
  the extracted value **back into the file**, silently truncating your unzipped `Info.plist` to
  just that key — then every later check "fails". Use **read-only `plutil -p`** (as above), or
  `plutil -extract KEY xml1 -o -` (explicit stdout). This is a verification-tool trap, not a build bug.
- **`gen/apple` is git-ignored.** If a fix (icon, URL scheme, camera key, `-lapp` exclude) is only
  in `gen/apple`, it is lost on the next init. The fix must live in `scripts/ios-postinit.sh`
  (which patches `project.yml`, since xcodegen regenerates `Info.plist` from it) or in
  `gui/src-tauri/ios/PacketTunnel.target.yml`.
- **`rm -rf gen/apple` before init** whenever `ios/PacketTunnel.target.yml` or project info changed —
  init does not overwrite an existing project, so postinit's extension inject is skipped otherwise.
- **Icon regen must pass `icons/icon_source.png`** (the canonical "An"). Regenerating from any other
  source re-introduces the swirl. postinit does this as its last step and restores `icons/` afterward.

## App Store submit

Distribution archive + ASC metadata/privacy/Trader-status/5.4-VPN are the account holder's
manual steps — see `docs/ios-appstore-release-prep.md`.
