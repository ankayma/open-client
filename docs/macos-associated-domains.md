# Associated Domains on macOS + iOS — why the entitlement bricked the app twice

> **Scope.** How `com.apple.developer.associated-domains` is wired for both the Developer ID
> macOS build and the App Store iOS build, and what has to be true outside this repo for
> either to work.
>
> **Read §0 first.** The entitlement was originally added on the theory that it would make
> `navigator.credentials.*` work inside WKWebView. That theory is wrong. The entitlement is
> still required — for a different reason — and the macOS wiring below is still correct and
> still had to be fixed, because claiming it without a provisioning profile made the app
> impossible to launch at all.

## 0. What this entitlement does and does not buy

It does **not** make the "Register a security key" button work. Verified 2026-07-29: with the
entitlement present in the signature and the app launching cleanly, `navigator.credentials
.create()` still fails with `NotAllowedError`, and the system log shows **no**
AuthenticationServices activity at all — WebKit rejects the call internally, before the OS is
ever asked.

> "Apple does not support FIDO2 security keys for the WebAuthn flow using a WKWebView."
> — [Yubico — Supporting FIDO2 Security Keys on iOS/iPadOS, FAQ](https://developers.yubico.com/WebAuthn/Supporting_FIDO2_Security_Keys_on_iOS_or_iPadOS/FAQ.html) `[T]`

The narrow exception is **passkeys** (platform authenticator) in WKWebView on iOS 16.1+, and
*that* is what needs Associated Domains. Roaming USB keys are outside it. `webauthn.ts`
predicted exactly this in its header comment before any of this was attempted.

So the entitlement's real job here is to authorize the **native** `AuthenticationServices`
path (`ASAuthorizationSecurityKeyPublicKeyCredentialProvider`), which validates the RP ID
against the AASA file — see `docs/webauthn-security-key-decision.md`. Everything below is a
prerequisite for that, not for the webview.

Correcting the record: commit `a135590` states *"WKWebView refuses navigator.credentials
.create()/get() without this — confirmed live"*. That was an `[A]` written as `[T]` — a
`NotAllowedError` was observed and the entitlement was inferred to be the cause. The
entitlement is now demonstrably in place and the error is unchanged, so it never was.

## 1. The failure

`v1.1.26` and `v1.1.28` shipped with the entitlement and **could not be opened at all**:

```
Error Domain=RBSRequestErrorDomain Code=5 "Launchd job spawn failed"
… NSPOSIXErrorDomain Code=163
```

Both were reverted (`6d7a112`, `1d7738b`). What made this expensive to diagnose: **every
static check passed** on the broken builds — `codesign --verify`, notarization, `spctl`
and `stapler validate` all reported the bundle as perfectly valid. Only `open` (the real
LaunchServices path) reproduced the failure.

The second revert happened *after* the Associated Domains capability was already enabled on
the App ID in the developer portal — so "portal capability is on" was demonstrably not the
fix, which is worth stating plainly because it is the intuitive place to stop looking.

## 2. Root cause

`com.apple.developer.associated-domains` is a **restricted entitlement**. Claiming it in the
code signature is not enough; the claim must be *authorized*, and the authorization lives in
a provisioning profile embedded in the bundle at `Contents/embedded.provisionprofile`.

For an app distributed outside the App Store (Developer ID), Apple evaluates that profile
**at every launch**, not only at install time:

> "If your application utilizes a Developer ID provisioning profile to support advanced
> capabilities, then that profile is also evaluated, both at app installation time and at
> every app launch."
> — [Provisioning profile updates](https://developer.apple.com/help/account/provisioning-profiles/provisioning-profile-updates/)

Our bundle had the entitlement and no profile, so `taskgated` refused the spawn. `codesign`
never looks at this, which is exactly why the signature checks were green.

Associated Domains *is* supported on the Developer ID channel — see the macOS capability
matrix ([Supported capabilities (macOS)](https://developer.apple.com/help/account/reference/supported-capabilities-macos)),
where the "Associated domains" row is ✓ for **ADP**, **Developer ID** and **Apple Developer**.
So this is a wiring problem, not a distribution-model dead end. `[T]`

## 3. macOS wiring

| Piece | Where |
|---|---|
| Entitlement claim | `gui/src-tauri/macos/entitlements.plist` → `webcredentials:ankayma.com` |
| Entitlement wired into the bundle | `tauri.conf.json` → `bundle.macOS.entitlements` |
| Profile embedded | `tauri.conf.json` → `bundle.macOS.files["embedded.provisionprofile"]` |
| Profile file (gitignored) | `gui/src-tauri/macos/ankayma-devid.provisionprofile` |
| Profile in CI | secret `APPLE_PROVISION_PROFILE_BASE64`, decoded by `release-macos.yml` |

Tauri copies `bundle.macOS.files` into `Contents/` during bundling, **before** code signing,
which is the order this needs. `[T:v2.tauri.app/distribute/macos-application-bundle]`

### Generating the profile

developer.apple.com → Certificates, IDs & Profiles → **Profiles → + → Developer ID** →
Profile Type **Mac** → App ID `com.ankayma.app` → select the **Developer ID Application**
certificate that CI signs with → Generate → Download.

Two things that silently produce the same brick if wrong:

- The profile must be generated **after** Associated Domains is enabled on the App ID,
  otherwise the entitlement is not in it.
- The profile must list **the same certificate** the build signs with. A profile generated
  against a different Developer ID cert fails identically, with no distinguishing error.

Developer ID profiles issued after 2017-02-22 are valid for 18 years regardless of the
certificate's own expiry — the current one expires 2044-07-24 while the cert expires
2027-02-01. Renewing the cert therefore does **not** require regenerating the profile, but
it does mean the profile must list the renewed cert; re-check this at cert renewal. `[A —
verify at the 2027-02-01 renewal]`

### Guards

`scripts/release-macos.sh` refuses to build when `bundle.macOS.entitlements` is wired but
the profile is missing, and refuses when the profile does not list the signing certificate.
After bundling it runs a **launch gate** — `open` the built app and confirm it stays alive —
because that is the only check that catches this class of failure. Set `SKIP_LAUNCH_CHECK=1`
to bypass it only when the failure mode is understood.

## 4. iOS wiring

The iOS project (`gui/src-tauri/gen/apple/`) is generated and gitignored; xcodegen rewrites
the `.entitlements` file from `project.yml` on every run, so the entitlement is injected as a
**project.yml entitlements property** by `scripts/ios-postinit.sh` (§3c), not by editing the
generated file. Only the app target gets it — the PacketTunnel extension does not need it.

iOS has no equivalent brick risk (an App Store `.ipa` always embeds its profile), but the
App Store provisioning profile must be **regenerated** after enabling the capability on the
App ID, or Archive fails with *"profile doesn't include the entitlement"*. Xcode's automatic
signing does this on the next Archive.

## 5. Server side (already live)

- `https://ankayma.com/.well-known/apple-app-site-association` serves
  `{"webcredentials":{"apps":["8UF87JS6WW.com.ankayma.app"]}}` over HTTPS, 200, no redirect.
- Control-plane has `WEBAUTHN_RP_ID=ankayma.com` and
  `WEBAUTHN_FRONTEND_ORIGIN=https://ankayma.com` (previously defaulted to `localhost`).

For local testing, `webcredentials:ankayma.com?mode=developer` bypasses Apple's CDN cache of
the AASA file, and `xcrun swcutil dl -d ankayma.com` shows what the system actually resolved.

## 6. Checklist before shipping this entitlement again

- [ ] Associated Domains enabled on App ID `com.ankayma.app` in the portal
- [ ] Developer ID profile generated **after** that, against the CI signing cert
- [ ] `APPLE_PROVISION_PROFILE_BASE64` secret set on the repo
- [ ] Local build: `Contents/embedded.provisionprofile` present in the `.app`
- [ ] **`open` the built app and confirm it launches** — not `codesign`, not `spctl`

Do **not** add "YubiKey registration works" to this list: per §0 that is gated on the native
AuthenticationServices work, not on anything in this document.
