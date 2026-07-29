# WebAuthn security keys (E-7 StepUp Phase 3, AAL3) — decision record: drive the ceremony through native AuthenticationServices, not the webview

> **Created**: 2026-07-29
> **Status**: **WORKING on macOS, hardware-verified 2026-07-29** `[T]`. A physical
> YubiKey completed a registration ceremony end to end: the macOS system sheet
> appeared, the key was touched, and the control plane accepted the attestation and
> stored the credential (the Security page reads "Registered" from the server, not
> from local state). `cargo fmt --check`, `cargo clippy -- -D warnings`,
> `cargo test -p ankayma-gui` (19 passed) and `svelte-check` (0 errors) are green.
> **Still unproven:** the *assertion* half (proving possession for a step-up) has not
> been exercised — registration is what was tested. iOS shares the framework but is
> not wired (different presentation anchor: `UIWindow`).
> The prerequisite entitlement plumbing is done and committed
> (`fix(macos): embed the Developer ID provisioning profile…`,
> `feat(ios): claim the Associated Domains entitlement…`).
> **Scope**: client only — `gui/src-tauri` (new native module + Tauri command),
> `frontend/app-gui/src/lib/webauthn.ts`, `crates/agent-core/src/adapters.rs`
> (comments only; the wire format does not change).
> **Server: no change.** The control plane's step-up service (webauthn-rs) speaks
> the standard browser JSON transport and does not care which side of the FFI ran
> the ceremony.
> **Owner ratification**: required and given — this changes *how* an A.1.10 AAL3
> factor is obtained, not *whether* (no Part A invariant amended). Also adds a
> platform dependency, which CLAUDE.md reserves for the owner.
> **Upstream SSOT**: `workspace/02-architecture/implementation/part-d-e7-stepup.md`
> §H.7 + §H.8 Phase 3, changelog R.5 v0.9.

## 1. Why — the thing that forced this

`navigator.credentials.create()` inside Tauri's webview cannot ever register a
YubiKey on Apple platforms. This is a platform limit, not a bug we can fix:

> "Apple does not support FIDO2 security keys for the WebAuthn flow using a WKWebView."
> — [Yubico — Supporting FIDO2 Security Keys on iOS/iPadOS, FAQ](https://developers.yubico.com/WebAuthn/Supporting_FIDO2_Security_Keys_on_iOS_or_iPadOS/FAQ.html) `[T]`

WebKit's own position is the same: WebAuthn is not exposed to general WKWebViews
and they are "not considering opening this API for all WKWebViews"
([WebKit bug 220559](https://bugs.webkit.org/show_bug.cgi?id=220559), resolved as
a duplicate of the narrower default-browser case). `[T]`

Apple's one exception is **passkeys** — platform authenticator, iOS 16.1+ — and
*that* is what the Associated Domains entitlement gates. Roaming USB keys are
outside it.

**Observed, hardware, 2026-07-29** (owner's machine, real YubiKey, signed build
with the entitlement present and verified in the signature): `create()` rejects
with `NotAllowedError`, and `log show` contains **no** AuthenticationServices or
`swcd` activity at all. WebKit refuses internally; the OS is never asked. `[T]`

### 1.1 A false lead worth recording, because it cost two broken releases

Commit `a135590` added the Associated Domains entitlement stating *"WKWebView
refuses navigator.credentials.create()/get() without this — confirmed live"*.
That was an `[A]` written as a `[T]`: a `NotAllowedError` was observed and the
entitlement was **inferred** to be the cause, with no source and no test that
isolated it.

The entitlement is restricted, so claiming it without an embedded provisioning
profile made macOS refuse to launch the app at all — v1.1.26 and v1.1.28 shipped
unlaunchable and were reverted (`6d7a112`, `1d7738b`). See
`docs/macos-associated-domains.md` for that failure and its fix.

With the entitlement now demonstrably present *and* the app launching, the error
is unchanged. So the entitlement was never the cause.

**Lesson for whoever reads this next:** observing a symptom is not confirming a
cause. If you cannot cite a source or an experiment that isolates the variable,
mark it `[A?]` and keep looking. Two releases were burned on the difference.

## 2. Decision

Run the security-key ceremony through **native AuthenticationServices**
(`ASAuthorizationSecurityKeyPublicKeyCredentialProvider`) behind a Tauri command,
on both macOS and iOS. The webview keeps the UI and the server exchange; it stops
being the thing that talks to the authenticator.

Chosen over the two alternatives below because it is the only option that covers
macOS **and** iOS, keeps the ceremony inside the app, needs no new web page, and
uses the Associated Domains entitlement that is already wired and shipped.

### 2.1 Alternatives rejected

| | Approach | Why not |
|---|---|---|
| **B** | `ASWebAuthenticationSession` — run the ceremony on `https://ankayma.com/…` in Safari, return via the `ankayma://` deep link | Works, and is Apple's generic recommendation, but it needs a new hosted page carrying the ceremony, pushes a security-critical flow out to a browser and back through a URL callback, and adds a redirect surface to abuse. Keep as fallback if A hits an unforeseen wall. |
| **C** | Native CTAP-HID crate behind a Tauri command | **Does not solve iOS** — no raw USB HID access there — so it could never be the only path. Also the largest new dependency surface, on the security-critical path. Still the likely answer for Linux (see §5). |

## 3. API surface — read from the SDK, not from memory

Source: `MacOSX26.5.sdk/System/Library/Frameworks/AuthenticationServices.framework/Headers`
on this machine, 2026-07-29. Prefer re-reading these headers over any web result.

```objc
API_AVAILABLE(macos(12.0), ios(15.0)) API_UNAVAILABLE(watchos, tvos)
@interface ASAuthorizationSecurityKeyPublicKeyCredentialProvider : NSObject <ASAuthorizationProvider>
- (instancetype)initWithRelyingPartyIdentifier:(NSString *)relyingPartyIdentifier;
- (ASAuthorizationSecurityKeyPublicKeyCredentialRegistrationRequest *)
    createCredentialRegistrationRequestWithChallenge:(NSData *)challenge
                                        displayName:(NSString *)displayName
                                               name:(NSString *)name
                                             userID:(NSData *)userID;
- (ASAuthorizationSecurityKeyPublicKeyCredentialAssertionRequest *)
    createCredentialAssertionRequestWithChallenge:(NSData *)challenge;
@end
```

Request knobs that map onto what the server already sends:
`credentialParameters` (← `pubKeyCredParams`), `excludedCredentials`
(← `excludeCredentials`), `residentKeyPreference`, and `attestationPreference` /
`challenge` / `name` / `userID` from the shared
`ASAuthorizationPublicKeyCredentialRegistrationRequest` protocol.

Results: `rawAttestationObject` (registration), plus `rawClientDataJSON` and
`credentialID` from `ASPublicKeyCredential`. Those are exactly the three fields
`webauthn.ts` already base64url-encodes and posts, which is why the server does
not move.

**Availability is the one hard constraint**: macOS 12.0 / iOS 15.0. `tauri.conf.json`
sets `iOS.minimumSystemVersion: "16.0"` (fine) but sets **no** macOS minimum, so
Tauri's default applies and is lower than 12.0. Either raise it or gate at
runtime — do not assume. `[T: header API_AVAILABLE]`

## 4. Prerequisites — already done, do not redo

- `com.apple.developer.associated-domains` = `webcredentials:ankayma.com` on both
  platforms. The RP ID passed to `initWithRelyingPartyIdentifier:` is validated
  against the AASA file, so this entitlement is what makes `ankayma.com` usable as
  an RP ID from inside the app. **This is the entitlement's actual job** — not the
  webview thing it was originally added for.
- AASA live at `https://ankayma.com/.well-known/apple-app-site-association`
  → `{"webcredentials":{"apps":["8UF87JS6WW.com.ankayma.app"]}}`.
- macOS: Developer ID provisioning profile embedded, plus the launch gate in
  `scripts/release-macos.sh`. See `docs/macos-associated-domains.md`.
- iOS: entitlement injected via `scripts/ios-postinit.sh` §3c; the App Store
  provisioning profile must be regenerated after the portal capability was enabled.
- Control plane: `WEBAUTHN_RP_ID=ankayma.com`,
  `WEBAUTHN_FRONTEND_ORIGIN=https://ankayma.com`.

## 5. Gaps — what closed on 2026-07-29 and what did not

Closed by the live ceremony:

- **`clientDataJSON` origin — RESOLVED.** This was flagged as the most likely thing
  to break, on the theory that AuthenticationServices might write an origin the
  server would not recognise. It does not: the control plane accepted the
  attestation against `WEBAUTHN_FRONTEND_ORIGIN=https://ankayma.com` unchanged. `[T]`
- **Attestation format — RESOLVED.** webauthn-rs accepted what the YubiKey returned
  through this API, with no policy change on the server. `[T]`

Still open:

- **Assertion untested.** Only registration has run. The assertion path shares almost
  all of this code, but "almost" is not "verified" — do not call Phase 3 done on the
  strength of registration alone. `[A?]`
- **Windows / Linux.** Searched rather than guessed: WebView2 **does** support
  WebAuthn — it defers to the native Windows WebAuthn API the same way Chrome does
  — so the existing webview path is likely already working there and should not be
  deleted on suspicion. WebKitGTK **does not** support WebAuthn at all
  ([WebKit bug 205350](https://bugs.webkit.org/show_bug.cgi?id=205350) is still
  open), so on Linux the button can only ever fail and should be an honest gap
  rather than a dead control. Neither has been tested on real hardware here. `[A —
  sourced, not measured]`
- **Touch ID migration risk.** This release added `com.apple.application-identifier`
  to the signature. For a user who enrolled the Touch ID platform-key factor on an
  earlier build, that may move the app's keychain access group and make the existing
  Secure Enclave key invisible — the UI would silently offer "Set up" again and they
  would lose the factor without explanation. Not reproducible on the machine used
  here (it had never enrolled). Test before shipping: enrol on 1.1.28, upgrade, check
  the key still resolves. `[A? — plausible, unmeasured]`
- **FFI shape — resolved.** `objc2` + `objc2-authentication-services 0.3.2` (the
  framework crate requires `objc2 >=0.6.2`, and `objc2 = "0.6"` was already a
  dependency on iOS). The delegate is built with `define_class!`, which was the
  awkward part: `ASAuthorizationController` needs both a delegate and a
  presentation-anchor provider, so it is real main-thread UI plumbing.
  **Threading gotcha worth keeping:** `performRequests` returns immediately and the
  callback is delivered on the main run loop, so the ceremony is *started* on the main
  thread and *waited for* on a worker. Waiting on the main thread deadlocks — the run
  loop that would deliver the result is the one being blocked.
- **iOS not wired yet.** The framework is the same, but `ASPresentationAnchor` is
  `UIWindow` there, and `webauthn_apple.rs` is `#[cfg(target_os = "macos")]`.
- **No hardware test has passed yet.** Nothing here is `validated` until a real
  YubiKey completes register + assert against the live control plane. Given §1.1,
  do not mark this done on the strength of a compile.

## 6. Definition of done

- [x] **Register completes with a physical YubiKey on macOS** — 2026-07-29
- [ ] Assert completes (step-up proof), same key
- [ ] Same on a real iOS device
- [x] **Server accepts the attestation (no origin/RP-ID mismatch) and stores the credential** — 2026-07-29
- [ ] An F2+ action is refused without the key and succeeds with it (A.1.10 no-soft-fallback)
- [ ] `part-d-e7-stepup.md` §H.7 flipped from 🔴 to built, with the evidence
