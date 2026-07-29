// Browser-side WebAuthn/FIDO2 ceremony driver (E-7 StepUp Phase 3 — AAL3,
// Part D §H.8 Phase 3). The control plane (webauthn-rs) speaks
// the standard browser JSON transport (camelCase, base64url binary fields) —
// this is the only layer that touches `navigator.credentials`; the Tauri
// commands in tauri.ts are opaque JSON pass-throughs either side of it.
//
// CONFIRMED BROKEN ON APPLE PLATFORMS — this file's `navigator.credentials`
// calls cannot work inside Tauri's WKWebView, and no amount of configuration
// changes that. The risk this comment used to describe as unverified was
// hardware-tested on 2026-07-29 and is real:
//
//   "Apple does not support FIDO2 security keys for the WebAuthn flow using a
//    WKWebView."
//   [T:developers.yubico.com/WebAuthn/Supporting_FIDO2_Security_Keys_on_iOS_or_iPadOS/FAQ]
//
// Observed: `create()` rejects with `NotAllowedError` and the system log shows
// no AuthenticationServices activity at all — WebKit refuses internally, before
// the OS is ever asked. Apple's one exception is *passkeys* (platform
// authenticator) in WKWebView on iOS 16.1+, which is what the Associated
// Domains entitlement gates; roaming USB keys are outside it. Note that adding
// that entitlement is what bricked v1.1.26/v1.1.28 — see
// `docs/macos-associated-domains.md`.
//
// The replacement is the native AuthenticationServices path
// (`ASAuthorizationSecurityKeyPublicKeyCredentialProvider`) behind a Tauri
// command; the wire format below does not change, only who runs the ceremony.
// Decision + rejected alternatives: `docs/webauthn-security-key-decision.md`.
//
// Windows keeps the webview path below: WebView2 defers WebAuthn to the native
// Windows WebAuthn API the same way Chrome does, so `navigator.credentials` there
// reaches a real security key rather than a dead end. Linux does not — WebKitGTK
// has no WebAuthn implementation at all (WebKit bug 205350, still open), so the
// feature is hidden there instead of offering a button that can only throw. `[A —
// sourced, not measured on hardware]`

import {
  webauthnRegisterStart,
  webauthnRegisterFinish,
  webauthnAuthenticateStart,
  verifyStepUpWebauthn,
  getPlatform,
  webauthnNativeAvailable,
  webauthnNativeRegister,
  webauthnNativeAuthenticate,
} from "./tauri";

// Cached because it cannot change while the app is running, and both the ceremony
// and the "should we even show this button" check ask for it.
let nativePath: Promise<boolean> | null = null;
function useNative(): Promise<boolean> {
  nativePath ??= webauthnNativeAvailable().catch(() => false);
  return nativePath;
}

function b64urlToBuffer(b64url: string): ArrayBuffer {
  const pad = "=".repeat((4 - (b64url.length % 4)) % 4);
  const base64 = (b64url + pad).replace(/-/g, "+").replace(/_/g, "/");
  const raw = atob(base64);
  const bytes = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
  return bytes.buffer;
}

function bufferToB64url(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf);
  let str = "";
  for (const b of bytes) str += String.fromCharCode(b);
  return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function decodeCredentialDescriptors(list: any[] | undefined): PublicKeyCredentialDescriptor[] | undefined {
  return list?.map((c) => ({ ...c, id: b64urlToBuffer(c.id) }));
}

// Register a new security key for the signed-in user. Throws if the user
// cancels, the browser/OS has no WebAuthn support, or the server rejects the
// attestation (e.g. that physical key is already registered).
export async function registerSecurityKey(label?: string): Promise<void> {
  const { state_id, options } = await webauthnRegisterStart();
  const pk = options.publicKey;

  // Native path takes the server's options verbatim — it decodes base64url itself —
  // so branch before the ArrayBuffer conversion below rather than after.
  if (await useNative()) {
    const credentialJson = await webauthnNativeRegister(pk);
    await webauthnRegisterFinish(state_id, credentialJson, label);
    return;
  }

  const publicKey: PublicKeyCredentialCreationOptions = {
    rp: pk.rp,
    user: {
      id: b64urlToBuffer(pk.user.id),
      name: pk.user.name,
      displayName: pk.user.displayName,
    },
    challenge: b64urlToBuffer(pk.challenge),
    pubKeyCredParams: pk.pubKeyCredParams,
    timeout: pk.timeout,
    excludeCredentials: decodeCredentialDescriptors(pk.excludeCredentials),
    authenticatorSelection: pk.authenticatorSelection,
    attestation: pk.attestation,
  };

  const cred = (await navigator.credentials.create({ publicKey })) as PublicKeyCredential;
  const response = cred.response as AuthenticatorAttestationResponse;
  const credentialJson = {
    id: cred.id,
    rawId: bufferToB64url(cred.rawId),
    response: {
      attestationObject: bufferToB64url(response.attestationObject),
      clientDataJSON: bufferToB64url(response.clientDataJSON),
    },
    type: cred.type,
  };
  await webauthnRegisterFinish(state_id, credentialJson, label);
}

// Prove possession of a registered key for step-up purpose `purpose`.
// Returns the proof_token, same contract as verifyStepUp/verifyStepUpTotp.
export async function verifyWithSecurityKey(purpose: string): Promise<string> {
  const { state_id, options } = await webauthnAuthenticateStart();
  const pk = options.publicKey;

  if (await useNative()) {
    const credentialJson = await webauthnNativeAuthenticate(pk);
    return verifyStepUpWebauthn(purpose, state_id, credentialJson);
  }

  const publicKey: PublicKeyCredentialRequestOptions = {
    challenge: b64urlToBuffer(pk.challenge),
    rpId: pk.rpId,
    allowCredentials: decodeCredentialDescriptors(pk.allowCredentials),
    userVerification: pk.userVerification,
    timeout: pk.timeout,
  };

  const cred = (await navigator.credentials.get({ publicKey })) as PublicKeyCredential;
  const response = cred.response as AuthenticatorAssertionResponse;
  const credentialJson = {
    id: cred.id,
    rawId: bufferToB64url(cred.rawId),
    response: {
      authenticatorData: bufferToB64url(response.authenticatorData),
      clientDataJSON: bufferToB64url(response.clientDataJSON),
      signature: bufferToB64url(response.signature),
      ...(response.userHandle ? { userHandle: bufferToB64url(response.userHandle) } : {}),
    },
    type: cred.type,
  };
  return verifyStepUpWebauthn(purpose, state_id, credentialJson);
}

// Whether a security key can be used on this device at all — checked before offering
// the "register a security key" UI so we fail honestly (P.3) instead of showing a
// button that throws.
//
// The native path is checked FIRST and wins: on macOS the webview advertises
// `navigator.credentials` and `window.PublicKeyCredential` perfectly happily and then
// rejects every roaming key with NotAllowedError, so the browser check is actively
// misleading there and cannot be the one that decides.
//
// Linux is then excluded outright. WebKitGTK ships no WebAuthn implementation
// (WebKit bug 205350), so the API surface the check below looks for is either absent
// or non-functional; showing the section there would be a button that only ever
// throws. Windows is left to the browser check on purpose — WebView2 forwards
// WebAuthn to the native Windows API, so it is expected to work.
export async function webauthnAvailable(): Promise<boolean> {
  if (await useNative()) return true;
  try {
    if ((await getPlatform()) === "linux") return false;
  } catch {
    // Platform unknown — fall through to the capability check rather than hiding a
    // factor the user may well have. Failing open here is the honest default: the
    // worst case is the existing error message, not a missing feature.
  }
  return typeof navigator !== "undefined" && !!navigator.credentials && !!window.PublicKeyCredential;
}
