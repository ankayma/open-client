// Browser-side WebAuthn/FIDO2 ceremony driver (E-7 StepUp Phase 3 — AAL3,
// Part D §H.8 Phase 3). The control plane (webauthn-rs) speaks
// the standard browser JSON transport (camelCase, base64url binary fields) —
// this is the only layer that touches `navigator.credentials`; the Tauri
// commands in tauri.ts are opaque JSON pass-throughs either side of it.
//
// KNOWN RISK (flagged in the implementation plan, not yet hardware-verified
// in this environment): Tauri's embedded webview (WKWebView on macOS) has had
// inconsistent support for *roaming* USB/NFC FIDO2 keys — as opposed to
// platform authenticators (Touch ID/Windows Hello), which work reliably. If
// `navigator.credentials.create()` below never resolves or throws
// `NotSupportedError`/`NotAllowedError` immediately when a YubiKey is
// inserted, that's this platform gap, not a bug in the exchange logic — the
// fallback is a native FIDO2/CTAP-HID crate behind a Tauri command instead of
// the browser API (bigger change, needs its own dependency decision).

import {
  webauthnRegisterStart,
  webauthnRegisterFinish,
  webauthnAuthenticateStart,
  verifyStepUpWebauthn,
} from "./tauri";

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

// Whether this webview exposes the WebAuthn API at all — checked before
// offering the "register a security key" UI so we fail honestly (P.3)
// instead of showing a button that throws.
export function webauthnAvailable(): boolean {
  return typeof navigator !== "undefined" && !!navigator.credentials && !!window.PublicKeyCredential;
}
