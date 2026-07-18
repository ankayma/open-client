// Client side of the step-up authority gate (part-d-e7-stepup.md §H.5).
//
// A management action in a MULTI-USER tenant (mint a node-invite, revoke a node,
// invite/offboard a member) is gated server-side: the first call (no proof) returns
// STEP_UP_REQUIRED:<purpose>:<requiredAal>. This helper catches that, asks the
// control plane to email an OTP, shows a global modal, exchanges the entered code
// for a proof_token via `verifyStepUp`, and retries the action WITH the proof — a
// proof is not single-use, so a burst of same-purpose retries within its short TTL
// doesn't re-prompt. Solo F0 tenants never hit the gate, so `runWithStepUp` is a
// transparent pass-through for them.

import { writable } from "svelte/store";
import { requestStepUp, verifyStepUp, verifyStepUpTotp, totpStatus, type StepUpProof } from "./tauri";
import { verifyWithSecurityKey } from "./webauthn";

export interface StepUpState {
  purpose: string;
  requiredAal: number;
  // "totp": type the authenticator-app code straight away, no request needed.
  // "otp": the emailed-code path — a challenge has already been requested.
  factor: "totp" | "otp";
  sending: boolean;
  error: string | null;
  submit: (code: string) => Promise<void>;
  // OTP mode: mint a fresh emailed challenge (covers expiry/attempt-lock).
  // TOTP mode: fall back to the emailed OTP instead (lost/uninstalled app).
  resend: () => Promise<void>;
  // Epoch ms until which Resend is on cooldown (0 = available now). The modal
  // disables the button and shows a countdown until this passes — anti-spam so a
  // user can't hammer Resend and flood their inbox. [best-practice: escalating
  // backoff, aligns under the server's 3/min anti-bomb cap.]
  resendCooldownUntil: number;
  cancel: () => void;
}

// Escalating resend cooldown: 30s after the first send, then 60s, then 120s (cap).
// Client-side courtesy + anti-spam; the server enforces its own 3/min hard limit.
const RESEND_BACKOFF_SECS = [30, 60, 120];

// Null = no step-up in progress. The <StepUpModal/> in the layout renders this.
export const stepUp = writable<StepUpState | null>(null);

// The Rust command surfaces the gate as `STEP_UP_REQUIRED:<purpose>:<requiredAal>`.
export function isStepUpRequired(e: unknown): boolean {
  const m = e instanceof Error ? e.message : String(e);
  return m.includes("STEP_UP_REQUIRED");
}

function parseStepUpRequired(e: unknown): { purpose: string; requiredAal: number } {
  const m = e instanceof Error ? e.message : String(e);
  const [, purpose, aal] = m.split(":");
  return { purpose: purpose ?? "", requiredAal: aal ? parseInt(aal, 10) : 2 };
}

const PURPOSE_LABEL: Record<string, string> = {
  enroll_node: "create an invite link",
  revoke_node: "remove this device",
  invite_member: "invite this member",
  remove_member: "remove this member",
  manage_ci_policy: "change this deploy rule",
};
export function purposeLabel(p: string): string {
  return PURPOSE_LABEL[p] ?? p;
}

// Run `action`, transparently satisfying a server step-up demand. `action` is invoked
// first with no proof; on STEP_UP_REQUIRED we branch on the demanded AAL:
//   - requiredAal >= 3 (F2+, no-soft-fallback — A.1.10): the browser's own WebAuthn
//     UI (Touch ID / "insert your key") handles the prompt, no modal of ours needed.
//   - requiredAal 2: check whether the user has a confirmed TOTP credential (skip
//     straight to code entry) or fall back to emailing an OTP, drive the modal.
// Either way we exchange the proof for a proof_token and retry `action({proofToken})`
// until it succeeds, the user cancels, or a non-recoverable error surfaces.
export async function runWithStepUp<T>(
  purpose: string,
  action: (proof?: StepUpProof) => Promise<T>,
): Promise<T> {
  let requiredAal = 2;
  try {
    return await action();
  } catch (e) {
    if (!isStepUpRequired(e)) throw e;
    requiredAal = parseStepUpRequired(e).requiredAal;
  }

  if (requiredAal >= 3) {
    // No modal — the authenticator ceremony IS the UI. A failure/cancel here
    // propagates as a normal rejected promise (no soft-fallback to a weaker
    // factor is correct per A.1.10).
    const proofToken = await verifyWithSecurityKey(purpose);
    return await action({ proofToken });
  }

  let factor: "totp" | "otp" = (await totpStatus().catch(() => false)) ? "totp" : "otp";
  let challengeId = factor === "otp" ? await requestStepUp(purpose) : "";

  return await new Promise<T>((resolve, reject) => {
    const patch = (p: Partial<StepUpState>) =>
      stepUp.update((s) => (s ? { ...s, ...p } : s));
    const close = () => stepUp.set(null);

    // Escalating cooldown state. Each emailed send bumps the index → longer wait.
    let resendIdx = 0;
    let cooldownUntil = 0;
    const armCooldown = () => {
      const secs = RESEND_BACKOFF_SECS[Math.min(resendIdx, RESEND_BACKOFF_SECS.length - 1)];
      resendIdx += 1;
      cooldownUntil = Date.now() + secs * 1000;
      return cooldownUntil;
    };
    // OTP factor already emailed a code above (challengeId request) → start the
    // first cooldown now. TOTP factor has sent nothing yet, so no cooldown until
    // the user falls back to email.
    if (factor === "otp") armCooldown();

    const submit = async (code: string) => {
      const trimmed = code.trim();
      if (!trimmed) {
        patch({
          error: factor === "totp" ? "Enter your authenticator app code." : "Enter the code we emailed you.",
        });
        return;
      }
      patch({ sending: true, error: null });
      try {
        const proofToken =
          factor === "totp"
            ? await verifyStepUpTotp(purpose, trimmed)
            : await verifyStepUp(purpose, challengeId, trimmed);
        const r = await action({ proofToken });
        close();
        resolve(r);
      } catch (e2) {
        // Wrong/expired/locked → stay open so they can retry or resend.
        patch({ sending: false, error: e2 instanceof Error ? e2.message : String(e2) });
      }
    };

    // OTP mode: mint a fresh challenge (expiry/attempt-lock). TOTP mode: give up
    // on the authenticator app and fall back to an emailed code instead.
    const resend = async () => {
      // Guard: honor the cooldown even if the UI somehow calls through (the modal
      // also disables the button). Prevents inbox flooding + server rate-limit hits.
      if (Date.now() < cooldownUntil) return;
      patch({ sending: true, error: null });
      try {
        challengeId = await requestStepUp(purpose);
        factor = "otp";
        patch({
          sending: false,
          error: "A new code was sent.",
          factor: "otp",
          resendCooldownUntil: armCooldown(),
        });
      } catch (e3) {
        patch({ sending: false, error: e3 instanceof Error ? e3.message : String(e3) });
      }
    };

    const cancel = () => {
      close();
      reject(new Error("Step-up cancelled"));
    };

    stepUp.set({
      purpose,
      requiredAal,
      factor,
      sending: false,
      error: null,
      submit,
      resend,
      resendCooldownUntil: cooldownUntil,
      cancel,
    });
  });
}
