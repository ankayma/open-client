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
import { requestStepUp, verifyStepUp, type StepUpProof } from "./tauri";

export interface StepUpState {
  purpose: string;
  requiredAal: number;
  sending: boolean;
  error: string | null;
  submit: (code: string) => Promise<void>;
  resend: () => Promise<void>;
  cancel: () => void;
}

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
};
export function purposeLabel(p: string): string {
  return PURPOSE_LABEL[p] ?? p;
}

// Run `action`, transparently satisfying a server step-up demand. `action` is invoked
// first with no proof; on STEP_UP_REQUIRED we request an OTP, drive the modal,
// exchange the entered code for a proof_token, and retry `action({proofToken})`
// until it succeeds, the user cancels, or a non-recoverable error surfaces. Wrong
// code keeps the modal open; "Resend" mints a fresh challenge (covers expiry /
// attempt-lock). `requiredAal` is surfaced on the state for the modal to pick the
// right factor UI (Phase 3 will branch to WebAuthn here when it's 3 and a key is
// registered — today only the AAL2 OTP factor exists).
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

  let challengeId = await requestStepUp(purpose);

  return await new Promise<T>((resolve, reject) => {
    const patch = (p: Partial<StepUpState>) =>
      stepUp.update((s) => (s ? { ...s, ...p } : s));
    const close = () => stepUp.set(null);

    const submit = async (code: string) => {
      const trimmed = code.trim();
      if (!trimmed) {
        patch({ error: "Enter the code we emailed you." });
        return;
      }
      patch({ sending: true, error: null });
      try {
        const proofToken = await verifyStepUp(purpose, challengeId, trimmed);
        const r = await action({ proofToken });
        close();
        resolve(r);
      } catch (e2) {
        // Wrong/expired/locked → stay open so they can retry or resend.
        patch({ sending: false, error: e2 instanceof Error ? e2.message : String(e2) });
      }
    };

    const resend = async () => {
      patch({ sending: true, error: null });
      try {
        challengeId = await requestStepUp(purpose);
        patch({ sending: false, error: "A new code was sent." });
      } catch (e3) {
        patch({ sending: false, error: e3 instanceof Error ? e3.message : String(e3) });
      }
    };

    const cancel = () => {
      close();
      reject(new Error("Step-up cancelled"));
    };

    stepUp.set({ purpose, requiredAal, sending: false, error: null, submit, resend, cancel });
  });
}
