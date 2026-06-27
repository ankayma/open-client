// Client side of the step-up authority gate (Part D invite-flow §Authority model).
//
// A management action in a MULTI-USER tenant (mint a node-invite, revoke a node) is
// gated server-side: the first call (no proof) returns STEP_UP_REQUIRED. This helper
// catches that, asks the control plane to email an OTP, shows a global modal, and
// retries the action with the entered code. Solo F0 tenants never hit the gate, so
// `runWithStepUp` is a transparent pass-through for them.

import { writable } from "svelte/store";
import { requestStepUp, type StepUpProof } from "./tauri";

export interface StepUpState {
  purpose: string;
  sending: boolean;
  error: string | null;
  submit: (code: string) => Promise<void>;
  resend: () => Promise<void>;
  cancel: () => void;
}

// Null = no step-up in progress. The <StepUpModal/> in the layout renders this.
export const stepUp = writable<StepUpState | null>(null);

// The Rust command surfaces the gate as the sentinel string `STEP_UP_REQUIRED:<purpose>`.
export function isStepUpRequired(e: unknown): boolean {
  const m = e instanceof Error ? e.message : String(e);
  return m.includes("STEP_UP_REQUIRED");
}

const PURPOSE_LABEL: Record<string, string> = {
  enroll_node: "create an invite link",
  revoke_node: "remove this device",
};
export function purposeLabel(p: string): string {
  return PURPOSE_LABEL[p] ?? p;
}

// Run `action`, transparently satisfying a server step-up demand. `action` is invoked
// first with no proof; on STEP_UP_REQUIRED we request an OTP and drive the modal,
// retrying `action({challengeId, code})` until it succeeds, the user cancels, or a
// non-recoverable error surfaces. Wrong code keeps the modal open; "Resend" mints a
// fresh challenge (covers expiry / attempt-lock).
export async function runWithStepUp<T>(
  purpose: string,
  action: (proof?: StepUpProof) => Promise<T>,
): Promise<T> {
  try {
    return await action();
  } catch (e) {
    if (!isStepUpRequired(e)) throw e;
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
        const r = await action({ challengeId, code: trimmed });
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

    stepUp.set({ purpose, sending: false, error: null, submit, resend, cancel });
  });
}
