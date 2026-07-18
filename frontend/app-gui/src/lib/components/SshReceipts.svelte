<script lang="ts">
  // [F-2] Node-scoped SSH session receipts — the signed half of NoKey SSH.
  // Each session is a projection of a SshSessionOpened ledger event (A.1.8); the
  // block hash is the tamper-evident anchor, shown so the user can SEE the signed
  // record of who reached this node over the mesh, not just be told it exists.
  // Connection-level only (who / when), never the transcript (A.1.1). Read-only,
  // scoped by A.1.2. Mirrors LedgerReceipts (the CI/CD receipts view).
  import { onMount } from 'svelte';
  import { sshHistory } from '$lib/tauri';
  import type { SshSession } from '$lib/types';

  interface Props {
    node: string;
    onclose?: () => void;
  }
  let { node, onclose }: Props = $props();

  let sessions = $state<SshSession[] | null>(null);
  let err = $state('');

  onMount(async () => {
    try {
      sessions = await sshHistory(node);
    } catch (e) {
      err = String(e);
    }
  });
</script>

<div
  class="overlay"
  role="presentation"
  onclick={onclose}
  onkeydown={(e) => e.key === 'Escape' && onclose?.()}
>
  <div
    class="panel"
    role="dialog"
    aria-modal="true"
    tabindex="-1"
    onclick={(e) => e.stopPropagation()}
    onkeydown={(e) => e.stopPropagation()}
  >
    <div class="head">
      <span class="title">🔑 SSH access log → {node}</span>
      <button class="close" aria-label="Close" onclick={onclose}>✕</button>
    </div>

    {#if err}
      {#if err.includes('404')}
        <p class="note">SSH receipts need the updated control plane — it lands after the next server deploy.</p>
      {:else}
        <p class="note err">Could not load SSH history: {err}</p>
      {/if}
    {:else if sessions === null}
      <p class="note">Loading SSH history…</p>
    {:else if sessions.length === 0}
      <p class="note">No SSH sessions on this node yet — the first mesh SSH lands here with a signed receipt.</p>
    {:else}
      <div class="runs">
        {#each sessions as sess (sess.block_hash)}
          <div class="run">
            <span class="outcome allow">✓</span>
            <div class="main">
              <span class="repo">{sess.login ?? '?'}{sess.target_host ? `@${sess.target_host}` : ''}</span>
              <span class="meta">{sess.at ?? ''}{sess.session_id ? ` · ${sess.session_id}` : ''}</span>
            </div>
            {#if sess.block_hash}
              <span class="ledger" title="Tamper-evident ledger block · {sess.block_hash}"
                >🔒 ledger #{sess.block_hash.slice(0, 8)}</span>
            {/if}
          </div>
        {/each}
      </div>
      <p class="note">Every mesh SSH session is a ledger entry — connection-level only, never the transcript.</p>
    {/if}
  </div>
</div>

<style>
  .overlay {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.6);
    display: flex;
    align-items: flex-end;
    justify-content: center;
    z-index: 200;
  }
  .panel {
    background: var(--c-surface);
    border: 1px solid var(--c-border);
    border-radius: var(--radius) var(--radius) 0 0;
    padding: 20px;
    width: 100%;
    max-width: 480px;
  }
  .head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 16px;
  }
  .title {
    font-size: 15px;
    font-weight: 700;
  }
  .close {
    color: var(--c-text-dim);
    font-size: 16px;
    padding: 4px 8px;
  }
  .runs {
    display: flex;
    flex-direction: column;
    gap: 8px;
    padding: 10px;
    background: var(--c-bg);
    border-radius: 8px;
    margin-bottom: 10px;
    max-height: 50vh;
    overflow-y: auto;
  }
  .run {
    display: flex;
    align-items: flex-start;
    gap: 10px;
  }
  .outcome {
    color: var(--c-danger);
    font-weight: 700;
  }
  .outcome.allow {
    color: var(--sec-allow);
  }
  .main {
    display: flex;
    flex-direction: column;
    gap: 2px;
    min-width: 0;
  }
  .repo {
    font-size: 13px;
    font-weight: 600;
    word-break: break-all;
  }
  .meta {
    font-size: 11px;
    color: var(--c-text-dim);
    font-family: 'SF Mono', 'Fira Code', monospace;
    word-break: break-all;
  }
  .ledger {
    margin-left: auto;
    flex-shrink: 0;
    align-self: center;
    font-size: 10px;
    font-family: 'SF Mono', 'Fira Code', monospace;
    color: var(--sec-allow);
    background: color-mix(in srgb, var(--sec-allow) 12%, transparent);
    border-radius: 5px;
    padding: 3px 7px;
    white-space: nowrap;
    cursor: default;
  }
  .note {
    font-size: 12px;
    color: var(--c-text-dim);
    line-height: 1.5;
  }
  .note.err {
    color: var(--c-danger);
  }
  @media (min-width: 760px) {
    .overlay {
      align-items: center;
    }
    .panel {
      border-radius: var(--radius);
      max-width: 440px;
    }
  }
</style>
