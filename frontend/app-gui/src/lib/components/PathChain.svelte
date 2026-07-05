<script lang="ts">
  import { onMount } from 'svelte';
  import { getPathProof } from '$lib/tauri';
  import type { PathProof } from '$lib/types';

  interface Props {
    node?: string;
    ledgerEntry?: string;
    ledgerTime?: string;
    onclose?: () => void;
  }
  let { node = '', ledgerEntry = '', ledgerTime = '', onclose }: Props = $props();

  // [F-5 "Prove it"] Route + vendor rows are measured from the live WireGuard
  // state (get_path_proof), not hardcoded — the panel is a proof, not a claim.
  let proof = $state<PathProof | null>(null);
  let proofErr = $state('');
  let expanded = $state(false);
  // Endpoint = the node's static public IP:port. Masked by default so a shared
  // screenshot of the proof never leaks it; one tap reveals (owner asked for
  // this trade-off — proof stays available, leak needs intent, 2026-07-05).
  let revealEndpoint = $state(false);
  onMount(() => {
    getPathProof()
      .then((p) => (proof = p))
      .catch((e) => (proofErr = String(e)));
  });
  // [A] my_access `node` and path-proof `hostname` are both the peer's hostname
  // today; verify the join once my_access grows node ids.
  let peer = $derived(proof?.peers.find((p) => p.hostname === node) ?? null);
  let route = $derived(
    proof === null
      ? '…'
      : peer === null
        ? 'no active tunnel'
        : peer.direct
          ? 'direct peer-to-peer'
          : 'relayed · end-to-end encrypted'
  );
  let vendorInPath = $derived(proof?.vendor_on_data_path ?? null);
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
    <div class="panel-header">
      <span class="panel-title">◈ path chain</span>
      <button class="close-btn" onclick={onclose}>✕</button>
    </div>
    <div class="chain">
      <div class="chain-node">
        <div class="chain-dot your"></div>
        <span>Your device</span>
      </div>
      <div class="chain-line">──●──</div>
      <div class="chain-node">
        <div class="chain-dot remote"></div>
        <span>{node}</span>
      </div>
    </div>
    <div class="info-rows">
      <div class="info-row">
        <span class="info-label">Route</span>
        <span class="info-val">{route}</span>
      </div>
      <div class="info-row">
        <span class="info-label">Vendor in path</span>
        {#if vendorInPath === null}
          <span class="info-val">…</span>
        {:else if vendorInPath}
          <span class="info-val warn">Yes ⚠</span>
        {:else}
          <span class="info-val check">No ✓</span>
        {/if}
      </div>
      {#if ledgerEntry}
        <div class="info-row">
          <span class="info-label">Ledger entry</span>
          <span class="info-val">#{ledgerEntry}{ledgerTime ? ' · ' + ledgerTime : ''}</span>
        </div>
      {/if}
    </div>

    {#if expanded}
      <div class="detail">
        {#if proofErr}
          <p class="detail-err">Could not read the path proof: {proofErr}</p>
        {:else if proof === null}
          <p class="detail-note">Reading live path proof…</p>
        {:else}
          <div class="info-row">
            <span class="info-label">Node</span>
            <span class="info-val mono">{node}</span>
          </div>
          {#if peer}
            <div class="info-row">
              <span class="info-label">Overlay IP</span>
              <span class="info-val mono">{peer.overlay_ip}</span>
            </div>
            <div class="info-row">
              <span class="info-label">Endpoint</span>
              {#if !peer.endpoint}
                <span class="info-val mono">—</span>
              {:else if revealEndpoint}
                <span class="info-val mono">{peer.endpoint}</span>
              {:else}
                <button
                  class="reveal-btn"
                  title="Public IP of your node — hidden from screenshots by default"
                  onclick={() => (revealEndpoint = true)}
                >••••••••••:••••&nbsp; tap to reveal</button>
              {/if}
            </div>
          {:else}
            <p class="detail-note">No active tunnel to this node right now — connect and reopen to capture the live path.</p>
          {/if}
          <div class="info-row">
            <span class="info-label">Control plane</span>
            <span class="info-val mono">{proof.control_plane}</span>
          </div>
          <p class="detail-note">
            Coordination only — the control plane never carries your traffic. Measured
            live from the WireGuard session; signed per-session receipts land with the
            ledger export.
          </p>
        {/if}
      </div>
    {/if}
    <button class="link-btn" onclick={() => (expanded = !expanded)}>
      {expanded ? 'Hide ledger detail' : 'View full ledger entry'}
    </button>
  </div>
</div>

<style>
  .overlay {
    position: fixed;
    inset: 0;
    background: rgba(0,0,0,0.6);
    display: flex;
    align-items: flex-end;
    justify-content: center;
    z-index: 200;
    padding: 0;
  }

  .panel {
    background: var(--c-surface);
    border: 1px solid var(--c-border);
    border-radius: var(--radius) var(--radius) 0 0;
    padding: 20px;
    width: 100%;
    max-width: 480px;
  }

  .panel-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 20px;
  }

  .panel-title {
    font-size: 15px;
    font-weight: 700;
    color: var(--c-accent);
  }

  .close-btn {
    color: var(--c-text-dim);
    font-size: 16px;
    padding: 4px 8px;
  }

  .chain {
    display: flex;
    align-items: center;
    gap: 8px;
    margin-bottom: 20px;
    padding: 16px;
    background: var(--c-bg);
    border-radius: 8px;
    font-size: 13px;
    flex-wrap: wrap;
  }

  .chain-node {
    display: flex;
    align-items: center;
    gap: 6px;
  }

  .chain-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
  }

  .chain-dot.your {
    background: var(--c-accent);
  }

  .chain-dot.remote {
    background: var(--sec-allow);
  }

  .chain-line {
    color: var(--c-text-dim);
    font-size: 11px;
    letter-spacing: 1px;
  }

  .info-rows {
    display: flex;
    flex-direction: column;
    gap: 8px;
    margin-bottom: 16px;
  }

  .info-row {
    display: flex;
    justify-content: space-between;
    font-size: 13px;
  }

  .info-label {
    color: var(--c-text-dim);
  }

  .info-val {
    color: var(--c-text);
  }

  .info-val.check {
    color: var(--sec-allow);
  }

  .info-val.warn {
    color: var(--c-warn);
  }

  .info-val.mono {
    font-family: 'SF Mono', 'Fira Code', monospace;
    font-size: 12px;
    word-break: break-all;
    text-align: right;
  }

  .detail {
    display: flex;
    flex-direction: column;
    gap: 8px;
    margin-bottom: 16px;
    padding: 12px;
    background: var(--c-bg);
    border-radius: 8px;
  }

  .detail-note {
    font-size: 12px;
    color: var(--c-text-dim);
    line-height: 1.5;
  }

  .detail-err {
    font-size: 12px;
    color: var(--c-danger);
  }

  .reveal-btn {
    font-family: 'SF Mono', 'Fira Code', monospace;
    font-size: 11px;
    color: var(--c-text-dim);
    background: none;
    border: 1px dashed var(--c-border);
    border-radius: 6px;
    padding: 2px 8px;
    cursor: pointer;
  }
  .reveal-btn:hover {
    color: var(--c-text);
    border-color: var(--c-text-dim);
  }

  .link-btn {
    color: var(--c-accent);
    font-size: 13px;
    text-decoration: underline;
  }

  @media (min-width: 760px) {
    .overlay {
      align-items: center;
    }

    .panel {
      border-radius: var(--radius);
      max-width: 400px;
    }
  }
</style>
