<script lang="ts">
  import type { PathPeer } from '$lib/types';

  interface Props {
    node?: string;
    peer?: PathPeer | null;
    ledgerEntry?: string;
    ledgerTime?: string;
    onclose?: () => void;
    /**
     * [F-5] Drill into this node's signed activity (ledger receipts). Path chain
     * proves the live data-path (A.1.1); the ledger proves the actions (A.1.8).
     * They are two distinct artifacts, joined by this one link — a bare tunnel is
     * not a ledgered event, so the link points at the node's activity, never at
     * "the ledger entry for this connection". `[T:A.1.1 + A.1.8]`
     */
    onactivity?: () => void;
  }
  let { node = '', peer = null, ledgerEntry = '', ledgerTime = '', onclose, onactivity }: Props = $props();

  function fmtBytes(n: number): string {
    if (n < 1024) return `${n} B`;
    if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
    return `${(n / 1024 / 1024).toFixed(1)} MB`;
  }

  function fmtHandshake(secs: number): string {
    if (secs < 60) return `${secs}s ago`;
    if (secs < 3600) return `${Math.floor(secs / 60)}m ago`;
    return `${Math.floor(secs / 3600)}h ago`;
  }

  const hasTraffic = $derived(peer != null && (peer.tx_bytes > 0 || peer.rx_bytes > 0));
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
        {#if peer}
          {#if peer.direct}
            <span class="info-val">direct peer-to-peer</span>
          {:else}
            <span class="info-val relay">relayed (encrypted)</span>
          {/if}
        {:else}
          <span class="info-val dim">—</span>
        {/if}
      </div>
      <div class="info-row">
        <span class="info-label">Vendor in path</span>
        {#if peer}
          {#if peer.direct}
            <span class="info-val check">No ✓</span>
          {:else}
            <span class="info-val relay-warn">Yes · relay (content encrypted)</span>
          {/if}
        {:else}
          <span class="info-val dim">—</span>
        {/if}
      </div>
      {#if peer?.endpoint}
        <div class="info-row">
          <span class="info-label">Endpoint</span>
          <code class="info-val ep">{peer.endpoint}</code>
        </div>
      {/if}
      {#if peer?.last_handshake_secs != null}
        <div class="info-row">
          <span class="info-label">Handshake</span>
          <span class="info-val">{fmtHandshake(peer.last_handshake_secs)}</span>
        </div>
      {/if}
      {#if hasTraffic && peer}
        <div class="info-row">
          <span class="info-label">Traffic</span>
          <span class="info-val">↑ {fmtBytes(peer.tx_bytes)} · ↓ {fmtBytes(peer.rx_bytes)}</span>
        </div>
      {/if}
      {#if ledgerEntry}
        <div class="info-row">
          <span class="info-label">Ledger entry</span>
          <span class="info-val">#{ledgerEntry}{ledgerTime ? ' · ' + ledgerTime : ''}</span>
        </div>
      {/if}
    </div>
    {#if !peer}
      <p class="no-data">Connect the tunnel to see live path evidence.</p>
    {:else if !peer.direct}
      <p class="relay-note">
        Traffic flows through a vendor-operated relay encrypted end-to-end — vendor cannot read content.
        See <strong>Pricing &amp; Plans</strong> for direct P2P options.
      </p>
    {/if}
    {#if onactivity}
      <button class="activity-link" onclick={onactivity}>
        <span>Activity &amp; receipts</span>
        <span class="activity-arrow">↗</span>
      </button>
      <p class="activity-hint">Signed ledger receipts for actions on this node.</p>
    {/if}
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

  .info-val.dim {
    color: var(--c-text-dim);
  }

  .info-val.relay {
    color: var(--c-text-dim);
  }

  .info-val.relay-warn {
    color: var(--c-warn, #f5a623);
  }

  .info-val.ep {
    font-family: 'SF Mono', 'Fira Code', monospace;
    font-size: 12px;
    color: var(--c-text-dim);
  }

  .no-data {
    font-size: 12px;
    color: var(--c-text-dim);
    text-align: center;
    padding: 8px 0;
  }

  .relay-note {
    font-size: 12px;
    color: var(--c-text-dim);
    line-height: 1.5;
    padding: 10px;
    background: var(--c-bg);
    border-radius: 6px;
    margin-top: 4px;
  }

  .activity-link {
    display: flex;
    align-items: center;
    justify-content: space-between;
    width: 100%;
    margin-top: 12px;
    padding: 11px 14px;
    background: var(--c-bg);
    border: 1px solid var(--c-border);
    border-radius: 8px;
    color: var(--c-accent);
    font-size: 13px;
    font-weight: 600;
    cursor: pointer;
    transition: border-color 0.15s, background 0.15s;
  }

  .activity-link:hover {
    border-color: var(--c-accent);
    background: color-mix(in srgb, var(--c-accent) 8%, var(--c-bg));
  }

  .activity-arrow {
    font-weight: 400;
  }

  .activity-hint {
    font-size: 11px;
    color: var(--c-text-dim);
    text-align: center;
    margin: 6px 0 0;
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
