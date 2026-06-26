<script lang="ts">
  interface Props {
    node?: string;
    ledgerEntry?: string;
    ledgerTime?: string;
    onclose?: () => void;
  }
  let { node = '', ledgerEntry = '', ledgerTime = '', onclose }: Props = $props();
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
        <span class="info-val">direct peer-to-peer</span>
      </div>
      <div class="info-row">
        <span class="info-label">Vendor in path</span>
        <span class="info-val check">No ✓</span>
      </div>
      {#if ledgerEntry}
        <div class="info-row">
          <span class="info-label">Ledger entry</span>
          <span class="info-val">#{ledgerEntry}{ledgerTime ? ' · ' + ledgerTime : ''}</span>
        </div>
      {/if}
    </div>
    <button class="link-btn">View full ledger entry</button>
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
