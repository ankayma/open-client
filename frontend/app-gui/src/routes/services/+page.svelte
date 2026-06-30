<script lang="ts">
  import { onMount } from "svelte";
  import { myAccess, openSubdomain } from "$lib/tauri";
  import type { MyAccess, AccessService } from "$lib/types";
  import { connection } from "$lib/stores";
  import ConnectionCard from "$lib/components/ConnectionCard.svelte";
  import PathChain from "$lib/components/PathChain.svelte";

  // my-access (addendum §D): the services this identity may reach, derived from the
  // active PolicyBlock. Admin sees all (allow-within-owner); members see what policy
  // grants. The rule_ref shows WHY each is granted.
  let data = $state<MyAccess | null>(null);
  let loading = $state(true);
  let error = $state("");
  let pathChainSvc = $state<AccessService | null>(null);

  onMount(load);
  async function load() {
    loading = true;
    error = "";
    try {
      data = await myAccess();
    } catch (e: unknown) {
      error = e instanceof Error ? e.message : "Failed to load services";
    } finally {
      loading = false;
    }
  }
</script>

<main>
  <div class="layout">
    <aside class="conn-panel">
      <ConnectionCard />
    </aside>

    <section class="services-panel">
      <header>
        <h2>Services</h2>
        <div class="header-actions">
          <button class="btn-secondary filter-btn">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 7h18M3 12h18M3 17h18"/></svg>
            Filter ▾
          </button>
          <button class="icon-btn" onclick={load} aria-label="Refresh">↻</button>
        </div>
      </header>

      <p class="desc">
        What you can reach on this mesh, derived from your team's access policy. Each
        service opens privately over the overlay — no public port.
        {#if data && $connection.status === "connected"}<span class="role-chip">{data.role}</span>{/if}
      </p>

      {#if $connection.status !== "connected"}
        <div class="empty">
          <p>Not connected.</p>
          <p class="hint">
            Connect above to reach the services your team's access policy grants you.
          </p>
        </div>
      {:else if error}
        <p class="err">{error}</p>
      {:else if loading}
        <div class="empty">Loading…</div>
      {:else if !data || data.services.length === 0}
        <div class="empty">
          <p>No services you can reach yet.</p>
          <p class="hint">
            An admin grants access in <strong>Access</strong>, and services are named in
            <strong>Subdomains</strong>.
          </p>
        </div>
      {:else}
        <div class="grid">
          {#each data.services as svc (svc.fqdn)}
            <div class="card" class:denied={svc.status === "denied"}>
              <div class="card-head">
                <span class="label">{svc.label}</span>
                {#if svc.status !== "denied"}
                  <button class="btn-primary" onclick={() => openSubdomain(svc.fqdn)}>Open ↗</button>
                {/if}
              </div>
              <code class="fqdn">{svc.fqdn}</code>
              <div class="tags">
                <span class="tag" title="why you can reach this">{svc.rule_ref}</span>
                {#each svc.tags ?? [] as t}<span class="tag">{t}</span>{/each}
              </div>
              <div class="meta">
                {#if svc.status === "denied"}
                  <span class="denied-text">access denied (no policy)</span>
                {:else}
                  <span>→ {svc.node}</span>
                  <button class="btn-secondary chain-btn" onclick={() => (pathChainSvc = svc)}>◈ path chain</button>
                {/if}
              </div>
            </div>
          {/each}
        </div>
      {/if}
    </section>
  </div>
</main>

{#if pathChainSvc}
  <PathChain node={pathChainSvc.node} onclose={() => (pathChainSvc = null)} />
{/if}

<style>
  main {
    flex: 1;
    display: flex;
    flex-direction: column;
    padding: calc(var(--safe-top) + 16px) 16px calc(var(--safe-bottom) + 32px);
    width: 100%;
  }
  .layout {
    display: flex;
    flex-direction: column;
    gap: 16px;
    max-width: 480px;
    margin: 0 auto;
    width: 100%;
  }
  .services-panel {
    display: flex;
    flex-direction: column;
    gap: 16px;
    min-width: 0;
  }
  @media (min-width: 760px) {
    .layout {
      flex-direction: row;
      align-items: flex-start;
      max-width: 1080px;
    }
    .conn-panel {
      width: 260px;
      flex-shrink: 0;
      position: sticky;
      top: 24px;
    }
    .services-panel {
      flex: 1;
    }
  }
  header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
  }
  h2 {
    font-size: 22px;
    font-weight: 700;
  }
  .header-actions {
    display: flex;
    align-items: center;
    gap: 6px;
  }
  .filter-btn {
    display: flex;
    align-items: center;
    gap: 6px;
    font-size: 13px;
  }
  .icon-btn {
    color: var(--c-text-dim);
    font-size: 18px;
    padding: 6px 10px;
    border-radius: 8px;
  }
  .icon-btn:hover {
    background: var(--c-surface);
  }
  .desc {
    font-size: 14px;
    color: var(--c-text-dim);
    line-height: 1.6;
  }
  .role-chip {
    display: inline-block;
    margin-left: 6px;
    padding: 1px 8px;
    border-radius: 6px;
    background: color-mix(in srgb, var(--c-accent) 18%, transparent);
    color: var(--c-accent);
    font-size: 12px;
    font-weight: 700;
  }
  .err {
    color: var(--c-danger);
    font-size: 13px;
  }
  .empty {
    text-align: center;
    color: var(--c-text-dim);
    padding: 40px 0;
    font-size: 14px;
  }
  .hint {
    margin-top: 8px;
    font-size: 13px;
  }
  /* Single column on mobile; a responsive grid fills the desktop width. */
  .grid {
    display: grid;
    grid-template-columns: 1fr;
    gap: 10px;
  }
  @media (min-width: 760px) {
    .grid {
      grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
    }
  }
  .card {
    background: var(--c-surface);
    border: 1px solid var(--c-border);
    border-radius: 12px;
    padding: 14px 16px;
    display: flex;
    flex-direction: column;
    gap: 8px;
  }
  .card.denied {
    opacity: 0.55;
  }
  .card-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
  }
  .label {
    font-weight: 700;
    font-size: 15px;
  }
  .fqdn {
    font-family: "SF Mono", "Fira Code", monospace;
    font-size: 12px;
    color: var(--c-text-dim);
    word-break: break-all;
  }
  .tags {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
  }
  .meta {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
    font-size: 12px;
    color: var(--c-text-dim);
  }
  .denied-text {
    font-style: italic;
  }
  .chain-btn {
    font-size: 12px;
    padding: 5px 10px;
  }
</style>
