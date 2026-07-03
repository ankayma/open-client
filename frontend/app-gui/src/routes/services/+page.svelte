<script lang="ts">
  import { onMount } from "svelte";
  import { myAccess, openSubdomain, getNodeInfo } from "$lib/tauri";
  import type { MyAccess, AccessService } from "$lib/types";
  import { connection } from "$lib/stores";
  import ConnectionCard from "$lib/components/ConnectionCard.svelte";
  import PathChain from "$lib/components/PathChain.svelte";

  // my-access (addendum §D): the services this identity may reach, derived from the
  // active PolicyBlock. Admin sees all (allow-within-owner); members see what policy
  // grants. The rule_ref shows WHY each is granted. Fetched over REST regardless of
  // tunnel state — the list itself never needs to hide on disconnect (H.2.1); only
  // tunnel-dependent actions ("Open ↗") get disabled below.
  let data = $state<MyAccess | null>(null);
  let loading = $state(true);
  let error = $state("");
  let pathChainSvc = $state<AccessService | null>(null);
  let myHostname = $state<string | null>(null);

  onMount(() => {
    load();
    getNodeInfo().then((n) => (myHostname = n.hostname)).catch(() => {});
  });

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

  // Group services by node — a node with more than one reachable service renders
  // as one card with a child list, instead of one flat card per service. `owned`
  // is a device-scoped signal (does this node match *my* current hostname) — the
  // my-access response has no cross-device ownership field yet, so cards for a
  // teammate's other devices land in "Team / Shared" even if they're that
  // teammate's own node. [A] narrower than full ownership; verify once my-access
  // grows an owner field.
  interface NodeGroup { node: string; owned: boolean; services: AccessService[] }
  let groups = $derived.by((): NodeGroup[] => {
    const byNode = new Map<string, AccessService[]>();
    for (const svc of data?.services ?? []) {
      const list = byNode.get(svc.node) ?? [];
      list.push(svc);
      byNode.set(svc.node, list);
    }
    return [...byNode.entries()].map(([node, services]) => ({
      node,
      owned: myHostname !== null && node === myHostname,
      services
    }));
  });
  let ownedGroups = $derived(groups.filter((g) => g.owned));
  let teamGroups = $derived(groups.filter((g) => !g.owned));
  let showSectionHeaders = $derived(ownedGroups.length > 0 && teamGroups.length > 0);
  let connected = $derived($connection.status === "connected");
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
        {#if data}<span class="role-chip">{data.role}</span>{/if}
      </p>

      {#if error}
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
          {#if ownedGroups.length > 0}
            {#if showSectionHeaders}<div class="section-divider">── My Nodes</div>{/if}
            {#each ownedGroups as group (group.node)}
              {#if group.services.length === 1}
                {@render serviceCard(group.services[0], true)}
              {:else}
                {@render nodeCard(group)}
              {/if}
            {/each}
          {/if}

          {#if teamGroups.length > 0}
            {#if showSectionHeaders}<div class="section-divider">── Team / Shared</div>{/if}
            {#each teamGroups as group (group.node)}
              {#if group.services.length === 1}
                {@render serviceCard(group.services[0], false)}
              {:else}
                {@render nodeCard(group)}
              {/if}
            {/each}
          {/if}
        </div>
      {/if}
    </section>
  </div>
</main>

{#snippet serviceCard(svc: AccessService, owned: boolean)}
  <div class="card" class:denied={svc.status === "denied"} class:owned>
    <div class="card-head">
      <span class="label">
        {svc.label}
        {#if owned}<span class="owned-badge">● owned</span>{/if}
      </span>
      {#if svc.status !== "denied"}
        <button class="btn-primary" disabled={!connected} onclick={() => openSubdomain(svc.fqdn)}>Open ↗</button>
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
{/snippet}

{#snippet nodeCard(group: NodeGroup)}
  <div class="card node-card" class:owned={group.owned}>
    <div class="card-head">
      <span class="label">
        {group.node}
        {#if group.owned}<span class="owned-badge">● owned</span>{/if}
      </span>
    </div>
    <div class="child-list">
      {#each group.services as svc (svc.fqdn)}
        <div class="child-row" class:denied={svc.status === "denied"}>
          <div class="child-info">
            <span class="child-label">{svc.label}</span>
            <code class="fqdn">{svc.fqdn}</code>
            <div class="tags">
              <span class="tag" title="why you can reach this">{svc.rule_ref}</span>
              {#each svc.tags ?? [] as t}<span class="tag">{t}</span>{/each}
            </div>
          </div>
          {#if svc.status === "denied"}
            <span class="denied-text">access denied</span>
          {:else}
            <div class="child-actions">
              <button class="btn-primary sm" disabled={!connected} onclick={() => openSubdomain(svc.fqdn)}>Open ↗</button>
              <button class="btn-secondary sm" onclick={() => (pathChainSvc = svc)}>◈</button>
            </div>
          {/if}
        </div>
      {/each}
    </div>
  </div>
{/snippet}

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
  .section-divider {
    grid-column: 1 / -1;
    font-size: 11px;
    font-weight: 700;
    color: var(--c-text-dim);
    text-transform: uppercase;
    letter-spacing: 0.8px;
    padding: 4px 0;
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
  /* Own node — accent left border (H.2.1.1 ▌ visual marker) */
  .card.owned {
    border-left: 3px solid var(--c-accent);
    padding-left: 14px;
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
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .owned-badge {
    font-size: 11px;
    font-weight: 500;
    color: color-mix(in srgb, var(--c-accent) 80%, var(--c-text-dim));
    background: color-mix(in srgb, var(--c-accent) 10%, transparent);
    border: 1px solid color-mix(in srgb, var(--c-accent) 22%, transparent);
    border-radius: 99px;
    padding: 1px 7px;
    white-space: nowrap;
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
  :global(.btn-primary:disabled) {
    opacity: 0.4;
    cursor: not-allowed;
  }

  /* Node card (H.2.1.2): a node with >1 reachable service renders as one card
     with a child list instead of one flat card per service. */
  .node-card {
    grid-column: span 1;
  }
  @media (min-width: 760px) {
    .grid > .node-card {
      grid-column: 1 / -1;
    }
  }
  .child-list {
    display: flex;
    flex-direction: column;
    gap: 8px;
    padding-top: 8px;
    border-top: 1px solid var(--c-border);
  }
  .child-row {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 10px;
    padding: 8px 10px;
    background: color-mix(in srgb, var(--c-accent) 4%, var(--c-bg));
    border: 1px solid var(--c-border);
    border-radius: 8px;
  }
  .child-row.denied {
    opacity: 0.55;
  }
  .child-info {
    display: flex;
    flex-direction: column;
    gap: 4px;
    min-width: 0;
  }
  .child-label {
    font-size: 13px;
    font-weight: 600;
  }
  .child-actions {
    display: flex;
    gap: 4px;
    flex-shrink: 0;
  }
  :global(.btn-primary.sm),
  :global(.btn-secondary.sm) {
    padding: 4px 8px;
    font-size: 12px;
  }
</style>
