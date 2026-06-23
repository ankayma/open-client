<script lang="ts">
  import { onMount } from "svelte";
  import { myAccess, openSubdomain } from "$lib/tauri";
  import type { MyAccess } from "$lib/types";

  // my-access (addendum §D): the services this identity may reach, derived from the
  // active PolicyBlock. Admin sees all (allow-within-owner); members see what policy
  // grants. The rule_ref shows WHY each is granted.
  let data = $state<MyAccess | null>(null);
  let loading = $state(true);
  let error = $state("");

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
  <header>
    <h2>Services</h2>
    <button class="icon-btn" onclick={load} aria-label="Refresh">↻</button>
  </header>

  <p class="desc">
    What you can reach on this mesh, derived from your team's access policy. Each
    service opens privately over the overlay — no public port.
    {#if data}<span class="role-chip">{data.role}</span>{/if}
  </p>

  {#if error}<p class="err">{error}</p>{/if}

  {#if loading}
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
        <div class="card">
          <div class="card-head">
            <span class="label">{svc.label}</span>
            <button class="open" onclick={() => openSubdomain(svc.fqdn)}>Open ↗</button>
          </div>
          <code class="fqdn">{svc.fqdn}</code>
          <div class="meta">
            <span>→ {svc.node}</span>
            <span class="ref" title="why you can reach this">via {svc.rule_ref}</span>
          </div>
        </div>
      {/each}
    </div>
  {/if}
</main>

<style>
  main {
    flex: 1;
    display: flex;
    flex-direction: column;
    padding: calc(var(--safe-top) + 16px) 16px calc(var(--safe-bottom) + 32px);
    max-width: 480px;
    margin: 0 auto;
    width: 100%;
  }
  header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 8px 0 16px;
  }
  h2 {
    font-size: 22px;
    font-weight: 700;
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
    margin-bottom: 16px;
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
    margin-bottom: 12px;
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
  .card-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
  }
  .label {
    font-weight: 700;
    font-size: 15px;
  }
  .open {
    font-size: 13px;
    font-weight: 600;
    color: var(--c-accent);
    padding: 4px 10px;
    border-radius: 6px;
  }
  .open:hover {
    background: color-mix(in srgb, var(--c-accent) 12%, transparent);
  }
  .fqdn {
    font-family: "SF Mono", "Fira Code", monospace;
    font-size: 12px;
    color: var(--c-text-dim);
    word-break: break-all;
  }
  .meta {
    display: flex;
    justify-content: space-between;
    gap: 10px;
    font-size: 12px;
    color: var(--c-text-dim);
  }
  .ref {
    font-family: "SF Mono", "Fira Code", monospace;
    opacity: 0.8;
  }
</style>
