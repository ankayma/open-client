<script lang="ts">
  import { onMount } from "svelte";
  import { getPolicy, submitPolicy, listMembers } from "$lib/tauri";

  // PolicyBlock authoring (Slice B). Admin edits the typed rules (from a principal
  // selector → to a resource selector) and publishes a new block onto the tenant's
  // tamper-evident chain. Members see it read-only. Default-deny: only listed Allow
  // rules grant access.
  type Sel = Record<string, string | number>;
  interface Rule {
    from: Sel;
    to: Sel;
  }

  let version = $state(0);
  let chainIntact = $state(true);
  let blockHash = $state<string | null>(null);
  let rules = $state<Rule[]>([]);
  let isAdmin = $state(false);
  let loading = $state(true);
  let error = $state("");
  let saved = $state("");

  // New-rule form fields.
  let fromRole = $state("");
  let fromTag = $state("");
  let toService = $state("");
  let toTag = $state("");

  onMount(load);
  async function load() {
    loading = true;
    error = "";
    try {
      const [p, m] = await Promise.all([getPolicy(), listMembers()]);
      version = p.version;
      chainIntact = p.chain_intact;
      blockHash = p.block_hash ?? null;
      rules = Array.isArray(p.rules) ? (p.rules as Rule[]) : [];
      isAdmin = m.your_role === "admin";
    } catch (e: unknown) {
      error = e instanceof Error ? e.message : "Failed to load policy";
    } finally {
      loading = false;
    }
  }

  function addRule() {
    const from: Sel = {};
    if (fromRole) from.role = fromRole;
    if (fromTag.trim()) from.tag = fromTag.trim();
    const to: Sel = {};
    if (toService.trim() && toService.trim() !== "*") to.service_name = toService.trim();
    if (toTag.trim()) to.resource_tag = toTag.trim();
    rules = [...rules, { from, to }];
    fromRole = fromTag = toService = toTag = "";
  }

  function removeRule(i: number) {
    rules = rules.filter((_, idx) => idx !== i);
  }

  async function publish() {
    error = "";
    saved = "";
    try {
      await submitPolicy(JSON.stringify({ rules }));
      saved = "Published ✓";
      await load();
    } catch (e: unknown) {
      // Surfaces the §B reason verbatim (e.g. "unknown field `display_name`").
      error = e instanceof Error ? e.message : "Publish failed";
    }
  }

  function side(s: Sel): string {
    const parts = Object.entries(s).map(([k, v]) => `${k}=${v}`);
    return parts.length ? parts.join(",") : "*";
  }
</script>

<main>
  <header>
    <h2>Access</h2>
    <span class="ver">v{version}</span>
  </header>

  <p class="desc">
    Who can reach what. <strong>Default-deny</strong> — only the Allow rules below grant
    access. Admins author; the policy is tamper-evident (hash-chain).
  </p>

  <div class="chain" class:bad={!chainIntact}>
    {#if version === 0}
      No policy yet — members can reach nothing until you add a rule.
    {:else}
      chain {chainIntact ? "intact ✓" : "BROKEN ✗"}
      {#if blockHash}<code>{blockHash.slice(0, 12)}…</code>{/if}
    {/if}
  </div>

  {#if error}<p class="err">{error}</p>{/if}
  {#if saved}<p class="ok">{saved}</p>{/if}

  {#if loading}
    <div class="empty">Loading…</div>
  {:else}
    <ul class="rules">
      {#each rules as r, i (i)}
        <li class="rule">
          <span class="from">{side(r.from)}</span>
          <span class="arrow">→</span>
          <span class="to">{side(r.to)}</span>
          {#if isAdmin}
            <button class="rm" onclick={() => removeRule(i)} aria-label="Remove rule">✕</button>
          {/if}
        </li>
      {/each}
      {#if rules.length === 0}
        <li class="rule muted">No rules — nothing is allowed (default-deny).</li>
      {/if}
    </ul>

    {#if isAdmin}
      <section class="builder">
        <h3>Add a rule</h3>
        <div class="cols">
          <div class="col">
            <span class="field-label">Who (principal)</span>
            <select bind:value={fromRole}>
              <option value="">any role</option>
              <option value="admin">role: admin</option>
              <option value="member">role: member</option>
            </select>
            <input bind:value={fromTag} placeholder="tag (optional, e.g. engineer)" />
          </div>
          <div class="col">
            <span class="field-label">What (service)</span>
            <input bind:value={toService} placeholder="service name, or * for any" />
            <input bind:value={toTag} placeholder="resource tag (optional)" />
          </div>
        </div>
        <button class="add" onclick={addRule}>+ Add rule</button>
      </section>

      <button class="publish" onclick={publish}>Publish policy v{version + 1}</button>
    {/if}
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
    gap: 8px;
  }
  header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 8px 0;
  }
  h2 {
    font-size: 22px;
    font-weight: 700;
  }
  .ver {
    color: var(--c-text-dim);
    font-family: "SF Mono", monospace;
    font-size: 13px;
  }
  .desc {
    font-size: 14px;
    color: var(--c-text-dim);
    line-height: 1.6;
  }
  .chain {
    font-size: 12px;
    color: var(--c-success);
    background: color-mix(in srgb, var(--c-success) 10%, transparent);
    border-radius: 8px;
    padding: 8px 12px;
  }
  .chain.bad {
    color: var(--c-danger);
    background: color-mix(in srgb, var(--c-danger) 12%, transparent);
  }
  .chain code {
    font-size: 11px;
    opacity: 0.8;
  }
  .err {
    color: var(--c-danger);
    font-size: 13px;
  }
  .ok {
    color: var(--c-success);
    font-size: 13px;
  }
  .empty {
    text-align: center;
    color: var(--c-text-dim);
    padding: 40px 0;
  }
  .rules {
    list-style: none;
    background: var(--c-surface);
    border: 1px solid var(--c-border);
    border-radius: 12px;
    overflow: hidden;
    margin: 8px 0;
  }
  .rule {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 12px 16px;
    border-bottom: 1px solid var(--c-border);
    font-family: "SF Mono", "Fira Code", monospace;
    font-size: 13px;
  }
  .rule:last-child {
    border-bottom: none;
  }
  .rule.muted {
    color: var(--c-text-dim);
    font-family: inherit;
  }
  .from {
    color: var(--c-accent);
  }
  .to {
    color: var(--c-success);
  }
  .arrow {
    opacity: 0.5;
  }
  .rm {
    margin-left: auto;
    color: var(--c-text-dim);
    padding: 2px 8px;
    border-radius: 6px;
  }
  .rm:hover {
    background: color-mix(in srgb, var(--c-danger) 14%, transparent);
    color: var(--c-danger);
  }
  .builder {
    background: var(--c-surface);
    border: 1px solid var(--c-border);
    border-radius: 12px;
    padding: 14px 16px;
    margin-top: 8px;
  }
  h3 {
    font-size: 15px;
    font-weight: 700;
    margin-bottom: 12px;
  }
  .cols {
    display: grid;
    grid-template-columns: 1fr;
    gap: 12px;
  }
  @media (min-width: 760px) {
    .cols {
      grid-template-columns: 1fr 1fr;
    }
  }
  .col {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }
  .field-label {
    font-size: 12px;
    color: var(--c-text-dim);
    font-weight: 600;
  }
  select,
  input {
    background: var(--c-bg);
    border: 1px solid var(--c-border);
    border-radius: 8px;
    padding: 9px 11px;
    color: var(--c-text);
    font-size: 13px;
  }
  .add {
    margin-top: 12px;
    color: var(--c-accent);
    font-weight: 600;
    font-size: 14px;
    padding: 8px 0;
  }
  .publish {
    margin-top: 12px;
    background: var(--c-accent);
    color: #fff;
    font-weight: 600;
    font-size: 14px;
    padding: 12px;
    border-radius: 10px;
  }
</style>
