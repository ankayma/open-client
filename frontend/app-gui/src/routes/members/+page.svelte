<script lang="ts">
  import { onMount } from "svelte";
  import { listMembers, inviteMember, joinTeam, removeMember } from "$lib/tauri";
  import type { MembersView } from "$lib/types";

  // F1 team membership (Slice C). Admin invites/removes; anyone sees the roster;
  // a removed member loses access on their next call (instant offboard).
  let data = $state<MembersView | null>(null);
  let loading = $state(true);
  let error = $state("");

  let inviteUrl = $state("");
  let joinInput = $state("");
  let busy = $state(false);

  let isAdmin = $derived(data?.your_role === "admin");

  onMount(load);
  async function load() {
    loading = true;
    error = "";
    try {
      data = await listMembers();
    } catch (e: unknown) {
      error = e instanceof Error ? e.message : "Failed to load members";
    } finally {
      loading = false;
    }
  }

  async function invite() {
    busy = true;
    error = "";
    try {
      inviteUrl = await inviteMember();
    } catch (e: unknown) {
      error = e instanceof Error ? e.message : "Invite failed";
    } finally {
      busy = false;
    }
  }

  async function join() {
    if (!joinInput.trim()) return;
    busy = true;
    error = "";
    try {
      // Accept a full ankayma://join-team?token=… link or a bare token.
      const m = joinInput.match(/token=([^&\s]+)/);
      await joinTeam(m ? m[1] : joinInput.trim());
      joinInput = "";
      await load();
    } catch (e: unknown) {
      error = e instanceof Error ? e.message : "Join failed";
    } finally {
      busy = false;
    }
  }

  async function remove(userId: string) {
    try {
      await removeMember(userId);
      await load();
    } catch (e: unknown) {
      error = e instanceof Error ? e.message : "Remove failed";
    }
  }

  function copy(text: string) {
    navigator.clipboard?.writeText(text);
  }
</script>

<main>
  <header>
    <h2>Members</h2>
    {#if data}<span class="count">{data.members.length}/{data.limit}</span>{/if}
  </header>

  <p class="desc">
    Everyone in this team and their role. Admins manage access in <strong>Access</strong>.
  </p>

  {#if error}<p class="err">{error}</p>{/if}

  {#if loading}
    <div class="empty">Loading…</div>
  {:else if data}
    <ul class="list">
      {#each data.members as m (m.user_id)}
        <li class="row">
          <div class="who">
            <span class="login">{m.github_login}</span>
            <span class="role" class:admin={m.role === "admin"}>{m.role}</span>
            {#if m.is_owner}<span class="owner">owner</span>{/if}
          </div>
          {#if isAdmin && !m.is_owner}
            <button class="remove" onclick={() => remove(m.user_id)} aria-label="Remove member"
              >Remove</button
            >
          {/if}
        </li>
      {/each}
    </ul>

    {#if isAdmin}
      <section class="panel">
        <h3>Invite a member</h3>
        <p class="hint">Mint a link; the teammate signs in and pastes it to join.</p>
        <button class="btn" onclick={invite} disabled={busy}>Create invite link</button>
        {#if inviteUrl}
          <div class="invite">
            <code>{inviteUrl}</code>
            <button class="copy" onclick={() => copy(inviteUrl)}>Copy</button>
          </div>
        {/if}
      </section>
    {/if}

    <section class="panel">
      <h3>Join a team</h3>
      <p class="hint">Paste an invite link from an admin.</p>
      <div class="join-row">
        <input
          bind:value={joinInput}
          placeholder="ankayma://join-team?token=…"
          autocapitalize="none"
          autocorrect="off"
          spellcheck="false"
        />
        <button class="btn" onclick={join} disabled={busy || !joinInput.trim()}>Join</button>
      </div>
    </section>
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
  .count {
    color: var(--c-text-dim);
    font-size: 13px;
    font-family: "SF Mono", monospace;
  }
  .desc {
    font-size: 14px;
    color: var(--c-text-dim);
    line-height: 1.6;
  }
  .err {
    color: var(--c-danger);
    font-size: 13px;
  }
  .empty {
    text-align: center;
    color: var(--c-text-dim);
    padding: 40px 0;
  }
  .list {
    list-style: none;
    background: var(--c-surface);
    border: 1px solid var(--c-border);
    border-radius: 12px;
    overflow: hidden;
    margin: 8px 0;
  }
  .row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 12px 16px;
    border-bottom: 1px solid var(--c-border);
  }
  .row:last-child {
    border-bottom: none;
  }
  .who {
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .login {
    font-weight: 600;
  }
  .role {
    font-size: 11px;
    font-weight: 700;
    padding: 1px 7px;
    border-radius: 5px;
    background: var(--c-border);
    color: var(--c-text-dim);
  }
  .role.admin {
    background: color-mix(in srgb, var(--c-accent) 18%, transparent);
    color: var(--c-accent);
  }
  .owner {
    font-size: 11px;
    color: var(--c-text-dim);
  }
  .remove {
    font-size: 13px;
    color: var(--c-text-dim);
    padding: 5px 10px;
    border-radius: 6px;
  }
  .remove:hover {
    background: color-mix(in srgb, var(--c-danger) 14%, transparent);
    color: var(--c-danger);
  }
  .panel {
    background: var(--c-surface);
    border: 1px solid var(--c-border);
    border-radius: 12px;
    padding: 14px 16px;
    margin-top: 8px;
  }
  h3 {
    font-size: 15px;
    font-weight: 700;
    margin-bottom: 4px;
  }
  .hint {
    font-size: 13px;
    color: var(--c-text-dim);
    margin-bottom: 12px;
  }
  .btn {
    background: var(--c-accent);
    color: #fff;
    font-weight: 600;
    font-size: 14px;
    padding: 10px 16px;
    border-radius: 9px;
  }
  .btn:disabled {
    opacity: 0.5;
  }
  .invite {
    display: flex;
    align-items: center;
    gap: 8px;
    margin-top: 12px;
  }
  .invite code {
    flex: 1;
    background: var(--c-bg);
    border: 1px solid var(--c-border);
    border-radius: 8px;
    padding: 8px 10px;
    font-size: 12px;
    color: var(--c-accent);
    word-break: break-all;
  }
  .copy {
    color: var(--c-text-dim);
    font-size: 13px;
    padding: 6px 10px;
  }
  .join-row {
    display: flex;
    gap: 8px;
  }
  .join-row input {
    flex: 1;
    background: var(--c-bg);
    border: 1px solid var(--c-border);
    border-radius: 8px;
    padding: 10px 12px;
    color: var(--c-text);
    font-size: 13px;
  }
</style>
