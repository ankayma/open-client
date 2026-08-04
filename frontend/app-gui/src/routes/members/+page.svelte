<script lang="ts">
  import { onMount } from "svelte";
  import {
    listMembers,
    inviteMember,
    removeMember,
    resetMemberTotp,
    listPendingInvites,
    revokeInvite,
  } from "$lib/tauri";
  import { auth } from "$lib/stores";
  import { runWithStepUp } from "$lib/stepup";
  import type { MembersView, PendingInvite } from "$lib/types";

  // F1 team membership (Slice C). Admin invites/removes; anyone sees the roster;
  // a removed member loses access on their next call (instant offboard).
  let data = $state<MembersView | null>(null);
  let loading = $state(true);
  let error = $state("");

  // Pending admissions — invited, not yet redeemed. The roster above reads memberships,
  // which only exist AFTER redeem, so an invited teammate used to be invisible: "I invited
  // them and they haven't opened it" was indistinguishable from "I never invited them".
  let pending = $state<PendingInvite[]>([]);

  let inviteUrl = $state("");
  let busy = $state(false);

  let isAdmin = $derived(data?.your_role === "admin");

  // Inviting members is a team feature — F0 (solo) must upgrade first. [A] §2.3.
  let tier = $derived($auth.status === "authenticated" ? $auth.user.tier : null);
  let canInvite = $derived(isAdmin && tier !== "F0");

  // Configurable member-invite TTL (server clamps to [1d, 30d]). [A] §TTL policy.
  const MEMBER_TTL_OPTIONS = [
    { label: "1 day", secs: 86400 },
    { label: "3 days", secs: 259200 },
    { label: "7 days", secs: 604800 },
    { label: "30 days", secs: 2592000 },
  ];
  let memberTtl = $state(604800);

  // Invite deep links are NOT consumed here any more. This page used to redeem a held
  // `join-team` token through the session-authed endpoint, which binds the invite to
  // whoever is logged in rather than to the address it was issued to. The layout now
  // redeems every such token through the magic-link path, so there is a single redeem
  // route for a single kind of token — and no way to join as the wrong identity.
  onMount(async () => {
    await load();
  });

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
    await loadPending();
  }

  // Admin-only endpoint: a plain member gets 403, which is not an error worth showing them
  // — the roster they CAN see loaded fine. Swallow it and leave the section absent.
  async function loadPending() {
    if (data?.your_role !== "admin") {
      pending = [];
      return;
    }
    try {
      pending = (await listPendingInvites()).invites;
    } catch {
      pending = [];
    }
  }

  // "Sent 3 days ago" beats a raw timestamp for the one question this list answers:
  // has it been long enough that they are probably not going to open it?
  function ago(iso?: string): string {
    if (!iso) return "";
    const then = Date.parse(iso);
    if (Number.isNaN(then)) return "";
    const mins = Math.max(0, Math.round((Date.now() - then) / 60000));
    if (mins < 1) return "just now";
    if (mins < 60) return `${mins}m ago`;
    const hours = Math.round(mins / 60);
    if (hours < 24) return `${hours}h ago`;
    return `${Math.round(hours / 24)}d ago`;
  }

  // Time LEFT on the invite — the other half of the same question.
  function expiresIn(iso?: string): string {
    if (!iso) return "";
    const at = Date.parse(iso);
    if (Number.isNaN(at)) return "";
    const mins = Math.round((at - Date.now()) / 60000);
    if (mins <= 0) return "expired";
    if (mins < 60) return `expires in ${mins}m`;
    const hours = Math.round(mins / 60);
    if (hours < 48) return `expires in ${hours}h`;
    return `expires in ${Math.round(hours / 24)}d`;
  }

  let inviteEmail = $state("");
  // Commercial SeatType for the invitee (quota dimension). Node/domain caps per seat:
  const SEAT_TYPES = [
    { value: "user", label: "User", caps: "10 nodes · 2 domains" },
    { value: "builder", label: "Builder", caps: "30 nodes · 10 domains" },
    { value: "admin", label: "Admin", caps: "50 nodes · 20 domains" },
    { value: "lite", label: "Lite", caps: "1 node · 0 domains" },
  ];
  let inviteSeatType = $state("user");
  async function invite() {
    if (!inviteEmail.trim()) return;
    busy = true;
    error = "";
    try {
      // Admin action (M-1) — a multi-user tenant gates this behind a step-up;
      // runWithStepUp drives the modal transparently. [T:Part D H.2#6]
      inviteUrl = await runWithStepUp("invite_member", (proof) =>
        inviteMember(inviteEmail.trim(), inviteSeatType, memberTtl, proof),
      );
      await loadPending();
    } catch (e: unknown) {
      error = e instanceof Error ? e.message : "Invite failed";
    } finally {
      busy = false;
    }
  }

  // Re-send. Same endpoint as the first invite and deliberately so: the server keeps the
  // EXISTING token, refreshes its expiry and mails the same link again — so a link already
  // sitting in the invitee's inbox stays valid instead of being silently replaced by a
  // second one. The seat/role travel with it, which is also how a mis-set seat gets fixed.
  // Server enforces a per-address cooldown; the button reflects it rather than guessing.
  let resending = $state("");
  async function resend(inv: PendingInvite) {
    resending = inv.email;
    error = "";
    try {
      await runWithStepUp("invite_member", (proof) =>
        inviteMember(inv.email, inv.seat_type ?? "user", memberTtl, proof),
      );
      await loadPending();
    } catch (e: unknown) {
      if (e instanceof Error && e.message === "Step-up cancelled") return;
      error = e instanceof Error ? e.message : "Re-send failed";
    } finally {
      resending = "";
    }
  }

  async function revoke(email: string) {
    if (!confirm(`Revoke the invite for ${email}? Their link stops working immediately.`)) return;
    try {
      await revokeInvite(email);
      await loadPending();
    } catch (e: unknown) {
      error = e instanceof Error ? e.message : "Revoke failed";
    }
  }

  async function remove(userId: string) {
    try {
      // Admin action (M-4) — same step-up gate as invite. [T:Part D H.2#7]
      await runWithStepUp("remove_member", (proof) => removeMember(userId, proof));
      await load();
    } catch (e: unknown) {
      error = e instanceof Error ? e.message : "Remove failed";
    }
  }

  // Admin-mediated factor recovery (H.9): a member who lost their authenticator
  // and can't self-recover asks out-of-band; the admin resets it here so they can
  // re-enroll. Gated by the admin's OWN step-up. [T:Part D §H.9]
  async function resetTotp(userId: string, login: string) {
    if (!confirm(`Reset ${login}'s authenticator? They'll sign in with an emailed code and set up a new one.`))
      return;
    try {
      await runWithStepUp("manage_member_factor", (proof) => resetMemberTotp(userId, proof));
      error = "";
    } catch (e: unknown) {
      if (e instanceof Error && e.message === "Step-up cancelled") return;
      error = e instanceof Error ? e.message : "Reset failed";
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
            {#if m.seat_type}<span class="role" style="text-transform:capitalize;">{m.seat_type}</span>{/if}
            {#if m.is_owner}<span class="owner">owner</span>{/if}
            {#if m.used && m.seat_caps}
              <span style="color:var(--c-text-dim);font-size:11px;flex-basis:100%;margin-top:2px;">nodes {m.used.nodes}/{m.seat_caps.nodes} · domains {m.used.privdomains}/{m.seat_caps.privdomains}</span>
            {/if}
          </div>
          {#if isAdmin && !m.is_owner}
            <div class="actions">
              <button
                class="reset"
                onclick={() => resetTotp(m.user_id, m.github_login)}
                aria-label="Reset member authenticator">Reset 2FA</button
              >
              <button class="remove" onclick={() => remove(m.user_id)} aria-label="Remove member"
                >Remove</button
              >
            </div>
          {/if}
        </li>
      {/each}
    </ul>

    {#if isAdmin && pending.length > 0}
      <section class="pending">
        <h3>Pending invites <span class="count">{pending.length}</span></h3>
        <p class="hint">
          Invited, not joined yet. Re-send mails the same link again and refreshes its expiry.
        </p>
        <ul class="list">
          {#each pending as p (p.email)}
            <li class="row">
              <div class="who">
                <span class="login">{p.email}</span>
                {#if p.seat_type}<span class="role" style="text-transform:capitalize;">{p.seat_type}</span>{/if}
                {#if p.expired}<span class="role expired">expired</span>{/if}
                <span style="color:var(--c-text-dim);font-size:11px;flex-basis:100%;margin-top:2px;">
                  sent {ago(p.last_sent_at ?? p.created_at)}{#if p.send_count > 1} · {p.send_count} times{/if}
                  {#if !p.expired && p.expires_at} · {expiresIn(p.expires_at)}{/if}
                </span>
              </div>
              <div class="actions">
                <button
                  class="reset"
                  onclick={() => resend(p)}
                  disabled={resending === p.email}
                  aria-label="Re-send invite">{resending === p.email ? "Sending…" : "Resend"}</button
                >
                <button class="remove" onclick={() => revoke(p.email)} aria-label="Revoke invite"
                  >Revoke</button
                >
              </div>
            </li>
          {/each}
        </ul>
      </section>
    {/if}

    {#if isAdmin && tier === "F0"}
      <section class="panel upgrade-notice">
        <h3>Invite teammates</h3>
        <p class="hint">Team membership is a paid feature. Upgrade to invite members.</p>
        <a class="btn" href="https://ankayma.com/pricing" target="_blank" rel="noopener">Upgrade plan</a>
      </section>
    {:else if canInvite}
      <section class="panel">
        <h3>Invite a member</h3>
        <p class="hint">Enter their email — we send a join link there. They confirm with a code (no GitHub needed).</p>
        <input
          class="email-input"
          type="email"
          bind:value={inviteEmail}
          placeholder="teammate@email.com"
          autocapitalize="none"
          autocorrect="off"
          spellcheck="false"
        />
        <div class="ttl-row">
          <label for="seat-type">Seat type</label>
          <select id="seat-type" bind:value={inviteSeatType}>
            {#each SEAT_TYPES as st (st.value)}
              <option value={st.value}>{st.label} — {st.caps}</option>
            {/each}
          </select>
        </div>
        <div class="ttl-row">
          <label for="member-ttl">Invite expires in</label>
          <select id="member-ttl" bind:value={memberTtl}>
            {#each MEMBER_TTL_OPTIONS as o (o.secs)}
              <option value={o.secs}>{o.label}</option>
            {/each}
          </select>
        </div>
        <button class="btn" onclick={invite} disabled={busy || !inviteEmail.trim()}>Send invite</button>
        {#if inviteUrl}
          <p class="hint" style="margin-top:10px">Invite sent to <strong>{inviteEmail}</strong>. You can also share the link:</p>
          <div class="invite">
            <code>{inviteUrl}</code>
            <button class="copy" onclick={() => copy(inviteUrl)}>Copy</button>
          </div>
        {/if}
      </section>
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
  /* Mobile-first: stack so a long login never squeezes the action button off the
     row — the button drops to its own line, last. Desktop restores the inline row
     (see @media below). */
  .row {
    display: flex;
    flex-direction: column;
    align-items: stretch;
    gap: 10px;
    padding: 12px 16px;
    border-bottom: 1px solid var(--c-border);
  }
  .row:last-child {
    border-bottom: none;
  }
  .who {
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: 8px;
    min-width: 0;
  }
  .remove {
    align-self: flex-end;
  }
  @media (min-width: 760px) {
    .row {
      flex-direction: row;
      align-items: center;
      justify-content: space-between;
    }
    .remove {
      align-self: auto;
    }
  }
  .login {
    font-weight: 600;
    word-break: break-word;
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
    background: color-mix(in srgb, var(--sec-info) 14%, transparent);
    color: var(--sec-info);
    border: 1px solid color-mix(in srgb, var(--sec-info) 35%, transparent);
  }
  .owner {
    font-size: 11px;
    color: var(--c-text-dim);
  }
  .remove {
    font-size: 13px;
    padding: 5px 10px;
    border-radius: 6px;
    background: var(--btn-danger-bg);
    color: var(--btn-danger-text);
    border: 1px solid var(--btn-danger-border);
    transition: background 0.12s;
  }
  .remove:hover {
    background: color-mix(in srgb, var(--c-danger) 22%, var(--c-surface));
  }
  .actions {
    display: flex;
    gap: 8px;
    align-items: center;
  }
  .reset {
    font-size: 13px;
    padding: 5px 10px;
    border-radius: 6px;
    background: transparent;
    color: var(--c-text-dim);
    border: 1px solid var(--c-border);
    transition: background 0.12s;
  }
  .reset:hover {
    background: var(--c-surface);
    color: var(--c-text);
  }
  .pending {
    margin-top: 8px;
  }
  .pending h3 {
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .pending .hint {
    margin-bottom: 0;
  }
  /* Dimmer than the roster: these people are not in the team yet. */
  .pending .list {
    background: transparent;
    border-style: dashed;
  }
  .role.expired {
    background: color-mix(in srgb, var(--c-danger) 14%, transparent);
    color: var(--c-danger);
    border: 1px solid color-mix(in srgb, var(--c-danger) 35%, transparent);
  }
  .reset:disabled {
    opacity: 0.5;
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
    display: inline-block;
    background: var(--c-accent);
    color: #fff;
    font-weight: 600;
    font-size: 14px;
    padding: 10px 16px;
    border-radius: 9px;
    text-align: center;
  }
  .btn:hover { text-decoration: none; }
  .btn:disabled {
    opacity: 0.5;
  }
  .upgrade-notice .btn { background: var(--sec-info, var(--c-accent)); }
  .ttl-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    margin-bottom: 12px;
    font-size: 13px;
    color: var(--c-text-dim);
  }
  .ttl-row select {
    background: var(--c-bg);
    border: 1px solid var(--c-border);
    border-radius: 8px;
    padding: 7px 10px;
    color: var(--c-text);
    font-size: 13px;
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
  .email-input {
    width: 100%;
    background: var(--c-bg);
    border: 1px solid var(--c-border);
    border-radius: 8px;
    padding: 10px 12px;
    color: var(--c-text);
    font-size: 14px;
    margin-bottom: 10px;
  }
</style>
