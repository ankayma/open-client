<script lang="ts">
	// Live grants with their TTL draining — the same panel on the tenant view and on a
	// user's own. The clock ticks here so neither page has to own a timer.
	// [T:part-d-tenant-dashboard §H.1 panel 3]
	import { onMount } from 'svelte';
	import type { OverviewGrant, OverviewDelegation } from '$lib/types';
	import { remaining, ttlPct, short } from '$lib/overview-format';

	let {
		grants,
		delegations,
		empty = 'No live grants.'
	}: { grants: OverviewGrant[]; delegations: OverviewDelegation[]; empty?: string } = $props();

	let now = $state(Date.now());
	onMount(() => {
		const t = setInterval(() => (now = Date.now()), 1000);
		return () => clearInterval(t);
	});
</script>

{#if grants.length === 0 && delegations.length === 0}
	<p class="empty">{empty}</p>
{:else}
	{#each grants as g (g.grant_id)}
		<div class="grant">
			<div class="grant-line">
				<span class="grant-what">
					{g.kind === 'command' ? 'Command' : 'Session'} ·
					{short(g.actor_id, 16)}{g.node_id ? ' → ' + short(g.node_id, 12) : ''}
				</span>
				<span class="grant-ttl">{remaining(g.expires_at, now)}</span>
			</div>
			<div class="bar"><div class="bar-fill" style="width:{ttlPct(g, now)}%"></div></div>
		</div>
	{/each}
	{#each delegations as d (d.window_id)}
		<div class="grant">
			<div class="grant-line">
				<span class="grant-what">Delegated · {short(d.agent_actor_id, 16)} <span class="ai">AI</span></span>
				<span class="grant-ttl">{remaining(d.expires_at, now)}</span>
			</div>
			<div class="bar"><div class="bar-fill warn" style="width:{ttlPct(d, now)}%"></div></div>
		</div>
	{/each}
{/if}

<style>
	.empty { font-size: 13px; color: var(--c-text-dim); }
	.grant { display: flex; flex-direction: column; gap: 6px; }
	.grant-line { display: flex; align-items: center; gap: 8px; font-size: 13px; }
	/* min-width:0 — without it a flex child's automatic minimum is its CONTENT width,
	   so a long actor id pushes the whole card wider than a phone screen and the page
	   scrolls sideways; ellipsis never gets a chance to apply. */
	.grant-what { flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
	.grant-ttl { font-size: 12px; color: var(--c-text-dim); flex-shrink: 0; }
	.ai { font-size: 10px; font-weight: 700; padding: 1px 6px; border-radius: 999px;
		background: color-mix(in srgb, var(--c-warn) 14%, transparent);
		border: 1px solid color-mix(in srgb, var(--c-warn) 40%, transparent); color: var(--c-warn); }
	.bar { height: 4px; border-radius: 999px; background: color-mix(in srgb, var(--c-bg) 50%, var(--c-border)); overflow: hidden; }
	.bar-fill { height: 4px; border-radius: 999px; background: var(--c-accent); }
	.bar-fill.warn { background: var(--c-warn); }
</style>
