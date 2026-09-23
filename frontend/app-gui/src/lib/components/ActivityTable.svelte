<script lang="ts">
	// One table for both overview scopes — the tenant ledger (admin) and a user's own
	// rows. The MEMBER column is dropped when every row is the same person: repeating
	// your own address twenty times is noise, not evidence. [T:part-d-tenant-dashboard §H.1 panel 2]
	import type { OverviewActivity } from '$lib/types';
	import { action, target, actorOf, clockTime, short } from '$lib/overview-format';

	let { activity, showMember = true }: { activity: OverviewActivity[]; showMember?: boolean } =
		$props();
</script>

{#if activity.length === 0}
	<p class="empty">No recent events.</p>
{:else}
	<div class="act-head" class:no-who={!showMember}>
		<span>TIME</span>{#if showMember}<span>MEMBER</span>{/if}<span>ACTION</span><span>TARGET</span>
	</div>
	<div class="act-rows">
		{#each activity as a (a.id)}
			{@const act = action(a.event_type)}
			<div class="act-row" class:no-who={!showMember}>
				<span class="t">{clockTime(a.created_at)}</span>
				{#if showMember}<span class="who" title={actorOf(a)}>{short(actorOf(a), 20)}</span>{/if}
				<span class="act act-{act.kind}">{act.label}</span>
				<span class="tgt" title={target(a)}>{target(a) || '—'}</span>
			</div>
		{/each}
	</div>
{/if}

<style>
	.empty { font-size: 13px; color: var(--c-text-dim); }

	.act-head, .act-row {
		display: grid;
		grid-template-columns: 52px minmax(0, 1fr) 74px minmax(0, 1.1fr);
		gap: 8px;
		align-items: center;
	}
	.act-head.no-who, .act-row.no-who {
		grid-template-columns: 52px 84px minmax(0, 1fr);
	}
	.act-head { font-size: 11px; font-weight: 600; color: var(--c-text-dim); letter-spacing: 0.03em; padding: 0 8px; }
	/* Twenty rows is taller than most windows; let the list scroll inside the card so
	   the page stays one screen and nothing below it gets pushed out of sight. */
	.act-rows { display: flex; flex-direction: column; gap: 2px; max-height: 420px; overflow-y: auto; }
	.act-row { font-size: 13px; padding: 8px; border-radius: 8px; }
	.act-row:nth-child(odd) { background: color-mix(in srgb, var(--c-bg) 45%, transparent); }
	.act-row .t { color: var(--c-text-dim); font-size: 12px; }
	.act-row .who, .act-row .tgt { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
	.act-row .tgt { color: var(--c-text-dim); }
	.act { font-size: 12px; font-weight: 600; }
	.act-ssh, .act-node { color: var(--c-text); }
	.act-elevate { color: var(--c-warn); }
	.act-cicd { color: var(--c-accent); }
	.act-open, .act-service, .act-member { color: var(--c-text); }
	.act-other { color: var(--c-text-dim); }

	@media (min-width: 860px) {
		.act-head, .act-row { grid-template-columns: 60px minmax(0, 1fr) 84px minmax(0, 1.2fr); }
		.act-head.no-who, .act-row.no-who { grid-template-columns: 60px 96px minmax(0, 1fr); }
	}
</style>
