<script lang="ts">
	// One table for both overview scopes — the tenant ledger (admin) and a user's own
	// rows. The MEMBER column is dropped when every row is the same person: repeating
	// your own address twenty times is noise, not evidence.
	// A row is a summary, so it is also a door: the ledger event carries more than four
	// columns can hold (the raw type, the grant it ran under, the whole payload), and
	// that detail is the difference between "something happened" and evidence you can
	// act on. [T:part-d-tenant-dashboard.md §H.1 panel 2]
	import type { OverviewActivity } from '$lib/types';
	import { action, target, actorOf, clockTime, short } from '$lib/overview-format';
	import { activeLang } from '$lib/stores';
	import { STRINGS, type Lang } from '$lib/i18n';

	let lang = $state<Lang>('vn');
	activeLang.subscribe((l) => { lang = l; });

	let { activity, showMember = true }: { activity: OverviewActivity[]; showMember?: boolean } =
		$props();

	let selected = $state<OverviewActivity | null>(null);

	function fullTime(iso: string): string {
		const d = new Date(iso);
		if (isNaN(d.getTime())) return iso;
		const p = (n: number) => String(n).padStart(2, '0');
		return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
	}

	// Payload as rows. The control plane shapes it per event type, so nothing is
	// hard-coded: whatever the event carried is what the detail shows.
	function payloadRows(a: OverviewActivity): [string, string][] {
		const p = a.payload as Record<string, unknown> | null;
		if (!p || typeof p !== 'object') return [];
		return Object.entries(p).map(([k, v]) => [
			k,
			typeof v === 'string' ? v : JSON.stringify(v)
		]);
	}

	function onKey(e: KeyboardEvent) {
		if (e.key === 'Escape') selected = null;
	}
</script>

<svelte:window on:keydown={onKey} />

{#if activity.length === 0}
	<p class="empty">No recent events.</p>
{:else}
	<div class="act-head" class:no-who={!showMember}>
		<span>TIME</span>{#if showMember}<span>MEMBER</span>{/if}<span>ACTION</span><span>TARGET</span>
	</div>
	<div class="act-rows">
		{#each activity as a (a.id)}
			{@const act = action(a.event_type)}
			<button class="act-row" class:no-who={!showMember} onclick={() => (selected = a)}>
				<span class="t">{clockTime(a.created_at)}</span>
				{#if showMember}<span class="who" title={actorOf(a)}>{short(actorOf(a), 24)}</span>{/if}
				<span class="act act-{act.kind}">{act.label}</span>
				<span class="tgt" title={target(a)}>{target(a) || '—'}</span>
			</button>
		{/each}
	</div>
{/if}

{#if selected}
	{@const act = action(selected.event_type)}
	<div
		class="overlay"
		role="button"
		tabindex="-1"
		aria-label="Close"
		onclick={() => (selected = null)}
		onkeydown={(e) => e.key === 'Enter' && (selected = null)}
	>
		<div class="modal" role="dialog" aria-modal="true" tabindex="-1" onclick={(e) => e.stopPropagation()} onkeydown={() => {}}>
			<div class="modal-head">
				<div>
					<h3>{act.label}</h3>
					<p class="raw">{selected.event_type}</p>
				</div>
				<button class="close" onclick={() => (selected = null)} aria-label="Close">✕</button>
			</div>

			<dl class="kv">
				<dt>{STRINGS[lang].detail_when}</dt>
				<dd>{fullTime(selected.created_at)}</dd>
				<dt>{STRINGS[lang].detail_who}</dt>
				<dd>{actorOf(selected)}</dd>
				<dt>{STRINGS[lang].detail_what}</dt>
				<dd>{target(selected) || '—'}</dd>
				{#if selected.grant_id}
					<dt>{STRINGS[lang].detail_grant}</dt>
					<dd class="mono">{selected.grant_id}</dd>
				{/if}
				<dt>{STRINGS[lang].detail_event_id}</dt>
				<dd class="mono">#{selected.id}</dd>
			</dl>

			{#if payloadRows(selected).length > 0}
				<p class="section-label">{STRINGS[lang].detail_payload}</p>
				<dl class="kv payload">
					{#each payloadRows(selected) as [k, v]}
						<dt class="mono">{k}</dt>
						<dd class="mono">{v}</dd>
					{/each}
				</dl>
			{/if}

			<p class="foot">{STRINGS[lang].detail_ledger_note}</p>
		</div>
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
	.act-row { font-size: 13px; padding: 8px; border-radius: 8px; text-align: left; width: 100%; }
	.act-row:nth-child(odd) { background: color-mix(in srgb, var(--c-bg) 45%, transparent); }
	.act-row:hover { background: color-mix(in srgb, var(--c-accent) 10%, transparent); }
	.act-row .t { color: var(--c-text-dim); font-size: 12px; }
	.act-row .who, .act-row .tgt { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
	.act-row .tgt { color: var(--c-text-dim); }
	.act { font-size: 12px; font-weight: 600; }
	.act-ssh, .act-node { color: var(--c-text); }
	.act-elevate { color: var(--c-warn); }
	.act-cicd { color: var(--c-accent); }
	.act-open, .act-service, .act-member { color: var(--c-text); }
	.act-other { color: var(--c-text-dim); }

	.overlay {
		position: fixed; inset: 0; z-index: 50; display: flex; align-items: center;
		justify-content: center; padding: 20px;
		background: color-mix(in srgb, #000 62%, transparent);
	}
	.modal {
		background: var(--c-surface); border: 1px solid var(--c-border); border-radius: var(--radius);
		padding: 18px 20px; width: min(560px, 100%); max-height: 80vh; overflow-y: auto;
		display: flex; flex-direction: column; gap: 14px; text-align: left; cursor: default;
	}
	.modal-head { display: flex; align-items: flex-start; gap: 12px; }
	.modal-head h3 { font-size: 16px; font-weight: 700; }
	.modal-head div { flex: 1; min-width: 0; }
	.raw { font-size: 12px; color: var(--c-text-dim); margin-top: 2px; }
	.close { color: var(--c-text-dim); font-size: 15px; padding: 2px 6px; border-radius: 6px; }
	.close:hover { color: var(--c-text); background: color-mix(in srgb, var(--c-accent) 10%, transparent); }

	.kv { display: grid; grid-template-columns: 116px minmax(0, 1fr); gap: 6px 12px; font-size: 13px; }
	.kv dt { color: var(--c-text-dim); }
	.kv dd { overflow-wrap: anywhere; }
	.payload { padding-top: 2px; border-top: 1px solid var(--c-border); }
	.mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; }
	.section-label { font-size: 11.5px; font-weight: 600; color: var(--c-text-dim); letter-spacing: 0.03em; }
	.foot { font-size: 11.5px; color: var(--c-text-dim); }

	@media (min-width: 860px) {
		.act-head, .act-row { grid-template-columns: 76px minmax(0, 1fr) 96px minmax(0, 1.6fr); }
		.act-head.no-who, .act-row.no-who { grid-template-columns: 76px 110px minmax(0, 1fr); }
		.act-rows { max-height: 520px; }
	}
</style>
