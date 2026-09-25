<script lang="ts">
	// What an outside auditor is handed. Not a screen of rows — a file of the bytes the
	// control plane recorded, in order, that the receiver can verify without trusting us.
	// Contents and wording follow the evidence-schema design: the ledger holds references
	// and classifications, never payload (§8.7), the export projections are named up front
	// (§8.6), and reading the ledger is itself a ledger event (A.1.8).
	// [T:ankayma-painpoint-schema-evidence.md §8.5-§8.7 + part-d-tenant-dashboard.md §H.1]
	import { activeLang } from '$lib/stores';
	import { STRINGS, type Lang } from '$lib/i18n';
	import { exportLedger, exportRoi } from '$lib/tauri';
	import type { ExportResult } from '$lib/types';

	let lang = $state<Lang>('vn');
	activeLang.subscribe((l) => { lang = l; });

	let { onclose }: { onclose: () => void } = $props();

	let running = $state<'ledger' | 'roi' | null>(null);
	let result = $state<(ExportResult & { kind: 'ledger' | 'roi' }) | null>(null);
	let err = $state<string | null>(null);

	async function run(kind: 'ledger' | 'roi') {
		running = kind;
		err = null;
		result = null;
		try {
			const r = kind === 'ledger' ? await exportLedger() : await exportRoi();
			result = { ...r, kind };
		} catch (e) {
			err = String(e);
		} finally {
			running = null;
		}
	}

	function onKey(e: KeyboardEvent) {
		if (e.key === 'Escape') onclose();
	}
</script>

<svelte:window on:keydown={onKey} />

<div
	class="overlay"
	role="button"
	tabindex="-1"
	aria-label="Close"
	onclick={onclose}
	onkeydown={(e) => e.key === 'Enter' && onclose()}
>
	<div class="modal" role="dialog" aria-modal="true" tabindex="-1" onclick={(e) => e.stopPropagation()} onkeydown={() => {}}>
		<div class="head">
			<h3>{STRINGS[lang].export_title}</h3>
			<button class="close" onclick={onclose} aria-label="Close">✕</button>
		</div>
		<p class="intro">{STRINGS[lang].export_intro}</p>

		<section class="item">
			<div class="item-head">
				<h4>{STRINGS[lang].export_ledger_title}</h4>
				<button class="btn-primary" onclick={() => run('ledger')} disabled={running !== null}>
					{running === 'ledger' ? STRINGS[lang].export_running : STRINGS[lang].export_run}
				</button>
			</div>
			<p>{STRINGS[lang].export_ledger_desc}</p>
		</section>

		<section class="item">
			<div class="item-head">
				<h4>{STRINGS[lang].export_roi_title}</h4>
				<button class="btn-secondary" onclick={() => run('roi')} disabled={running !== null}>
					{running === 'roi' ? STRINGS[lang].export_running : STRINGS[lang].export_run}
				</button>
			</div>
			<p>{STRINGS[lang].export_roi_desc}</p>
		</section>

		{#if err}
			<p class="err">{err}</p>
		{:else if result}
			<p class="ok">
				{STRINGS[lang].export_done} <span class="mono">{result.path}</span>
				· {result.count}
				{#if !result.complete}
					<br /><span class="warn">{STRINGS[lang].export_partial}</span>
				{/if}
			</p>
		{/if}

		<section class="notes">
			<p>{STRINGS[lang].export_privacy}</p>
			<p>{STRINGS[lang].export_selfaudit}</p>
		</section>

		<section class="soon">
			<p class="soon-title">{STRINGS[lang].export_soon_title}</p>
			<p>{STRINGS[lang].export_soon_desc}</p>
		</section>
	</div>
</div>

<style>
	.overlay {
		position: fixed; inset: 0; z-index: 60; display: flex; align-items: center;
		justify-content: center; padding: 20px;
		background: color-mix(in srgb, #000 62%, transparent);
	}
	.modal {
		background: var(--c-surface); border: 1px solid var(--c-border); border-radius: var(--radius);
		padding: 20px 22px; width: min(620px, 100%); max-height: 84vh; overflow-y: auto;
		display: flex; flex-direction: column; gap: 14px; text-align: left; cursor: default;
	}
	.head { display: flex; align-items: center; gap: 12px; }
	.head h3 { font-size: 16px; font-weight: 700; flex: 1; }
	.close { color: var(--c-text-dim); font-size: 15px; padding: 2px 6px; border-radius: 6px; }
	.close:hover { color: var(--c-text); background: color-mix(in srgb, var(--c-accent) 10%, transparent); }
	.intro { font-size: 13px; color: var(--c-text-dim); }

	.item { border: 1px solid var(--c-border); border-radius: 10px; padding: 14px 16px;
		display: flex; flex-direction: column; gap: 8px; }
	.item-head { display: flex; align-items: center; gap: 12px; }
	.item-head h4 { font-size: 14px; font-weight: 600; flex: 1; }
	.item p { font-size: 12.5px; color: var(--c-text-dim); line-height: 1.55; }

	.ok { font-size: 12.5px; color: var(--c-success); overflow-wrap: anywhere; }
	.err { font-size: 12.5px; color: var(--c-danger); overflow-wrap: anywhere; }
	.warn { color: var(--c-warn); }
	.mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }

	.notes { display: flex; flex-direction: column; gap: 6px; padding-top: 4px;
		border-top: 1px solid var(--c-border); }
	.notes p { font-size: 11.5px; color: var(--c-text-dim); line-height: 1.55; }

	.soon { border: 1px dashed var(--c-border); border-radius: 10px; padding: 12px 14px;
		display: flex; flex-direction: column; gap: 6px; }
	.soon-title { font-size: 11px; font-weight: 700; letter-spacing: 0.04em; color: var(--c-warn); }
	.soon p { font-size: 12px; color: var(--c-text-dim); line-height: 1.55; }
</style>
