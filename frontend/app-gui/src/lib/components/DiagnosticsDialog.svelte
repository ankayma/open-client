<script lang="ts">
	// User-triggered diagnostics — the "Send diagnostics" review dialog. It builds the
	// bundle (connection-level operational metadata: daemon log tails + status snapshot
	// + version/OS/connection state — NEVER keys/tokens/payload, [T:A.1.1]), shows it
	// for the user to REVIEW, and uploads it only on the explicit Send tap. No
	// background stream — the vendor stays off the data path (P.3 honest). On success
	// it surfaces a report id the user quotes to support.
	import { onMount } from 'svelte';
	import { activeLang } from '$lib/stores';
	import { STRINGS, type Lang } from '$lib/i18n';
	import { diagnosticsBuild, diagnosticsSend, type DiagnosticBundle } from '$lib/tauri';

	interface Props {
		// Seeds the report category (the Tunnel-down card sends 'daemon-crash').
		category?: string;
		onclose: () => void;
	}
	let { category, onclose }: Props = $props();

	let lang = $state<Lang>('vn');
	activeLang.subscribe((l) => (lang = l));
	const t = $derived(STRINGS[lang]);

	let bundle = $state<DiagnosticBundle | null>(null);
	let building = $state(true);
	let sending = $state(false);
	let reportId = $state<string | null>(null);
	let error = $state<string | null>(null);

	onMount(async () => {
		try {
			bundle = await diagnosticsBuild(category);
		} catch (e) {
			error = e instanceof Error ? e.message : String(e);
		} finally {
			building = false;
		}
	});

	async function send() {
		sending = true;
		error = null;
		try {
			reportId = await diagnosticsSend();
		} catch (e) {
			error = e instanceof Error ? e.message : String(e);
		} finally {
			sending = false;
		}
	}

	// The two log tails joined for the scrollable preview — exactly the bytes that ship.
	const logPreview = $derived(
		bundle ? [bundle.agent_log_tail, bundle.helper_log_tail].filter(Boolean).join('\n') : ''
	);
</script>

<div class="overlay" role="presentation" onclick={onclose} onkeydown={(e) => e.key === 'Escape' && onclose()}>
	<div class="panel" role="dialog" aria-modal="true" tabindex="-1" onclick={(e) => e.stopPropagation()} onkeydown={(e) => e.stopPropagation()}>
		<div class="head">
			<span class="title">🩺 {t.diag_title}</span>
			<button class="x" onclick={onclose} aria-label="Close">✕</button>
		</div>

		{#if reportId}
			<p class="sent">{t.diag_sent} <code>{reportId}</code></p>
			<p class="hint">{t.diag_sent_hint}</p>
			<div class="actions"><button class="btn primary" onclick={onclose}>OK</button></div>
		{:else}
			<p class="intro">{t.diag_intro}</p>

			{#if building}
				<p class="dim">{t.diag_building}</p>
			{:else if bundle}
				<dl class="meta">
					<div><dt>report</dt><dd class="mono">{bundle.report_id}</dd></div>
					<div><dt>category</dt><dd>{bundle.category}{#if bundle.code} · {bundle.code}{/if}</dd></div>
					<div><dt>state</dt><dd>{bundle.connection_state}</dd></div>
					<div><dt>version</dt><dd class="mono">{bundle.app_version} · {bundle.platform}</dd></div>
				</dl>
				{#if logPreview}
					<pre class="logs">{logPreview}</pre>
				{/if}
			{/if}

			{#if error}<p class="err">{t.diag_error} {error}</p>{/if}

			<div class="actions">
				<button class="btn" onclick={onclose} disabled={sending}>{t.diag_cancel}</button>
				<button class="btn primary" onclick={send} disabled={building || sending || !bundle}>
					{sending ? t.diag_sending : t.diag_send_btn}
				</button>
			</div>
		{/if}
	</div>
</div>

<style>
	.overlay {
		position: fixed;
		inset: 0;
		background: rgba(0, 0, 0, 0.6);
		display: flex;
		align-items: flex-end;
		justify-content: center;
		z-index: 200;
	}
	.panel {
		background: var(--c-surface);
		border: 1px solid var(--c-border);
		border-radius: var(--radius) var(--radius) 0 0;
		padding: 20px;
		width: 100%;
		max-width: 480px;
	}
	.head {
		display: flex;
		align-items: center;
		justify-content: space-between;
		margin-bottom: 12px;
	}
	.title {
		font-size: 15px;
		font-weight: 700;
		color: var(--c-accent);
	}
	.x {
		color: var(--c-text-dim);
		font-size: 16px;
		padding: 4px 8px;
	}
	.intro {
		font-size: 13px;
		color: var(--c-text-dim);
		line-height: 1.5;
		margin: 0 0 14px;
	}
	.meta {
		display: flex;
		flex-direction: column;
		gap: 6px;
		margin: 0 0 12px;
	}
	.meta > div {
		display: flex;
		justify-content: space-between;
		font-size: 13px;
	}
	.meta dt {
		color: var(--c-text-dim);
		margin: 0;
	}
	.meta dd {
		margin: 0;
		color: var(--c-text);
	}
	.mono {
		font-family: 'SF Mono', 'Fira Code', monospace;
		font-size: 12px;
	}
	.logs {
		max-height: 180px;
		overflow: auto;
		background: var(--c-bg);
		border: 1px solid var(--c-border);
		border-radius: 8px;
		padding: 10px;
		font-family: 'SF Mono', 'Fira Code', monospace;
		font-size: 11px;
		line-height: 1.45;
		color: var(--c-text-dim);
		white-space: pre-wrap;
		word-break: break-word;
		margin: 0 0 12px;
	}
	.sent {
		font-size: 14px;
		color: var(--c-text);
		margin: 4px 0;
	}
	.sent code {
		font-family: 'SF Mono', 'Fira Code', monospace;
		color: var(--c-accent);
		font-weight: 700;
	}
	.hint {
		font-size: 12px;
		color: var(--c-text-dim);
		margin: 0 0 14px;
	}
	.dim {
		font-size: 13px;
		color: var(--c-text-dim);
	}
	.err {
		font-size: 12px;
		color: var(--sec-deny, #ff453a);
		margin: 4px 0 12px;
	}
	.actions {
		display: flex;
		gap: 10px;
		justify-content: flex-end;
	}
	.btn {
		padding: 10px 16px;
		border-radius: 8px;
		border: 1px solid var(--c-border);
		background: var(--c-bg);
		color: var(--c-text);
		font-size: 13px;
		font-weight: 600;
		cursor: pointer;
	}
	.btn.primary {
		background: var(--c-accent);
		border-color: var(--c-accent);
		color: #fff;
	}
	.btn:disabled {
		opacity: 0.5;
		cursor: default;
	}

	@media (min-width: 760px) {
		.overlay {
			align-items: center;
		}
		.panel {
			border-radius: var(--radius);
			max-width: 440px;
		}
	}
</style>
