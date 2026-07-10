<script lang="ts">
	// [03b §1.2] CI/CD Deploy Rules — list of the tenant's policies.
	import { goto } from '$app/navigation';
	import { onMount } from 'svelte';
	import { listCiPolicies, deleteCiPolicy } from '$lib/tauri';
	import { runWithStepUp } from '$lib/stepup';
	import type { CiPolicy } from '$lib/types';

	let policies = $state<CiPolicy[]>([]);
	let loading = $state(true);
	let error = $state('');
	let confirmRepo = $state<string | null>(null);
	let deleting = $state(false);

	async function load() {
		loading = true;
		error = '';
		try {
			policies = await listCiPolicies();
		} catch (e) {
			error = String(e);
		} finally {
			loading = false;
		}
	}
	onMount(load);

	function scopeLabel(p: CiPolicy): string {
		if (p.ref) return p.ref;
		if (p.environment) return `env: ${p.environment}`;
		return '—';
	}

	function editHref(repo: string): string {
		return `/policies/${repo}`; // repo = owner/name → rest route [...repo]
	}

	async function doDelete(repo: string) {
		deleting = true;
		try {
			// Paid tiers step up before removing a deploy rule (E-7).
			await runWithStepUp('manage_ci_policy', (proof) => deleteCiPolicy(repo, proof));
			confirmRepo = null;
			await load();
		} catch (e) {
			error = String(e);
		} finally {
			deleting = false;
		}
	}
</script>

<main>
	<header>
		<button class="back-btn" aria-label="Back" onclick={() => goto('/services')}>
			<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M19 12H5M12 5l-7 7 7 7" /></svg>
		</button>
		<h2>Deploy Rules</h2>
		<button class="add-btn" onclick={() => goto('/policies/new')}>Add rule</button>
	</header>

	{#if loading}
		<p class="muted">Loading…</p>
	{:else if error}
		<div class="error-box">{error}</div>
		<button class="retry" onclick={load}>Retry</button>
	{:else if policies.length === 0}
		<section class="empty">
			<p>No deploy rules yet.</p>
			<button class="cta" onclick={() => goto('/policies/new')}>Add your first rule</button>
			<code>agent ci-policy add &lt;owner/repo&gt; --ref refs/heads/main</code>
			<small>The GUI is one face — the CLI does the same thing.</small>
		</section>
	{:else}
		<section class="list">
			{#each policies as p (p.repo)}
				<div class="row">
					<button class="row-main" onclick={() => goto(editHref(p.repo))}>
						<div class="repo">
							<span class="badge {p.issuer}">{p.issuer}</span>
							{p.repo}
						</div>
						<div class="meta">
							<span>{scopeLabel(p)}</span>
							<span class="target">→ {p.target_hostname ?? '—'}</span>
						</div>
					</button>
					<button class="del" aria-label="Delete rule" onclick={() => (confirmRepo = p.repo)}>
						<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M3 6h18M8 6V4h8v2M19 6l-1 14H6L5 6" /></svg>
					</button>
				</div>
			{/each}
		</section>
	{/if}
</main>

{#if confirmRepo}
	<div class="overlay" role="presentation" onclick={() => (confirmRepo = null)}>
		<div class="dialog" role="dialog" aria-modal="true" onclick={(e) => e.stopPropagation()}>
			<p>Delete deploy rule for <strong>{confirmRepo}</strong>?</p>
			<div class="dialog-actions">
				<button class="ghost" onclick={() => (confirmRepo = null)}>Cancel</button>
				<button class="danger" disabled={deleting} onclick={() => doDelete(confirmRepo!)}>
					{deleting ? 'Deleting…' : 'Delete'}
				</button>
			</div>
		</div>
	</div>
{/if}

<style>
	main {
		flex: 1;
		display: flex;
		flex-direction: column;
		padding: calc(var(--safe-top) + 16px) 16px calc(var(--safe-bottom) + 24px);
		gap: 16px;
		max-width: 640px;
		margin: 0 auto;
		width: 100%;
	}
	header {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 8px;
		padding: 8px 0;
	}
	h2 {
		font-size: 20px;
		font-weight: 700;
		flex: 1;
	}
	.back-btn {
		width: 36px;
		height: 36px;
		display: flex;
		align-items: center;
		justify-content: center;
		border-radius: 10px;
		color: var(--c-text-dim);
	}
	.back-btn:hover {
		color: var(--c-text);
	}
	.add-btn {
		background: var(--c-accent);
		color: #fff;
		padding: 8px 14px;
		border-radius: 8px;
		font-size: 14px;
		font-weight: 600;
		white-space: nowrap;
	}
	.muted {
		color: var(--c-text-dim);
	}
	.error-box {
		background: color-mix(in srgb, var(--c-danger) 10%, transparent);
		border: 1px solid color-mix(in srgb, var(--c-danger) 30%, transparent);
		border-radius: 8px;
		padding: 12px;
		color: var(--c-danger);
		font-size: 14px;
	}
	.retry {
		align-self: flex-start;
		color: var(--c-accent);
		font-size: 14px;
	}
	.empty {
		display: flex;
		flex-direction: column;
		align-items: center;
		gap: 12px;
		text-align: center;
		padding: 40px 16px;
		background: var(--c-surface);
		border: 1px solid var(--c-border);
		border-radius: var(--radius);
	}
	.empty .cta {
		background: var(--c-accent);
		color: #fff;
		padding: 10px 18px;
		border-radius: 8px;
		font-weight: 600;
	}
	.empty code {
		font-family: 'SF Mono', 'Fira Code', monospace;
		font-size: 12px;
		color: var(--c-text-dim);
		background: var(--c-bg);
		border: 1px solid var(--c-border);
		border-radius: 6px;
		padding: 8px 10px;
	}
	.empty small {
		color: var(--c-text-dim);
		font-size: 12px;
	}
	.list {
		display: flex;
		flex-direction: column;
		gap: 2px;
		background: var(--c-surface);
		border: 1px solid var(--c-border);
		border-radius: var(--radius);
		overflow: hidden;
	}
	.row {
		display: flex;
		align-items: center;
		border-bottom: 1px solid var(--c-border);
	}
	.row:last-child {
		border-bottom: none;
	}
	.row-main {
		flex: 1;
		display: flex;
		flex-direction: column;
		gap: 4px;
		padding: 14px 16px;
		text-align: left;
	}
	.row-main:hover {
		background: color-mix(in srgb, var(--c-accent) 6%, transparent);
	}
	.repo {
		display: flex;
		align-items: center;
		gap: 8px;
		font-size: 15px;
		font-weight: 500;
	}
	.badge {
		font-size: 11px;
		text-transform: uppercase;
		letter-spacing: 0.04em;
		padding: 2px 7px;
		border-radius: 5px;
		background: var(--c-border);
		color: var(--c-text-dim);
	}
	.badge.github {
		background: color-mix(in srgb, #6e5494 30%, var(--c-surface));
		color: #d6c9f0;
	}
	.badge.gitlab {
		background: color-mix(in srgb, #fc6d26 25%, var(--c-surface));
		color: #ffc6a8;
	}
	.meta {
		display: flex;
		gap: 12px;
		font-size: 12px;
		color: var(--c-text-dim);
		font-family: 'SF Mono', 'Fira Code', monospace;
	}
	.del {
		width: 44px;
		align-self: stretch;
		display: flex;
		align-items: center;
		justify-content: center;
		color: var(--c-text-dim);
	}
	.del:hover {
		color: var(--c-danger);
	}
	.overlay {
		position: fixed;
		inset: 0;
		background: rgba(0, 0, 0, 0.55);
		display: flex;
		align-items: center;
		justify-content: center;
		padding: 24px;
		z-index: 50;
	}
	.dialog {
		background: var(--c-surface);
		border: 1px solid var(--c-border);
		border-radius: var(--radius);
		padding: 20px;
		max-width: 360px;
		width: 100%;
		display: flex;
		flex-direction: column;
		gap: 16px;
	}
	.dialog p {
		font-size: 15px;
	}
	.dialog-actions {
		display: flex;
		justify-content: flex-end;
		gap: 8px;
	}
	.ghost {
		padding: 9px 16px;
		border-radius: 8px;
		color: var(--c-text-dim);
	}
	.ghost:hover {
		color: var(--c-text);
	}
	.danger {
		background: var(--c-danger);
		color: #fff;
		padding: 9px 16px;
		border-radius: 8px;
		font-weight: 600;
	}
	.danger:disabled {
		opacity: 0.5;
	}
</style>
