<script lang="ts">
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { auth } from '$lib/stores';
	import { signOut, getNodeInfo } from '$lib/tauri';
	import type { NodeInfo } from '$lib/types';

	let signing_out = $state(false);
	let nodeInfo = $state<NodeInfo | null>(null);

	onMount(async () => {
		try {
			nodeInfo = await getNodeInfo();
		} catch {
			// daemon not connected or not enrolled
		}
	});

	async function handleSignOut() {
		signing_out = true;
		try {
			await signOut();
			auth.set({ status: 'unauthenticated' });
			goto('/welcome');
		} catch {
			signing_out = false;
		}
	}
</script>

<main>
	<header>
		<button class="back-btn" onclick={() => goto('/dashboard')}>
			<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
				<path d="M19 12H5M12 5l-7 7 7 7"/>
			</svg>
		</button>
		<h2>Settings</h2>
		<div style="width: 36px"></div>
	</header>

	{#if $auth.status === 'authenticated'}
		<section class="card">
			<div class="row">
				<span class="label">Account</span>
				<span class="value">{$auth.user.email}</span>
			</div>
			<div class="row">
				<span class="label">Plan</span>
				<span class="value">{$auth.user.tier}</span>
			</div>
		</section>
	{/if}

	{#if nodeInfo}
		<section class="card">
			<div class="section-label">Network</div>
			<div class="row">
				<span class="label">Hostname</span>
				<span class="value mono">{nodeInfo.hostname}</span>
			</div>
			<div class="row">
				<span class="label">Node ID</span>
				<span class="value mono">{nodeInfo.node_id}</span>
			</div>
			<div class="row col">
				<span class="label">Public key</span>
				<span class="value mono pubkey">{nodeInfo.public_key}</span>
			</div>
		</section>
	{/if}

	<section class="card">
		<div class="row">
			<span class="label">Version</span>
			<span class="value mono">0.1.0</span>
		</div>
		<div class="row">
			<span class="label">Agent</span>
			<a href="https://github.com/ankayma/open-client" class="value link" target="_blank" rel="noopener">
				Open source ↗
			</a>
		</div>
	</section>

	<button class="sign-out-btn" onclick={handleSignOut} disabled={signing_out}>
		{signing_out ? 'Signing out…' : 'Sign out'}
	</button>
</main>

<style>
	main {
		flex: 1;
		display: flex;
		flex-direction: column;
		padding: calc(var(--safe-top) + 16px) 16px calc(var(--safe-bottom) + 40px);
		gap: 16px;
		max-width: 420px;
		margin: 0 auto;
		width: 100%;
	}

	header {
		display: flex;
		align-items: center;
		justify-content: space-between;
		padding: 8px 0;
		margin-bottom: 8px;
	}

	h2 {
		font-size: 18px;
		font-weight: 700;
	}

	.back-btn {
		display: flex;
		align-items: center;
		color: var(--c-text-dim);
		padding: 8px;
		border-radius: 8px;
	}

	.card {
		background: var(--c-surface);
		border: 1px solid var(--c-border);
		border-radius: var(--radius);
		overflow: hidden;
	}

	.row {
		display: flex;
		justify-content: space-between;
		align-items: center;
		padding: 14px 16px;
		border-bottom: 1px solid var(--c-border);
	}

	.row:last-child {
		border-bottom: none;
	}

	.label {
		font-size: 14px;
		color: var(--c-text-dim);
	}

	.value {
		font-size: 14px;
		font-weight: 500;
	}

	.mono {
		font-family: 'SF Mono', 'Fira Code', monospace;
		font-size: 13px;
	}

	.link {
		color: var(--c-accent);
	}

	.section-label {
		font-size: 11px;
		font-weight: 700;
		text-transform: uppercase;
		letter-spacing: 0.08em;
		color: var(--c-text-dim);
		padding: 10px 16px 6px;
	}

	.row.col {
		flex-direction: column;
		align-items: flex-start;
		gap: 4px;
	}

	.pubkey {
		font-size: 11px;
		color: var(--c-text-dim);
		word-break: break-all;
		line-height: 1.5;
	}

	.sign-out-btn {
		padding: 16px;
		background: color-mix(in srgb, var(--c-danger) 10%, var(--c-surface));
		border: 1px solid color-mix(in srgb, var(--c-danger) 30%, transparent);
		color: var(--c-danger);
		border-radius: var(--radius);
		font-size: 15px;
		font-weight: 600;
		transition: background 0.15s;
	}

	.sign-out-btn:hover:not(:disabled) {
		background: color-mix(in srgb, var(--c-danger) 20%, var(--c-surface));
	}
</style>
