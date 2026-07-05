<script lang="ts">
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { getVersion } from '@tauri-apps/api/app';
	import { auth } from '$lib/stores';
	import { signOut, getNodeInfo } from '$lib/tauri';
	import type { NodeInfo } from '$lib/types';

	let signing_out = $state(false);
	let nodeInfo = $state<NodeInfo | null>(null);
	// Read the real bundle version at runtime so it can never drift from the
	// shipped build (was hard-coded to 0.1.0 and went stale). [T:tauri-api-app@2]
	let appVersion = $state('');

	onMount(async () => {
		try {
			nodeInfo = await getNodeInfo();
		} catch {
			// daemon not connected or not enrolled
		}
		try {
			appVersion = await getVersion();
		} catch {
			// non-Tauri (browser dev) — leave blank
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
		<h2>Account</h2>
	</header>

	{#if $auth.status === 'authenticated'}
		<section class="card">
			<div class="section-label">Account</div>
			<div class="row">
				<span class="label">Email</span>
				<span class="value">{$auth.user.email}</span>
			</div>
			<div class="row">
				<span class="label">Plan</span>
				<span class="value tier-badge">{$auth.user.tier}</span>
			</div>
		</section>

		{#if $auth.user.tier === 'F0'}
			<section class="upgrade-banner">
				<div>
					<strong>F0-Plus — $9/mo</strong>
					<span>More bandwidth · Multiple subdomains · Raw TCP</span>
				</div>
				<button class="upgrade-btn" onclick={() => goto('/upgrade')}>Upgrade</button>
			</section>
		{/if}
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
			<span class="value mono">{appVersion || '—'}</span>
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
		padding: 16px 16px calc(var(--safe-bottom) + 40px);
		gap: 16px;
		max-width: 420px;
		margin: 0 auto;
		width: 100%;
	}

	header {
		padding: 8px 0;
	}

	h2 {
		font-size: 20px;
		font-weight: 700;
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

	.tier-badge {
		padding: 3px 10px;
		background: color-mix(in srgb, var(--c-accent) 10%, transparent);
		border: 1px solid color-mix(in srgb, var(--c-accent) 25%, transparent);
		border-radius: 99px;
		color: var(--c-accent);
		font-size: 12px;
		font-weight: 700;
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

	.upgrade-banner {
		background: color-mix(in srgb, var(--c-accent) 10%, var(--c-surface));
		border: 1px solid color-mix(in srgb, var(--c-accent) 30%, transparent);
		border-radius: var(--radius);
		padding: 16px;
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 12px;
	}

	.upgrade-banner strong {
		display: block;
		font-size: 14px;
		margin-bottom: 2px;
	}

	.upgrade-banner span {
		font-size: 12px;
		color: var(--c-text-dim);
	}

	.upgrade-btn {
		background: var(--c-accent);
		color: #fff;
		padding: 10px 18px;
		border-radius: 8px;
		font-size: 14px;
		font-weight: 600;
		white-space: nowrap;
		flex-shrink: 0;
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
