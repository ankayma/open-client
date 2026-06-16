<script lang="ts">
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { auth, connection, quota } from '$lib/stores';
	import { checkAuthState, getConnectionStatus, getQuota } from '$lib/tauri';

	let { children } = $props();

	onMount(async () => {
		try {
			const [authState, connState, quotaData] = await Promise.all([
				checkAuthState(),
				getConnectionStatus(),
				getQuota().catch(() => null)
			]);
			auth.set(authState);
			connection.set(connState);
			if (quotaData) quota.set(quotaData);

			if (authState.status === 'unauthenticated') {
				goto('/welcome');
			} else if (connState.status === 'disconnected') {
				goto('/dashboard');
			}
		} catch {
			// Tauri not available (browser dev) — stay on current route
		}
	});
</script>

<svelte:head>
	<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover" />
</svelte:head>

<div class="app">
	{@render children()}
</div>

<style>
	:global(*) {
		box-sizing: border-box;
		margin: 0;
		padding: 0;
	}

	:global(:root) {
		--c-bg: #0a0a0f;
		--c-surface: #13131a;
		--c-border: #1e1e2e;
		--c-text: #e0e0f0;
		--c-text-dim: #7070a0;
		--c-accent: #6366f1;
		--c-accent-dim: #4f52c9;
		--c-success: #22c55e;
		--c-warn: #f59e0b;
		--c-danger: #ef4444;
		--radius: 12px;
		--safe-top: env(safe-area-inset-top, 0px);
		--safe-bottom: env(safe-area-inset-bottom, 0px);
	}

	:global(body) {
		background: var(--c-bg);
		color: var(--c-text);
		font-family: -apple-system, BlinkMacSystemFont, 'SF Pro Text', 'Segoe UI', sans-serif;
		font-size: 16px;
		line-height: 1.5;
		-webkit-font-smoothing: antialiased;
		overscroll-behavior: none;
		user-select: none;
	}

	:global(button) {
		cursor: pointer;
		border: none;
		background: none;
		font: inherit;
		color: inherit;
	}

	:global(a) {
		color: var(--c-accent);
		text-decoration: none;
	}

	.app {
		min-height: 100dvh;
		display: flex;
		flex-direction: column;
	}
</style>
