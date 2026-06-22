<script lang="ts">
	import { onMount, onDestroy } from 'svelte';
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import { listen, type UnlistenFn } from '@tauri-apps/api/event';
	import { auth, connection, quota } from '$lib/stores';
	import { checkAuthState, getConnectionStatus, getQuota } from '$lib/tauri';
	import type { ConnectionState } from '$lib/types';

	let { children } = $props();

	let unlisteners: UnlistenFn[] = [];

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

		// Keep the window in sync when the macOS tray drives connect/disconnect
		// or navigation. No-op in browser dev (listen rejects without Tauri IPC).
		try {
			unlisteners.push(
				await listen<ConnectionState>('connection-changed', (e) => connection.set(e.payload)),
				await listen<string>('tray-navigate', (e) => goto(e.payload))
			);
		} catch {
			// Tauri events unavailable — ignore
		}
	});

	onDestroy(() => {
		for (const off of unlisteners) off();
	});

	// Desktop chrome only: the sidebar is rendered when signed in and hidden
	// below 760px via CSS, so mobile keeps its native full-screen flow. [A?]
	let signedIn = $derived($auth.status === 'authenticated');
	let tier = $derived($auth.status === 'authenticated' ? $auth.user.tier : '');
	let path = $derived(page.url.pathname);
	function active(href: string): boolean {
		return path === href || path.startsWith(href + '/');
	}
</script>

<svelte:head>
	<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover" />
</svelte:head>

<div class="app" class:with-sidebar={signedIn}>
	{#if signedIn}
		<aside class="sidebar">
			<div class="brand">
				<span class="brand-dot" class:on={$connection.status === 'connected'}></span>
				Ankayma
			</div>
			<nav>
				<button class="nav-item" class:active={active('/dashboard')} onclick={() => goto('/dashboard')}>
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M3 12l9-9 9 9M5 10v10h14V10"/></svg>
					<span>Dashboard</span>
				</button>
				{#if tier === 'F0Plus'}
					<button class="nav-item" class:active={active('/subdomains')} onclick={() => goto('/subdomains')}>
						<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="12" cy="12" r="9"/><path d="M3.6 9h16.8M3.6 15h16.8M12 3a15 15 0 010 18"/></svg>
						<span>Subdomains</span>
					</button>
				{/if}
				<button class="nav-item" class:active={active('/add-device')} onclick={() => goto('/add-device')}>
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="5" y="2" width="14" height="20" rx="2"/><path d="M12 18h.01"/></svg>
					<span>Add device</span>
				</button>
				{#if tier === 'F0'}
					<button class="nav-item" class:active={active('/upgrade')} onclick={() => goto('/upgrade')}>
						<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M12 19V5M5 12l7-7 7 7"/></svg>
						<span>Upgrade</span>
					</button>
				{/if}
			</nav>
			<button class="nav-item bottom" class:active={active('/settings')} onclick={() => goto('/settings')}>
				<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 11-2.83 2.83l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-4 0v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 11-2.83-2.83l.06-.06A1.65 1.65 0 004.6 15a1.65 1.65 0 00-1.51-1H3a2 2 0 010-4h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 112.83-2.83l.06.06A1.65 1.65 0 009 4.6a1.65 1.65 0 001-1.51V3a2 2 0 014 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 112.83 2.83l-.06.06a1.65 1.65 0 00-.33 1.82V12a1.65 1.65 0 001.51 1H21a2 2 0 010 4h-.09a1.65 1.65 0 00-1.51 1z"/></svg>
				<span>Settings</span>
			</button>
		</aside>
	{/if}

	<div class="view">
		{@render children()}
	</div>
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

	/* Mobile-first: single column, sidebar hidden. */
	.app {
		min-height: 100dvh;
		display: flex;
		flex-direction: column;
	}

	.view {
		flex: 1;
		display: flex;
		flex-direction: column;
		min-width: 0;
	}

	.sidebar {
		display: none;
	}

	/* Desktop chrome: left nav rail + scrollable content area. */
	@media (min-width: 760px) {
		.app.with-sidebar {
			flex-direction: row;
			height: 100dvh;
		}

		.app.with-sidebar .sidebar {
			display: flex;
			flex-direction: column;
			width: 232px;
			flex-shrink: 0;
			padding: 18px 12px;
			gap: 4px;
			background: var(--c-surface);
			border-right: 1px solid var(--c-border);
		}

		.app.with-sidebar .view {
			height: 100dvh;
			overflow-y: auto;
		}

		.brand {
			display: flex;
			align-items: center;
			gap: 10px;
			font-size: 17px;
			font-weight: 700;
			padding: 6px 10px 16px;
		}

		.brand-dot {
			width: 9px;
			height: 9px;
			border-radius: 50%;
			background: var(--c-text-dim);
		}

		.brand-dot.on {
			background: var(--c-success);
			box-shadow: 0 0 8px var(--c-success);
		}

		nav {
			display: flex;
			flex-direction: column;
			gap: 2px;
		}

		.nav-item {
			display: flex;
			align-items: center;
			gap: 12px;
			padding: 10px 12px;
			border-radius: 8px;
			font-size: 14px;
			font-weight: 500;
			color: var(--c-text-dim);
			text-align: left;
			transition: background 0.12s, color 0.12s;
		}

		.nav-item svg {
			width: 18px;
			height: 18px;
			flex-shrink: 0;
		}

		.nav-item:hover {
			background: color-mix(in srgb, var(--c-accent) 8%, transparent);
			color: var(--c-text);
		}

		.nav-item.active {
			background: color-mix(in srgb, var(--c-accent) 16%, transparent);
			color: var(--c-text);
		}

		.nav-item.bottom {
			margin-top: auto;
		}
	}
</style>
