<script lang="ts">
	import { onMount, onDestroy } from 'svelte';
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import { listen, type UnlistenFn } from '@tauri-apps/api/event';
	import { auth, connection, quota, activeTheme, activeLang } from '$lib/stores';
	import { checkAuthState, getConnectionStatus, getQuota } from '$lib/tauri';
	import { applyTheme, THEMES, THEME_PAIRS } from '$lib/theme';
	import { STRINGS, type Lang } from '$lib/i18n';
	import type { ConnectionState } from '$lib/types';

	let { children } = $props();

	let unlisteners: UnlistenFn[] = [];
	let unsubTheme: (() => void) | null = null;
	let unsubLang:  (() => void) | null = null;

	// Re-check auth and, if a deep-link token was adopted, land on the dashboard.
	// Called on mount, on the `auth-pending` nudge, and whenever the window regains
	// focus — so "Open app" works whether the app was cold-launched or already open,
	// without depending on event timing. `silent` avoids bouncing to /welcome on a
	// focus check that found nothing (e.g. the user is mid-sign-in).
	async function refreshAuth(silent = false) {
		try {
			const authState = await checkAuthState();
			auth.set(authState);
			if (authState.status === 'authenticated') {
				goto('/dashboard');
			} else if (!silent) {
				goto('/welcome');
			}
		} catch {
			// Tauri not available (browser dev) — stay on current route
		}
	}

	onMount(async () => {
		try {
			const [connState, quotaData] = await Promise.all([
				getConnectionStatus(),
				getQuota().catch(() => null)
			]);
			connection.set(connState);
			if (quotaData) quota.set(quotaData);
		} catch {
			// Tauri not available (browser dev)
		}
		// Initial auth check (adopts a cold-start deep-link token if present).
		await refreshAuth();

		// Catch-all paths so deep-link "Open app" always lands on the dashboard:
		try {
			unlisteners.push(
				await listen<ConnectionState>('connection-changed', (e) => connection.set(e.payload)),
				await listen<string>('tray-navigate', (e) => goto(e.payload)),
				// Warm start: the running app received the deep link.
				await listen('auth-pending', () => refreshAuth(true))
			);
		} catch {
			// Tauri events unavailable — ignore
		}
		// Universal catch-all: clicking "Allow" brings the app to the foreground —
		// re-check then, regardless of whether any event arrived.
		window.addEventListener('focus', onFocus);

		// Apply saved theme and wire up persistence
		unsubTheme = activeTheme.subscribe((t) => {
			applyTheme(t);
			localStorage.setItem('ankayma_theme', t);
		});
		unsubLang = activeLang.subscribe((l) => {
			localStorage.setItem('ankayma_lang', l);
		});
	});

	function onFocus() {
		if ($auth.status !== 'authenticated') refreshAuth(true);
	}

	onDestroy(() => {
		for (const off of unlisteners) off();
		window.removeEventListener('focus', onFocus);
		unsubTheme?.();
		unsubLang?.();
	});

	// i18n
	let lang = $state<Lang>('vn');
	activeLang.subscribe((l) => { lang = l; });
	function toggleLang() { activeLang.update(l => l === 'vn' ? 'en' : 'vn'); }

	// theme
	let isDark = $state(true);
	activeTheme.subscribe((tid) => { isDark = THEMES[tid]?.dark ?? true; });
	function toggleTheme() {
		activeTheme.update((tid) => {
			if (THEME_PAIRS[tid]) return THEME_PAIRS[tid]!;
			const dark  = Object.values(THEMES).filter(t => t.dark);
			const light = Object.values(THEMES).filter(t => !t.dark);
			return THEMES[tid]?.dark ? light[0].id : dark[0].id;
		});
	}

	// Desktop chrome only: the sidebar is rendered when signed in and hidden
	// below 760px via CSS, so mobile keeps its native full-screen flow.
	let signedIn = $derived($auth.status === 'authenticated');
	let tier      = $derived($auth.status === 'authenticated' ? $auth.user.tier : '');
	let userEmail = $derived($auth.status === 'authenticated' ? $auth.user.email : '');
	let path      = $derived(page.url.pathname);

	function active(href: string): boolean {
		return path === href || path.startsWith(href + '/');
	}

	function getInitials(email: string): string {
		const local = email.split('@')[0];
		const parts = local.split(/[\s._-]+/).filter(Boolean);
		if (parts.length >= 2) return (parts[0][0] + parts[1][0]).toUpperCase();
		return local.slice(0, 2).toUpperCase();
	}

	const TIER_LABELS: Record<string, string> = {
		F0:        'F0',
		F0Plus:    'F0+',
		F1Starter: 'F1 Starter',
	};
	const AVATAR_COLORS: Record<string, string> = {
		F0:        'var(--c-surface)',
		F0Plus:    'color-mix(in srgb, var(--c-accent) 30%, var(--c-surface))',
		F1Starter: 'var(--c-accent)',
	};
	const AVATAR_TEXT: Record<string, string> = {
		F0:        'var(--c-text-dim)',
		F0Plus:    'var(--c-text)',
		F1Starter: '#fff',
	};

	let avatarInitials = $derived(getInitials(userEmail));
	let avatarBg       = $derived(AVATAR_COLORS[tier] ?? 'var(--c-surface)');
	let avatarText     = $derived(AVATAR_TEXT[tier] ?? 'var(--c-text-dim)');
	let tierLabel      = $derived(TIER_LABELS[tier] ?? tier);
</script>

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
				<button class="nav-item" class:active={active('/devices')} onclick={() => goto('/devices')}>
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="2" y="4" width="20" height="14" rx="2"/><path d="M8 21h8M12 18v3"/></svg>
					<span>{STRINGS[lang].nav_nodes}</span>
				</button>
				<button class="nav-item" class:active={active('/services')} onclick={() => goto('/services')}>
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M3 7h18M3 12h18M3 17h18"/><circle cx="7" cy="7" r="0.5"/></svg>
					<span>{STRINGS[lang].nav_services}</span>
				</button>
				<button class="nav-item" class:active={active('/subdomains')} onclick={() => goto('/subdomains')}>
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="12" cy="12" r="9"/><path d="M3.6 9h16.8M3.6 15h16.8M12 3a15 15 0 010 18"/></svg>
					<span>Subdomains</span>
				</button>
				<button class="nav-item" class:active={active('/members')} onclick={() => goto('/members')}>
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 00-3-3.87M16 3.13a4 4 0 010 7.75"/></svg>
					<span>{STRINGS[lang].nav_users}</span>
				</button>
				<button class="nav-item" class:active={active('/access')} onclick={() => goto('/access')}>
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>
					<span>Access</span>
				</button>
				<button class="nav-item" class:active={active('/policies')} onclick={() => goto('/policies')}>
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M4 17l6-6-6-6M12 19h8"/></svg>
					<span>Deploy Rules</span>
				</button>
				{#if tier === 'F0'}
					<button class="nav-item" class:active={active('/upgrade')} onclick={() => goto('/upgrade')}>
						<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M12 19V5M5 12l7-7 7 7"/></svg>
						<span>Upgrade</span>
					</button>
				{/if}
				<button class="nav-item nav-settings" class:active={active('/settings')} onclick={() => goto('/settings')}>
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 11-2.83 2.83l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-4 0v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 11-2.83-2.83l.06-.06A1.65 1.65 0 004.6 15a1.65 1.65 0 00-1.51-1H3a2 2 0 010-4h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 112.83-2.83l.06.06A1.65 1.65 0 009 4.6a1.65 1.65 0 001-1.51V3a2 2 0 014 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 112.83 2.83l-.06.06a1.65 1.65 0 00-.33 1.82V12a1.65 1.65 0 001.51 1H21a2 2 0 010 4h-.09a1.65 1.65 0 00-1.51 1z"/></svg>
					<span>{STRINGS[lang].nav_settings}</span>
				</button>
			</nav>

			<div class="user-chip">
				<div class="user-avatar" style="background:{avatarBg};color:{avatarText}">
					{avatarInitials}
				</div>
				<div class="user-info">
					<div class="user-email">{userEmail}</div>
					<div class="user-tier">{tierLabel}</div>
				</div>
			</div>

			<div class="sidebar-prefs">
				<button class="pref-btn" onclick={toggleTheme} title={isDark ? 'Switch to light' : 'Switch to dark'}>
					{#if isDark}
						<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" width="16" height="16"><path d="M21 12.79A9 9 0 1111.21 3a7 7 0 009.79 9.79z"/></svg>
					{:else}
						<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" width="16" height="16"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>
					{/if}
				</button>
				<button class="pref-btn lang-btn" onclick={toggleLang} title="Switch language">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" width="15" height="15"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-4 10 15.3 15.3 0 01-4-10 15.3 15.3 0 014-10z"/></svg>
					<span class="lang-label">{lang.toUpperCase()}</span>
				</button>
			</div>
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
		/* security state layer — fixed, overwritten by applyTheme() on mount */
		--sec-allow: #1A7F37;
		--sec-deny:  #CF222E;
		--sec-info:  #0969DA;
		/* button component tokens — overwritten per theme */
		--btn-secondary-bg:     var(--c-surface);
		--btn-secondary-border: var(--c-border);
		--btn-secondary-text:   var(--c-text);
		--btn-danger-bg:        color-mix(in srgb, #ef4444 16%, #13131a);
		--btn-danger-border:    color-mix(in srgb, #ef4444 45%, transparent);
		--btn-danger-text:      #ef4444;
		--btn-warn-bg:          color-mix(in srgb, #f59e0b 14%, #13131a);
		--btn-warn-border:      color-mix(in srgb, #f59e0b 40%, transparent);
		--btn-warn-text:        #f59e0b;
	}

	:global(html), :global(body) {
		width: 100%;
		max-width: 100%;
		/* Never let a stray wide child create a horizontal scroll on mobile —
		   keeps the narrow webview from rendering content past the right edge. */
		overflow-x: hidden;
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

	/* Global button classes */
	:global(.btn-primary) {
		background: var(--c-accent);
		color: #fff;
		border: 1px solid var(--c-accent);
		padding: 7px 14px;
		border-radius: var(--radius);
		font-size: 13px;
		font-weight: 500;
		cursor: pointer;
		transition: background 0.12s, border-color 0.12s;
	}
	:global(.btn-primary:hover) {
		background: var(--c-accent-dim);
		border-color: var(--c-accent-dim);
	}

	:global(.btn-secondary) {
		background: var(--btn-secondary-bg);
		color: var(--btn-secondary-text);
		border: 1px solid var(--btn-secondary-border);
		padding: 7px 14px;
		border-radius: var(--radius);
		font-size: 13px;
		font-weight: 500;
		cursor: pointer;
		transition: background 0.12s, border-color 0.12s;
	}
	:global(.btn-secondary:hover) {
		background: color-mix(in srgb, var(--c-text) 6%, var(--btn-secondary-bg));
	}

	:global(.btn-danger) {
		background: var(--btn-danger-bg);
		color: var(--btn-danger-text);
		border: 1px solid var(--btn-danger-border);
		padding: 7px 14px;
		border-radius: var(--radius);
		font-size: 13px;
		font-weight: 500;
		cursor: pointer;
		transition: background 0.12s, border-color 0.12s;
	}
	:global(.btn-danger:hover) {
		background: color-mix(in srgb, var(--c-danger) 22%, var(--c-surface));
	}

	:global(.btn-warn) {
		background: var(--btn-warn-bg);
		color: var(--btn-warn-text);
		border: 1px solid var(--btn-warn-border);
		padding: 7px 14px;
		border-radius: var(--radius);
		font-size: 13px;
		font-weight: 500;
		cursor: pointer;
		transition: background 0.12s, border-color 0.12s;
	}
	:global(.btn-warn:hover) {
		background: color-mix(in srgb, var(--c-warn) 22%, var(--c-surface));
	}

	:global(.btn-ghost) {
		background: transparent;
		color: var(--c-text-dim);
		border: 1px solid transparent;
		padding: 7px 14px;
		border-radius: var(--radius);
		font-size: 13px;
		font-weight: 500;
		cursor: pointer;
		transition: background 0.12s, color 0.12s;
	}
	:global(.btn-ghost:hover) {
		background: color-mix(in srgb, var(--c-text) 8%, transparent);
		color: var(--c-text);
	}

	/* Mobile-first: single column, sidebar hidden. */
	.app {
		min-height: 100dvh;
		width: 100%;
		max-width: 100%;
		min-width: 0;
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
			height: 100dvh;
			overflow-y: auto;
		}

		.app.with-sidebar .view {
			height: 100dvh;
			overflow-y: auto;
		}

		/* Use the desktop window: pages cap at a mobile column (480px) by default;
		   on desktop let them breathe to a wide content measure so tables/detail
		   panels have room. One rule, every page — no per-screen retrofit. */
		.app.with-sidebar .view :global(main) {
			max-width: 1080px;
		}

		.brand {
			display: flex;
			align-items: center;
			gap: 10px;
			font-size: 17px;
			font-weight: 700;
			padding: 6px 10px 16px;
			flex-shrink: 0;
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
			flex: 1;
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

		.nav-settings {
			margin-top: auto;
		}

		/* User chip */
		.user-chip {
			display: flex;
			align-items: center;
			gap: 8px;
			padding: 10px 12px;
			border-top: 1px solid var(--c-border);
			margin-top: 4px;
			flex-shrink: 0;
		}

		.user-avatar {
			width: 30px;
			height: 30px;
			border-radius: 50%;
			flex-shrink: 0;
			display: flex;
			align-items: center;
			justify-content: center;
			font-size: 11px;
			font-weight: 700;
			letter-spacing: 0.03em;
			border: 1.5px solid color-mix(in srgb, var(--c-border) 60%, transparent);
		}

		.user-info {
			min-width: 0;
		}

		.user-email {
			font-size: 12px;
			color: var(--c-text);
			white-space: nowrap;
			overflow: hidden;
			text-overflow: ellipsis;
		}

		.user-tier {
			font-size: 11px;
			color: var(--c-text-dim);
			white-space: nowrap;
			overflow: hidden;
			text-overflow: ellipsis;
		}

		/* Preference buttons: theme + lang */
		.sidebar-prefs {
			display: flex;
			align-items: center;
			gap: 4px;
			padding: 8px 10px 10px;
			border-top: 1px solid var(--c-border);
			flex-shrink: 0;
		}

		.pref-btn {
			display: flex;
			align-items: center;
			gap: 5px;
			padding: 5px 8px;
			border-radius: 6px;
			color: var(--c-text-dim);
			font-size: 12px;
			border: 1px solid transparent;
			cursor: pointer;
			transition: color 0.12s, background 0.12s;
		}

		.pref-btn:hover {
			color: var(--c-text);
			background: color-mix(in srgb, var(--c-text) 8%, transparent);
			border-color: var(--c-border);
		}

		.lang-btn {
			margin-left: auto;
		}

		.lang-label {
			font-size: 11px;
			font-weight: 600;
			letter-spacing: 0.05em;
		}
	}

	@media print {
		.sidebar { display: none !important; }
		.app { display: block !important; }
		.view { padding: 0 !important; }
	}
</style>
