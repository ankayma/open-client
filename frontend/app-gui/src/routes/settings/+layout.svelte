<script lang="ts">
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import { activeLang } from '$lib/stores';
	import { STRINGS, type Lang } from '$lib/i18n';

	let { children } = $props();

	let lang = $state<Lang>('vn');
	activeLang.subscribe((l) => { lang = l; });

	let path = $derived(page.url.pathname);
	function active(href: string): boolean {
		return path === href || path.startsWith(href + '/');
	}

	// Same three destinations as the desktop sidebar subnav (routes/+layout.svelte)
	// — repeated here so mobile (sidebar hidden below 760px) can reach Account and
	// Security too, not just the default My Devices tab.
	let tabs = $derived([
		{ href: '/settings/devices',  label: STRINGS[lang].nav_devices },
		{ href: '/settings/account',  label: STRINGS[lang].nav_account },
		{ href: '/settings/security', label: STRINGS[lang].nav_security }
	]);
</script>

<div class="settings-shell">
	<nav class="tabs">
		{#each tabs as tab}
			<button class="tab" class:active={active(tab.href)} onclick={() => goto(tab.href)}>
				{tab.label}
			</button>
		{/each}
	</nav>
	{@render children()}
	<!-- Language switch — mobile only (the desktop sidebar already carries one). Below
	     760px the sidebar is hidden, so Settings is where a phone user changes language. -->
	<div class="lang-switch">
		<button class:active={lang === 'en'} onclick={() => activeLang.set('en')}>EN</button>
		<button class:active={lang === 'vn'} onclick={() => activeLang.set('vn')}>VN</button>
	</div>
</div>

<style>
	.settings-shell {
		display: flex;
		flex-direction: column;
		flex: 1;
		min-width: 0;
	}

	.tabs {
		display: flex;
		gap: 4px;
		padding: calc(var(--safe-top) + 12px) 16px 0;
		max-width: 640px;
		margin: 0 auto;
		width: 100%;
	}

	.tab {
		padding: 8px 14px;
		border-radius: 999px;
		font-size: 13px;
		font-weight: 600;
		color: var(--c-text-dim);
		background: var(--c-surface);
		border: 1px solid var(--c-border);
	}

	.tab.active {
		background: color-mix(in srgb, var(--c-accent) 14%, transparent);
		border-color: color-mix(in srgb, var(--c-accent) 35%, transparent);
		color: var(--c-accent);
	}

	.lang-switch {
		display: flex;
		gap: 6px;
		justify-content: center;
		padding: 16px 16px calc(var(--safe-bottom) + 16px);
		margin-top: auto;
	}
	.lang-switch button {
		padding: 7px 20px;
		border-radius: 999px;
		font-size: 13px;
		font-weight: 600;
		color: var(--c-text-dim);
		background: var(--c-surface);
		border: 1px solid var(--c-border);
	}
	.lang-switch button.active {
		background: color-mix(in srgb, var(--c-accent) 14%, transparent);
		border-color: color-mix(in srgb, var(--c-accent) 35%, transparent);
		color: var(--c-accent);
	}

	@media (min-width: 760px) {
		/* Desktop already shows this subnav + language control in the sidebar
		   (routes/+layout.svelte) — avoid the redundant second controls at that breakpoint. */
		.tabs,
		.lang-switch {
			display: none;
		}
	}
</style>
