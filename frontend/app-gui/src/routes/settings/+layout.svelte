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

	@media (min-width: 760px) {
		/* Desktop already shows this subnav in the sidebar (routes/+layout.svelte) —
		   avoid the redundant second control at that breakpoint. */
		.tabs {
			display: none;
		}
	}
</style>
