<script lang="ts">
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import { activeLang } from '$lib/stores';
	import { STRINGS, type Lang } from '$lib/i18n';

	let lang = $state<Lang>('vn');
	activeLang.subscribe((l) => { lang = l; });

	let path = $derived(page.url.pathname);
	function active(hrefs: string[]): boolean {
		return hrefs.some((h) => path === h || path.startsWith(h + '/'));
	}

	const TABS = [
		{
			hrefs: ['/services'],
			go: '/services',
			label: () => STRINGS[lang].nav_services,
			icon: 'M3 7h18M3 12h18M3 17h18'
		},
		{
			hrefs: ['/devices'],
			go: '/devices',
			label: () => STRINGS[lang].nav_nodes,
			icon: 'M2 4h20v14H2zM8 21h8M12 18v3'
		},
		{
			hrefs: ['/admin', '/subdomains', '/members', '/access', '/policies'],
			go: '/admin',
			label: () => STRINGS[lang].nav_admin,
			icon: 'M3 11h18v11H3zM7 11V7a5 5 0 0110 0v4'
		},
		{
			hrefs: ['/settings'],
			go: '/settings',
			label: () => STRINGS[lang].nav_settings,
			icon: 'M12 9a3 3 0 100 6 3 3 0 000-6z'
		}
	];
</script>

<nav class="tabbar">
	{#each TABS as tab}
		<button class="tab" class:active={active(tab.hrefs)} onclick={() => goto(tab.go)}>
			<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d={tab.icon}/></svg>
			<span>{tab.label()}</span>
		</button>
	{/each}
</nav>

<style>
	.tabbar {
		display: flex;
		position: fixed;
		left: 0;
		right: 0;
		bottom: 0;
		background: var(--c-surface);
		border-top: 1px solid var(--c-border);
		padding-bottom: var(--safe-bottom);
		z-index: 10;
	}

	@media (min-width: 760px) {
		.tabbar {
			display: none;
		}
	}

	.tab {
		flex: 1;
		display: flex;
		flex-direction: column;
		align-items: center;
		gap: 2px;
		padding: 8px 0 6px;
		color: var(--c-text-dim);
		font-size: 11px;
		font-weight: 500;
	}

	.tab svg {
		width: 20px;
		height: 20px;
	}

	.tab.active {
		color: var(--c-accent);
	}
</style>
