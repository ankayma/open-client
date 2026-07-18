<script lang="ts">
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import { activeLang, myRole } from '$lib/stores';
	import { STRINGS, type Lang } from '$lib/i18n';

	let lang = $state<Lang>('vn');
	activeLang.subscribe((l) => { lang = l; });

	let path = $derived(page.url.pathname);
	function active(hrefs: string[]): boolean {
		return hrefs.some((h) => path === h || path.startsWith(h + '/'));
	}

	const ALL_TABS = [
		{
			hrefs: ['/services'],
			go: '/services',
			label: () => STRINGS[lang].nav_services,
			icon: 'M3 7h18M3 12h18M3 17h18'
		},
		{
			hrefs: ['/admin', '/subdomains', '/members', '/access', '/policies'],
			go: '/admin',
			label: () => STRINGS[lang].nav_admin,
			icon: 'M3 11h18v11H3zM7 11V7a5 5 0 0110 0v4',
			adminOnly: true
		},
		{
			hrefs: ['/settings'],
			go: '/settings/devices',
			label: () => STRINGS[lang].nav_settings,
			// A proper settings gear (Feather "settings"): the lone center circle read
			// as a broken dot before.
			icon: 'M12 15a3 3 0 100-6 3 3 0 000 6z M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 11-2.83 2.83l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-4 0v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 11-2.83-2.83l.06-.06a1.65 1.65 0 00.33-1.82 1.65 1.65 0 00-1.51-1H3a2 2 0 010-4h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 112.83-2.83l.06.06a1.65 1.65 0 001.82.33H9a1.65 1.65 0 001-1.51V3a2 2 0 014 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 112.83 2.83l-.06.06a1.65 1.65 0 00-.33 1.82V9a1.65 1.65 0 001.51 1H21a2 2 0 010 4h-.09a1.65 1.65 0 00-1.51 1z'
		}
	];

	// Hide the admin tab from members. Fail open: until the role is known (null), keep
	// showing it — the server still gates every admin action, so this is UX only.
	let showAdmin = $derived($myRole === null || $myRole === 'admin');
	let tabs = $derived(ALL_TABS.filter((t) => t.adminOnly !== true || showAdmin));
</script>

<nav class="tabbar">
	{#each tabs as tab}
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
