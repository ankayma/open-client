<script lang="ts">
	import { goto } from '$app/navigation';
	import { auth, activeLang } from '$lib/stores';
	import { STRINGS, type Lang } from '$lib/i18n';

	let lang = $state<Lang>('vn');
	activeLang.subscribe((l) => { lang = l; });

	let tier = $derived($auth.status === 'authenticated' ? $auth.user.tier : '');
</script>

<main>
	<header>
		<h2>{STRINGS[lang].nav_admin}</h2>
	</header>

	<section class="quick-actions">
		<button class="quick-item" onclick={() => goto('/subdomains')}>
			<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8">
				<circle cx="12" cy="12" r="9"/><path d="M3.6 9h16.8M3.6 15h16.8M12 3a15 15 0 010 18"/>
			</svg>
			<span>Subdomains</span>
			<svg class="arrow" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
				<path d="M9 18l6-6-6-6"/>
			</svg>
		</button>
		<button class="quick-item" onclick={() => goto('/members')}>
			<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8">
				<path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 00-3-3.87M16 3.13a4 4 0 010 7.75"/>
			</svg>
			<span>{STRINGS[lang].nav_users}</span>
			<svg class="arrow" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
				<path d="M9 18l6-6-6-6"/>
			</svg>
		</button>
		<button class="quick-item" onclick={() => goto('/access')}>
			<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8">
				<rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/>
			</svg>
			<span>Access</span>
			<svg class="arrow" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
				<path d="M9 18l6-6-6-6"/>
			</svg>
		</button>
		<button class="quick-item" onclick={() => goto('/policies')}>
			<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8">
				<path d="M4 17l6-6-6-6M12 19h8"/>
			</svg>
			<span>Deploy Rules</span>
			<svg class="arrow" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
				<path d="M9 18l6-6-6-6"/>
			</svg>
		</button>
	</section>

	{#if tier === 'F0'}
		<section class="upgrade-banner">
			<div>
				<strong>F0-Plus — $9/mo</strong>
				<span>More bandwidth · Multiple subdomains · Raw TCP</span>
			</div>
			<button class="upgrade-btn" onclick={() => goto('/upgrade')}>Upgrade</button>
		</section>
	{/if}
</main>

<style>
	main {
		flex: 1;
		display: flex;
		flex-direction: column;
		padding: calc(var(--safe-top) + 16px) 16px calc(var(--safe-bottom) + 24px);
		gap: 16px;
		max-width: 420px;
		margin: 0 auto;
		width: 100%;
	}

	header {
		padding: 8px 0;
	}

	h2 {
		font-size: 22px;
		font-weight: 700;
	}

	.quick-actions {
		display: flex;
		flex-direction: column;
		gap: 2px;
		background: var(--c-surface);
		border: 1px solid var(--c-border);
		border-radius: var(--radius);
		overflow: hidden;
	}

	.quick-item {
		display: flex;
		align-items: center;
		gap: 12px;
		padding: 14px 16px;
		font-size: 14px;
		color: var(--c-text);
		width: 100%;
		text-align: left;
		border-bottom: 1px solid var(--c-border);
		transition: background 0.1s;
	}

	.quick-item:last-child { border-bottom: none; }
	.quick-item:hover { background: color-mix(in srgb, var(--c-accent) 6%, transparent); }
	.quick-item svg:first-child { color: var(--c-accent); flex-shrink: 0; }
	.quick-item span { flex: 1; }
	.quick-item .arrow { color: var(--c-text-dim); flex-shrink: 0; }

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
</style>
