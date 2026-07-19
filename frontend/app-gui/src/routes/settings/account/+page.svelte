<script lang="ts">
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { invoke } from '@tauri-apps/api/core';
	import { getVersion } from '@tauri-apps/api/app';
	import { auth, quota } from '$lib/stores';
	import { signOut, getNodeInfo, getQuota } from '$lib/tauri';
	import type { NodeInfo } from '$lib/types';

	let signing_out = $state(false);
	let nodeInfo = $state<NodeInfo | null>(null);
	let addingAdmin = $state(false);
	let addonError = $state('');

	// Buy one +$9 admin add-on (Model B): a distinct add-on subscription the control plane
	// maps to `admins_included += 1` (and member cap +1). Opens the LS checkout in the
	// browser like any other plan. [T:pricing.md §2 Admin thêm]
	async function addAdminSeat() {
		addingAdmin = true;
		addonError = '';
		try {
			await invoke('open_billing_checkout', { plan: 'admin-addon' });
		} catch (e) {
			addonError = String(e);
		} finally {
			addingAdmin = false;
		}
	}
	// Read the real bundle version at runtime so it can never drift from the
	// shipped build (was hard-coded to 0.1.0 and went stale). [T:tauri-api-app@2]
	let appVersion = $state('');

	// Upgrade ladder per Pricing SSOT (pricing.md §4 — cửa chuyển tier): every tier
	// below the top has a path up (F0→F0-Plus→F1 team→grow/add-admin). All route to
	// /upgrade, the plan picker. Previously the banner only rendered for F0, so a paid
	// F0-Plus user had no visible way to start a team. [T:pricing.md §4]
	const UPGRADE: Record<string, { title: string; sub: string; cta: string }> = {
		'F0': { title: 'Upgrade to F0-Plus', sub: '$9/mo · more nodes, private domains, raw TCP & step-up 2FA', cta: 'Upgrade' },
		'F0-Plus': { title: 'Start a team — F1', sub: 'Invite people and keep your $9 seat — you become the admin', cta: 'See team plans' },
		'F1-Starter': { title: 'Grow your team', sub: 'Add seats up to 25, or an extra admin (+$9/mo)', cta: 'Manage plan' }
	};
	let upgrade = $derived($auth.status === 'authenticated' ? UPGRADE[$auth.user.tier] : undefined);

	onMount(async () => {
		try {
			nodeInfo = await getNodeInfo();
		} catch {
			// daemon not connected or not enrolled
		}
		try {
			// Node quota is enforced tenant-/seat-wide by the control plane — show the
			// real used/limit, not a hard-coded number (BM R8.1: quota reads from config).
			quota.set(await getQuota());
		} catch {
			// not enrolled / offline — leave the last known value
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
			<!-- Two orthogonal dimensions (Part B §B.1.8 SeatType, choice A):
			     Seat type = your quota (node/domain) · Role = what you can manage. -->
			{#if $auth.user.tier !== 'F0'}
				<div class="row">
					<span class="label">Seat type</span>
					<span class="value">
						<span class="tier-badge">{({ admin: 'Admin', builder: 'Builder', user: 'User', lite: 'Lite' })[$auth.user.seat_type] ?? $auth.user.seat_type}</span>
						{#if $auth.user.tier === 'F1-Starter'}
							<span style="color:var(--c-text-dim);font-size:12px;margin-left:6px;">· {$auth.user.seat_node_cap} nodes · {$auth.user.seat_privdomain_cap} domains</span>
						{/if}
					</span>
				</div>
			{/if}
			<div class="row">
				<span class="label">Role</span>
				<span class="value">{$auth.user.role === 'admin' ? 'Admin' : 'Member'}</span>
			</div>
			{#if $quota}
				<div class="row">
					<span class="label">Nodes</span>
					<span class="value">{$quota.nodes_used} / {$quota.nodes_limit}</span>
				</div>
			{/if}
		</section>

		{#if upgrade}
			<section class="upgrade-banner">
				<div>
					<strong>{upgrade.title}</strong>
					<span>{upgrade.sub}</span>
				</div>
				<div class="banner-actions">
					<button class="upgrade-btn" onclick={() => goto('/upgrade')}>{upgrade.cta}</button>
					{#if $auth.user.tier === 'F1-Starter'}
						<button class="addon-btn" onclick={addAdminSeat} disabled={addingAdmin}>
							{addingAdmin ? 'Opening…' : 'Add admin +$9'}
						</button>
					{/if}
				</div>
			</section>
			{#if addonError}
				<p class="addon-error">{addonError}</p>
			{/if}
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

	.banner-actions {
		display: flex;
		flex-direction: column;
		gap: 8px;
		flex-shrink: 0;
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

	.addon-btn {
		background: transparent;
		color: var(--c-accent);
		border: 1px solid color-mix(in srgb, var(--c-accent) 40%, transparent);
		padding: 8px 18px;
		border-radius: 8px;
		font-size: 13px;
		font-weight: 600;
		white-space: nowrap;
	}

	.addon-btn:disabled {
		opacity: 0.6;
		cursor: not-allowed;
	}

	.addon-error {
		font-size: 12px;
		color: var(--c-danger, #e5484d);
		text-align: center;
		margin-top: -8px;
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
