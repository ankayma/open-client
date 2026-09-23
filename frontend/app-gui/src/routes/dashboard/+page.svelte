<script lang="ts">
	// Every user's own dashboard. Deliberately NOT a smaller copy of the tenant view:
	// the tenant one answers "who in this company accessed what" (admin capability,
	// A.1.15), this one answers "what did I do, what is open in my name" — the
	// my-access view A.1.2 leaves to the member. Same read-model, caller as its scope.
	// [T:part-d-tenant-dashboard.md §H.2]
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { auth, activeLang } from '$lib/stores';
	import { STRINGS, type Lang } from '$lib/i18n';
	import { myOverview } from '$lib/tauri';
	import type { MyOverview } from '$lib/types';
	import { clockTime, short } from '$lib/overview-format';
	import ActivityTable from '$lib/components/ActivityTable.svelte';
	import GrantList from '$lib/components/GrantList.svelte';

	let lang = $state<Lang>('vn');
	activeLang.subscribe((l) => { lang = l; });

	let email = $derived($auth.status === 'authenticated' ? $auth.user.email : '');
	let tier  = $derived($auth.status === 'authenticated' ? $auth.user.tier : '');

	let data = $state<MyOverview | null>(null);
	let loading = $state(true);
	let err = $state<string | null>(null);

	async function load() {
		loading = true;
		err = null;
		try {
			data = await myOverview();
		} catch (e) {
			err = String(e);
		} finally {
			loading = false;
		}
	}

	onMount(load);
</script>

<main>
	<header>
		<div class="title">
			<h2>{STRINGS[lang].my_dashboard_title}</h2>
			<p class="sub">{email}</p>
		</div>
		<button class="refresh" onclick={load} disabled={loading} aria-label="Refresh">
			<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8">
				<path d="M21 12a9 9 0 11-2.6-6.3M21 3v6h-6"/>
			</svg>
		</button>
	</header>

	{#if err}
		<section class="notice err">{STRINGS[lang].my_dashboard_err} — {err}</section>
	{:else if loading && !data}
		<section class="notice">Loading…</section>
	{:else if data}
		<section class="tiles">
			<div class="tile">
				<div class="tile-label">{STRINGS[lang].my_devices_label}</div>
				<div class="tile-val">
					{data.fleet.nodes_seen_5m}<span class="dim">/{data.fleet.nodes_total}</span>
					<span class="tile-note">{STRINGS[lang].checked_in_5m}</span>
				</div>
			</div>
			<div class="tile">
				<div class="tile-label">{STRINGS[lang].my_grants_label}</div>
				<div class="tile-val">
					{data.grants.length + data.delegations.length}
					<span class="tile-note">
						{data.grants.length} grant · {data.delegations.length} delegated
					</span>
				</div>
			</div>
		</section>

		<div class="grid">
			<section class="card">
				<div class="card-head">
					<div>
						<h3>{STRINGS[lang].my_activity_title}</h3>
						<p class="sub">{STRINGS[lang].my_activity_sub}</p>
					</div>
				</div>
				<!-- No MEMBER column: every row here is the same person. -->
				<ActivityTable activity={data.activity} showMember={false} />
			</section>

			<div class="col">
				<section class="card">
					<div class="card-head"><h3>{STRINGS[lang].my_grants_title}</h3></div>
					<GrantList
						grants={data.grants}
						delegations={data.delegations}
						empty={STRINGS[lang].my_grants_empty}
					/>
				</section>

				{#if data.alerts.stale_nodes.length > 0}
					<section class="card">
						<div class="card-head"><h3>{STRINGS[lang].my_devices_attention}</h3></div>
						{#each data.alerts.stale_nodes as n}
							<div class="alert warn">
								<span class="dot"></span>
								<div>
									<div class="al-t">{n.hostname || short(n.node_id, 16)}</div>
									<div class="al-s">
										{n.last_seen_at ? 'last seen ' + clockTime(n.last_seen_at) : 'never checked in'}
									</div>
								</div>
							</div>
						{/each}
					</section>
				{/if}

				<section class="card links">
					<button onclick={() => goto('/services')}>{STRINGS[lang].nav_services} →</button>
					<button onclick={() => goto('/settings/devices')}>{STRINGS[lang].nav_devices} →</button>
					{#if data.me.role === 'admin'}
						<button onclick={() => goto('/admin')}>{STRINGS[lang].tenant_overview_title} →</button>
					{/if}
				</section>
			</div>
		</div>
	{/if}

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
		width: 100%;
	}

	header { display: flex; align-items: center; gap: 12px; padding: 8px 0 0; }
	.title { flex: 1; }
	h2 { font-size: 22px; font-weight: 700; }
	.sub { font-size: 12.5px; color: var(--c-text-dim); margin-top: 2px; }
	.refresh {
		width: 34px; height: 34px; display: flex; align-items: center; justify-content: center;
		border: 1px solid var(--c-border); border-radius: 10px; background: var(--c-surface);
		color: var(--c-text-dim); flex-shrink: 0;
	}
	.refresh:hover { color: var(--c-text); }
	.refresh:disabled { opacity: 0.5; }

	.notice { padding: 18px; background: var(--c-surface); border: 1px solid var(--c-border);
		border-radius: var(--radius); color: var(--c-text-dim); font-size: 14px; }
	.notice.err { color: var(--c-danger); border-color: color-mix(in srgb, var(--c-danger) 40%, transparent); }

	.tiles { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; }
	.tile { background: var(--c-surface); border: 1px solid var(--c-border); border-radius: var(--radius);
		padding: 14px 16px; display: flex; flex-direction: column; gap: 4px; }
	.tile-label { font-size: 11.5px; font-weight: 600; color: var(--c-text-dim); letter-spacing: 0.03em; }
	.tile-val { font-size: 24px; font-weight: 700; display: flex; align-items: baseline; gap: 8px; flex-wrap: wrap; }
	.tile-val .dim { font-size: 15px; color: var(--c-text-dim); font-weight: 500; }
	.tile-note { font-size: 11.5px; color: var(--c-text-dim); font-weight: 500; }

	.grid { display: grid; grid-template-columns: 1fr; gap: 12px; }
	.col { display: flex; flex-direction: column; gap: 12px; }

	.card { background: var(--c-surface); border: 1px solid var(--c-border); border-radius: var(--radius);
		padding: 16px 18px; display: flex; flex-direction: column; gap: 12px; }
	.card-head { display: flex; align-items: center; gap: 10px; }
	.card-head h3 { font-size: 14px; font-weight: 600; flex: 1; }

	.links { gap: 2px; }
	.links button { text-align: left; font-size: 13px; color: var(--c-accent); padding: 6px 0; }

	.alert { display: flex; gap: 10px; padding: 10px 12px; border-radius: 8px; align-items: flex-start; }
	.alert .dot { width: 8px; height: 8px; border-radius: 50%; margin-top: 5px; flex-shrink: 0; }
	.alert.warn { background: color-mix(in srgb, var(--c-warn) 7%, transparent);
		border: 1px solid color-mix(in srgb, var(--c-warn) 30%, transparent); }
	.alert.warn .dot { background: var(--c-warn); }
	.al-t { font-size: 13px; color: var(--c-text); }
	.al-s { font-size: 12px; color: var(--c-text-dim); }

	.upgrade-banner { background: color-mix(in srgb, var(--c-accent) 10%, var(--c-surface));
		border: 1px solid color-mix(in srgb, var(--c-accent) 30%, transparent); border-radius: var(--radius);
		padding: 16px; display: flex; align-items: center; justify-content: space-between; gap: 12px; }
	.upgrade-banner strong { display: block; font-size: 14px; margin-bottom: 2px; }
	.upgrade-banner span { font-size: 12px; color: var(--c-text-dim); }
	.upgrade-btn { background: var(--c-accent); color: #fff; padding: 10px 18px; border-radius: 8px;
		font-size: 14px; font-weight: 600; white-space: nowrap; flex-shrink: 0; }

	@media (min-width: 860px) {
		.tiles { grid-template-columns: repeat(4, minmax(0, 1fr)); }
		.grid { grid-template-columns: minmax(0, 1.7fr) minmax(0, 1fr); align-items: start; }
	}
</style>
