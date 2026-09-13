<script lang="ts">
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { auth, activeLang } from '$lib/stores';
	import { STRINGS, type Lang } from '$lib/i18n';
	import { overview } from '$lib/tauri';
	import type { Overview, OverviewActivity, OverviewGrant, OverviewDelegation } from '$lib/types';

	let lang = $state<Lang>('vn');
	activeLang.subscribe((l) => { lang = l; });

	let tier = $derived($auth.status === 'authenticated' ? $auth.user.tier : '');

	let data = $state<Overview | null>(null);
	let loading = $state(true);
	let err = $state<string | null>(null);
	// Admin-only endpoint: a plain member gets 403 → show the nav, hide the panels.
	let forbidden = $state(false);
	// A ticking clock so grant TTL countdowns update live without re-fetching.
	let now = $state(Date.now());

	async function load() {
		loading = true;
		err = null;
		try {
			data = await overview();
			forbidden = false;
		} catch (e) {
			const msg = String(e);
			if (msg.includes('403')) { forbidden = true; }
			else { err = msg; }
		} finally {
			loading = false;
		}
	}

	onMount(() => {
		load();
		const t = setInterval(() => (now = Date.now()), 1000);
		return () => clearInterval(t);
	});

	// ── formatting helpers ────────────────────────────────────────────────────
	// event_type → a short ACTION label + which glyph. Unknown types fall back to
	// the raw type so nothing is hidden. [T:audit_events event set]
	type ActionKind = 'ssh' | 'open' | 'cicd' | 'elevate' | 'member' | 'node' | 'service' | 'other';
	function action(ev: string): { label: string; kind: ActionKind } {
		switch (ev) {
			case 'SshSessionOpened': return { label: 'SSH', kind: 'ssh' };
			// The private-URL visit: the request is peer-to-peer, so the app reports it
			// (POST /api/v1/subdomains/{fqdn}/opened) — nothing else can see it.
			case 'ServiceOpened': return { label: 'Open', kind: 'open' };
			case 'ElevationGranted': return { label: 'Elevate', kind: 'elevate' };
			case 'CiArtifactPublished':
			case 'CiDeployPolicyRegistered':
			case 'CiDeployPolicyRemoved': return { label: 'CI/CD', kind: 'cicd' };
			case 'CiDeployDenied':
			case 'CiArtifactDenied': return { label: 'Denied', kind: 'other' };
			case 'NodeEnrolled':
			case 'NodeRevoked':
			case 'NodeKeyRotated': return { label: 'Node', kind: 'node' };
			case 'MemberJoined':
			case 'MemberRemoved':
			case 'MemberInviteRevoked': return { label: 'Member', kind: 'member' };
			case 'SubdomainRegistered':
			case 'SubdomainRemoved':
			case 'ServiceTagsDeclared':
			case 'ServiceDataClassDeclared': return { label: 'Service', kind: 'service' };
			case 'GrantTerminated': return { label: 'Session end', kind: 'ssh' };
			case 'CommandApprovalRequested':
			case 'CommandApprovalDecided': return { label: 'Approval', kind: 'elevate' };
			case 'StepUpDowngradeRefused': return { label: 'Denied', kind: 'other' };
			case 'AuthFactorDisabled':
			case 'MemberFactorReset':
			case 'VendorFactorReset': return { label: 'Factor', kind: 'member' };
			case 'PolicyBlockSubmitted': return { label: 'Policy', kind: 'cicd' };
			case 'AgentIdentityIssued':
			case 'DelegationWithdrawn': return { label: 'Delegate', kind: 'cicd' };
			default: return { label: ev, kind: 'other' };
		}
	}

	// Best-effort target from the event payload — the CP shapes payload per event, so
	// try the common keys and fall back to blank rather than inventing a value.
	function target(a: OverviewActivity): string {
		const p = a.payload as Record<string, unknown> | null;
		if (!p || typeof p !== 'object') return '';
		// Most specific NAME first: a row about a service should read as the service,
		// not as the node id it happens to sit on (which is what `node_id` first gave).
		for (const k of ['fqdn', 'subdomain', 'label', 'hostname', 'node_id', 'node', 'email', 'repo', 'actor_id']) {
			const v = p[k];
			if (typeof v === 'string' && v) return v;
		}
		return '';
	}

	function actorOf(a: OverviewActivity): string {
		const p = a.payload as Record<string, unknown> | null;
		if (p && typeof p === 'object') {
			for (const k of ['email', 'actor_id', 'user_id', 'github_login', 'opened_by']) {
				const v = p[k];
				if (typeof v === 'string' && v) return v;
			}
		}
		// Resolved through the grant by the control plane. Falling back to the grant's
		// own id, as this did, put "grant grant_5f" in a column headed MEMBER — an
		// answer to a question nobody asked. A dash is the honest answer when no human
		// is attached to the event.
		return a.actor || '—';
	}

	function clockTime(iso: string): string {
		const d = new Date(iso);
		if (isNaN(d.getTime())) return iso;
		return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
	}

	// TTL remaining, in "12m" / "45s" / "expired" form, recomputed as `now` ticks.
	function remaining(iso: string, _now: number): string {
		const end = new Date(iso).getTime();
		if (isNaN(end)) return '';
		const ms = end - _now;
		if (ms <= 0) return 'expired';
		const s = Math.floor(ms / 1000);
		if (s < 60) return `${s}s left`;
		const m = Math.floor(s / 60);
		if (m < 60) return `${m}m left`;
		return `${Math.floor(m / 60)}h ${m % 60}m left`;
	}
	// How full the TTL bar is: fraction of the grant's lifetime still remaining.
	function ttlPct(g: OverviewGrant | OverviewDelegation, _now: number): number {
		const startIso = 'issued_at' in g ? g.issued_at : g.opened_at;
		const end = new Date(g.expires_at).getTime();
		const start = new Date(startIso).getTime();
		if (isNaN(end) || isNaN(start) || end <= start) return 0;
		const pct = ((end - _now) / (end - start)) * 100;
		return Math.max(0, Math.min(100, pct));
	}

	function short(id: string, n = 10): string {
		return id.length > n ? id.slice(0, n) + '…' : id;
	}
</script>

<main>
	<header>
		<div class="title">
			<h2>Tenant Overview</h2>
			<p class="sub">What is happening, who accessed what</p>
		</div>
		<button class="refresh" onclick={load} disabled={loading} aria-label="Refresh">
			<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8">
				<path d="M21 12a9 9 0 11-2.6-6.3M21 3v6h-6"/>
			</svg>
		</button>
	</header>

	<!-- Section navigation. Stays ABOVE the overview: this route is the Admin MENU
	     first and a dashboard second, and putting the panels first buried every
	     admin section under a screenful of activity — reachable only by scrolling
	     past it, which reads as "the tabs are gone". -->
	<section class="quick-actions">
		<button class="quick-item" onclick={() => goto('/subdomains')}>
			<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8">
				<circle cx="12" cy="12" r="9"/><path d="M3.6 9h16.8M3.6 15h16.8M12 3a15 15 0 010 18"/>
			</svg>
			<span>Subdomains</span>
			<svg class="arrow" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 18l6-6-6-6"/></svg>
		</button>
		<button class="quick-item" onclick={() => goto('/members')}>
			<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8">
				<path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 00-3-3.87M16 3.13a4 4 0 010 7.75"/>
			</svg>
			<span>{STRINGS[lang].nav_users}</span>
			<svg class="arrow" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 18l6-6-6-6"/></svg>
		</button>
		<button class="quick-item" onclick={() => goto('/access')}>
			<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8">
				<rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/>
			</svg>
			<span>Access</span>
			<svg class="arrow" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 18l6-6-6-6"/></svg>
		</button>
		<button class="quick-item" onclick={() => goto('/policies')}>
			<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M4 17l6-6-6-6M12 19h8"/></svg>
			<span>Deploy Rules</span>
			<svg class="arrow" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 18l6-6-6-6"/></svg>
		</button>
		<button class="quick-item" onclick={() => goto('/governance')}>
			<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M12 3l8 4v6c0 4-3.5 7-8 8-4.5-1-8-4-8-8V7z"/></svg>
			<span>Governance</span>
			<svg class="arrow" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 18l6-6-6-6"/></svg>
		</button>
	</section>

	{#if forbidden}
		<section class="notice">Tenant overview is an admin-only view.</section>
	{:else if err}
		<section class="notice err">Could not load overview — {err}</section>
	{:else if loading && !data}
		<section class="notice">Loading…</section>
	{:else if data}
		<!-- Panel 1 — stat tiles -->
		<section class="tiles">
			<div class="tile">
				<div class="tile-label">NODES</div>
				<div class="tile-val">
					{data.fleet.nodes_seen_5m}<span class="dim">/{data.fleet.nodes_total}</span>
					<span class="tile-note">checked in &lt;5m</span>
				</div>
			</div>
			<div class="tile">
				<div class="tile-label">MEMBERS</div>
				<div class="tile-val">{data.fleet.members_total}
					<span class="tile-note">{data.fleet.members_by_seat.map((s) => `${s.count} ${s.seat_type}`).join(' · ')}</span>
				</div>
			</div>
			<div class="tile">
				<div class="tile-label">SERVICES</div>
				<div class="tile-val">{data.fleet.services_total}<span class="tile-note">private subdomains</span></div>
			</div>
			<div class="tile">
				<div class="tile-label">ACTIVE GRANTS</div>
				<div class="tile-val">{data.grants.length + data.delegations.length}
					<span class="tile-note">{data.grants.length} grant · {data.delegations.length} delegated</span>
				</div>
			</div>
		</section>

		<div class="grid">
			<!-- Panel 2 — access activity -->
			<section class="card activity">
				<div class="card-head">
					<div>
						<h3>Access activity</h3>
						<p class="sub">who → what, from the tenant ledger</p>
					</div>
				</div>
				{#if data.activity.length === 0}
					<p class="empty">No recent events.</p>
				{:else}
					<div class="act-head">
						<span>TIME</span><span>MEMBER</span><span>ACTION</span><span>TARGET</span>
					</div>
					<div class="act-rows">
						{#each data.activity as a (a.id)}
							{@const act = action(a.event_type)}
							<div class="act-row">
								<span class="t">{clockTime(a.created_at)}</span>
								<span class="who" title={actorOf(a)}>{short(actorOf(a), 20)}</span>
								<span class="act act-{act.kind}">{act.label}</span>
								<span class="tgt" title={target(a)}>{target(a) || '—'}</span>
							</div>
						{/each}
					</div>
				{/if}
			</section>

			<div class="col">
				<!-- Panel 3 — active grants -->
				<section class="card">
					<div class="card-head"><h3>Active grants</h3></div>
					{#if data.grants.length === 0 && data.delegations.length === 0}
						<p class="empty">No live grants.</p>
					{:else}
						{#each data.grants as g (g.grant_id)}
							<div class="grant">
								<div class="grant-line">
									<span class="grant-what">
										{g.kind === 'command' ? 'Command' : 'Session'} ·
										{short(g.actor_id, 16)}{g.node_id ? ' → ' + short(g.node_id, 12) : ''}
									</span>
									<span class="grant-ttl">{remaining(g.expires_at, now)}</span>
								</div>
								<div class="bar"><div class="bar-fill" style="width:{ttlPct(g, now)}%"></div></div>
							</div>
						{/each}
						{#each data.delegations as d (d.window_id)}
							<div class="grant">
								<div class="grant-line">
									<span class="grant-what">Delegated · {short(d.agent_actor_id, 16)} <span class="ai">AI</span></span>
									<span class="grant-ttl">{remaining(d.expires_at, now)}</span>
								</div>
								<div class="bar"><div class="bar-fill warn" style="width:{ttlPct(d, now)}%"></div></div>
							</div>
						{/each}
					{/if}
				</section>

				<!-- Panel 4 — alerts -->
				<section class="card">
					<div class="card-head">
						<h3>Alerts</h3>
						{#if data.alerts.pending_approvals > 0}
							<span class="badge">{data.alerts.pending_approvals} pending</span>
						{/if}
					</div>
					{#if data.alerts.stale_nodes.length === 0 && data.alerts.recent_denies.length === 0 && data.alerts.pending_approvals === 0}
						<p class="empty ok">Nothing needs attention.</p>
					{:else}
						{#each data.alerts.recent_denies as dny}
							<div class="alert danger">
								<span class="dot"></span>
								<div><div class="al-t">{dny.event_type}</div><div class="al-s">{clockTime(dny.created_at)}</div></div>
							</div>
						{/each}
						{#if data.alerts.pending_approvals > 0}
							<div class="alert warn">
								<span class="dot"></span>
								<div><div class="al-t">{data.alerts.pending_approvals} command approval(s) waiting</div></div>
							</div>
						{/if}
						{#each data.alerts.stale_nodes as n}
							<div class="alert warn">
								<span class="dot"></span>
								<div>
									<div class="al-t">Node not checked in: {n.hostname || short(n.node_id, 16)}</div>
									<div class="al-s">{n.last_seen_at ? 'last seen ' + clockTime(n.last_seen_at) : 'never'}</div>
								</div>
							</div>
						{/each}
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

	/* Stat tiles */
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
	.empty { font-size: 13px; color: var(--c-text-dim); }
	.empty.ok { color: var(--c-success); }
	.badge { font-size: 11px; font-weight: 600; padding: 2px 9px; border-radius: 999px;
		background: color-mix(in srgb, var(--c-warn) 14%, transparent);
		border: 1px solid color-mix(in srgb, var(--c-warn) 40%, transparent); color: var(--c-warn); }

	/* Activity table */
	.act-head, .act-row {
		display: grid; grid-template-columns: 52px minmax(0, 1fr) 74px minmax(0, 1.1fr);
		gap: 8px; align-items: center;
	}
	.act-head { font-size: 11px; font-weight: 600; color: var(--c-text-dim); letter-spacing: 0.03em; padding: 0 8px; }
	/* Twenty rows is taller than most windows; let the list scroll inside the card so
	   the page stays one screen and nothing below it gets pushed out of sight. */
	.act-rows { display: flex; flex-direction: column; gap: 2px; max-height: 420px; overflow-y: auto; }
	.act-row { font-size: 13px; padding: 8px; border-radius: 8px; }
	.act-row:nth-child(odd) { background: color-mix(in srgb, var(--c-bg) 45%, transparent); }
	.act-row .t { color: var(--c-text-dim); font-size: 12px; }
	.act-row .who, .act-row .tgt { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
	.act-row .tgt { color: var(--c-text-dim); }
	.act { font-size: 12px; font-weight: 600; }
	.act-ssh, .act-node { color: var(--c-text); }
	.act-elevate { color: var(--c-warn); }
	.act-cicd { color: var(--c-accent); }
	.act-open, .act-service, .act-member { color: var(--c-text); }
	.act-other { color: var(--c-text-dim); }

	/* Grants */
	.grant { display: flex; flex-direction: column; gap: 6px; }
	.grant-line { display: flex; align-items: center; gap: 8px; font-size: 13px; }
	.grant-what { flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
	.grant-ttl { font-size: 12px; color: var(--c-text-dim); flex-shrink: 0; }
	.ai { font-size: 10px; font-weight: 700; padding: 1px 6px; border-radius: 999px;
		background: color-mix(in srgb, var(--c-warn) 14%, transparent);
		border: 1px solid color-mix(in srgb, var(--c-warn) 40%, transparent); color: var(--c-warn); }
	.bar { height: 4px; border-radius: 999px; background: color-mix(in srgb, var(--c-bg) 50%, var(--c-border)); overflow: hidden; }
	.bar-fill { height: 4px; border-radius: 999px; background: var(--c-accent); }
	.bar-fill.warn { background: var(--c-warn); }

	/* Alerts */
	.alert { display: flex; gap: 10px; padding: 10px 12px; border-radius: 8px; align-items: flex-start; }
	.alert .dot { width: 8px; height: 8px; border-radius: 50%; margin-top: 5px; flex-shrink: 0; }
	.alert.danger { background: color-mix(in srgb, var(--c-danger) 8%, transparent);
		border: 1px solid color-mix(in srgb, var(--c-danger) 35%, transparent); }
	.alert.danger .dot { background: var(--c-danger); }
	.alert.warn { background: color-mix(in srgb, var(--c-warn) 7%, transparent);
		border: 1px solid color-mix(in srgb, var(--c-warn) 30%, transparent); }
	.alert.warn .dot { background: var(--c-warn); }
	.al-t { font-size: 13px; color: var(--c-text); }
	.al-s { font-size: 12px; color: var(--c-text-dim); }

	/* Section nav (unchanged behaviour) */
	.quick-actions { display: flex; flex-direction: column; gap: 2px; background: var(--c-surface);
		border: 1px solid var(--c-border); border-radius: var(--radius); overflow: hidden; }
	.quick-item { display: flex; align-items: center; gap: 12px; padding: 14px 16px; font-size: 14px;
		color: var(--c-text); width: 100%; text-align: left; border-bottom: 1px solid var(--c-border); transition: background 0.1s; }
	.quick-item:last-child { border-bottom: none; }
	.quick-item:hover { background: color-mix(in srgb, var(--c-accent) 6%, transparent); }
	.quick-item svg:first-child { color: var(--c-accent); flex-shrink: 0; }
	.quick-item span { flex: 1; }
	.quick-item .arrow { color: var(--c-text-dim); flex-shrink: 0; }

	.upgrade-banner { background: color-mix(in srgb, var(--c-accent) 10%, var(--c-surface));
		border: 1px solid color-mix(in srgb, var(--c-accent) 30%, transparent); border-radius: var(--radius);
		padding: 16px; display: flex; align-items: center; justify-content: space-between; gap: 12px; }
	.upgrade-banner strong { display: block; font-size: 14px; margin-bottom: 2px; }
	.upgrade-banner span { font-size: 12px; color: var(--c-text-dim); }
	.upgrade-btn { background: var(--c-accent); color: #fff; padding: 10px 18px; border-radius: 8px;
		font-size: 14px; font-weight: 600; white-space: nowrap; flex-shrink: 0; }

	/* Desktop: two-column main grid + wider activity table */
	@media (min-width: 860px) {
		.tiles { grid-template-columns: repeat(4, minmax(0, 1fr)); }
		.grid { grid-template-columns: minmax(0, 1.7fr) minmax(0, 1fr); align-items: start; }
		.act-head, .act-row { grid-template-columns: 60px minmax(0, 1fr) 84px minmax(0, 1.2fr); }
		/* One segmented bar instead of five stacked rows: the sections have to be
		   visible with the overview, not instead of it. The phone keeps the list. */
		.quick-actions { flex-direction: row; flex-wrap: wrap; gap: 0; }
		.quick-item { width: auto; flex: 1 1 0; justify-content: center; gap: 8px;
			padding: 12px 14px; border-bottom: none; border-right: 1px solid var(--c-border); }
		.quick-item:last-child { border-right: none; }
		.quick-item span { flex: 0 1 auto; }
		.quick-item .arrow { display: none; }
	}
</style>
