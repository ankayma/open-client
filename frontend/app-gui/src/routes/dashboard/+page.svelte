<script lang="ts">
	import { goto } from '$app/navigation';
	import { onMount, onDestroy } from 'svelte';
	import { auth, connection, quota } from '$lib/stores';
	import {
		connect,
		disconnect,
		getQuota,
		getConnectionStatus,
		getPathProof,
		startDataplane,
		stopDataplane,
		getDataplaneStatus,
		type DataplaneStatus,
		vpnConnect,
		vpnDisconnect,
		getPlatform
	} from '$lib/tauri';
	import type { PathProof } from '$lib/types';

	let toggling = $state(false);
	let connectError = $state<string | null>(null);
	let proof = $state<PathProof | null>(null);
	let proving = $state(false);
	let tunnelBusy = $state(false);
	let tunnelMsg = $state<string | null>(null);
	let dp = $state<DataplaneStatus | null>(null);
	// iOS runs the data plane in-app (Packet Tunnel extension); desktop hands off to
	// the privileged daemon. The connect toggle picks the path from this. [T:A.1.9]
	let isIos = $state(false);

	// [slice 2] Poll the daemon's live status so the card reflects the REAL tunnel
	// (heartbeat fresh = up), not just enrollment.
	async function refreshDataplane() {
		try {
			dp = await getDataplaneStatus();
		} catch {
			dp = null;
		}
	}
	let dpTimer: ReturnType<typeof setInterval> | undefined;
	onMount(() => {
		getPlatform()
			.then((os) => (isIos = os === 'ios'))
			.catch(() => (isIos = false));
		refreshDataplane();
		dpTimer = setInterval(refreshDataplane, 4000);
	});
	onDestroy(() => clearInterval(dpTimer));

	// [milestone 1.2] Bring up / tear down the real WireGuard tunnel via the
	// privileged daemon (macOS admin prompt). The GUI enrolls; the daemon owns the
	// utun (needs root).
	async function startTunnel() {
		tunnelBusy = true;
		tunnelMsg = null;
		try {
			await startDataplane();
			tunnelMsg = 'Secure tunnel daemon launched — bringing the tunnel up…';
			setTimeout(refreshDataplane, 1500);
		} catch (e) {
			tunnelMsg = e instanceof Error ? e.message : String(e);
		} finally {
			tunnelBusy = false;
		}
	}

	async function stopTunnel() {
		tunnelBusy = true;
		tunnelMsg = null;
		try {
			await stopDataplane();
			setTimeout(refreshDataplane, 1000);
		} catch (e) {
			tunnelMsg = e instanceof Error ? e.message : String(e);
		} finally {
			tunnelBusy = false;
		}
	}

	// [F-5 "Prove it"] On demand, show that traffic is peer-to-peer and the vendor is
	// never on the data path (A.1.1) — the differentiator, demoable from F0.
	async function proveIt() {
		proving = true;
		try {
			proof = await getPathProof();
		} catch (e) {
			console.error(e);
		} finally {
			proving = false;
		}
	}

	async function toggleConnection() {
		toggling = true;
		connectError = null;
		try {
			const conn = $connection;
			if (conn.status === 'connected') {
				// iOS tears down the in-app Packet Tunnel; desktop just un-enrolls
				// (the daemon tunnel is stopped via stopTunnel).
				if (isIos) await vpnDisconnect();
				else await disconnect();
				connection.set({ status: 'disconnected' });
			} else {
				connection.set({ status: 'connecting' });
				// iOS: enroll + bring the Packet Tunnel up in one step. Desktop: enroll
				// only (the real tunnel comes up via the daemon / startTunnel).
				if (isIos) await vpnConnect();
				else await connect();
				// Reflect the real post-enrollment status (Connected + node_id).
				connection.set(await getConnectionStatus());
			}
		} catch (e) {
			connection.set({ status: 'disconnected' });
			// Surface the control plane's reason (e.g. device quota reached) instead
			// of failing silently — on mobile there's no console to inspect.
			connectError = e instanceof Error ? e.message : String(e);
		} finally {
			toggling = false;
		}
	}

	async function refreshQuota() {
		try {
			const q = await getQuota();
			quota.set(q);
		} catch {}
	}

	function formatBytes(bytes: number): string {
		if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
		if (bytes < 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
		return `${(bytes / 1024 / 1024 / 1024).toFixed(2)} GB`;
	}

	let quotaPct = $derived(
		$quota ? Math.min(100, ($quota.bandwidth_bytes_used / $quota.bandwidth_bytes_limit) * 100) : 0
	);

	let quotaWarn = $derived(quotaPct >= 80);
	let quotaCritical = $derived(quotaPct >= 95);
</script>

<main>
	<header>
		<h2>Ankayma</h2>
		<div class="header-actions">
			<button class="icon-btn" aria-label="Settings" onclick={() => goto('/settings')}>
				<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8">
					<circle cx="12" cy="12" r="3"/>
					<path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 010 2.83 2 2 0 01-2.83 0l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-4 0v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83-2.83l.06-.06A1.65 1.65 0 004.68 15a1.65 1.65 0 00-1.51-1H3a2 2 0 010-4h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 012.83-2.83l.06.06A1.65 1.65 0 009 4.68a1.65 1.65 0 001-1.51V3a2 2 0 014 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 012.83 2.83l-.06.06A1.65 1.65 0 0019.4 9a1.65 1.65 0 001.51 1H21a2 2 0 010 4h-.09a1.65 1.65 0 00-1.51 1z"/>
				</svg>
			</button>
		</div>
	</header>

	<section class="connection-card">
		{#if $connection.status === 'connected'}
			<div class="status-indicator connected"></div>
			<div class="status-text">
				<span class="status-label connected">Connected</span>
				{#if $connection.status === 'connected'}
					<span class="node-id">{$connection.node_id}</span>
				{/if}
			</div>
		{:else if $connection.status === 'connecting'}
			<div class="status-indicator connecting"></div>
			<div class="status-text">
				<span class="status-label">Connecting…</span>
			</div>
		{:else}
			<div class="status-indicator"></div>
			<div class="status-text">
				<span class="status-label">Disconnected</span>
				<span class="status-sub">Tap to connect</span>
			</div>
		{/if}

		<button
			class="toggle-btn"
			class:active={$connection.status === 'connected'}
			onclick={toggleConnection}
			disabled={toggling || $connection.status === 'connecting'}
			aria-label={$connection.status === 'connected' ? 'Disconnect' : 'Connect'}
		>
			<svg width="32" height="32" viewBox="0 0 24 24" fill="currentColor">
				<path d="M13 3h-2v10h2V3zm4.83 2.17l-1.42 1.42A6.92 6.92 0 0119 12c0 3.87-3.13 7-7 7A7 7 0 015 12c0-1.68.59-3.22 1.58-4.42L5.17 6.17A8.932 8.932 0 003 12c0 4.97 4.03 9 9 9s9-4.03 9-9c0-2.74-1.23-5.18-3.17-6.83z"/>
			</svg>
		</button>

		{#if connectError}
			<p class="connect-error">{connectError}</p>
		{/if}

		{#if $connection.status === 'connected'}
			{#if dp?.running}
				<p style="margin-top:10px;font-size:13px;color:var(--c-success, #34d399);text-align:center;">
					🔒 Secure tunnel up · {dp.peers.length} peer{dp.peers.length === 1 ? '' : 's'}
				</p>
				<button
					class="tunnel-btn"
					style="margin-top:8px;padding:10px 16px;border:1px solid var(--c-border);border-radius:8px;font-size:13px;color:var(--c-text-dim);background:transparent;"
					onclick={stopTunnel}
					disabled={tunnelBusy}
				>
					{tunnelBusy ? 'Stopping…' : 'Stop tunnel'}
				</button>
			{:else}
				<button
					class="tunnel-btn"
					style="margin-top:10px;padding:10px 16px;border:1px solid var(--c-border);border-radius:8px;font-size:13px;color:var(--c-text);background:var(--c-surface);"
					onclick={startTunnel}
					disabled={tunnelBusy}
				>
					{tunnelBusy ? 'Starting…' : 'Bring up secure tunnel (admin)'}
				</button>
			{/if}
			{#if tunnelMsg}
				<p style="font-size:12px;color:var(--c-text-dim);text-align:center;margin-top:6px;overflow-wrap:anywhere;max-width:100%;">{tunnelMsg}</p>
			{/if}
		{/if}
	</section>

	<!-- [F-5 "Prove it"] The differentiator: prove the vendor is not on your data path. -->
	{#if $connection.status === 'connected'}
		<section class="prove-card">
			<div class="prove-head">
				<span>Prove it</span>
				<button class="prove-btn" onclick={proveIt} disabled={proving}>
					{proving ? 'Checking…' : 'Show data path'}
				</button>
			</div>

			{#if proof}
				<div class="prove-row vendor">
					<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
						<path d="M9 12l2 2 4-4"/>
						<circle cx="12" cy="12" r="9"/>
					</svg>
					<span>Vendor is <strong>not on the data path</strong> — control channel only</span>
				</div>

				{#if proof.peers.length > 0}
					{#each proof.peers as p (p.overlay_ip)}
						<div class="prove-row">
							<span class="peer-name">{p.hostname}</span>
							<span class="peer-path">
								{p.direct ? 'direct WireGuard' : 'peer-to-peer'}
								{#if p.endpoint}<code>{p.endpoint}</code>{/if}
							</span>
						</div>
					{/each}
				{:else}
					<div class="prove-row muted">
						No peers yet — connect another device to see the peer-to-peer path.
					</div>
				{/if}
			{:else}
				<p class="prove-hint">
					Your traffic goes peer-to-peer over WireGuard. Tap to see the live path —
					no hop through the vendor.
				</p>
			{/if}

			<!-- [F-5 / ND-A1] Coexistence proof: the "won't touch production" promise
			     as a positive artifact (A.1.5). Structural — not a live measurement. -->
			<div class="coexist">
				<p class="coexist-label">Coexistence</p>
				<div class="coexist-paths">
					<div class="coexist-path">
						<span class="cp-title">Path 1 · production-critical</span>
						<span class="cp-body">DB replication, engine-native TLS — <strong>outside the mesh, untouched</strong>. No dependency on Ankayma being up.</span>
					</div>
					<div class="coexist-path secured">
						<span class="cp-title">Path 2 · secured by Ankayma</span>
						<span class="cp-body">This access — peer-to-peer, vendor off the data path.</span>
					</div>
				</div>
				<p class="coexist-note">Structural guarantee (A.1.5) — turning on security doesn't put your running system on the mesh.</p>
			</div>
		</section>
	{/if}

	{#if $quota}
		<section class="quota-card">
			<div class="quota-header">
				<span>Bandwidth</span>
				<span class:warn={quotaWarn} class:critical={quotaCritical}>
					{formatBytes($quota.bandwidth_bytes_used)} / {formatBytes($quota.bandwidth_bytes_limit)}
				</span>
			</div>
			<div class="quota-bar">
				<div
					class="quota-fill"
					class:warn={quotaWarn}
					class:critical={quotaCritical}
					style="width: {quotaPct}%"
				></div>
			</div>

			{#if quotaWarn}
				<div class="quota-nudge" class:critical={quotaCritical}>
					{#if quotaCritical}
						<strong>95% used</strong> — upgrade to avoid interruption
					{:else}
						<strong>80% used</strong> — consider upgrading for more bandwidth
					{/if}
					<button class="nudge-btn" onclick={() => goto('/upgrade')}>
						Upgrade →
					</button>
				</div>
			{/if}

			<div class="quota-nodes">
				<span>Nodes</span>
				<span>{$quota.nodes_used} / {$quota.nodes_limit}</span>
			</div>
		</section>
	{/if}

	{#if $auth.status === 'authenticated'}
		<section class="quick-actions">
			<button class="quick-item" onclick={() => goto('/devices')}>
				<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8">
					<rect x="2" y="4" width="20" height="14" rx="2"/><path d="M8 21h8M12 18v3"/>
				</svg>
				<span>Network devices</span>
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
	{/if}

	{#if $auth.status === 'authenticated' && $auth.user.tier === 'F0Plus'}
		<section class="quick-actions">
			<button class="quick-item" onclick={() => goto('/subdomains')}>
				<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8">
					<path d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
					<path d="M3.6 9h16.8M3.6 15h16.8M12 3a15 15 0 010 18"/>
				</svg>
				<span>Subdomains</span>
				<svg class="arrow" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
					<path d="M9 18l6-6-6-6"/>
				</svg>
			</button>
			<button class="quick-item" onclick={() => goto('/add-device')}>
				<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8">
					<rect x="5" y="2" width="14" height="20" rx="2"/>
					<path d="M12 18h.01"/>
				</svg>
				<span>Add device</span>
				<svg class="arrow" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
					<path d="M9 18l6-6-6-6"/>
				</svg>
			</button>
		</section>
	{/if}

	{#if $auth.status === 'authenticated' && $auth.user.tier === 'F0'}
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
		display: flex;
		align-items: center;
		justify-content: space-between;
		padding: 8px 0;
	}

	h2 {
		font-size: 20px;
		font-weight: 700;
	}

	.icon-btn {
		width: 40px;
		height: 40px;
		display: flex;
		align-items: center;
		justify-content: center;
		border-radius: 10px;
		background: var(--c-surface);
		border: 1px solid var(--c-border);
		color: var(--c-text-dim);
		transition: color 0.15s;
	}

	.icon-btn:hover {
		color: var(--c-text);
	}

	.connection-card {
		background: var(--c-surface);
		border: 1px solid var(--c-border);
		border-radius: var(--radius);
		padding: 32px 24px;
		display: flex;
		flex-direction: column;
		align-items: center;
		gap: 16px;
	}

	.status-indicator {
		width: 12px;
		height: 12px;
		border-radius: 50%;
		background: var(--c-text-dim);
	}

	.status-indicator.connected {
		background: var(--c-success);
		box-shadow: 0 0 8px var(--c-success);
	}

	.status-indicator.connecting {
		background: var(--c-warn);
		animation: pulse 1s ease-in-out infinite;
	}

	@keyframes pulse {
		0%, 100% { opacity: 1; }
		50% { opacity: 0.3; }
	}

	.status-text {
		text-align: center;
	}

	.status-label {
		display: block;
		font-size: 18px;
		font-weight: 600;
	}

	.status-label.connected {
		color: var(--c-success);
	}

	.node-id, .status-sub {
		font-size: 12px;
		color: var(--c-text-dim);
		font-family: 'SF Mono', 'Fira Code', monospace;
		overflow-wrap: anywhere;
		max-width: 100%;
	}

	.toggle-btn {
		width: 80px;
		height: 80px;
		border-radius: 50%;
		background: var(--c-border);
		color: var(--c-text-dim);
		display: flex;
		align-items: center;
		justify-content: center;
		transition: background 0.2s, color 0.2s, box-shadow 0.2s;
	}

	.toggle-btn.active {
		background: color-mix(in srgb, var(--c-success) 20%, var(--c-surface));
		color: var(--c-success);
		box-shadow: 0 0 24px color-mix(in srgb, var(--c-success) 30%, transparent);
	}

	.toggle-btn:hover:not(:disabled) {
		background: var(--c-accent);
		color: #fff;
	}

	.toggle-btn:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}

	.connect-error {
		font-size: 13px;
		color: var(--c-danger);
		background: color-mix(in srgb, var(--c-danger) 10%, transparent);
		border: 1px solid color-mix(in srgb, var(--c-danger) 30%, transparent);
		padding: 10px 14px;
		border-radius: 8px;
		text-align: center;
		max-width: 100%;
		overflow-wrap: anywhere;
	}

	.quota-card {
		background: var(--c-surface);
		border: 1px solid var(--c-border);
		border-radius: var(--radius);
		padding: 16px;
		display: flex;
		flex-direction: column;
		gap: 10px;
	}

	.quota-header {
		display: flex;
		justify-content: space-between;
		font-size: 14px;
	}

	.quota-header span:first-child {
		color: var(--c-text-dim);
	}

	.quota-header .warn { color: var(--c-warn); }
	.quota-header .critical { color: var(--c-danger); }

	.quota-bar {
		height: 6px;
		background: var(--c-border);
		border-radius: 3px;
		overflow: hidden;
	}

	.quota-fill {
		height: 100%;
		background: var(--c-accent);
		border-radius: 3px;
		transition: width 0.3s ease;
	}

	.quota-fill.warn { background: var(--c-warn); }
	.quota-fill.critical { background: var(--c-danger); }

	.quota-nudge {
		display: flex;
		align-items: center;
		justify-content: space-between;
		padding: 10px 12px;
		background: color-mix(in srgb, var(--c-warn) 10%, transparent);
		border: 1px solid color-mix(in srgb, var(--c-warn) 30%, transparent);
		border-radius: 8px;
		font-size: 13px;
		gap: 8px;
	}

	.quota-nudge.critical {
		background: color-mix(in srgb, var(--c-danger) 10%, transparent);
		border-color: color-mix(in srgb, var(--c-danger) 30%, transparent);
	}

	.nudge-btn {
		background: var(--c-accent);
		color: #fff;
		padding: 6px 12px;
		border-radius: 6px;
		font-size: 13px;
		font-weight: 600;
		white-space: nowrap;
		flex-shrink: 0;
	}

	.quota-nodes {
		display: flex;
		justify-content: space-between;
		font-size: 13px;
		color: var(--c-text-dim);
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

	/* [F-5 "Prove it"] data-path proof panel */
	.prove-card {
		background: var(--c-surface);
		border: 1px solid var(--c-border);
		border-radius: var(--radius);
		padding: 16px;
		display: flex;
		flex-direction: column;
		gap: 12px;
	}

	.prove-head {
		display: flex;
		align-items: center;
		justify-content: space-between;
		font-size: 14px;
		font-weight: 600;
	}

	.prove-btn {
		background: color-mix(in srgb, var(--c-accent) 12%, transparent);
		color: var(--c-accent);
		padding: 8px 14px;
		border-radius: 8px;
		font-size: 13px;
		font-weight: 600;
	}

	.prove-btn:disabled { opacity: 0.5; cursor: not-allowed; }

	.prove-hint {
		font-size: 13px;
		color: var(--c-text-dim);
		line-height: 1.5;
		margin: 0;
	}

	/* [F-5 / ND-A1] coexistence split-view */
	.coexist {
		margin-top: 14px;
		border-top: 1px solid var(--c-border);
		padding-top: 12px;
	}
	.coexist-label {
		font-size: 11px;
		text-transform: uppercase;
		letter-spacing: 0.04em;
		color: var(--c-text-dim);
		margin: 0 0 8px;
	}
	.coexist-paths {
		display: flex;
		gap: 8px;
		flex-wrap: wrap;
	}
	.coexist-path {
		flex: 1;
		min-width: 150px;
		background: var(--c-surface);
		border: 1px solid var(--c-border);
		border-radius: 8px;
		padding: 10px 12px;
		display: flex;
		flex-direction: column;
		gap: 3px;
	}
	.coexist-path.secured {
		background: color-mix(in srgb, var(--c-accent) 8%, var(--c-surface));
		border-color: color-mix(in srgb, var(--c-accent) 30%, transparent);
	}
	.cp-title {
		font-size: 12px;
		font-weight: 600;
		color: var(--c-text);
	}
	.coexist-path.secured .cp-title {
		color: var(--c-accent);
	}
	.cp-body {
		font-size: 11px;
		color: var(--c-text-dim);
		line-height: 1.5;
	}
	.coexist-note {
		font-size: 10px;
		color: var(--c-text-dim);
		margin: 8px 0 0;
	}

	.prove-row {
		display: flex;
		align-items: center;
		gap: 8px;
		font-size: 13px;
		color: var(--c-text);
	}

	.prove-row.vendor {
		color: var(--c-success);
		padding-bottom: 8px;
		border-bottom: 1px solid var(--c-border);
	}

	.prove-row.vendor svg { flex-shrink: 0; }
	.prove-row.muted { color: var(--c-text-dim); }
	.prove-row .peer-name { flex: 1; font-weight: 600; }
	.prove-row .peer-path { color: var(--c-text-dim); display: flex; gap: 6px; align-items: center; }
	.prove-row code {
		background: var(--c-border);
		padding: 1px 6px;
		border-radius: 4px;
		font-family: 'SF Mono', 'Fira Code', monospace;
		font-size: 11px;
	}
</style>
