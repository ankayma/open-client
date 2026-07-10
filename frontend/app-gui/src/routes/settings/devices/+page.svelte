<script lang="ts">
	// Settings → My Devices — the tenant's enrolled nodes (mesh peers), plus the
	// node-count quota (H.2.1.4). Bandwidth is intentionally not shown here —
	// P2P traffic is off-path by design (A.1.1), so a bandwidth number would be
	// a claim the client can't actually verify (P.3 honest gap). `[T per A.1.1 + P.3]`
	import { goto } from '$app/navigation';
	import { onMount } from 'svelte';
	import { connection, quota } from '$lib/stores';
	import { listNodes, getNodeInfo, deleteNode, getQuota, getPathProof } from '$lib/tauri';
	import { runWithStepUp } from '$lib/stepup';
	import type { PeerBrief } from '$lib/types';

	// A peer counts as live only if WireGuard handshook with it this recently.
	// WireGuard rekeys well inside two minutes on an active tunnel, so three is
	// slack, not evidence of nothing.
	const HANDSHAKE_FRESH_SECS = 180;

	// Liveness is DATA-PLANE evidence, never a control-plane claim. The old code
	// read the server's `active` flag, which is `expires_at IS NULL OR expires_at
	// > NOW()` -- always true for a persistent node, so every device showed green
	// forever, including ones dead for months.
	//
	// The vendor is off the data path by design (A.1.1), so the control plane
	// CANNOT know which devices are reachable on the mesh. Only the two tunnel
	// endpoints know. This device already measures it: the daemon publishes each
	// peer's last WireGuard handshake age, surfaced by `get_path_proof`.
	//
	// Where we have no measurement -- disconnected, or a peer this tunnel has
	// never handshook with -- the answer is `unknown`, not `offline`. Claiming a
	// device is down when we simply cannot see it would be the same lie in the
	// other direction. `[T:A.1.1 + P.3 honest gap]`
	type Liveness = 'live' | 'unknown';

	function liveness(d: PeerBrief): Liveness {
		if (d.node_id === thisNodeId) {
			return $connection.status === 'connected' ? 'live' : 'unknown';
		}
		const secs = handshakeAge.get(d.overlay_ip);
		if (secs === undefined || secs === null) return 'unknown';
		return secs <= HANDSHAKE_FRESH_SECS ? 'live' : 'unknown';
	}

	// Why a peer is not shown as live -- so the dot never has to carry the whole
	// story on its own.
	function livenessTitle(d: PeerBrief): string {
		if (d.node_id === thisNodeId) {
			return $connection.status === 'connected' ? 'Connected' : 'Not connected';
		}
		if (!pathKnown) return 'Connect to see which devices are reachable';
		const secs = handshakeAge.get(d.overlay_ip);
		if (secs === undefined || secs === null) return 'No handshake with this device yet';
		if (secs <= HANDSHAKE_FRESH_SECS) return `Handshake ${secs}s ago`;
		const mins = Math.round(secs / 60);
		return mins < 60 ? `Silent for ${mins}m` : `Silent for ${Math.round(mins / 60)}h`;
	}

	let devices = $state<PeerBrief[]>([]);
	let thisNodeId = $state<string | null>(null);
	let loading = $state(true);
	let error = $state('');
	let confirmNode = $state<PeerBrief | null>(null);
	let removing = $state(false);
	// overlay_ip -> seconds since last handshake. overlay_ip is unique per node,
	// and is the only key both the roster and the data-plane status share.
	let handshakeAge = $state(new Map<string, number | null>());
	// False when the data plane cannot be read at all (not connected, or a
	// platform with no daemon status file). Every peer is then `unknown`.
	let pathKnown = $state(false);

	async function load() {
		loading = true;
		error = '';
		try {
			// This device first (so we can flag it), then the full peer list. The
			// data-plane proof is best-effort: without it every peer reads `unknown`,
			// which is the honest answer, so its failure must not fail the page.
			const [self, peers, proof] = await Promise.all([
				getNodeInfo().catch(() => null),
				listNodes(),
				getPathProof().catch(() => null)
			]);
			thisNodeId = self?.node_id ?? null;
			devices = peers;
			pathKnown = proof?.connected ?? false;
			handshakeAge = new Map(
				(proof?.peers ?? []).map((p) => [p.overlay_ip, p.last_handshake_secs])
			);
		} catch (e) {
			error = String(e);
		} finally {
			loading = false;
		}
	}
	onMount(() => {
		load();
		getQuota().then((q) => quota.set(q)).catch(() => {});
	});

	// [F-2 §H.2.2] "SSH ↗" — open the in-app terminal (xterm.js over the mesh
	// russh transport). Works on desktop AND iOS/iPad (no system Terminal needed).
	// Not shown for this device (ssh to yourself is a confusing no-op at F0).
	let sshError = $state('');
	function sshTo(d: PeerBrief) {
		sshError = '';
		goto(`/terminal?node=${encodeURIComponent(d.node_id)}&host=${encodeURIComponent(d.hostname)}`);
	}

	async function removeDevice(nodeId: string) {
		removing = true;
		try {
			// Multi-user tenant gates revoke behind a step-up; runWithStepUp drives the
			// OTP and retries. Solo tenants pass straight through. [Part D §Authority]
			await runWithStepUp('revoke_node', (proof) => deleteNode(nodeId, proof));
			confirmNode = null;
			await load();
			getQuota().then((q) => quota.set(q)).catch(() => {});
		} catch (e) {
			if (String(e).includes('Step-up cancelled')) return; // user backed out
			error = String(e);
		} finally {
			removing = false;
		}
	}

	// This device on top, then by hostname.
	let sorted = $derived(
		[...devices].sort((a, b) => {
			if (a.node_id === thisNodeId) return -1;
			if (b.node_id === thisNodeId) return 1;
			return a.hostname.localeCompare(b.hostname);
		})
	);

	let atLimit = $derived($quota ? $quota.nodes_used >= $quota.nodes_limit : false);
</script>

<main>
	<header>
		<h2>My Devices</h2>
		<div class="header-actions">
			<button class="icon-btn" onclick={load} aria-label="Refresh" disabled={loading}>
				<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
					<path d="M23 4v6h-6M1 20v-6h6"/>
					<path d="M3.51 9a9 9 0 0114.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0020.49 15"/>
				</svg>
			</button>
			<button
				class="add-node-btn"
				onclick={() => goto('/add-device')}
				disabled={atLimit}
				title={atLimit ? 'Limit reached. Remove a node or contact admin.' : ''}
			>
				<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 5v14M5 12h14"/></svg>
				Add Node
			</button>
		</div>
	</header>

	{#if $quota}
		<div class="quota-bar">
			<div class="quota-track"><div class="quota-fill" class:full={atLimit} style="width: {Math.min(100, Math.round(($quota.nodes_used / $quota.nodes_limit) * 100))}%"></div></div>
			<div class="quota-label">
				<span>{$quota.nodes_used} / {$quota.nodes_limit} nodes</span>
				{#if atLimit}
					<span class="quota-warn">Limit reached. Remove a node or contact admin.</span>
				{:else}
					<span class="quota-remaining">{$quota.nodes_limit - $quota.nodes_used} remaining</span>
				{/if}
			</div>
		</div>
	{/if}

	{#if loading}
		<div class="state"><span class="spinner-lg"></span></div>
	{:else if error}
		<div class="state error">
			<p>{error}</p>
			<button class="btn" onclick={load}>Retry</button>
		</div>
	{:else if sorted.length === 0}
		<div class="state">
			<p class="muted">No devices in your mesh yet.</p>
			<button class="btn" onclick={() => goto('/add-device')}>Add a device</button>
		</div>
	{:else}
		{#if sshError}
			<p class="ssh-error">{sshError}</p>
		{/if}
		<ul class="device-list">
			{#each sorted as d (d.node_id)}
				<li class="device">
					<span
						class="dot"
						class:online={liveness(d) === 'live'}
						title={livenessTitle(d)}
						aria-label={livenessTitle(d)}
					></span>
					<div class="info">
						<div class="name-row">
							<span class="name">{d.hostname}</span>
							{#if d.node_id === thisNodeId}<span class="badge">This device</span>{/if}
						</div>
						<span class="ip">{d.overlay_ip}</span>
					</div>
					{#if d.node_id !== thisNodeId}
						<button
							class="ssh-btn"
							aria-label="SSH into {d.hostname}"
							title="SSH into {d.hostname}"
							onclick={() => sshTo(d)}
						>
							<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 17l6-6-6-6M12 19h8"/></svg>
							SSH
						</button>
					{/if}
					<button
						class="remove-btn"
						aria-label="Remove device"
						onclick={() => (confirmNode = d)}
					>
						<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 6L6 18M6 6l12 12"/></svg>
					</button>
				</li>
			{/each}
		</ul>
	{/if}
</main>

{#if confirmNode}
	<div
		role="presentation"
		onclick={() => (confirmNode = null)}
		style="position:fixed;inset:0;background:rgba(0,0,0,0.55);display:flex;align-items:center;justify-content:center;padding:24px;z-index:50;"
	>
		<div
			role="dialog"
			aria-modal="true"
			tabindex="-1"
			onclick={(e) => e.stopPropagation()}
			style="background:var(--c-surface);border:1px solid var(--c-border);border-radius:var(--radius);padding:20px;max-width:340px;width:100%;display:flex;flex-direction:column;gap:16px;"
		>
			<p style="font-size:15px;line-height:1.5;">
				Remove <strong>{confirmNode.hostname}</strong> from your mesh?{#if confirmNode.node_id === thisNodeId}
					This is the current device — it re-enrolls on the next connect.{/if}
			</p>
			<div style="display:flex;justify-content:flex-end;gap:8px;">
				<button class="btn-ghost" onclick={() => (confirmNode = null)}>Cancel</button>
				<button
					class="btn-danger"
					disabled={removing}
					onclick={() => removeDevice(confirmNode!.node_id)}
				>
					{removing ? 'Removing…' : 'Remove'}
				</button>
			</div>
		</div>
	</div>
{/if}

<style>
	main {
		flex: 1;
		display: flex;
		flex-direction: column;
		padding: 16px 16px calc(var(--safe-bottom) + 24px);
		gap: 16px;
		max-width: 420px;
		margin: 0 auto;
		width: 100%;
	}

	header {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 8px;
		padding: 8px 0;
	}

	h2 {
		font-size: 20px;
		font-weight: 700;
	}

	.header-actions {
		display: flex;
		align-items: center;
		gap: 6px;
	}

	.icon-btn {
		width: 36px;
		height: 36px;
		display: flex;
		align-items: center;
		justify-content: center;
		border-radius: 10px;
		color: var(--c-text-dim);
		flex-shrink: 0;
	}
	.icon-btn:hover:not(:disabled) { color: var(--c-text); }
	.icon-btn:disabled { opacity: 0.5; }

	.add-node-btn {
		display: flex;
		align-items: center;
		gap: 5px;
		padding: 7px 14px;
		background: var(--c-accent);
		border-radius: 8px;
		color: white;
		font-size: 13px;
		font-weight: 600;
		flex-shrink: 0;
	}
	.add-node-btn:hover:not(:disabled) { background: var(--c-accent-dim); }
	.add-node-btn:disabled { opacity: 0.4; cursor: not-allowed; }

	.quota-bar {
		display: flex;
		flex-direction: column;
		gap: 6px;
	}

	.quota-track {
		height: 6px;
		background: var(--c-border);
		border-radius: 99px;
		overflow: hidden;
	}

	.quota-fill {
		height: 100%;
		background: var(--c-accent);
		border-radius: 99px;
		transition: width 0.2s;
	}

	.quota-fill.full {
		background: var(--c-warn);
	}

	.quota-label {
		display: flex;
		align-items: center;
		justify-content: space-between;
		font-size: 12px;
		color: var(--c-text-dim);
	}

	.quota-warn {
		color: var(--c-warn);
		font-weight: 600;
	}

	.device-list {
		list-style: none;
		display: flex;
		flex-direction: column;
		gap: 2px;
		background: var(--c-surface);
		border: 1px solid var(--c-border);
		border-radius: var(--radius);
		overflow: hidden;
	}

	.device {
		display: flex;
		align-items: flex-start;
		gap: 12px;
		padding: 14px 16px;
		border-bottom: 1px solid var(--c-border);
		min-width: 0;
	}
	.device:last-child { border-bottom: none; }

	/* Hollow = we have no data-plane evidence about this device, which is not the
	   same as knowing it is off. A filled grey dot would assert "offline" -- a
	   claim this client cannot make (A.1.1 / P.3). Hover for the reason. */
	.dot {
		width: 9px;
		height: 9px;
		border-radius: 50%;
		background: transparent;
		border: 1.5px solid var(--c-text-dim);
		margin-top: 5px;
		flex-shrink: 0;
	}
	.dot.online {
		background: var(--sec-allow);
		border-color: var(--sec-allow);
		box-shadow: 0 0 8px var(--sec-allow);
	}

	.info {
		display: flex;
		flex-direction: column;
		gap: 2px;
		min-width: 0;
		flex: 1;
	}

	.name-row {
		display: flex;
		align-items: center;
		gap: 8px;
	}

	.name {
		font-size: 15px;
		font-weight: 600;
		overflow-wrap: anywhere;
	}

	.badge {
		font-size: 11px;
		font-weight: 600;
		color: var(--c-accent);
		background: color-mix(in srgb, var(--c-accent) 14%, transparent);
		padding: 2px 8px;
		border-radius: 999px;
		flex-shrink: 0;
	}

	.ip {
		font-size: 12px;
		color: var(--c-text-dim);
		font-family: 'SF Mono', 'Fira Code', monospace;
		overflow-wrap: anywhere;
	}

	.state {
		display: flex;
		flex-direction: column;
		align-items: center;
		gap: 14px;
		padding: 48px 16px;
		text-align: center;
	}
	.state.error p { color: var(--c-danger); }
	.muted { color: var(--c-text-dim); }

	.btn {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		gap: 8px;
		padding: 12px 18px;
		background: var(--c-accent);
		color: #fff;
		border-radius: var(--radius);
		font-size: 14px;
		font-weight: 600;
	}
	.btn:hover { background: var(--c-accent-dim); }

	/* Mesh-terminal button — same accent-tinted chip as the SSH button on
	   Services (keep the two in sync: one affordance, one look — geometry
	   mirrors the global .btn-primary/.btn-secondary: 7px 14px, 13px). */
	.ssh-btn {
		display: inline-flex;
		align-items: center;
		gap: 6px;
		font-size: 13px;
		font-weight: 500;
		padding: 7px 14px;
		border-radius: var(--radius);
		flex-shrink: 0;
		color: var(--c-accent);
		background: var(--btn-secondary-bg);
		border: 1px solid color-mix(in srgb, var(--c-accent) 35%, var(--c-border));
		transition: background 0.12s, color 0.12s;
	}
	.ssh-btn:hover {
		background: color-mix(in srgb, var(--c-accent) 12%, transparent);
	}

	.ssh-error {
		font-size: 12px;
		color: var(--c-danger);
	}

	.remove-btn {
		margin-left: auto;
		width: 32px;
		height: 32px;
		display: flex;
		align-items: center;
		justify-content: center;
		border-radius: 6px;
		flex-shrink: 0;
		color: var(--c-text-dim);
		background: transparent;
		transition: background 0.12s, color 0.12s;
	}
	.remove-btn:hover {
		background: var(--btn-danger-bg);
		color: var(--btn-danger-text);
	}

	.spinner-lg {
		width: 28px;
		height: 28px;
		border: 3px solid var(--c-border);
		border-top-color: var(--c-accent);
		border-radius: 50%;
		animation: spin 0.8s linear infinite;
	}
	@keyframes spin { to { transform: rotate(360deg); } }
</style>
