<script lang="ts">
	// Network devices — the tenant's enrolled nodes (mesh peers). Mirrors the
	// macOS tray "Network Devices" submenu so the list is visible in the GUI too.
	// Backed by the existing `list_nodes` command (GET /api/v1/peers).
	import { goto } from '$app/navigation';
	import { onMount } from 'svelte';
	import { connection } from '$lib/stores';
	import { listNodes, getNodeInfo, deleteNode } from '$lib/tauri';
	import type { PeerBrief } from '$lib/types';

	// "Online" dot: this device follows the app's connection state (matches the
	// dashboard); a peer is online when it advertises a reachable endpoint.
	function isOnline(d: PeerBrief): boolean {
		if (d.node_id === thisNodeId) return $connection.status === 'connected';
		return !!d.endpoint;
	}

	let devices = $state<PeerBrief[]>([]);
	let thisNodeId = $state<string | null>(null);
	let loading = $state(true);
	let error = $state('');
	let confirmNode = $state<PeerBrief | null>(null);
	let removing = $state(false);

	async function load() {
		loading = true;
		error = '';
		try {
			// This device first (so we can flag it), then the full peer list.
			const [self, peers] = await Promise.all([
				getNodeInfo().catch(() => null),
				listNodes()
			]);
			thisNodeId = self?.node_id ?? null;
			devices = peers;
		} catch (e) {
			error = String(e);
		} finally {
			loading = false;
		}
	}
	onMount(load);

	async function removeDevice(nodeId: string) {
		removing = true;
		try {
			await deleteNode(nodeId);
			confirmNode = null;
			await load();
		} catch (e) {
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
</script>

<main>
	<header>
		<button class="back-btn" onclick={() => goto('/dashboard')} aria-label="Back">
			<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
				<path d="M19 12H5M12 5l-7 7 7 7"/>
			</svg>
		</button>
		<h2>Network devices</h2>
		<button class="back-btn" onclick={load} aria-label="Refresh" disabled={loading}>
			<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
				<path d="M23 4v6h-6M1 20v-6h6"/>
				<path d="M3.51 9a9 9 0 0114.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0020.49 15"/>
			</svg>
		</button>
	</header>

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
		<ul class="device-list">
			{#each sorted as d (d.node_id)}
				<li class="device">
					<span class="dot" class:online={isOnline(d)}></span>
					<div class="info">
						<div class="name-row">
							<span class="name">{d.hostname}</span>
							{#if d.node_id === thisNodeId}<span class="badge">This device</span>{/if}
						</div>
						<span class="ip">{d.overlay_ip}</span>
						{#if d.endpoint}<span class="endpoint">{d.endpoint}</span>{/if}
					</div>
					<button
						class="remove"
						style="margin-left:auto;width:32px;height:32px;display:flex;align-items:center;justify-content:center;color:var(--c-text-dim);border-radius:6px;flex-shrink:0;background:transparent;"
						aria-label="Remove device"
						onclick={() => (confirmNode = d)}
					>
						<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 6L6 18M6 6l12 12"/></svg>
					</button>
				</li>
			{/each}
		</ul>

		<button class="btn add" onclick={() => goto('/add-device')}>
			<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
				<path d="M12 5v14M5 12h14"/>
			</svg>
			Add a device
		</button>
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
				<button onclick={() => (confirmNode = null)} style="padding:9px 16px;border-radius:8px;color:var(--c-text-dim);background:transparent;">Cancel</button>
				<button
					disabled={removing}
					onclick={() => removeDevice(confirmNode!.node_id)}
					style="padding:9px 16px;border-radius:8px;background:var(--c-danger, #ef4444);color:#fff;"
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
		gap: 8px;
		padding: 8px 0;
	}

	h2 {
		font-size: 20px;
		font-weight: 700;
		flex: 1;
		text-align: center;
	}

	.back-btn {
		width: 36px;
		height: 36px;
		display: flex;
		align-items: center;
		justify-content: center;
		border-radius: 10px;
		color: var(--c-text-dim);
		flex-shrink: 0;
	}
	.back-btn:hover:not(:disabled) { color: var(--c-text); }
	.back-btn:disabled { opacity: 0.5; }

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

	.dot {
		width: 9px;
		height: 9px;
		border-radius: 50%;
		background: var(--c-text-dim);
		margin-top: 5px;
		flex-shrink: 0;
	}
	.dot.online {
		background: var(--c-success);
		box-shadow: 0 0 8px var(--c-success);
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

	.ip, .endpoint {
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
	.btn.add { width: 100%; }

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
