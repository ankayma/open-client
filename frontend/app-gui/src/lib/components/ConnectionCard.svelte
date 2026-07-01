<script lang="ts">
	import { onMount, onDestroy } from 'svelte';
	import { connection } from '$lib/stores';
	import {
		connect,
		disconnect,
		getConnectionStatus,
		startDataplane,
		stopDataplane,
		getDataplaneStatus,
		type DataplaneStatus,
		vpnConnect,
		vpnDisconnect,
		vpnStatus,
		getPlatform,
		getNodeInfo
	} from '$lib/tauri';

	let toggling = $state(false);
	let connectError = $state<string | null>(null);
	let dp = $state<DataplaneStatus | null>(null);
	let hostname = $state<string | null>(null);
	// iOS runs the data plane in-app (Packet Tunnel extension); desktop hands off to
	// the privileged daemon. The connect toggle picks the path from this. [T:A.1.9]
	let isIos = $state(false);

	async function refreshDataplane() {
		try {
			if (isIos) {
				const s = await vpnStatus();
				const running = s.status === 'connected' || s.status === 'reasserting';
				dp = running ? { running: true, pid: null, age_secs: null, peers: [] } : null;
			} else {
				dp = await getDataplaneStatus();
			}
		} catch {
			dp = null;
		}
	}

	let dpTimer: ReturnType<typeof setInterval> | undefined;
	onMount(() => {
		getPlatform()
			.then((os) => { isIos = os === 'ios'; refreshDataplane(); })
			.catch(() => (isIos = false));
		refreshDataplane();
		dpTimer = setInterval(refreshDataplane, 4000);
		getNodeInfo().then((n) => (hostname = n.hostname)).catch(() => {});
	});
	onDestroy(() => clearInterval(dpTimer));

	async function toggleConnection() {
		toggling = true;
		connectError = null;
		try {
			const conn = $connection;
			if (conn.status === 'connected') {
				if (isIos) {
					await vpnDisconnect();
				} else {
					try { await stopDataplane(); } catch { /* ignore — daemon may not be running */ }
					await disconnect();
				}
				connection.set({ status: 'disconnected' });
			} else {
				connection.set({ status: 'connecting' });
				if (isIos) {
					await vpnConnect();
				} else {
					await connect();
					await startDataplane();
				}
				connection.set(await getConnectionStatus());
			}
		} catch (e) {
			connection.set({ status: 'disconnected' });
			connectError = e instanceof Error ? e.message : String(e);
		} finally {
			toggling = false;
		}
	}
</script>

<section class="card">
	<div class="row head">
		<span
			class="dot"
			class:connected={$connection.status === 'connected'}
			class:connecting={$connection.status === 'connecting'}
		></span>
		<span class="status" class:connected={$connection.status === 'connected'}>
			{#if $connection.status === 'connected'}Connected
			{:else if $connection.status === 'connecting'}Connecting…
			{:else}Disconnected{/if}
		</span>
	</div>

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
	{#if $connection.status !== 'connected'}
		<span class="hint">{$connection.status === 'connecting' ? 'Connecting…' : 'Tap to connect'}</span>
	{/if}

	<div class="kv">
		{#if hostname}
			<div class="kv-row"><span class="k">Device</span><span class="v mono">{hostname}</span></div>
		{/if}
		{#if $connection.status === 'connected'}
			<div class="kv-row"><span class="k">Endpoint</span><span class="v mono">{$connection.endpoint}</span></div>
			<!-- TODO[A]: hidden until a Tauri command returns cert expiry / AAL -->
			{#if $connection.cert_expires_days}
				<div class="kv-row"><span class="k">Cert</span><span class="v ok">{$connection.cert_expires_days}d remaining</span></div>
			{/if}
			{#if $connection.aal}
				<div class="kv-row"><span class="k">AAL</span><span class="v">{$connection.aal}</span></div>
			{/if}
		{/if}
	</div>

	{#if connectError}
		<p class="error">{connectError}</p>
	{/if}

	{#if $connection.status === 'connected' && dp?.running}
		<p class="tunnel">
			🔒 Secure tunnel up · {dp.peers.length} peer{dp.peers.length === 1 ? '' : 's'}
		</p>
	{/if}
</section>

<style>
	.card {
		background: var(--c-surface);
		border: 1px solid var(--c-border);
		border-radius: var(--radius);
		padding: 24px 16px;
		display: flex;
		flex-direction: column;
		align-items: center;
		gap: 12px;
	}
	.row.head {
		display: flex;
		align-items: center;
		gap: 8px;
	}
	.dot {
		width: 10px;
		height: 10px;
		border-radius: 50%;
		background: var(--c-text-dim);
		flex-shrink: 0;
	}
	.dot.connected {
		background: var(--c-success);
		box-shadow: 0 0 8px var(--c-success);
	}
	.dot.connecting {
		background: var(--c-warn);
		animation: pulse 1s ease-in-out infinite;
	}
	@keyframes pulse {
		0%, 100% { opacity: 1; }
		50% { opacity: 0.3; }
	}
	.status {
		font-size: 16px;
		font-weight: 700;
	}
	.status.connected {
		color: var(--c-success);
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
		flex-shrink: 0;
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
	.hint {
		font-size: 13px;
		color: var(--c-text-dim);
		margin-top: -4px;
	}
	.kv {
		display: flex;
		flex-direction: column;
		gap: 6px;
		width: 100%;
	}
	.kv-row {
		display: flex;
		justify-content: space-between;
		gap: 12px;
		font-size: 13px;
	}
	.k {
		color: var(--c-text-dim);
	}
	.v {
		color: var(--c-text);
		text-align: right;
		overflow-wrap: anywhere;
	}
	.v.mono {
		font-family: 'SF Mono', 'Fira Code', monospace;
		font-size: 12px;
	}
	.v.ok {
		color: var(--c-success);
	}
	.error {
		width: 100%;
		font-size: 13px;
		color: var(--c-danger);
		background: color-mix(in srgb, var(--c-danger) 10%, transparent);
		border: 1px solid color-mix(in srgb, var(--c-danger) 30%, transparent);
		padding: 10px 14px;
		border-radius: 8px;
		text-align: center;
		overflow-wrap: anywhere;
		box-sizing: border-box;
	}
	.tunnel {
		font-size: 13px;
		color: var(--c-success);
		text-align: center;
	}
</style>
