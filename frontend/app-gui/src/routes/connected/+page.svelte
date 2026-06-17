<script lang="ts">
	import { goto } from '$app/navigation';
	import { connection } from '$lib/stores';

	// Shown once after first successful tunnel — aha moment
	const nodeAddr = $derived(
		$connection.status === 'connected' ? $connection.node_id : 'node_…'
	);
</script>

<main>
	<div class="content">
		<div class="checkmark" aria-hidden="true">
			<svg width="56" height="56" viewBox="0 0 24 24" fill="none">
				<circle cx="12" cy="12" r="11" stroke="var(--c-success)" stroke-width="1.5"/>
				<path d="M7 12.5l3.5 3.5 6.5-7" stroke="var(--c-success)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
			</svg>
		</div>

		<h1>You're in the mesh</h1>
		<p class="sub">Your node is live. Encrypted. Customer-controlled.</p>

		<div class="node-card">
			<span class="node-label">Your node address</span>
			<code class="node-addr">{nodeAddr}</code>
			<span class="node-note">Stable across networks — use this to reach this device from your mesh</span>
		</div>

		<div class="next-steps">
			<p class="next-label">What's next</p>
			<button class="next-item primary" onclick={() => goto('/add-device')}>
				<span class="next-icon">📱</span>
				<div>
					<strong>Add another device</strong>
					<span>Connect your phone, server, or laptop</span>
				</div>
				<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
					<path d="M9 18l6-6-6-6"/>
				</svg>
			</button>
			<button class="next-item" onclick={() => goto('/dashboard')}>
				<span class="next-icon">📊</span>
				<div>
					<strong>Go to dashboard</strong>
					<span>Manage connections and quota</span>
				</div>
				<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
					<path d="M9 18l6-6-6-6"/>
				</svg>
			</button>
		</div>
	</div>
</main>

<style>
	main {
		flex: 1;
		display: flex;
		align-items: center;
		justify-content: center;
		padding: calc(var(--safe-top) + 24px) 24px calc(var(--safe-bottom) + 32px);
		min-height: 100dvh;
	}

	.content {
		width: 100%;
		max-width: 380px;
		display: flex;
		flex-direction: column;
		align-items: center;
		gap: 12px;
		text-align: center;
	}

	.checkmark {
		animation: pop 0.4s cubic-bezier(0.34, 1.56, 0.64, 1) both;
		margin-bottom: 8px;
	}

	@keyframes pop {
		from { transform: scale(0.5); opacity: 0; }
		to   { transform: scale(1);   opacity: 1; }
	}

	h1 {
		font-size: 26px;
		font-weight: 800;
		letter-spacing: -0.3px;
	}

	.sub {
		font-size: 15px;
		color: var(--c-text-dim);
		margin-bottom: 12px;
	}

	.node-card {
		width: 100%;
		background: var(--c-surface);
		border: 1px solid var(--c-border);
		border-radius: var(--radius);
		padding: 16px;
		display: flex;
		flex-direction: column;
		gap: 6px;
		text-align: left;
		margin-bottom: 8px;
	}

	.node-label {
		font-size: 11px;
		font-weight: 600;
		text-transform: uppercase;
		letter-spacing: 0.08em;
		color: var(--c-text-dim);
	}

	.node-addr {
		font-family: 'SF Mono', 'Fira Code', monospace;
		font-size: 14px;
		color: var(--c-accent);
		word-break: break-all;
	}

	.node-note {
		font-size: 12px;
		color: var(--c-text-dim);
		line-height: 1.5;
	}

	.next-steps {
		width: 100%;
		display: flex;
		flex-direction: column;
		gap: 8px;
	}

	.next-label {
		font-size: 12px;
		font-weight: 600;
		text-transform: uppercase;
		letter-spacing: 0.08em;
		color: var(--c-text-dim);
		text-align: left;
		margin-bottom: 2px;
	}

	.next-item {
		width: 100%;
		display: flex;
		align-items: center;
		gap: 12px;
		padding: 14px 16px;
		background: var(--c-surface);
		border: 1px solid var(--c-border);
		border-radius: var(--radius);
		text-align: left;
		transition: border-color 0.15s;
	}

	.next-item:hover { border-color: var(--c-accent); }

	.next-item.primary {
		border-color: color-mix(in srgb, var(--c-accent) 40%, transparent);
		background: color-mix(in srgb, var(--c-accent) 5%, var(--c-surface));
	}

	.next-icon { font-size: 22px; flex-shrink: 0; }

	.next-item div { flex: 1; }

	.next-item strong {
		display: block;
		font-size: 14px;
		font-weight: 600;
		margin-bottom: 2px;
	}

	.next-item span {
		font-size: 12px;
		color: var(--c-text-dim);
	}

	.next-item svg { flex-shrink: 0; color: var(--c-text-dim); }
</style>
