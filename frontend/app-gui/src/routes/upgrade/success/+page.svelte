<script lang="ts">
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { auth, quota } from '$lib/stores';
	import { trackEvent } from '$lib/tauri';

	onMount(async () => {
		// [A] stub — real upgrade: control-plane webhook updates tier, agent-core refreshes quota
		// Here we just fire the funnel event and let the dashboard refresh quota on next poll
		try {
			await trackEvent('upgrade_success', { tier: 'F0-Plus' });
		} catch { /* non-blocking */ }

		// Auto-navigate to dashboard after 3s
		setTimeout(() => goto('/services'), 3000);
	});
</script>

<main>
	<div class="content">
		<div class="icon" aria-hidden="true">
			<svg width="64" height="64" viewBox="0 0 24 24" fill="none">
				<circle cx="12" cy="12" r="11" stroke="var(--c-success)" stroke-width="1.5"/>
				<path d="M7 12.5l3.5 3.5 6.5-7" stroke="var(--c-success)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
			</svg>
		</div>

		<h1>You're on F0-Plus</h1>
		<p class="sub">Your subscription is active. Enjoy 10× bandwidth, multiple subdomains, and raw TCP tunneling.</p>

		<div class="features">
			<div class="feature">
				<span class="dot"></span>
				<span>10× the free-tier bandwidth</span>
			</div>
			<div class="feature">
				<span class="dot"></span>
				<span>Multiple custom subdomains</span>
			</div>
			<div class="feature">
				<span class="dot"></span>
				<span>Raw TCP tunneling</span>
			</div>
			<div class="feature">
				<span class="dot"></span>
				<span>DLP basic — PII + payment card detection</span>
			</div>
		</div>

		<p class="redirect-note">Taking you to your dashboard…</p>

		<button class="btn" onclick={() => goto('/services')}>Go to dashboard now</button>
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
		gap: 16px;
		text-align: center;
	}

	.icon {
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
		line-height: 1.6;
	}

	.features {
		width: 100%;
		background: var(--c-surface);
		border: 1px solid var(--c-border);
		border-radius: var(--radius);
		padding: 16px 20px;
		display: flex;
		flex-direction: column;
		gap: 10px;
		text-align: left;
	}

	.feature {
		display: flex;
		align-items: center;
		gap: 10px;
		font-size: 14px;
	}

	.dot {
		width: 6px;
		height: 6px;
		border-radius: 50%;
		background: var(--c-success);
		flex-shrink: 0;
	}

	.redirect-note {
		font-size: 13px;
		color: var(--c-text-dim);
	}

	.btn {
		width: 100%;
		padding: 14px;
		background: var(--c-accent);
		color: #fff;
		border-radius: var(--radius);
		font-size: 15px;
		font-weight: 600;
	}

	.btn:hover { background: var(--c-accent-dim); }
</style>
