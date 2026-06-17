<script lang="ts">
	import { goto } from '$app/navigation';
	import { trackEvent } from '$lib/tauri';

	// Fire cancel event non-blockingly
	trackEvent('upgrade_cancel', {}).catch(() => {});
</script>

<main>
	<div class="content">
		<div class="icon" aria-hidden="true">
			<svg width="56" height="56" viewBox="0 0 24 24" fill="none">
				<circle cx="12" cy="12" r="11" stroke="var(--c-text-dim)" stroke-width="1.5"/>
				<path d="M8 12h8" stroke="var(--c-text-dim)" stroke-width="2" stroke-linecap="round"/>
			</svg>
		</div>

		<h1>Checkout cancelled</h1>
		<p class="sub">No charge was made. You're still on the free tier — upgrade anytime.</p>

		<div class="actions">
			<button class="btn-primary" onclick={() => goto('/upgrade')}>Try again</button>
			<button class="btn-ghost" onclick={() => goto('/dashboard')}>Back to dashboard</button>
		</div>

		<div class="free-note">
			<p>Still on F0 free tier — 10 GB / month, up to 5 devices.</p>
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
		max-width: 360px;
		display: flex;
		flex-direction: column;
		align-items: center;
		gap: 20px;
		text-align: center;
	}

	.icon { margin-bottom: 4px; }

	h1 {
		font-size: 22px;
		font-weight: 700;
	}

	.sub {
		font-size: 15px;
		color: var(--c-text-dim);
		line-height: 1.6;
	}

	.actions {
		width: 100%;
		display: flex;
		flex-direction: column;
		gap: 10px;
	}

	.btn-primary {
		width: 100%;
		padding: 14px;
		background: var(--c-accent);
		color: #fff;
		border-radius: var(--radius);
		font-size: 15px;
		font-weight: 600;
	}

	.btn-primary:hover { background: var(--c-accent-dim); }

	.btn-ghost {
		width: 100%;
		padding: 14px;
		background: transparent;
		color: var(--c-text-dim);
		border: 1px solid var(--c-border);
		border-radius: var(--radius);
		font-size: 15px;
	}

	.btn-ghost:hover { border-color: var(--c-accent); color: var(--c-text); }

	.free-note {
		width: 100%;
		background: var(--c-surface);
		border: 1px solid var(--c-border);
		border-radius: var(--radius);
		padding: 14px;
		font-size: 13px;
		color: var(--c-text-dim);
	}
</style>
