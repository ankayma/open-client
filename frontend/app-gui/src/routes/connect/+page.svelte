<script lang="ts">
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { connection } from '$lib/stores';
	import { getConnectionStatus } from '$lib/tauri';

	// [A] stub steps — real sequence wired to agent-core enrollment (milestone 1.2)
	const STEPS = [
		{ id: 'keys',   label: 'Generating keys',     sub: 'WireGuard keypair created on your device' },
		{ id: 'enroll', label: 'Enrolling node',       sub: 'Registering with your tenant CA' },
		{ id: 'tunnel', label: 'Tunnel ready',         sub: 'Overlay IP assigned, mesh joined' },
	] as const;

	let current = $state(0);   // index into STEPS
	let failed  = $state(false);
	let error   = $state('');

	onMount(async () => {
		// Poll real status once agent-core is wired.
		// For now advance through steps on a timer to show the UX.
		try {
			const status = await getConnectionStatus();
			if (status.status === 'connected') {
				goto('/connected');
				return;
			}
		} catch { /* Tauri not available */ }

		// Animate steps — replace with real event stream from agent-core
		for (let i = 0; i < STEPS.length; i++) {
			current = i;
			await delay(i === 0 ? 800 : 1200);
		}
		// After all steps: poll once more
		try {
			const status = await getConnectionStatus();
			if (status.status === 'connected') {
				connection.set(status);
				goto('/connected');
			} else {
				goto('/dashboard');
			}
		} catch {
			goto('/dashboard');
		}
	});

	function delay(ms: number) {
		return new Promise(r => setTimeout(r, ms));
	}
</script>

<main>
	<div class="content">
		<div class="logo-wrap">
			<svg width="52" height="52" viewBox="0 0 64 64" fill="none" xmlns="http://www.w3.org/2000/svg">
				<rect width="64" height="64" rx="14" fill="#6366f1" fill-opacity="0.15"/>
				<path d="M32 12L50 22V42L32 52L14 42V22L32 12Z" stroke="#6366f1" stroke-width="2" fill="none" stroke-linejoin="round"/>
				<circle cx="32" cy="32" r="7" fill="#6366f1"/>
			</svg>
		</div>

		<h1>Joining your mesh</h1>
		<p class="sub">Setting up your secure node. This takes about 30 seconds.</p>

		<div class="steps">
			{#each STEPS as step, i}
				<div class="step" class:done={i < current} class:active={i === current} class:pending={i > current}>
					<div class="step-icon">
						{#if i < current}
							<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
								<path d="M20 6L9 17l-5-5"/>
							</svg>
						{:else if i === current}
							<span class="spinner"></span>
						{:else}
							<span class="dot"></span>
						{/if}
					</div>
					<div class="step-text">
						<span class="step-label">{step.label}</span>
						{#if i <= current}
							<span class="step-sub">{step.sub}</span>
						{/if}
					</div>
				</div>
			{/each}
		</div>

		{#if failed}
			<div class="error-box">
				<p>{error || 'Connection failed. Please try again.'}</p>
				<button onclick={() => goto('/dashboard')}>Back to dashboard</button>
			</div>
		{/if}

		<p class="note">Private key never leaves your device</p>
	</div>
</main>

<style>
	main {
		flex: 1;
		display: flex;
		align-items: center;
		justify-content: center;
		padding: calc(var(--safe-top) + 24px) 24px calc(var(--safe-bottom) + 24px);
		min-height: 100dvh;
	}

	.content {
		width: 100%;
		max-width: 360px;
		display: flex;
		flex-direction: column;
		align-items: center;
		gap: 8px;
		text-align: center;
	}

	.logo-wrap { margin-bottom: 16px; }

	h1 {
		font-size: 22px;
		font-weight: 700;
		margin-bottom: 4px;
	}

	.sub {
		font-size: 14px;
		color: var(--c-text-dim);
		margin-bottom: 32px;
	}

	.steps {
		width: 100%;
		display: flex;
		flex-direction: column;
		gap: 0;
		text-align: left;
		margin-bottom: 32px;
	}

	.step {
		display: flex;
		align-items: flex-start;
		gap: 14px;
		padding: 14px 0;
		border-bottom: 1px solid var(--c-border);
		transition: opacity 0.2s;
	}

	.step:last-child { border-bottom: none; }
	.step.pending { opacity: 0.35; }

	.step-icon {
		width: 28px;
		height: 28px;
		border-radius: 50%;
		display: flex;
		align-items: center;
		justify-content: center;
		flex-shrink: 0;
		margin-top: 2px;
	}

	.step.done .step-icon {
		background: color-mix(in srgb, var(--c-success) 15%, transparent);
		color: var(--c-success);
	}

	.step.active .step-icon {
		background: color-mix(in srgb, var(--c-accent) 15%, transparent);
	}

	.step.pending .step-icon {
		background: var(--c-border);
	}

	.spinner {
		width: 14px;
		height: 14px;
		border: 2px solid color-mix(in srgb, var(--c-accent) 30%, transparent);
		border-top-color: var(--c-accent);
		border-radius: 50%;
		animation: spin 0.7s linear infinite;
	}

	.dot {
		width: 6px;
		height: 6px;
		border-radius: 50%;
		background: var(--c-text-dim);
	}

	@keyframes spin { to { transform: rotate(360deg); } }

	.step-text { display: flex; flex-direction: column; gap: 2px; }

	.step-label {
		font-size: 15px;
		font-weight: 600;
	}

	.step-sub {
		font-size: 12px;
		color: var(--c-text-dim);
	}

	.note {
		font-size: 12px;
		color: var(--c-text-dim);
		display: flex;
		align-items: center;
		gap: 4px;
	}

	.note::before { content: "🔒"; font-size: 12px; }

	.error-box {
		width: 100%;
		background: color-mix(in srgb, var(--c-danger) 10%, transparent);
		border: 1px solid color-mix(in srgb, var(--c-danger) 30%, transparent);
		border-radius: var(--radius);
		padding: 16px;
		font-size: 14px;
		color: var(--c-danger);
	}

	.error-box button {
		margin-top: 10px;
		color: var(--c-text-dim);
		font-size: 13px;
		text-decoration: underline;
	}
</style>
