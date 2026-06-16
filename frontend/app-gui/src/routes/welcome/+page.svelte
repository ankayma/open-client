<script lang="ts">
	import { goto } from '$app/navigation';
	import { auth } from '$lib/stores';
	import { signInGithub } from '$lib/tauri';

	let signing_in = $state(false);
	let error = $state<string | null>(null);

	async function handleSignIn() {
		signing_in = true;
		error = null;
		try {
			await signInGithub();
			auth.set({ status: 'authenticating' });
			goto('/dashboard');
		} catch (e) {
			error = e instanceof Error ? e.message : 'Sign-in failed';
			signing_in = false;
		}
	}
</script>

<main>
	<div class="hero">
		<div class="logo">
			<svg width="64" height="64" viewBox="0 0 64 64" fill="none" xmlns="http://www.w3.org/2000/svg">
				<rect width="64" height="64" rx="16" fill="#6366f1" fill-opacity="0.15"/>
				<path d="M32 14L48 23V41L32 50L16 41V23L32 14Z" stroke="#6366f1" stroke-width="2" fill="none"/>
				<circle cx="32" cy="32" r="6" fill="#6366f1"/>
			</svg>
		</div>
		<h1>Ankayma</h1>
		<p class="tagline">Zero-trust P2P network.<br/>Your infrastructure, your keys.</p>
	</div>

	<div class="features">
		<div class="feature">
			<span class="icon">🔒</span>
			<div>
				<strong>End-to-end encrypted</strong>
				<span>WireGuard mesh, customer-controlled keys</span>
			</div>
		</div>
		<div class="feature">
			<span class="icon">⚡</span>
			<div>
				<strong>Under 5 minutes to first tunnel</strong>
				<span>Connect any device, any network</span>
			</div>
		</div>
		<div class="feature">
			<span class="icon">🔍</span>
			<div>
				<strong>Open-source agent</strong>
				<span>Audit what runs on your nodes</span>
			</div>
		</div>
	</div>

	<div class="actions">
		{#if error}
			<p class="error">{error}</p>
		{/if}
		<button class="btn-primary" onclick={handleSignIn} disabled={signing_in}>
			{#if signing_in}
				<span class="spinner"></span> Signing in…
			{:else}
				<svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
					<path d="M12 2C6.477 2 2 6.477 2 12c0 4.418 2.865 8.166 6.839 9.489.5.092.682-.217.682-.482 0-.237-.009-.868-.013-1.703-2.782.604-3.369-1.342-3.369-1.342-.454-1.155-1.11-1.463-1.11-1.463-.908-.62.069-.608.069-.608 1.003.07 1.531 1.03 1.531 1.03.892 1.529 2.341 1.087 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.11-4.555-4.943 0-1.091.39-1.984 1.03-2.682-.103-.253-.447-1.27.098-2.646 0 0 .84-.269 2.75 1.025A9.578 9.578 0 0112 6.836a9.59 9.59 0 012.504.337c1.909-1.294 2.747-1.025 2.747-1.025.547 1.376.203 2.394.1 2.646.64.698 1.026 1.591 1.026 2.682 0 3.841-2.337 4.687-4.565 4.935.359.309.678.919.678 1.852 0 1.336-.012 2.415-.012 2.741 0 .267.18.578.688.48C19.138 20.163 22 16.418 22 12c0-5.523-4.477-10-10-10z"/>
				</svg>
				Continue with GitHub
			{/if}
		</button>
		<p class="terms">
			Free tier · No credit card required ·
			<a href="https://ankayma.com/terms" target="_blank" rel="noopener">Terms</a>
		</p>
	</div>
</main>

<style>
	main {
		flex: 1;
		display: flex;
		flex-direction: column;
		align-items: center;
		justify-content: space-between;
		padding: calc(var(--safe-top) + 48px) 24px calc(var(--safe-bottom) + 40px);
		max-width: 420px;
		margin: 0 auto;
		width: 100%;
	}

	.hero {
		text-align: center;
	}

	.logo {
		margin-bottom: 24px;
	}

	h1 {
		font-size: 32px;
		font-weight: 700;
		letter-spacing: -0.5px;
		margin-bottom: 12px;
	}

	.tagline {
		color: var(--c-text-dim);
		font-size: 16px;
		line-height: 1.6;
	}

	.features {
		display: flex;
		flex-direction: column;
		gap: 16px;
		width: 100%;
	}

	.feature {
		display: flex;
		align-items: flex-start;
		gap: 12px;
		padding: 16px;
		background: var(--c-surface);
		border: 1px solid var(--c-border);
		border-radius: var(--radius);
	}

	.icon {
		font-size: 20px;
		flex-shrink: 0;
		margin-top: 2px;
	}

	.feature strong {
		display: block;
		font-size: 14px;
		font-weight: 600;
		margin-bottom: 2px;
	}

	.feature span {
		font-size: 13px;
		color: var(--c-text-dim);
	}

	.actions {
		width: 100%;
		display: flex;
		flex-direction: column;
		align-items: center;
		gap: 12px;
	}

	.btn-primary {
		width: 100%;
		display: flex;
		align-items: center;
		justify-content: center;
		gap: 10px;
		padding: 16px 24px;
		background: var(--c-accent);
		color: #fff;
		border-radius: var(--radius);
		font-size: 16px;
		font-weight: 600;
		transition: background 0.15s;
	}

	.btn-primary:hover:not(:disabled) {
		background: var(--c-accent-dim);
	}

	.btn-primary:disabled {
		opacity: 0.6;
		cursor: not-allowed;
	}

	.spinner {
		width: 16px;
		height: 16px;
		border: 2px solid rgba(255,255,255,0.3);
		border-top-color: #fff;
		border-radius: 50%;
		animation: spin 0.7s linear infinite;
	}

	@keyframes spin {
		to { transform: rotate(360deg); }
	}

	.terms {
		font-size: 12px;
		color: var(--c-text-dim);
		text-align: center;
	}

	.error {
		font-size: 13px;
		color: var(--c-danger);
		background: color-mix(in srgb, var(--c-danger) 10%, transparent);
		padding: 10px 14px;
		border-radius: 8px;
		width: 100%;
		text-align: center;
	}
</style>
