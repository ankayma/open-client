<script lang="ts">
	import { goto } from '$app/navigation';
	import { onMount, onDestroy } from 'svelte';
	import { get } from 'svelte/store';
	import { auth, pendingInvite } from '$lib/stores';
	import { signInGithub, pollLogin, submitSessionToken, joinTeamLink, takePendingJoinTeam } from '$lib/tauri';
	import { listen } from '@tauri-apps/api/event';

	// idle   → initial screen with GitHub button
	// waiting → browser opened; the app POLLS the handoff (no deep-link needed) and
	//           auto-signs-in when GitHub finishes. Paste box also shown as fallback.
	// paste  → manual fallback (no browser / headless)
	// joining → redeeming a magic-link team invite (no GitHub, no OTP) — Part D §A
	let step = $state<'idle' | 'waiting' | 'paste' | 'joining'>('idle');
	let busy = $state(false);
	let token = $state('');
	let error = $state<string | null>(null);

	// Magic-link team join (invitee has no GitHub): the emailed token IS the credential —
	// redeem it directly, ZERO confirm, no OTP (Part D §A invite-flow §Cases, doc 28-30).
	async function redeemInvite(inviteToken: string) {
		step = 'joining';
		error = null;
		try {
			const state = await joinTeamLink(inviteToken);
			auth.set(state);
			goto('/services');
		} catch (e) {
			error = e instanceof Error ? e.message : 'Could not join the team — the invite may have expired';
			step = 'idle';
		}
	}

	// One-time handoff nonce + poll loop: bấm-là-vô without the ankayma:// deep link.
	let nonce = '';
	let pollTimer: ReturnType<typeof setInterval> | undefined;

	function stopPoll() {
		if (pollTimer) {
			clearInterval(pollTimer);
			pollTimer = undefined;
		}
	}

	function startPoll() {
		stopPoll();
		let elapsed = 0;
		pollTimer = setInterval(async () => {
			elapsed += 2;
			if (elapsed > 300) return stopPoll(); // give up after 5 min
			try {
				const state = await pollLogin(nonce);
				if (state) {
					stopPoll();
					auth.set(state);
					goto('/services');
				}
			} catch {
				// transient network blip — keep polling
			}
		}, 2000);
	}

	async function handleSignIn() {
		busy = true;
		error = null;
		try {
			nonce = crypto.randomUUID();
			await signInGithub(nonce);
			// Browser opened → poll the handoff until GitHub completes, then auto-sign-in.
			step = 'waiting';
			startPoll();
		} catch {
			// Can't open a browser (headless / iOS sim) — fall back to manual paste.
			step = 'paste';
		} finally {
			busy = false;
		}
	}

	async function handleSubmitToken() {
		if (!token.trim()) return;
		busy = true;
		error = null;
		try {
			const state = await submitSessionToken(token.trim());
			stopPoll();
			auth.set(state);
			goto('/services');
		} catch (e) {
			error = e instanceof Error ? e.message : 'Invalid token';
			busy = false;
		}
	}

	function reset() {
		stopPoll();
		step = 'idle';
		error = null;
		token = '';
	}

	let cleanups: (() => void)[] = [];
	onMount(async () => {
		// Warm-start path: layout's join-team-pending listener already set the store.
		const inv = get(pendingInvite);
		if (inv?.type === 'join-team') {
			pendingInvite.set(null);
			redeemInvite(inv.token);
		} else {
			// Cold-start path: the join-team-pending event fired before the JS listener
			// registered (lost), but Rust holds the token in its mutex until we drain it.
			try {
				const tok = await takePendingJoinTeam();
				if (tok) redeemInvite(tok);
			} catch { /* Tauri not available in browser dev */ }
		}

		// Warm-start while already on welcome: deep link arrives → auth-pending fires →
		// check Rust for a newly-stored invite token and redeem immediately.
		const unsubPending = await listen('auth-pending', async () => {
			if (step === 'joining') return;
			try {
				const tok = await takePendingJoinTeam();
				if (tok) redeemInvite(tok);
			} catch { /* browser dev */ }
		});
		const unsubCancel = await listen('auth-cancelled', () => reset());
		cleanups.push(unsubPending, unsubCancel);
	});
	onDestroy(() => {
		stopPoll();
		for (const off of cleanups) off();
	});
</script>

<main>
	<div class="hero">
		<img class="logo-lockup" src="/ankayma_icon.png" alt="Ankayma" />
		<p class="tagline">The sovereign zero-trust mesh —<br/>identity-bound access, your keys, your proof.</p>
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
		{#if step === 'idle'}
			<button class="btn-primary" onclick={handleSignIn} disabled={busy}>
				{#if busy}
					<span class="spinner"></span> Opening browser…
				{:else}
					<svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
						<path d="M12 2C6.477 2 2 6.477 2 12c0 4.418 2.865 8.166 6.839 9.489.5.092.682-.217.682-.482 0-.237-.009-.868-.013-1.703-2.782.604-3.369-1.342-3.369-1.342-.454-1.155-1.11-1.463-1.11-1.463-.908-.62.069-.608.069-.608 1.003.07 1.531 1.03 1.531 1.03.892 1.529 2.341 1.087 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.11-4.555-4.943 0-1.091.39-1.984 1.03-2.682-.103-.253-.447-1.27.098-2.646 0 0 .84-.269 2.75 1.025A9.578 9.578 0 0112 6.836a9.59 9.59 0 012.504.337c1.909-1.294 2.747-1.025 2.747-1.025.547 1.376.203 2.394.1 2.646.64.698 1.026 1.591 1.026 2.682 0 3.841-2.337 4.687-4.565 4.935.359.309.678.919.678 1.852 0 1.336-.012 2.415-.012 2.741 0 .267.18.578.688.48C19.138 20.163 22 16.418 22 12c0-5.523-4.477-10-10-10z"/>
					</svg>
					Continue with GitHub
				{/if}
			</button>
			<button class="btn-link" onclick={() => { step = 'paste'; error = null; }}>
				Enter a token instead
			</button>

		{:else if step === 'waiting'}
			<div class="waiting-card">
				<span class="spinner-lg"></span>
				<p class="waiting-text">Waiting for GitHub…</p>
				<p class="waiting-sub">Approve access in the browser — you'll be signed in here automatically. Stuck? Tap <strong>Copy token</strong> there and paste it below.</p>
			</div>
			{#if error}<p class="error">{error}</p>{/if}
			<input
				class="token-input"
				type="text"
				placeholder="Paste session token"
				bind:value={token}
				autocomplete="off"
				spellcheck="false"
				onkeydown={(e) => e.key === 'Enter' && handleSubmitToken()}
			/>
			<button class="btn-primary" onclick={handleSubmitToken} disabled={busy || !token.trim()}>
				{#if busy}<span class="spinner"></span> Verifying…{:else}Paste token &amp; sign in{/if}
			</button>
			<button class="btn-link" onclick={handleSignIn} disabled={busy}>Re-open browser</button>
			<button class="btn-link" onclick={reset}>← Cancel</button>

		{:else if step === 'joining'}
			<div class="waiting-card">
				<span class="spinner-lg"></span>
				<p class="waiting-text">Joining the team…</p>
				<p class="waiting-sub">Redeeming your invite — you'll be signed in automatically.</p>
			</div>

		{:else}
			{#if error}<p class="error">{error}</p>{/if}
			<input
				class="token-input"
				type="text"
				placeholder="Paste session token"
				bind:value={token}
				autocomplete="off"
				spellcheck="false"
				onkeydown={(e) => e.key === 'Enter' && handleSubmitToken()}
			/>
			<button class="btn-primary" onclick={handleSubmitToken} disabled={busy || !token.trim()}>
				{#if busy}<span class="spinner"></span> Verifying…{:else}Sign in{/if}
			</button>
			<button class="btn-link" onclick={reset}>← Back</button>
		{/if}

		<p class="terms">
			Free tier · No credit card required ·
			<a href="https://ankayma.com/terms.html" target="_blank" rel="noopener">Terms</a>
		</p>
	</div>
</main>

<style>
	main {
		display: flex;
		flex-direction: column;
		align-items: center;
		gap: 32px;
		padding: calc(var(--safe-top) + 48px) 24px calc(var(--safe-bottom) + 40px);
		max-width: 420px;
		margin: 0 auto;
		width: 100%;
	}

	.hero {
		text-align: center;
	}

	.logo-lockup {
		width: 96px;
		height: 96px;
		border-radius: 22px;
		margin-bottom: 20px;
		display: block;
		margin-left: auto;
		margin-right: auto;
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

	.waiting-card {
		width: 100%;
		display: flex;
		flex-direction: column;
		align-items: center;
		gap: 10px;
		padding: 24px 16px;
		background: var(--c-surface);
		border: 1px solid var(--c-border);
		border-radius: var(--radius);
	}

	.spinner-lg {
		width: 28px;
		height: 28px;
		border: 3px solid var(--c-border);
		border-top-color: var(--c-accent);
		border-radius: 50%;
		animation: spin 0.8s linear infinite;
	}

	.waiting-text {
		font-size: 15px;
		font-weight: 600;
		color: var(--c-text);
	}

	.waiting-sub {
		font-size: 13px;
		color: var(--c-text-dim);
		text-align: center;
	}

	.token-input {
		width: 100%;
		padding: 14px 16px;
		background: var(--c-surface);
		border: 1px solid var(--c-border);
		border-radius: var(--radius);
		color: var(--c-text);
		font-size: 14px;
		font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
	}

	.token-input:focus {
		outline: none;
		border-color: var(--c-accent);
	}

	.btn-link {
		background: none;
		color: var(--c-text-dim);
		font-size: 13px;
		padding: 4px;
	}

	.btn-link:hover:not(:disabled) {
		color: var(--c-text);
	}
</style>
