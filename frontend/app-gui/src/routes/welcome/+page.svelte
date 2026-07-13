<script lang="ts">
	import { goto } from '$app/navigation';
	import { onMount, onDestroy } from 'svelte';
	import { get } from 'svelte/store';
	import { auth, pendingInvite } from '$lib/stores';
	import { signInGithub, pollLogin, submitSessionToken, joinTeamLink, takePendingJoinTeam, getPlatform } from '$lib/tauri';
	import { listen } from '@tauri-apps/api/event';

	// idle   → initial screen with GitHub button
	// waiting → browser opened; the app POLLS the handoff (no deep-link needed) and
	//           auto-signs-in when GitHub finishes. Paste box also shown as fallback.
	// paste  → manual fallback (no browser / headless)
	// joining → redeeming a magic-link team invite (no GitHub, no OTP) — Part D §A
	// join-node → node-invite entry (QR): OS-camera scan opens the ankayma:// link by
	//             itself; this panel is the paste fallback + the future in-app scanner.
	//             TODO[A]: in-app camera decode needs an owner-gated dep (A.1.21 —
	//             jsQR / tauri-plugin-barcode-scanner); until then paste-only.
	let step = $state<'idle' | 'waiting' | 'paste' | 'joining' | 'join-node'>('idle');
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
				if (state?.status === 'cancelled') {
					// User bailed on a browser-side step (e.g. the region picker) —
					// stop polling and say so, instead of hanging on "Waiting for
					// GitHub..." for up to 5 minutes with no explanation.
					stopPoll();
					error = 'Sign-in cancelled.';
					step = 'idle';
				} else if (state) {
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
		joinInput = '';
	}

	// Node-invite paste path (mirrors add-device Cases C/D: scan = enrolled, the
	// join token IS the authorization — no session needed).
	let joinInput = $state('');
	let joinBusy = $state(false);
	let scanning = $state(false);

	// [scan-qr] Open the in-app native camera scanner (tauri-plugin-barcode-scanner,
	// mobile-only). On success the decoded `ankayma://join?token=…` is redeemed
	// directly. On desktop (no camera scanner) or on cancel/error, fall back to the
	// paste step so the flow always has a path.
	async function startScan() {
		error = null;
		let platform = 'unknown';
		try { platform = await getPlatform(); } catch { /* browser dev */ }
		if (platform !== 'ios' && platform !== 'android') {
			step = 'join-node'; // desktop → paste fallback
			return;
		}
		try {
			const { scan, checkPermissions, requestPermissions, Format } =
				await import('@tauri-apps/plugin-barcode-scanner');
			let perm = await checkPermissions();
			if (perm !== 'granted') perm = await requestPermissions();
			if (perm !== 'granted') {
				error = 'Camera permission is needed to scan the invite QR.';
				step = 'join-node';
				return;
			}
			// The native scanner makes the webview transparent (camera behind); our
			// overlay (frame + Cancel) is drawn on top — toggle the transparent mode.
			scanning = true;
			document.documentElement.classList.add('scanning');
			const res = await scan({ windowed: true, formats: [Format.QRCode] });
			document.documentElement.classList.remove('scanning');
			scanning = false;
			if (res?.content) {
				// Show what was scanned + let any redeem error surface on the paste step.
				joinInput = res.content;
				step = 'join-node';
				await redeemScanned(res.content); // success → /services; fail → error shown
			}
		} catch (e) {
			// user cancelled the scanner, or the plugin is unavailable → paste path.
			const msg = e instanceof Error ? e.message : String(e);
			if (!/cancel/i.test(msg)) { error = msg; step = 'join-node'; }
		} finally {
			document.documentElement.classList.remove('scanning');
			scanning = false;
		}
	}

	// Cancel an in-progress scan (Cancel button on the scan overlay).
	async function cancelScan() {
		try {
			const { cancel } = await import('@tauri-apps/plugin-barcode-scanner');
			await cancel();
		} catch { /* nothing to cancel */ }
		document.documentElement.classList.remove('scanning');
		scanning = false;
	}

	// Redeem a scanned/typed invite (shared by camera result + paste). A TEAM
	// invite makes you a member and returns a session → straight into the app. A
	// node/device invite only enrols a device and carries NO session, so the GUI
	// (which needs a session to show services) can't sign you in from it — guide
	// the user instead of dumping them on an empty, footer-less page.
	async function redeemScanned(raw: string) {
		const v = raw.trim();
		if (!v) return;
		joinBusy = true;
		error = null;
		try {
			const m = v.match(/token=([^&\s]+)/);
			const tok = m ? m[1] : v;
			if (/join-team/.test(v)) {
				const state = await joinTeamLink(tok);
				auth.set(state);
				goto('/services');
			} else if (/\bjoin\b/.test(v)) {
				error = 'This is a device invite. Sign in first, then add this device from Settings → My Devices.';
			} else {
				// Bare token — try it as a team invite (the only kind that signs you in).
				const state = await joinTeamLink(tok);
				auth.set(state);
				goto('/services');
			}
		} catch (e) {
			error = e instanceof Error ? e.message : 'Could not join — the invite may have expired.';
		} finally {
			joinBusy = false;
		}
	}
	function handleJoinNode() {
		redeemScanned(joinInput);
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

	<!-- [T per wow-5p plan §3a] 3 wow actions + the proof that closes each one —
	     sovereignty evidence, not connectivity (connectivity is commodity). -->
	<div class="features">
		<div class="feature">
			<span class="icon">🧾</span>
			<div>
				<strong>No-secret CI/CD</strong>
				<span>Deploy from CI with no static secret — every run ends in a signed receipt</span>
			</div>
		</div>
		<div class="feature">
			<span class="icon">🔑</span>
			<div>
				<strong>No-key SSH</strong>
				<span>SSH to prod: no bastion, no static key — every session lands in your ledger</span>
			</div>
		</div>
		<div class="feature">
			<span class="icon">🌐</span>
			<div>
				<strong>Private domain</strong>
				<span>Your services on your own domain — only your mesh can see them</span>
			</div>
		</div>
		<div class="feature">
			<span class="icon">◈</span>
			<div>
				<strong>Prove it</strong>
				<span>One click shows the real path: peer-to-peer, vendor never in the middle</span>
			</div>
		</div>
		<p class="coexist">Adds on without touching what's already running.</p>
	</div>

	<div class="actions">
		{#if step === 'idle'}
			<div class="signin-row">
				<button class="btn-primary" onclick={handleSignIn} disabled={busy}>
					{#if busy}
						<span class="spinner"></span> Opening…
					{:else}
						<svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
							<path d="M12 2C6.477 2 2 6.477 2 12c0 4.418 2.865 8.166 6.839 9.489.5.092.682-.217.682-.482 0-.237-.009-.868-.013-1.703-2.782.604-3.369-1.342-3.369-1.342-.454-1.155-1.11-1.463-1.11-1.463-.908-.62.069-.608.069-.608 1.003.07 1.531 1.03 1.531 1.03.892 1.529 2.341 1.087 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.11-4.555-4.943 0-1.091.39-1.984 1.03-2.682-.103-.253-.447-1.27.098-2.646 0 0 .84-.269 2.75 1.025A9.578 9.578 0 0112 6.836a9.59 9.59 0 012.504.337c1.909-1.294 2.747-1.025 2.747-1.025.547 1.376.203 2.394.1 2.646.64.698 1.026 1.591 1.026 2.682 0 3.841-2.337 4.687-4.565 4.935.359.309.678.919.678 1.852 0 1.336-.012 2.415-.012 2.741 0 .267.18.578.688.48C19.138 20.163 22 16.418 22 12c0-5.523-4.477-10-10-10z"/>
						</svg>
						GitHub
					{/if}
				</button>
				<button class="btn-scan" onclick={startScan} disabled={scanning} title="Scan QR to join a mesh">
					<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
						<path d="M3 7V5a2 2 0 012-2h2M17 3h2a2 2 0 012 2v2M21 17v2a2 2 0 01-2 2h-2M7 21H5a2 2 0 01-2-2v-2"/>
						<path d="M7 12h10" stroke-width="2.2"/>
					</svg>
					Scan QR
				</button>
			</div>
			<button class="btn-link" onclick={() => { step = 'paste'; error = null; }}>
				Enter a token instead
			</button>

		{:else if step === 'join-node'}
			<div class="waiting-card">
				<p class="waiting-text">Join this device to a mesh</p>
				<p class="waiting-sub">
					Paste the invite link below, or go back and tap <strong>Scan QR</strong> to use
					the camera. The <code>ankayma://join</code> token is the credential — no sign-in needed.
				</p>
			</div>
			{#if error}<p class="error">{error}</p>{/if}
			<input
				class="token-input"
				type="text"
				placeholder="ankayma://join?token=…  (or the raw token)"
				bind:value={joinInput}
				autocomplete="off"
				spellcheck="false"
				onkeydown={(e) => e.key === 'Enter' && handleJoinNode()}
			/>
			<button class="btn-primary" onclick={handleJoinNode} disabled={joinBusy || !joinInput.trim()}>
				{#if joinBusy}<span class="spinner"></span> Joining…{:else}Join mesh{/if}
			</button>
			<button class="btn-link" onclick={reset}>← Back</button>

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
			Free tier · No credit card required · Open-source agent ·
			<a href="https://ankayma.com/terms.html" target="_blank" rel="noopener">Terms</a>
		</p>
	</div>
</main>

<!-- [scan-qr] Camera overlay: the native scanner shows the camera behind a
     transparent webview; this draws the viewfinder + a Cancel button on top. -->
{#if scanning}
	<div class="scan-overlay">
		<div class="scan-frame"></div>
		<p class="scan-hint">Point the camera at the invite QR code</p>
		<button class="scan-cancel" onclick={cancelScan} aria-label="Cancel scan">✕ Cancel</button>
	</div>
{/if}

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

	/* Desktop: widen and lay the 4 wow cards out 2×2 so the GitHub CTA sits
	   above the fold — no scroll to reach sign-in. */
	@media (min-width: 700px) {
		main {
			max-width: 800px;
			gap: 24px;
			padding-top: calc(var(--safe-top) + 32px);
		}
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
		display: grid;
		grid-template-columns: 1fr;
		gap: 16px;
		width: 100%;
	}

	@media (min-width: 700px) {
		.features {
			grid-template-columns: 1fr 1fr;
			gap: 12px;
		}

		.coexist {
			grid-column: 1 / -1;
		}
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

	.coexist {
		font-size: 12px;
		color: var(--c-text-dim);
		text-align: center;
		font-style: italic;
	}

	.actions {
		width: 100%;
		max-width: 420px;
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

	.signin-row {
		width: 100%;
		display: flex;
		gap: 10px;
	}
	.signin-row .btn-primary {
		flex: 2;
		width: auto;
	}
	.btn-scan {
		flex: 1;
		display: flex;
		align-items: center;
		justify-content: center;
		gap: 7px;
		padding: 14px 12px;
		background: var(--btn-secondary-bg, transparent);
		color: var(--c-text);
		border: 1px solid color-mix(in srgb, var(--c-accent) 40%, var(--c-border));
		border-radius: var(--radius);
		font-size: 14px;
		font-weight: 600;
		white-space: nowrap;
		transition: background 0.15s, border-color 0.15s;
	}

	.btn-scan:hover:not(:disabled) {
		background: color-mix(in srgb, var(--c-accent) 10%, transparent);
		border-color: var(--c-accent);
	}

	.btn-scan:disabled {
		opacity: 0.6;
		cursor: not-allowed;
	}

	/* During a scan the WKWebView is made transparent so the native camera shows
	   through — hide the welcome content and clear every ancestor background. */
	:global(html.scanning),
	:global(html.scanning body),
	:global(html.scanning .app),
	:global(html.scanning .view) {
		background: transparent !important;
	}
	:global(html.scanning main) {
		visibility: hidden;
	}

	.scan-overlay {
		position: fixed;
		inset: 0;
		z-index: 500;
		display: flex;
		flex-direction: column;
		align-items: center;
		justify-content: center;
		gap: 20px;
		padding: 40px 24px calc(var(--safe-bottom) + 40px);
		background: transparent;
	}
	.scan-frame {
		width: 240px;
		height: 240px;
		border: 3px solid #fff;
		border-radius: 20px;
		box-shadow: 0 0 0 100vmax rgba(0, 0, 0, 0.35);
	}
	.scan-hint {
		color: #fff;
		font-size: 15px;
		font-weight: 600;
		text-shadow: 0 1px 3px rgba(0, 0, 0, 0.6);
	}
	.scan-cancel {
		margin-top: auto;
		padding: 14px 28px;
		background: rgba(20, 20, 24, 0.9);
		color: #fff;
		border: 1px solid rgba(255, 255, 255, 0.3);
		border-radius: 99px;
		font-size: 16px;
		font-weight: 600;
	}
</style>
