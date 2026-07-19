<script lang="ts">
	import { goto } from '$app/navigation';
	import { invoke } from '@tauri-apps/api/core';

	let loading = $state(false);
	let error = $state('');

	// Which product family the user is buying. The control plane maps the plan key to a
	// Lemon Squeezy variant + our internal tier — the client only sends the key.
	let family = $state<'F0-Plus' | 'F1'>('F0-Plus');

	// F1 seat packs mirror the pricing page (team size → monthly price + admin count).
	const F1_PACKS = [
		{ seats: 3, mo: 19, admins: 1 },
		{ seats: 5, mo: 29, admins: 1 },
		{ seats: 10, mo: 49, admins: 2 },
		{ seats: 25, mo: 99, admins: 3 }
	];
	let seats = $state(3);

	// The plan key the control plane understands: "F0-Plus" or "F1-<seats>".
	let plan = $derived(family === 'F0-Plus' ? 'F0-Plus' : `F1-${seats}`);
	let price = $derived(family === 'F0-Plus' ? 9 : (F1_PACKS.find((p) => p.seats === seats)?.mo ?? 0));

	async function startCheckout() {
		loading = true;
		error = '';
		try {
			// Mark that a checkout is in flight. The checkout opens in the EXTERNAL browser,
			// so LS can't redirect back into the app — instead, when the app regains focus
			// and sees our tier has changed, the layout shows the success screen. The ts lets
			// a stale flag (abandoned checkout) expire. [T:layout onFocus]
			try { localStorage.setItem('ankayma_pending_upgrade', JSON.stringify({ plan, ts: Date.now() })); } catch { /* private mode */ }
			// Account-first: the control plane stamps our tenant into the checkout from the
			// session, so the paid webhook activates the right tenant. [T:A.1.1]
			await invoke('open_billing_checkout', { plan });
		} catch (e) {
			console.error(e);
			error = String(e);
		} finally {
			// Reset on BOTH paths: on success the checkout has opened in the browser, so the
			// button must stop spinning — it previously only reset on error, so a successful
			// open left it stuck on "Opening checkout…".
			loading = false;
		}
	}
</script>

<main>
	<button class="back-btn" onclick={() => goto('/services')} aria-label="Back">
		<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
			<path d="M19 12H5M12 5l-7 7 7 7"/>
		</svg>
	</button>

	<div class="content">
		<div class="tabs" role="tablist">
			<button class="tab" class:active={family === 'F0-Plus'} role="tab" aria-selected={family === 'F0-Plus'} onclick={() => (family = 'F0-Plus')}>
				F0-Plus
				<span>Personal</span>
			</button>
			<button class="tab" class:active={family === 'F1'} role="tab" aria-selected={family === 'F1'} onclick={() => (family = 'F1')}>
				F1 Team
				<span>Multi-user</span>
			</button>
		</div>

		{#if family === 'F0-Plus'}
			<h1>Upgrade to F0-Plus</h1>
			<p class="price">${price} <span class="per">/ month</span></p>
			<ul class="features">
				<li><span class="check">✓</span><div><strong>50 mesh nodes</strong><span>5× the free tier — 10 → 50 devices</span></div></li>
				<li><span class="check">✓</span><div><strong>20 private domains</strong><span>Branded names only your mesh resolves — 5 → 20</span></div></li>
				<li><span class="check">✓</span><div><strong>Raw TCP tunneling</strong><span>Any protocol, not just HTTP/S</span></div></li>
				<li><span class="check">✓</span><div><strong>Step-up 2FA</strong><span>TOTP second factor, optional YubiKey</span></div></li>
				<li><span class="check">✓</span><div><strong>Your existing mesh continues</strong><span>No re-enrollment, same keys</span></div></li>
			</ul>
		{:else}
			<h1>Upgrade to F1 Team</h1>
			<p class="price">${price} <span class="per">/ month</span></p>
			<div class="seats" role="group" aria-label="Team size">
				{#each F1_PACKS as pack}
					<button class="seat" class:active={seats === pack.seats} onclick={() => (seats = pack.seats)}>
						<strong>{pack.seats}</strong>
						<span>members</span>
					</button>
				{/each}
			</div>
			<p class="seat-note">
				{F1_PACKS.find((p) => p.seats === seats)?.admins} admin{(F1_PACKS.find((p) => p.seats === seats)?.admins ?? 1) > 1 ? 's' : ''}
				· up to {seats} members
			</p>
			<ul class="features">
				<li><span class="check">✓</span><div><strong>Everything in F0-Plus</strong><span>All personal features included</span></div></li>
				<li><span class="check">✓</span><div><strong>Team members</strong><span>Invite up to {seats} people</span></div></li>
				<li><span class="check">✓</span><div><strong>Shared policies &amp; access</strong><span>Team-wide PolicyBlocks and roles</span></div></li>
				<li><span class="check">✓</span><div><strong>Admin console</strong><span>Manage members, devices and audit</span></div></li>
			</ul>
		{/if}

		<button class="btn-primary" onclick={startCheckout} disabled={loading}>
			{#if loading}
				<span class="spinner"></span> Opening checkout…
			{:else}
				Subscribe — ${price}/mo
			{/if}
		</button>

		{#if error}
			<p class="error">{error}</p>
		{/if}

		<p class="terms">
			Cancel anytime. Billed monthly. Handled securely by Lemon Squeezy.
		</p>
	</div>
</main>

<style>
	main {
		flex: 1;
		display: flex;
		flex-direction: column;
		padding: calc(var(--safe-top) + 16px) 24px calc(var(--safe-bottom) + 40px);
		max-width: 420px;
		margin: 0 auto;
		width: 100%;
	}

	.back-btn {
		display: flex;
		align-items: center;
		color: var(--c-text-dim);
		padding: 8px 0;
		margin-bottom: 24px;
	}

	.content {
		display: flex;
		flex-direction: column;
		gap: 24px;
	}

	.tabs {
		display: flex;
		gap: 8px;
	}

	.tab {
		flex: 1;
		display: flex;
		flex-direction: column;
		align-items: center;
		gap: 2px;
		padding: 12px;
		border: 1px solid var(--c-border, rgba(128,128,128,0.3));
		border-radius: var(--radius);
		font-size: 15px;
		font-weight: 600;
		color: var(--c-text-dim);
		transition: all 0.15s;
	}

	.tab span {
		font-size: 11px;
		font-weight: 400;
	}

	.tab.active {
		border-color: var(--c-accent);
		color: var(--c-accent);
	}

	h1 {
		font-size: 26px;
		font-weight: 700;
		letter-spacing: -0.3px;
	}

	.price {
		font-size: 36px;
		font-weight: 700;
		color: var(--c-accent);
	}

	.price .per {
		font-size: 15px;
		font-weight: 400;
		color: var(--c-text-dim);
	}

	.seats {
		display: grid;
		grid-template-columns: repeat(4, 1fr);
		gap: 8px;
	}

	.seat {
		display: flex;
		flex-direction: column;
		align-items: center;
		padding: 12px 4px;
		border: 1px solid var(--c-border, rgba(128,128,128,0.3));
		border-radius: var(--radius);
		color: var(--c-text-dim);
		transition: all 0.15s;
	}

	.seat strong {
		font-size: 18px;
		font-weight: 700;
	}

	.seat span {
		font-size: 11px;
	}

	.seat.active {
		border-color: var(--c-accent);
		color: var(--c-accent);
	}

	.seat-note {
		font-size: 13px;
		color: var(--c-text-dim);
		margin-top: -12px;
	}

	.features {
		list-style: none;
		display: flex;
		flex-direction: column;
		gap: 16px;
	}

	.features li {
		display: flex;
		align-items: flex-start;
		gap: 12px;
	}

	.check {
		color: var(--c-success);
		font-size: 16px;
		font-weight: 700;
		flex-shrink: 0;
		margin-top: 2px;
	}

	.features strong {
		display: block;
		font-size: 15px;
		margin-bottom: 2px;
	}

	.features span {
		font-size: 13px;
		color: var(--c-text-dim);
	}

	.btn-primary {
		width: 100%;
		display: flex;
		align-items: center;
		justify-content: center;
		gap: 10px;
		padding: 16px;
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

	.error {
		font-size: 13px;
		color: var(--c-danger, #e5484d);
		text-align: center;
	}

	.terms {
		font-size: 12px;
		color: var(--c-text-dim);
		text-align: center;
	}
</style>
