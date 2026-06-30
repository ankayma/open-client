<script lang="ts">
	import { goto } from '$app/navigation';
	import { invoke } from '@tauri-apps/api/core';

	let loading = $state(false);

	async function startCheckout() {
		loading = true;
		try {
			// Opens Stripe checkout in system browser (control-plane generates session URL)
			// [T:A.1.1] billing logic lives in control-plane, not client
			await invoke('open_stripe_checkout');
		} catch (e) {
			console.error(e);
			loading = false;
		}
	}
</script>

<main>
	<button class="back-btn" onclick={() => goto('/services')}>
		<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
			<path d="M19 12H5M12 5l-7 7 7 7"/>
		</svg>
	</button>

	<div class="content">
		<h1>Upgrade to F0-Plus</h1>
		<p class="price">$9 / month</p>

		<ul class="features">
			<li>
				<span class="check">✓</span>
				<div>
					<strong>More bandwidth</strong>
					<span>10× the free tier quota</span>
				</div>
			</li>
			<li>
				<span class="check">✓</span>
				<div>
					<strong>Multiple subdomains</strong>
					<span>Custom subdomains for each service</span>
				</div>
			</li>
			<li>
				<span class="check">✓</span>
				<div>
					<strong>Raw TCP tunneling</strong>
					<span>Any protocol, not just HTTP/S</span>
				</div>
			</li>
			<li>
				<span class="check">✓</span>
				<div>
					<strong>DLP basic</strong>
					<span>PII and payment card detection</span>
				</div>
			</li>
			<li>
				<span class="check">✓</span>
				<div>
					<strong>Your existing mesh continues</strong>
					<span>No re-enrollment, same keys</span>
				</div>
			</li>
		</ul>

		<button class="btn-primary" onclick={startCheckout} disabled={loading}>
			{#if loading}
				<span class="spinner"></span> Opening checkout…
			{:else}
				Subscribe with Stripe
			{/if}
		</button>

		<p class="terms">
			Cancel anytime. Billed monthly. Handled securely by Stripe.
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

	.terms {
		font-size: 12px;
		color: var(--c-text-dim);
		text-align: center;
	}
</style>
