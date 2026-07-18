<script lang="ts">
	// Shows what the agent actually knows about this device's security posture,
	// plus TOTP enrollment (E-7 StepUp Phase 2 — Part D §H.8).
	// No cert-renewal action here — not wired to a Tauri command yet, and a
	// button that does nothing is worse than no button (P.3 honest gap).
	import { onMount } from 'svelte';
	import { connection } from '$lib/stores';
	import { totpStatus, totpEnroll, totpConfirm, webauthnStatus } from '$lib/tauri';
	import { registerSecurityKey, webauthnAvailable } from '$lib/webauthn';

	// idle: not enrolled, offer setup. enrolling: secret shown, awaiting a code
	// to confirm. backupCodes: just confirmed — show the 10 one-time codes,
	// exactly once (never retrievable again). enrolled: a confirmed factor exists.
	let totpState = $state<'loading' | 'idle' | 'enrolling' | 'backupCodes' | 'enrolled'>('loading');
	let otpauthUrl = $state('');
	let secret = $state('');
	let confirmCode = $state('');
	let backupCodes = $state<string[]>([]);
	let totpError = $state('');
	let busy = $state(false);

	onMount(async () => {
		try {
			totpState = (await totpStatus()) ? 'enrolled' : 'idle';
		} catch {
			// Server has no STEPUP_TOTP_ENC_KEY configured, or not signed in —
			// either way, nothing to offer here (P.3 honest gap, no dead button).
			totpState = 'idle';
		}
		try {
			webauthnRegistered = await webauthnStatus();
		} catch {
			webauthnRegistered = false;
		}
	});

	// Security key (YubiKey/FIDO2) — E-7 StepUp Phase 3, AAL3.
	let webauthnRegistered = $state(false);
	let webauthnBusy = $state(false);
	let webauthnError = $state('');

	async function registerKey() {
		webauthnBusy = true;
		webauthnError = '';
		try {
			await registerSecurityKey();
			webauthnRegistered = true;
		} catch (e) {
			webauthnError = e instanceof Error ? e.message : 'Could not register the security key';
		} finally {
			webauthnBusy = false;
		}
	}

	async function startEnroll() {
		busy = true;
		totpError = '';
		try {
			[otpauthUrl, secret] = await totpEnroll();
			totpState = 'enrolling';
		} catch (e) {
			totpError = e instanceof Error ? e.message : 'Could not start TOTP setup';
		} finally {
			busy = false;
		}
	}

	async function confirmEnroll() {
		if (!confirmCode.trim()) return;
		busy = true;
		totpError = '';
		try {
			backupCodes = await totpConfirm(confirmCode.trim());
			confirmCode = '';
			totpState = 'backupCodes';
		} catch (e) {
			totpError = e instanceof Error ? e.message : 'Incorrect code';
		} finally {
			busy = false;
		}
	}

	function copy(text: string) {
		navigator.clipboard?.writeText(text);
	}
</script>

<main>
	<header>
		<h2>Security</h2>
	</header>

	<section class="card">
		<div class="section-label">Device</div>
		{#if $connection.status === 'connected'}
			<div class="row">
				<span class="label">Authentication level (AAL)</span>
				<span class="value">{$connection.aal ?? '—'}</span>
			</div>
			<div class="row">
				<span class="label">Device certificate</span>
				<span class="value" class:mono={!$connection.cert_expires_days}>
					{$connection.cert_expires_days ? `${$connection.cert_expires_days}d remaining` : 'not reported yet'}
				</span>
			</div>
		{:else}
			<div class="row">
				<span class="value dim">Connect to see AAL and certificate status.</span>
			</div>
		{/if}
	</section>

	<section class="card">
		<div class="section-label">Two-factor authentication</div>
		{#if totpState === 'loading'}
			<div class="row"><span class="value dim">Checking…</span></div>
		{:else if totpState === 'enrolled'}
			<div class="row">
				<span class="label">Authenticator app</span>
				<span class="value">Enabled</span>
			</div>
		{:else if totpState === 'idle'}
			<div class="row">
				<span class="value dim">
					Set up an authenticator app (Google Authenticator, 1Password, etc.) as your step-up
					factor — faster than waiting on an emailed code.
				</span>
			</div>
			<div class="row">
				<button class="su-primary" onclick={startEnroll} disabled={busy}>
					{busy ? 'Starting…' : 'Set up authenticator app'}
				</button>
			</div>
		{:else if totpState === 'enrolling'}
			<div class="row totp-setup">
				<p class="hint">Add this secret to your authenticator app (manual entry):</p>
				<button type="button" class="secret" onclick={() => copy(secret)} title="Tap to copy">
					{secret}
				</button>
				<p class="hint">Then enter the 6-digit code it shows:</p>
				<input
					bind:value={confirmCode}
					inputmode="numeric"
					autocomplete="one-time-code"
					maxlength="6"
					placeholder="6-digit code"
					class="code-input"
				/>
				{#if totpError}<p class="err">{totpError}</p>{/if}
				<button class="su-primary" onclick={confirmEnroll} disabled={busy || !confirmCode.trim()}>
					{busy ? 'Verifying…' : 'Confirm'}
				</button>
			</div>
		{:else if totpState === 'backupCodes'}
			<div class="row totp-setup">
				<p class="hint">
					Save these backup codes somewhere safe — each works once if you lose your authenticator
					app. They will not be shown again.
				</p>
				<div class="backup-codes">
					{#each backupCodes as c (c)}
						<span class="mono">{c}</span>
					{/each}
				</div>
				<button class="su-primary" onclick={() => (totpState = 'enrolled')}>Done</button>
			</div>
		{/if}
	</section>

	{#if webauthnAvailable()}
		<section class="card">
			<div class="section-label">Security key</div>
			{#if webauthnRegistered}
				<div class="row">
					<span class="label">YubiKey / security key</span>
					<span class="value">Registered</span>
				</div>
			{:else}
				<div class="row">
					<span class="value dim">
						Register a hardware security key (YubiKey or similar) — required once your plan
						reaches a tier that mandates it, optional before then.
					</span>
				</div>
				<div class="row">
					<button class="su-primary" onclick={registerKey} disabled={webauthnBusy}>
						{webauthnBusy ? 'Waiting for key…' : 'Register a security key'}
					</button>
				</div>
				{#if webauthnError}<p class="err">{webauthnError}</p>{/if}
			{/if}
		</section>
	{/if}
</main>

<style>
	main {
		flex: 1;
		display: flex;
		flex-direction: column;
		padding: 16px 16px calc(var(--safe-bottom) + 24px);
		gap: 16px;
		max-width: 420px;
		margin: 0 auto;
		width: 100%;
	}

	header {
		padding: 8px 0;
	}

	h2 {
		font-size: 20px;
		font-weight: 700;
	}

	.card {
		background: var(--c-surface);
		border: 1px solid var(--c-border);
		border-radius: var(--radius);
		overflow: hidden;
	}

	.section-label {
		font-size: 11px;
		font-weight: 700;
		text-transform: uppercase;
		letter-spacing: 0.08em;
		color: var(--c-text-dim);
		padding: 10px 16px 6px;
	}

	.row {
		display: flex;
		justify-content: space-between;
		align-items: center;
		padding: 14px 16px;
		border-bottom: 1px solid var(--c-border);
	}

	.row:last-child {
		border-bottom: none;
	}

	.label {
		font-size: 14px;
		color: var(--c-text-dim);
	}

	.value {
		font-size: 14px;
		font-weight: 500;
	}

	.value.mono {
		font-family: 'SF Mono', 'Fira Code', monospace;
		font-size: 13px;
		color: var(--c-text-dim);
	}

	.value.dim {
		color: var(--c-text-dim);
		font-weight: 400;
	}

	.totp-setup {
		flex-direction: column;
		align-items: stretch;
		gap: 10px;
	}

	.hint {
		font-size: 13px;
		line-height: 1.5;
		color: var(--c-text-dim);
	}

	.secret {
		font-family: 'SF Mono', 'Fira Code', monospace;
		font-size: 14px;
		letter-spacing: 1px;
		background: var(--c-bg);
		border: 1px solid var(--c-border);
		border-radius: 8px;
		padding: 10px 12px;
		text-align: center;
		word-break: break-all;
	}

	.code-input {
		background: var(--c-bg);
		border: 1px solid var(--c-border);
		border-radius: 8px;
		padding: 10px 12px;
		color: var(--c-text);
		font-size: 16px;
		letter-spacing: 3px;
		text-align: center;
	}

	.backup-codes {
		display: grid;
		grid-template-columns: 1fr 1fr;
		gap: 8px;
		background: var(--c-bg);
		border: 1px solid var(--c-border);
		border-radius: 8px;
		padding: 12px;
	}

	.backup-codes .mono {
		font-family: 'SF Mono', 'Fira Code', monospace;
		font-size: 13px;
		text-align: center;
	}

	.err {
		color: var(--c-danger);
		font-size: 13px;
	}

	.su-primary {
		font-size: 14px;
		font-weight: 600;
		color: #fff;
		background: var(--c-accent);
		padding: 10px 16px;
		border-radius: 8px;
	}
	.su-primary:disabled {
		opacity: 0.5;
	}
</style>
