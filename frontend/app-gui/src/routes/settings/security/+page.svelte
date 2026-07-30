<script lang="ts">
	// Shows what the agent actually knows about this device's security posture,
	// plus TOTP enrollment (E-7 StepUp Phase 2 — Part D §H.8).
	// No cert-renewal action here — not wired to a Tauri command yet, and a
	// button that does nothing is worse than no button (P.3 honest gap).
	import { onMount } from 'svelte';
	import { connection } from '$lib/stores';
	import {
		totpStatus,
		totpEnroll,
		totpConfirm,
		totpDisable,
		webauthnStatus,
		getPlatform,
		platformKeyStatus,
		platformKeyEnroll,
		platformKeyList,
		securityKeyList,
		platformKeyRemove,
		securityKeyRemove,
		type StepUpFactor
	} from '$lib/tauri';
	import { runWithStepUp } from '$lib/stepup';
	import { registerSecurityKey, webauthnAvailable } from '$lib/webauthn';

	// Tauri's invoke() rejects a failed `Result<T, String>` command with the raw
	// string, NOT an Error instance — only browser-thrown errors (e.g.
	// navigator.credentials.* in webauthn.ts) are real Error objects. `e
	// instanceof Error ? e.message : fallback` silently swallows every Tauri-side
	// error behind a generic fallback. This covers both shapes correctly.
	function errMsg(e: unknown, fallback: string): string {
		if (typeof e === 'string' && e) return e;
		if (e instanceof Error && e.message) return e.message;
		return fallback;
	}

	// idle: not enrolled, offer setup. enrolling: secret shown, awaiting a code
	// to confirm. enrolled: a confirmed factor exists. No backup-codes step
	// (removed 2026-07-20): a lost authenticator recovers via
	// the email-OTP AAL2 path or an admin/vendor disable.
	let totpState = $state<'loading' | 'idle' | 'enrolling' | 'enrolled'>('loading');
	let otpauthUrl = $state('');
	let secret = $state('');
	let confirmCode = $state('');
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
			await loadFactors();
		} catch {
			webauthnRegistered = false;
		}
		// webauthnAvailable() is async now: on macOS the answer depends on whether the
		// NATIVE ceremony is available, which only Rust can answer — the webview's own
		// navigator.credentials check says yes and then fails every roaming key.
		try {
			securityKeySupported = await webauthnAvailable();
		} catch {
			securityKeySupported = false;
		}
		try {
			const plat = await getPlatform();
			// Same Secure Enclave + LocalAuthentication factor on both Apple platforms; only
			// the name the user knows it by differs, and on iPad/older iPhones it is Touch ID
			// rather than Face ID, so keep the wording covering both there.
			isMacOS = plat === 'macos';
			// iOS is deliberately excluded. security-framework never attaches
			// kSecAttrAccessControl on iOS (the kSecPrivateKeyAttrs push is inside a
			// cfg(target_os = "macos") block), so the Secure Enclave key came out with NO
			// biometric constraint: it signed without ever showing Face ID, and the server
			// accepted it as a valid AAL2 factor. A biometric control that does not check
			// biometrics is worse than none, so the section stays hidden here until key
			// generation is done against SecKeyCreateRandomKey directly.
			// [T — reproduced on an iPhone 11 / iOS 18.7.8 with 1.1.29, 2026-07-30]
			biometricSupported = plat === 'macos' || plat === 'ios';
			biometricName = plat === 'ios' ? 'Face ID' : 'Touch ID';
		} catch {
			isMacOS = false;
			biometricSupported = false;
		}
		if (biometricSupported) {
			try {
				platformKeyRegistered = await platformKeyStatus();
			} catch {
				// Server has no platform-key endpoint yet, or not signed in — the
				// section still shows (this IS a Mac), just as not-yet-set-up.
				platformKeyRegistered = false;
			}
		}
	});

	// Touch ID (E-7 StepUp biometric-only factor, macOS-only for now — owner-directed
	// 2026-07-28). Deliberately separate from the security-key section: this is a
	// Secure Enclave key with biometryCurrentSet, not a WebAuthn/passkey credential.
	let isMacOS = $state(false);
	let biometricSupported = $state(false);
	let biometricName = $state('Touch ID');
	let platformKeyRegistered = $state(false);
	let platformKeyBusy = $state(false);
	let platformKeyError = $state('');

	async function enrollPlatformKey() {
		platformKeyBusy = true;
		platformKeyError = '';
		try {
			await platformKeyEnroll();
			platformKeyRegistered = true;
		} catch (e) {
			platformKeyError = errMsg(e, 'Could not set up Touch ID');
		} finally {
			platformKeyBusy = false;
		}
	}

	// Enrolled factors, listed so they can be removed one by one.
	//
	// This list exists because the account accumulated keys nobody could see. Every
	// re-enrolment registers a NEW key on the account, and the enrol path deliberately
	// destroys the local key first rather than reuse one it cannot verify is still
	// usable — so a few rounds of debugging leave several keys behind, of which at most
	// one per device can still sign. Status reported only a count, so none of them were
	// reachable: you cannot revoke what you cannot name.
	type FactorRow = StepUpFactor & { kind: 'biometric' | 'security' };
	let factors = $state<FactorRow[]>([]);
	let factorsLoaded = $state(false);
	let factorError = $state('');
	let removingId = $state('');
	let confirmingId = $state('');

	async function loadFactors() {
		try {
			const [bio, sec] = await Promise.all([
				platformKeyList().catch(() => [] as StepUpFactor[]),
				securityKeyList().catch(() => [] as StepUpFactor[])
			]);
			factors = [
				...bio.map((f) => ({ ...f, kind: 'biometric' as const })),
				...sec.map((f) => ({ ...f, kind: 'security' as const }))
			];
		} finally {
			factorsLoaded = true;
		}
	}

	async function removeFactor(f: FactorRow) {
		removingId = f.id;
		factorError = '';
		try {
			// `manage_auth_factor` is single-use server-side: one ceremony authorizes
			// exactly one removal, so removing three keys means three ceremonies. That
			// is the server's deliberate choice, not something to batch around here.
			await runWithStepUp('manage_auth_factor', (proof) =>
				f.kind === 'biometric'
					? platformKeyRemove(f.id, proof?.proofToken)
					: securityKeyRemove(f.id, proof?.proofToken)
			);
			await loadFactors();
			// The enrol/registered rows above are now stale — re-read rather than
			// guessing, since removing one of several keys may leave the factor set up.
			platformKeyRegistered = await platformKeyStatus().catch(() => false);
			webauthnRegistered = await webauthnStatus().catch(() => false);
		} catch (e) {
			factorError = errMsg(e, 'Could not remove this key');
		} finally {
			removingId = '';
			confirmingId = '';
		}
	}

	function shortDate(iso: string | null): string {
		if (!iso) return '';
		// Postgres `timestamptz::text` is "2026-07-30 12:22:51.05+08", which Safari's
		// Date parser rejects outright — it wants a `T` and no fractional-second slop.
		// Slicing beats parsing: the user needs to tell four keys apart, not know the
		// millisecond. [T: WebKit rejects space-separated datetimes that V8 accepts]
		return iso.slice(0, 16).replace(' ', ' · ');
	}

	// Security key (YubiKey/FIDO2) — E-7 StepUp Phase 3, AAL3.
	let webauthnRegistered = $state(false);
	let securityKeySupported = $state(false);
	let webauthnBusy = $state(false);
	let webauthnError = $state('');

	async function registerKey() {
		webauthnBusy = true;
		webauthnError = '';
		try {
			await registerSecurityKey();
			webauthnRegistered = true;
		} catch (e) {
			webauthnError = errMsg(e, 'Could not register the security key');
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
			totpError = errMsg(e, 'Could not start TOTP setup');
		} finally {
			busy = false;
		}
	}

	async function confirmEnroll() {
		if (!confirmCode.trim()) return;
		busy = true;
		totpError = '';
		try {
			await totpConfirm(confirmCode.trim());
			confirmCode = '';
			totpState = 'enrolled';
		} catch (e) {
			totpError = errMsg(e, 'Incorrect code');
		} finally {
			busy = false;
		}
	}

	// Remove the confirmed TOTP factor. Gated by a `manage_auth_factor` step-up:
	// runWithStepUp drives the modal (the user's own TOTP, or the AAL2 email
	// "lost-authenticator" fallback at F0-Plus/F1) and retries with the proof.
	// This is also the escape hatch for a stale/unwanted enrollment.
	// [T:Part D §H.9]
	async function disableTotp() {
		busy = true;
		totpError = '';
		try {
			await runWithStepUp('manage_auth_factor', (proof) => totpDisable(proof));
			totpState = 'idle';
		} catch (e) {
			if (e instanceof Error && e.message === 'Step-up cancelled') return;
			totpError = errMsg(e, 'Could not disable the authenticator');
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
			<div class="row">
				<span class="value dim">
					Lost your authenticator? Disable it here to set up a new one — you'll confirm with your
					current code, or an emailed code if you've lost access.
				</span>
			</div>
			<div class="row">
				<button class="su-danger" onclick={disableTotp} disabled={busy}>
					{busy ? 'Working…' : 'Disable authenticator app'}
				</button>
			</div>
			{#if totpError}<p class="err">{totpError}</p>{/if}
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
		{/if}
	</section>

	{#if biometricSupported}
		<section class="card">
			<div class="section-label">{biometricName}</div>
			{#if platformKeyRegistered}
				<div class="row">
					<span class="label">{biometricName}</span>
					<!-- This is the ENROLLED state, so it must not read "Set up" — that looked
					     like an action, was a plain span, and did nothing when clicked.
					     Mirrors the Security key row below. -->
					<span class="value">Registered</span>
				</div>
				<!-- The key is bound to the biometrics enrolled at the time and dies for good
				     when those change, after which signing fails with no prompt at all. Without
				     this the factor would be stuck in that state permanently, since enrolment is
				     the only way back and the row above offers no action. -->
				<div class="row">
					<button class="su-primary" onclick={enrollPlatformKey} disabled={platformKeyBusy}>
						{platformKeyBusy
							? `Waiting for ${biometricName}…`
							: `Set up again on this ${isMacOS ? 'Mac' : 'device'}`}
					</button>
				</div>
				{#if platformKeyError}<p class="err">{platformKeyError}</p>{/if}
			{:else}
				<div class="row">
					<span class="value dim">
						Use {biometricName} to confirm sensitive actions instead of typing a code. A failed
						or cancelled {biometricName} never falls back to a password — you'll just be asked
						to try again or use another factor.
					</span>
				</div>
				<div class="row">
					<button class="su-primary" onclick={enrollPlatformKey} disabled={platformKeyBusy}>
						{platformKeyBusy ? `Waiting for ${biometricName}…` : `Set up ${biometricName}`}
					</button>
				</div>
				{#if platformKeyError}<p class="err">{platformKeyError}</p>{/if}
			{/if}
		</section>
	{/if}

	<!-- Rendered on every platform and regardless of what this device supports: the
	     keys most urgently needing removal are the ones whose hardware is gone. -->
	{#if factorsLoaded && factors.length > 0}
		<section class="card">
			<div class="section-label">Enrolled keys</div>
			{#each factors as f (f.id)}
				<div class="row factor">
					<div class="factor-id">
						<span class="label">{f.label || (f.kind === 'security' ? 'Security key' : 'Biometric key')}</span>
						<span class="value dim small">
							Added {shortDate(f.created_at)}{f.last_used_at
								? ` · last used ${shortDate(f.last_used_at)}`
								: ' · never used'}
						</span>
					</div>
					{#if confirmingId === f.id}
						<div class="confirm">
							<button
								class="su-danger"
								onclick={() => removeFactor(f)}
								disabled={removingId === f.id}
							>
								{removingId === f.id ? 'Removing…' : 'Confirm'}
							</button>
							<button class="su-plain" onclick={() => (confirmingId = '')}>Cancel</button>
						</div>
					{:else}
						<button class="su-plain" onclick={() => (confirmingId = f.id)} disabled={!!removingId}>
							Remove
						</button>
					{/if}
				</div>
			{/each}
			<!-- Said once, here, rather than per row: a key can only be removed by
			     proving a factor, and each removal needs its own proof. -->
			<div class="row">
				<span class="value dim small">
					Removing a key asks you to confirm with another factor, once per key. A key you
					remove here stops working immediately and cannot be restored — set it up again if
					you need it.
				</span>
			</div>
			{#if factorError}<p class="err">{factorError}</p>{/if}
		</section>
	{/if}

	{#if securityKeySupported}
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

	.factor {
		gap: 12px;
		align-items: flex-start;
	}

	.factor-id {
		display: flex;
		flex-direction: column;
		gap: 2px;
		min-width: 0;
		flex: 1;
	}

	/* The label carries the device name now, and a phone name can be long. Wrap it
	   instead of letting it push the Remove button off the row. */
	.factor-id .label {
		white-space: normal;
		overflow-wrap: anywhere;
	}

	.small {
		font-size: 11px;
	}

	.confirm {
		display: flex;
		gap: 8px;
		flex-shrink: 0;
	}

	.su-danger {
		background: var(--c-danger, #c0392b);
		color: #fff;
		border: none;
		border-radius: 8px;
		padding: 6px 12px;
		font-size: 13px;
		font-weight: 600;
		cursor: pointer;
	}

	.su-danger:disabled {
		opacity: 0.6;
		cursor: default;
	}

	.su-plain {
		background: transparent;
		color: var(--c-text-dim);
		border: 1px solid var(--c-border);
		border-radius: 8px;
		padding: 6px 12px;
		font-size: 13px;
		cursor: pointer;
		flex-shrink: 0;
	}

	.su-plain:disabled {
		opacity: 0.5;
		cursor: default;
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

	.su-danger {
		font-size: 14px;
		font-weight: 600;
		color: var(--c-danger);
		background: transparent;
		border: 1px solid var(--c-danger);
		padding: 10px 16px;
		border-radius: 8px;
	}
	.su-danger:disabled {
		opacity: 0.5;
	}
</style>
