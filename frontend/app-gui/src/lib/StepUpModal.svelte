<script lang="ts">
	// Global step-up OTP modal — driven by the `stepUp` store (lib/stepup.ts). Mounted
	// once in the root layout; appears whenever a gated action needs an OTP.
	import { stepUp, purposeLabel } from '$lib/stepup';

	let code = $state('');

	// Reset the field each time a fresh prompt opens.
	$effect(() => {
		if ($stepUp) code = '';
	});
</script>

{#if $stepUp}
	<div
		role="presentation"
		onclick={() => $stepUp?.cancel()}
		style="position:fixed;inset:0;background:rgba(0,0,0,0.55);display:flex;align-items:center;justify-content:center;padding:24px;z-index:60;"
	>
		<div
			role="dialog"
			aria-modal="true"
			aria-label="Verify it's you"
			tabindex="-1"
			onclick={(e) => e.stopPropagation()}
			style="background:var(--c-surface);border:1px solid var(--c-border);border-radius:var(--radius);padding:20px;max-width:340px;width:100%;display:flex;flex-direction:column;gap:14px;"
		>
			<h3 style="font-size:16px;font-weight:700;">Verify it's you</h3>
			<p style="font-size:14px;line-height:1.5;color:var(--c-text-dim);">
				For security, enter the code we emailed you to {purposeLabel($stepUp.purpose)}.
			</p>
			<input
				bind:value={code}
				inputmode="numeric"
				autocomplete="one-time-code"
				maxlength="6"
				placeholder="6-digit code"
				autocapitalize="none"
				autocorrect="off"
				spellcheck="false"
				style="background:var(--c-bg);border:1px solid var(--c-border);border-radius:8px;padding:10px 12px;color:var(--c-text);font-size:16px;letter-spacing:3px;text-align:center;"
			/>
			{#if $stepUp.error}
				<p style="color:var(--c-danger);font-size:13px;">{$stepUp.error}</p>
			{/if}
			<div style="display:flex;justify-content:flex-end;gap:8px;align-items:center;">
				<button class="su-ghost" onclick={() => $stepUp?.cancel()}>Cancel</button>
				<button class="su-ghost" onclick={() => $stepUp?.resend()} disabled={$stepUp.sending}>
					Resend
				</button>
				<button
					class="su-primary"
					onclick={() => $stepUp?.submit(code)}
					disabled={$stepUp.sending || !code.trim()}
				>
					{$stepUp.sending ? 'Verifying…' : 'Verify'}
				</button>
			</div>
		</div>
	</div>
{/if}

<style>
	.su-ghost {
		font-size: 13px;
		color: var(--c-text-dim);
		padding: 8px 12px;
		border-radius: 8px;
	}
	.su-ghost:hover { color: var(--c-text); }
	.su-primary {
		font-size: 14px;
		font-weight: 600;
		color: #fff;
		background: var(--c-accent);
		padding: 8px 16px;
		border-radius: 8px;
	}
	.su-primary:disabled { opacity: 0.5; }
</style>
