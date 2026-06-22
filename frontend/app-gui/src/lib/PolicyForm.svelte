<script lang="ts">
	// [03b §1.2/§1.3] Shared create/edit form for a CI/CD deploy rule.
	// Exactly one scope (ref XOR environment) via a radio + single input.
	import { goto } from '$app/navigation';
	import { onMount } from 'svelte';
	import { addCiPolicy, listNodes } from '$lib/tauri';
	import type { CiPolicy, PeerBrief } from '$lib/types';

	let { initial = null }: { initial?: CiPolicy | null } = $props();

	const editing = !!initial;
	let issuer = $state<'github' | 'gitlab'>((initial?.issuer as 'github' | 'gitlab') ?? 'github');
	let repo = $state(initial?.repo ?? '');
	let scopeType = $state<'ref' | 'environment'>(initial?.environment ? 'environment' : 'ref');
	let scopeValue = $state(initial?.environment ?? initial?.ref ?? '');
	let targetHostname = $state(initial?.target_hostname ?? '');

	let nodes = $state<PeerBrief[]>([]);
	let errors = $state<string[]>([]);
	let serverError = $state('');
	let saving = $state(false);

	onMount(async () => {
		try {
			nodes = await listNodes();
		} catch {
			// Offline / browser dev — picker just stays empty (target is optional).
		}
	});

	// Mirror server safe-by-default (UX only; server is the real gate). [03b §1.3]
	function validate(): string[] {
		const e: string[] = [];
		const r = repo.trim();
		if (!r || r.includes('*')) e.push('repo: pin exact owner/name, no wildcard');
		else if (!r.includes('/')) e.push('repo: must be owner/name');
		const v = scopeValue.trim();
		if (!v || v.includes('*'))
			e.push(`${scopeType}: required, exactly one of ref/environment, no wildcard`);
		if (issuer !== 'github' && issuer !== 'gitlab') e.push('issuer: github | gitlab');
		return e;
	}

	async function submit(ev: Event) {
		ev.preventDefault();
		serverError = '';
		errors = validate();
		if (errors.length) return; // do NOT call API on client-validation failure
		saving = true;
		try {
			await addCiPolicy({
				issuer,
				repo: repo.trim(),
				ref: scopeType === 'ref' ? scopeValue.trim() : undefined,
				environment: scopeType === 'environment' ? scopeValue.trim() : undefined,
				target_hostname: targetHostname || undefined
			});
			goto('/policies');
		} catch (err) {
			// Surface the control plane's reason verbatim (400/409 safe-by-default).
			serverError = String(err);
		} finally {
			saving = false;
		}
	}
</script>

<main>
	<header>
		<button class="back-btn" aria-label="Back" onclick={() => goto('/policies')}>
			<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M19 12H5M12 5l-7 7 7 7" /></svg>
		</button>
		<h2>{editing ? 'Edit deploy rule' : 'New deploy rule'}</h2>
		<div style="width: 36px"></div>
	</header>

	<form onsubmit={submit}>
		<label class="field">
			<span>Issuer</span>
			<select bind:value={issuer}>
				<option value="github">GitHub</option>
				<option value="gitlab">GitLab</option>
			</select>
		</label>

		<label class="field">
			<span>Repository</span>
			<input
				type="text"
				placeholder="owner/name"
				bind:value={repo}
				readonly={editing}
				autocapitalize="off"
				autocomplete="off"
				spellcheck="false"
			/>
			{#if editing}
				<small>Repo is the rule key — create a new rule to target a different repo.</small>
			{/if}
		</label>

		<fieldset class="field scope">
			<span>Scope</span>
			<div class="radios">
				<label><input type="radio" value="ref" bind:group={scopeType} /> Ref</label>
				<label><input type="radio" value="environment" bind:group={scopeType} /> Environment</label>
			</div>
			<input
				type="text"
				placeholder={scopeType === 'ref' ? 'refs/heads/main' : 'prod'}
				bind:value={scopeValue}
				autocapitalize="off"
				autocomplete="off"
				spellcheck="false"
			/>
			<small>Exactly one branch/ref or environment — no wildcards (safe-by-default).</small>
		</fieldset>

		<label class="field">
			<span>Target node <em>(optional)</em></span>
			<select bind:value={targetHostname}>
				<option value="">— any of my nodes —</option>
				{#each nodes as n (n.node_id)}
					<option value={n.hostname}>{n.hostname} ({n.overlay_ip})</option>
				{/each}
			</select>
		</label>

		{#if errors.length}
			<div class="errors">
				{#each errors as e (e)}<div>• {e}</div>{/each}
			</div>
		{/if}
		{#if serverError}
			<div class="errors server">{serverError}</div>
		{/if}

		<button class="submit" type="submit" disabled={saving}>
			{saving ? 'Saving…' : editing ? 'Save changes' : 'Create rule'}
		</button>
	</form>
</main>

<style>
	main {
		flex: 1;
		display: flex;
		flex-direction: column;
		padding: calc(var(--safe-top) + 16px) 16px calc(var(--safe-bottom) + 24px);
		gap: 16px;
		max-width: 520px;
		margin: 0 auto;
		width: 100%;
	}
	header {
		display: flex;
		align-items: center;
		justify-content: space-between;
		padding: 8px 0;
	}
	h2 {
		font-size: 20px;
		font-weight: 700;
	}
	.back-btn {
		width: 36px;
		height: 36px;
		display: flex;
		align-items: center;
		justify-content: center;
		border-radius: 10px;
		color: var(--c-text-dim);
	}
	.back-btn:hover {
		color: var(--c-text);
	}
	form {
		display: flex;
		flex-direction: column;
		gap: 16px;
	}
	.field {
		display: flex;
		flex-direction: column;
		gap: 6px;
		border: none;
	}
	.field > span {
		font-size: 13px;
		color: var(--c-text-dim);
	}
	.field em {
		font-style: normal;
		opacity: 0.7;
	}
	input[type='text'],
	select {
		background: var(--c-surface);
		border: 1px solid var(--c-border);
		border-radius: 8px;
		padding: 11px 12px;
		color: var(--c-text);
		font: inherit;
		font-size: 15px;
		width: 100%;
	}
	input[readonly] {
		opacity: 0.6;
	}
	input:focus,
	select:focus {
		outline: none;
		border-color: var(--c-accent);
	}
	small {
		font-size: 12px;
		color: var(--c-text-dim);
	}
	.scope .radios {
		display: flex;
		gap: 16px;
		font-size: 14px;
	}
	.scope .radios label {
		display: flex;
		align-items: center;
		gap: 6px;
		cursor: pointer;
	}
	.errors {
		background: color-mix(in srgb, var(--c-danger) 10%, transparent);
		border: 1px solid color-mix(in srgb, var(--c-danger) 30%, transparent);
		border-radius: 8px;
		padding: 10px 12px;
		font-size: 13px;
		color: var(--c-danger);
		display: flex;
		flex-direction: column;
		gap: 4px;
		white-space: pre-wrap;
	}
	.submit {
		background: var(--c-accent);
		color: #fff;
		padding: 13px;
		border-radius: 8px;
		font-size: 15px;
		font-weight: 600;
	}
	.submit:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}
</style>
