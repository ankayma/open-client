<script lang="ts">
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { listSubdomains, createSubdomain, deleteSubdomain, openSubdomain, listNodes } from '$lib/tauri';
	import { runWithStepUp } from '$lib/stepup';
	import type { Subdomain, PeerBrief } from '$lib/types';

	// F-3 branded subdomain (Part C §H.3.6.1, milestone 1.4): a private name mapped
	// onto one of your mesh nodes. Private-default — resolves only on enrolled
	// devices; the data path is direct over the overlay (A.1.1). Real list/create/
	// delete go through the control-plane registry via agent-core.

	let entries = $state<Subdomain[]>([]);
	let nodes = $state<PeerBrief[]>([]);
	let loading = $state(true);
	let loadError = $state('');

	let showAddForm = $state(false);
	let newLabel = $state('');
	let newTarget = $state('');
	let newPort = $state('80');
	let adding = $state(false);
	let error = $state('');

	onMount(load);

	async function load() {
		loading = true;
		loadError = '';
		try {
			[entries, nodes] = await Promise.all([listSubdomains(), listNodes()]);
			if (!newTarget && nodes.length > 0) newTarget = nodes[0].node_id;
		} catch (e: unknown) {
			loadError = e instanceof Error ? e.message : 'Failed to load subdomains';
		} finally {
			loading = false;
		}
	}

	async function addSubdomain() {
		const port = Number(newPort);
		if (!isValidLabel(newLabel) || !newTarget || !isValidPort(port)) return;
		adding = true;
		error = '';
		try {
			await runWithStepUp('manage_subdomain', (proof) =>
				createSubdomain(newLabel.trim().toLowerCase(), newTarget, port, proof),
			);
			newLabel = '';
			showAddForm = false;
			await load();
		} catch (e: unknown) {
			// Surface the control plane's reason verbatim (invalid label / cap / dup).
			error = e instanceof Error ? e.message : 'Failed to create subdomain';
		} finally {
			adding = false;
		}
	}

	async function removeSubdomain(label: string) {
		try {
			await runWithStepUp('manage_subdomain', (proof) => deleteSubdomain(label, proof));
			await load();
		} catch (e: unknown) {
			loadError = e instanceof Error ? e.message : 'Failed to remove subdomain';
		}
	}

	function nodeName(id: string) {
		return nodes.find(n => n.node_id === id)?.hostname ?? id;
	}

	// RFC 1035 LDH label, lowercase, 1–63, no leading/trailing hyphen (mirrors the
	// control-plane `edge::validate_label`; the server is authoritative).
	function isValidLabel(s: string) {
		const l = s.trim();
		return /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/.test(l);
	}

	function isValidPort(p: number) {
		return Number.isInteger(p) && p > 0 && p <= 65535;
	}

	// Auto-TLS (Slice 3) issuance state — badge label + tone per cert_status.
	function certLabel(status?: string) {
		switch (status) {
			case 'issued': return 'TLS ready';
			case 'pending': return 'Issuing TLS…';
			case 'failed': return 'TLS failed';
			default: return 'No TLS yet';
		}
	}
</script>

<main>
	<header>
		<button class="back-btn" aria-label="Back to dashboard" onclick={() => goto('/services')}>
			<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
				<path d="M19 12H5M12 5l-7 7 7 7"/>
			</svg>
		</button>
		<h2>Subdomains</h2>
		<div style="width:36px"></div>
	</header>

		<div class="body">
			<p class="desc">
				Map a private name onto one of your mesh nodes. It resolves <strong>only on enrolled devices</strong> and the traffic goes direct over the overlay — no public port, no vendor on the path.
				<span class="note-inline">Auto-TLS issues a certificate for your node to terminate locally; not yet live-validated end-to-end.</span>
			</p>

			{#if loadError}
				<p class="form-error">{loadError}</p>
			{/if}

			<!-- Entry list -->
			{#if loading}
				<div class="empty"><p>Loading…</p></div>
			{:else if entries.length === 0}
				<div class="empty">
					<p>No subdomains yet. Add one to give a service a private name.</p>
				</div>
			{:else}
				<ul class="entry-list">
					{#each entries as entry (entry.fqdn)}
						<li class="entry">
							<div class="entry-info">
								<code class="entry-fqdn">{entry.fqdn}</code>
								<div class="entry-meta">
									<span class="badge">private</span>
									<span class="arrow">→</span>
									<span class="target">{nodeName(entry.target_node_id)}:{entry.target_port ?? 80}</span>
								</div>
								<div class="entry-meta">
									<span class="badge cert-{entry.cert_status ?? 'none'}">{certLabel(entry.cert_status)}</span>
								</div>
							</div>
							<div class="entry-actions">
								<button class="link-btn" onclick={() => openSubdomain(entry.fqdn)} aria-label="Open in browser">Open</button>
								<button class="remove-btn" onclick={() => removeSubdomain(entry.label)} aria-label="Remove subdomain">
									<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
										<path d="M18 6L6 18M6 6l12 12"/>
									</svg>
								</button>
							</div>
						</li>
					{/each}
				</ul>
			{/if}

			<!-- Add form -->
			{#if showAddForm}
				<div class="add-form">
					<h4>New subdomain</h4>

					<label class="field">
						<span>Name</span>
						<input
							type="text"
							bind:value={newLabel}
							placeholder="epos"
							maxlength="63"
							autocapitalize="none"
							autocorrect="off"
							spellcheck="false"
						/>
					</label>

					<label class="field">
						<span>Target node</span>
						{#if nodes.length === 0}
							<span class="form-error">Enroll a node first.</span>
						{:else}
							<select bind:value={newTarget}>
								{#each nodes as n (n.node_id)}
									<option value={n.node_id}>{n.hostname}</option>
								{/each}
							</select>
						{/if}
					</label>

					<label class="field">
						<span>Local port on that node</span>
						<input
							type="number"
							bind:value={newPort}
							placeholder="80"
							min="1"
							max="65535"
						/>
					</label>

					{#if error}
						<p class="form-error">{error}</p>
					{/if}

					<div class="form-actions">
						<button
							class="btn-primary"
							onclick={addSubdomain}
							disabled={adding || !isValidLabel(newLabel) || !newTarget || !isValidPort(Number(newPort))}
						>
							{#if adding}
								<span class="spinner"></span> Adding…
							{:else}
								Add subdomain
							{/if}
						</button>
						<button class="btn-ghost" onclick={() => { showAddForm = false; error = ''; }}>
							Cancel
						</button>
					</div>
				</div>
			{:else}
				<button class="add-btn" onclick={() => showAddForm = true}>
					<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
						<path d="M12 5v14M5 12h14"/>
					</svg>
					Add subdomain
				</button>
			{/if}
		</div>
</main>

<style>
	main {
		flex: 1;
		display: flex;
		flex-direction: column;
		padding: calc(var(--safe-top) + 16px) 16px calc(var(--safe-bottom) + 32px);
		max-width: 480px;
		margin: 0 auto;
		width: 100%;
	}

	header {
		display: flex;
		align-items: center;
		justify-content: space-between;
		padding: 8px 0;
		margin-bottom: 20px;
	}

	h2 { font-size: 18px; font-weight: 700; }

	.back-btn {
		display: flex;
		align-items: center;
		color: var(--c-text-dim);
		padding: 8px;
		border-radius: 8px;
	}

	/* Gate (F0 users) */
	/* Body */
	.body {
		display: flex;
		flex-direction: column;
		gap: 16px;
	}

	.desc {
		font-size: 13px;
		color: var(--c-text-dim);
		line-height: 1.6;
	}

	.note-inline {
		display: block;
		margin-top: 4px;
		font-size: 11px;
		opacity: 0.7;
	}

	/* Entry list */
	.empty {
		background: var(--c-surface);
		border: 1px dashed var(--c-border);
		border-radius: var(--radius);
		padding: 24px;
		text-align: center;
		font-size: 14px;
		color: var(--c-text-dim);
	}

	.entry-list {
		list-style: none;
		display: flex;
		flex-direction: column;
		gap: 0;
	}

	.entry {
		display: flex;
		align-items: center;
		gap: 12px;
		padding: 14px 0;
		border-bottom: 1px solid var(--c-border);
	}

	.entry:last-child { border-bottom: none; }

	.entry-info { flex: 1; display: flex; flex-direction: column; gap: 5px; }

	.entry-fqdn {
		font-family: 'SF Mono', 'Fira Code', monospace;
		font-size: 13px;
		color: var(--c-accent);
		word-break: break-all;
	}

	.entry-meta {
		display: flex;
		align-items: center;
		gap: 6px;
		font-size: 12px;
		color: var(--c-text-dim);
	}

	.badge {
		background: color-mix(in srgb, var(--c-accent) 15%, transparent);
		color: var(--c-accent);
		font-size: 10px;
		font-weight: 700;
		padding: 1px 5px;
		border-radius: 4px;
	}

	.arrow { opacity: 0.5; }

	.target { font-family: 'SF Mono', 'Fira Code', monospace; }

	/* Auto-TLS (Slice 3) issuance-state badge */
	.badge.cert-issued { background: color-mix(in srgb, #22c55e 15%, transparent); color: #22c55e; }
	.badge.cert-pending { background: color-mix(in srgb, #eab308 15%, transparent); color: #eab308; }
	.badge.cert-failed { background: color-mix(in srgb, var(--c-danger) 15%, transparent); color: var(--c-danger); }
	.badge.cert-none { background: color-mix(in srgb, var(--c-text-dim) 15%, transparent); color: var(--c-text-dim); }

	.entry-actions { display: flex; align-items: center; gap: 4px; flex-shrink: 0; }

	.link-btn {
		font-size: 13px;
		font-weight: 600;
		color: var(--c-accent);
		padding: 6px 10px;
		border-radius: 6px;
	}

	.link-btn:hover { background: color-mix(in srgb, var(--c-accent) 12%, transparent); }

	.remove-btn {
		width: 32px;
		height: 32px;
		display: flex;
		align-items: center;
		justify-content: center;
		color: var(--c-text-dim);
		border-radius: 6px;
		flex-shrink: 0;
	}

	.remove-btn:hover { background: color-mix(in srgb, var(--c-danger) 15%, transparent); color: var(--c-danger); }

	/* Add button */
	.add-btn {
		display: flex;
		align-items: center;
		gap: 8px;
		padding: 12px 16px;
		background: var(--c-surface);
		border: 1px dashed var(--c-border);
		border-radius: var(--radius);
		font-size: 14px;
		color: var(--c-text-dim);
		width: 100%;
		justify-content: center;
		transition: border-color 0.15s;
	}

	.add-btn:hover { border-color: var(--c-accent); color: var(--c-accent); }

	/* Add form */
	.add-form {
		background: var(--c-surface);
		border: 1px solid var(--c-border);
		border-radius: var(--radius);
		padding: 20px;
		display: flex;
		flex-direction: column;
		gap: 14px;
	}

	.add-form h4 { font-size: 15px; font-weight: 600; }

	.field {
		display: flex;
		flex-direction: column;
		gap: 6px;
		font-size: 13px;
		color: var(--c-text-dim);
	}

	.field input {
		padding: 10px 12px;
		background: var(--c-bg);
		border: 1px solid var(--c-border);
		border-radius: 8px;
		font-size: 14px;
		color: var(--c-text);
		width: 100%;
	}

	.field input:focus {
		outline: none;
		border-color: var(--c-accent);
	}

	.field select {
		padding: 10px 12px;
		border: 1px solid var(--c-border);
		border-radius: 8px;
		background: var(--c-bg);
		color: var(--c-text);
		font-size: 14px;
	}

	.form-error {
		font-size: 13px;
		color: var(--c-danger);
	}

	.form-actions {
		display: flex;
		flex-direction: column;
		gap: 8px;
	}

	.btn-primary {
		width: 100%;
		display: flex;
		align-items: center;
		justify-content: center;
		gap: 8px;
		padding: 12px;
		background: var(--c-accent);
		color: #fff;
		border-radius: var(--radius);
		font-size: 14px;
		font-weight: 600;
	}

	.btn-primary:hover:not(:disabled) { background: var(--c-accent-dim); }
	.btn-primary:disabled { opacity: 0.5; cursor: not-allowed; }

	.btn-ghost {
		width: 100%;
		padding: 12px;
		background: transparent;
		border: 1px solid var(--c-border);
		border-radius: var(--radius);
		font-size: 14px;
		color: var(--c-text-dim);
	}

	.btn-ghost:hover { border-color: var(--c-accent); }

	.spinner {
		width: 14px;
		height: 14px;
		border: 2px solid rgba(255,255,255,0.3);
		border-top-color: #fff;
		border-radius: 50%;
		animation: spin 0.7s linear infinite;
	}

	@keyframes spin { to { transform: rotate(360deg); } }
</style>
