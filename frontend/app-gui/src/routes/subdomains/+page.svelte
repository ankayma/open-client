<script lang="ts">
	import { goto } from '$app/navigation';
	import { auth } from '$lib/stores';

	// [A] stub — real subdomain list comes from control-plane (POST /api/subdomains → list)
	// Subdomain = a named reverse-proxy entry pointing to a node:port in the mesh
	// F0-Plus only; F0 sees upgrade prompt

	interface SubdomainEntry {
		id: string;
		subdomain: string;          // e.g. "api" → api.<tenant>.ankayma.net
		target_node_id: string;
		target_port: number;
		protocol: 'https' | 'tcp';
		active: boolean;
	}

	let isF0Plus = $derived(
		$auth.status === 'authenticated' && $auth.user.tier === 'F0Plus'
	);

	// Real list comes from invoke('list_subdomains') once the control plane is
	// wired (milestone 1.3). Until then start empty — never seed fake entries.
	let entries = $state<SubdomainEntry[]>([]);

	let showAddForm = $state(false);
	let newSub = $state('');
	let newPort = $state(443);
	let newProto = $state<'https' | 'tcp'>('https');
	let adding = $state(false);
	let error = $state('');

	async function addSubdomain() {
		if (!newSub.trim()) return;
		adding = true;
		error = '';
		try {
			// [A] stub — real: invoke('create_subdomain', { subdomain: newSub, port: newPort, protocol: newProto })
			await new Promise(r => setTimeout(r, 600)); // fake latency
			entries = [...entries, {
				id: `sub_${Date.now()}`,
				subdomain: newSub.trim().toLowerCase(),
				target_node_id: 'node_placeholder',
				target_port: newPort,
				protocol: newProto,
				active: true,
			}];
			newSub = '';
			newPort = 443;
			showAddForm = false;
		} catch (e: unknown) {
			error = e instanceof Error ? e.message : 'Failed to create subdomain';
		} finally {
			adding = false;
		}
	}

	async function removeSubdomain(id: string) {
		// [A] stub — real: invoke('delete_subdomain', { id })
		entries = entries.filter(e => e.id !== id);
	}

	function fqdn(sub: string) {
		const tenantId = $auth.status === 'authenticated' ? $auth.user.tenant_id : 'tenant';
		// [A] domain pattern pending control-plane DNS delegation spec
		return `${sub}.${tenantId}.ankayma.net`;
	}

	// Subdomain validation: lowercase alphanumeric + hyphen, 3-32 chars
	function isValidSub(s: string) {
		return /^[a-z0-9][a-z0-9-]{1,30}[a-z0-9]$/.test(s) || /^[a-z0-9]{3,32}$/.test(s);
	}
</script>

<main>
	<header>
		<button class="back-btn" aria-label="Back to dashboard" onclick={() => goto('/dashboard')}>
			<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
				<path d="M19 12H5M12 5l-7 7 7 7"/>
			</svg>
		</button>
		<h2>Subdomains</h2>
		<div style="width:36px"></div>
	</header>

	{#if !isF0Plus}
		<!-- Gate: F0 users see upgrade prompt -->
		<div class="gate">
			<div class="gate-icon" aria-hidden="true">
				<svg width="40" height="40" viewBox="0 0 24 24" fill="none">
					<rect x="3" y="11" width="18" height="11" rx="2" stroke="var(--c-accent)" stroke-width="1.5"/>
					<path d="M7 11V7a5 5 0 0110 0v4" stroke="var(--c-accent)" stroke-width="1.5" stroke-linecap="round"/>
					<circle cx="12" cy="16" r="1.5" fill="var(--c-accent)"/>
				</svg>
			</div>
			<h3>F0-Plus feature</h3>
			<p>Custom subdomains let you expose mesh services at a stable URL — no port forwarding, no IP changes.</p>
			<button class="btn-primary" onclick={() => goto('/upgrade')}>Upgrade to F0-Plus — $9/mo</button>
		</div>
	{:else}
		<div class="body">
			<p class="desc">
				Each subdomain routes HTTPS or TCP traffic from the public internet to a node in your mesh, at a stable <code>*.ankayma.net</code> URL.
				<span class="note-inline">Subdomain provisioning is being finalized and lands in an upcoming release.</span>
			</p>

			<!-- Entry list -->
			{#if entries.length === 0}
				<div class="empty">
					<p>No subdomains yet. Add one to expose a service.</p>
				</div>
			{:else}
				<ul class="entry-list">
					{#each entries as entry (entry.id)}
						<li class="entry">
							<div class="entry-info">
								<code class="entry-fqdn">{fqdn(entry.subdomain)}</code>
								<div class="entry-meta">
									<span class="badge" class:tcp={entry.protocol === 'tcp'}>{entry.protocol.toUpperCase()}</span>
									<span class="arrow">→</span>
									<span class="target">:{entry.target_port}</span>
									{#if entry.active}
										<span class="active-dot" title="Active"></span>
									{/if}
								</div>
							</div>
							<button class="remove-btn" onclick={() => removeSubdomain(entry.id)} aria-label="Remove subdomain">
								<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
									<path d="M18 6L6 18M6 6l12 12"/>
								</svg>
							</button>
						</li>
					{/each}
				</ul>
			{/if}

			<!-- Add form -->
			{#if showAddForm}
				<div class="add-form">
					<h4>New subdomain</h4>

					<label class="field">
						<span>Subdomain prefix</span>
						<div class="input-suffix-wrap">
							<input
								type="text"
								bind:value={newSub}
								placeholder="api"
								maxlength="32"
								autocapitalize="none"
								autocorrect="off"
								spellcheck="false"
							/>
							<span class="suffix">.…ankayma.net</span>
						</div>
					</label>

					<label class="field">
						<span>Target port</span>
						<input type="number" bind:value={newPort} min="1" max="65535" placeholder="443"/>
					</label>

					<div class="field">
						<span>Protocol</span>
						<div class="proto-toggle">
							<button class:active={newProto === 'https'} onclick={() => newProto = 'https'}>HTTPS</button>
							<button class:active={newProto === 'tcp'} onclick={() => newProto = 'tcp'}>TCP</button>
						</div>
					</div>

					{#if error}
						<p class="form-error">{error}</p>
					{/if}

					<div class="form-actions">
						<button
							class="btn-primary"
							onclick={addSubdomain}
							disabled={adding || !isValidSub(newSub)}
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
	{/if}
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
	.gate {
		flex: 1;
		display: flex;
		flex-direction: column;
		align-items: center;
		justify-content: center;
		gap: 16px;
		text-align: center;
		padding: 32px 0;
	}

	.gate-icon {
		width: 72px;
		height: 72px;
		background: color-mix(in srgb, var(--c-accent) 10%, transparent);
		border-radius: 50%;
		display: flex;
		align-items: center;
		justify-content: center;
	}

	.gate h3 { font-size: 20px; font-weight: 700; }

	.gate p {
		font-size: 14px;
		color: var(--c-text-dim);
		line-height: 1.6;
		max-width: 300px;
	}

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

	.badge.tcp {
		background: color-mix(in srgb, var(--c-success) 15%, transparent);
		color: var(--c-success);
	}

	.arrow { opacity: 0.5; }

	.target { font-family: 'SF Mono', 'Fira Code', monospace; }

	.active-dot {
		width: 6px;
		height: 6px;
		border-radius: 50%;
		background: var(--c-success);
	}

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

	.input-suffix-wrap {
		display: flex;
		align-items: center;
		gap: 0;
	}

	.input-suffix-wrap input {
		border-radius: 8px 0 0 8px;
		border-right: none;
		flex: 1;
	}

	.suffix {
		padding: 10px 12px;
		background: var(--c-border);
		border: 1px solid var(--c-border);
		border-radius: 0 8px 8px 0;
		font-family: 'SF Mono', 'Fira Code', monospace;
		font-size: 12px;
		color: var(--c-text-dim);
		white-space: nowrap;
	}

	.proto-toggle {
		display: flex;
		gap: 0;
		border: 1px solid var(--c-border);
		border-radius: 8px;
		overflow: hidden;
	}

	.proto-toggle button {
		flex: 1;
		padding: 9px;
		font-size: 13px;
		font-weight: 600;
		color: var(--c-text-dim);
		transition: background 0.1s;
	}

	.proto-toggle button.active {
		background: var(--c-accent);
		color: #fff;
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
