<script lang="ts">
	// Governance — the three surfaces that turn recorded evidence into something a person
	// can act on: the register, the approval queue, and one task's dossier.
	//
	// Nothing here decides anything. The client shows what the control plane recorded and
	// carries a human's answer back; every rule lives on the other side. [T:A.1.4]
	import { onMount } from 'svelte';
	import {
		listPrincipals,
		amendPrincipal,
		listPendingApprovals,
		decideApproval,
		taskRecord
	} from '$lib/tauri';
	import type { RegisteredPrincipal, PendingApproval } from '$lib/types';

	let principals = $state<RegisteredPrincipal[]>([]);
	let approvals = $state<PendingApproval[]>([]);
	let loading = $state(true);
	let error = $state('');

	// Which entity is being amended, and the draft. Empty inputs are sent as undefined so
	// a blank box means "not stating this", never "set it to empty" — a stated-and-empty
	// legal name reads as a fact.
	let editing = $state<string | null>(null);
	let draft = $state({ legal_name: '', lei: '', jurisdiction: '', criticality: '' });
	let saving = $state(false);

	let deciding = $state<string | null>(null);
	let taskId = $state('');
	let dossier = $state<unknown>(null);

	async function load() {
		loading = true;
		error = '';
		try {
			[principals, approvals] = await Promise.all([listPrincipals(), listPendingApprovals()]);
		} catch (e) {
			error = String(e);
		} finally {
			loading = false;
		}
	}
	onMount(load);

	function startEdit(p: RegisteredPrincipal) {
		editing = p.principal_id;
		draft = {
			legal_name: p.legal_name ?? '',
			lei: p.lei ?? '',
			jurisdiction: p.jurisdiction ?? '',
			criticality: p.criticality ?? ''
		};
	}

	const blankToUndefined = (v: string) => (v.trim() === '' ? undefined : v.trim());

	async function save(principalId: string) {
		saving = true;
		error = '';
		try {
			await amendPrincipal(principalId, {
				legalName: blankToUndefined(draft.legal_name),
				lei: blankToUndefined(draft.lei),
				jurisdiction: blankToUndefined(draft.jurisdiction),
				criticality: blankToUndefined(draft.criticality)
			});
			editing = null;
			await load();
		} catch (e) {
			error = String(e);
		} finally {
			saving = false;
		}
	}

	async function decide(id: string, approve: boolean) {
		deciding = id;
		error = '';
		try {
			await decideApproval(id, approve);
			await load();
		} catch (e) {
			error = String(e);
		} finally {
			deciding = null;
		}
	}

	async function openDossier() {
		error = '';
		dossier = null;
		try {
			dossier = await taskRecord(taskId.trim());
		} catch (e) {
			error = String(e);
		}
	}

	/** What the person is actually being asked, in their words rather than an enum. */
	function gateQuestion(a: PendingApproval): string {
		switch (a.gate_reason) {
			case 'irreversible':
				return 'This cannot be undone by running something else.';
			case 'freeform':
				return 'This command is NOT in the catalog. Break-glass.';
			default:
				return 'This template asks for a person before it runs.';
		}
	}
</script>

<section class="page">
	<h1>Governance</h1>

	{#if error}<p class="error" role="alert">{error}</p>{/if}
	{#if loading}<p>Loading…</p>{/if}

	<h2>Waiting for you</h2>
	{#if approvals.length === 0}
		<p class="muted">Nothing is waiting for a decision.</p>
	{:else}
		<ul class="approvals">
			{#each approvals as a (a.approval_id)}
				<li class="approval" class:danger={a.gate_reason !== 'gate'}>
					<p class="why">{gateQuestion(a)}</p>
					<!-- The exact argv, not a description of it. A gate on a summary is a gate
					     on the summary. -->
					<pre class="argv">{a.argv.join(' ')}</pre>
					<dl>
						<dt>Template</dt><dd>{a.template_id}</dd>
						<dt>Risk</dt><dd>{a.risk_class}</dd>
						<dt>On node</dt><dd>{a.node_id}</dd>
						<dt>For agent</dt><dd>{a.actor_id}</dd>
						<dt>Asked by</dt><dd>{a.requested_by}</dd>
						<dt>Expires</dt><dd>{a.expires_at}</dd>
					</dl>
					{#if a.justification}
						<p class="justification">“{a.justification}”</p>
					{/if}
					<div class="actions">
						<button disabled={deciding === a.approval_id} onclick={() => decide(a.approval_id, true)}>
							Approve
						</button>
						<button
							class="secondary"
							disabled={deciding === a.approval_id}
							onclick={() => decide(a.approval_id, false)}
						>
							Deny
						</button>
					</div>
					<p class="note">
						No credential exists until you approve. Denying is final — it cannot be
						re-decided.
					</p>
				</li>
			{/each}
		</ul>
	{/if}

	<h2>Register of legal entities</h2>
	<p class="muted">
		Who answers for access in this tenant. Blank fields are blank because nobody has
		stated them — they are never guessed.
	</p>
	<ul class="register">
		{#each principals as p (p.principal_id)}
			<li>
				<div class="entity">
					<strong>{p.legal_name ?? 'Unnamed entity'}</strong>
					<span class="tag">{p.relationship}</span>
					{#if p.missing_fields.length > 0}
						<span class="tag warn">missing: {p.missing_fields.join(', ')}</span>
					{/if}
				</div>
				{#if editing === p.principal_id}
					<div class="form">
						<label>Legal name<input bind:value={draft.legal_name} /></label>
						<label>LEI<input bind:value={draft.lei} placeholder="20 characters, ISO 17442" /></label>
						<label>Jurisdiction<input bind:value={draft.jurisdiction} /></label>
						<label>
							Criticality
							<select bind:value={draft.criticality}>
								<option value="">not stated</option>
								<option value="cif">cif</option>
								<option value="important">important</option>
								<option value="standard">standard</option>
							</select>
						</label>
						<div class="actions">
							<button disabled={saving} onclick={() => save(p.principal_id)}>Save</button>
							<button class="secondary" onclick={() => (editing = null)}>Cancel</button>
						</div>
					</div>
				{:else}
					<button class="secondary" onclick={() => startEdit(p)}>State details</button>
				{/if}
			</li>
		{/each}
	</ul>

	<h2>Task record</h2>
	<p class="muted">
		One page per task, whatever its size. Nine commands and two hundred thousand produce
		the same summary; only what carries weight is named individually.
	</p>
	<div class="actions">
		<input bind:value={taskId} placeholder="task_…" />
		<button disabled={taskId.trim() === ''} onclick={openDossier}>Open</button>
	</div>
	{#if dossier}
		<pre class="dossier">{JSON.stringify(dossier, null, 2)}</pre>
	{/if}
</section>

<style>
	.page {
		padding: 1rem;
		max-width: 46rem;
	}
	h2 {
		margin-top: 2rem;
	}
	.muted {
		opacity: 0.75;
	}
	.error {
		color: var(--error, #b00020);
	}
	.approvals,
	.register {
		list-style: none;
		padding: 0;
		display: grid;
		gap: 0.75rem;
	}
	.approval {
		border: 1px solid var(--border, #ddd);
		border-radius: 0.5rem;
		padding: 0.75rem;
	}
	/* Irreversible and break-glass are not the same question as a routine gate, and the
	   card says so before the reader gets to the buttons. */
	.approval.danger {
		border-color: var(--error, #b00020);
	}
	.why {
		font-weight: 600;
		margin: 0 0 0.5rem;
	}
	.argv,
	.dossier {
		background: var(--surface-2, #f5f5f5);
		padding: 0.5rem;
		border-radius: 0.25rem;
		overflow-x: auto;
		white-space: pre-wrap;
		word-break: break-all;
	}
	dl {
		display: grid;
		grid-template-columns: max-content 1fr;
		gap: 0.15rem 0.75rem;
		margin: 0.5rem 0;
		font-size: 0.9em;
	}
	dt {
		opacity: 0.7;
	}
	dd {
		margin: 0;
	}
	.justification {
		font-style: italic;
	}
	.note {
		font-size: 0.85em;
		opacity: 0.75;
	}
	.actions {
		display: flex;
		gap: 0.5rem;
		align-items: center;
		flex-wrap: wrap;
	}
	.form {
		display: grid;
		gap: 0.5rem;
		margin-top: 0.5rem;
	}
	.form label {
		display: grid;
		gap: 0.2rem;
		font-size: 0.9em;
	}
	.entity {
		display: flex;
		gap: 0.5rem;
		align-items: center;
		flex-wrap: wrap;
	}
	.tag {
		font-size: 0.8em;
		padding: 0.1rem 0.4rem;
		border-radius: 0.25rem;
		background: var(--surface-2, #eee);
	}
	.tag.warn {
		background: var(--warn-bg, #fff3cd);
	}
</style>
