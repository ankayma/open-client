<script lang="ts">
	// [03b §1.2] Edit a CI/CD deploy rule. `repo` is the rest param (owner/name).
	// No GET-by-repo endpoint exists; pre-fill by finding the rule in the list.
	import { page } from '$app/state';
	import { goto } from '$app/navigation';
	import { onMount } from 'svelte';
	import { listCiPolicies } from '$lib/tauri';
	import type { CiPolicy } from '$lib/types';
	import PolicyForm from '$lib/PolicyForm.svelte';

	let policy = $state<CiPolicy | null>(null);
	let loading = $state(true);

	onMount(async () => {
		const repo = page.params.repo;
		try {
			const all = await listCiPolicies();
			policy = all.find((p) => p.repo === repo) ?? null;
		} catch {
			policy = null;
		} finally {
			loading = false;
		}
	});
</script>

{#if loading}
	<main class="state">Loading…</main>
{:else if policy}
	<PolicyForm initial={policy} />
{:else}
	<main class="state">
		<p>Rule not found.</p>
		<button onclick={() => goto('/policies')}>Back to rules</button>
	</main>
{/if}

<style>
	.state {
		flex: 1;
		display: flex;
		flex-direction: column;
		align-items: center;
		justify-content: center;
		gap: 12px;
		color: var(--c-text-dim);
		padding: 40px;
	}
	.state button {
		color: var(--c-accent);
	}
</style>
