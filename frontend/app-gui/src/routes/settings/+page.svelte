<script lang="ts">
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';

	// Bare /settings has no content of its own — My Devices is the default tab.
	onMount(() => goto('/settings/devices', { replaceState: true }));
</script>

<div class="loading">
	<div class="spinner"></div>
</div>

<style>
	.loading {
		flex: 1;
		display: flex;
		align-items: center;
		justify-content: center;
		min-height: 40vh;
	}

	.spinner {
		width: 32px;
		height: 32px;
		border: 3px solid var(--c-border);
		border-top-color: var(--c-accent);
		border-radius: 50%;
		animation: spin 0.8s linear infinite;
	}

	@keyframes spin {
		to { transform: rotate(360deg); }
	}
</style>
