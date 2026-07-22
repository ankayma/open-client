<script lang="ts">
	// Pre-flight permission gate — a friendly onboarding card shown in place of the
	// Connect button when the platform's tunnel permission isn't granted yet (macOS
	// helper daemon, iOS/Android VPN consent). One component, all platforms; the copy
	// is driven by i18n keys (pf_*) so it's edited in one place and stays bilingual.
	//
	// It requests the permission, deep-links to the OS prompt, then polls until the
	// user grants it and calls `onready` — so the permission is handled at setup time
	// instead of surfacing as a Connect-time error. [T:A.1.7 helper, A.1.9 vpn]
	import { onMount, onDestroy } from 'svelte';
	import { activeLang } from '$lib/stores';
	import { STRINGS, type Lang } from '$lib/i18n';
	import { preflightStatus, preflightRequest } from '$lib/tauri';

	interface Props {
		// Which permission this platform needs — picks the copy + action label.
		kind: 'helper' | 'vpn';
		// Called once the permission is granted (parent swaps back to the Connect button).
		onready: () => void;
	}
	let { kind, onready }: Props = $props();

	let lang = $state<Lang>('vn');
	activeLang.subscribe((l) => (lang = l));

	let requesting = $state(false);
	let waiting = $state(false);
	let error = $state<string | null>(null);
	let pollTimer: ReturnType<typeof setInterval> | undefined;

	let t = $derived(STRINGS[lang]);
	let title = $derived(kind === 'vpn' ? t.pf_vpn_title : t.pf_helper_title);
	let body = $derived(kind === 'vpn' ? t.pf_vpn_body : t.pf_helper_body);
	let action = $derived(kind === 'vpn' ? t.pf_action_vpn : t.pf_action_helper);

	async function check() {
		try {
			const s = await preflightStatus();
			if (s.ready) {
				stopPolling();
				onready();
			}
		} catch {
			/* browser/dev or transient — keep showing the gate */
		}
	}

	function startPolling() {
		waiting = true;
		if (!pollTimer) pollTimer = setInterval(check, 1000);
	}

	function stopPolling() {
		waiting = false;
		if (pollTimer) {
			clearInterval(pollTimer);
			pollTimer = undefined;
		}
	}

	async function request() {
		error = null;
		requesting = true;
		try {
			await preflightRequest();
			// The user now acts in the OS prompt / Settings; poll until it takes.
			startPolling();
		} catch (e) {
			error = e instanceof Error ? e.message : String(e);
		} finally {
			requesting = false;
		}
	}

	// Coming back to the app (after flipping the Settings toggle) is the moment the
	// permission most often just became ready — re-check on focus, not only on the timer.
	function onFocus() {
		check();
	}

	onMount(() => {
		window.addEventListener('focus', onFocus);
		check();
	});
	onDestroy(() => {
		window.removeEventListener('focus', onFocus);
		stopPolling();
	});
</script>

<div class="gate">
	<div class="badge" aria-hidden="true">
		<svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8">
			<rect x="3" y="11" width="18" height="11" rx="2" />
			<path d="M7 11V7a5 5 0 0110 0v4" />
		</svg>
	</div>
	<span class="intro">{t.pf_intro}</span>
	<h2>{title}</h2>
	<p class="body">{body}</p>

	<button class="btn-primary act" onclick={request} disabled={requesting}>{action}</button>

	{#if waiting}
		<span class="waiting"><span class="spinner"></span>{t.pf_waiting}</span>
	{/if}
	{#if error}
		<p class="err">{error}</p>
	{/if}
</div>

<style>
	.gate {
		width: 100%;
		display: flex;
		flex-direction: column;
		align-items: center;
		text-align: center;
		gap: 10px;
		padding: 8px 4px 4px;
	}
	.badge {
		width: 52px;
		height: 52px;
		border-radius: 14px;
		display: flex;
		align-items: center;
		justify-content: center;
		color: var(--c-accent);
		background: color-mix(in srgb, var(--c-accent) 14%, transparent);
		border: 1px solid color-mix(in srgb, var(--c-accent) 30%, transparent);
		margin-bottom: 2px;
	}
	.intro {
		font-size: 12px;
		font-weight: 600;
		letter-spacing: 0.04em;
		text-transform: uppercase;
		color: var(--c-accent);
	}
	h2 {
		font-size: 17px;
		font-weight: 700;
		margin: 0;
	}
	.body {
		font-size: 13px;
		line-height: 1.55;
		color: var(--c-text-dim);
		max-width: 300px;
	}
	.act {
		margin-top: 6px;
		padding: 10px 18px;
		font-size: 14px;
	}
	.waiting {
		display: inline-flex;
		align-items: center;
		gap: 8px;
		font-size: 12px;
		color: var(--c-text-dim);
	}
	.spinner {
		width: 12px;
		height: 12px;
		border: 2px solid color-mix(in srgb, var(--c-accent) 30%, transparent);
		border-top-color: var(--c-accent);
		border-radius: 50%;
		animation: spin 0.7s linear infinite;
	}
	@keyframes spin {
		to {
			transform: rotate(360deg);
		}
	}
	.err {
		font-size: 12px;
		color: var(--c-danger);
		max-width: 300px;
	}
</style>
