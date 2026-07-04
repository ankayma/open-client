<script lang="ts">
	// [F-2 §H.2.2] In-app SSH terminal — xterm.js driven by the mesh russh transport
	// through Tauri commands. Works on desktop AND iOS/iPad (no system Terminal).
	import { onMount, onDestroy } from 'svelte';
	import { goto } from '$app/navigation';
	import { page } from '$app/stores';
	import { Terminal } from '@xterm/xterm';
	import { FitAddon } from '@xterm/addon-fit';
	import { listen, type UnlistenFn } from '@tauri-apps/api/event';
	import '@xterm/xterm/css/xterm.css';
	import { sshOpen, sshWrite, sshResize, sshClose } from '$lib/tauri';

	const nodeId = $derived($page.url.searchParams.get('node') ?? '');
	const host = $derived($page.url.searchParams.get('host') ?? nodeId);

	let termEl: HTMLDivElement;
	let term: Terminal | null = null;
	let fit: FitAddon | null = null;
	let sessionId = '';
	let unlistenData: UnlistenFn | null = null;
	let unlistenEnd: UnlistenFn | null = null;
	let status = $state<'connecting' | 'connected' | 'ended' | 'error'>('connecting');
	let errorMsg = $state('');
	let elevated = $state(false);

	// base64 <-> bytes (browser-safe, no Buffer).
	function b64ToBytes(b64: string): Uint8Array {
		const bin = atob(b64);
		const out = new Uint8Array(bin.length);
		for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
		return out;
	}
	function strToB64(s: string): string {
		const bytes = new TextEncoder().encode(s);
		let bin = '';
		for (const b of bytes) bin += String.fromCharCode(b);
		return btoa(bin);
	}

	async function start(root: boolean) {
		status = 'connecting';
		errorMsg = '';
		try {
			const { cols, rows } = fit!.proposeDimensions() ?? { cols: 80, rows: 24 };
			sessionId = await sshOpen(nodeId, cols, rows, { root });
			elevated = root;
			unlistenData = await listen<string>(`ssh_data_${sessionId}`, (e) => {
				term?.write(b64ToBytes(e.payload));
			});
			unlistenEnd = await listen(`ssh_end_${sessionId}`, () => {
				status = 'ended';
				term?.write('\r\n\x1b[2m— session ended —\x1b[0m\r\n');
			});
			status = 'connected';
		} catch (e) {
			status = 'error';
			errorMsg = String(e);
		}
	}

	async function teardown() {
		if (unlistenData) unlistenData();
		if (unlistenEnd) unlistenEnd();
		unlistenData = null;
		unlistenEnd = null;
		if (sessionId) {
			try {
				await sshClose(sessionId);
			} catch {
				/* already gone */
			}
			sessionId = '';
		}
	}

	// [Elevate ↑] — reconnect as root (§H.4). F1+ needs a step-up proof; if the CP
	// demands one, the error surfaces (step-up UI is the follow-up).
	async function elevate() {
		await teardown();
		term?.clear();
		await start(true);
	}

	function sendBytes(bytes: number[]) {
		if (!sessionId) return;
		let bin = '';
		for (const b of bytes) bin += String.fromCharCode(b);
		sshWrite(sessionId, btoa(bin)).catch(() => {});
	}

	function onWindowResize() {
		fit?.fit();
	}

	onMount(async () => {
		term = new Terminal({
			fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace',
			fontSize: 13,
			cursorBlink: true,
			theme: { background: '#0b0e14', foreground: '#c9d1d9' }
		});
		fit = new FitAddon();
		term.loadAddon(fit);
		term.open(termEl);
		fit.fit();

		term.onData((d) => {
			if (sessionId) sshWrite(sessionId, strToB64(d)).catch(() => {});
		});
		term.onResize(({ cols, rows }) => {
			if (sessionId) sshResize(sessionId, cols, rows).catch(() => {});
		});
		window.addEventListener('resize', onWindowResize);

		if (!nodeId) {
			status = 'error';
			errorMsg = 'no node specified';
			return;
		}
		await start(false);
		term.focus();
	});

	onDestroy(() => {
		window.removeEventListener('resize', onWindowResize);
		teardown();
		term?.dispose();
	});
</script>

<div class="term-page">
	<header>
		<button class="back" onclick={() => goto('/settings/devices')} aria-label="Close terminal">✕</button>
		<div class="title">
			<span class="host">{host}</span>
			<span class="dot {status}"></span>
			<span class="state">{status}{elevated ? ' · root' : ''}</span>
		</div>
		{#if status === 'connected' && !elevated}
			<button class="elevate" onclick={elevate}>Elevate ↑</button>
		{:else}
			<span class="spacer"></span>
		{/if}
	</header>

	{#if status === 'error'}
		<div class="err">SSH error: {errorMsg}</div>
	{/if}

	<div class="term" bind:this={termEl}></div>

	<!-- Mobile key-bar: keys a virtual keyboard lacks. Hidden on desktop. -->
	<div class="keybar">
		<button onclick={() => sendBytes([0x1b])}>Esc</button>
		<button onclick={() => sendBytes([0x09])}>Tab</button>
		<button onclick={() => sendBytes([0x03])}>Ctrl-C</button>
		<button onclick={() => sendBytes([0x04])}>Ctrl-D</button>
		<button onclick={() => sendBytes([0x1b, 0x5b, 0x41])}>↑</button>
		<button onclick={() => sendBytes([0x1b, 0x5b, 0x42])}>↓</button>
		<button onclick={() => sendBytes([0x1b, 0x5b, 0x44])}>←</button>
		<button onclick={() => sendBytes([0x1b, 0x5b, 0x43])}>→</button>
	</div>
</div>

<style>
	.term-page {
		position: fixed;
		inset: 0;
		display: flex;
		flex-direction: column;
		background: #0b0e14;
		z-index: 50;
	}
	header {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		padding: 0.5rem 0.75rem;
		background: #11151f;
		border-bottom: 1px solid #1f2633;
		color: #c9d1d9;
	}
	.back {
		background: none;
		border: none;
		color: #8b949e;
		font-size: 1rem;
		cursor: pointer;
		padding: 0.25rem 0.5rem;
	}
	.title {
		flex: 1;
		display: flex;
		align-items: center;
		gap: 0.5rem;
		font-size: 0.9rem;
	}
	.host {
		font-weight: 600;
	}
	.dot {
		width: 8px;
		height: 8px;
		border-radius: 50%;
		background: #d29922;
	}
	.dot.connected {
		background: #2ea043;
	}
	.dot.ended,
	.dot.error {
		background: #f85149;
	}
	.state {
		color: #8b949e;
		font-size: 0.8rem;
	}
	.elevate {
		background: #1f6feb;
		color: #fff;
		border: none;
		border-radius: 6px;
		padding: 0.3rem 0.6rem;
		font-size: 0.8rem;
		cursor: pointer;
	}
	.spacer {
		width: 1px;
	}
	.err {
		color: #f85149;
		background: #21262d;
		padding: 0.4rem 0.75rem;
		font-size: 0.85rem;
	}
	.term {
		flex: 1;
		min-height: 0;
		padding: 0.25rem;
	}
	.keybar {
		display: none;
		gap: 0.4rem;
		padding: 0.4rem;
		background: #11151f;
		border-top: 1px solid #1f2633;
		overflow-x: auto;
	}
	.keybar button {
		flex: 0 0 auto;
		background: #21262d;
		color: #c9d1d9;
		border: 1px solid #30363d;
		border-radius: 6px;
		padding: 0.5rem 0.7rem;
		font-size: 0.85rem;
		cursor: pointer;
	}
	/* Show the key-bar on touch / small screens (iOS/iPad). */
	@media (pointer: coarse), (max-width: 820px) {
		.keybar {
			display: flex;
		}
	}
</style>
