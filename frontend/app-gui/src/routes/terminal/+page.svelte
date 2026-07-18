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
	import { sshOpen, sshWrite, sshResize, sshClose, openSshTerminal, getPlatform } from '$lib/tauri';
	import SshReceipts from '$lib/components/SshReceipts.svelte';

	const nodeId = $derived($page.url.searchParams.get('node') ?? '');
	const host = $derived($page.url.searchParams.get('host') ?? nodeId);
	// Close returns to the page the terminal was opened from (Services or My
	// Devices), not a hard-coded route. Falls back to My Devices for old links.
	const from = $derived($page.url.searchParams.get('from') ?? '/settings/devices');

	// Desktop-only "open in external terminal" (Terminal.app / iTerm2 / …) for power
	// users who want their terminal's features. Choice persists in localStorage.
	// TODO[A]: detect which terminal apps are actually installed (e.g. a Tauri cmd
	// that checks /Applications + `mdfind`) and only list those, so a not-installed
	// pick (e.g. Ghostty) can't be chosen. For now an uninstalled app errors softly.
	let platform = $state('');
	let isDesktop = $state(false);
	// The terminal-app list is per-OS (a macOS pick must not leak to Windows), so
	// the choice is keyed by platform and defaults to that OS's native terminal.
	let termApp = $state('Terminal');
	getPlatform()
		.then((p) => {
			platform = p;
			isDesktop = p !== 'ios' && p !== 'android';
			const saved =
				typeof localStorage !== 'undefined' ? localStorage.getItem(`ssh_terminal_app_${p}`) : null;
			termApp = saved || (p === 'windows' ? 'Windows Terminal' : 'Terminal');
		})
		.catch(() => {});
	function openExternal() {
		if (typeof localStorage !== 'undefined')
			localStorage.setItem(`ssh_terminal_app_${platform}`, termApp);
		openSshTerminal(nodeId, undefined, termApp).catch((e) => (notice = 'Mở terminal ngoài lỗi: ' + String(e)));
	}

	let termEl: HTMLDivElement;
	let term: Terminal | null = null;
	let fit: FitAddon | null = null;
	let sessionId = '';
	let unlistenData: UnlistenFn | null = null;
	let unlistenEnd: UnlistenFn | null = null;
	let status = $state<'connecting' | 'connected' | 'ended' | 'error'>('connecting');
	let errorMsg = $state('');
	let showSshLog = $state(false); // SSH access receipts modal (signed ledger)
	let notice = $state(''); // non-fatal notice (e.g. elevate needs step-up) — keeps the shell
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

	// Wire a session's output/end events to the terminal.
	async function attachListeners(id: string) {
		unlistenData = await listen<string>(`ssh_data_${id}`, (e) => {
			term?.write(b64ToBytes(e.payload));
		});
		unlistenEnd = await listen(`ssh_end_${id}`, () => {
			status = 'ended';
			term?.write('\r\n\x1b[2m— session ended —\x1b[0m\r\n');
		});
	}

	function detachListeners() {
		if (unlistenData) unlistenData();
		if (unlistenEnd) unlistenEnd();
		unlistenData = null;
		unlistenEnd = null;
	}

	async function start(root: boolean) {
		status = 'connecting';
		errorMsg = '';
		try {
			const { cols, rows } = fit!.proposeDimensions() ?? { cols: 80, rows: 24 };
			sessionId = await sshOpen(nodeId, cols, rows, { root });
			elevated = root;
			await attachListeners(sessionId);
			status = 'connected';
		} catch (e) {
			status = 'error';
			errorMsg = String(e);
		}
	}

	async function teardown() {
		detachListeners();
		if (sessionId) {
			try {
				await sshClose(sessionId);
			} catch {
				/* already gone */
			}
			sessionId = '';
		}
	}

	// [Elevate ↑] — open a NEW root session; swap to it only on success so a failure
	// (e.g. F1 needs a step-up proof) never kills the working shell. `[T:f2 §H.4]`
	async function elevate() {
		if (!term) return;
		notice = '';
		try {
			const { cols, rows } = fit!.proposeDimensions() ?? { cols: 80, rows: 24 };
			const newId = await sshOpen(nodeId, cols, rows, { root: true });
			// Success → detach + close the old session, swap in the root one.
			detachListeners();
			const oldId = sessionId;
			sessionId = newId;
			elevated = true;
			await attachListeners(newId);
			term.clear();
			if (oldId) sshClose(oldId).catch(() => {});
		} catch (e) {
			// Keep the current shell; surface a friendly, non-fatal notice.
			const msg = String(e);
			notice = msg.includes('STEP_UP_REQUIRED')
				? 'Lên root cần xác thực 2 lớp (tier F1). Terminal chưa nhập TOTP — dùng CLI `agent ssh <node> --root --proof <mã>`.'
				: 'Elevate lỗi: ' + msg;
			term.focus();
		}
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
		<button class="back" onclick={() => goto(from)} aria-label="Close terminal">✕</button>
		<div class="title">
			<span class="host">{host}</span>
			<span class="dot {status}"></span>
			<span class="state">{status}{elevated ? ' · root' : ''}</span>
		</div>
		{#if platform === 'windows' || platform === 'macos'}
			<div class="ext" title="Mở phiên này trong terminal ngoài (nhiều tính năng hơn)">
				<select bind:value={termApp} aria-label="Terminal app">
					{#if platform === 'windows'}
						<option value="Windows Terminal">Windows Terminal</option>
						<option value="PowerShell">PowerShell</option>
						<option value="cmd">Command Prompt</option>
					{:else}
						<option value="Terminal">Terminal</option>
						<option value="iTerm">iTerm2</option>
						<option value="Ghostty">Ghostty</option>
						<option value="WezTerm">WezTerm</option>
						<option value="Alacritty">Alacritty</option>
					{/if}
				</select>
				<button class="extbtn" onclick={openExternal}>Mở ngoài ↗</button>
			</div>
		{/if}
		<button class="sshlog" onclick={() => (showSshLog = true)} title="Signed SSH access log (ledger receipts)">🧾 Log</button>
		{#if status === 'connected' && !elevated}
			<button class="elevate" onclick={elevate}>Elevate ↑</button>
		{:else}
			<span class="spacer"></span>
		{/if}
	</header>

	{#if showSshLog}
		<SshReceipts node={nodeId} onclose={() => (showSshLog = false)} />
	{/if}

	<!-- Key-bar at the TOP so the on-screen keyboard (which covers the bottom)
	     never hides it. Only the keys a virtual keyboard lacks. Touch/mobile only. -->
	<div class="keybar">
		<button onclick={() => sendBytes([0x09])}>Tab</button>
		<button onclick={() => sendBytes([0x03])}>Ctrl-C</button>
		<button onclick={() => sendBytes([0x1b, 0x5b, 0x41])}>↑</button>
		<button onclick={() => sendBytes([0x1b, 0x5b, 0x42])}>↓</button>
		<button onclick={() => sendBytes([0x1b, 0x5b, 0x44])}>←</button>
		<button onclick={() => sendBytes([0x1b, 0x5b, 0x43])}>→</button>
	</div>

	{#if status === 'error'}
		<div class="err">
			{#if /failed after|attempt|timed out|timeout|connect|refused|no route/i.test(errorMsg)}
				<strong>Không kết nối được tới {host}.</strong>
				Node có thể chưa ở trên mesh — app bên đó chưa Connect / máy offline, hoặc sau NAT
				mà relay chưa khả dụng. WireGuard chỉ bắt tay khi cả hai đầu cùng online.
			{:else}
				SSH error: {errorMsg}
			{/if}
			<div class="err-detail">{errorMsg}</div>
			<button class="retry" onclick={() => start(false)}>Thử lại</button>
		</div>
	{/if}
	{#if status === 'connecting'}
		<div class="connecting">Đang kết nối tới {host}…</div>
	{/if}
	{#if notice}
		<div class="notice">
			<span>{notice}</span>
			<button onclick={() => (notice = '')} aria-label="Dismiss">✕</button>
		</div>
	{/if}

	<div class="term" bind:this={termEl}></div>
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
		/* Respect the notch / status bar so the title isn't under the clock. */
		padding: calc(0.5rem + env(safe-area-inset-top)) calc(0.75rem + env(safe-area-inset-right))
			0.5rem calc(0.75rem + env(safe-area-inset-left));
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
	.sshlog {
		background: transparent;
		color: var(--c-text-dim);
		border: 1px solid var(--c-border);
		border-radius: 6px;
		padding: 0.3rem 0.6rem;
		font-size: 0.8rem;
		cursor: pointer;
		white-space: nowrap;
	}
	.sshlog:hover {
		color: var(--c-text);
		border-color: var(--c-text-dim);
	}
	.ext {
		display: flex;
		align-items: center;
		gap: 0.3rem;
	}
	.ext select {
		background: #21262d;
		color: #c9d1d9;
		border: 1px solid #30363d;
		border-radius: 6px;
		padding: 0.25rem 0.4rem;
		font-size: 0.78rem;
	}
	.extbtn {
		background: #21262d;
		color: #c9d1d9;
		border: 1px solid #30363d;
		border-radius: 6px;
		padding: 0.3rem 0.55rem;
		font-size: 0.78rem;
		cursor: pointer;
		white-space: nowrap;
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
	.err-detail {
		color: #8b949e;
		font-family: 'SF Mono', 'Fira Code', monospace;
		font-size: 0.72rem;
		margin-top: 0.3rem;
		opacity: 0.8;
	}
	.retry {
		margin-top: 0.4rem;
		background: #30363d;
		color: #e6edf3;
		border: 1px solid #444c56;
		border-radius: 6px;
		padding: 0.2rem 0.7rem;
		font-size: 0.8rem;
		cursor: pointer;
	}
	.term {
		flex: 1;
		min-height: 0;
		padding: 0.25rem;
	}
	.keybar {
		display: none;
		gap: 0.4rem;
		/* Sits under the header (top of screen) so the keyboard can't cover it. */
		padding: 0.4rem calc(0.4rem + env(safe-area-inset-right)) 0.4rem
			calc(0.4rem + env(safe-area-inset-left));
		background: #11151f;
		border-bottom: 1px solid #1f2633;
		overflow-x: auto;
		flex: 0 0 auto;
	}
	.connecting {
		color: #8b949e;
		background: #161b22;
		padding: 0.4rem 0.75rem;
		font-size: 0.85rem;
	}
	.notice {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		color: #e3b341;
		background: #2d2611;
		padding: 0.5rem 0.75rem;
		font-size: 0.85rem;
	}
	.notice span {
		flex: 1;
	}
	.notice button {
		background: none;
		border: none;
		color: #e3b341;
		cursor: pointer;
		font-size: 0.9rem;
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
