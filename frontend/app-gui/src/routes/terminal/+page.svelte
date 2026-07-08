<script lang="ts">
  import { onMount, onDestroy } from "svelte";
  import { page } from "$app/stores";
  import { goto } from "$app/navigation";
  import { invoke } from "@tauri-apps/api/core";
  import { listen } from "@tauri-apps/api/event";
  import type { UnlistenFn } from "@tauri-apps/api/event";

  // Query params: nodeId, nodeHostname, login (all optional)
  const nodeId = $derived($page.url.searchParams.get("nodeId") ?? "");
  const nodeHostname = $derived($page.url.searchParams.get("nodeHostname") ?? undefined);
  const login = $derived($page.url.searchParams.get("login") ?? undefined);

  let termEl: HTMLDivElement;
  let status = $state("Connecting…");
  let error = $state("");

  let unlistenData: UnlistenFn | null = null;
  let unlistenExit: UnlistenFn | null = null;

  onMount(async () => {
    // Dynamic import: xterm only runs in the Tauri webview (not during SSR/prerender).
    const { Terminal } = await import("@xterm/xterm");
    const { FitAddon } = await import("@xterm/addon-fit");
    await import("@xterm/xterm/css/xterm.css");

    const term = new Terminal({
      cursorBlink: true,
      fontSize: 13,
      fontFamily: '"SF Mono", "Cascadia Code", "Fira Code", monospace',
      theme: {
        background: "#0d1117",
        foreground: "#c9d1d9",
        cursor: "#58a6ff",
        selectionBackground: "#264f78",
      },
    });

    const fitAddon = new FitAddon();
    term.loadAddon(fitAddon);
    term.open(termEl);
    fitAddon.fit();

    const rows = term.rows;
    const cols = term.cols;

    // Forward xterm keystrokes to the PTY.
    term.onData((data) => {
      invoke("ssh_terminal_input", { data }).catch(() => {});
    });

    // Handle resize.
    const ro = new ResizeObserver(() => {
      fitAddon.fit();
      invoke("ssh_terminal_resize", { rows: term.rows, cols: term.cols }).catch(
        () => {}
      );
    });
    ro.observe(termEl);

    // Receive PTY output from Rust.
    unlistenData = await listen<string>("ssh-data", ({ payload }) => {
      term.write(payload);
    });

    unlistenExit = await listen<void>("ssh-exit", () => {
      status = "Connection closed";
      term.write("\r\n\x1b[33m[Session ended — press any key to go back]\x1b[0m\r\n");
      term.onKey(() => goto("/services"));
    });

    // Start the SSH session.
    try {
      await invoke("ssh_terminal_start", {
        nodeId,
        nodeHostname,
        login,
        rows,
        cols,
      });
      status = "Connected";
    } catch (e) {
      error = String(e);
      status = "Failed";
    }
  });

  onDestroy(() => {
    unlistenData?.();
    unlistenExit?.();
    invoke("ssh_terminal_close").catch(() => {});
  });
</script>

<div class="terminal-page">
  <header>
    <button class="back-btn" onclick={() => goto("/services")}>← Back</button>
    <span class="status" class:ok={status === "Connected"} class:err={status === "Failed"}>
      {status}
    </span>
    {#if nodeHostname}
      <span class="host">{nodeHostname}</span>
    {/if}
  </header>

  {#if error}
    <div class="err-box">{error}</div>
  {/if}

  <div class="term-wrap" bind:this={termEl}></div>
</div>

<style>
  :global(body) {
    margin: 0;
    padding: 0;
    background: #0d1117;
  }

  .terminal-page {
    display: flex;
    flex-direction: column;
    height: 100dvh;
    background: #0d1117;
    color: #c9d1d9;
  }

  header {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 8px 14px;
    background: #161b22;
    border-bottom: 1px solid #30363d;
    font-size: 13px;
    flex-shrink: 0;
  }

  .back-btn {
    background: none;
    border: 1px solid #30363d;
    border-radius: 6px;
    color: #c9d1d9;
    padding: 4px 10px;
    font-size: 13px;
    cursor: pointer;
  }
  .back-btn:hover {
    background: #21262d;
  }

  .status {
    font-size: 12px;
    padding: 2px 8px;
    border-radius: 10px;
    background: #21262d;
    color: #8b949e;
  }
  .status.ok {
    background: color-mix(in srgb, #2ea043 18%, transparent);
    color: #2ea043;
  }
  .status.err {
    background: color-mix(in srgb, #f85149 18%, transparent);
    color: #f85149;
  }

  .host {
    font-family: "SF Mono", "Fira Code", monospace;
    font-size: 12px;
    color: #58a6ff;
  }

  .err-box {
    padding: 10px 14px;
    color: #f85149;
    font-size: 13px;
    background: color-mix(in srgb, #f85149 10%, transparent);
    border-bottom: 1px solid #30363d;
  }

  .term-wrap {
    flex: 1;
    padding: 8px;
    overflow: hidden;
  }

  /* Override xterm.js defaults for full stretch */
  :global(.xterm) {
    height: 100%;
  }
  :global(.xterm-viewport) {
    overflow-y: auto !important;
  }
</style>
