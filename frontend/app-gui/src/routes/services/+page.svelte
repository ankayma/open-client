<script lang="ts">
  import { onMount } from "svelte";
  import { goto } from "$app/navigation";
  import { myAccess, openSubdomain, getNodeInfo, listNodes, listCiPolicies, ciHistory, sshHistory, getPathProof, probeReachable } from "$lib/tauri";
  import type { MyAccess, AccessService, PeerBrief, CiPolicy, CiRun, SshSession, PathProof, PathPeer } from "$lib/types";
  import { connection, myRole } from "$lib/stores";
  import ConnectionCard from "$lib/components/ConnectionCard.svelte";
  import PathChain from "$lib/components/PathChain.svelte";

  // my-access (addendum §D): the services this identity may reach, derived from the
  // active PolicyBlock. Admin sees all (allow-within-owner); members see what policy
  // grants. The rule_ref shows WHY each is granted. Fetched over REST regardless of
  // tunnel state — the list itself never needs to hide on disconnect (H.2.1); only
  // tunnel-dependent actions ("Open ↗") get disabled below.
  let data = $state<MyAccess | null>(null);
  let loading = $state(true);
  let error = $state("");
  let pathChainSvc = $state<AccessService | null>(null);
  let myHostname = $state<string | null>(null);
  let myNodeId = $state<string | null>(null);
  let peers = $state<PeerBrief[]>([]);
  let proof = $state<PathProof | null>(null);
  // hostname → reachable, from the active TCP probe (authoritative "reachable NOW").
  let reachMap = $state<Map<string, boolean>>(new Map());

  onMount(() => {
    load();
    getNodeInfo()
      .then((n) => {
        myHostname = n.hostname;
        myNodeId = n.node_id;
      })
      .catch(() => {});
    // Peer list backs the SSH button (hostname → node_id for /terminal). A member
    // without the nodes scope just gets no SSH buttons — not an error state.
    listNodes().then((p) => (peers = p)).catch(() => {});
    // [F-1 viewer] Deploy rules back the CI/CD chip: a node targeted by a rule
    // shows the chip; clicking opens its CI run history. Owner/admin sees by
    // default; a member the server doesn't authorize simply gets no chips.
    listCiPolicies().then((p) => (ciPolicies = p)).catch(() => {});
    // Live reachability: poll the WireGuard handshake age so each node shows whether
    // it's actually on the mesh (SSH/Open only work if a handshake is fresh). A node
    // can be powered on yet unreachable — its agent may not be connected. [T:F-5]
    loadProof();
    probeReach();
    const iv = setInterval(loadProof, 8000);
    // Active probe is heavier (one TCP connect per peer) — run it less often.
    const pv = setInterval(probeReach, 25000);
    return () => {
      clearInterval(iv);
      clearInterval(pv);
    };
  });

  async function loadProof() {
    try {
      proof = await getPathProof();
    } catch {
      /* keep the last snapshot rather than blanking the badges */
    }
  }

  // Active reachability: TCP-probe every peer's overlay (which also wakes its WG
  // handshake), then reduce to hostname → reachable (a node is reachable if ANY of
  // its overlay IPs responds). This is authoritative "reachable NOW", unlike the
  // lagging handshake age. Skips when disconnected. [T:A.1.1]
  async function probeReach() {
    if (!connected) {
      reachMap = new Map();
      return;
    }
    const pr = proof ?? (await getPathProof().catch(() => null));
    if (!pr || pr.peers.length === 0) return;
    try {
      const ips = pr.peers.map((p) => p.overlay_ip);
      const results = await probeReachable(ips);
      const m = new Map<string, boolean>();
      pr.peers.forEach((p, i) => {
        m.set(p.hostname, (m.get(p.hostname) ?? false) || !!results[i]);
      });
      reachMap = m;
    } catch {
      /* keep last */
    }
  }

  // Reachability of a node over the mesh, from the live WireGuard handshake age
  // (types.ts: the real "is this reachable" signal — NOT the CP `active` flag).
  // Honest per P.3: a null/stale handshake means "not handshaking now" (agent down,
  // asleep, or NAT with no relay yet) — we say "no handshake", not "offline".
  type Reach = "online" | "stale" | "unknown";
  function reachOf(node: string): Reach {
    if (!connected) return "unknown";
    // Prefer the active probe (authoritative NOW); fall back to handshake age until
    // the first probe lands.
    if (reachMap.has(node)) return reachMap.get(node) ? "online" : "stale";
    if (!proof) return "unknown";
    const matches = proof.peers.filter((p) => p.hostname === node);
    if (matches.length === 0) return "unknown";
    const best = matches.reduce((a, b) => {
      const av = a.last_handshake_secs ?? Infinity;
      const bv = b.last_handshake_secs ?? Infinity;
      return bv < av ? b : a;
    });
    const hs = best.last_handshake_secs;
    if (hs === null || hs === undefined) return "stale";
    return hs <= 180 ? "online" : "stale";
  }
  // Probe-CONFIRMED unreachable — only true after a probe returned false (not merely
  // "no handshake yet"). Actions are disabled only on this, so a not-yet-probed node
  // stays clickable (no deadlock while the first probe is in flight).
  function probedDown(node: string): boolean {
    return reachMap.get(node) === false;
  }
  const REACH_LABEL = { online: "reachable", stale: "unreachable", unknown: "" } as const;
  const REACH_TITLE = {
    online: "Responds over the mesh — reachable",
    stale: "No response over the mesh — SSH/Open will time out (agent not connected, asleep, or NAT without a relay)",
    unknown: "Connect the tunnel to see reachability",
  } as const;

  async function load() {
    loading = true;
    error = "";
    try {
      data = await myAccess();
      myRole.set(data.role); // surface role app-wide (BottomTabBar admin-tab gate)
    } catch (e: unknown) {
      error = e instanceof Error ? e.message : "Failed to load services";
    } finally {
      loading = false;
    }
  }

  // Group services by node — a node with more than one reachable service renders
  // as one card with a child list, instead of one flat card per service. `owned`
  // is a device-scoped signal (does this node match *my* current hostname) — the
  // my-access response has no cross-device ownership field yet, so cards for a
  // teammate's other devices land in "Team / Shared" even if they're that
  // teammate's own node. [A] narrower than full ownership; verify once my-access
  // grows an owner field.
  interface NodeGroup { node: string; owned: boolean; services: AccessService[] }
  let groups = $derived.by((): NodeGroup[] => {
    const byNode = new Map<string, AccessService[]>();
    for (const svc of data?.services ?? []) {
      const list = byNode.get(svc.node) ?? [];
      list.push(svc);
      byNode.set(svc.node, list);
    }
    return [...byNode.entries()].map(([node, services]) => ({
      node,
      owned: myHostname !== null && node === myHostname,
      services
    }));
  });
  let ownedGroups = $derived(groups.filter((g) => g.owned));
  let teamGroups = $derived(groups.filter((g) => !g.owned));
  let connected = $derived($connection.status === "connected");

  // Filter (header dropdown) — narrows the list to my nodes / team-shared.
  let filter = $state<"all" | "mine" | "team">("all");
  let filterOpen = $state(false);
  const FILTER_LABELS = { all: "All", mine: "My nodes", team: "Team / Shared" } as const;
  const FILTER_OPTIONS = ["all", "mine", "team"] as const;
  let visibleOwned = $derived(filter === "team" ? [] : ownedGroups);
  let visibleTeam = $derived(filter === "mine" ? [] : teamGroups);
  let showSectionHeaders = $derived(visibleOwned.length > 0 && visibleTeam.length > 0);

  // [F-2 §H.2.2] SSH button next to Open — mesh terminal to the node behind the
  // service. Gated on role: my_access has no per-service SSH-grant field yet, so
  // admin is the only role that provably holds node access. TODO[A]: switch to a
  // per-service grant once my_access returns one (verify post F1 multi-user).
  function sshPeer(node: string): PeerBrief | null {
    if (data?.role !== "admin") return null;
    const p = peers.find((p) => p.hostname === node) ?? null;
    // ssh to yourself is a confusing no-op at F0 — same rule as My Devices.
    return p && p.node_id !== myNodeId ? p : null;
  }
  function sshTo(p: PeerBrief) {
    goto(
      `/terminal?node=${encodeURIComponent(p.node_id)}&host=${encodeURIComponent(p.hostname)}&from=${encodeURIComponent("/services")}`
    );
  }

  // [F-1 viewer] CI/CD chip + history modal state.
  let ciPolicies = $state<CiPolicy[]>([]);
  let ciNode = $state<string | null>(null);
  // "ci" = the CICD chip (deploys only) · "all" = Activity & receipts (deploys + SSH).
  let ciMode = $state<"ci" | "all">("all");
  let ciRuns = $state<CiRun[] | null>(null);
  let sshSessions = $state<SshSession[] | null>(null);
  let ciErr = $state("");
  // Which receipt is expanded (keyed by block hash). Tap-to-reveal, because a phone has no
  // hover — the signed detail (exact time, issuer, run/session id, full block) must be
  // reachable by touch, not only a desktop title tooltip.
  let openReceipt = $state<string | null>(null);
  function ciRules(node: string): CiPolicy[] {
    return ciPolicies.filter((p) => p.target_hostname === node);
  }

  // Unified node ledger: EVERY signed action on this node — CI deploys AND SSH sessions —
  // newest first. "Who did what, when", each anchored to its append-only ledger block, so
  // the receipts pane isn't just deploys. [T:A.1.8 append-only ledger]
  type Activity = {
    kind: "deploy" | "ssh";
    who: string; // repo (no ref — moved to detail) or login@host
    action: string;
    ok: boolean;
    at?: string;
    hash?: string;
    ref?: string;
    issuer?: string;
    environment?: string;
    refId?: string; // run_id (deploy) or session_id (ssh)
  };
  let activity = $derived.by((): Activity[] | null => {
    if (ciRuns === null && sshSessions === null) return null; // both still loading
    const out: Activity[] = [];
    for (const r of ciRuns ?? []) {
      out.push({
        kind: "deploy",
        who: r.repo ?? "?",
        action: r.outcome === "allow" ? "deployed" : "deploy denied",
        ok: r.outcome === "allow",
        at: r.at,
        hash: r.block_hash,
        ref: r.ref,
        issuer: r.issuer,
        environment: r.environment,
        refId: r.run_id,
      });
    }
    for (const s of sshSessions ?? []) {
      out.push({
        kind: "ssh",
        who: `${s.login ?? "?"}${s.target_host ? `@${s.target_host}` : ""}`,
        action: "SSH session",
        ok: true,
        at: s.at,
        hash: s.block_hash,
        refId: s.session_id,
      });
    }
    return out.sort((a, b) => (b.at ?? "").localeCompare(a.at ?? "")); // newest first
  });

  // `rule_ref` is access provenance like "role=member → service=X", "tag=prod → …",
  // "* → …", or "owner (admin)". The tag only needs the short access basis — the role,
  // the matching tag, or "owner"/"all" — so the card stays tidy. The full string is
  // kept in the tag's title for anyone who wants the detail.
  function shortRule(ref: string): string {
    if (ref.startsWith("owner")) return "owner";
    const from = ref.split("→")[0].trim();
    if (!from || from === "*") return "all";
    const role = from.match(/role=([^,\s]+)/);
    if (role) return role[1];
    const first = from.split(",")[0].trim();
    return first.includes("=") ? first.split("=")[1] : first;
  }
  // GitHub-style relative time ("15m ago", "1d ago") — the absolute timestamp stays on
  // hover (title). Far easier to scan than a full ISO string in the deploy ledger.
  function timeAgo(iso?: string): string {
    if (!iso) return "";
    const t = new Date(iso).getTime();
    if (Number.isNaN(t)) return iso;
    const s = Math.floor((Date.now() - t) / 1000);
    if (s < 45) return "just now";
    const m = Math.floor(s / 60);
    if (m < 60) return `${m}m ago`;
    const h = Math.floor(m / 60);
    if (h < 24) return `${h}h ago`;
    const d = Math.floor(h / 24);
    if (d < 30) return `${d}d ago`;
    const mo = Math.floor(d / 30);
    if (mo < 12) return `${mo}mo ago`;
    return `${Math.floor(mo / 12)}y ago`;
  }
  // Exact local time, minute precision — "2026-07-18 20:46". Cleaner than the raw ISO
  // (microseconds + tz) for the receipt detail.
  function formatTime(iso?: string): string {
    if (!iso) return "";
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return iso;
    const p = (n: number) => String(n).padStart(2, "0");
    return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
  }
  function openCiHistory(node: string, mode: "ci" | "all" = "all") {
    ciNode = node;
    ciMode = mode;
    ciRuns = null;
    // "ci" mode never merges SSH — seed it empty so the deploys render on their own.
    sshSessions = mode === "all" ? null : [];
    ciErr = "";
    ciHistory(node)
      .then((r) => (ciRuns = r))
      .catch((e) => (ciErr = String(e)));
    // SSH ledger only for the full Activity view; failing = no session receipts to merge.
    if (mode === "all") {
      sshHistory(node)
        .then((s) => (sshSessions = s))
        .catch(() => (sshSessions = []));
    }
  }

  // `proof` is polled on mount (loadProof) for the reachability badges; the path
  // chain modal reuses that same live snapshot — no separate load/null needed.

  // Find the WireGuard peer that backs the selected service node.
  const pathChainPeer: PathPeer | null = $derived(
    proof?.peers.find((p) => p.hostname === pathChainSvc?.node) ?? null
  );
</script>

<main>
  <div class="layout">
    <aside class="conn-panel">
      <ConnectionCard />
    </aside>

    <section class="services-panel">
      <header>
        <h2>Services</h2>
        <div class="header-actions">
          <div class="filter-wrap">
            <button
              class="btn-secondary filter-btn"
              class:active={filter !== "all"}
              aria-haspopup="menu"
              aria-expanded={filterOpen}
              onclick={() => (filterOpen = !filterOpen)}
            >
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 7h18M3 12h18M3 17h18"/></svg>
              {filter === "all" ? "Filter" : FILTER_LABELS[filter]} ▾
            </button>
            {#if filterOpen}
              <div class="filter-backdrop" role="presentation" onclick={() => (filterOpen = false)}></div>
              <div class="filter-menu" role="menu">
                {#each FILTER_OPTIONS as f (f)}
                  <button
                    class="filter-opt"
                    class:selected={filter === f}
                    role="menuitemradio"
                    aria-checked={filter === f}
                    onclick={() => { filter = f; filterOpen = false; }}
                  >
                    {FILTER_LABELS[f]}
                    {#if filter === f}<span class="check">✓</span>{/if}
                  </button>
                {/each}
              </div>
            {/if}
          </div>
          <button class="icon-btn" onclick={load} aria-label="Refresh">↻</button>
        </div>
      </header>

      <p class="desc">
        What you can reach on this mesh, derived from your team's access policy. Each
        service opens privately over the overlay — no public port.
        {#if data}<span class="role-chip">{data.role}</span>{/if}
      </p>

      {#if error}
        <p class="err">{error}</p>
      {:else if loading}
        <div class="empty">Loading…</div>
      {:else if !data || data.services.length === 0}
        <div class="empty">
          <p>No services you can reach yet.</p>
          <p class="hint">
            An admin grants access in <strong>Access</strong>, and services are named in
            <strong>Subdomains</strong>.
          </p>
        </div>
      {:else}
        <div class="grid">
          {#if visibleOwned.length > 0}
            {#if showSectionHeaders}<div class="section-divider">── My Nodes</div>{/if}
            {#each visibleOwned as group (group.node)}
              {#if group.services.length === 1}
                {@render serviceCard(group.services[0], true)}
              {:else}
                {@render nodeCard(group)}
              {/if}
            {/each}
          {/if}

          {#if visibleTeam.length > 0}
            {#if showSectionHeaders}<div class="section-divider">── Team / Shared</div>{/if}
            {#each visibleTeam as group (group.node)}
              {#if group.services.length === 1}
                {@render serviceCard(group.services[0], false)}
              {:else}
                {@render nodeCard(group)}
              {/if}
            {/each}
          {/if}
        </div>
      {/if}
    </section>
  </div>
</main>

{#snippet serviceCard(svc: AccessService, owned: boolean)}
  <div class="card" class:denied={svc.status === "denied"} class:owned>
    <div class="card-head">
      <span class="label">
        {#if !owned}
          <span class="reach-dot {reachOf(svc.node)}" title={REACH_TITLE[reachOf(svc.node)]}>{reachOf(svc.node) === "online" ? "●" : "○"}</span>
        {/if}
        {svc.label}
        {#if owned}<span class="owned-badge">● owned</span>{/if}
        <span class="tag" title={svc.rule_ref}>{shortRule(svc.rule_ref)}</span>
      </span>
    </div>
    <code class="fqdn">{svc.fqdn}</code>
    {#if (svc.tags ?? []).length > 0}
      <div class="tags">
        {#each svc.tags ?? [] as t}<span class="tag">{t}</span>{/each}
      </div>
    {/if}
    <div class="meta">
      {#if svc.status === "denied"}
        <span class="denied-text">access denied (no policy)</span>
      {:else}
        <span>→ {svc.node}</span>
      {/if}
    </div>
    {#if svc.status !== "denied"}
      <!-- Every action on one row at the card's foot — keeps the head clear so a long
           label/rule tag can't push buttons off-screen. -->
      <div class="card-actions">
        {#if !owned}
          <button
            class="btn-secondary chain-btn"
            disabled={probedDown(svc.node)}
            title={probedDown(svc.node) ? "Unreachable — no live path to show" : ""}
            onclick={() => (pathChainSvc = svc)}
          >◈ path</button>
        {/if}
        {#if ciRules(svc.node).length > 0}
          <button class="btn-secondary ci-chip" title="CI deploy history for {svc.node}" onclick={() => openCiHistory(svc.node, "ci")}>🧾 CICD</button>
        {/if}
        <!-- self device (this machine): Open/SSH/path chain to yourself are no-ops;
             keep only CI/CD history. `owned` == the current device (hostname match). -->
        {#if !owned && sshPeer(svc.node)}
          <button
            class="btn-secondary ssh-btn"
            disabled={!connected || probedDown(svc.node)}
            title={probedDown(svc.node) ? "Unreachable — no response over the mesh" : "SSH into " + svc.node}
            onclick={() => sshTo(sshPeer(svc.node)!)}
          >
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 17l6-6-6-6M12 19h8"/></svg>
            SSH
          </button>
        {/if}
        {#if !owned}
          <button class="btn-primary" disabled={!connected || probedDown(svc.node)} title={probedDown(svc.node) ? "Unreachable — no response over the mesh" : ""} onclick={() => openSubdomain(svc.fqdn)}>Open ↗</button>
        {/if}
      </div>
    {/if}
  </div>
{/snippet}

{#snippet nodeCard(group: NodeGroup)}
  <div class="card node-card" class:owned={group.owned}>
    <div class="card-head">
      <span class="label">
        {#if !group.owned}
          <span class="reach-dot {reachOf(group.node)}" title={REACH_TITLE[reachOf(group.node)]}>{reachOf(group.node) === "online" ? "●" : "○"}</span>
        {/if}
        {group.node}
        {#if group.owned}<span class="owned-badge">● owned</span>{/if}
      </span>
    </div>
    {#if !group.owned || ciRules(group.node).length > 0}
      <!-- Node-level actions on their own row. Path chain and CI/CD are per-NODE
           (the live data-path to THIS node, and this node's deploy ledger) — the
           same for every service on it, so they live here once, not repeated per
           service. Only "Open" is per-domain (below). CI/CD hides when the node has
           no deploy rule. -->
      <div class="card-actions">
        {#if !group.owned}
          <button
            class="btn-secondary chain-btn"
            disabled={probedDown(group.node)}
            title={probedDown(group.node) ? "Unreachable — no live path to show" : "Signed data-path to this node"}
            onclick={() => (pathChainSvc = group.services[0])}
          >◈ path</button>
        {/if}
        {#if ciRules(group.node).length > 0}
          <button class="btn-secondary ci-chip" title="CI deploy history for {group.node}" onclick={() => openCiHistory(group.node, "ci")}>🧾 CICD</button>
        {/if}
        {#if !group.owned && sshPeer(group.node)}
          <button
            class="btn-secondary ssh-btn"
            disabled={!connected || probedDown(group.node)}
            title={probedDown(group.node) ? "Unreachable — no response over the mesh" : "SSH into " + group.node}
            onclick={() => sshTo(sshPeer(group.node)!)}
          >
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 17l6-6-6-6M12 19h8"/></svg>
            SSH
          </button>
        {/if}
      </div>
    {/if}
    <div class="child-list">
      {#each group.services as svc (svc.fqdn)}
        <div class="child-row" class:denied={svc.status === "denied"}>
          <div class="child-info">
            <span class="child-label">
              {svc.label}
              <span class="tag" title={svc.rule_ref}>{shortRule(svc.rule_ref)}</span>
            </span>
            <code class="fqdn">{svc.fqdn}</code>
            {#if (svc.tags ?? []).length > 0}
              <div class="tags">
                {#each svc.tags ?? [] as t}<span class="tag">{t}</span>{/each}
              </div>
            {/if}
          </div>
          {#if svc.status === "denied"}
            <span class="denied-text">access denied</span>
          {:else if !group.owned}
            <!-- Per-domain action only: Open. Path chain + CI/CD are node-level (in
                 the node header above) — they're identical for every service here. -->
            <div class="child-actions">
              <button class="btn-primary sm" disabled={!connected || probedDown(svc.node)} title={probedDown(svc.node) ? "Unreachable — no response over the mesh" : ""} onclick={() => openSubdomain(svc.fqdn)}>Open ↗</button>
            </div>
          {/if}
        </div>
      {/each}
    </div>
  </div>
{/snippet}

{#if pathChainSvc}
  <PathChain
    node={pathChainSvc.node}
    peer={pathChainPeer}
    onclose={() => (pathChainSvc = null)}
    onactivity={() => {
      // [F-5] One link from live path-proof → this node's signed ledger receipts.
      const n = pathChainSvc?.node;
      pathChainSvc = null;
      if (n) openCiHistory(n);
    }}
  />
{/if}

<!-- [F-1 viewer] CI history — deploy rules + recent runs for one node, straight
     from the tenant's append-only ledger (read-only). -->
{#if ciNode}
  <div
    class="ci-overlay"
    role="presentation"
    onclick={() => (ciNode = null)}
    onkeydown={(e) => e.key === "Escape" && (ciNode = null)}
  >
    <div
      class="ci-panel"
      role="dialog"
      aria-modal="true"
      tabindex="-1"
      onclick={(e) => e.stopPropagation()}
      onkeydown={(e) => e.stopPropagation()}
    >
      <div class="ci-head">
        <span class="ci-title">{ciMode === "ci" ? "🧾 CI deploys" : "🧾 Activity &amp; receipts"} → {ciNode}</span>
        <button class="ci-close" onclick={() => (ciNode = null)}>✕</button>
      </div>

      <div class="ci-rules">
        {#each ciRules(ciNode) as r (r.repo)}
          <div class="ci-rule">
            <span class="tag">{r.issuer}</span>
            <code class="ci-repo">{r.repo}</code>
            <span class="ci-scope">{r.ref ?? r.environment ?? ""}</span>
          </div>
        {/each}
      </div>

      <!-- Deploy 404 on an older control plane degrades gracefully (A.1.20): rules render
           above, SSH sessions still merge below. Only a NON-404 CI error is surfaced hard. -->
      {#if ciErr && !ciErr.includes("404")}
        <p class="ci-note err">Could not load deploy history: {ciErr}</p>
      {:else if ciErr.includes("404")}
        <p class="ci-note">Deploy history needs the updated control plane — rules above are active; it lands after the next server deploy.</p>
      {/if}
      {#if activity === null}
        <p class="ci-note">Loading activity…</p>
      {:else if activity.length === 0}
        <p class="ci-note">{ciMode === "ci" ? "No deploy runs yet — the first CI run on a rule above lands here, with a signed receipt." : "No signed activity yet — deploys and SSH sessions land here, each with a receipt."}</p>
      {:else}
        <div class="ci-runs">
          {#each activity as a (a.hash ?? `${a.kind}-${a.at}`)}
            {@const key = a.hash ?? `${a.kind}-${a.at}`}
            <div class="ci-entry">
              <button
                type="button"
                class="ci-run"
                aria-expanded={openReceipt === key}
                onclick={() => (openReceipt = openReceipt === key ? null : key)}
              >
                <span class="ci-run-outcome" class:allow={a.ok}>{a.kind === "ssh" ? "🔑" : a.ok ? "✓" : "✕"}</span>
                <div class="ci-run-main">
                  <span class="ci-run-repo">{a.who}</span>
                  <span class="ci-run-meta">{a.action} · {timeAgo(a.at)}</span>
                </div>
                {#if a.hash}
                  <span class="ci-run-ledger">🔒 #{a.hash.slice(0, 8)}</span>
                {/if}
                <span class="ci-run-chevron" class:open={openReceipt === key}>⌄</span>
              </button>
              {#if openReceipt === key}
                <div class="ci-run-detail">
                  <div><span class="dk">time</span> {formatTime(a.at)}</div>
                  {#if a.ref}<div><span class="dk">ref</span> {a.ref}</div>{/if}
                  {#if a.issuer}<div><span class="dk">issued by</span> {a.issuer}</div>{/if}
                  {#if a.environment}<div><span class="dk">env</span> {a.environment}</div>{/if}
                  {#if a.refId}<div><span class="dk">{a.kind === "ssh" ? "session" : "run"}</span> {a.refId}</div>{/if}
                  {#if a.hash}<div class="ci-run-block"><span class="dk">block</span> {a.hash}</div>{/if}
                </div>
              {/if}
            </div>
          {/each}
        </div>
        <p class="ci-note">{ciMode === "ci" ? "Tap a deploy for its signed receipt — re-verify with its run id." : "Tap an entry for its signed receipt — re-verify with its id."}</p>
      {/if}
    </div>
  </div>
{/if}

<style>
  main {
    flex: 1;
    display: flex;
    flex-direction: column;
    /* Bottom padding is JUST breathing room — the tab-bar + home-indicator
       clearance is already reserved once by `.view.with-tabbar`
       (calc(52px + safe-bottom)). Re-adding safe-bottom here double-counted it
       and left a ~100px dead band under the last card. [T:layout #5 fix] */
    padding: calc(var(--safe-top) + 16px) 16px 24px;
    width: 100%;
  }
  .layout {
    display: flex;
    flex-direction: column;
    gap: 16px;
    max-width: 480px;
    margin: 0 auto;
    width: 100%;
  }
  .services-panel {
    display: flex;
    flex-direction: column;
    gap: 16px;
    min-width: 0;
  }
  @media (min-width: 760px) {
    .layout {
      flex-direction: row;
      align-items: flex-start;
      max-width: 1280px;
    }
    .conn-panel {
      width: 260px;
      flex-shrink: 0;
      position: sticky;
      top: 24px;
    }
    .services-panel {
      flex: 1;
    }
  }
  header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
  }
  h2 {
    font-size: 22px;
    font-weight: 700;
  }
  .header-actions {
    display: flex;
    align-items: center;
    gap: 6px;
  }
  .filter-wrap {
    position: relative;
  }
  .filter-btn {
    display: flex;
    align-items: center;
    gap: 6px;
    font-size: 13px;
  }
  .filter-btn.active {
    color: var(--c-accent);
    border-color: color-mix(in srgb, var(--c-accent) 40%, var(--c-border));
  }
  .filter-backdrop {
    position: fixed;
    inset: 0;
    z-index: 90;
  }
  .filter-menu {
    position: absolute;
    top: calc(100% + 6px);
    right: 0;
    z-index: 100;
    min-width: 160px;
    background: var(--c-surface);
    border: 1px solid var(--c-border);
    border-radius: 10px;
    padding: 4px;
    box-shadow: 0 8px 24px rgba(0, 0, 0, 0.35);
    display: flex;
    flex-direction: column;
  }
  .filter-opt {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
    padding: 8px 10px;
    border-radius: 7px;
    font-size: 13px;
    text-align: left;
    color: var(--c-text);
  }
  .filter-opt:hover {
    background: color-mix(in srgb, var(--c-accent) 10%, transparent);
  }
  .filter-opt.selected {
    color: var(--c-accent);
    font-weight: 600;
  }
  .filter-opt .check {
    font-size: 12px;
  }
  .icon-btn {
    color: var(--c-text-dim);
    font-size: 18px;
    padding: 6px 10px;
    border-radius: 8px;
  }
  .icon-btn:hover {
    background: var(--c-surface);
  }
  .desc {
    font-size: 14px;
    color: var(--c-text-dim);
    line-height: 1.6;
  }
  .role-chip {
    display: inline-block;
    margin-left: 6px;
    padding: 1px 8px;
    border-radius: 6px;
    background: color-mix(in srgb, var(--c-accent) 18%, transparent);
    color: var(--c-accent);
    font-size: 12px;
    font-weight: 700;
  }
  .err {
    color: var(--c-danger);
    font-size: 13px;
  }
  .empty {
    text-align: center;
    color: var(--c-text-dim);
    padding: 40px 0;
    font-size: 14px;
  }
  .hint {
    margin-top: 8px;
    font-size: 13px;
  }
  /* One card per row on every width — cards share the panel's full horizontal
     span so single-service cards line up with grouped node cards. */
  .grid {
    display: grid;
    grid-template-columns: 1fr;
    gap: 10px;
  }
  .section-divider {
    grid-column: 1 / -1;
    font-size: 11px;
    font-weight: 700;
    color: var(--c-text-dim);
    text-transform: uppercase;
    letter-spacing: 0.8px;
    padding: 4px 0;
  }
  .card {
    background: var(--c-surface);
    border: 1px solid var(--c-border);
    border-radius: 12px;
    padding: 14px 16px;
    display: flex;
    flex-direction: column;
    gap: 8px;
    min-width: 0;
    overflow: hidden;
  }
  .card.denied {
    opacity: 0.55;
  }
  /* Own node — accent left border (H.2.1.1 ▌ visual marker) */
  .card.owned {
    border-left: 3px solid var(--c-accent);
    padding-left: 14px;
  }
  .card-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
  }
  .label {
    font-weight: 700;
    font-size: 15px;
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: 8px;
    min-width: 0;
  }
  .label .tag {
    white-space: normal;
    word-break: break-word;
  }
  .owned-badge {
    font-size: 11px;
    font-weight: 500;
    color: color-mix(in srgb, var(--c-accent) 80%, var(--c-text-dim));
    background: color-mix(in srgb, var(--c-accent) 10%, transparent);
    border: 1px solid color-mix(in srgb, var(--c-accent) 22%, transparent);
    border-radius: 99px;
    padding: 1px 7px;
    white-space: nowrap;
  }
  .reach {
    font-size: 11px;
    font-weight: 500;
    border-radius: 99px;
    padding: 1px 7px;
    white-space: nowrap;
    cursor: help;
  }
  .reach.online {
    color: #34c759;
    background: color-mix(in srgb, #34c759 12%, transparent);
    border: 1px solid color-mix(in srgb, #34c759 26%, transparent);
  }
  .reach.stale {
    color: var(--c-text-dim);
    background: color-mix(in srgb, var(--c-text-dim) 10%, transparent);
    border: 1px solid color-mix(in srgb, var(--c-text-dim) 22%, transparent);
  }
  /* Reachability shown as just a leading dot (green = reachable, gray = not), placed
     before the node name — the "reachable"/"unreachable" text was redundant with it. */
  .reach-dot {
    font-size: 10px;
    margin-right: 6px;
    cursor: help;
    vertical-align: middle;
    color: var(--c-text-dim); /* default gray (unreachable / not yet probed) */
  }
  .reach-dot.online { color: #34c759; } /* green only when reachable now */
  .fqdn {
    font-family: "SF Mono", "Fira Code", monospace;
    font-size: 12px;
    color: var(--c-text-dim);
    word-break: break-all;
  }
  .tags {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
  }
  .meta {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
    font-size: 12px;
    color: var(--c-text-dim);
  }
  .denied-text {
    font-style: italic;
  }
  .chain-btn {
    font-size: 12px;
    padding: 5px 10px;
  }
  /* All card actions on one wrapping row at the card's foot (flat + node cards). */
  .card-actions {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 6px;
    margin-top: 2px;
  }
  /* Mesh-terminal button — accent-tinted secondary. Same geometry as the
     btn-primary "Open" next to it (base padding/font/radius come from
     .btn-secondary); only the coloring differs. Keep in sync with
     .ssh-btn in settings/devices (same affordance, same look). */
  .ssh-btn {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    color: var(--c-accent);
    border-color: color-mix(in srgb, var(--c-accent) 35%, var(--c-border));
  }
  .ssh-btn:hover:not(:disabled) {
    background: color-mix(in srgb, var(--c-accent) 12%, transparent);
  }
  .ssh-btn:disabled {
    opacity: 0.4;
    cursor: not-allowed;
  }
  .ci-chip {
    display: inline-flex;
    align-items: center;
    gap: 5px;
  }

  /* CI history modal — same overlay pattern as PathChain. */
  .ci-overlay {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.6);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 200;
    padding: 16px;
  }
  .ci-panel {
    background: var(--c-surface);
    border: 1px solid var(--c-border);
    border-radius: var(--radius);
    padding: 20px;
    width: 100%;
    max-width: 480px;
    max-height: 80vh;
    overflow-y: auto;
    display: flex;
    flex-direction: column;
    gap: 14px;
  }
  .ci-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
  }
  .ci-title {
    font-size: 15px;
    font-weight: 700;
    color: var(--c-accent);
  }
  .ci-close {
    color: var(--c-text-dim);
    font-size: 16px;
    padding: 4px 8px;
  }
  .ci-rules {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }
  .ci-rule {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
    font-size: 13px;
  }
  .ci-repo {
    font-family: "SF Mono", "Fira Code", monospace;
    font-size: 12px;
    word-break: break-all;
  }
  .ci-scope {
    color: var(--c-text-dim);
    font-size: 12px;
  }
  .ci-runs {
    display: flex;
    flex-direction: column;
    gap: 8px;
    padding: 10px;
    background: var(--c-bg);
    border-radius: 8px;
  }
  .ci-run {
    display: flex;
    align-items: flex-start;
    gap: 10px;
    width: 100%;
    text-align: left;
    background: none;
    border: none;
    padding: 4px 0;
    cursor: pointer;
    color: inherit;
  }
  .ci-run-chevron {
    align-self: center;
    color: var(--c-text-dim);
    font-size: 14px;
    transition: transform 0.15s;
    flex-shrink: 0;
  }
  .ci-run-chevron.open { transform: rotate(180deg); }
  .ci-run-detail {
    margin: 2px 0 8px 30px;
    padding: 8px 10px;
    background: color-mix(in srgb, var(--c-text-dim) 8%, transparent);
    border-radius: 8px;
    font-size: 11px;
    color: var(--c-text-dim);
    line-height: 1.6;
    word-break: break-word;
  }
  .ci-run-block {
    font-family: 'SF Mono', 'Fira Code', monospace;
    word-break: break-all;
  }
  .ci-run-detail .dk {
    display: inline-block;
    min-width: 62px;
    color: color-mix(in srgb, var(--c-text-dim) 70%, transparent);
  }
  .ci-run-outcome {
    color: var(--c-danger);
    font-weight: 700;
  }
  .ci-run-outcome.allow {
    color: var(--sec-allow);
  }
  .ci-run-main {
    display: flex;
    flex-direction: column;
    gap: 2px;
    min-width: 0;
  }
  .ci-run-repo {
    font-size: 13px;
    font-weight: 600;
    word-break: break-all;
  }
  .ci-run-meta {
    font-size: 11px;
    color: var(--c-text-dim);
    font-family: "SF Mono", "Fira Code", monospace;
    word-break: break-all;
  }
  .ci-run-ledger {
    margin-left: auto;
    flex-shrink: 0;
    align-self: center;
    font-size: 10px;
    font-family: "SF Mono", "Fira Code", monospace;
    color: var(--sec-allow);
    background: color-mix(in srgb, var(--sec-allow) 12%, transparent);
    border-radius: 5px;
    padding: 3px 7px;
    white-space: nowrap;
    cursor: default;
  }
  .ci-note {
    font-size: 12px;
    color: var(--c-text-dim);
    line-height: 1.5;
  }
  .ci-note.err {
    color: var(--c-danger);
  }
  :global(.btn-primary:disabled),
  :global(.btn-secondary:disabled) {
    opacity: 0.4;
    cursor: not-allowed;
  }

  /* Node card (H.2.1.2): a node with >1 reachable service renders as one card
     with a child list instead of one flat card per service. */
  .child-list {
    display: flex;
    flex-direction: column;
    gap: 8px;
    padding-top: 8px;
    border-top: 1px solid var(--c-border);
  }
  .child-row {
    display: flex;
    flex-direction: column;
    align-items: stretch;
    gap: 8px;
    padding: 8px 10px;
    background: color-mix(in srgb, var(--c-accent) 4%, var(--c-bg));
    border: 1px solid var(--c-border);
    border-radius: 8px;
  }
  .child-row.denied {
    opacity: 0.55;
  }
  .child-info {
    display: flex;
    flex-direction: column;
    gap: 4px;
    min-width: 0;
  }
  .child-label {
    font-size: 13px;
    font-weight: 600;
    display: flex;
    align-items: center;
    gap: 6px;
    flex-wrap: wrap;
  }
  .child-actions {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
    justify-content: flex-end;
  }
  :global(.btn-primary.sm),
  :global(.btn-secondary.sm) {
    padding: 4px 8px;
    font-size: 12px;
  }
</style>
