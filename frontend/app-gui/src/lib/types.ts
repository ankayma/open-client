// Domain types — mirror domain-core entities (Part B §B.1)

export type ProductLine = "Personal" | "Enterprise";

// Canonical tier strings as the control plane emits them (hyphenated). The client
// speaks the CP's language — do NOT re-spell these camelCase, or every `tier === …`
// comparison silently misses and tier-gated UI (seat caps, upgrade CTA) never fires.
// [T:tier-feature-set canonical "F0" | "F0-Plus" | "F1-Starter"]
export type Tier = "F0" | "F0-Plus" | "F1-Starter";

// Commercial SeatType — the QUOTA dimension (per-member), orthogonal to `role`
// (capability). Part B §B.1.8 SeatType, choice A.
export type SeatType = "admin" | "builder" | "user" | "lite";

export interface User {
  tenant_id: string;
  email: string;
  tier: Tier;
  product_line: ProductLine;
  role: string; // capability: "admin" | "member"
  seat_type: SeatType; // quota class
  seat_node_cap: number; // per-member node cap for this seat_type
  seat_privdomain_cap: number;
}

export type AuthState =
  | { status: "unauthenticated" }
  | { status: "authenticating" }
  | { status: "authenticated"; user: User }
  | { status: "cancelled" };

export type ConnectionState =
  | { status: "disconnected" }
  | { status: "connecting" }
  | {
      status: "connected";
      node_id: string;
      endpoint: string;
      // TODO[A]: no Tauri command returns these yet — UI hides the row until
      // get_connection_status (or a new command) starts populating them.
      cert_expires_days?: number;
      aal?: string;
    }
  // Enrolled but the daemon stopped writing its status snapshot — the tunnel is
  // NOT carrying traffic. Rendered as an explicit fault state, never as
  // "connected" (desktop only; mobile reports through vpn_status).
  | { status: "dataplane_down"; node_id: string; endpoint: string };

export interface Quota {
  bandwidth_bytes_used: number;
  bandwidth_bytes_limit: number;
  nodes_used: number;
  nodes_limit: number;
}

export interface NodeInfo {
  node_id: string;
  hostname: string;
  public_key: string;
}

// [F-5 "Prove it"] Data-path proof — mirrors PathProof in gui/src-tauri/src/lib.rs.
export interface PathPeer {
  hostname: string;
  overlay_ip: string;
  /** True = direct WireGuard (no vendor relay). False = relayed (A.1.12 / P.3). */
  direct: boolean;
  endpoint: string | null;
  /** Seconds since last WireGuard handshake; null if no handshake yet. */
  last_handshake_secs: number | null;
  tx_bytes: number;
  rx_bytes: number;
}

export interface PathProof {
  connected: boolean;
  control_plane: string;
  /** True if any peer routes via vendor relay. Computed, not hardcoded (P.3). */
  vendor_on_data_path: boolean;
  peers: PathPeer[];
}

// [03b] CI/CD deploy policy (F0) — mirrors agent-core domain::CiPolicy wire shape.
export interface CiPolicy {
  repo: string;
  issuer: string;
  ref?: string;
  environment?: string;
  target_hostname?: string;
  created_at?: string;
}

// Form draft sent to add_ci_policy. Exactly one of ref / environment is set.
export interface CiPolicyDraft {
  issuer: string;
  repo: string;
  ref?: string;
  environment?: string;
  target_hostname?: string;
}

// Tenant node (from GET /api/v1/peers) for the deploy-target picker.
export interface PeerBrief {
  node_id: string;
  overlay_ip: string;
  hostname: string;
  /**
   * NOT a liveness signal. This is `expires_at IS NULL OR expires_at > NOW()`
   * from GET /api/v1/nodes -- it only says an ephemeral node's lease has not
   * lapsed. A persistent node has no expiry, so this is permanently `true`,
   * even for a device that died months ago.
   *
   * For "is this device reachable", use the WireGuard handshake age from
   * `getPathProof()`. The vendor is off the data path (A.1.1), so the control
   * plane cannot answer that question at all. `[T:P.3]`
   */
  active: boolean;
  owner_user_id?: string;
  /**
   * Last CONTROL-PLANE check-in (ISO-8601 UTC), stamped server-side on any
   * node-authenticated request — roughly once a minute for a live daemon.
   * Says "the daemon reached the control plane recently"; it is NOT mesh
   * reachability (A.1.1 — only the tunnel endpoints can measure that, via
   * `getPathProof()`). Word it "checked in", never "online". Absent/null:
   * older control plane, or the node never checked in since the migration.
   */
  last_seen_at?: string | null;
  /**
   * Part B `Tag` (part-b-domain.md:147) — e.g. `env:production`, `tier:1` — what
   * `policy::authz::Resource.tags` reads. Always an array, never absent, on a
   * control plane that has the column.
   */
  tags: string[];
}

// F-3 branded subdomain (Part C §H.3.6.1): a private name mapped onto a mesh node.
export interface Subdomain {
  fqdn: string;
  label: string;
  target_node_id: string;
  created_at?: string;
  // Auto-TLS (Slice 3): the local port on target_node_id the node's own TLS
  // relay forwards decrypted traffic to; issuance progress for that cert.
  target_port?: number;
  cert_status?: 'none' | 'pending' | 'issued' | 'failed';
  // Part B `Tag`, this service's own — not inherited from target_node_id's tags
  // (Node and Service are independently-taggable per part-b-domain.md:147).
  tags: string[];
}

// GET /api/v1/subdomain/{fqdn}/cert — polling fallback for ACME issuance state.
export interface SubdomainCert {
  fqdn: string;
  cert_status: 'none' | 'pending' | 'issued' | 'failed';
  cert_pem?: string;
  cert_expires_at?: string;
  cert_last_error?: string;
}

// F1 team membership (Slice C).
export interface Member {
  user_id: string;
  github_login: string;
  email?: string;
  role: string; // capability
  seat_type?: SeatType; // quota class
  seat_caps?: { nodes: number; privdomains: number };
  used?: { nodes: number; privdomains: number };
  created_at?: string;
  is_owner: boolean;
}
export interface MembersView {
  members: Member[];
  limit: number;
  your_role: string;
}

// An admission still in flight: invited, not yet redeemed. GET /api/v1/members/invites.
// No token / short code field — and none should ever be added: either would let whoever
// reads this list sign in AS the invitee. Re-send goes through the invite endpoint, which
// mails the link. [T:A.1.6]
export interface PendingInvite {
  email: string;
  role: string;
  seat_type?: SeatType;
  created_at?: string;
  expires_at?: string;
  last_sent_at?: string;
  send_count: number;
  expired: boolean;
}
export interface PendingInvitesView {
  invites: PendingInvite[];
}

// [F-1 viewer] One CI deploy run from GET /api/v1/ci/history — read-only
// projection of a CiDeployAccess ledger event (connection-level facts only).
export interface CiRun {
  run_id?: string;
  repo?: string;
  ref?: string;
  issuer?: string;
  environment?: string;
  outcome?: string;
  target_host?: string;
  block_hash?: string;
  at?: string;
}

// [F-2 viewer] One SSH session from GET /api/v1/ssh/history — signed
// SshSessionOpened receipt (connection-level only, no transcript).
export interface SshSession {
  session_id?: string;
  node_id?: string;
  target_host?: string;
  login?: string;
  block_hash?: string;
  at?: string;
}

// PolicyBlock authz (Slice B) + my-access catalog (Slice D).
export interface PolicyView {
  version: number;
  rules: unknown; // raw JSON array of { from, to } rules
  block_hash?: string;
  chain_intact: boolean;
}
export interface AccessService {
  fqdn: string;
  label: string;
  node: string;
  rule_ref: string;
  // Auto-TLS state from my_access: "issued" → Open over HTTPS; otherwise HTTP
  // (TLS not ready). Present for every service incl. a teammate's shared one.
  cert_status?: string;
  // TODO[A]: my_access doesn't return these yet — UI hides them until the
  // command grows the field. tags/status mirror the mockup's pill/dot states.
  tags?: string[];
  status?: "online" | "offline" | "denied";
}
export interface MyAccess {
  principal: string;
  role: string;
  services: AccessService[];
}

// ── Governance surfaces ───────────────────────────────────────────────────────
// The register, the approval queue and the task dossier. Each mirrors what the control
// plane recorded; none of it is decided here.

/** One legal entity in the tenant's register, with its gaps named rather than blank. */
export interface RegisteredPrincipal {
	principal_id: string;
	/** `self` = the tenant's own entity · `third_party` = a supplier. */
	relationship: string;
	legal_name: string | null;
	lei: string | null;
	jurisdiction: string | null;
	criticality: string | null;
	/**
	 * What is still unstated. Shown, because a register that looks complete and is not is
	 * exactly what the regulatory export exists to avoid.
	 */
	missing_fields: string[];
}

/** A command waiting for a person. */
export interface PendingApproval {
	approval_id: string;
	template_id: string;
	/** The exact argv. A gate that shows a summary is a gate on the summary. */
	argv: string[];
	cmd_digest: string;
	risk_class: string;
	/** `gate` · `irreversible` · `freeform` — three different questions to be asked. */
	gate_reason: string;
	justification: string | null;
	node_id: string;
	actor_id: string;
	requested_by: string;
	requested_at: string;
	expires_at: string;
}

/** `delegate_agent`'s result — a fresh non-human identity plus the bounded window
 *  handed to it. `enroll_token` is single-use and shown once, in the copyable
 *  command; the popup never persists it. */
export interface DelegateAgentResult {
	agent_name: string;
	enroll_token: string;
	redeem_within_seconds: number;
	window_id: string;
	window_expires_at: number;
}

/** One row of the "Delegate ↗" popup's mini-history. */
export interface RecentDelegation {
	window_id: string;
	agent_actor_id: string;
	opened_by: string;
	opened_at: number;
	expires_at: number;
	closed: boolean;
}

/** `decide_approval`'s result — the credential itself, if approved. Shown once: this
 *  response is the only place `grant_token` ever appears. */
export interface ApprovalDecision {
	approval_id: string;
	decision: string;
	grant_id: string | null;
	grant_token: string | null;
	cmd_digest: string | null;
	expires_at: number | null;
	credential_issued: boolean;
}

// ── Tenant Overview (admin dashboard) — the report the CP composes ─────────────
// Timestamps arrive as ISO-8601 strings (the CP casts ::text), unlike the numeric
// epochs elsewhere in this file — the overview is a display report, not a domain entity.

export interface OverviewSeatCount {
	seat_type: string;
	count: number;
}

export interface OverviewActivity {
	id: number;
	event_type: string;
	payload: unknown;
	created_at: string;
	grant_id: string;
}

export interface OverviewGrant {
	grant_id: string;
	kind: string; // "session" | "command"
	actor_id: string;
	node_id: string;
	on_behalf_of: string;
	issued_at: string;
	expires_at: string;
}

export interface OverviewDelegation {
	window_id: string;
	agent_actor_id: string;
	opened_by: string;
	opened_at: string;
	expires_at: string;
}

export interface OverviewStaleNode {
	node_id: string;
	hostname: string;
	last_seen_at: string;
}

export interface OverviewDeny {
	event_type: string;
	created_at: string;
}

export interface Overview {
	fleet: {
		// last_seen is CP check-in recency, NOT a reachability claim (same caveat as NodeInfo).
		nodes_total: number;
		nodes_seen_5m: number;
		members_total: number;
		members_by_seat: OverviewSeatCount[];
		services_total: number;
	};
	activity: OverviewActivity[];
	grants: OverviewGrant[];
	delegations: OverviewDelegation[];
	alerts: {
		stale_nodes: OverviewStaleNode[];
		pending_approvals: number;
		recent_denies: OverviewDeny[];
	};
}
