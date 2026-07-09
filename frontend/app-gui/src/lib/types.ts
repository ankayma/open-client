// Domain types — mirror domain-core entities (Part B §B.1)

export type ProductLine = "Personal" | "Enterprise";

export type Tier = "F0" | "F0Plus" | "F1Starter";

export interface User {
  tenant_id: string;
  email: string;
  tier: Tier;
  product_line: ProductLine;
}

export type AuthState =
  | { status: "unauthenticated" }
  | { status: "authenticating" }
  | { status: "authenticated"; user: User };

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
    };

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
  /** Server-side active status from GET /api/v1/nodes (expires_at check). */
  active: boolean;
  owner_user_id?: string;
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
  role: string;
  created_at?: string;
  is_owner: boolean;
}
export interface MembersView {
  members: Member[];
  limit: number;
  your_role: string;
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
