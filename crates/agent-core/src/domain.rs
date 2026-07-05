//! domain — entity types, policy, events (Part A §A.3.1).

use serde::{Deserialize, Serialize};

/// Enrollment request to the control-plane Agent API.
/// Mirrors the control-plane `EnrollReq` wire shape. `[T:B.5.1]`
#[derive(Debug, Clone, Serialize)]
pub struct EnrollRequest {
    /// This node's WireGuard public key (base64).
    pub public_key: String,
    /// Human-readable device name.
    pub hostname: String,
    /// Optional reachable "ip:port" the agent advertises to peers.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// [T:Part B §B.1.4] Canonical workload kind (e.g. "AppServer", "ClientDevice").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workload_kind: Option<String>,
}

/// Control-plane response to a successful enrollment. `[T:B.5.1]`
#[derive(Debug, Clone, Deserialize)]
pub struct EnrollResponse {
    pub node_id: String,
    /// Assigned overlay IP from the 100.64.0.0/10 CGNAT pool (RFC 6598).
    pub overlay_ip: String,
    pub allowed_ips: Vec<String>,
    pub peers: Vec<PeerInfo>,
    /// [T:Part D §D.11] Scoped bearer token for GET /api/v1/peers/events.
    /// TTL 90d; absent if control-plane pre-dates migration 015.
    #[serde(default)]
    pub node_service_token: Option<String>,
    /// RFC3339 expiry of the service token.
    #[serde(default)]
    pub token_expires_at: Option<String>,
    /// [T:part-d-layer2-cert-infrastructure.md §H.2] Layer 2 node identity:
    /// leaf cert signed by the TenantCA, used for mTLS to the broker (B.5.1).
    /// Absent from CPs that pre-date Layer 2 — `None`, no break (P.4 compose).
    #[serde(default)]
    pub node_cert_pem: Option<String>,
    /// Provisioning CA chain to verify broker TLS (TH-A dynamic trust — the
    /// binary pins no CA; trust arrives at enrollment). [T:A.1.18 per-PL chain]
    #[serde(default)]
    pub provisioning_ca_pem: Option<String>,
    /// URL to fetch the CRL from the CP (revocation = CRL broadcast, B.4.2).
    #[serde(default)]
    pub crl_url: Option<String>,
}

/// A node entry from the management endpoint `GET /api/v1/nodes`. [T:B.5.2]
/// Includes server-side `active` status; used for the admin/member device list UI.
/// Role-filtered server-side: admin sees all tenant nodes, member sees only own.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeBrief {
    pub node_id: String,
    pub hostname: String,
    pub overlay_ip: String,
    pub active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_user_id: Option<String>,
}

/// A peer in the mesh as returned by the control-plane. `[T:B.5.1]`
/// `[T:A.1.1]` metadata only — no business payload crosses the control plane.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerInfo {
    pub node_id: String,
    pub public_key: String,
    pub overlay_ip: String,
    pub hostname: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
}

/// Authenticated session info from `GET /api/v1/session`. `[T:B.5.2]`
#[derive(Debug, Clone, Deserialize)]
pub struct SessionInfo {
    pub tenant_id: String,
    pub email: String,
    pub login: String,
    pub tier: String,
}

/// Usage quota from `GET /api/v1/quota`. `[T:B.5.2]`
#[derive(Debug, Clone, Deserialize)]
pub struct Quota {
    pub bandwidth_bytes_used: u64,
    pub bandwidth_bytes_limit: u64,
    pub nodes_used: u32,
    pub nodes_limit: u32,
    pub tier: String,
}

/// Secretless CI deploy request. `POST /api/v1/ci/deploy`. `[T:Part C §H.3.3]`
/// The OIDC `token` IS the credential — there is no session token and no static
/// secret. The control plane verifies it (closed IP); the agent only sends it.
#[derive(Debug, Clone, Serialize)]
pub struct CiDeployRequest {
    /// CI OIDC JWT (GitHub Actions / GitLab CI), minted for audience `ankayma-deploy`.
    pub token: String,
    /// Ephemeral WireGuard public key (base64) generated for this deploy run.
    pub public_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
}

/// Control-plane response to a verified CI deploy. Mirrors `CiDeployResp`.
/// `[T:Part C §H.3.3]`
#[derive(Debug, Clone, Deserialize)]
pub struct CiDeployResponse {
    pub node_id: String,
    pub overlay_ip: String,
    pub allowed_ips: Vec<String>,
    /// TTL of the ephemeral enrollment — the runner must finish within this window.
    pub expires_in_seconds: u32,
    /// The deploy target peer (if the registered policy named one).
    #[serde(default)]
    pub target: Option<PeerInfo>,
    /// Signed run-receipt — the F-1 wow artifact (proof, not connectivity).
    /// `Option` for forward-compat with an older control plane. `[T:Part C §H.3.3]`
    #[serde(default)]
    pub receipt: Option<DeployReceipt>,
}

/// Tamper-evident proof of a secretless deploy run, anchored into the control
/// plane's append-only audit hash-chain (`ledger_block_hash`, A.1.8) and
/// re-verifiable via `GET /api/v1/ci/receipt/{run_id}`. `[T:Part C §H.3.3]`
///
/// `customer_signed:false` at F0 (tamper-evident only); customer-key signing is
/// Part C `[A-p]`. The agent only displays this — it never decides ALLOW/DENY.
#[derive(Debug, Clone, Deserialize)]
pub struct DeployReceipt {
    pub run_id: String,
    pub repo: String,
    #[serde(rename = "ref")]
    pub git_ref: String,
    pub issuer: String,
    #[serde(default)]
    pub environment: Option<String>,
    #[serde(default)]
    pub target: Option<String>,
    pub scope: String,
    pub static_secret: bool,
    pub customer_signed: bool,
    pub anchor: String,
    pub ledger_event: String,
    pub ledger_block_hash: String,
}

/// F-4 redeem: an agent presents its single-use mint token (the token IS the
/// credential — no session, no static secret) for short-TTL ephemeral access.
/// `[T:Part C §H.3.3]`
#[derive(Debug, Clone, Serialize)]
pub struct AgentEnrollRequest {
    /// Single-use identity token minted by `POST /api/v1/agents/token`.
    pub token: String,
    /// Ephemeral WireGuard public key (base64) generated for this grant.
    pub public_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
}

/// Control-plane response to an agent identity redemption. Mirrors `AgentEnrollResp`.
#[derive(Debug, Clone, Deserialize)]
pub struct AgentEnrollResponse {
    pub node_id: String,
    pub overlay_ip: String,
    pub allowed_ips: Vec<String>,
    pub expires_in_seconds: u32,
    pub receipt: AgentReceipt,
}

/// Proof a non-human actor was admitted — first-class in the ledger, scoped,
/// time-limited, zero secret residue. Re-verifiable via
/// `GET /api/v1/agents/receipt/{run_id}`. `[T:Part C §H.3.3]`
#[derive(Debug, Clone, Deserialize)]
pub struct AgentReceipt {
    pub run_id: String,
    pub agent_name: String,
    pub actor_kind: String,
    pub scope: String,
    pub ttl_seconds: i64,
    pub secret_residue: String,
    pub anchor: String,
    pub ledger_event: String,
    pub ledger_block_hash: String,
}

/// `POST /api/v1/ssh/session` request: open an identity-bound SSH session to one
/// of the tenant's OWN mesh nodes. `[T:Part C §H.3.6.1 F-2]`
#[derive(Debug, Clone, Serialize)]
pub struct SshSessionRequest {
    pub node_id: String,
    /// Optional OS login; omitted → the local user. Server sanitizes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub login: Option<String>,
}

/// `POST /api/v1/ssh/session` response: the resolved overlay target + honest
/// receipt of the ledger-anchored session. The CP never sees the SSH stream
/// (A.1.1) — it only resolves the target and records that a session opened.
#[derive(Debug, Clone, Deserialize)]
pub struct SshSessionResponse {
    pub overlay_ip: String,
    #[serde(default)]
    pub login: Option<String>,
    #[serde(default)]
    pub receipt: Option<SshSessionReceipt>,
    /// Port of the target's embedded SSH server (F-2 transport v0.5). Absent on an
    /// older control plane → the caller falls back to the default 22022.
    #[serde(default)]
    pub ssh_port: Option<u16>,
    /// The target's SSH host key (OpenSSH one-line), bound to node identity so the
    /// client can PIN it — no blind TOFU (A.1.3). Absent on an older CP.
    #[serde(default)]
    pub server_host_key: Option<String>,
}

/// `POST /api/v1/ssh/elevate` request: ask the control plane for a root-elevation
/// grant on one of the tenant's nodes (§H.4). `[T:f2 §H.4]`
#[derive(Debug, Clone, Serialize)]
pub struct SshElevateRequest {
    pub node_id: String,
    /// Persona to elevate to — "root" at F0 (owner-implicit).
    pub persona: String,
    /// Requested lifetime in seconds; CP caps it at the TTL ceiling (≤900).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_secs: Option<i64>,
    /// AAL step-up proof for F1+ tiers (E-7). F0 owner needs none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_token: Option<String>,
}

/// `POST /api/v1/ssh/elevate` response: the signed grant token the client presents
/// to the node's embedded server, plus when it expires. `[T:f2 §H.4]`
#[derive(Debug, Clone, Deserialize)]
pub struct SshElevateResponse {
    pub grant: String,
    pub expires_at: i64,
}

/// Honest receipt of an opened SSH session (mirrors the control-plane shape, P.3).
/// `[T:Part C §H.3.6.1 F-2 + A.1.3 + A.1.8]`
#[derive(Debug, Clone, Deserialize)]
pub struct SshSessionReceipt {
    pub session_id: String,
    pub node_id: String,
    pub target: String,
    #[serde(default)]
    pub login: Option<String>,
    pub identity_bound: bool,
    pub bastion: bool,
    pub static_key: bool,
    pub session_recorded: bool,
    pub anchor: String,
    pub ledger_event: String,
    pub ledger_block_hash: String,
}

/// One private branded name and the overlay address it resolves to. `[T:F-3]`
/// `target_node_id`/`target_port` ride along so the owning node can recognize
/// its own entries and relay-terminate TLS locally (Slice 3) — no separate
/// lookup needed. `[T:F-3 auto-TLS]`
#[derive(Debug, Clone, Deserialize)]
pub struct ResolvedName {
    pub fqdn: String,
    pub label: String,
    pub overlay_ip: String,
    pub target_node_id: String,
    pub target_port: u16,
}

/// `GET /api/v1/mesh/resolve` — the tenant's private-default resolve table, served
/// only to an enrolled device (a non-enrolled caller gets 401 ≡ NXDOMAIN). The
/// agent resolves these names locally; the data path is direct over the overlay.
#[derive(Debug, Clone, Deserialize)]
pub struct ResolveTable {
    pub zone: String,
    pub names: Vec<ResolvedName>,
}

/// A registered F-3 branded subdomain as returned by `GET /api/v1/subdomain`.
/// Tenant-scoped. `[T:Part C §H.3.6.1 F-3]`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subdomain {
    pub fqdn: String,
    pub label: String,
    pub target_node_id: String,
    #[serde(default)]
    pub created_at: Option<String>,
    /// The local port on `target_node_id` the node's own TLS relay (Slice 3)
    /// forwards decrypted traffic to after handshake. `[T:F-3 auto-TLS]`
    #[serde(default)]
    pub target_port: Option<u16>,
    /// `none|pending|issued|failed` — ACME issuance progress. `[T:F-3 auto-TLS]`
    #[serde(default)]
    pub cert_status: Option<String>,
}

/// Create request for a branded subdomain. `POST /api/v1/subdomain` — map `label`
/// onto one of the tenant's own nodes. The control plane validates + enforces the
/// ND-R6 cap. `[T:Part C §H.3.6.1 F-3]`
#[derive(Debug, Clone, Serialize)]
pub struct SubdomainReq {
    pub label: String,
    pub target_node_id: String,
    pub target_port: u16,
}

/// This node's own CSR for its branded subdomain — the private key never
/// leaves the node; only the CSR (public) travels. `POST
/// /api/v1/subdomain/{fqdn}/csr`, node-service-token authed. `[T:A.1.1 + F-3 auto-TLS]`
#[derive(Debug, Clone, Serialize)]
pub struct SubdomainCsrReq {
    pub csr_pem: String,
}

/// ACME issuance state for one subdomain. `GET /api/v1/subdomain/{fqdn}/cert` —
/// the polling fallback to the `cert_issued` SSE push (belt-and-suspenders,
/// same lesson as the resolver's stale-table bug). `[T:F-3 auto-TLS]`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubdomainCert {
    pub fqdn: String,
    pub cert_status: String,
    pub cert_pem: Option<String>,
    pub cert_expires_at: Option<String>,
    pub cert_last_error: Option<String>,
}

// ── F1 team membership (Slice C) ──────────────────────────────────────────────

/// A member of the active tenant. `GET /api/v1/members`. `[T:Part C §H.3.4]`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Member {
    pub user_id: String,
    pub github_login: String,
    pub role: String,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub is_owner: bool,
}

/// `GET /api/v1/members` envelope: roster + cap + the caller's own role.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MembersView {
    pub members: Vec<Member>,
    pub limit: u32,
    pub your_role: String,
}

// ── PolicyBlock authz (Slice B/D) ─────────────────────────────────────────────

/// The active PolicyBlock as `GET /api/v1/policies` returns it. `rules` is the raw
/// JSON array (the GUI renders/edits it). `[T:Part B §B.3.2]`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyView {
    pub version: i64,
    pub rules: serde_json::Value,
    #[serde(default)]
    pub block_hash: Option<String>,
    #[serde(default)]
    pub chain_intact: bool,
}

/// One granted service in the caller's catalog. `GET /api/v1/my-access`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessService {
    pub fqdn: String,
    pub label: String,
    pub node: String,
    pub rule_ref: String,
}

/// `GET /api/v1/my-access` envelope — what the caller may reach (addendum §D).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MyAccess {
    pub principal: String,
    pub role: String,
    pub services: Vec<AccessService>,
}

/// One CI deploy run as returned by `GET /api/v1/ci/history` — a read-only
/// projection of a `CiDeployAccess` ledger event. Connection-level facts only,
/// never command content (A.1.1); `run_id` re-verifies independently at
/// `GET /api/v1/ci/receipt/{run_id}`. All fields optional: the ledger payload
/// evolved across versions, honesty over fabrication. `[T:A.1.8]`
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CiRun {
    pub run_id: Option<String>,
    pub repo: Option<String>,
    #[serde(rename = "ref")]
    pub git_ref: Option<String>,
    pub issuer: Option<String>,
    pub environment: Option<String>,
    pub outcome: Option<String>,
    pub target_host: Option<String>,
    pub block_hash: Option<String>,
    pub at: Option<String>,
}

/// A CI/CD deploy policy rule as returned by `GET /api/v1/ci/policy`. Tenant-scoped.
/// `[T:Part C §H.3.3 / B.5.2]` `ref` and `environment` are the safe-by-default scope:
/// exactly one is set (server enforces; client mirrors in UX). `target_hostname` is
/// optional (the node a deploy may reach).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CiPolicy {
    pub repo: String,
    pub issuer: String,
    #[serde(rename = "ref", default, skip_serializing_if = "Option::is_none")]
    pub git_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_hostname: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
}

/// Create/update request for a CI/CD deploy policy. `POST /api/v1/ci/policy`
/// (upsert by `repo`). Safe-by-default is server-enforced; the client sends only
/// the fields the user set. `[T:Part C §H.3.3]`
#[derive(Debug, Clone, Serialize)]
pub struct CiPolicyReq {
    pub issuer: String,
    pub repo: String,
    #[serde(rename = "ref", skip_serializing_if = "Option::is_none")]
    pub git_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_hostname: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enroll_request_serializes_expected_keys() {
        let req = EnrollRequest {
            public_key: "PUBKEY".into(),
            hostname: "laptop".into(),
            endpoint: None,
            workload_kind: None,
        };
        let v: serde_json::Value = serde_json::to_value(&req).unwrap();
        assert_eq!(v["public_key"], "PUBKEY");
        assert_eq!(v["hostname"], "laptop");
        // endpoint omitted when None (matches control-plane #[serde(default)]).
        assert!(v.get("endpoint").is_none());
    }

    #[test]
    fn enroll_response_parses_control_plane_shape() {
        // Shape emitted by control-plane bin/control-plane (EnrollResp). [T:B.5.1]
        let json = r#"{
            "node_id": "n1",
            "overlay_ip": "100.64.0.2",
            "allowed_ips": ["100.64.0.2/32"],
            "peers": [
                {"node_id":"n2","public_key":"K2","overlay_ip":"100.64.0.3","hostname":"phone"}
            ]
        }"#;
        let resp: EnrollResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.overlay_ip, "100.64.0.2");
        assert_eq!(resp.peers.len(), 1);
        assert_eq!(resp.peers[0].hostname, "phone");
        assert_eq!(resp.peers[0].endpoint, None);
        // Pre-Layer-2 CP: cert fields absent → None, no decode break (P.4).
        assert_eq!(resp.node_cert_pem, None);
        assert_eq!(resp.provisioning_ca_pem, None);
        assert_eq!(resp.crl_url, None);
    }

    #[test]
    fn enroll_response_parses_layer2_cert_fields() {
        // Layer 2 CP additionally returns cert material + CRL location.
        // [T:part-d-layer2-cert-infrastructure.md §H.2 Step 1]
        let json = r#"{
            "node_id": "n1",
            "overlay_ip": "100.64.0.2",
            "allowed_ips": ["100.64.0.2/32"],
            "peers": [],
            "node_cert_pem": "-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----\n",
            "provisioning_ca_pem": "-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----\n",
            "crl_url": "https://cp.example/pki/crl.pem"
        }"#;
        let resp: EnrollResponse = serde_json::from_str(json).unwrap();
        assert!(resp.node_cert_pem.unwrap().contains("LEAF"));
        assert!(resp.provisioning_ca_pem.unwrap().contains("CA"));
        assert_eq!(
            resp.crl_url.as_deref(),
            Some("https://cp.example/pki/crl.pem")
        );
    }

    #[test]
    fn ci_deploy_response_parses_receipt_shape() {
        // Shape emitted by control-plane ci_deploy (CiDeployResp + DeployReceipt).
        // [T:Part C §H.3.3] `ref` is the JSON key; F0 = not customer-signed.
        let json = r#"{
            "node_id": "ci_abc",
            "overlay_ip": "fd00::2",
            "allowed_ips": ["fd00::/64"],
            "expires_in_seconds": 900,
            "receipt": {
                "run_id": "ci_abc",
                "repo": "acme/api",
                "ref": "refs/heads/main",
                "issuer": "github",
                "environment": "prod",
                "target": "prod-web",
                "scope": "deploy-only",
                "static_secret": false,
                "customer_signed": false,
                "anchor": "ledger-hash-chain",
                "ledger_event": "CiDeployAccess",
                "ledger_block_hash": "9f3c"
            }
        }"#;
        let resp: CiDeployResponse = serde_json::from_str(json).unwrap();
        let r = resp.receipt.expect("receipt present");
        assert_eq!(r.git_ref, "refs/heads/main"); // parsed from JSON key `ref`
        assert!(!r.customer_signed); // F0: tamper-evident only, not customer-signed
        assert_eq!(r.scope, "deploy-only");
        assert_eq!(r.ledger_block_hash, "9f3c");
    }

    #[test]
    fn ci_deploy_response_tolerates_missing_receipt() {
        // Forward/backward-compat: an older control plane omits `receipt`.
        let json = r#"{"node_id":"ci_x","overlay_ip":"fd00::2",
            "allowed_ips":[],"expires_in_seconds":900}"#;
        let resp: CiDeployResponse = serde_json::from_str(json).unwrap();
        assert!(resp.receipt.is_none());
    }

    #[test]
    fn agent_enroll_response_parses_receipt_shape() {
        // Shape emitted by control-plane agent_enroll (AgentEnrollResp + AgentReceipt).
        // [T:Part C §H.3.3 / F-4] first-class non-human actor, scoped, bounded.
        let json = r#"{
            "node_id": "ci_agent1",
            "overlay_ip": "fd00::3",
            "allowed_ips": ["fd00::/64"],
            "expires_in_seconds": 30,
            "receipt": {
                "run_id": "ci_agent1",
                "agent_name": "nightly-backup",
                "actor_kind": "non-human",
                "scope": "mesh:connect",
                "ttl_seconds": 30,
                "secret_residue": "none",
                "anchor": "ledger-hash-chain",
                "ledger_event": "AgentAccess",
                "ledger_block_hash": "9f3c"
            }
        }"#;
        let resp: AgentEnrollResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.receipt.actor_kind, "non-human");
        assert_eq!(resp.receipt.secret_residue, "none");
        assert_eq!(resp.receipt.ttl_seconds, 30);
        assert_eq!(resp.receipt.ledger_event, "AgentAccess");
    }

    #[test]
    fn ci_policy_parses_list_shape_and_req_serializes_ref() {
        // Shape emitted by control-plane GET /api/v1/ci/policy. `ref` is the JSON key.
        let json = r#"{
            "repo": "acme/api",
            "issuer": "github",
            "ref": "refs/heads/main",
            "target_hostname": "prod-web",
            "created_at": "2026-06-22T00:00:00Z"
        }"#;
        let p: CiPolicy = serde_json::from_str(json).unwrap();
        assert_eq!(p.git_ref.as_deref(), Some("refs/heads/main"));
        assert_eq!(p.environment, None);
        assert_eq!(p.target_hostname.as_deref(), Some("prod-web"));

        // Request serializes `git_ref` back to the `ref` key; None fields omitted.
        let req = CiPolicyReq {
            issuer: "gitlab".into(),
            repo: "grp/proj".into(),
            git_ref: None,
            environment: Some("prod".into()),
            target_hostname: None,
        };
        let v: serde_json::Value = serde_json::to_value(&req).unwrap();
        assert_eq!(v["environment"], "prod");
        assert!(v.get("ref").is_none());
        assert!(v.get("target_hostname").is_none());
    }
}
