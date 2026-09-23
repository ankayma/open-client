//! adapters — concrete port impls (control-plane HTTP, WireGuard, NATS, OIDC).

use crate::domain::{
    AgentEnrollRequest, AgentEnrollResponse, CiDeployRequest, CiDeployResponse, CiPolicy,
    CiPolicyReq, CiRun, EnrollRequest, EnrollResponse, MembersView, MyAccess, NodeBrief, PeerInfo,
    PendingInvitesView, PolicyView, Quota, ResolveTable, SessionInfo, SshSession,
    SshSessionRequest, SshSessionResponse, Subdomain, SubdomainCert, SubdomainCsrReq, SubdomainReq,
};

/// The D.11 scoped NODE service token (opaque `nst_…`). Authenticates node-scoped
/// control-plane routes (relay map, peer-events SSE, token renewal, CSR submit) which the
/// control plane serves ONLY to a node — they reject the user session token. A distinct
/// type from the session token so the compiler rejects passing one where the other is
/// required, closing the recurring session/node mixup at compile time rather than at a
/// runtime 401. `[T:part-d-token-identity-model.md §2.1]`
#[derive(Clone, Debug)]
pub struct NodeServiceToken(pub String);

impl NodeServiceToken {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Hard upper bound for one REST round-trip to the control plane (headers +
/// body). This is what keeps a long-running daemon's refresh loop alive: with no
/// bound, one half-open TCP connection on a plain GET freezes the loop FOREVER —
/// a production node froze for 21h on exactly this (field incident 2026-07-04:
/// status file written once at startup, SSE never subscribed, roster never
/// resynced). Streaming endpoints (SSE) are exempt — see `subscribe_peer_events`.
///
/// 300ms under cfg(test) so the timeout path is exercisable in a unit test
/// without a 30s wait; release builds always get 30s.
pub const CP_REST_TIMEOUT: std::time::Duration = if cfg!(test) {
    std::time::Duration::from_millis(300)
} else {
    std::time::Duration::from_secs(30)
};

/// Errors from the control-plane HTTP client.
#[derive(Debug)]
pub enum ApiError {
    /// Network/transport failure.
    Transport(String),
    /// Server returned a non-2xx status with no usable message body.
    Status(u16),
    /// Server returned a non-2xx status with an `error` message — surfaced verbatim
    /// so the GUI/CLI shows the control plane's reason (e.g. safe-by-default 400/409).
    Server { status: u16, message: String },
    /// Response body could not be decoded.
    Decode(String),
    /// Server demands a step-up proof before this management action — a
    /// multi-user tenant minting an invite, revoking a node, or an admin
    /// inviting/offboarding a member. The GUI catches this to drive the step-up
    /// flow (`verify_step_up` for a solved OTP/TOTP → `proof_token`), then
    /// retries with the proof. `required_aal` says how strong the proof must be
    /// (2 = email-OTP/TOTP, 3 = WebAuthn/YubiKey — A.1.10 no-soft-fallback).
    /// [T:Part D §H.5]
    StepUpRequired { purpose: String, required_aal: i32 },
    /// The control plane refuses an EMAIL-OTP step-up because the account holds a
    /// stronger factor (Touch ID / security key / confirmed TOTP) — 409 with
    /// `strong_factor_required`. A distinct variant because it is a permanent
    /// answer, not a hiccup: the GUI must not hand the user a code box that no
    /// code can ever fill, the way it did when this arrived as a generic server
    /// error. Recovery purposes keep the email path and never produce this.
    /// [T:control-plane stepup.rs strong_factor_required() — 409 + the flag]
    StrongFactorRequired { message: String },
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApiError::Transport(e) => write!(f, "control-plane transport error: {e}"),
            ApiError::Status(s) => write!(f, "control-plane returned HTTP {s}"),
            ApiError::Server { message, .. } => write!(f, "{message}"),
            ApiError::Decode(e) => write!(f, "control-plane decode error: {e}"),
            // Sentinel the GUI matches on to launch the step-up flow.
            ApiError::StepUpRequired {
                purpose,
                required_aal,
            } => write!(f, "STEP_UP_REQUIRED:{purpose}:{required_aal}"),
            // Sentinel + the server's own sentence, so the GUI can both branch on
            // it and show the reason verbatim.
            ApiError::StrongFactorRequired { message } => {
                write!(f, "STRONG_FACTOR_REQUIRED:{message}")
            }
        }
    }
}
impl std::error::Error for ApiError {}

fn url(base_url: &str, path: &str) -> String {
    format!("{}{}", base_url.trim_end_matches('/'), path)
}

/// GET an authenticated JSON endpoint and decode it. `[T:A.1.1]` the control
/// plane returns metadata only — no business payload.
async fn get_json<T: serde::de::DeserializeOwned>(
    http: &reqwest::Client,
    base_url: &str,
    path: &str,
    session_token: &str,
) -> Result<T, ApiError> {
    let resp = http
        .get(url(base_url, path))
        .bearer_auth(session_token)
        .timeout(CP_REST_TIMEOUT)
        .send()
        .await
        .map_err(|e| ApiError::Transport(e.to_string()))?;
    let status = resp.status();
    if !status.is_success() {
        return Err(ApiError::Status(status.as_u16()));
    }
    resp.json::<T>()
        .await
        .map_err(|e| ApiError::Decode(e.to_string()))
}

/// Redeem a signed cross-region sign-in hand-off for a real session token at the
/// target region's control plane. `POST /api/v1/session/redeem-handoff`.
///
/// A user authenticates once at the auth gateway; when their region differs from the
/// gateway's, the gateway can't mint a session in the right region's store (per-region
/// isolation, no shared DB `[T:A.1.23]`), so it returns a signed hand-off instead. The
/// client presents it HERE, to the region's own CP, which verifies the signature and
/// mints the session locally. No bearer — the signed hand-off IS the credential.
pub async fn redeem_handoff(
    http: &reqwest::Client,
    base_url: &str,
    handoff: &str,
) -> Result<String, ApiError> {
    #[derive(serde::Serialize)]
    struct Req<'a> {
        handoff: &'a str,
    }
    #[derive(serde::Deserialize)]
    struct Resp {
        token: String,
    }
    let resp = http
        .post(url(base_url, "/api/v1/session/redeem-handoff"))
        .json(&Req { handoff })
        .timeout(CP_REST_TIMEOUT)
        .send()
        .await
        .map_err(|e| ApiError::Transport(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(status_error(resp).await);
    }
    resp.json::<Resp>()
        .await
        .map(|r| r.token)
        .map_err(|e| ApiError::Decode(e.to_string()))
}

/// Validate a session token and fetch the signed-in user. `GET /api/v1/session`.
pub async fn session_info(
    http: &reqwest::Client,
    base_url: &str,
    session_token: &str,
) -> Result<SessionInfo, ApiError> {
    get_json(http, base_url, "/api/v1/session", session_token).await
}

/// Upload a user-triggered diagnostic bundle. `POST /api/v1/diagnostics`, session-authed.
/// The bundle is connection-level operational metadata (daemon log tails + status
/// snapshot) — never data-plane payload [T:A.1.1] — and the user consents per send
/// (no background stream). Returns the server's report id, which the user quotes to
/// support. The server caps the body and rate-limits; a 429 surfaces as `Status(429)`.
pub async fn post_diagnostics(
    http: &reqwest::Client,
    base_url: &str,
    session_token: &str,
    bundle: &serde_json::Value,
) -> Result<String, ApiError> {
    let resp = http
        .post(url(base_url, "/api/v1/diagnostics"))
        .bearer_auth(session_token)
        .json(bundle)
        .timeout(CP_REST_TIMEOUT)
        .send()
        .await
        .map_err(|e| ApiError::Transport(e.to_string()))?;
    let status = resp.status();
    if !status.is_success() {
        return Err(ApiError::Status(status.as_u16()));
    }
    #[derive(serde::Deserialize)]
    struct Out {
        report_id: String,
    }
    resp.json::<Out>()
        .await
        .map(|o| o.report_id)
        .map_err(|e| ApiError::Decode(e.to_string()))
}

/// Ask the control plane for a hosted checkout URL for `plan` (e.g. "F0-Plus", "F1-25").
/// `POST /api/v1/billing/checkout`. Billing logic lives in the control plane `[T:A.1.1]`:
/// the client only forwards the plan key and opens the returned URL. The CP stamps the
/// caller's tenant into the checkout from the bearer session, so the paid webhook can
/// activate the right tenant without the client handling any billing identity.
pub async fn billing_checkout(
    http: &reqwest::Client,
    base_url: &str,
    session_token: &str,
    plan: &str,
) -> Result<String, ApiError> {
    #[derive(serde::Serialize)]
    struct Req<'a> {
        plan: &'a str,
    }
    #[derive(serde::Deserialize)]
    struct Resp {
        url: String,
    }
    let resp = http
        .post(url(base_url, "/api/v1/billing/checkout"))
        .bearer_auth(session_token)
        .json(&Req { plan })
        .timeout(CP_REST_TIMEOUT)
        .send()
        .await
        .map_err(|e| ApiError::Transport(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(status_error(resp).await);
    }
    resp.json::<Resp>()
        .await
        .map(|r| r.url)
        .map_err(|e| ApiError::Decode(e.to_string()))
}

/// One relay in the vendor-operated fleet map. The agent dials `endpoint` (`host:port`)
/// as a NAT-fallback transport, addressing peers by WireGuard public key
/// `[T:A.1.1 relay-block + Decision D-T1]`.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct RelayEndpoint {
    pub relay_id: String,
    pub region: String,
    pub endpoint: String,
}

/// Fetch this tenant's relay fleet map. `GET /api/v1/relay/map`. The control plane
/// returns only enabled relays; an empty list is a normal, cacheable answer — the
/// caller then runs direct-only, unchanged. `[T:§D.9.3]`
pub async fn relay_map(
    http: &reqwest::Client,
    base_url: &str,
    token: &NodeServiceToken,
) -> Result<Vec<RelayEndpoint>, ApiError> {
    #[derive(serde::Deserialize)]
    struct Resp {
        relays: Vec<RelayEndpoint>,
    }
    let resp: Resp = get_json(http, base_url, "/api/v1/relay/map", token.as_str()).await?;
    Ok(resp.relays)
}

/// Poll the desktop OAuth handoff: `GET /auth/handoff?nonce=…`. Returns the session
/// token once the browser-side GitHub OAuth completes, or `None` while still pending
/// (HTTP 204). Lets the app sign in by polling instead of relying on the `ankayma://`
/// deep link firing. `[T:A.1.3 handoff]`
pub async fn fetch_handoff(
    http: &reqwest::Client,
    base_url: &str,
    nonce: &str,
) -> Result<Option<String>, ApiError> {
    #[derive(serde::Deserialize)]
    struct Resp {
        token: String,
    }
    let resp = http
        .get(url(base_url, &format!("/auth/handoff?nonce={nonce}")))
        .timeout(CP_REST_TIMEOUT)
        .send()
        .await
        .map_err(|e| ApiError::Transport(e.to_string()))?;
    if resp.status().as_u16() == 204 {
        return Ok(None); // still pending
    }
    if !resp.status().is_success() {
        return Err(status_error(resp).await);
    }
    resp.json::<Resp>()
        .await
        .map(|r| Some(r.token))
        .map_err(|e| ApiError::Decode(e.to_string()))
}

/// Fetch the tenant's usage quota. `GET /api/v1/quota`.
pub async fn quota(
    http: &reqwest::Client,
    base_url: &str,
    session_token: &str,
) -> Result<Quota, ApiError> {
    get_json(http, base_url, "/api/v1/quota", session_token).await
}

/// Wire shape of `GET /api/v1/peers`: the full mesh roster (includes self and
/// any stale entries). The data plane filters it via `dataplane::dialable_peers`.
#[derive(Debug, Clone, serde::Deserialize)]
struct PeersResponse {
    peers: Vec<PeerInfo>,
}

/// Wire shape of `GET /api/v1/nodes`: management surface (role-filtered server-side).
#[derive(Debug, Clone, serde::Deserialize)]
struct NodesResponse {
    nodes: Vec<NodeBrief>,
}

/// Fetch the device list for the UI. `GET /api/v1/nodes`. [T:B.5.2]
/// Role-filtered server-side: admin sees all tenant nodes, member sees only own.
/// Replaces the old `peers` call for the device list page (peers is for mesh routing).
pub async fn list_nodes(
    http: &reqwest::Client,
    base_url: &str,
    session_token: &str,
) -> Result<Vec<NodeBrief>, ApiError> {
    let resp: NodesResponse = get_json(http, base_url, "/api/v1/nodes", session_token).await?;
    Ok(resp.nodes)
}

/// Fetch the current mesh roster. `GET /api/v1/peers`. `[T:B.5.1]`
/// Used to discover peers that enrolled *after* this node did, so a long-running
/// agent's view of the mesh stays fresh. Re-enrolling to refresh the roster would
/// be wasteful, not harmful: enrollment is idempotent on the machine key, and on
/// the WireGuard key before that.
pub async fn peers(
    http: &reqwest::Client,
    base_url: &str,
    session_token: &str,
) -> Result<Vec<PeerInfo>, ApiError> {
    let resp: PeersResponse = get_json(http, base_url, "/api/v1/peers", session_token).await?;
    Ok(resp.peers)
}

/// Enroll this node with the control-plane Agent API.
/// `POST {base_url}/api/v1/enrollment` with a Bearer session token. `[T:B.5.1]`
pub async fn enroll(
    http: &reqwest::Client,
    base_url: &str,
    session_token: &str,
    req: &EnrollRequest,
) -> Result<EnrollResponse, ApiError> {
    let resp = http
        .post(url(base_url, "/api/v1/enrollment"))
        .bearer_auth(session_token)
        .json(req)
        .timeout(CP_REST_TIMEOUT)
        .send()
        .await
        .map_err(|e| ApiError::Transport(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(status_error(resp).await);
    }
    resp.json::<EnrollResponse>()
        .await
        .map_err(|e| ApiError::Decode(e.to_string()))
}

/// Build an HTTP client that trusts ONLY the Provisioning CA received at
/// enrollment (TH-A dynamic trust — no CA pinned in the binary, no system
/// roots). For broker connections (AgentControl, B.5.1); CP REST calls keep
/// `reqwest::Client::new()` with system roots — cp.ankayma.com serves a
/// public web-PKI cert. `[T:Part D §H.2 Step 1]`
///
/// Excluding system roots is what makes cross-PL isolation fail at the TLS
/// layer: a broker of another product line presents a chain to a different
/// Provisioning CA and the handshake fails before any bytes flow.
/// `[T:B.4.1 + B.5.1]`
///
/// `crl_pem`: revocation is CRL broadcast (B.4.2). rustls 0.23 (under reqwest
/// 0.12 `rustls-tls`) enforces CRLs natively at handshake.
/// `[T:reqwest@0.12.28-add_crl]`
pub fn broker_client(
    provisioning_ca_pem: &str,
    crl_pem: Option<&str>,
) -> Result<reqwest::Client, ApiError> {
    // from_pem_bundle: the CA *chain* (root + intermediates) arrives as one
    // concatenated PEM string. [T:reqwest@0.12.28-from_pem_bundle]
    let cas = reqwest::Certificate::from_pem_bundle(provisioning_ca_pem.as_bytes())
        .map_err(|e| ApiError::Transport(format!("provisioning CA parse: {e}")))?;
    if cas.is_empty() {
        return Err(ApiError::Transport(
            "provisioning CA PEM contains no certificate".into(),
        ));
    }
    let mut builder = reqwest::Client::builder().tls_built_in_root_certs(false);
    for ca in cas {
        builder = builder.add_root_certificate(ca);
    }
    if let Some(crl) = crl_pem {
        let crls = reqwest::tls::CertificateRevocationList::from_pem_bundle(crl.as_bytes())
            .map_err(|e| ApiError::Transport(format!("CRL parse: {e}")))?;
        builder = builder.add_crls(crls);
    }
    builder
        .build()
        .map_err(|e| ApiError::Transport(e.to_string()))
}

/// Wire shape of `POST /api/v1/enrollment/token`: a single-use join link for
/// enrolling a second device into the same tenant.
#[derive(Debug, serde::Deserialize)]
struct JoinTokenResponse {
    url: String,
    #[allow(dead_code)]
    expires_in_seconds: u32,
}

/// Mint a short-lived join link (`ankayma://join?token=…`) so another device can
/// enroll into this tenant without re-doing GitHub OAuth. `POST
/// /api/v1/enrollment/token` (session-authed). `ttl_seconds` optionally overrides
/// the server's default TTL (the control plane clamps it). Returns the
/// `ankayma://join?…` URL. `[T:A.1.10/A.1.22 enrollment]`
pub async fn issue_join_token(
    http: &reqwest::Client,
    base_url: &str,
    session_token: &str,
    ttl_seconds: Option<u64>,
    proof_token: Option<&str>,
) -> Result<String, ApiError> {
    let mut qs: Vec<String> = Vec::new();
    if let Some(ttl) = ttl_seconds {
        qs.push(format!("ttl_seconds={ttl}"));
    }
    if let Some(p) = proof_token {
        qs.push(format!("proof_token={p}"));
    }
    let base = url(base_url, "/api/v1/enrollment/token");
    let endpoint = if qs.is_empty() {
        base
    } else {
        format!("{base}?{}", qs.join("&"))
    };
    let resp = http
        .post(endpoint)
        .bearer_auth(session_token)
        .timeout(CP_REST_TIMEOUT)
        .send()
        .await
        .map_err(|e| ApiError::Transport(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(status_error(resp).await);
    }
    resp.json::<JoinTokenResponse>()
        .await
        .map(|r| r.url)
        .map_err(|e| ApiError::Decode(e.to_string()))
}

/// Wire shape of `POST /api/v1/enrollment/join` — the recipient half of a node
/// invite. Mirrors the control-plane `JoinEnrollReq`. The `join_token` IS the
/// authorization to join the tenant, so there is no Bearer header. `[T:A.1.10]`
#[derive(Debug, serde::Serialize)]
pub struct JoinEnrollRequest {
    pub join_token: String,
    pub public_key: String,
    pub hostname: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// Workload classification (Part B §B.1.4). A headless server enrolled via join
    /// token sets `AppServer`, matching the session-authed `enroll` path; the control
    /// plane's `join_enroll` accepts the same field (`JoinEnrollReq.workload_kind`).
    /// `None` for an ordinary app-device join. `[T:Part B §B.1.4]`
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workload_kind: Option<String>,
    /// See `domain::EnrollRequest::platform`. `[T:f2 §H.6]`
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    /// See `domain::EnrollRequest::machine_proof`. Redeeming an invite also lifts an
    /// administrator's revocation of this device — the invite IS the re-admission.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub machine_proof: Option<String>,
    /// See `domain::EnrollRequest::caps`. A node that joins by invite enrols exactly like
    /// one that joins by session, so it declares the same way. `[T:A.1.20]`
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub caps: Vec<String>,
}

/// Redeem a node invite (`ankayma://join?token=…`) to enroll THIS device into the
/// invite's tenant. `POST {base_url}/api/v1/enrollment/join` — NO Authorization
/// header; the join token authorizes the enroll (A.1.10/A.1.22). Returns the same
/// `EnrollResponse` shape as a session-authed `enroll`. `[T:A.1.10/A.1.22 enrollment]`
pub async fn enroll_via_join_token(
    http: &reqwest::Client,
    base_url: &str,
    req: &JoinEnrollRequest,
) -> Result<EnrollResponse, ApiError> {
    let resp = http
        .post(url(base_url, "/api/v1/enrollment/join"))
        .json(req)
        .timeout(CP_REST_TIMEOUT)
        .send()
        .await
        .map_err(|e| ApiError::Transport(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(status_error(resp).await);
    }
    resp.json::<EnrollResponse>()
        .await
        .map_err(|e| ApiError::Decode(e.to_string()))
}

/// Open an identity-bound SSH session to one of the tenant's OWN mesh nodes.
/// `POST /api/v1/ssh/session` (session-authed). The control plane resolves the
/// overlay target + anchors a connection-level `SshSessionOpened` event — it never
/// sees the SSH stream (A.1.1). Returns the target + honest receipt; the caller
/// execs `ssh <login>@<overlay_ip>`. `[T:Part C §H.3.6.1 F-2 + A.1.3 + A.1.8]`
pub async fn open_ssh_session(
    http: &reqwest::Client,
    base_url: &str,
    session_token: &str,
    req: &SshSessionRequest,
) -> Result<SshSessionResponse, ApiError> {
    let resp = http
        .post(url(base_url, "/api/v1/ssh/session"))
        .bearer_auth(session_token)
        .json(req)
        .timeout(CP_REST_TIMEOUT)
        .send()
        .await
        .map_err(|e| ApiError::Transport(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(status_error(resp).await);
    }
    resp.json::<SshSessionResponse>()
        .await
        .map_err(|e| ApiError::Decode(e.to_string()))
}

/// An AGENT identity asks to connect to one node under its own live delegation
/// window. `POST /api/v1/agents/ssh-session` — no bearer session: the request body's
/// `proof` is what authenticates the caller (the control plane's `resolve_anchor`
/// agent branch), the same way `agent_enroll`'s single-use token is what
/// authenticates a redemption rather than a header.
pub async fn open_agent_ssh_session(
    http: &reqwest::Client,
    base_url: &str,
    req: &crate::domain::AgentSshSessionRequest,
) -> Result<crate::domain::AgentSshSessionResponse, ApiError> {
    let resp = http
        .post(url(base_url, "/api/v1/agents/ssh-session"))
        .json(req)
        .timeout(CP_REST_TIMEOUT)
        .send()
        .await
        .map_err(|e| ApiError::Transport(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(status_error(resp).await);
    }
    resp.json::<crate::domain::AgentSshSessionResponse>()
        .await
        .map_err(|e| ApiError::Decode(e.to_string()))
}

/// Request a root-elevation grant for a node. `POST /api/v1/ssh/elevate`
/// (session-authed). The CP evaluates authz (owner-implicit at F0, AdminAccessPolicy
/// at F1+) + AAL step-up, then returns a signed grant the client presents to the
/// node's embedded server — never a password, never standing sudo. `[T:f2 §H.4]`
pub async fn elevate_ssh_session(
    http: &reqwest::Client,
    base_url: &str,
    session_token: &str,
    req: &crate::domain::SshElevateRequest,
) -> Result<crate::domain::SshElevateResponse, ApiError> {
    let resp = http
        .post(url(base_url, "/api/v1/ssh/elevate"))
        .bearer_auth(session_token)
        .json(req)
        .timeout(CP_REST_TIMEOUT)
        .send()
        .await
        .map_err(|e| ApiError::Transport(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(status_error(resp).await);
    }
    resp.json::<crate::domain::SshElevateResponse>()
        .await
        .map_err(|e| ApiError::Decode(e.to_string()))
}

/// Fetch the control plane's F-2 elevation verify key (base64). A node calls this
/// at `agent up` so its embedded server can verify root-elevation grants against the
/// CP key. `GET /api/v1/ssh/elevate/pubkey` (unauthenticated — it's a public key).
/// `[T:f2 §H.4]`
pub async fn elevate_pubkey(http: &reqwest::Client, base_url: &str) -> Result<String, ApiError> {
    let resp = http
        .get(url(base_url, "/api/v1/ssh/elevate/pubkey"))
        .timeout(CP_REST_TIMEOUT)
        .send()
        .await
        .map_err(|e| ApiError::Transport(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(status_error(resp).await);
    }
    let v: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| ApiError::Decode(e.to_string()))?;
    v.get("pubkey")
        .and_then(|p| p.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| ApiError::Decode("no pubkey field".to_string()))
}

/// Fetch the tenant's F-3 mesh-resolve table. `GET /api/v1/mesh/resolve`
/// (session-authed). A non-enrolled device gets 401 — the names do not exist for
/// it (private-default); a revoked target node drops its name server-side (instant
/// revoke). The agent resolves these locally, off the vendor's path (A.1.1).
/// `[T:Part C §H.3.6.1 F-3 + A.1.1/A.1.2]`
pub async fn resolve_subdomains(
    http: &reqwest::Client,
    base_url: &str,
    session_token: &str,
) -> Result<ResolveTable, ApiError> {
    get_json(http, base_url, "/api/v1/mesh/resolve", session_token).await
}

/// List this tenant's registered branded subdomains. `GET /api/v1/subdomain`.
pub async fn list_subdomains(
    http: &reqwest::Client,
    base_url: &str,
    session_token: &str,
) -> Result<Vec<Subdomain>, ApiError> {
    #[derive(serde::Deserialize)]
    struct Resp {
        subdomains: Vec<Subdomain>,
    }
    let r: Resp = get_json(http, base_url, "/api/v1/subdomain", session_token).await?;
    Ok(r.subdomains)
}

/// Register a branded subdomain (map `label` → a node). `POST /api/v1/subdomain`.
/// The control plane validates the label + enforces the ND-R6 cap; its error
/// message (400/404/409) is surfaced verbatim. Returns the new FQDN.
pub async fn register_subdomain(
    http: &reqwest::Client,
    base_url: &str,
    session_token: &str,
    req: &SubdomainReq,
    proof_token: Option<&str>,
) -> Result<String, ApiError> {
    #[derive(serde::Deserialize)]
    struct Resp {
        fqdn: String,
    }
    let base = url(base_url, "/api/v1/subdomain");
    let endpoint = match proof_token {
        Some(p) => format!("{base}?proof_token={p}"),
        None => base,
    };
    let resp = http
        .post(endpoint)
        .bearer_auth(session_token)
        .json(req)
        .timeout(CP_REST_TIMEOUT)
        .send()
        .await
        .map_err(|e| ApiError::Transport(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(status_error(resp).await);
    }
    resp.json::<Resp>()
        .await
        .map(|r| r.fqdn)
        .map_err(|e| ApiError::Decode(e.to_string()))
}

/// Submit this node's own CSR for a branded subdomain it owns. `POST
/// /api/v1/subdomain/{fqdn}/csr`, node-service-token authed — the private key
/// that matches this CSR never leaves the node (A.1.1). `[T:F-3 auto-TLS]`
pub async fn submit_subdomain_csr(
    http: &reqwest::Client,
    base_url: &str,
    service_token: &NodeServiceToken,
    fqdn: &str,
    csr_pem: &str,
) -> Result<(), ApiError> {
    let req = SubdomainCsrReq {
        csr_pem: csr_pem.to_string(),
    };
    let resp = http
        .post(url(base_url, &format!("/api/v1/subdomain/{fqdn}/csr")))
        .bearer_auth(service_token.as_str())
        .json(&req)
        .timeout(CP_REST_TIMEOUT)
        .send()
        .await
        .map_err(|e| ApiError::Transport(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(status_error(resp).await);
    }
    Ok(())
}

/// Poll ACME issuance state for a subdomain. `GET /api/v1/subdomain/{fqdn}/cert`
/// — the fallback to the `cert_issued` SSE push (belt-and-suspenders, same
/// lesson as the resolver's stale-table bug). `[T:F-3 auto-TLS]`
pub async fn get_subdomain_cert(
    http: &reqwest::Client,
    base_url: &str,
    token: &str,
    fqdn: &str,
) -> Result<SubdomainCert, ApiError> {
    get_json(
        http,
        base_url,
        &format!("/api/v1/subdomain/{fqdn}/cert"),
        token,
    )
    .await
}

/// Remove a branded subdomain by label. `DELETE /api/v1/subdomain/{label}`.
pub async fn delete_subdomain(
    http: &reqwest::Client,
    base_url: &str,
    session_token: &str,
    label: &str,
    proof_token: Option<&str>,
) -> Result<(), ApiError> {
    let base = url(base_url, &format!("/api/v1/subdomain/{label}"));
    let endpoint = match proof_token {
        Some(p) => format!("{base}?proof_token={p}"),
        None => base,
    };
    let resp = http
        .delete(endpoint)
        .bearer_auth(session_token)
        .timeout(CP_REST_TIMEOUT)
        .send()
        .await
        .map_err(|e| ApiError::Transport(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(status_error(resp).await);
    }
    Ok(())
}

// ── F1 team membership ────────────────────────────────────────────────────────

/// List the active tenant's members + cap + your role. `GET /api/v1/members`.
pub async fn list_members(
    http: &reqwest::Client,
    base_url: &str,
    session_token: &str,
) -> Result<MembersView, ApiError> {
    get_json(http, base_url, "/api/v1/members", session_token).await
}

/// List the pending admissions — invited, not yet redeemed (admin only).
/// `GET /api/v1/members/invites`. The response carries no invite token by design:
/// re-sending goes back through `invite_member`, which mails the link, so the admin
/// never holds a credential that would let them sign in as the invitee. `[T:A.1.6]`
pub async fn list_member_invites(
    http: &reqwest::Client,
    base_url: &str,
    session_token: &str,
) -> Result<PendingInvitesView, ApiError> {
    get_json(http, base_url, "/api/v1/members/invites", session_token).await
}

/// Withdraw a pending invite (admin). `DELETE /api/v1/members/invites?email=…`.
/// Access-reducing, so no step-up proof — see the server handler's rationale.
pub async fn revoke_member_invite(
    http: &reqwest::Client,
    base_url: &str,
    session_token: &str,
    email: &str,
) -> Result<(), ApiError> {
    let resp = http
        .delete(url(base_url, "/api/v1/members/invites"))
        .query(&[("email", email)])
        .bearer_auth(session_token)
        .timeout(CP_REST_TIMEOUT)
        .send()
        .await
        .map_err(|e| ApiError::Transport(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(status_error(resp).await);
    }
    Ok(())
}

/// Mint a member invite (admin). `ttl_seconds` optionally overrides the server's
/// default member-invite TTL (clamped server-side). Gated behind a step-up proof
/// (M-1 — Part D H.2#6). Returns the `ankayma://join-team?…` URL.
pub async fn invite_member(
    http: &reqwest::Client,
    base_url: &str,
    session_token: &str,
    email: &str,
    seat_type: Option<&str>,
    ttl_seconds: Option<u64>,
    proof_token: Option<&str>,
) -> Result<String, ApiError> {
    #[derive(serde::Deserialize)]
    struct Resp {
        url: String,
    }
    let resp = http
        .post(url(base_url, "/api/v1/members/invite"))
        .bearer_auth(session_token)
        .json(&serde_json::json!({
            "email": email,
            "seat_type": seat_type,
            "ttl_seconds": ttl_seconds,
            "proof_token": proof_token,
        }))
        .timeout(CP_REST_TIMEOUT)
        .send()
        .await
        .map_err(|e| ApiError::Transport(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(status_error(resp).await);
    }
    resp.json::<Resp>()
        .await
        .map(|r| r.url)
        .map_err(|e| ApiError::Decode(e.to_string()))
}

/// Member magic-link join (no session, no OTP): redeem the emailed invite token — which
/// IS the credential — to become an email-rooted member. Returns a NEW session token (the
/// invitee is now signed in, no GitHub). `POST /api/v1/members/join-link`. `[T:Part D §A
/// invite-flow §Cases — ZERO confirm at redeem, doc lines 28-30]`
/// Re-mint a user session by proving possession of this device's durable machine key
/// — the device-key re-auth that removes the 4h session wall (no second sign-in).
/// NO Authorization header: the `machine_proof` IS the credential (PoP, non-bearer).
/// `POST {base_url}/api/v1/session/refresh` → the fresh session token.
/// [T:E-6 device-key re-auth + A.1.10]
pub async fn session_refresh(
    http: &reqwest::Client,
    base_url: &str,
    node_id: &str,
    machine_proof: &str,
) -> Result<String, ApiError> {
    #[derive(serde::Deserialize)]
    struct Resp {
        session_token: String,
    }
    let resp = http
        .post(url(base_url, "/api/v1/session/refresh"))
        .json(&serde_json::json!({ "node_id": node_id, "machine_proof": machine_proof }))
        .timeout(CP_REST_TIMEOUT)
        .send()
        .await
        .map_err(|e| ApiError::Transport(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(status_error(resp).await);
    }
    resp.json::<Resp>()
        .await
        .map(|r| r.session_token)
        .map_err(|e| ApiError::Transport(e.to_string()))
}

pub async fn join_team_link(
    http: &reqwest::Client,
    base_url: &str,
    token: &str,
    method: Option<&str>,
) -> Result<String, ApiError> {
    #[derive(serde::Deserialize)]
    struct Resp {
        token: String,
    }
    let mut body = serde_json::json!({ "token": token });
    if let Some(m) = method.filter(|s| !s.is_empty()) {
        body["method"] = serde_json::json!(m);
    }
    let resp = http
        .post(url(base_url, "/api/v1/members/join-link"))
        .json(&body)
        .timeout(CP_REST_TIMEOUT)
        .send()
        .await
        .map_err(|e| ApiError::Transport(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(status_error(resp).await);
    }
    resp.json::<Resp>()
        .await
        .map(|r| r.token)
        .map_err(|e| ApiError::Decode(e.to_string()))
}

/// Redeem an invite to join a team. `POST /api/v1/members/join`.
pub async fn join_team(
    http: &reqwest::Client,
    base_url: &str,
    session_token: &str,
    invite: &str,
) -> Result<(), ApiError> {
    let resp = http
        .post(url(base_url, "/api/v1/members/join"))
        .bearer_auth(session_token)
        .json(&serde_json::json!({ "token": invite }))
        .timeout(CP_REST_TIMEOUT)
        .send()
        .await
        .map_err(|e| ApiError::Transport(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(status_error(resp).await);
    }
    Ok(())
}

/// Remove a member (admin). `DELETE /api/v1/members/{user_id}`. Gated behind a
/// step-up proof (M-4 — Part D H.2#7).
pub async fn remove_member(
    http: &reqwest::Client,
    base_url: &str,
    session_token: &str,
    user_id: &str,
    proof_token: Option<&str>,
) -> Result<(), ApiError> {
    let base = url(base_url, &format!("/api/v1/members/{user_id}"));
    let endpoint = match proof_token {
        Some(p) => format!("{base}?proof_token={p}"),
        None => base,
    };
    let resp = http
        .delete(endpoint)
        .bearer_auth(session_token)
        .timeout(CP_REST_TIMEOUT)
        .send()
        .await
        .map_err(|e| ApiError::Transport(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(status_error(resp).await);
    }
    Ok(())
}

/// Admin resets a member's TOTP (the admin-mediated recovery path, H.9).
/// `POST /api/v1/members/{user_id}/totp/disable`, gated by the admin's own
/// `manage_member_factor` step-up proof (passed as a query param, matching the
/// server's `Query<StepUpQuery>`). [T:Part D §H.9]
pub async fn reset_member_totp(
    http: &reqwest::Client,
    base_url: &str,
    session_token: &str,
    user_id: &str,
    proof_token: Option<&str>,
) -> Result<(), ApiError> {
    let base = url(base_url, &format!("/api/v1/members/{user_id}/totp/disable"));
    let endpoint = match proof_token {
        Some(p) => format!("{base}?proof_token={p}"),
        None => base,
    };
    let resp = http
        .post(endpoint)
        .bearer_auth(session_token)
        .timeout(CP_REST_TIMEOUT)
        .send()
        .await
        .map_err(|e| ApiError::Transport(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(status_error(resp).await);
    }
    Ok(())
}

// ── PolicyBlock authz + my-access ─────────────────────────────────────────────

/// Read the active PolicyBlock + chain status. `GET /api/v1/policies`.
pub async fn get_policy(
    http: &reqwest::Client,
    base_url: &str,
    session_token: &str,
) -> Result<PolicyView, ApiError> {
    get_json(http, base_url, "/api/v1/policies", session_token).await
}

/// Submit a new PolicyBlock (admin). `body` is the `{"rules":[…]}` JSON; the control
/// plane rejects a cosmetic/network selector key (§B) with a clear message.
pub async fn submit_policy(
    http: &reqwest::Client,
    base_url: &str,
    session_token: &str,
    body: &str,
    proof_token: Option<&str>,
) -> Result<(), ApiError> {
    let base = url(base_url, "/api/v1/policies");
    let endpoint = match proof_token {
        Some(p) => format!("{base}?proof_token={p}"),
        None => base,
    };
    let resp = http
        .post(endpoint)
        .bearer_auth(session_token)
        .header("content-type", "application/json")
        .body(body.to_string())
        .timeout(CP_REST_TIMEOUT)
        .send()
        .await
        .map_err(|e| ApiError::Transport(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(status_error(resp).await);
    }
    Ok(())
}

/// The caller's service catalog derived from policy. `GET /api/v1/my-access`.
pub async fn my_access(
    http: &reqwest::Client,
    base_url: &str,
    session_token: &str,
) -> Result<MyAccess, ApiError> {
    get_json(http, base_url, "/api/v1/my-access", session_token).await
}

/// Exchange a CI OIDC token for ephemeral mesh access.
/// `POST {base_url}/api/v1/ci/deploy`. `[T:Part C §H.3.3]`
/// No bearer header: the OIDC token in the body IS the credential. The control
/// plane verifies it cryptographically — the agent never decides ALLOW/DENY.
pub async fn ci_deploy(
    http: &reqwest::Client,
    base_url: &str,
    req: &CiDeployRequest,
) -> Result<CiDeployResponse, ApiError> {
    let resp = http
        .post(url(base_url, "/api/v1/ci/deploy"))
        .json(req)
        .timeout(CP_REST_TIMEOUT)
        .send()
        .await
        .map_err(|e| ApiError::Transport(e.to_string()))?;
    let status = resp.status();
    if !status.is_success() {
        return Err(ApiError::Status(status.as_u16()));
    }
    resp.json::<CiDeployResponse>()
        .await
        .map_err(|e| ApiError::Decode(e.to_string()))
}

/// F-4 redeem: exchange a single-use agent identity token for ephemeral mesh access
/// plus a receipt. `POST /api/v1/agents/enroll`. The token IS the credential — no
/// session, no static secret. `[T:Part C §H.3.3]`
pub async fn agent_enroll(
    http: &reqwest::Client,
    base_url: &str,
    req: &AgentEnrollRequest,
) -> Result<AgentEnrollResponse, ApiError> {
    let resp = http
        .post(url(base_url, "/api/v1/agents/enroll"))
        .json(req)
        .timeout(CP_REST_TIMEOUT)
        .send()
        .await
        .map_err(|e| ApiError::Transport(e.to_string()))?;
    let status = resp.status();
    if !status.is_success() {
        return Err(ApiError::Status(status.as_u16()));
    }
    resp.json::<AgentEnrollResponse>()
        .await
        .map_err(|e| ApiError::Decode(e.to_string()))
}

/// Deliver queued command-grant outcomes. `POST {base_url}/api/v1/exec/outcome`.
///
/// Authenticated with the NODE service token, not a user session: the node is the only
/// party that watched the command, and a report authenticated as a human would be a
/// report from something that did not see it. `[T:Part D §D.11]`
///
/// Delivers oldest-first and STOPS at the first failure, putting that outcome back at the
/// front. Continuing past it would reorder the ledger, and an operator reading it should
/// see the outcomes in the order they happened rather than in the order the network
/// recovered.
pub async fn deliver_outcomes(
    http: &reqwest::Client,
    base_url: &str,
    node_service_token: &NodeServiceToken,
    queue: &crate::exec_outcome::OutcomeQueue,
) -> usize {
    let mut pending = queue.drain();
    let mut delivered = 0usize;
    while !pending.is_empty() {
        let outcome = pending.remove(0);
        let sent = http
            .post(url(base_url, "/api/v1/exec/outcome"))
            .bearer_auth(node_service_token.as_str())
            .json(&outcome)
            .timeout(CP_REST_TIMEOUT)
            .send()
            .await;
        match sent {
            // A 4xx means the control plane has decided about this grant — already
            // closed, or not ours. Retrying forever would block every outcome behind it,
            // so it is dropped and the reason logged. Only a transport failure or a 5xx
            // is worth waiting out.
            Ok(r) if r.status().is_success() => delivered += 1,
            Ok(r) if r.status().is_client_error() => {
                eprintln!(
                    "[F-2] control plane refused an outcome for {} ({}); dropping it",
                    outcome.grant_id,
                    r.status()
                );
            }
            _ => {
                queue.requeue_front(outcome);
                for left in pending.into_iter().rev() {
                    queue.requeue_front(left);
                }
                return delivered;
            }
        }
    }
    delivered
}

// ── Governance surfaces (register · approvals · task record) ──────────────────
// [T:A.1.4 — the customer sees what the control plane recorded, in their own client]
//
// Every one of these is a READ of the tenant's own evidence, or a human decision about
// it. None of them is control-plane logic: the client shows and asks, the control plane
// decides and records. `[T:Part D §D.2 open/closed]`

/// One legal entity in the tenant's register, with its gaps named.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct RegisteredPrincipal {
    pub principal_id: String,
    pub relationship: String,
    pub legal_name: Option<String>,
    pub lei: Option<String>,
    pub jurisdiction: Option<String>,
    pub criticality: Option<String>,
    /// What is still unstated. Surfaced rather than left blank, because a register that
    /// looks complete and is not is the failure `roi_export` exists to prevent.
    #[serde(default)]
    pub missing_fields: Vec<String>,
}

/// Fields a person may state about an entity. All optional — stating one is not a promise
/// to state the rest, and a half-filled entity beats none.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct PrincipalAmendment {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub legal_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lei: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jurisdiction: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub criticality: Option<String>,
}

/// `GET /api/v1/principals`.
pub async fn list_principals(
    http: &reqwest::Client,
    base_url: &str,
    token: &str,
) -> Result<Vec<RegisteredPrincipal>, ApiError> {
    #[derive(serde::Deserialize)]
    struct Resp {
        principals: Vec<RegisteredPrincipal>,
    }
    let resp = http
        .get(url(base_url, "/api/v1/principals"))
        .bearer_auth(token)
        .timeout(CP_REST_TIMEOUT)
        .send()
        .await
        .map_err(|e| ApiError::Transport(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(status_error(resp).await);
    }
    resp.json::<Resp>()
        .await
        .map(|r| r.principals)
        .map_err(|e| ApiError::Decode(e.to_string()))
}

/// `PATCH /api/v1/principals/{id}` — state what was not known before.
pub async fn amend_principal(
    http: &reqwest::Client,
    base_url: &str,
    token: &str,
    principal_id: &str,
    amendment: &PrincipalAmendment,
) -> Result<(), ApiError> {
    let resp = http
        .patch(url(base_url, &format!("/api/v1/principals/{principal_id}")))
        .bearer_auth(token)
        .json(amendment)
        .timeout(CP_REST_TIMEOUT)
        .send()
        .await
        .map_err(|e| ApiError::Transport(e.to_string()))?;
    expect_ok(resp).await
}

/// A command waiting for a person to decide.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct PendingApproval {
    pub approval_id: String,
    pub template_id: String,
    /// The EXACT argv. A gate that shows a summary is a gate on the summary.
    pub argv: Vec<String>,
    pub cmd_digest: String,
    pub risk_class: String,
    /// `gate` · `irreversible` · `freeform` — three different conversations for whoever
    /// is being asked, so the reason travels with the request.
    pub gate_reason: String,
    pub justification: Option<String>,
    pub node_id: String,
    pub actor_id: String,
    pub requested_by: String,
    pub requested_at: String,
    pub expires_at: String,
}

/// `GET /api/v1/approvals`.
pub async fn list_pending_approvals(
    http: &reqwest::Client,
    base_url: &str,
    token: &str,
) -> Result<Vec<PendingApproval>, ApiError> {
    #[derive(serde::Deserialize)]
    struct Resp {
        pending: Vec<PendingApproval>,
    }
    let resp = http
        .get(url(base_url, "/api/v1/approvals"))
        .bearer_auth(token)
        .timeout(CP_REST_TIMEOUT)
        .send()
        .await
        .map_err(|e| ApiError::Transport(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(status_error(resp).await);
    }
    resp.json::<Resp>()
        .await
        .map(|r| r.pending)
        .map_err(|e| ApiError::Decode(e.to_string()))
}

/// `POST /api/v1/approvals/{id}/decide` — the decision that creates, or withholds, a
/// credential. The control plane mints on approval; nothing is minted here.
/// `credential_issued` on the returned `ApprovalDecision` is the whole reason this
/// deserializes the body instead of discarding it like `expect_ok`: an approval mints
/// its credential HERE, in this response, and nowhere else — there is no later
/// fetch-by-approval-id.
pub async fn decide_approval(
    http: &reqwest::Client,
    base_url: &str,
    token: &str,
    approval_id: &str,
    approve: bool,
) -> Result<crate::domain::ApprovalDecision, ApiError> {
    let resp = http
        .post(url(
            base_url,
            &format!("/api/v1/approvals/{approval_id}/decide"),
        ))
        .bearer_auth(token)
        .json(&serde_json::json!({
            "decision": if approve { "approve" } else { "deny" }
        }))
        .timeout(CP_REST_TIMEOUT)
        .send()
        .await
        .map_err(|e| ApiError::Transport(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(status_error(resp).await);
    }
    resp.json::<crate::domain::ApprovalDecision>()
        .await
        .map_err(|e| ApiError::Decode(e.to_string()))
}

/// Declare a reusable command template. `POST /api/v1/command-templates`
/// (session-authed, requires `ManagePolicy`). The natural caller today is "save this
/// approved FREEFORM argv so it doesn't have to be typed as break-glass again" —
/// promoting it out of the catalog gap this whole tier's CLI otherwise leans on.
///
pub async fn submit_command_template(
    http: &reqwest::Client,
    base_url: &str,
    session_token: &str,
    t: &crate::domain::CommandTemplate,
) -> Result<(), ApiError> {
    let resp = http
        .post(url(base_url, "/api/v1/command-templates"))
        .bearer_auth(session_token)
        .json(t)
        .timeout(CP_REST_TIMEOUT)
        .send()
        .await
        .map_err(|e| ApiError::Transport(e.to_string()))?;
    expect_ok(resp).await
}

/// A human authorises an already-enrolled non-human actor to run specific commands on
/// one node. `POST /api/v1/grants/command` (session-authed — A.1.27 #2: an agent does
/// not mint its own authority, only a human may call this). A command whose template
/// asks for a person, or is off-catalog (`FREEFORM`), comes back `PENDING_APPROVAL`
/// with no credential — see `decide_approval`.
pub async fn mint_command_grants(
    http: &reqwest::Client,
    base_url: &str,
    session_token: &str,
    req: &crate::domain::CommandGrantRequest,
) -> Result<crate::domain::CommandGrantResponse, ApiError> {
    let resp = http
        .post(url(base_url, "/api/v1/grants/command"))
        .bearer_auth(session_token)
        .json(req)
        .timeout(CP_REST_TIMEOUT)
        .send()
        .await
        .map_err(|e| ApiError::Transport(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(status_error(resp).await);
    }
    resp.json::<crate::domain::CommandGrantResponse>()
        .await
        .map_err(|e| ApiError::Decode(e.to_string()))
}

/// `GET /api/v1/tasks/{id}` — the one-page dossier, returned as-is.
///
/// Deliberately untyped. The dossier is a REPORT whose shape is the control plane's to
/// decide; mirroring it into a struct here would mean a client release every time a
/// column is added to a summary the client only displays.
pub async fn task_record(
    http: &reqwest::Client,
    base_url: &str,
    token: &str,
    task_id: &str,
) -> Result<serde_json::Value, ApiError> {
    let resp = http
        .get(url(base_url, &format!("/api/v1/tasks/{task_id}")))
        .bearer_auth(token)
        .timeout(CP_REST_TIMEOUT)
        .send()
        .await
        .map_err(|e| ApiError::Transport(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(status_error(resp).await);
    }
    resp.json::<serde_json::Value>()
        .await
        .map_err(|e| ApiError::Decode(e.to_string()))
}

/// `GET /api/v1/overview` — the admin Tenant Overview, returned as-is.
///
/// Deliberately untyped, same reasoning as `task_record`: this is a REPORT the control
/// plane composes (fleet counts, recent ledger events, live grants, alerts). Mirroring
/// it into a struct would force a client release every time a panel gains a field the
/// client only displays. Admin-gated server-side (403 for a plain member). [T:A.1.1]
pub async fn overview(
    http: &reqwest::Client,
    base_url: &str,
    token: &str,
) -> Result<serde_json::Value, ApiError> {
    get_json(http, base_url, "/api/v1/overview", token).await
}

/// `GET /api/v1/me/overview` — the same report asked about ONESELF: my devices, my
/// access, my live grants. Needs no admin capability because the caller IS the scope
/// — the my-access view of `part-d-tenant-dashboard.md` §H.2. Untyped for the same
/// reason as `overview`. [T:part-d-tenant-dashboard.md §H.2 + A.1.2]
pub async fn my_overview(
    http: &reqwest::Client,
    base_url: &str,
    token: &str,
) -> Result<serde_json::Value, ApiError> {
    get_json(http, base_url, "/api/v1/me/overview", token).await
}

/// Open an SSE stream for peer events. `GET /api/v1/peers/events`.
/// Authenticated with the node service token (not the user session token).
/// Returns the raw response; the caller reads it as a byte stream.
/// [T:Part D §D.12]
pub async fn subscribe_peer_events(
    http: &reqwest::Client,
    base_url: &str,
    node_service_token: &NodeServiceToken,
) -> Result<reqwest::Response, ApiError> {
    // NO .timeout() here — reqwest's per-request timeout spans the WHOLE
    // response including the streamed body [T:reqwest@0.12-RequestBuilder::timeout],
    // so it would kill the long-lived SSE stream mid-session. Liveness is bounded
    // by the caller instead: up.rs wraps this connect in tokio::time::timeout and
    // caps each SSE session at 60s (SSE_SESSION_CAP) before a full resync.
    let resp = http
        .get(url(base_url, "/api/v1/peers/events"))
        .bearer_auth(node_service_token.as_str())
        .header("accept", "text/event-stream")
        .send()
        .await
        .map_err(|e| ApiError::Transport(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(status_error(resp).await);
    }
    Ok(resp)
}

/// Renew the node service token before it expires. `POST /api/v1/nodes/{id}/service-token`.
/// Authenticated with the current (still-valid) service token.
/// Returns (new_token, token_expires_at). [T:Part D §D.11]
pub async fn renew_service_token(
    http: &reqwest::Client,
    base_url: &str,
    node_id: &str,
    current_service_token: &NodeServiceToken,
) -> Result<(String, Option<String>), ApiError> {
    #[derive(serde::Deserialize)]
    struct Resp {
        node_service_token: String,
        token_expires_at: Option<String>,
    }
    let resp = http
        .post(url(
            base_url,
            &format!("/api/v1/nodes/{node_id}/service-token"),
        ))
        .bearer_auth(current_service_token.as_str())
        .timeout(CP_REST_TIMEOUT)
        .send()
        .await
        .map_err(|e| ApiError::Transport(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(status_error(resp).await);
    }
    resp.json::<Resp>()
        .await
        .map(|r| (r.node_service_token, r.token_expires_at))
        .map_err(|e| ApiError::Decode(e.to_string()))
}

/// Map a non-2xx response to an `ApiError`, surfacing the control plane's `error`
/// field verbatim when present (so safe-by-default 400/409 reasons reach the user).
async fn expect_ok(resp: reqwest::Response) -> Result<(), ApiError> {
    if resp.status().is_success() {
        return Ok(());
    }
    Err(status_error(resp).await)
}

/// Turn a non-2xx response into an `ApiError`, surfacing the control plane's
/// `error` message verbatim when present (so the GUI shows the real reason —
/// e.g. "device quota reached" on enrollment), else falling back to the status.
async fn status_error(resp: reqwest::Response) -> ApiError {
    let code = resp.status().as_u16();
    #[derive(serde::Deserialize)]
    struct ErrBody {
        error: Option<String>,
        #[serde(default)]
        step_up_required: bool,
        purpose: Option<String>,
        required_aal: Option<i32>,
        #[serde(default)]
        strong_factor_required: bool,
    }
    match resp.json::<ErrBody>().await {
        // Step-up demand (Part D §Authority model) takes priority — distinct variant
        // so the GUI can drive the step-up flow rather than show a raw error.
        // `required_aal` is absent only on the legacy inline shape (a malformed
        // /stepup/verify call) — 2 is the correct floor for anything gated at all.
        Ok(b) if b.step_up_required => ApiError::StepUpRequired {
            purpose: b.purpose.unwrap_or_default(),
            required_aal: b.required_aal.unwrap_or(2),
        },
        // A refused email-OTP downgrade is a decision, not a failure — keep it
        // typed so the GUI can stop the flow instead of opening a code box.
        Ok(b) if b.strong_factor_required => ApiError::StrongFactorRequired {
            message: b
                .error
                .unwrap_or_else(|| "a stronger sign-in method is enrolled; use it".to_string()),
        },
        Ok(ErrBody { error: Some(m), .. }) if !m.trim().is_empty() => ApiError::Server {
            status: code,
            message: m,
        },
        _ => ApiError::Status(code),
    }
}

/// Like `expect_ok` but returns the raw success body (for endpoints whose exact
/// response shape the client does not model — the caller surfaces it verbatim).
async fn read_ok_text(resp: reqwest::Response) -> Result<String, ApiError> {
    let status = resp.status();
    let code = status.as_u16();
    if status.is_success() {
        return resp
            .text()
            .await
            .map_err(|e| ApiError::Decode(e.to_string()));
    }
    #[derive(serde::Deserialize)]
    struct ErrBody {
        error: Option<String>,
    }
    match resp.json::<ErrBody>().await {
        Ok(ErrBody { error: Some(m) }) if !m.trim().is_empty() => Err(ApiError::Server {
            status: code,
            message: m,
        }),
        _ => Err(ApiError::Status(code)),
    }
}

/// Mint a single-use agent identity token (F-4) for a headless / non-human actor.
/// `POST /api/v1/agents/token` (session-authed). Returns the control plane's raw
/// JSON body (the mint token + receipt); the redeem half is `agent_enroll`
/// (`agent enroll-identity`). Raw because the client does not model the mint
/// response shape — the owner copies the token out of it. `[T:Part C §H.3.3 / F-4]`
pub async fn mint_agent_token(
    http: &reqwest::Client,
    base_url: &str,
    session_token: &str,
    agent_name: &str,
    scope: Option<&str>,
    ttl_seconds: Option<u64>,
) -> Result<String, ApiError> {
    #[derive(serde::Serialize)]
    struct Req<'a> {
        agent_name: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        scope: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        ttl_seconds: Option<u64>,
    }
    let resp = http
        .post(url(base_url, "/api/v1/agents/token"))
        .bearer_auth(session_token)
        .json(&Req {
            agent_name,
            scope,
            ttl_seconds,
        })
        .timeout(CP_REST_TIMEOUT)
        .send()
        .await
        .map_err(|e| ApiError::Transport(e.to_string()))?;
    read_ok_text(resp).await
}

/// Mint a single-use agent identity token, typed (GUI use — see
/// `domain::AgentIdentityMint`). Same endpoint as `mint_agent_token`; kept separate
/// rather than making the CLI's raw-string path parse-then-reserialize, per the
/// existing comment on why that one stays raw. `[T:Part C §H.3.3 / F-4]`
pub async fn mint_agent_identity(
    http: &reqwest::Client,
    base_url: &str,
    session_token: &str,
    agent_name: &str,
    scope: Option<&str>,
    ttl_seconds: Option<u64>,
) -> Result<crate::domain::AgentIdentityMint, ApiError> {
    #[derive(serde::Serialize)]
    struct Req<'a> {
        agent_name: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        scope: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        ttl_seconds: Option<u64>,
    }
    let resp = http
        .post(url(base_url, "/api/v1/agents/token"))
        .bearer_auth(session_token)
        .json(&Req {
            agent_name,
            scope,
            ttl_seconds,
        })
        .timeout(CP_REST_TIMEOUT)
        .send()
        .await
        .map_err(|e| ApiError::Transport(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(status_error(resp).await);
    }
    resp.json::<crate::domain::AgentIdentityMint>()
        .await
        .map_err(|e| ApiError::Decode(e.to_string()))
}

/// A human hands an agent actor a bounded delegation window, hung off a grant the
/// human already holds. `POST /api/v1/delegations` (session-authed).
pub async fn open_delegation_window(
    http: &reqwest::Client,
    base_url: &str,
    session_token: &str,
    req: &crate::domain::OpenDelegationRequest,
) -> Result<crate::domain::OpenDelegationResponse, ApiError> {
    let resp = http
        .post(url(base_url, "/api/v1/delegations"))
        .bearer_auth(session_token)
        .json(req)
        .timeout(CP_REST_TIMEOUT)
        .send()
        .await
        .map_err(|e| ApiError::Transport(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(status_error(resp).await);
    }
    resp.json::<crate::domain::OpenDelegationResponse>()
        .await
        .map_err(|e| ApiError::Decode(e.to_string()))
}

/// The last few delegation windows opened for a node, newest first — what the
/// "Delegate ↗" popup shows under the handle field. `GET /api/v1/delegations/recent`.
/// [A] `node_id` goes into the query string un-encoded, same as `ci_history`'s `node`:
/// these are DNS-label-shaped ids, which are query-safe.
pub async fn list_recent_delegations(
    http: &reqwest::Client,
    base_url: &str,
    session_token: &str,
    node_id: &str,
    limit: Option<i64>,
) -> Result<Vec<crate::domain::RecentDelegation>, ApiError> {
    #[derive(serde::Deserialize)]
    struct Resp {
        delegations: Vec<crate::domain::RecentDelegation>,
    }
    let path = match limit {
        Some(n) => format!("/api/v1/delegations/recent?node_id={node_id}&limit={n}"),
        None => format!("/api/v1/delegations/recent?node_id={node_id}"),
    };
    let resp: Resp = get_json(http, base_url, &path, session_token).await?;
    Ok(resp.delegations)
}

/// List the tenant's CI/CD deploy policies. `GET /api/v1/ci/policy`. `[T:Part C §H.3.3]`
pub async fn list_ci_policies(
    http: &reqwest::Client,
    base_url: &str,
    session_token: &str,
) -> Result<Vec<CiPolicy>, ApiError> {
    #[derive(serde::Deserialize)]
    struct Resp {
        policies: Vec<CiPolicy>,
    }
    let resp: Resp = get_json(http, base_url, "/api/v1/ci/policy", session_token).await?;
    Ok(resp.policies)
}

/// CI deploy history — recent `CiDeployAccess` ledger events for this tenant,
/// optionally narrowed to one node hostname. `GET /api/v1/ci/history`. `[T:A.1.8]`
/// [A] `node` goes into the query string un-encoded: hostnames here are DNS
/// labels (alnum/dot/dash), which are query-safe; revisit if labels widen.
pub async fn ci_history(
    http: &reqwest::Client,
    base_url: &str,
    session_token: &str,
    node: Option<&str>,
) -> Result<Vec<CiRun>, ApiError> {
    #[derive(serde::Deserialize)]
    struct Resp {
        runs: Vec<CiRun>,
    }
    let path = match node {
        Some(n) => format!("/api/v1/ci/history?node={n}"),
        None => "/api/v1/ci/history".to_string(),
    };
    let resp: Resp = get_json(http, base_url, &path, session_token).await?;
    Ok(resp.runs)
}

/// [F-2 viewer] SSH session history for a node — signed `SshSessionOpened` receipts
/// (connection-level only). Mirrors `ci_history`.
pub async fn ssh_history(
    http: &reqwest::Client,
    base_url: &str,
    session_token: &str,
    node: Option<&str>,
) -> Result<Vec<SshSession>, ApiError> {
    #[derive(serde::Deserialize)]
    struct Resp {
        sessions: Vec<SshSession>,
    }
    let path = match node {
        Some(n) => format!("/api/v1/ssh/history?node={n}"),
        None => "/api/v1/ssh/history".to_string(),
    };
    let resp: Resp = get_json(http, base_url, &path, session_token).await?;
    Ok(resp.sessions)
}

/// Create or update a CI/CD deploy policy (server upserts by `repo`).
/// `POST /api/v1/ci/policy`. Safe-by-default is server-enforced. `[T:Part C §H.3.3]`
pub async fn register_ci_policy(
    http: &reqwest::Client,
    base_url: &str,
    session_token: &str,
    req: &CiPolicyReq,
    proof_token: Option<&str>,
) -> Result<(), ApiError> {
    // Step-up gated on paid tiers (E-7 "F-1 CI"): first call has no proof, the server
    // answers STEP_UP_REQUIRED, the GUI runs the flow and retries with proof_token.
    let base = url(base_url, "/api/v1/ci/policy");
    let endpoint = match proof_token {
        Some(p) => format!("{base}?proof_token={p}"),
        None => base,
    };
    let resp = http
        .post(endpoint)
        .bearer_auth(session_token)
        .json(req)
        .timeout(CP_REST_TIMEOUT)
        .send()
        .await
        .map_err(|e| ApiError::Transport(e.to_string()))?;
    expect_ok(resp).await
}

/// Delete a CI/CD deploy policy. `DELETE /api/v1/ci/policy/{owner}/{repo}` — `repo`
/// (`owner/name`) is passed through as the path catch-all. `[T:Part C §H.3.3]`
pub async fn delete_ci_policy(
    http: &reqwest::Client,
    base_url: &str,
    session_token: &str,
    repo: &str,
    proof_token: Option<&str>,
) -> Result<(), ApiError> {
    let base = url(
        base_url,
        &format!("/api/v1/ci/policy/{}", repo.trim_matches('/')),
    );
    let endpoint = match proof_token {
        Some(p) => format!("{base}?proof_token={p}"),
        None => base,
    };
    let resp = http
        .delete(endpoint)
        .bearer_auth(session_token)
        .timeout(CP_REST_TIMEOUT)
        .send()
        .await
        .map_err(|e| ApiError::Transport(e.to_string()))?;
    expect_ok(resp).await
}

/// Remove one of the tenant's own mesh nodes (retire a device).
/// `DELETE /api/v1/nodes/{id}` (session-authed, tenant-scoped). The server gates
/// this behind a step-up on every tier above the free one — NOT on whether the
/// tenant has more than one member. Pass a `proof_token` from `verify_step_up`;
/// `None` succeeds only on the free tier. `[T:A.1.6 + Part D §Authority model]`
pub async fn delete_node(
    http: &reqwest::Client,
    base_url: &str,
    session_token: &str,
    node_id: &str,
    proof_token: Option<&str>,
) -> Result<(), ApiError> {
    let mut qs: Vec<String> = Vec::new();
    if let Some(p) = proof_token {
        qs.push(format!("proof_token={p}"));
    }
    let base = url(base_url, &format!("/api/v1/nodes/{node_id}"));
    let endpoint = if qs.is_empty() {
        base
    } else {
        format!("{base}?{}", qs.join("&"))
    };
    let resp = http
        .delete(endpoint)
        .bearer_auth(session_token)
        .timeout(CP_REST_TIMEOUT)
        .send()
        .await
        .map_err(|e| ApiError::Transport(e.to_string()))?;
    expect_ok(resp).await
}

/// Declare what a node is, for policy to read — Part B's `Tag` entity
/// (`part-b-domain.md:147`), e.g. `env:production`, `tier:1`. Always overwrites the
/// whole set; `&[]` clears every tag, it is not a no-op. `PUT
/// /api/v1/nodes/{node_id}/tags` (session-authed, owner-or-`ManageNodes`).
pub async fn set_node_tags(
    http: &reqwest::Client,
    base_url: &str,
    session_token: &str,
    node_id: &str,
    tags: &[String],
) -> Result<(), ApiError> {
    #[derive(serde::Serialize)]
    struct Req<'a> {
        tags: &'a [String],
    }
    let resp = http
        .put(url(base_url, &format!("/api/v1/nodes/{node_id}/tags")))
        .bearer_auth(session_token)
        .json(&Req { tags })
        .timeout(CP_REST_TIMEOUT)
        .send()
        .await
        .map_err(|e| ApiError::Transport(e.to_string()))?;
    expect_ok(resp).await
}

/// Same as `set_node_tags`, for a Service (subdomain) — Part B names Node and
/// Service as independently-taggable, so this is its own tag set, not the target
/// node's. `PUT /api/v1/subdomains/{fqdn}/tags` (session-authed,
/// owner-of-target-node-or-`ManageSubdomains`).
pub async fn set_subdomain_tags(
    http: &reqwest::Client,
    base_url: &str,
    session_token: &str,
    fqdn: &str,
    tags: &[String],
) -> Result<(), ApiError> {
    #[derive(serde::Serialize)]
    struct Req<'a> {
        tags: &'a [String],
    }
    let resp = http
        .put(url(base_url, &format!("/api/v1/subdomains/{fqdn}/tags")))
        .bearer_auth(session_token)
        .json(&Req { tags })
        .timeout(CP_REST_TIMEOUT)
        .send()
        .await
        .map_err(|e| ApiError::Transport(e.to_string()))?;
    expect_ok(resp).await
}

/// `POST /api/v1/subdomains/{fqdn}/opened` (session-authed) — tell the control plane
/// that this member just opened a private service, so the tenant's access panel shows
/// the visit next to the SSH and CI/CD rows it already had.
///
/// The request to the service itself never touches the control plane — it is
/// peer-to-peer over the overlay `[T:A.1.1]` — so this report is the only thing that
/// can put a service visit in the ledger at all. Best-effort by design: the caller
/// opens the browser first and does not wait on this.
pub async fn record_subdomain_opened(
    http: &reqwest::Client,
    base_url: &str,
    session_token: &str,
    fqdn: &str,
    scheme: &str,
) -> Result<(), ApiError> {
    #[derive(serde::Serialize)]
    struct Req<'a> {
        scheme: &'a str,
    }
    let resp = http
        .post(url(base_url, &format!("/api/v1/subdomains/{fqdn}/opened")))
        .bearer_auth(session_token)
        .json(&Req { scheme })
        .timeout(CP_REST_TIMEOUT)
        .send()
        .await
        .map_err(|e| ApiError::Transport(e.to_string()))?;
    expect_ok(resp).await
}

/// `POST /api/v1/stepup/request` (session-authed) — ask the control plane to mint an
/// OTP challenge for a sensitive action and send the code out-of-band. Returns the
/// `challenge_id` to pass back at the action. `[T:Part D invite-flow §Authority model]`
pub async fn request_step_up(
    http: &reqwest::Client,
    base_url: &str,
    session_token: &str,
    purpose: &str,
) -> Result<String, ApiError> {
    #[derive(serde::Deserialize)]
    struct Resp {
        challenge_id: String,
    }
    let resp = http
        .post(url(base_url, "/api/v1/stepup/request"))
        .bearer_auth(session_token)
        .json(&serde_json::json!({ "purpose": purpose }))
        .timeout(CP_REST_TIMEOUT)
        .send()
        .await
        .map_err(|e| ApiError::Transport(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(status_error(resp).await);
    }
    resp.json::<Resp>()
        .await
        .map(|r| r.challenge_id)
        .map_err(|e| ApiError::Decode(e.to_string()))
}

/// `POST /api/v1/stepup/verify` (session-authed) — exchange a solved OTP
/// challenge for a short-lived, purpose-scoped `proof_token`. This is the
/// generalized interface every gated action now takes a proof from, instead of
/// re-verifying `challenge_id`/`code` inline. [T:Part D §H.5]
pub async fn verify_step_up(
    http: &reqwest::Client,
    base_url: &str,
    session_token: &str,
    purpose: &str,
    challenge_id: &str,
    code: &str,
) -> Result<String, ApiError> {
    post_stepup_verify(
        http,
        base_url,
        session_token,
        &serde_json::json!({
            "factor": "otp",
            "purpose": purpose,
            "challenge_id": challenge_id,
            "code": code,
        }),
    )
    .await
}

/// Same exchange as `verify_step_up`, but against the user's enrolled TOTP
/// secret instead of an emailed challenge — no `challenge_id`, no email round
/// trip. [T:Part D §H.8 Phase 2]
pub async fn verify_step_up_totp(
    http: &reqwest::Client,
    base_url: &str,
    session_token: &str,
    purpose: &str,
    code: &str,
) -> Result<String, ApiError> {
    post_stepup_verify(
        http,
        base_url,
        session_token,
        &serde_json::json!({ "factor": "totp", "purpose": purpose, "code": code }),
    )
    .await
}

async fn post_stepup_verify(
    http: &reqwest::Client,
    base_url: &str,
    session_token: &str,
    body: &serde_json::Value,
) -> Result<String, ApiError> {
    #[derive(serde::Deserialize)]
    struct Resp {
        proof_token: String,
    }
    let resp = http
        .post(url(base_url, "/api/v1/stepup/verify"))
        .bearer_auth(session_token)
        .json(body)
        .timeout(CP_REST_TIMEOUT)
        .send()
        .await
        .map_err(|e| ApiError::Transport(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(status_error(resp).await);
    }
    resp.json::<Resp>()
        .await
        .map(|r| r.proof_token)
        .map_err(|e| ApiError::Decode(e.to_string()))
}

/// `GET /api/v1/stepup/totp/status` — whether the caller has a confirmed TOTP
/// credential, so the client can drive the step-up modal's TOTP path
/// (straight to code entry) instead of the email-OTP path (request first).
pub async fn totp_status(
    http: &reqwest::Client,
    base_url: &str,
    session_token: &str,
) -> Result<bool, ApiError> {
    #[derive(serde::Deserialize)]
    struct Resp {
        confirmed: bool,
    }
    let r: Resp = get_json(http, base_url, "/api/v1/stepup/totp/status", session_token).await?;
    Ok(r.confirmed)
}

/// `POST /api/v1/stepup/totp/enroll` — mint a fresh (unconfirmed) TOTP secret.
/// Returns the `otpauth://` URI + base32 secret for the authenticator app.
pub async fn totp_enroll(
    http: &reqwest::Client,
    base_url: &str,
    session_token: &str,
) -> Result<(String, String), ApiError> {
    #[derive(serde::Deserialize)]
    struct Resp {
        otpauth_url: String,
        secret: String,
    }
    let resp = http
        .post(url(base_url, "/api/v1/stepup/totp/enroll"))
        .bearer_auth(session_token)
        .timeout(CP_REST_TIMEOUT)
        .send()
        .await
        .map_err(|e| ApiError::Transport(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(status_error(resp).await);
    }
    resp.json::<Resp>()
        .await
        .map(|r| (r.otpauth_url, r.secret))
        .map_err(|e| ApiError::Decode(e.to_string()))
}

/// `POST /api/v1/stepup/totp/confirm` — prove the enrolled secret works and mark
/// it confirmed. No backup-codes returned (removed 2026-07-20 (recovery model):
/// a lost authenticator recovers via the email-OTP AAL2 path or an admin/vendor
/// disable, not a code-on-paper).
pub async fn totp_confirm(
    http: &reqwest::Client,
    base_url: &str,
    session_token: &str,
    code: &str,
) -> Result<(), ApiError> {
    let resp = http
        .post(url(base_url, "/api/v1/stepup/totp/confirm"))
        .bearer_auth(session_token)
        .json(&serde_json::json!({ "code": code }))
        .timeout(CP_REST_TIMEOUT)
        .send()
        .await
        .map_err(|e| ApiError::Transport(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(status_error(resp).await);
    }
    Ok(())
}

/// `POST /api/v1/stepup/totp/disable` — remove the caller's own confirmed TOTP
/// factor. Gated server-side by a `manage_auth_factor` step-up proof (the caller
/// proves a current factor, or the AAL2 email-OTP "lost-authenticator" path at
/// F0-Plus/F1). A missing/insufficient proof surfaces as the usual
/// `STEP_UP_REQUIRED:...` status, which the GUI's `runWithStepUp` handles.
pub async fn totp_disable(
    http: &reqwest::Client,
    base_url: &str,
    session_token: &str,
    proof_token: Option<&str>,
) -> Result<(), ApiError> {
    let resp = http
        .post(url(base_url, "/api/v1/stepup/totp/disable"))
        .bearer_auth(session_token)
        .json(&serde_json::json!({ "proof_token": proof_token }))
        .timeout(CP_REST_TIMEOUT)
        .send()
        .await
        .map_err(|e| ApiError::Transport(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(status_error(resp).await);
    }
    Ok(())
}

// ── WebAuthn / YubiKey (E-7 StepUp Phase 3 — AAL3) ────────────────────────────
// These adapters are opaque JSON pass-throughs between whoever runs the
// ceremony and the control plane; the shapes match webauthn-rs's own wire
// format 1:1 (it's designed to mirror the browser API's camelCase JSON). That
// framing is deliberate and still holds — the transport does not care which
// side of the FFI the ceremony happens on, so none of this changes below.
//
// What DID change: the claim that used to sit here — "the ceremony runs in the
// frontend via `navigator.credentials`, Tauri's webview exposes it, no Rust
// crate needed" — is false on Apple platforms. WKWebView does not support FIDO2
// security keys for WebAuthn at all, confirmed by hardware test 2026-07-29.
// [T:developers.yubico.com/WebAuthn/Supporting_FIDO2_Security_Keys_on_iOS_or_iPadOS/FAQ]
// macOS/iOS therefore drive the ceremony through native AuthenticationServices
// and feed the same JSON back through these functions. See
// `client/docs/webauthn-security-key-decision.md`.

/// `GET /api/v1/stepup/webauthn/status` — whether the caller has any
/// registered security key.
pub async fn webauthn_status(
    http: &reqwest::Client,
    base_url: &str,
    session_token: &str,
) -> Result<bool, ApiError> {
    #[derive(serde::Deserialize)]
    struct Resp {
        registered: bool,
    }
    let r: Resp = get_json(
        http,
        base_url,
        "/api/v1/stepup/webauthn/status",
        session_token,
    )
    .await?;
    Ok(r.registered)
}

/// `POST /api/v1/stepup/webauthn/register/start` — returns the raw
/// `{state_id, options}` JSON; the frontend converts `options.publicKey` into
/// `navigator.credentials.create()`'s argument.
pub async fn webauthn_register_start(
    http: &reqwest::Client,
    base_url: &str,
    session_token: &str,
) -> Result<serde_json::Value, ApiError> {
    let resp = http
        .post(url(base_url, "/api/v1/stepup/webauthn/register/start"))
        .bearer_auth(session_token)
        .timeout(CP_REST_TIMEOUT)
        .send()
        .await
        .map_err(|e| ApiError::Transport(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(status_error(resp).await);
    }
    resp.json::<serde_json::Value>()
        .await
        .map_err(|e| ApiError::Decode(e.to_string()))
}

/// `POST /api/v1/stepup/webauthn/register/finish` — `credential` is the
/// frontend's base64url-encoded `RegisterPublicKeyCredential` JSON, opaque here.
pub async fn webauthn_register_finish(
    http: &reqwest::Client,
    base_url: &str,
    session_token: &str,
    state_id: &str,
    credential: serde_json::Value,
    label: Option<&str>,
) -> Result<(), ApiError> {
    let resp = http
        .post(url(base_url, "/api/v1/stepup/webauthn/register/finish"))
        .bearer_auth(session_token)
        .json(&serde_json::json!({
            "state_id": state_id,
            "credential": credential,
            "label": label,
        }))
        .timeout(CP_REST_TIMEOUT)
        .send()
        .await
        .map_err(|e| ApiError::Transport(e.to_string()))?;
    expect_ok(resp).await
}

/// `POST /api/v1/stepup/webauthn/authenticate/start` — returns the raw
/// `{state_id, options}` JSON for `navigator.credentials.get()`.
pub async fn webauthn_authenticate_start(
    http: &reqwest::Client,
    base_url: &str,
    session_token: &str,
) -> Result<serde_json::Value, ApiError> {
    let resp = http
        .post(url(base_url, "/api/v1/stepup/webauthn/authenticate/start"))
        .bearer_auth(session_token)
        .timeout(CP_REST_TIMEOUT)
        .send()
        .await
        .map_err(|e| ApiError::Transport(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(status_error(resp).await);
    }
    resp.json::<serde_json::Value>()
        .await
        .map_err(|e| ApiError::Decode(e.to_string()))
}

/// Same exchange as `verify_step_up`/`verify_step_up_totp`, against a WebAuthn
/// assertion (AAL3). `credential` is the frontend's base64url-encoded
/// `PublicKeyCredential` JSON.
pub async fn verify_step_up_webauthn(
    http: &reqwest::Client,
    base_url: &str,
    session_token: &str,
    purpose: &str,
    state_id: &str,
    credential: serde_json::Value,
) -> Result<String, ApiError> {
    post_stepup_verify(
        http,
        base_url,
        session_token,
        &serde_json::json!({
            "factor": "webauthn",
            "purpose": purpose,
            "state_id": state_id,
            "credential": credential,
        }),
    )
    .await
}

/// `GET /api/v1/stepup/platform-key/status` — whether the caller has a
/// registered Secure Enclave (Touch ID/Face ID) key, mirroring
/// `webauthn_status`/`totp_status`.
pub async fn platform_key_status(
    http: &reqwest::Client,
    base_url: &str,
    session_token: &str,
) -> Result<bool, ApiError> {
    #[derive(serde::Deserialize)]
    struct Resp {
        registered: bool,
    }
    let r: Resp = get_json(
        http,
        base_url,
        "/api/v1/stepup/platform-key/status",
        session_token,
    )
    .await?;
    Ok(r.registered)
}

/// One enrolled step-up factor as the settings screen needs to show it.
/// `id` is the server's `key_id` (biometric) or `credential_id` (security key) —
/// the handle the DELETE endpoint takes.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StepUpFactor {
    pub id: String,
    pub label: Option<String>,
    pub created_at: Option<String>,
    pub last_used_at: Option<String>,
}

/// List the caller's enrolled Touch ID/Face ID keys.
///
/// Deliberately calls the OLD `platform-key/status` path, not the clearer
/// `biometric/status` alias. Regional control planes update independently, and a
/// region that has not pulled the rename yet would 404 the new path — whereas the
/// old one answers on both, and on a pre-rename server simply returns no `keys`
/// field, which `serde(default)` turns into an empty list. Degrading to "no keys
/// to show" beats an error the user cannot act on. The DELETE below has no such
/// choice: it only ever existed under the clear name.
pub async fn platform_key_list(
    http: &reqwest::Client,
    base_url: &str,
    session_token: &str,
) -> Result<Vec<StepUpFactor>, ApiError> {
    #[derive(serde::Deserialize)]
    struct Key {
        key_id: String,
        label: Option<String>,
        created_at: Option<String>,
        last_used_at: Option<String>,
    }
    #[derive(serde::Deserialize)]
    struct Resp {
        #[serde(default)]
        keys: Vec<Key>,
    }
    let r: Resp = get_json(
        http,
        base_url,
        "/api/v1/stepup/platform-key/status",
        session_token,
    )
    .await?;
    Ok(r.keys
        .into_iter()
        .map(|k| StepUpFactor {
            id: k.key_id,
            label: k.label,
            created_at: k.created_at,
            last_used_at: k.last_used_at,
        })
        .collect())
}

/// List the caller's enrolled FIDO2 security keys. Same path reasoning as
/// `platform_key_list`.
pub async fn security_key_list(
    http: &reqwest::Client,
    base_url: &str,
    session_token: &str,
) -> Result<Vec<StepUpFactor>, ApiError> {
    #[derive(serde::Deserialize)]
    struct Cred {
        credential_id: String,
        label: Option<String>,
        created_at: Option<String>,
        last_used_at: Option<String>,
    }
    #[derive(serde::Deserialize)]
    struct Resp {
        #[serde(default)]
        credentials: Vec<Cred>,
    }
    let r: Resp = get_json(
        http,
        base_url,
        "/api/v1/stepup/webauthn/status",
        session_token,
    )
    .await?;
    Ok(r.credentials
        .into_iter()
        .map(|c| StepUpFactor {
            id: c.credential_id,
            label: c.label,
            created_at: c.created_at,
            last_used_at: c.last_used_at,
        })
        .collect())
}

async fn delete_factor(
    http: &reqwest::Client,
    base_url: &str,
    session_token: &str,
    path: String,
    proof_token: Option<&str>,
) -> Result<(), ApiError> {
    let base = url(base_url, &path);
    let endpoint = match proof_token {
        Some(p) => format!("{base}?proof_token={p}"),
        None => base,
    };
    let resp = http
        .delete(endpoint)
        .bearer_auth(session_token)
        .timeout(CP_REST_TIMEOUT)
        .send()
        .await
        .map_err(|e| ApiError::Transport(e.to_string()))?;
    expect_ok(resp).await
}

/// Remove one Touch ID/Face ID key from the account.
/// `DELETE /api/v1/stepup/biometric/{key_id}` — gated on a `manage_auth_factor`
/// proof, which is single-use, so one ceremony removes exactly one key.
pub async fn platform_key_delete(
    http: &reqwest::Client,
    base_url: &str,
    session_token: &str,
    key_id: &str,
    proof_token: Option<&str>,
) -> Result<(), ApiError> {
    let path = format!("/api/v1/stepup/biometric/{}", key_id.trim_matches('/'));
    delete_factor(http, base_url, session_token, path, proof_token).await
}

/// Remove one FIDO2 security key from the account. Same gate; the server refuses
/// with 409 if this is the last key and the plan floors at AAL3, since nothing
/// weaker could then authorize registering a replacement.
pub async fn security_key_delete(
    http: &reqwest::Client,
    base_url: &str,
    session_token: &str,
    credential_id: &str,
    proof_token: Option<&str>,
) -> Result<(), ApiError> {
    let path = format!(
        "/api/v1/stepup/security-key/{}",
        credential_id.trim_matches('/')
    );
    delete_factor(http, base_url, session_token, path, proof_token).await
}

/// `POST /api/v1/stepup/platform-key/register` — `public_key` is the
/// base64-standard SEC1-uncompressed P-256 point the platform layer just
/// created in the Secure Enclave (biometryCurrentSet, no passcode fallback).
pub async fn platform_key_register(
    http: &reqwest::Client,
    base_url: &str,
    session_token: &str,
    public_key_b64: &str,
    label: Option<&str>,
) -> Result<(), ApiError> {
    let resp = http
        .post(url(base_url, "/api/v1/stepup/platform-key/register"))
        .bearer_auth(session_token)
        .json(&serde_json::json!({
            "public_key": public_key_b64,
            "label": label,
        }))
        .timeout(CP_REST_TIMEOUT)
        .send()
        .await
        .map_err(|e| ApiError::Transport(e.to_string()))?;
    expect_ok(resp).await
}

/// `POST /api/v1/stepup/platform-key/challenge` — mints a nonce for the
/// platform layer to sign with Touch ID/Face ID. Returns `(challenge_id,
/// nonce_b64)`.
pub async fn platform_key_challenge(
    http: &reqwest::Client,
    base_url: &str,
    session_token: &str,
    purpose: &str,
) -> Result<(String, String), ApiError> {
    #[derive(serde::Deserialize)]
    struct Resp {
        challenge_id: String,
        nonce: String,
    }
    let resp = http
        .post(url(base_url, "/api/v1/stepup/platform-key/challenge"))
        .bearer_auth(session_token)
        .json(&serde_json::json!({ "purpose": purpose }))
        .timeout(CP_REST_TIMEOUT)
        .send()
        .await
        .map_err(|e| ApiError::Transport(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(status_error(resp).await);
    }
    let r: Resp = resp
        .json()
        .await
        .map_err(|e| ApiError::Decode(e.to_string()))?;
    Ok((r.challenge_id, r.nonce))
}

/// Same exchange as `verify_step_up_webauthn`, against a Touch ID/Face ID
/// Secure Enclave signature (AAL2 — see StepUpVerifyReq::PlatformKey doc for
/// why this isn't AAL3). `signature_b64` is base64-standard ASN.1/DER
/// ECDSA-P256-SHA256 over the challenge's raw nonce bytes.
pub async fn verify_step_up_platform_key(
    http: &reqwest::Client,
    base_url: &str,
    session_token: &str,
    purpose: &str,
    challenge_id: &str,
    signature_b64: &str,
) -> Result<String, ApiError> {
    post_stepup_verify(
        http,
        base_url,
        session_token,
        &serde_json::json!({
            "factor": "platform_key",
            "purpose": purpose,
            "challenge_id": challenge_id,
            "signature": signature_b64,
        }),
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A REST call against a server that accepts and then never responds must
    /// fail within CP_REST_TIMEOUT (300ms under cfg(test)) instead of hanging
    /// forever — the 21h production-node wedge regression (2026-07-04). The
    /// listener deliberately never writes a byte.
    #[tokio::test]
    async fn rest_call_times_out_against_hanging_server() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        // Keep accepted sockets open (never respond) until the test ends.
        let _hold = tokio::spawn(async move {
            let mut held = Vec::new();
            loop {
                if let Ok((sock, _)) = listener.accept().await {
                    held.push(sock);
                }
            }
        });

        let http = reqwest::Client::new();
        let started = std::time::Instant::now();
        let err = peers(&http, &format!("http://{addr}"), "token")
            .await
            .unwrap_err();
        assert!(
            matches!(err, ApiError::Transport(_)),
            "expected timeout as Transport error, got {err:?}"
        );
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "call must be bounded by CP_REST_TIMEOUT, took {:?}",
            started.elapsed()
        );
    }

    /// A refused email-OTP downgrade must arrive as its own variant, not as a
    /// generic server error. The GUI branches on it to stop the flow; when it was
    /// indistinguishable from a transient send failure the user got a code box
    /// that no code could ever satisfy.
    #[tokio::test]
    async fn refused_email_downgrade_maps_to_its_own_variant() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            let (mut sock, _) = listener.accept().await.unwrap();
            // The control plane's exact refusal: 409 + the machine-readable flag.
            let body = r#"{"error":"a stronger sign-in method is enrolled; use it. Email codes are recovery-only.","strong_factor_required":true}"#;
            let resp = format!(
                "HTTP/1.1 409 Conflict\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = sock.write_all(resp.as_bytes()).await;
            let _ = sock.shutdown().await;
        });

        let http = reqwest::Client::new();
        let err = request_step_up(&http, &format!("http://{addr}"), "token", "enroll_node")
            .await
            .unwrap_err();
        let ApiError::StrongFactorRequired { message } = &err else {
            panic!("expected StrongFactorRequired, got {err:?}");
        };
        assert!(
            message.contains("recovery-only"),
            "the server's own sentence must survive: {message}"
        );
        assert!(
            err.to_string().starts_with("STRONG_FACTOR_REQUIRED:"),
            "the GUI matches on this sentinel: {err}"
        );
    }

    /// broker_client accepts a real CA PEM (rcgen-generated, no network) and
    /// builds a client — proving PEM parse + rustls root-store wiring compile
    /// into a working builder. TLS handshake itself = staging E2E (Step 2).
    #[test]
    fn broker_client_builds_from_generated_ca() {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec![]).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_pem = params.self_signed(&key).unwrap().pem();
        broker_client(&ca_pem, None).expect("client from valid CA PEM");
    }

    #[test]
    fn broker_client_rejects_garbage_ca() {
        let err = broker_client("not a pem", None).unwrap_err();
        assert!(matches!(err, ApiError::Transport(_)), "got {err:?}");
    }

    // Network tests: hit the live control-plane. Run explicitly on a host that can
    // reach it: `cargo test -p agent-core -- --ignored`. A bogus token must be
    // rejected, proving URL + auth header + error mapping are correct.
    #[tokio::test]
    #[ignore = "network: requires reachable control-plane"]
    async fn enroll_without_valid_token_is_rejected() {
        let http = reqwest::Client::new();
        let req = EnrollRequest {
            public_key: "x".into(),
            hostname: "h".into(),
            endpoint: None,
            workload_kind: None,
            platform: None,
            machine_proof: None,
            caps: vec![],
        };
        let err = enroll(&http, "https://cp.ankayma.com", "bogus-token", &req)
            .await
            .unwrap_err();
        // CP returns 401 with a JSON error body → mapped to Server{..}; a bare
        // Status(401) would mean the body was absent/unreadable. Both = rejected.
        assert!(
            matches!(
                err,
                ApiError::Status(401 | 400)
                    | ApiError::Server {
                        status: 401 | 400,
                        ..
                    }
            ),
            "expected auth rejection, got {err:?}"
        );
    }

    // A bogus join token must be rejected (401) — proving the no-auth join-enroll
    // URL + body + error mapping are correct.
    #[tokio::test]
    #[ignore = "network: requires reachable control-plane"]
    async fn join_enroll_with_bogus_token_is_rejected() {
        let http = reqwest::Client::new();
        let req = JoinEnrollRequest {
            join_token: "bogus-token".into(),
            public_key: "x".into(),
            hostname: "h".into(),
            endpoint: None,
            workload_kind: None,
            platform: None,
            machine_proof: None,
            caps: vec![],
        };
        let err = enroll_via_join_token(&http, "https://cp.ankayma.com", &req)
            .await
            .unwrap_err();
        // Same mapping note as above: 401 + JSON error body → Server{..}.
        assert!(
            matches!(
                err,
                ApiError::Status(401 | 400)
                    | ApiError::Server {
                        status: 401 | 400,
                        ..
                    }
            ),
            "expected token rejection, got {err:?}"
        );
    }

    /// E-3 live roundtrip: mint a join link (sender half) → redeem it with a
    /// fresh keypair (recipient half) → same `EnrollResponse` shape as E-2,
    /// incl. Layer 2 cert fields = None while the CP pre-dates Layer 2 → delete
    /// the test node again (E-4) so the roster stays clean.
    /// Run: ANKAYMA_SESSION_TOKEN=<live session> cargo test -p agent-core --lib -- --ignored join_enroll_live
    #[tokio::test]
    #[ignore = "network+credential: set ANKAYMA_SESSION_TOKEN to a live session token"]
    async fn join_enroll_live_roundtrip_creates_and_deletes_node() {
        let session = std::env::var("ANKAYMA_SESSION_TOKEN")
            .expect("set ANKAYMA_SESSION_TOKEN to run this test");
        let http = reqwest::Client::new();
        let base = "https://cp.ankayma.com";

        let link = issue_join_token(&http, base, &session, None, None)
            .await
            .expect("mint join link (E-3 sender half)");
        // ankayma://join?token=… — keep only the token value.
        let token = link
            .split("token=")
            .nth(1)
            .expect("join link carries token=")
            .split('&')
            .next()
            .unwrap()
            .to_string();

        let kp = crypto::WgKeypair::generate();
        let resp = enroll_via_join_token(
            &http,
            base,
            &JoinEnrollRequest {
                join_token: token,
                public_key: kp.public_b64,
                hostname: "layer2-regression-e3".into(),
                endpoint: None,
                workload_kind: None,
                platform: None,
                machine_proof: None,
                caps: vec![],
            },
        )
        .await
        .expect("redeem join link (E-3 recipient half)");

        assert!(!resp.overlay_ip.is_empty());
        assert!(
            resp.node_service_token.is_some(),
            "post-migration-015 CP returns a node service token"
        );
        // CP pre-Layer-2: cert fields absent → None (P.4 backward compat).
        assert_eq!(resp.node_cert_pem, None);
        assert_eq!(resp.provisioning_ca_pem, None);
        assert_eq!(resp.crl_url, None);

        delete_node(&http, base, &session, &resp.node_id, None)
            .await
            .expect("delete the test node (E-4)");
    }

    #[tokio::test]
    #[ignore = "network: requires reachable control-plane"]
    async fn session_with_bogus_token_is_unauthorized() {
        let http = reqwest::Client::new();
        let err = session_info(&http, "https://cp.ankayma.com", "bogus-token")
            .await
            .unwrap_err();
        assert!(matches!(err, ApiError::Status(401)), "got {err:?}");
    }
}
