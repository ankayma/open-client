//! adapters — concrete port impls (control-plane HTTP, WireGuard, NATS, OIDC).

use crate::domain::{
    AgentEnrollRequest, AgentEnrollResponse, CiDeployRequest, CiDeployResponse, CiPolicy,
    CiPolicyReq, CiRun, EnrollRequest, EnrollResponse, MembersView, MyAccess, NodeBrief, PeerInfo,
    PolicyView, Quota, ResolveTable, SessionInfo, SshSessionRequest, SshSessionResponse, Subdomain,
    SubdomainCert, SubdomainCsrReq, SubdomainReq,
};

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
    /// [T:part-d-e7-stepup.md §H.5]
    StepUpRequired { purpose: String, required_aal: i32 },
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

/// Validate a session token and fetch the signed-in user. `GET /api/v1/session`.
pub async fn session_info(
    http: &reqwest::Client,
    base_url: &str,
    session_token: &str,
) -> Result<SessionInfo, ApiError> {
    get_json(http, base_url, "/api/v1/session", session_token).await
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
/// public web-PKI cert. `[T:part-d-layer2-cert-infrastructure.md §H.2 Step 1]`
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
    /// See `domain::EnrollRequest::machine_proof`. Redeeming an invite also lifts an
    /// administrator's revocation of this device — the invite IS the re-admission.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub machine_proof: Option<String>,
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
) -> Result<String, ApiError> {
    #[derive(serde::Deserialize)]
    struct Resp {
        fqdn: String,
    }
    let resp = http
        .post(url(base_url, "/api/v1/subdomain"))
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
    service_token: &str,
    fqdn: &str,
    csr_pem: &str,
) -> Result<(), ApiError> {
    let req = SubdomainCsrReq {
        csr_pem: csr_pem.to_string(),
    };
    let resp = http
        .post(url(base_url, &format!("/api/v1/subdomain/{fqdn}/csr")))
        .bearer_auth(service_token)
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
) -> Result<(), ApiError> {
    let resp = http
        .delete(url(base_url, &format!("/api/v1/subdomain/{label}")))
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

/// Mint a member invite (admin). `ttl_seconds` optionally overrides the server's
/// default member-invite TTL (clamped server-side). Gated behind a step-up proof
/// (M-1 — part-d-e7-stepup.md H.2#6). Returns the `ankayma://join-team?…` URL.
pub async fn invite_member(
    http: &reqwest::Client,
    base_url: &str,
    session_token: &str,
    email: &str,
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
pub async fn join_team_link(
    http: &reqwest::Client,
    base_url: &str,
    token: &str,
) -> Result<String, ApiError> {
    #[derive(serde::Deserialize)]
    struct Resp {
        token: String,
    }
    let resp = http
        .post(url(base_url, "/api/v1/members/join-link"))
        .json(&serde_json::json!({ "token": token }))
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
/// step-up proof (M-4 — part-d-e7-stepup.md H.2#7).
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
) -> Result<(), ApiError> {
    let resp = http
        .post(url(base_url, "/api/v1/policies"))
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

/// Open an SSE stream for peer events. `GET /api/v1/peers/events`.
/// Authenticated with the node service token (not the user session token).
/// Returns the raw response; the caller reads it as a byte stream.
/// [T:Part D §D.12]
pub async fn subscribe_peer_events(
    http: &reqwest::Client,
    base_url: &str,
    node_service_token: &str,
) -> Result<reqwest::Response, ApiError> {
    // NO .timeout() here — reqwest's per-request timeout spans the WHOLE
    // response including the streamed body [T:reqwest@0.12-RequestBuilder::timeout],
    // so it would kill the long-lived SSE stream mid-session. Liveness is bounded
    // by the caller instead: up.rs wraps this connect in tokio::time::timeout and
    // caps each SSE session at 60s (SSE_SESSION_CAP) before a full resync.
    let resp = http
        .get(url(base_url, "/api/v1/peers/events"))
        .bearer_auth(node_service_token)
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
    current_service_token: &str,
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
        .bearer_auth(current_service_token)
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
/// re-verifying `challenge_id`/`code` inline. [T:part-d-e7-stepup.md §H.5]
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
/// trip. [T:part-d-e7-stepup.md §H.8 Phase 2]
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

/// `POST /api/v1/stepup/totp/confirm` — prove the enrolled secret works;
/// returns the 10 one-time backup codes (H.9 recovery), shown once.
pub async fn totp_confirm(
    http: &reqwest::Client,
    base_url: &str,
    session_token: &str,
    code: &str,
) -> Result<Vec<String>, ApiError> {
    #[derive(serde::Deserialize)]
    struct Resp {
        backup_codes: Vec<String>,
    }
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
    resp.json::<Resp>()
        .await
        .map(|r| r.backup_codes)
        .map_err(|e| ApiError::Decode(e.to_string()))
}

// ── WebAuthn / YubiKey (E-7 StepUp Phase 3 — AAL3) ────────────────────────────
// The actual register/assert ceremony runs in the frontend via the browser's
// `navigator.credentials` API (Tauri's webview exposes it — no Rust crate
// needed here). These adapters are opaque JSON pass-throughs between that
// frontend code and the control plane; the shapes match webauthn-rs's own
// wire format 1:1 (it's designed to mirror the browser API's camelCase JSON).

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
            machine_proof: None,
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
            machine_proof: None,
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
                machine_proof: None,
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
