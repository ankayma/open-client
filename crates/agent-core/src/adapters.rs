//! adapters — concrete port impls (control-plane HTTP, WireGuard, NATS, OIDC).

use crate::domain::{
    AgentEnrollRequest, AgentEnrollResponse, CiDeployRequest, CiDeployResponse, CiPolicy,
    CiPolicyReq, EnrollRequest, EnrollResponse, MembersView, MyAccess, PeerInfo, PolicyView, Quota,
    ResolveTable, SessionInfo, SshSessionRequest, SshSessionResponse, Subdomain, SubdomainReq,
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
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApiError::Transport(e) => write!(f, "control-plane transport error: {e}"),
            ApiError::Status(s) => write!(f, "control-plane returned HTTP {s}"),
            ApiError::Server { message, .. } => write!(f, "{message}"),
            ApiError::Decode(e) => write!(f, "control-plane decode error: {e}"),
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

/// Fetch the current mesh roster. `GET /api/v1/peers`. `[T:B.5.1]`
/// Used to discover peers that enrolled *after* this node did, so a long-running
/// agent's view of the mesh stays fresh without re-enrolling (which would create
/// a new node each time — the control plane does not dedup by public key).
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
/// /api/v1/enrollment/token` (session-authed); the control plane sets the TTL
/// (15 min). Returns the `ankayma://join?…` URL. `[T:A.1.10/A.1.22 enrollment]`
pub async fn issue_join_token(
    http: &reqwest::Client,
    base_url: &str,
    session_token: &str,
) -> Result<String, ApiError> {
    let resp = http
        .post(url(base_url, "/api/v1/enrollment/token"))
        .bearer_auth(session_token)
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

/// Mint a member invite (admin). Returns the `ankayma://join-team?…` URL.
pub async fn invite_member(
    http: &reqwest::Client,
    base_url: &str,
    session_token: &str,
) -> Result<String, ApiError> {
    #[derive(serde::Deserialize)]
    struct Resp {
        url: String,
    }
    let resp = http
        .post(url(base_url, "/api/v1/members/invite"))
        .bearer_auth(session_token)
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
        .send()
        .await
        .map_err(|e| ApiError::Transport(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(status_error(resp).await);
    }
    Ok(())
}

/// Remove a member (admin). `DELETE /api/v1/members/{user_id}`.
pub async fn remove_member(
    http: &reqwest::Client,
    base_url: &str,
    session_token: &str,
    user_id: &str,
) -> Result<(), ApiError> {
    let resp = http
        .delete(url(base_url, &format!("/api/v1/members/{user_id}")))
        .bearer_auth(session_token)
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
    }
    match resp.json::<ErrBody>().await {
        Ok(ErrBody { error: Some(m) }) if !m.trim().is_empty() => ApiError::Server {
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

/// Create or update a CI/CD deploy policy (server upserts by `repo`).
/// `POST /api/v1/ci/policy`. Safe-by-default is server-enforced. `[T:Part C §H.3.3]`
pub async fn register_ci_policy(
    http: &reqwest::Client,
    base_url: &str,
    session_token: &str,
    req: &CiPolicyReq,
) -> Result<(), ApiError> {
    let resp = http
        .post(url(base_url, "/api/v1/ci/policy"))
        .bearer_auth(session_token)
        .json(req)
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
) -> Result<(), ApiError> {
    let path = format!("/api/v1/ci/policy/{}", repo.trim_matches('/'));
    let resp = http
        .delete(url(base_url, &path))
        .bearer_auth(session_token)
        .send()
        .await
        .map_err(|e| ApiError::Transport(e.to_string()))?;
    expect_ok(resp).await
}

/// Remove one of the tenant's own mesh nodes (retire a device).
/// `DELETE /api/v1/nodes/{id}` (session-authed, tenant-scoped). `[T:A.1.6]`
pub async fn delete_node(
    http: &reqwest::Client,
    base_url: &str,
    session_token: &str,
    node_id: &str,
) -> Result<(), ApiError> {
    let resp = http
        .delete(url(base_url, &format!("/api/v1/nodes/{node_id}")))
        .bearer_auth(session_token)
        .send()
        .await
        .map_err(|e| ApiError::Transport(e.to_string()))?;
    expect_ok(resp).await
}

#[cfg(test)]
mod tests {
    use super::*;

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
        };
        let err = enroll(&http, "https://cp.ankayma.com", "bogus-token", &req)
            .await
            .unwrap_err();
        assert!(
            matches!(err, ApiError::Status(401) | ApiError::Status(400)),
            "expected auth rejection, got {err:?}"
        );
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
