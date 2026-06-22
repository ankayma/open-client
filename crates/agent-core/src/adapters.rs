//! adapters — concrete port impls (control-plane HTTP, WireGuard, NATS, OIDC).

use crate::domain::{
    AgentEnrollRequest, AgentEnrollResponse, CiDeployRequest, CiDeployResponse, EnrollRequest,
    EnrollResponse, PeerInfo, Quota, SessionInfo,
};

/// Errors from the control-plane HTTP client.
#[derive(Debug)]
pub enum ApiError {
    /// Network/transport failure.
    Transport(String),
    /// Server returned a non-2xx status.
    Status(u16),
    /// Response body could not be decoded.
    Decode(String),
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApiError::Transport(e) => write!(f, "control-plane transport error: {e}"),
            ApiError::Status(s) => write!(f, "control-plane returned HTTP {s}"),
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
    let status = resp.status();
    if !status.is_success() {
        return Err(ApiError::Status(status.as_u16()));
    }
    resp.json::<EnrollResponse>()
        .await
        .map_err(|e| ApiError::Decode(e.to_string()))
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
