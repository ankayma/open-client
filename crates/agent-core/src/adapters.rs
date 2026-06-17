//! adapters — concrete port impls (WireGuard, NATS, OIDC).

use crate::domain::{EnrollRequest, EnrollResponse};

/// Errors from the HTTP enrollment client.
#[derive(Debug)]
pub enum EnrollError {
    /// Network/transport failure.
    Transport(String),
    /// Server returned a non-2xx status.
    Status(u16),
    /// Response body could not be decoded.
    Decode(String),
}

impl std::fmt::Display for EnrollError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EnrollError::Transport(e) => write!(f, "enroll transport error: {e}"),
            EnrollError::Status(s) => write!(f, "enroll failed: HTTP {s}"),
            EnrollError::Decode(e) => write!(f, "enroll decode error: {e}"),
        }
    }
}
impl std::error::Error for EnrollError {}

/// Enroll this node with the control-plane Agent API.
/// `POST {base_url}/api/v1/enrollment` with a Bearer session token. `[T:B.5.1]`
/// `[T:A.1.1]` the control plane returns mesh metadata only — no business payload.
pub async fn enroll(
    http: &reqwest::Client,
    base_url: &str,
    session_token: &str,
    req: &EnrollRequest,
) -> Result<EnrollResponse, EnrollError> {
    let url = format!("{}/api/v1/enrollment", base_url.trim_end_matches('/'));
    let resp = http
        .post(url)
        .bearer_auth(session_token)
        .json(req)
        .send()
        .await
        .map_err(|e| EnrollError::Transport(e.to_string()))?;
    let status = resp.status();
    if !status.is_success() {
        return Err(EnrollError::Status(status.as_u16()));
    }
    resp.json::<EnrollResponse>()
        .await
        .map_err(|e| EnrollError::Decode(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Network test: hits the live control-plane. Run explicitly on a host that can
    // reach it: `cargo test -p agent-core -- --ignored`. A bogus token must be
    // rejected with 401, proving URL + auth header + error mapping are correct.
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
            matches!(err, EnrollError::Status(401) | EnrollError::Status(400)),
            "expected auth rejection, got {err:?}"
        );
    }
}
