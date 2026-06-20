//! `oidc` — fetch a CI OIDC identity token for secretless deploy (Part C §H.3.3,
//! feature B-3). OPEN.
//!
//! The token is a short-lived JWT the CI platform mints to prove "this run is repo
//! X, ref Y". The agent only *obtains and forwards* it; the control plane verifies
//! it (closed). No static secret is ever stored in CI. `[T:A.1.4 golden rule]`
//!
//! Two ways a runner exposes the token:
//!   * **GitHub Actions** — an HTTP endpoint (`ACTIONS_ID_TOKEN_REQUEST_URL`) plus a
//!     one-time bearer (`ACTIONS_ID_TOKEN_REQUEST_TOKEN`); we mint with our audience.
//!   * **GitLab CI / others** — the runner injects the JWT directly into an env var
//!     (`id_tokens:` in `.gitlab-ci.yml`), already bound to our audience.
//!
//! `detect_source` is pure (env accessor injected) so the branching is unit-tested
//! without a live runner; `fetch_ci_token` is the one network call.

use anyhow::{anyhow, bail, Context, Result};
use serde::Deserialize;

/// Where this runner's OIDC token comes from.
#[derive(Debug, PartialEq, Eq)]
pub enum CiTokenSource {
    /// GitHub Actions: must HTTP-GET the request URL with the request bearer.
    GitHubActions {
        request_url: String,
        request_token: String,
    },
    /// The forge already injected a ready JWT into the environment.
    PreInjected { token: String },
}

/// Env var names checked, in priority order, for a pre-injected JWT.
const PREINJECTED_VARS: [&str; 2] = ["ANKAYMA_ID_TOKEN", "ANKAYMA_TOKEN"];

/// Decide the token source from environment. Pure — caller supplies `get`.
/// GitHub Actions takes priority (its pair is unambiguous); otherwise a
/// pre-injected JWT var; otherwise an error explaining what to configure.
pub fn detect_source(get: impl Fn(&str) -> Option<String>) -> Result<CiTokenSource> {
    let gh_url = get("ACTIONS_ID_TOKEN_REQUEST_URL").filter(|s| !s.is_empty());
    let gh_tok = get("ACTIONS_ID_TOKEN_REQUEST_TOKEN").filter(|s| !s.is_empty());
    if let (Some(request_url), Some(request_token)) = (gh_url, gh_tok) {
        return Ok(CiTokenSource::GitHubActions {
            request_url,
            request_token,
        });
    }
    for var in PREINJECTED_VARS {
        if let Some(token) = get(var).filter(|s| !s.is_empty()) {
            return Ok(CiTokenSource::PreInjected { token });
        }
    }
    bail!(
        "no CI OIDC token found. On GitHub Actions add `permissions: id-token: write`; \
         on GitLab set an `id_tokens:` entry exporting ANKAYMA_ID_TOKEN (aud=ankayma-deploy)."
    )
}

#[derive(Deserialize)]
struct GhTokenResp {
    value: String,
}

/// Obtain the OIDC token for `audience`, reading the ambient CI environment.
pub async fn fetch_ci_token(http: &reqwest::Client, audience: &str) -> Result<String> {
    let source = detect_source(|k| std::env::var(k).ok())?;
    fetch_from_source(http, &source, audience).await
}

/// Resolve a token from an already-determined source (split out for clarity/testing).
pub async fn fetch_from_source(
    http: &reqwest::Client,
    source: &CiTokenSource,
    audience: &str,
) -> Result<String> {
    match source {
        CiTokenSource::PreInjected { token } => Ok(token.clone()),
        CiTokenSource::GitHubActions {
            request_url,
            request_token,
        } => {
            // The request URL already carries a query string; append our audience.
            let url = format!("{request_url}&audience={audience}");
            let resp = http
                .get(&url)
                .bearer_auth(request_token)
                .send()
                .await
                .context("request GitHub Actions OIDC token")?;
            if !resp.status().is_success() {
                bail!("GitHub OIDC token endpoint returned HTTP {}", resp.status());
            }
            let body: GhTokenResp = resp.json().await.context("parse GitHub OIDC token")?;
            if body.value.is_empty() {
                return Err(anyhow!(
                    "GitHub OIDC token endpoint returned an empty token"
                ));
            }
            Ok(body.value)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let m: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |k: &str| m.get(k).cloned()
    }

    #[test]
    fn detects_github_actions() {
        let src = detect_source(env(&[
            (
                "ACTIONS_ID_TOKEN_REQUEST_URL",
                "https://gh/oidc?api-version=1",
            ),
            ("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "reqtok"),
        ]))
        .unwrap();
        assert_eq!(
            src,
            CiTokenSource::GitHubActions {
                request_url: "https://gh/oidc?api-version=1".into(),
                request_token: "reqtok".into(),
            }
        );
    }

    #[test]
    fn detects_preinjected_gitlab() {
        let src = detect_source(env(&[("ANKAYMA_ID_TOKEN", "eyJ.jwt.sig")])).unwrap();
        assert_eq!(
            src,
            CiTokenSource::PreInjected {
                token: "eyJ.jwt.sig".into()
            }
        );
    }

    #[test]
    fn github_takes_priority_over_preinjected() {
        let src = detect_source(env(&[
            ("ACTIONS_ID_TOKEN_REQUEST_URL", "https://gh/oidc?x=1"),
            ("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "t"),
            ("ANKAYMA_ID_TOKEN", "ignored"),
        ]))
        .unwrap();
        assert!(matches!(src, CiTokenSource::GitHubActions { .. }));
    }

    #[test]
    fn errors_when_nothing_configured() {
        assert!(detect_source(env(&[])).is_err());
        // a half-configured GitHub pair must not be treated as GitHub.
        assert!(detect_source(env(&[("ACTIONS_ID_TOKEN_REQUEST_URL", "u")])).is_err());
    }

    #[tokio::test]
    async fn preinjected_returns_token_without_network() {
        let http = reqwest::Client::new();
        let src = CiTokenSource::PreInjected {
            token: "the.jwt.here".into(),
        };
        assert_eq!(
            fetch_from_source(&http, &src, "ankayma-deploy")
                .await
                .unwrap(),
            "the.jwt.here"
        );
    }
}
