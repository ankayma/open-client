// GUI shell — thin Tauri command layer.
// [T:A.1.1] All control-plane I/O goes through agent-core; the GUI never talks
// to the control plane directly. WireGuard tunnel bring-up is still pending
// (boringtun, milestone 1.2 slice 5) — connect/* commands remain stubs.

use std::sync::Mutex;

use agent_core::{adapters, domain, reqwest};
use serde::{Deserialize, Serialize};
use tauri::{Manager, State};

/// Default control plane; override with ANKAYMA_CONTROL_PLANE for dev/staging.
const DEFAULT_CONTROL_PLANE: &str = "https://cp.ankayma.com";

/// Process-wide app state: one HTTP client + the current session token.
struct AppState {
    http: reqwest::Client,
    base_url: String,
    session: Mutex<Option<String>>,
}

impl AppState {
    fn new() -> Self {
        let base_url = std::env::var("ANKAYMA_CONTROL_PLANE")
            .unwrap_or_else(|_| DEFAULT_CONTROL_PLANE.to_string());
        AppState {
            http: reqwest::Client::new(),
            base_url,
            session: Mutex::new(None),
        }
    }

    fn token(&self) -> Option<String> {
        self.session.lock().expect("session lock poisoned").clone()
    }

    fn set_token(&self, tok: Option<String>) {
        *self.session.lock().expect("session lock poisoned") = tok;
    }
}

// --- Domain types (mirror Part B §B.1 subset needed by GUI) ---

#[derive(Serialize, Deserialize, Clone)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum AuthState {
    Unauthenticated,
    Authenticating,
    Authenticated { user: User },
}

#[derive(Serialize, Deserialize, Clone)]
pub struct User {
    pub tenant_id: String,
    pub email: String,
    pub tier: String,         // "F0" | "F0Plus"
    pub product_line: String, // this control plane is the Personal PL
}

impl From<domain::SessionInfo> for User {
    fn from(s: domain::SessionInfo) -> Self {
        User {
            tenant_id: s.tenant_id,
            email: s.email,
            tier: s.tier,
            product_line: "Personal".into(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Connected { node_id: String, endpoint: String },
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Quota {
    pub bandwidth_bytes_used: u64,
    pub bandwidth_bytes_limit: u64,
    pub nodes_used: u32,
    pub nodes_limit: u32,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct NodeInfo {
    pub node_id: String,
    pub hostname: String,
    pub public_key: String,
}

// --- Commands ---

#[tauri::command]
async fn check_auth_state(state: State<'_, AppState>) -> Result<AuthState, String> {
    match state.token() {
        None => Ok(AuthState::Unauthenticated),
        // Re-validate the stored token against the control plane.
        Some(tok) => match adapters::session_info(&state.http, &state.base_url, &tok).await {
            Ok(s) => Ok(AuthState::Authenticated { user: s.into() }),
            Err(_) => {
                state.set_token(None);
                Ok(AuthState::Unauthenticated)
            }
        },
    }
}

#[tauri::command]
async fn sign_in_github(state: State<'_, AppState>) -> Result<(), String> {
    // Open the system browser to the control-plane OAuth start. After GitHub,
    // the page shows a session token to paste back via submit_session_token.
    let url = format!("{}/auth/github", state.base_url.trim_end_matches('/'));
    open::that(&url).map_err(|e| format!("could not open browser: {e}"))
}

#[tauri::command]
async fn submit_session_token(
    token: String,
    state: State<'_, AppState>,
) -> Result<AuthState, String> {
    let token = token.trim().to_string();
    if token.is_empty() {
        return Err("session token is empty".into());
    }
    // Validate by fetching the session; only store the token if it works.
    let info = adapters::session_info(&state.http, &state.base_url, &token)
        .await
        .map_err(|e| e.to_string())?;
    state.set_token(Some(token));
    Ok(AuthState::Authenticated { user: info.into() })
}

#[tauri::command]
async fn sign_out(state: State<'_, AppState>) -> Result<(), String> {
    state.set_token(None);
    Ok(())
}

#[tauri::command]
async fn get_quota(state: State<'_, AppState>) -> Result<Quota, String> {
    let tok = state.token().ok_or("not signed in")?;
    let q = adapters::quota(&state.http, &state.base_url, &tok)
        .await
        .map_err(|e| e.to_string())?;
    Ok(Quota {
        bandwidth_bytes_used: q.bandwidth_bytes_used,
        bandwidth_bytes_limit: q.bandwidth_bytes_limit,
        nodes_used: q.nodes_used,
        nodes_limit: q.nodes_limit,
    })
}

// --- Still stubs: need the WireGuard tunnel (boringtun, slice 5) ---

#[tauri::command]
async fn get_connection_status() -> Result<ConnectionState, String> {
    // [A] stub — query agent-core daemon once the tunnel exists (slice 5)
    Ok(ConnectionState::Disconnected)
}

#[tauri::command]
async fn connect() -> Result<(), String> {
    // [A] stub — enroll + boringtun bring-up pending (slice 5)
    Err("Not yet implemented — WireGuard tunnel pending (boringtun)".into())
}

#[tauri::command]
async fn disconnect() -> Result<(), String> {
    Ok(())
}

#[tauri::command]
async fn get_node_info() -> Result<NodeInfo, String> {
    // [A] stub — populated from enrollment once connect() is wired (slice 5)
    Ok(NodeInfo {
        node_id: "node_placeholder".into(),
        hostname: "my-device".into(),
        public_key: "[A] pending enrollment".into(),
    })
}

#[tauri::command]
async fn create_join_link() -> Result<String, String> {
    // [A] stub — POST /api/v1/enrollment/token (slice 4b)
    Err("Not yet implemented — enrollment token pending".into())
}

#[tauri::command]
async fn track_event(
    name: String,
    props: std::collections::HashMap<String, String>,
) -> Result<(), String> {
    // [A] stub — analytics relay pending (milestone 1.2 signal acquisition)
    let _ = (name, props);
    Ok(())
}

#[tauri::command]
async fn open_stripe_checkout() -> Result<(), String> {
    // [A] stub — Stripe integration pending (milestone 1.3)
    Err("Not yet implemented — Stripe pending (milestone 1.3)".into())
}

// --- App entry point ---

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            app.manage(AppState::new());
            if cfg!(debug_assertions) {
                app.handle().plugin(
                    tauri_plugin_log::Builder::default()
                        .level(log::LevelFilter::Info)
                        .build(),
                )?;
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            check_auth_state,
            sign_in_github,
            submit_session_token,
            sign_out,
            get_connection_status,
            connect,
            disconnect,
            get_quota,
            get_node_info,
            create_join_link,
            track_event,
            open_stripe_checkout,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
