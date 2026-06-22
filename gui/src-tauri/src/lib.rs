// GUI shell — thin Tauri command layer.
// [T:A.1.1] All control-plane I/O goes through agent-core; the GUI never talks
// to the control plane directly.
//
// `connect` performs the REAL control-plane half: generate a WireGuard keypair,
// enroll with the control plane, and receive an overlay IP + peer list. The
// data-plane half — bringing up a utun device and routing packets through
// boringtun — needs OS privileges (root on macOS) and a peer, so it runs in the
// privileged agent-daemon, not this unprivileged GUI. [A] tracked: data path.

use std::sync::Mutex;

use agent_core::domain::EnrollRequest;
use agent_core::{adapters, domain, reqwest, WgKeypair};
use serde::{Deserialize, Serialize};
use tauri::{Manager, State};

/// Default control plane; override with ANKAYMA_CONTROL_PLANE for dev/staging.
const DEFAULT_CONTROL_PLANE: &str = "https://cp.ankayma.com";

/// A node enrolled on the mesh: its WireGuard identity + assigned overlay IP +
/// the peers the control plane returned. The private key stays in-process.
struct EnrolledNode {
    /// WG private key — kept in-process for the data-plane tunnel handed to the
    /// privileged daemon (boringtun + utun). Not read yet. [A]
    #[allow(dead_code)]
    private_b64: String,
    public_b64: String,
    node_id: String,
    overlay_ip: String,
    /// Peers to dial once the tunnel is up (privileged daemon). Not read yet. [A]
    #[allow(dead_code)]
    peers: Vec<domain::PeerInfo>,
}

/// Process-wide app state: HTTP client + session token + enrolled node (if any).
struct AppState {
    http: reqwest::Client,
    base_url: String,
    session: Mutex<Option<String>>,
    node: Mutex<Option<EnrolledNode>>,
}

impl AppState {
    fn new() -> Self {
        let base_url = std::env::var("ANKAYMA_CONTROL_PLANE")
            .unwrap_or_else(|_| DEFAULT_CONTROL_PLANE.to_string());
        AppState {
            http: reqwest::Client::new(),
            base_url,
            session: Mutex::new(None),
            node: Mutex::new(None),
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

/// [F-5 / A.1.1] One mesh peer on the data path. `direct` = a reachable endpoint is
/// known, so traffic is peer-to-peer. No NAT-fallback relay exists yet.
#[derive(Serialize, Deserialize, Clone)]
pub struct PathPeer {
    pub hostname: String,
    pub overlay_ip: String,
    pub direct: bool,
    pub endpoint: Option<String>,
}

/// [F-5 "Prove it"] Path-proof: your traffic is peer-to-peer; the vendor (control
/// plane) is the control channel only, never on the data path (A.1.1).
#[derive(Serialize, Deserialize, Clone)]
pub struct PathProof {
    pub connected: bool,
    pub control_plane: String,
    /// Always false: A.1.1 keeps the vendor off the data path.
    pub vendor_on_data_path: bool,
    pub peers: Vec<PathPeer>,
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

// --- Mesh enrollment (real control-plane half of connect) ---

fn device_hostname() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| "ankayma-desktop".to_string())
}

#[tauri::command]
async fn get_connection_status(state: State<'_, AppState>) -> Result<ConnectionState, String> {
    Ok(match &*state.node.lock().expect("node lock poisoned") {
        Some(n) => ConnectionState::Connected {
            node_id: n.node_id.clone(),
            endpoint: n.overlay_ip.clone(),
        },
        None => ConnectionState::Disconnected,
    })
}

#[tauri::command]
async fn connect(state: State<'_, AppState>) -> Result<(), String> {
    let tok = state.token().ok_or("not signed in")?;
    // Idempotent: if already enrolled, connect is a no-op.
    if state.node.lock().expect("node lock poisoned").is_some() {
        return Ok(());
    }
    // Real flow: fresh WireGuard keypair → enroll → overlay IP + peers.
    let kp = WgKeypair::generate();
    let req = EnrollRequest {
        public_key: kp.public_b64.clone(),
        hostname: device_hostname(),
        endpoint: None,
    };
    let resp = adapters::enroll(&state.http, &state.base_url, &tok, &req)
        .await
        .map_err(|e| e.to_string())?;
    *state.node.lock().expect("node lock poisoned") = Some(EnrolledNode {
        private_b64: kp.private_b64,
        public_b64: kp.public_b64,
        node_id: resp.node_id,
        overlay_ip: resp.overlay_ip,
        peers: resp.peers,
    });
    // [A] data path next: hand private_b64 + peers to the privileged daemon to
    // bring up a utun device and route packets through boringtun.
    Ok(())
}

#[tauri::command]
async fn disconnect(state: State<'_, AppState>) -> Result<(), String> {
    *state.node.lock().expect("node lock poisoned") = None;
    Ok(())
}

#[tauri::command]
async fn get_node_info(state: State<'_, AppState>) -> Result<NodeInfo, String> {
    Ok(match &*state.node.lock().expect("node lock poisoned") {
        Some(n) => NodeInfo {
            node_id: n.node_id.clone(),
            hostname: device_hostname(),
            public_key: n.public_b64.clone(),
        },
        None => NodeInfo {
            node_id: "—".into(),
            hostname: device_hostname(),
            public_key: "not enrolled".into(),
        },
    })
}

/// [F-5 "Prove it"] Surface the data path for the current connection: each peer is
/// reached peer-to-peer, and the vendor is never on the data path (A.1.1). Built from
/// the enrolled node's peer list — no extra control-plane round-trip.
#[tauri::command]
async fn get_path_proof(state: State<'_, AppState>) -> Result<PathProof, String> {
    let guard = state.node.lock().expect("node lock poisoned");
    let (connected, peers) = match &*guard {
        Some(n) => {
            let peers = n
                .peers
                .iter()
                .map(|p| PathPeer {
                    hostname: p.hostname.clone(),
                    overlay_ip: p.overlay_ip.clone(),
                    // A reachable endpoint ⇒ a direct dial. No relay exists yet, so a
                    // responder-only peer (no endpoint) is still reached peer-to-peer.
                    direct: p.endpoint.is_some(),
                    endpoint: p.endpoint.clone(),
                })
                .collect();
            (true, peers)
        }
        None => (false, Vec::new()),
    };
    Ok(PathProof {
        connected,
        control_plane: state.base_url.clone(),
        // [T:A.1.1] data plane never transits the vendor — structural, not a setting.
        vendor_on_data_path: false,
        peers,
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
            get_path_proof,
            create_join_link,
            track_event,
            open_stripe_checkout,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
