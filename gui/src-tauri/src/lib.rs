// GUI shell — thin Tauri command layer.
// [T:A.1.1] All control-plane I/O goes through agent-core; the GUI never talks
// to the control plane directly.
//
// `connect` performs the REAL control-plane half: generate a WireGuard keypair,
// enroll with the control plane, and receive an overlay IP + peer list. The
// data-plane half — bringing up a utun device and routing packets through
// boringtun — needs OS privileges (root on macOS) and a peer, so it runs in the
// privileged agent-daemon, not this unprivileged GUI. [A] tracked: data path.
//
// On macOS the app is a menu-bar (tray) app modeled on Tailscale: the Dock icon
// is hidden (ActivationPolicy::Accessory) and the dropdown drives connect/status
// from the same AppState the window uses. All tray code is #[cfg(desktop)] so
// mobile (iOS/Android) is unaffected. [T:A.3.1]

use std::sync::Mutex;

use agent_core::domain::EnrollRequest;
use agent_core::{adapters, domain, reqwest, WgKeypair};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager, State};

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
    /// Peers to dial once the tunnel is up (privileged daemon). Shown in the
    /// tray "Network Devices" submenu (desktop only).
    #[cfg_attr(not(desktop), allow(dead_code))]
    peers: Vec<domain::PeerInfo>,
}

/// Process-wide app state: HTTP client + session token + enrolled node (if any).
struct AppState {
    http: reqwest::Client,
    base_url: String,
    session: Mutex<Option<String>>,
    /// Signed-in account email, surfaced in the tray menu. None when signed out.
    email: Mutex<Option<String>>,
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
            email: Mutex::new(None),
            node: Mutex::new(None),
        }
    }

    fn token(&self) -> Option<String> {
        self.session.lock().expect("session lock poisoned").clone()
    }

    fn set_token(&self, tok: Option<String>) {
        *self.session.lock().expect("session lock poisoned") = tok;
    }

    fn set_email(&self, email: Option<String>) {
        *self.email.lock().expect("email lock poisoned") = email;
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

// --- Core helpers (shared by #[tauri::command]s and the tray) ---

/// The live connection status derived from AppState — single source of truth
/// for both the window UI and the tray menu.
fn current_connection(state: &AppState) -> ConnectionState {
    match &*state.node.lock().expect("node lock poisoned") {
        Some(n) => ConnectionState::Connected {
            node_id: n.node_id.clone(),
            endpoint: n.overlay_ip.clone(),
        },
        None => ConnectionState::Disconnected,
    }
}

/// Reuse the persisted identity from the handoff file (~/.ankayma/agent.json) —
/// the SAME node the daemon uses — but only if it still exists server-side, so a
/// GUI restart/reconnect doesn't enroll a duplicate node. Returns None when there
/// is no valid file or the stored node was removed (→ caller enrolls fresh).
async fn load_handoff_node(state: &AppState, tok: &str) -> Option<EnrolledNode> {
    let home = std::env::var("HOME").ok()?;
    let path = std::path::Path::new(&home).join(".ankayma/agent.json");
    let bytes = std::fs::read(&path).ok()?;
    #[derive(serde::Deserialize)]
    struct Stored {
        private_b64: String,
        public_b64: String,
        node_id: String,
        overlay_ip: String,
    }
    let s: Stored = serde_json::from_slice(&bytes).ok()?;
    let peers = adapters::peers(&state.http, &state.base_url, tok)
        .await
        .ok()?;
    // The stored node must still be in the tenant roster (not deleted server-side),
    // else fall through to a fresh enroll instead of showing a ghost node.
    if !peers.iter().any(|p| p.node_id == s.node_id) {
        return None;
    }
    Some(EnrolledNode {
        private_b64: s.private_b64,
        public_b64: s.public_b64,
        node_id: s.node_id,
        overlay_ip: s.overlay_ip,
        peers,
    })
}

/// Real control-plane enrollment. Idempotent: reuses a persisted identity if one
/// exists; a no-op if already enrolled in-process.
async fn connect_inner(state: &AppState) -> Result<(), String> {
    let tok = state.token().ok_or("not signed in")?;
    if state.node.lock().expect("node lock poisoned").is_some() {
        return Ok(());
    }

    // Reuse the persisted identity (the daemon's node) if it still exists — so a
    // GUI restart/reconnect does NOT enroll a duplicate node. Only enroll fresh
    // when there is no valid identity. [T:A.1.10]
    if let Some(node) = load_handoff_node(state, &tok).await {
        *state.node.lock().expect("node lock poisoned") = Some(node);
        return Ok(());
    }

    // Fresh: new WireGuard keypair → enroll → overlay IP + peers.
    let kp = WgKeypair::generate();
    let req = EnrollRequest {
        public_key: kp.public_b64.clone(),
        hostname: device_hostname(),
        endpoint: None,
    };
    let resp = adapters::enroll(&state.http, &state.base_url, &tok, &req)
        .await
        .map_err(|e| e.to_string())?;

    // Handoff: persist this identity where the privileged daemon (`agent up`)
    // reads it (~/.ankayma/agent.json), so the data plane reuses THIS node — no
    // duplicate enrollment. The GUI never opens a utun itself (needs root);
    // `start_dataplane` hands off to the daemon. [T:A.1.10 / up.rs load_or_enroll]
    if let Err(e) = write_handoff_state(
        &kp.private_b64,
        &kp.public_b64,
        &resp.node_id,
        &resp.overlay_ip,
    ) {
        log::warn!("handoff state not written ({e}); `agent up` would re-enroll");
    }

    *state.node.lock().expect("node lock poisoned") = Some(EnrolledNode {
        private_b64: kp.private_b64,
        public_b64: kp.public_b64,
        node_id: resp.node_id,
        overlay_ip: resp.overlay_ip,
        peers: resp.peers,
    });
    Ok(())
}

fn disconnect_inner(state: &AppState) {
    *state.node.lock().expect("node lock poisoned") = None;
}

/// Propagate a connection/auth change: notify the window (so its store updates
/// even when the change came from the tray) and refresh the tray menu.
fn apply_connection_change(app: &AppHandle) {
    let conn = current_connection(&app.state::<AppState>());
    let _ = app.emit("connection-changed", conn);
    #[cfg(desktop)]
    update_tray(app);
}

// --- Commands ---

#[tauri::command]
async fn check_auth_state(app: AppHandle, state: State<'_, AppState>) -> Result<AuthState, String> {
    let result = match state.token() {
        None => AuthState::Unauthenticated,
        // Re-validate the stored token against the control plane.
        Some(tok) => match adapters::session_info(&state.http, &state.base_url, &tok).await {
            Ok(s) => {
                state.set_email(Some(s.email.clone()));
                AuthState::Authenticated { user: s.into() }
            }
            Err(_) => {
                state.set_token(None);
                state.set_email(None);
                AuthState::Unauthenticated
            }
        },
    };
    apply_connection_change(&app);
    Ok(result)
}

#[tauri::command]
async fn sign_in_github(state: State<'_, AppState>) -> Result<(), String> {
    // Open the system browser to the control-plane OAuth start. After GitHub,
    // the page shows a session token to paste back via submit_session_token.
    let url = format!("{}/auth/github", state.base_url.trim_end_matches('/'));
    open::that(&url).map_err(|e| format!("could not open browser: {e}"))
}

/// Validate a session token against the control plane and, if good, store it +
/// refresh the UI/tray. Shared by the manual paste path (`submit_session_token`)
/// and the `ankayma://` deep-link path so both behave identically.
/// See docs/auth-deeplink-signin-spec.md.
async fn apply_session_token(app: &AppHandle, token: String) -> Result<User, String> {
    let token = token.trim().to_string();
    if token.is_empty() {
        return Err("session token is empty".into());
    }
    let state = app.state::<AppState>();
    // Validate by fetching the session; only store the token if it works.
    let info = adapters::session_info(&state.http, &state.base_url, &token)
        .await
        .map_err(|e| e.to_string())?;
    state.set_email(Some(info.email.clone()));
    state.set_token(Some(token));
    let user: User = info.into();
    apply_connection_change(app);
    Ok(user)
}

#[tauri::command]
async fn submit_session_token(app: AppHandle, token: String) -> Result<AuthState, String> {
    let user = apply_session_token(&app, token).await?;
    Ok(AuthState::Authenticated { user })
}

/// Pull the `token` out of a `ankayma://auth?token=…` deep link. Returns None
/// for any other scheme or a missing/empty token. (Generic over the URL type so
/// we don't take a direct dependency on the `url` crate's exact version.)
fn token_from_deep_link(url: &url::Url) -> Option<String> {
    if url.scheme() != "ankayma" {
        return None;
    }
    url.query_pairs()
        .find(|(k, _)| k == "token")
        .map(|(_, v)| v.into_owned())
        .filter(|t| !t.is_empty())
}

/// Handle one batch of deep-link URLs: validate the token, sign in, focus the
/// window, and tell the frontend (`signed-in`) so it navigates to the dashboard.
fn handle_deep_links(app: &AppHandle, urls: Vec<url::Url>) {
    for url in urls {
        let Some(token) = token_from_deep_link(&url) else {
            continue;
        };
        let app = app.clone();
        tauri::async_runtime::spawn(async move {
            match apply_session_token(&app, token).await {
                Ok(user) => {
                    log::info!("deep-link sign-in succeeded (tier {:?})", user.tier);
                    #[cfg(desktop)]
                    show_main_window(&app);
                    let _ = app.emit("signed-in", AuthState::Authenticated { user });
                }
                Err(e) => {
                    // Token never written to the log — only the failure reason.
                    log::error!("deep-link sign-in failed: {e}");
                    let _ = app.emit("signin-error", e);
                }
            }
        });
    }
}

#[tauri::command]
async fn sign_out(app: AppHandle, state: State<'_, AppState>) -> Result<(), String> {
    state.set_token(None);
    state.set_email(None);
    disconnect_inner(&state);
    apply_connection_change(&app);
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
    Ok(current_connection(&state))
}

#[tauri::command]
async fn connect(app: AppHandle, state: State<'_, AppState>) -> Result<(), String> {
    connect_inner(&state).await?;
    apply_connection_change(&app);
    Ok(())
}

#[tauri::command]
async fn disconnect(app: AppHandle, state: State<'_, AppState>) -> Result<(), String> {
    disconnect_inner(&state);
    apply_connection_change(&app);
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
async fn create_join_link(state: State<'_, AppState>) -> Result<String, String> {
    // Mint a single-use `ankayma://join?token=…` link via the control plane so a
    // second device enrolls into this tenant (A.1.10/A.1.22). 15-min TTL.
    let tok = state.token().ok_or("not signed in")?;
    adapters::issue_join_token(&state.http, &state.base_url, &tok)
        .await
        .map_err(|e| e.to_string())
}

// --- Data plane (milestone 1.2 — privileged daemon handoff) ---
// The GUI cannot open a utun device (root-only on macOS), so it enrolls on the
// control plane (no privilege) and hands the identity to the `agent` daemon,
// which owns the kernel tunnel (utun + boringtun). Mirrors up.rs `AgentState`.

const DATAPLANE_LISTEN_PORT: u16 = 51820; // WireGuard default; matches agent-daemon

/// Persist the enrolled identity to `~/.ankayma/agent.json` — the same file the
/// privileged `agent` daemon reads on `agent up`, so it reuses THIS node instead
/// of enrolling a second one. Shape mirrors `agent-daemon::up::AgentState`.
fn write_handoff_state(
    private_b64: &str,
    public_b64: &str,
    node_id: &str,
    overlay_ip: &str,
) -> Result<(), String> {
    let home = std::env::var("HOME").map_err(|_| "HOME not set".to_string())?;
    let dir = std::path::Path::new(&home).join(".ankayma");
    std::fs::create_dir_all(&dir).map_err(|e| format!("mkdir ~/.ankayma: {e}"))?;
    let state = serde_json::json!({
        "private_b64": private_b64,
        "public_b64": public_b64,
        "node_id": node_id,
        "overlay_ip": overlay_ip,
        "listen_port": DATAPLANE_LISTEN_PORT,
    });
    let bytes = serde_json::to_vec_pretty(&state).map_err(|e| e.to_string())?;
    std::fs::write(dir.join("agent.json"), bytes).map_err(|e| format!("write agent.json: {e}"))
}

/// Locate the `agent` daemon binary — next to this app (bundled) or a dev build.
fn locate_agent_binary() -> Result<std::path::PathBuf, String> {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let sib = dir.join("agent");
            if sib.exists() {
                return Ok(sib);
            }
        }
    }
    for p in [
        "target/debug/agent",
        "target/release/agent",
        "../../target/debug/agent",
        "../../target/release/agent",
    ] {
        let pb = std::path::PathBuf::from(p);
        if pb.exists() {
            return Ok(pb.canonicalize().unwrap_or(pb));
        }
    }
    Err("agent daemon binary not found (looked next to the app and in target/)".into())
}

/// Launch the privileged `agent` daemon (utun + boringtun need root). macOS shows
/// one admin prompt; the daemon detaches and reuses ~/.ankayma/agent.json.
#[cfg(target_os = "macos")]
fn bring_up_dataplane(
    agent_bin: &std::path::Path,
    token: &str,
    control_plane: &str,
) -> Result<(), String> {
    let bin = agent_bin.to_string_lossy();
    // Session token is hex, control-plane is a URL — no shell metacharacters.
    // Single-quote paths (an .app bundle path may contain spaces).
    let sh = format!(
        "nohup '{bin}' up --token {token} --control-plane '{control_plane}' \
         >> /tmp/ankayma-agent.log 2>&1 &"
    );
    let script = format!("do shell script \"{sh}\" with administrator privileges");
    let out = std::process::Command::new("osascript")
        .arg("-e")
        .arg(script)
        .output()
        .map_err(|e| format!("launch privileged daemon: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "data plane launch failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn bring_up_dataplane(_b: &std::path::Path, _t: &str, _c: &str) -> Result<(), String> {
    Err("data plane is macOS-only at milestone 1.2".into())
}

/// Hand the enrolled identity to the privileged daemon so a real WireGuard tunnel
/// comes up. Enroll (`connect`) first; macOS prompts for admin once.
#[tauri::command]
async fn start_dataplane(state: State<'_, AppState>) -> Result<(), String> {
    let tok = state.token().ok_or("not signed in")?;
    if state.node.lock().expect("node lock poisoned").is_none() {
        return Err("not connected — enroll first".into());
    }
    let bin = locate_agent_binary()?;
    bring_up_dataplane(&bin, &tok, &state.base_url)
}

/// Tear down the data plane (stop the privileged daemon). Killing a root-owned
/// process needs admin — macOS prompts once. Prefer the recorded PID (clean),
/// fall back to a name match.
#[tauri::command]
async fn stop_dataplane() -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        let home = std::env::var("HOME").unwrap_or_default();
        let pid = std::fs::read(format!("{home}/.ankayma/agent-status.json"))
            .ok()
            .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
            .and_then(|v| v.get("pid").and_then(|p| p.as_u64()));
        let kill = match pid {
            Some(p) => format!("kill {p} 2>/dev/null || pkill -f 'agent up' || true"),
            None => "pkill -f 'agent up' || true".to_string(),
        };
        let script = format!("do shell script \"{kill}\" with administrator privileges");
        let out = std::process::Command::new("osascript")
            .arg("-e")
            .arg(script)
            .output()
            .map_err(|e| format!("stop daemon: {e}"))?;
        if !out.status.success() {
            return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
        }
        Ok(())
    }
    #[cfg(not(target_os = "macos"))]
    Err("data plane is macOS-only".into())
}

#[derive(serde::Serialize)]
struct DataplanePeer {
    hostname: String,
    overlay_ip: String,
    endpoint: Option<String>,
}

/// Live data-plane status read from the daemon's heartbeat file. `running` is
/// true only if the file is fresh (daemon heartbeats every 5s; >15s stale = down,
/// and a clean shutdown removes the file). This is how the GUI reflects the REAL
/// tunnel instead of just "enrolled". Connection-level only [T:A.1.1].
#[derive(serde::Serialize)]
struct DataplaneStatus {
    running: bool,
    pid: Option<u32>,
    age_secs: Option<u64>,
    peers: Vec<DataplanePeer>,
}

#[tauri::command]
async fn get_dataplane_status() -> Result<DataplaneStatus, String> {
    let down = || DataplaneStatus {
        running: false,
        pid: None,
        age_secs: None,
        peers: vec![],
    };
    let home = std::env::var("HOME").map_err(|_| "HOME not set".to_string())?;
    let path = std::path::Path::new(&home).join(".ankayma/agent-status.json");
    let Ok(bytes) = std::fs::read(&path) else {
        return Ok(down());
    };
    #[derive(serde::Deserialize)]
    struct FilePeer {
        hostname: String,
        overlay_ip: String,
        endpoint: Option<String>,
    }
    #[derive(serde::Deserialize)]
    struct FileStatus {
        pid: u32,
        updated_at: u64,
        peers: Vec<FilePeer>,
    }
    let Ok(s) = serde_json::from_slice::<FileStatus>(&bytes) else {
        return Ok(down());
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let age = now.saturating_sub(s.updated_at);
    Ok(DataplaneStatus {
        running: age <= 15,
        pid: Some(s.pid),
        age_secs: Some(age),
        peers: s
            .peers
            .into_iter()
            .map(|p| DataplanePeer {
                hostname: p.hostname,
                overlay_ip: p.overlay_ip,
                endpoint: p.endpoint,
            })
            .collect(),
    })
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

// --- CI/CD deploy policy (F0) — feature-03b-gui-spec.md §1.4 ---

/// CI/CD deploy policy draft from the GUI form. Mirrors the §1.1 POST body; empty
/// strings are dropped so the safe-by-default ref XOR environment holds.
#[derive(Deserialize)]
struct CiPolicyDraft {
    issuer: String,
    repo: String,
    #[serde(rename = "ref", default)]
    git_ref: Option<String>,
    #[serde(default)]
    environment: Option<String>,
    #[serde(default)]
    target_hostname: Option<String>,
}

#[tauri::command]
async fn list_ci_policies(state: State<'_, AppState>) -> Result<Vec<domain::CiPolicy>, String> {
    let tok = state.token().ok_or("not signed in")?;
    adapters::list_ci_policies(&state.http, &state.base_url, &tok)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn add_ci_policy(req: CiPolicyDraft, state: State<'_, AppState>) -> Result<(), String> {
    let tok = state.token().ok_or("not signed in")?;
    let nonempty = |s: Option<String>| s.filter(|v| !v.trim().is_empty());
    let body = domain::CiPolicyReq {
        issuer: req.issuer,
        repo: req.repo,
        git_ref: nonempty(req.git_ref),
        environment: nonempty(req.environment),
        target_hostname: nonempty(req.target_hostname),
    };
    adapters::register_ci_policy(&state.http, &state.base_url, &tok, &body)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn delete_ci_policy(repo: String, state: State<'_, AppState>) -> Result<(), String> {
    let tok = state.token().ok_or("not signed in")?;
    adapters::delete_ci_policy(&state.http, &state.base_url, &tok, &repo)
        .await
        .map_err(|e| e.to_string())
}

/// Remove one of the tenant's own mesh nodes (retire a device). Tenant-scoped on
/// the control plane (A.1.6). If it's THIS device, also drop the local identity
/// so the next connect enrolls cleanly.
#[tauri::command]
async fn delete_node(node_id: String, state: State<'_, AppState>) -> Result<(), String> {
    let tok = state.token().ok_or("not signed in")?;
    adapters::delete_node(&state.http, &state.base_url, &tok, &node_id)
        .await
        .map_err(|e| e.to_string())?;
    // If we removed the node we're currently using, clear local state + handoff so
    // we don't keep a ghost identity.
    let is_self = state
        .node
        .lock()
        .expect("node lock poisoned")
        .as_ref()
        .is_some_and(|n| n.node_id == node_id);
    if is_self {
        *state.node.lock().expect("node lock poisoned") = None;
        if let Ok(home) = std::env::var("HOME") {
            let _ = std::fs::remove_file(format!("{home}/.ankayma/agent.json"));
        }
    }
    Ok(())
}

/// Tenant node roster for the deploy-target picker. Reuses `GET /api/v1/peers`.
#[tauri::command]
async fn list_nodes(state: State<'_, AppState>) -> Result<Vec<domain::PeerInfo>, String> {
    let tok = state.token().ok_or("not signed in")?;
    adapters::peers(&state.http, &state.base_url, &tok)
        .await
        .map_err(|e| e.to_string())
}

// --- macOS menu-bar tray (desktop only) ---

/// Build the tray dropdown from the current AppState. Rebuilt on every state
/// change so status text, account, device IP and the peer list stay live.
/// [T:tauri@2.11-tray] [T:tauri@2.11-menu]
#[cfg(desktop)]
fn build_tray_menu(
    app: &AppHandle,
    state: &AppState,
) -> tauri::Result<tauri::menu::Menu<tauri::Wry>> {
    use tauri::menu::{IsMenuItem, Menu, MenuItem, PredefinedMenuItem, Submenu};

    let conn = current_connection(state);
    let connected = matches!(conn, ConnectionState::Connected { .. });
    let status_text = match conn {
        ConnectionState::Connected { .. } => "● Connected",
        ConnectionState::Connecting => "Connecting…",
        ConnectionState::Disconnected => "○ Disconnected",
    };
    let status = MenuItem::with_id(app, "status", status_text, false, None::<&str>)?;
    let toggle = MenuItem::with_id(
        app,
        "toggle",
        if connected { "Disconnect" } else { "Connect" },
        true,
        None::<&str>,
    )?;

    let email = state.email.lock().expect("email lock poisoned").clone();
    let account = MenuItem::with_id(
        app,
        "account",
        email.as_deref().unwrap_or("Not signed in"),
        false,
        None::<&str>,
    )?;

    let (device_text, peers) = {
        let node = state.node.lock().expect("node lock poisoned");
        match &*node {
            Some(n) => (
                format!("This Device: {} ({})", device_hostname(), n.overlay_ip),
                n.peers.clone(),
            ),
            None => (format!("This Device: {}", device_hostname()), Vec::new()),
        }
    };
    let device = MenuItem::with_id(app, "device", device_text, false, None::<&str>)?;

    // Network Devices submenu — one disabled entry per peer (hostname + IP).
    let peer_items: Vec<MenuItem<tauri::Wry>> = if peers.is_empty() {
        vec![MenuItem::with_id(
            app,
            "no-peers",
            "No devices",
            false,
            None::<&str>,
        )?]
    } else {
        peers
            .iter()
            .enumerate()
            .map(|(i, p)| {
                MenuItem::with_id(
                    app,
                    format!("peer-{i}"),
                    format!("{} ({})", p.hostname, p.overlay_ip),
                    false,
                    None::<&str>,
                )
            })
            .collect::<tauri::Result<Vec<_>>>()?
    };
    let peer_refs: Vec<&dyn IsMenuItem<tauri::Wry>> = peer_items
        .iter()
        .map(|m| m as &dyn IsMenuItem<tauri::Wry>)
        .collect();
    let netdev = Submenu::with_id_and_items(app, "netdev", "Network Devices", true, &peer_refs)?;

    let settings = MenuItem::with_id(app, "settings", "Settings", true, None::<&str>)?;
    let open = MenuItem::with_id(app, "open", "Open Ankayma", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
    let s1 = PredefinedMenuItem::separator(app)?;
    let s2 = PredefinedMenuItem::separator(app)?;
    let s3 = PredefinedMenuItem::separator(app)?;

    let items: Vec<&dyn IsMenuItem<tauri::Wry>> = vec![
        &status, &toggle, &s1, &account, &device, &netdev, &s2, &settings, &open, &s3, &quit,
    ];
    Menu::with_items(app, &items)
}

/// A 32×32 RGBA status dot for the menu bar: green when connected, dim gray
/// otherwise. Drawn in code so no extra icon assets are needed. [A] a template
/// (auto light/dark) icon is a later refinement.
#[cfg(desktop)]
fn status_icon(connected: bool) -> tauri::image::Image<'static> {
    const N: u32 = 32;
    let (r, g, b) = if connected {
        (0x22, 0xc5, 0x5e) // --c-success green
    } else {
        (0x80, 0x80, 0x90) // dim gray
    };
    let center = (N as f32 - 1.0) / 2.0;
    let radius = N as f32 * 0.40;
    let mut rgba = vec![0u8; (N * N * 4) as usize];
    for y in 0..N {
        for x in 0..N {
            let dx = x as f32 - center;
            let dy = y as f32 - center;
            let dist = (dx * dx + dy * dy).sqrt();
            // 1px anti-aliased edge so the dot isn't jagged in the menu bar.
            let alpha = (radius - dist + 0.5).clamp(0.0, 1.0);
            let i = ((y * N + x) * 4) as usize;
            rgba[i] = r;
            rgba[i + 1] = g;
            rgba[i + 2] = b;
            rgba[i + 3] = (alpha * 255.0) as u8;
        }
    }
    tauri::image::Image::new_owned(rgba, N, N)
}

/// Rebuild the tray menu and icon in place after a state change.
#[cfg(desktop)]
fn update_tray(app: &AppHandle) {
    if let Some(tray) = app.tray_by_id("main") {
        let state = app.state::<AppState>();
        let connected = matches!(
            current_connection(&state),
            ConnectionState::Connected { .. }
        );
        match build_tray_menu(app, &state) {
            Ok(menu) => {
                let _ = tray.set_menu(Some(menu));
            }
            Err(e) => log::error!("tray menu rebuild failed: {e}"),
        }
        let _ = tray.set_icon(Some(status_icon(connected)));
    }
}

#[cfg(desktop)]
fn show_main_window(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.show();
        let _ = w.set_focus();
    }
}

/// Handle a tray menu click. Connect/disconnect run on the async runtime since
/// enrollment is a network call.
#[cfg(desktop)]
fn handle_tray_menu(app: &AppHandle, event: tauri::menu::MenuEvent) {
    match event.id().as_ref() {
        "toggle" => {
            let app = app.clone();
            tauri::async_runtime::spawn(async move {
                let state = app.state::<AppState>();
                let connected = matches!(
                    current_connection(&state),
                    ConnectionState::Connected { .. }
                );
                if connected {
                    disconnect_inner(&state);
                } else if let Err(e) = connect_inner(&state).await {
                    log::error!("tray connect failed: {e}");
                }
                apply_connection_change(&app);
            });
        }
        "settings" => {
            show_main_window(app);
            let _ = app.emit("tray-navigate", "/settings");
        }
        "open" => show_main_window(app),
        "quit" => app.exit(0),
        _ => {}
    }
}

// --- App entry point ---

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    #[allow(unused_mut)]
    let mut builder = tauri::Builder::default();

    // single-instance (desktop only) MUST be the first plugin: when the app is
    // already running and the user clicks `ankayma://…`, focus the live window
    // instead of spawning a 2nd copy. On Windows/Linux the URL arrives in argv
    // and the `deep-link` feature routes it to on_open_url; on macOS the OS
    // delivers it to the running instance directly.
    #[cfg(desktop)]
    {
        builder = builder.plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| {
            show_main_window(app);
        }));
    }

    builder
        .plugin(tauri_plugin_deep_link::init())
        .setup(|app| {
            app.manage(AppState::new());

            // Route `ankayma://auth?token=…` straight into sign-in (no copy/paste).
            {
                use tauri_plugin_deep_link::DeepLinkExt;
                let handle = app.handle().clone();
                app.deep_link()
                    .on_open_url(move |event| handle_deep_links(&handle, event.urls()));
                // Cold start: the app may have been launched *by* the deep link
                // (URL already consumed before the handler was attached).
                if let Ok(Some(urls)) = app.deep_link().get_current() {
                    handle_deep_links(&app.handle().clone(), urls);
                }
                // Dev only (unbundled): register the scheme at runtime where the
                // OS supports it. macOS/iOS register via the bundle Info.plist.
                #[cfg(any(target_os = "linux", target_os = "windows"))]
                let _ = app.deep_link().register_all();
            }

            #[cfg(desktop)]
            {
                use tauri::tray::TrayIconBuilder;
                let handle = app.handle().clone();
                let st = handle.state::<AppState>();
                let menu = build_tray_menu(&handle, &st)?;
                let connected =
                    matches!(current_connection(&st), ConnectionState::Connected { .. });
                TrayIconBuilder::with_id("main")
                    .icon(status_icon(connected))
                    .tooltip("Ankayma")
                    .menu(&menu)
                    .show_menu_on_left_click(true)
                    .on_menu_event(handle_tray_menu)
                    .build(&handle)?;
            }

            // macOS: show the Dock icon (Regular) in addition to the menu-bar
            // tray. The window opens from the Dock icon or the tray "Open
            // Ankayma" item. [T:tauri@2.11-ActivationPolicy]
            #[cfg(target_os = "macos")]
            app.set_activation_policy(tauri::ActivationPolicy::Regular);

            if cfg!(debug_assertions) {
                app.handle().plugin(
                    tauri_plugin_log::Builder::default()
                        .level(log::LevelFilter::Info)
                        .build(),
                )?;
            }
            Ok(())
        })
        .on_window_event(|_window, _event| {
            // Close-to-tray: the window hides instead of quitting; the app keeps
            // running in the menu bar. [T:tauri@2.11-WindowEvent]
            #[cfg(desktop)]
            if let tauri::WindowEvent::CloseRequested { api, .. } = _event {
                api.prevent_close();
                let _ = _window.hide();
            }
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
            list_ci_policies,
            add_ci_policy,
            delete_ci_policy,
            list_nodes,
            delete_node,
            create_join_link,
            start_dataplane,
            stop_dataplane,
            get_dataplane_status,
            track_event,
            open_stripe_checkout,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
