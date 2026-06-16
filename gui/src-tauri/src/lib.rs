// GUI shell — thin Tauri command layer.
// [T:A.1.1] All business logic (auth, WireGuard, billing) lives in agent-core / control-plane.
// Commands here are stubs; real impl wires into agent-core when available.

use serde::{Deserialize, Serialize};

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
    pub tier: String,         // "F0" | "F0Plus" | "F1Starter"
    pub product_line: String, // "Personal" | "Enterprise"
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
// [A] All commands are stubs pending agent-core WireGuard + control-plane integration (milestone 1.2)

#[tauri::command]
async fn check_auth_state() -> Result<AuthState, String> {
    // [A] stub — replace with agent-core session check
    Ok(AuthState::Unauthenticated)
}

#[tauri::command]
async fn sign_in_github() -> Result<(), String> {
    // [A] stub — open system browser to control-plane OAuth endpoint
    // Real: tauri::api::shell::open(&app.shell_scope(), oauth_url, None)
    Err("Not yet implemented — control-plane integration pending".into())
}

#[tauri::command]
async fn sign_out() -> Result<(), String> {
    // [A] stub — clear agent-core session
    Ok(())
}

#[tauri::command]
async fn get_connection_status() -> Result<ConnectionState, String> {
    // [A] stub — query agent-core daemon via IPC socket
    Ok(ConnectionState::Disconnected)
}

#[tauri::command]
async fn connect() -> Result<(), String> {
    // [A] stub — send Connect intent to agent-core
    // Real: agent_core::application::connect(&session).await
    Err("Not yet implemented — agent-core WireGuard pending".into())
}

#[tauri::command]
async fn disconnect() -> Result<(), String> {
    // [A] stub — send Disconnect intent to agent-core
    Ok(())
}

#[tauri::command]
async fn get_quota() -> Result<Quota, String> {
    // [A] stub — query control-plane quota endpoint via agent-core
    Ok(Quota {
        bandwidth_bytes_used: 0,
        bandwidth_bytes_limit: 10 * 1024 * 1024 * 1024, // 10 GB F0 limit [A]
        nodes_used: 1,
        nodes_limit: 5,
    })
}

#[tauri::command]
async fn get_node_info() -> Result<NodeInfo, String> {
    // [A] stub — read from agent-core local state
    Ok(NodeInfo {
        node_id: "node_placeholder".into(),
        hostname: "my-device".into(),
        public_key: "[A] pending enrollment".into(),
    })
}

#[tauri::command]
async fn open_stripe_checkout() -> Result<(), String> {
    // [A] stub — control-plane generates Stripe session URL, open in system browser
    // Real: control_plane_client::billing::create_checkout_session().await -> url
    //       tauri::api::shell::open(url)
    Err("Not yet implemented — Stripe integration pending milestone 1.3".into())
}

// --- App entry point ---

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
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
            sign_out,
            get_connection_status,
            connect,
            disconnect,
            get_quota,
            get_node_info,
            open_stripe_checkout,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
