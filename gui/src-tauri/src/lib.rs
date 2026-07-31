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
use agent_core::{adapters, domain, machine_key, reqwest, WgKeypair};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager, State};

// VPN bridge for iOS (frontend → Swift TunnelManager via a C ABI). Compiled on all
// platforms; the iOS-only path is gated inside. [T:A.1.9]
mod vpn;

// Deferred deep-link InviteResolver for email invitations (clipboard / Install Referrer).
mod deferred_invite;

// Native FIDO2 security-key ceremony (E-7 Phase 3 / AAL3). WKWebView cannot run
// navigator.credentials against a roaming key at all, so macOS drives the ceremony
// through AuthenticationServices instead. [T:docs/webauthn-security-key-decision.md]
#[cfg(any(target_os = "macos", target_os = "ios"))]
mod webauthn_apple;

// Android VPN bridge (frontend → AnkaymaVpnService via JNI). Owns the TUN fd, the
// in-process WireGuard pump, and the control-plane bypass proxy. [T:A.1.9, F-3]
#[cfg(target_os = "android")]
mod vpn_android;

// Windows data-plane lifecycle (Change 4 of docs/windows-daemon-lifecycle-decision.md):
// one-time SCM install + the auto-updater's verified stop/start (win_service_install),
// and the named-pipe client to the always-on service for everyday Connect/Disconnect/
// Status (win_service_client) — replaces the old Start-Process/taskkill pair.
#[cfg(target_os = "windows")]
mod win_service_client;
#[cfg(target_os = "windows")]
mod win_service_install;

// Unified cross-platform pre-flight permission gate. Lets the UI ask "is the OS
// permission this platform needs for the tunnel already granted?" and request it
// up front (right after sign-in), instead of only discovering it as a Connect
// error. macOS=helper daemon, iOS/Android=VPN configuration consent. [T:A.1.7/A.1.9]
mod preflight;

/// Target OS this build runs on ("ios"/"macos"/"linux"/"windows"). The frontend uses
/// it to pick the data-plane path: iOS brings the tunnel up in-app (Packet Tunnel
/// extension); desktop hands off to the privileged `agent` daemon. [T:A.1.9]
#[tauri::command]
fn get_platform() -> &'static str {
    std::env::consts::OS
}

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
    /// [T:CP-UAE region-routing] Fixed at the auth-gateway — login (`sign_in_github`),
    /// the desktop OAuth poll (`fetch_handoff`), and validating a raw token
    /// (`session_info`) all go here, never to a regional CP. `[T:A.1.1]` auth stays
    /// central; see main.rs module doc on the control-plane side.
    auth_base_url: String,
    /// Where every OTHER API call goes (enroll, ssh, ci_deploy, policy, …) — starts
    /// equal to `auth_base_url`, then flips to `https://{region}.cp.ankayma.com`
    /// once a session_info() call resolves the signed-in tenant's region. Behind a
    /// Mutex because that resolution happens after `AppState` is already shared.
    regional_base_url: Mutex<String>,
    /// True when `ANKAYMA_CONTROL_PLANE` is set (dev/test pointing everything at one
    /// box) — region-based switching is skipped so overriding stays fully in effect.
    region_override_active: bool,
    /// Platform-correct data directory; Tauri resolves this per-OS so it works in
    /// the iOS sandbox (where $HOME is unreliable). [T:A.1.9]
    data_dir: std::path::PathBuf,
    session: Mutex<Option<String>>,
    /// Signed-in account email, surfaced in the tray menu. None when signed out.
    email: Mutex<Option<String>>,
    node: Mutex<Option<EnrolledNode>>,
    /// The diagnostic bundle the user is previewing, cached so `diagnostics_send`
    /// transmits EXACTLY what `diagnostics_build` showed — consent is per that exact
    /// content. Cleared after a send. [T:A.1.1 operational metadata only]
    pending_diagnostic: Mutex<Option<serde_json::Value>>,
    /// A deep-link token captured at COLD start (the app was launched by
    /// `ankayma://auth/callback?token=…`). The frontend isn't listening yet at that
    /// moment, so we hold it here and let the first `check_auth_state` drain it —
    /// no event-timing race. Warm-start deep links use the live `signed-in` event.
    pending_token: Mutex<Option<String>>,
    /// A held `ankayma://join-team?token=…` invite, captured the same way as
    /// `pending_token`. Drained only once authenticated so a not-yet-signed-in
    /// recipient keeps it across sign-in. See Part D §Edge case.
    pending_join_team: Mutex<Option<String>>,
    /// A held `ankayma://join?token=…` node-enrollment invite. Same lifecycle as
    /// `pending_join_team`: drained only once authenticated.
    pending_join_node: Mutex<Option<String>>,
    /// [F-2 §H.2.2] Live in-app SSH terminals: id → write handle. The read side of
    /// each session runs in a task that emits `ssh_data_<id>` events to xterm.js.
    ssh_sessions: Mutex<std::collections::HashMap<String, agent_core::ssh_client::SshInput>>,
    /// Monotonic id source for terminal sessions.
    ssh_seq: std::sync::atomic::AtomicU64,
    /// When `start_dataplane` last succeeded (desktop). Gives the daemon a settle
    /// window to write its first status snapshot before `current_connection`
    /// declares the data plane down — without it, every Connect would flash
    /// "tunnel down" during daemon startup.
    dataplane_started: Mutex<Option<std::time::Instant>>,
}

/// Build the control-plane HTTP client. On Android the full-tunnel VPN (0.0.0.0/0 +
/// ::/0) would black-hole the app's own HTTPS to the *public* control plane, so route
/// it through a loopback CONNECT proxy whose upstream socket is bound to the non-VPN
/// network (vpn_android::start_control_plane_proxy). TLS stays end-to-end. Falls back
/// to a plain client if the proxy can't start (still fine while disconnected).
/// Desktop/iOS are unaffected. [T:protect-socket, F-3]
///
/// Region-safe on every platform (verified 2026-07-13):
///  - Android is full-tunnel (VpnService addRoute 0.0.0.0/0 + ::/0), so it needs this
///    proxy — but the proxy is host-transparent: it dials whatever host each request's
///    `CONNECT` names (`handle_connect` in vpn_android.rs) and only protect()s the
///    socket from the VPN loop; it never pins a control plane.
///  - Windows/macOS/Linux/iOS are split-tunnel (only the overlay CIDR is routed to the
///    tun; the /32 host-address model, not a default route), so control-plane HTTPS
///    goes straight out the normal interface — the plain client below needs no proxy.
///
/// Either way, when `regional_base_url` flips to `https://{region}.cp.ankayma.com` the
/// next request reaches that regional CP with no client rebuild.
///
/// `base_url` is currently unused (the proxy needs no target; the plain-client fallback
/// takes none) — kept as a parameter so a future per-host client config has a seam.
fn build_http_client(base_url: &str) -> reqwest::Client {
    #[cfg(target_os = "android")]
    match vpn_android::start_control_plane_proxy() {
        Ok(local_port) => {
            let proxy_url = format!("http://127.0.0.1:{local_port}");
            match reqwest::Proxy::all(&proxy_url) {
                // Disable connection reuse: a pooled tunnel opened while disconnected
                // has an UNBOUND upstream socket that the full-tunnel VPN black-holes
                // once it comes up. A fresh connection per request re-runs the CONNECT
                // → the proxy binds each new upstream socket to the non-VPN network at
                // request time (bound=true while connected). [T:protect-socket]
                Ok(proxy) => match reqwest::Client::builder()
                    .proxy(proxy)
                    .pool_max_idle_per_host(0)
                    .build()
                {
                    Ok(c) => {
                        log::info!("control-plane client routed via {proxy_url}");
                        return c;
                    }
                    Err(e) => log::error!("cp-proxy: client build failed: {e}"),
                },
                Err(e) => log::error!("cp-proxy: Proxy::all failed: {e}"),
            }
        }
        Err(e) => log::error!("cp-proxy: start failed: {e}"),
    }
    let _ = base_url;
    reqwest::Client::new()
}

impl AppState {
    fn new(data_dir: std::path::PathBuf) -> Self {
        let override_url = std::env::var("ANKAYMA_CONTROL_PLANE").ok();
        let auth_base_url = override_url
            .clone()
            .unwrap_or_else(|| DEFAULT_CONTROL_PLANE.to_string());
        // Regional starts equal to auth (correct for a fresh install before any
        // session has told us a region); update_region() moves it once known.
        let regional_base_url = auth_base_url.clone();
        let region_override_active = override_url.is_some();
        let session = load_session_from_disk(&data_dir);
        AppState {
            // build_http_client is the Android control-plane proxy path (no-op on
            // other platforms); point it at the auth gateway, where the very first
            // calls go before a session resolves the tenant's region.
            http: build_http_client(&auth_base_url),
            auth_base_url,
            regional_base_url: Mutex::new(regional_base_url),
            region_override_active,
            data_dir,
            session: Mutex::new(session),
            email: Mutex::new(None),
            node: Mutex::new(None),
            pending_diagnostic: Mutex::new(None),
            pending_token: Mutex::new(None),
            pending_join_team: Mutex::new(None),
            pending_join_node: Mutex::new(None),
            ssh_sessions: Mutex::new(std::collections::HashMap::new()),
            ssh_seq: std::sync::atomic::AtomicU64::new(0),
            dataplane_started: Mutex::new(None),
        }
    }

    fn set_pending(&self, tok: Option<String>) {
        *self.pending_token.lock().expect("pending lock poisoned") = tok;
    }

    fn take_pending(&self) -> Option<String> {
        self.pending_token
            .lock()
            .expect("pending lock poisoned")
            .take()
    }

    fn set_pending_join_team(&self, tok: Option<String>) {
        *self
            .pending_join_team
            .lock()
            .expect("pending join-team lock poisoned") = tok;
    }

    fn take_pending_join_team(&self) -> Option<String> {
        self.pending_join_team
            .lock()
            .expect("pending join-team lock poisoned")
            .take()
    }

    fn set_pending_join_node(&self, tok: Option<String>) {
        *self
            .pending_join_node
            .lock()
            .expect("pending join-node lock poisoned") = tok;
    }

    fn take_pending_join_node(&self) -> Option<String> {
        self.pending_join_node
            .lock()
            .expect("pending join-node lock poisoned")
            .take()
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

    /// [T:CP-UAE region-routing] Current base URL for everything except auth.
    fn regional_base_url(&self) -> String {
        self.regional_base_url
            .lock()
            .expect("regional_base_url lock poisoned")
            .clone()
    }

    /// Call once a session_info() response resolves the signed-in tenant's region
    /// (e.g. right after login, or on the periodic re-validate in
    /// `check_auth_state`). No-op under `ANKAYMA_CONTROL_PLANE` — a dev/test
    /// override should stay in full effect, not get overridden back to a real
    /// regional subdomain.
    fn update_region(&self, region: &str) {
        if self.region_override_active {
            return;
        }
        *self
            .regional_base_url
            .lock()
            .expect("regional_base_url lock poisoned") = format!("https://{region}.cp.ankayma.com");
    }
}

// --- Session persistence (survive app restarts without re-login) ---
// Token is stored as plain text in $HOME/.ankayma/session (mode 600 on Unix).
// On macOS the file sits in the user's home dir (under user-level protection);
// on iOS it sits in the app sandbox (inaccessible to other apps). The token is
// server-validated on every startup via check_auth_state, so a revoked/expired
// token is caught and the file is cleared automatically.

fn session_file_path(data_dir: &std::path::Path) -> std::path::PathBuf {
    data_dir.join("session")
}

fn save_session_to_disk(data_dir: &std::path::Path, token: &str) {
    let path = session_file_path(data_dir);
    if let Some(p) = path.parent() {
        let _ = std::fs::create_dir_all(p);
    }
    if std::fs::write(&path, token.as_bytes()).is_ok() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }
    }
}

fn load_session_from_disk(data_dir: &std::path::Path) -> Option<String> {
    let tok = std::fs::read_to_string(session_file_path(data_dir)).ok()?;
    let tok = tok.trim().to_string();
    if tok.is_empty() {
        None
    } else {
        Some(tok)
    }
}

fn clear_session_from_disk(data_dir: &std::path::Path) {
    let _ = std::fs::remove_file(session_file_path(data_dir));
}

// --- Domain types (mirror Part B §B.1 subset needed by GUI) ---

#[derive(Serialize, Deserialize, Clone)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum AuthState {
    Unauthenticated,
    Authenticating,
    Authenticated {
        user: User,
    },
    /// [T:CP-UAE region-routing] User bailed on the region picker (or any other
    /// browser-side step) instead of finishing. Distinct from `Unauthenticated`
    /// so the UI can say "cancelled" instead of silently reverting with no
    /// explanation — found live-testing 2026-07-12 (poll otherwise hangs on
    /// "Waiting for GitHub..." for up to 5 minutes with no signal).
    Cancelled,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct User {
    pub tenant_id: String,
    pub email: String,
    pub tier: String,         // "F0" | "F0Plus" | "F1Starter"
    pub product_line: String, // this control plane is the Personal PL
    pub role: String,         // capability: "admin" | "member"
    pub seat_type: String,    // quota class: "admin"|"builder"|"user"|"lite"
    pub seat_node_cap: u32,   // per-member node cap for this seat_type
    pub seat_privdomain_cap: u32,
}

impl From<domain::SessionInfo> for User {
    fn from(s: domain::SessionInfo) -> Self {
        User {
            tenant_id: s.tenant_id,
            email: s.email,
            tier: s.tier,
            product_line: "Personal".into(),
            role: s.role,
            seat_type: s.seat_type,
            seat_node_cap: s.seat_caps.nodes,
            seat_privdomain_cap: s.seat_caps.privdomains,
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Connected {
        node_id: String,
        endpoint: String,
    },
    /// Enrolled, but the privileged daemon is not writing its status snapshot —
    /// the tunnel is NOT carrying traffic. Shown instead of a false "Connected"
    /// when the daemon died or never came up (the failure mode that had the GUI
    /// green while the data plane was dead). Desktop only; mobile reports the
    /// tunnel state through `vpn_status`.
    DataplaneDown {
        node_id: String,
        endpoint: String,
    },
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

/// [F-5 / A.1.1] One mesh peer on the data path. `direct` = endpoint is known and
/// traffic is peer-to-peer (no relay). Stats are live from boringtun via
/// agent-status.json — evidence that data moved without transiting the vendor.
#[derive(Serialize, Deserialize, Clone)]
pub struct PathPeer {
    pub hostname: String,
    pub overlay_ip: String,
    /// True = direct WireGuard (no relay). False = relayed (vendor in data path per
    /// A.1.12; honest per P.3). Currently always true — relay not yet implemented.
    pub direct: bool,
    pub endpoint: Option<String>,
    /// Seconds since the last WireGuard handshake; None if no handshake yet.
    pub last_handshake_secs: Option<u64>,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
}

/// [F-5 "Prove it"] Path-proof: each peer's data-path type, live WireGuard evidence,
/// and whether the vendor is on the data path. [T:A.1.1 / P.3]
#[derive(Serialize, Deserialize, Clone)]
pub struct PathProof {
    pub connected: bool,
    pub control_plane: String,
    /// True only when any peer routes via vendor relay (A.1.12 Personal line).
    /// Computed from peers, not hardcoded — turns correct automatically when relay lands.
    pub vendor_on_data_path: bool,
    pub peers: Vec<PathPeer>,
}

// --- Core helpers (shared by #[tauri::command]s and the tray) ---

/// Age in seconds of the daemon's status snapshot, None when absent/unreadable.
/// The snapshot is heartbeat-rewritten every 15s while the daemon runs, so its
/// age is the ground truth for "is the data plane actually up". [T:F-5]
#[cfg(not(any(target_os = "ios", target_os = "android")))]
fn dataplane_snapshot_age() -> Option<u64> {
    #[derive(serde::Deserialize)]
    struct Stamp {
        updated_at: u64,
    }
    let bytes = std::fs::read(freshest_status_path()).ok()?;
    let s: Stamp = serde_json::from_slice(&bytes).ok()?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    Some(now.saturating_sub(s.updated_at))
}

/// 3× the daemon's 15s heartbeat: tolerates a missed tick without flapping the
/// UI off, matches the F-5 path-proof threshold. [T:F-5]
#[cfg(not(any(target_os = "ios", target_os = "android")))]
const DATAPLANE_FRESH_SECS: u64 = 45;
/// How long after `start_dataplane` the daemon gets to write its FIRST snapshot
/// (enroll reuse + roster fetch + utun) before "no snapshot" means "down".
#[cfg(not(any(target_os = "ios", target_os = "android")))]
const DATAPLANE_SETTLE_SECS: u64 = 25;

/// The live connection status derived from AppState — single source of truth
/// for both the window UI and the tray menu.
///
/// Desktop: enrollment alone is NOT a connection. "Connected" additionally
/// requires a fresh daemon status snapshot; a dead daemon shows `DataplaneDown`
/// instead of the old false green (the GUI stayed "Connected" for hours while
/// the tunnel was down — see docs/daemon-state-dir.md for one way that happened).
/// Mobile keeps enrollment-only: the in-app tunnel reports through `vpn_status`.
fn current_connection(state: &AppState) -> ConnectionState {
    let Some((node_id, endpoint)) = state
        .node
        .lock()
        .expect("node lock poisoned")
        .as_ref()
        .map(|n| (n.node_id.clone(), n.overlay_ip.clone()))
    else {
        return ConnectionState::Disconnected;
    };
    #[cfg(not(any(target_os = "ios", target_os = "android")))]
    {
        match dataplane_snapshot_age() {
            Some(age) if age <= DATAPLANE_FRESH_SECS => {
                ConnectionState::Connected { node_id, endpoint }
            }
            _ => {
                let started = *state
                    .dataplane_started
                    .lock()
                    .expect("dataplane_started lock poisoned");
                match started {
                    // Daemon launched recently — first snapshot may still be
                    // seconds away. Also the pre-`start_dataplane` window right
                    // after enroll (started=None): the frontend drives that phase
                    // and calls start_dataplane immediately, so report Connecting
                    // rather than flashing a false "down".
                    Some(t) if t.elapsed().as_secs() <= DATAPLANE_SETTLE_SECS => {
                        ConnectionState::Connecting
                    }
                    None => ConnectionState::Connecting,
                    Some(_) => ConnectionState::DataplaneDown { node_id, endpoint },
                }
            }
        }
    }
    #[cfg(any(target_os = "ios", target_os = "android"))]
    {
        ConnectionState::Connected { node_id, endpoint }
    }
}

/// Where the node identity (agent.json) is persisted. On iOS AND Android this MUST
/// be the app data dir: `$HOME` in either sandbox is not a stable, persistent,
/// writable location, so a handoff written there is lost (or never written) between
/// launches — which made every Connect enroll a BRAND-NEW node with a fresh
/// WireGuard key (roster filled with duplicate nodes; peers that already knew the
/// old key dropped the new handshakes → tunnel stuck at rx 0). On desktop this is
/// the GUI's OWN copy of the identity — on macOS the privileged daemon receives its
/// content over the helper IPC at Start and keeps a root-owned copy under
/// /Library/Ankayma (docs/daemon-state-dir.md). `[T:A.1.10]`
fn handoff_state_dir(state: &AppState) -> std::path::PathBuf {
    #[cfg(any(target_os = "ios", target_os = "android"))]
    {
        return state.data_dir.join(".ankayma");
    }
    #[cfg(not(any(target_os = "ios", target_os = "android")))]
    {
        let _ = state;
        // One resolver for every entrypoint (HOME on unix, USERPROFILE on Windows).
        // Reading a bare HOME here (unset on Windows) persisted identity to a relative
        // `.ankayma` under an unwritable CWD. [T:agent_core::home_root]
        std::path::PathBuf::from(agent_core::home_root()).join(".ankayma")
    }
}

/// The WireGuard keypair persisted by a previous enroll, if any. Body testable
/// without touching the process-global HOME (mirrors `write_handoff_state_to`).
///
/// Deliberately does NOT check the control plane for the node's continued
/// existence. The old code verified via `GET /api/v1/peers` and treated ANY
/// failure — a transient network error, or an owner-scoped roster that hides a
/// null-owner node from a member session — as "no identity", falling through to
/// `WgKeypair::generate()` and enrolling a duplicate. Failing to *verify* an
/// identity must never mint a *new* one. `[T:P.2 no back doors]`
fn load_stored_keypair_from(dir: &std::path::Path) -> Option<WgKeypair> {
    let bytes = std::fs::read(dir.join("agent.json")).ok()?;
    #[derive(serde::Deserialize)]
    struct Stored {
        private_b64: String,
        public_b64: String,
    }
    let s: Stored = serde_json::from_slice(&bytes).ok()?;
    Some(WgKeypair {
        private_b64: s.private_b64,
        public_b64: s.public_b64,
    })
}

/// The persisted node identity — `(node_id, wg_public_b64)` — recovered from agent.json.
/// Device-key re-auth needs both; on a COLD START `state.node` is empty (the node is only
/// put in memory by a Connect this run), so without this the app would force a fresh
/// sign-in after every kill/relaunch even though the durable identity is on disk. `[T:A.1.10]`
fn load_stored_node_identity(dir: &std::path::Path) -> Option<(String, String)> {
    let bytes = std::fs::read(dir.join("agent.json")).ok()?;
    #[derive(serde::Deserialize)]
    struct Stored {
        node_id: String,
        public_b64: String,
    }
    let s: Stored = serde_json::from_slice(&bytes).ok()?;
    (!s.node_id.is_empty() && !s.public_b64.is_empty()).then_some((s.node_id, s.public_b64))
}

/// The persisted NODE service token, recovered from agent.json. Node-scoped routes
/// (`GET /api/v1/relay/map`, the relay's own membership verify) authenticate the node
/// via this token — the user session token (`AppState::token`, an OAuth token) is
/// rejected there. Written by `persist_*` alongside the WG key. `[T:D.11 scoped token]`
// Only the mobile Packet Tunnel builder (`vpn::build_config`, iOS/Android) reads this;
// on desktop the daemon holds its own service token.
#[cfg_attr(not(any(target_os = "ios", target_os = "android")), allow(dead_code))]
fn load_stored_service_token(dir: &std::path::Path) -> Option<String> {
    let bytes = std::fs::read(dir.join("agent.json")).ok()?;
    #[derive(serde::Deserialize)]
    struct Stored {
        service_token: Option<String>,
    }
    let s: Stored = serde_json::from_slice(&bytes).ok()?;
    s.service_token.filter(|t| !t.is_empty())
}

/// Real control-plane enrollment. Idempotent: a no-op if already enrolled
/// in-process, otherwise enrolls with the persisted keypair when one exists.
///
/// Always enrolling — rather than trusting a locally cached node_id — is what
/// makes this safe in both directions. `POST /api/v1/enrollment` is idempotent on
/// the enrolled public key: if the node still exists the server returns the SAME
/// node_id and overlay_ip; if it was retired, exactly one node is recreated for
/// that key. Neither branch can produce a duplicate. Mirrors
/// `agent-daemon::up::load_or_enroll`. `[T:A.1.10 / adapters::enroll contract]`
///
/// The machine proof carries this further: the server matches on the DEVICE, so even
/// a lost WireGuard key rotates the node we already have instead of enrolling a
/// second one. `agent.json` is the WireGuard key and dies with the tenant;
/// `machine.key` is the device and outlives every tenant it joins.
async fn connect_inner(state: &AppState) -> Result<(), String> {
    let tok = state.token().ok_or("not signed in")?;
    if state.node.lock().expect("node lock poisoned").is_some() {
        return Ok(());
    }

    let state_dir = handoff_state_dir(state);
    // Reuse the persisted keypair when present; a fresh one only on first enroll.
    let kp = load_stored_keypair_from(&state_dir).unwrap_or_else(WgKeypair::generate);
    // Fail closed. Enrolling without the proof would silently fall back to matching on
    // the WireGuard key — exactly the behaviour whose failures fill a roster with
    // ghosts of one device. `[T:P.2 no back doors]`
    let machine = machine_key::MachineKey::load_or_create(&state_dir)
        .map_err(|e| format!("cannot load this device's identity: {e}"))?;
    let proof = machine
        .proof_now(&kp.public_b64)
        .map_err(|e| format!("cannot prove this device's identity: {e}"))?;

    let req = EnrollRequest {
        public_key: kp.public_b64.clone(),
        hostname: device_hostname(),
        endpoint: None,
        workload_kind: Some("ClientDevice".to_string()),
        platform: Some(std::env::consts::OS.to_string()),
        machine_proof: Some(proof),
    };
    let resp = adapters::enroll(&state.http, &state.regional_base_url(), &tok, &req)
        .await
        .map_err(|e| e.to_string())?;

    // Handoff: persist this identity so the NEXT connect reuses THIS node instead
    // of enrolling a duplicate. Desktop writes ~/.ankayma/agent.json for the
    // privileged `agent up` daemon to read; iOS/Android write the app data dir (the
    // tunnel runs in-app, no daemon) — see handoff_state_dir.
    //
    // Fail CLOSED. An enroll that succeeds server-side but whose identity we cannot
    // persist is worse than no enroll at all: the node exists, counts against the
    // tier quota, and the next Connect enrolls another one. Roll the node back and
    // surface the error. `[T:P.2 front-load, no "ship now fix later"]`
    if let Err(e) = write_handoff_state_to(
        &state_dir,
        &kp.private_b64,
        &kp.public_b64,
        &resp.node_id,
        &resp.overlay_ip,
        resp.node_service_token.as_deref(),
        resp.token_expires_at.as_deref(),
    ) {
        // Best-effort rollback. The server gates DELETE behind a step-up proof —
        // which we do not hold here — for every tier above the free one (see
        // `adapters::delete_node`), so this can fail; the node then leaks and an
        // admin must retire it. The free tier, whose node quota is the tightest and
        // where a leak hurts soonest, is ungated and rolls back cleanly. `[A: revisit
        // when the client can mint a step-up proof non-interactively]`
        if let Err(del) = adapters::delete_node(
            &state.http,
            &state.regional_base_url(),
            &tok,
            &resp.node_id,
            None,
        )
        .await
        {
            log::error!("enroll rollback failed for {}: {del}", resp.node_id);
        }
        return Err(format!("cannot persist node identity: {e}"));
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
    *state
        .dataplane_started
        .lock()
        .expect("dataplane_started lock poisoned") = None;
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

/// The stored session expired (4h). Instead of logging out, prove possession of this
/// device's DURABLE machine key and re-mint a session — no second sign-in, no "4h
/// wall" (E-6 device-key model; [T:E-6 device-key re-auth + A.1.10]).
/// Returns the refreshed user, or None if this device cannot re-auth: no enrolled node
/// in memory (never connected this run), or the CP rejects the proof (device revoked /
/// legacy). None → the caller does a real logout + disconnect.
async fn try_reauth_via_device_key(app: &AppHandle, state: &AppState) -> Option<User> {
    // Node identity: the in-memory enrolled node if we connected this run, else recover it
    // from the persisted handoff (agent.json). The disk fallback is what makes re-auth work
    // on a COLD START — after the app is killed and reopened, `state.node` is empty, but the
    // durable node_id + WG pubkey (and the machine key) are still on disk, so we re-mint a
    // session with no second sign-in. [T:E-6 device-key re-auth + A.1.10]
    let (node_id, wg_pubkey) = {
        let held = state.node.lock().ok().and_then(|n| {
            n.as_ref()
                .map(|n| (n.node_id.clone(), n.public_b64.clone()))
        });
        match held {
            Some(pair) => pair,
            None => load_stored_node_identity(&handoff_state_dir(state))?,
        }
    };
    let machine = machine_key::MachineKey::load_or_create(&handoff_state_dir(state)).ok()?;
    let proof = machine.proof_now(&wg_pubkey).ok()?;
    // session_refresh runs on — and mints the session INTO — the owner's REGIONAL CP
    // (regional_base_url). Validate + adopt it THERE, not the gateway (auth_base_url):
    // a regional (e.g. UAE) session lives only on its region's box, so checking it
    // against the gateway would 401. [T:E-6 device-key re-auth + A.1.10]
    let base = state.regional_base_url();
    let session = adapters::session_refresh(&state.http, &base, &node_id, &proof)
        .await
        .ok()?;
    let info = adapters::session_info(&state.http, &base, &session)
        .await
        .ok()?;
    state.set_email(Some(info.email.clone()));
    state.update_region(&info.region);
    save_session_to_disk(&state.data_dir, &session);
    state.set_token(Some(session));
    apply_connection_change(app);
    Some(info.into())
}

#[tauri::command]
async fn check_auth_state(app: AppHandle, state: State<'_, AppState>) -> Result<AuthState, String> {
    // Cold-start deep link: adopt a token the app was launched with, if any. This
    // is what makes "Open app" land straight on the dashboard with no manual paste.
    if state.token().is_none() {
        if let Some(pending) = state.take_pending() {
            state.set_token(Some(pending));
        }
    }
    let result = match state.token() {
        None => AuthState::Unauthenticated,
        // Re-validate the stored token against the control plane.
        Some(tok) => match adapters::session_info(&state.http, &state.auth_base_url, &tok).await {
            Ok(s) => {
                state.set_email(Some(s.email.clone()));
                state.update_region(&s.region);
                AuthState::Authenticated { user: s.into() }
            }
            // Session invalid/expired (4h). Try device-key re-auth before giving up —
            // no second sign-in, no dropped tunnel. [T:E-6 device-key re-auth + A.1.10]
            Err(_) => match try_reauth_via_device_key(&app, state.inner()).await {
                Some(user) => AuthState::Authenticated { user },
                None => {
                    // Device can't re-auth (revoked / legacy / never enrolled) → real
                    // logout, and tear the tunnel down too (fix: logout must disconnect).
                    clear_session_from_disk(&state.data_dir);
                    state.set_token(None);
                    state.set_email(None);
                    disconnect_inner(state.inner());
                    AuthState::Unauthenticated
                }
            },
        },
    };
    // Hand any held invite token to the frontend, but ONLY once authenticated. A
    // not-yet-signed-in recipient (or one whose session was revoked) keeps the
    // pending invite across sign-in, since we don't drain it here until the session
    // validates. [A] flow per Part D §Edge case.
    if matches!(result, AuthState::Authenticated { .. }) {
        if let Some(tok) = state.take_pending_join_team() {
            let _ = app.emit("join-team-pending", tok);
        }
        if let Some(tok) = state.take_pending_join_node() {
            let _ = app.emit("join-node-pending", tok);
        }
    }
    apply_connection_change(&app);
    Ok(result)
}

#[tauri::command]
async fn sign_in_github(state: State<'_, AppState>, nonce: String) -> Result<(), String> {
    // Open the system browser to the control-plane OAuth start, passing a one-time
    // `nonce`. After GitHub, the callback parks the session token under that nonce;
    // the frontend polls `poll_login(nonce)` to sign in — no `ankayma://` deep link
    // needed (it's unreliable under `tauri dev`). Deep-link + paste remain fallbacks.
    let base = state.auth_base_url.trim_end_matches('/');
    let url = format!("{base}/auth/github?source=desktop&nonce={nonce}");
    open_url(&url)
}

/// Open an external URL in the system browser. On desktop the `open` crate launches
/// the OS default browser; on iOS/Android that crate no-ops (no `open`/`xdg-open`), so
/// route through the platform bridge instead — Swift `UIApplication.open` on iOS, an
/// ACTION_VIEW intent on Android. [T:A.1.9]
fn open_url(url: &str) -> Result<(), String> {
    #[cfg(any(target_os = "ios", target_os = "android"))]
    {
        vpn::open_external_url(url)
    }
    #[cfg(not(any(target_os = "ios", target_os = "android")))]
    {
        open::that(url).map_err(|e| format!("could not open browser: {e}"))
    }
}

/// Poll the OAuth handoff: returns Authenticated once the browser-side GitHub login
/// completes (token parked under `nonce`), else None while still pending.
#[tauri::command]
async fn poll_login(
    app: AppHandle,
    state: State<'_, AppState>,
    nonce: String,
) -> Result<Option<AuthState>, String> {
    match adapters::fetch_handoff(&state.http, &state.auth_base_url, &nonce).await {
        // [T:CP-UAE region-routing] Server-side cancel (region picker) parks this
        // sentinel instead of a real token — not a session, don't try to validate
        // it as one.
        Ok(Some(token)) if token == "CANCELLED" => Ok(Some(AuthState::Cancelled)),
        Ok(Some(token)) => {
            let user = apply_session_token(&app, token).await?;
            Ok(Some(AuthState::Authenticated { user }))
        }
        Ok(None) => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}

/// Scheme tag for a cross-region sign-in hand-off (vs a plain session token). Kept in
/// sync with the control plane's issuer. `[T:A.1.23 region isolation]`
const REGION_HANDOFF_PREFIX: &str = "rhf1.";

fn is_region_handoff(token: &str) -> bool {
    token.starts_with(REGION_HANDOFF_PREFIX)
}

/// Read the target `region` out of a hand-off's (server-signed) claims — used ONLY to
/// pick which regional CP to redeem at. The signature is verified server-side, not
/// here; a tampered region just routes the redeem to the wrong CP, which rejects it.
fn region_from_handoff(blob: &str) -> Option<String> {
    use base64::Engine as _;
    let rest = blob.strip_prefix(REGION_HANDOFF_PREFIX)?;
    let (payload_b64, _sig) = rest.split_once('.')?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64)
        .ok()?;
    #[derive(serde::Deserialize)]
    struct Claims {
        region: String,
    }
    serde_json::from_slice::<Claims>(&bytes)
        .ok()
        .map(|c| c.region)
}

/// Exchange a signed region hand-off for a real session token at the target region's
/// control plane, and point `regional_base_url` there. A user who signs in at the auth
/// gateway for a different region gets a hand-off instead of a session (the gateway
/// can't write the other region's store — no shared DB `[T:A.1.23]`); this redeems it.
async fn redeem_region_handoff(state: &AppState, blob: String) -> Result<String, String> {
    let region = region_from_handoff(&blob).ok_or("malformed region hand-off")?;
    // Move regional_base_url to that region first (no-op under ANKAYMA_CONTROL_PLANE,
    // which keeps every role on the single dev/test CP). Redeem happens there.
    state.update_region(&region);
    let base = state.regional_base_url();
    adapters::redeem_handoff(&state.http, &base, &blob)
        .await
        .map_err(|e| e.to_string())
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

    // A cross-region hand-off (`rhf1.…`) is NOT a session token — it's a signed voucher
    // the target region's CP exchanges for a real session that lives only on that CP.
    // Redeem it first; the returned token then validates on the regional base URL that
    // redeem just pointed us at. A plain token validates on the auth gateway as before.
    // `[T:A.1.23 region isolation]`
    let is_handoff = is_region_handoff(&token);
    let token = if is_handoff {
        redeem_region_handoff(&state, token).await?
    } else {
        token
    };
    let validate_base = if is_handoff {
        state.regional_base_url()
    } else {
        state.auth_base_url.clone()
    };

    // Validate by fetching the session; only store the token if it works.
    let info = adapters::session_info(&state.http, &validate_base, &token)
        .await
        .map_err(|e| e.to_string())?;
    state.set_email(Some(info.email.clone()));
    state.update_region(&info.region);
    save_session_to_disk(&state.data_dir, &token);
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

/// The three `ankayma://` deep links we route on, distinguished by host:
/// `auth` (session sign-in), `join-team` (member invite), `join` (node enrollment
/// invite). The previous code keyed only on scheme, so a `join-team`/`join` token
/// was wrongly adopted as a session token. [A] per Part D (invite flow).
enum DeepLinkKind {
    Auth,
    JoinTeam,
    JoinNode,
}

/// Parse a `ankayma://<host>?token=…` deep link into its kind + token. Returns None
/// for a foreign scheme, an unknown host, or a missing/empty token — so a stray URL
/// can't be mistaken for any of the three flows.
fn parse_deep_link(url: &url::Url) -> Option<(DeepLinkKind, String)> {
    if url.scheme() != "ankayma" {
        return None;
    }
    let token = url
        .query_pairs()
        .find(|(k, _)| k == "token")
        .map(|(_, v)| v.into_owned())
        .filter(|t| !t.is_empty())?;
    let kind = match url.host_str().unwrap_or("") {
        "auth" => DeepLinkKind::Auth,
        "join-team" => DeepLinkKind::JoinTeam,
        "join" => DeepLinkKind::JoinNode,
        _ => return None,
    };
    Some((kind, token))
}

/// Handle a batch of deep-link URLs (cold OR warm start): hold the token by kind and
/// nudge the frontend. We do NOT validate-and-emit here because that races the
/// webview's listeners; instead the frontend's `check_auth_state` (driven on mount,
/// on the `auth-pending` nudge, and on window focus) adopts the held token and routes
/// (dashboard for auth; `/members` or `/add-device` for invites) — one code path, no
/// timing assumptions.
fn handle_deep_links(app: &AppHandle, urls: Vec<url::Url>) {
    let st = app.state::<AppState>();
    let mut got = false;
    for url in urls {
        match parse_deep_link(&url) {
            Some((DeepLinkKind::Auth, token)) => {
                st.set_pending(Some(token));
                got = true;
            }
            Some((DeepLinkKind::JoinTeam, token)) => {
                st.set_pending_join_team(Some(token));
                got = true;
            }
            Some((DeepLinkKind::JoinNode, token)) => {
                st.set_pending_join_node(Some(token));
                got = true;
            }
            None => {
                if url.scheme() == "ankayma" && url.query_pairs().any(|(k, _)| k == "error") {
                    let _ = app.emit("auth-cancelled", ());
                }
            }
        }
    }
    if got {
        #[cfg(desktop)]
        show_main_window(app);
        // Best-effort nudge for the warm case; if it's lost (cold start), the
        // window-focus / mount re-check still picks the token up.
        let _ = app.emit("auth-pending", ());
    }
}

#[tauri::command]
async fn sign_out(app: AppHandle, state: State<'_, AppState>) -> Result<(), String> {
    // Retire the node server-side BEFORE forgetting it locally. Dropping only the
    // local handoff strands the node in the tenant roster forever: it still counts
    // against the tier's node quota, and the next Connect enrolls a replacement. A
    // few sign-out cycles exhaust the quota and Connect starts failing.
    //
    // Best-effort, and only fully effective on the free tier: every tier above it
    // gates DELETE behind a step-up proof we do not hold here (see
    // `adapters::delete_node`), so the retire fails and the node is left for an
    // admin. Sign-out must still clear local state either way — a session that
    // cannot be dropped is a worse failure than a leaked node.
    // `[T:adapters::delete_node step-up contract]`
    // `[A: closing the paid-tier leak needs a non-interactive step-up proof; asking
    //  a user to pass MFA in order to SIGN OUT is not an acceptable trade]`
    let retiring = state
        .node
        .lock()
        .expect("node lock poisoned")
        .as_ref()
        .map(|n| n.node_id.clone());
    if let (Some(tok), Some(node_id)) = (state.token(), retiring) {
        if let Err(e) = adapters::delete_node(
            &state.http,
            &state.regional_base_url(),
            &tok,
            &node_id,
            None,
        )
        .await
        {
            log::warn!("could not retire {node_id} on sign-out ({e}); an admin must remove it");
        }
    }

    clear_session_from_disk(&state.data_dir);
    state.set_token(None);
    state.set_email(None);
    // Tear the DATA PLANE down, not just the control-plane handoff. `disconnect_inner`
    // only drops the in-memory node; the desktop helper daemon (and the mobile in-app
    // tunnel) keep the OLD tenant's mesh alive otherwise. Symptom: sign out, enroll a
    // fresh token, and the new node inherits the previous session's peers. The power
    // toggle stops the daemon explicitly (ConnectionCard); sign-out must do the same.
    // Best-effort — a failed teardown must never block sign-out (a stuck session that
    // cannot be dropped is worse than a lingering daemon we already logged).
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    if let Err(e) = stop_dataplane_inner() {
        log::warn!("could not stop data plane on sign-out: {e}");
    }
    #[cfg(any(target_os = "ios", target_os = "android"))]
    if let Err(e) = vpn::vpn_disconnect() {
        log::warn!("could not stop tunnel on sign-out: {e}");
    }
    disconnect_inner(&state);
    // Forget the enrolled MESH identity. Otherwise, signing in to a DIFFERENT tenant
    // (or as a different user) on the same device would carry the previous tenant's
    // node handoff — the next Connect could reuse it and land in the wrong mesh
    // (services mismatch / peer unreachable).
    //
    // The DEVICE identity (`machine.key`) deliberately survives. It is not tenant
    // state; it is what makes the next enrollment — in this tenant or another — land
    // on one node instead of minting a fresh one. Deleting it here would rebuild the
    // duplicate-node bug out of a sign-out.
    *state.node.lock().expect("node lock poisoned") = None;
    let handoff = handoff_state_dir(&state).join("agent.json");
    let _ = std::fs::remove_file(&handoff);
    apply_connection_change(&app);
    Ok(())
}

#[tauri::command]
async fn get_quota(state: State<'_, AppState>) -> Result<Quota, String> {
    let tok = state.token().ok_or("not signed in")?;
    let q = adapters::quota(&state.http, &state.regional_base_url(), &tok)
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

// iOS: `gethostname(2)` returns "localhost" in the sandbox, so ask UIKit for the
// real device name (Swift `ankayma_device_name` in VpnBridge.swift).
#[cfg(target_os = "ios")]
extern "C" {
    fn ankayma_device_name(buf: *mut std::os::raw::c_char, len: usize);
}

fn device_hostname() -> String {
    // iOS first: UIDevice.current.name via the Swift bridge (the sandbox hostname is
    // useless), else every phone enrolls as the "ankayma-desktop" fallback below.
    #[cfg(target_os = "ios")]
    {
        let mut buf = [0i8; 256];
        // SAFETY: valid buffer + length; Swift strlcpy's a NUL-terminated name in.
        unsafe { ankayma_device_name(buf.as_mut_ptr(), buf.len()) };
        let name = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) }
            .to_string_lossy()
            .trim()
            .to_string();
        if !name.is_empty() && name != "localhost" {
            return name;
        }
    }
    // $HOSTNAME is set by shells on Linux but NOT by macOS launchd/GUI apps.
    // Fall back to gethostname(2) which works on macOS, Linux, and iOS sandbox.
    if let Ok(h) = std::env::var("HOSTNAME") {
        let h = h.trim().to_string();
        if !h.is_empty() && h != "localhost" {
            return h;
        }
    }
    #[cfg(unix)]
    {
        let mut buf = [0u8; 256];
        let ret = unsafe { libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len()) };
        if ret == 0 {
            let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
            if let Ok(name) = std::str::from_utf8(&buf[..end]) {
                let name = name.trim().to_string();
                if !name.is_empty() && name != "localhost" {
                    return name;
                }
            }
        }
    }
    // Windows is not `unix`, so gethostname(2) above never runs there and $HOSTNAME
    // is unset — without this every Windows box enrolled as the "ankayma-desktop"
    // fallback. COMPUTERNAME is the OS-provided machine name. [T:parity with agent home_root]
    #[cfg(target_os = "windows")]
    {
        if let Ok(h) = std::env::var("COMPUTERNAME") {
            let h = h.trim().to_string();
            if !h.is_empty() && h != "localhost" {
                return h;
            }
        }
    }
    "ankayma-desktop".to_string()
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

/// [F-5 "Prove it"] Live data-path proof read from the daemon's heartbeat file.
/// Returns per-peer WireGuard stats (handshake age, byte counts) so the viewer can
/// Active reachability probe for a batch of overlay IPs. The WireGuard handshake
/// age is a *lagging* signal — a reachable-but-idle node reads "no handshake" until
/// something sends it traffic. This nudges each peer with a short TCP connect (which
/// itself triggers the handshake through the tunnel) and classifies the result:
/// connected OR refused (the node sent a RST) → **reachable**; timed out → the WG
/// path never came up → **unreachable**. Runs the batch concurrently, ~3s worst
/// case. Honest per P.3 — a filtered port on a live node can still read unreachable,
/// so this is "best-effort reachable", surfaced as a hint, not a guarantee. `[T:A.1.1]`
#[tauri::command]
async fn probe_reachable(targets: Vec<String>) -> Result<Vec<String>, String> {
    // Blocking connects on a blocking thread so the async runtime isn't stalled; each
    // target gets its own thread so the batch runs concurrently (~12s worst case,
    // paid only by targets that never answer — see PROBE_TIMEOUT).
    tauri::async_runtime::spawn_blocking(move || {
        use std::io::ErrorKind;
        use std::net::{TcpStream, ToSocketAddrs};
        use std::time::Duration;
        // Embedded mesh-SSH port. RST-vs-timeout tells us whether the HOST is up; open-vs-
        // RST tells us whether SSH is actually being served there. Both matter, and
        // conflating them is the bug this returns three states to avoid.
        const PROBE_PORT: u16 = 22022;
        // 3s was a guess, and it was wrong. A peer with no live tunnel has to do
        // discovery plus a WireGuard handshake before the first byte moves, and that
        // was measured at 5.67s against a freshly enrolled node — so a perfectly
        // healthy node that simply had not been talked to yet timed out, went
        // un-dotted, and had its SSH button disabled. That is the same class of lie
        // this function was rewritten to stop telling, arrived at from the opposite
        // direction. The second connection to the same node took 0.01s, so this
        // ceiling is only ever paid once per cold peer, and the probes already run
        // one thread per target, so a genuinely dead node delays nothing but itself.
        // [T — measured 2026-07-31: cold 5.67s, warm 0.01s; ping6 100% loss before
        //  the handshake, 0% and ~5ms after]
        const PROBE_TIMEOUT: Duration = Duration::from_secs(12);
        let threads: Vec<_> = targets
            .into_iter()
            .map(|ip| {
                std::thread::spawn(move || {
                    // Bracket IPv6 literals (overlay is ULA IPv6; IPv4 passes through).
                    let hostport = if ip.contains(':') {
                        format!("[{ip}]:{PROBE_PORT}")
                    } else {
                        format!("{ip}:{PROBE_PORT}")
                    };
                    let addr = match hostport.to_socket_addrs().ok().and_then(|mut a| a.next()) {
                        Some(a) => a,
                        // Unresolvable is indistinguishable from unreachable to the caller.
                        None => return "timeout",
                    };
                    // Three outcomes, not two. Collapsing the first two into "reachable"
                    // is what let the UI offer SSH on a node that has none: a refusal
                    // proves the host is alive AND that nothing is listening on the mesh
                    // SSH port — an agent too old to embed the F-2 server, or one where it
                    // declined to start. The node is genuinely on the mesh (fresh
                    // handshake, ICMP fine), so every "is it up?" signal says yes while
                    // SSH cannot possibly work. [T — ankayma-desktop, 2026-07-30: refused
                    // in 0.7s on 22022 and on a port known closed; ping 0% loss]
                    match TcpStream::connect_timeout(&addr, PROBE_TIMEOUT) {
                        Ok(_) => "open",
                        Err(e) if e.kind() == ErrorKind::ConnectionRefused => "refused",
                        Err(_) => "timeout",
                    }
                })
            })
            .collect();
        threads
            .into_iter()
            .map(|t| t.join().unwrap_or("timeout").to_string())
            .collect::<Vec<String>>()
    })
    .await
    .map_err(|e| format!("probe task failed: {e}"))
}

/// Path of the data-plane status snapshot the GUI reads for path-proof. On iOS the Packet
/// Tunnel extension (a SEPARATE process) writes it into the App Group container, so the app
/// must read from there, not its own sandbox HOME; the `connect`-side config passes the
/// SAME path to the extension so both agree. macOS reads the daemon's root-owned
/// `/Library/Ankayma/agent-status.json`; other platforms use `~/.ankayma`. [T:F-5]
///
/// iOS-only now: it is the extension's single write target (passed via the connect config)
/// and the read path on iOS. Desktop reads go through `freshest_status_path`, which picks
/// the freshest of the possible daemon locations rather than one fixed spot.
#[cfg(target_os = "ios")]
pub(crate) fn status_snapshot_path() -> std::path::PathBuf {
    #[cfg(target_os = "ios")]
    {
        extern "C" {
            fn ankayma_app_group_dir(buf: *mut std::os::raw::c_char, len: usize);
        }
        let mut buf = [0i8; 1024];
        // SAFETY: valid buffer + length; Swift strlcpy's a NUL-terminated path in (or leaves
        // it empty when the App Group container is unavailable).
        unsafe { ankayma_app_group_dir(buf.as_mut_ptr(), buf.len()) };
        let dir = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) }
            .to_string_lossy()
            .to_string();
        if !dir.is_empty() {
            return std::path::PathBuf::from(dir).join("agent-status.json");
        }
        // else fall through to the home path (unavailable container → best-effort).
    }
    // macOS desktop: the daemon owns its state root-side under /Library/Ankayma
    // (the helper passes --state-dir; launchd gives root daemons no $HOME). The
    // snapshot is world-readable — connection-level metadata only, never payload
    // [T:A.1.1]. See docs/daemon-state-dir.md.
    #[cfg(target_os = "macos")]
    {
        std::path::PathBuf::from("/Library/Ankayma/agent-status.json")
    }
    #[cfg(not(target_os = "macos"))]
    {
        std::path::PathBuf::from(agent_core::home_root()).join(".ankayma/agent-status.json")
    }
}

/// The two places a desktop daemon may have written its status snapshot: the platform
/// system-state dir (a current-build helper spawns the agent with `--state-dir`) and the
/// caller's `~/.ankayma` (a pre-1.1.18 helper spawns it WITHOUT `--state-dir`, so state
/// lands under `$HOME`). System dir first = the canonical current location.
#[cfg(not(target_os = "ios"))]
fn desktop_status_candidates() -> Vec<std::path::PathBuf> {
    let home = std::path::PathBuf::from(agent_core::home_root()).join(".ankayma/agent-status.json");
    #[cfg(target_os = "macos")]
    let sys = std::path::PathBuf::from("/Library/Ankayma/agent-status.json");
    #[cfg(target_os = "windows")]
    let sys = std::path::PathBuf::from("C:\\ProgramData\\Ankayma\\agent-status.json");
    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "ios")))]
    let sys = std::path::PathBuf::from("/var/lib/ankayma/agent-status.json");
    vec![sys, home]
}

/// The status snapshot to READ — the freshest-written of the possible daemon locations.
/// After an app update the OLD root helper can still be resident (launchd does not reload a
/// swapped daemon binary until reboot), so it keeps spawning the agent WITHOUT `--state-dir`
/// and the live snapshot lands in `~/.ankayma` while the new GUI's canonical path is the
/// system dir — reading whichever was written most recently keeps a live tunnel from showing
/// a false "Tunnel down". iOS has a single writer (the extension → App Group), so there is
/// nothing to choose. Read-only: this never writes either path, so it cannot conflict. The
/// helper's own `stop_agent` already dual-reads the same two spots. [T:A.1.1 status metadata]
pub(crate) fn freshest_status_path() -> std::path::PathBuf {
    #[cfg(target_os = "ios")]
    {
        status_snapshot_path()
    }
    #[cfg(not(target_os = "ios"))]
    {
        let candidates = desktop_status_candidates();
        candidates
            .iter()
            .filter_map(|p| {
                std::fs::metadata(p)
                    .and_then(|m| m.modified())
                    .ok()
                    .map(|t| (t, p))
            })
            .max_by_key(|(t, _)| *t)
            .map(|(_, p)| p.clone())
            // Neither snapshot exists yet → return the canonical path; the read fails and the
            // caller reports "down", the same as before.
            .unwrap_or_else(|| candidates.into_iter().next().expect("non-empty candidates"))
    }
}

/// verify the connection is real and peer-to-peer without trusting the GUI alone.
/// vendor_on_data_path is computed from peer states — honest per P.3, not hardcoded.
#[tauri::command]
async fn get_path_proof(state: State<'_, AppState>) -> Result<PathProof, String> {
    let control_plane = state.regional_base_url();
    let not_connected = || PathProof {
        connected: false,
        control_plane: control_plane.clone(),
        vendor_on_data_path: false,
        peers: vec![],
    };

    // The F-5 path proof reads the same status snapshot the data plane writes. On iOS the
    // extension writes it into the App Group container (a separate process from this app);
    // desktop reads the daemon's snapshot from whichever location was written most recently
    // (see freshest_status_path — resilient to a stale root helper after an app update).
    let path = freshest_status_path();
    let Ok(bytes) = std::fs::read(&path) else {
        return Ok(not_connected());
    };

    #[derive(serde::Deserialize)]
    struct FilePeer {
        hostname: String,
        overlay_ip: String,
        endpoint: Option<String>,
        #[serde(default)]
        direct: bool,
        #[serde(default)]
        last_handshake_secs: Option<u64>,
        #[serde(default)]
        tx_bytes: u64,
        #[serde(default)]
        rx_bytes: u64,
    }
    #[derive(serde::Deserialize)]
    struct FileStatus {
        updated_at: u64,
        peers: Vec<FilePeer>,
    }

    let Ok(s) = serde_json::from_slice::<FileStatus>(&bytes) else {
        return Ok(not_connected());
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Fresh if written within 45s: the daemon/extension heartbeat rewrites every 15s, so
    // 3× the heartbeat tolerates a missed tick without flapping "connected" off. [T:F-5]
    let connected = now.saturating_sub(s.updated_at) <= 45;

    // vendor_on_data_path: computed from relay state of each peer (P.3 honest).
    // Currently always false — relay not yet implemented. Becomes correct automatically
    // when relay lands and any peer has direct=false (Personal NAT relay, A.1.12).
    let vendor_on_data_path = s.peers.iter().any(|p| !p.direct);

    Ok(PathProof {
        connected,
        control_plane,
        vendor_on_data_path,
        peers: s
            .peers
            .into_iter()
            .map(|p| PathPeer {
                hostname: p.hostname,
                overlay_ip: p.overlay_ip,
                direct: p.direct,
                endpoint: p.endpoint,
                last_handshake_secs: p.last_handshake_secs,
                tx_bytes: p.tx_bytes,
                rx_bytes: p.rx_bytes,
            })
            .collect(),
    })
}

#[tauri::command]
async fn create_join_link(
    state: State<'_, AppState>,
    ttl_seconds: Option<u64>,
    proof_token: Option<String>,
) -> Result<String, String> {
    // Mint a single-use `ankayma://join?token=…` link via the control plane so a
    // second device enrolls into this tenant (A.1.10/A.1.22). `ttl_seconds` lets the
    // admin pick the expiry; the control plane clamps it. In a multi-user tenant the
    // server gates this behind a step-up — on the first call (no proof) it returns
    // STEP_UP_REQUIRED; the GUI runs the step-up flow and retries with a proof_token.
    let tok = state.token().ok_or("not signed in")?;
    adapters::issue_join_token(
        &state.http,
        &state.regional_base_url(),
        &tok,
        ttl_seconds,
        proof_token.as_deref(),
    )
    .await
    .map_err(|e| e.to_string())
}

/// Build the CLI command to enroll a headless node (server/VPS, no Ankayma app) —
/// `agent up --token <session_token> --control-plane <url>`. Read-only: the GUI
/// never runs this, only displays it for the user to copy onto the server's shell.
/// TODO[A]: reuses the full session token, same as `bring_up_dataplane` does for
/// this device — `agent up` has no `--join-token` flag yet to redeem the scoped
/// join-link instead. Verify-by: ship `--join-token` support on `agent up`
/// (it can reuse `enroll_via_join_token`, already used by `join_enroll_node`),
/// then swap this to a scoped token.
#[tauri::command]
async fn get_server_enroll_command(
    state: State<'_, AppState>,
    join_token: String,
) -> Result<ServerEnrollCommands, String> {
    // Build the server-enroll command from a SCOPED, single-use join token (E-3) —
    // NOT the session token. The caller mints it behind a step-up, exactly like the
    // device invite link, so this command never carries the user's full credential.
    // The agent enrolls the server as AppServer itself. [T:P.3 + invite-flow authority]
    if join_token.is_empty() {
        return Err("missing enrollment token".into());
    }
    let cp = state.regional_base_url();
    Ok(ServerEnrollCommands {
        // Install-and-enroll, one line, per platform. The previous single
        // `agent up --join-token …` assumed the binary was already on the server —
        // true for a machine being re-enrolled, useless on a fresh one, where it is
        // just `command not found`. It predates the headless installers; those now
        // exist for all three platforms and each reads these two variables.
        // [T:scripts/install.sh, install-macos-headless.sh, install-windows.ps1 —
        //  all accept ANKAYMA_JOIN_TOKEN + ANKAYMA_CONTROL_PLANE]
        //
        // The control plane is spelled out rather than left to each installer's
        // default of https://cp.ankayma.com: a tenant in another region would
        // otherwise enroll its server against the wrong one, and the failure would
        // land at first connect rather than here where it is obvious.
        linux: format!(
            "ANKAYMA_JOIN_TOKEN={join_token} ANKAYMA_CONTROL_PLANE={cp} \
             curl -fsSL https://get.ankayma.com/install.sh | sudo sh"
        ),
        macos: format!(
            "ANKAYMA_JOIN_TOKEN={join_token} ANKAYMA_CONTROL_PLANE={cp} \
             curl -fsSL https://get.ankayma.com/macos-headless/install.sh | sudo sh"
        ),
        windows: format!(
            "$env:ANKAYMA_JOIN_TOKEN=\"{join_token}\"; $env:ANKAYMA_CONTROL_PLANE=\"{cp}\"; \
             irm https://get.ankayma.com/windows-headless/install.ps1 | iex"
        ),
        // Kept for a machine that already has the agent — re-enrolling after a wipe,
        // or a host provisioned by something else.
        already_installed: format!("agent up --join-token {join_token} --control-plane {cp}"),
    })
}

/// One install line per platform, all carrying the same single-use join token.
/// The app cannot know what the server runs — it is minting this on the user's
/// laptop — so it hands over all of them rather than guessing and being wrong.
#[derive(serde::Serialize)]
struct ServerEnrollCommands {
    linux: String,
    macos: String,
    windows: String,
    already_installed: String,
}

#[tauri::command]
async fn request_step_up(state: State<'_, AppState>, purpose: String) -> Result<String, String> {
    // Ask the control plane to email an OTP for a sensitive action; returns the
    // challenge_id to pass back at `verify_step_up`. [T:Part D §Authority model]
    let tok = state.token().ok_or("not signed in")?;
    adapters::request_step_up(&state.http, &state.regional_base_url(), &tok, &purpose)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn verify_step_up(
    state: State<'_, AppState>,
    purpose: String,
    challenge_id: String,
    code: String,
) -> Result<String, String> {
    // Exchange the solved OTP for a proof_token, then retry the original action
    // with it. [T:Part D §H.5]
    let tok = state.token().ok_or("not signed in")?;
    adapters::verify_step_up(
        &state.http,
        &state.regional_base_url(),
        &tok,
        &purpose,
        &challenge_id,
        &code,
    )
    .await
    .map_err(|e| e.to_string())
}

#[tauri::command]
async fn verify_step_up_totp(
    state: State<'_, AppState>,
    purpose: String,
    code: String,
) -> Result<String, String> {
    // Same exchange, against the enrolled TOTP secret instead of an emailed
    // challenge. [T:Part D §H.8 Phase 2]
    let tok = state.token().ok_or("not signed in")?;
    adapters::verify_step_up_totp(
        &state.http,
        &state.regional_base_url(),
        &tok,
        &purpose,
        &code,
    )
    .await
    .map_err(|e| e.to_string())
}

// ── TOTP enrollment (Settings → Security) ─────────────────────────────────────

#[tauri::command]
async fn totp_status(state: State<'_, AppState>) -> Result<bool, String> {
    let tok = state.token().ok_or("not signed in")?;
    adapters::totp_status(&state.http, &state.regional_base_url(), &tok)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn totp_enroll(state: State<'_, AppState>) -> Result<(String, String), String> {
    let tok = state.token().ok_or("not signed in")?;
    adapters::totp_enroll(&state.http, &state.regional_base_url(), &tok)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn totp_confirm(state: State<'_, AppState>, code: String) -> Result<(), String> {
    let tok = state.token().ok_or("not signed in")?;
    adapters::totp_confirm(&state.http, &state.regional_base_url(), &tok, &code)
        .await
        .map_err(|e| e.to_string())
}

/// Disable the caller's own TOTP factor. Called WITHOUT a proof first: the CP
/// returns STEP_UP_REQUIRED (`manage_auth_factor`), the GUI's `runWithStepUp`
/// runs the step-up (TOTP, or the AAL2 email "lost-authenticator" path at
/// F0-Plus/F1) and retries WITH the proof. [T:Part D §H.9]
#[tauri::command]
async fn totp_disable(
    state: State<'_, AppState>,
    proof_token: Option<String>,
) -> Result<(), String> {
    let tok = state.token().ok_or("not signed in")?;
    adapters::totp_disable(
        &state.http,
        &state.regional_base_url(),
        &tok,
        proof_token.as_deref(),
    )
    .await
    .map_err(|e| e.to_string())
}

// ── WebAuthn / YubiKey (Settings → Security + step-up AAL3) ──────────────────
// These commands are opaque JSON pass-throughs to the control plane. Where the
// ceremony itself runs depends on the platform: on macOS and iOS it CANNOT run in the
// webview (WKWebView does not support FIDO2 security keys — see
// docs/webauthn-security-key-decision.md), so `webauthn_native_*` below drives it
// through AuthenticationServices and hands back the same JSON the browser path would
// have produced. On iOS that also buys NFC — tapping a YubiKey to the phone is handled
// by the system sheet, no cable — which is the more natural way to use a key there.
// Other platforms still use `navigator.credentials` in the frontend.

/// Whether this platform can run the ceremony natively. The frontend calls this to
/// decide which path to take, rather than sniffing the user agent.
#[tauri::command]
async fn webauthn_native_available() -> bool {
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        webauthn_apple::is_supported()
    }
    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    {
        false
    }
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
async fn webauthn_native_run(
    app: tauri::AppHandle,
    options: serde_json::Value,
    which: webauthn_apple::Ceremony,
) -> Result<serde_json::Value, String> {
    // Only the macOS branch below reaches for a Tauri window; iOS finds its own.
    #[cfg(target_os = "macos")]
    use tauri::Manager;

    // The ceremony needs a presentation anchor and must be started on the main thread;
    // the result arrives asynchronously on the run loop. So: hop to main, start it there,
    // and wait on the channel from this worker. Blocking on the main thread instead would
    // deadlock — the callback we are waiting for is delivered by the very run loop we
    // would be holding.
    //
    // The anchor is `NSWindow` on macOS and `UIWindow` on iOS. Tauri hands us the former;
    // it exposes nothing for the latter, so the iOS side digs the key window out of
    // UIApplication itself (webauthn_apple::presentation_anchor).
    #[cfg(target_os = "macos")]
    let window = app
        .get_webview_window("main")
        .ok_or("no main window to anchor the security key prompt to")?;
    let (tx, rx) = webauthn_apple::channel();

    app.run_on_main_thread(move || {
        #[cfg(target_os = "macos")]
        let anchor = window
            .ns_window()
            .map(|w| w as *mut objc2::runtime::AnyObject)
            .unwrap_or(std::ptr::null_mut());
        #[cfg(target_os = "ios")]
        let anchor = webauthn_apple::presentation_anchor();
        webauthn_apple::start_on_main(anchor, &options, which, tx);
    })
    .map_err(|e| format!("could not start the security key prompt: {e}"))?;

    // `recv` blocks this worker until the user touches the key or dismisses the sheet.
    // There is no timeout here on purpose: the sheet is the OS's, it has its own
    // dismissal affordances, and a client-side timer racing it would leave the delegate
    // alive with nobody listening.
    tauri::async_runtime::spawn_blocking(move || rx.recv())
        .await
        .map_err(|e| format!("security key task failed: {e}"))?
        .map_err(|_| "the security key ceremony ended without a result".to_string())?
}

/// Run the registration ceremony natively and return browser-shaped credential JSON.
#[tauri::command]
async fn webauthn_native_register(
    app: tauri::AppHandle,
    options: serde_json::Value,
) -> Result<serde_json::Value, String> {
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        webauthn_native_run(app, options, webauthn_apple::Ceremony::Register).await
    }
    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    {
        let _ = (app, options);
        Err("native security key support is not available on this platform".to_string())
    }
}

/// Run the assertion ceremony natively and return browser-shaped credential JSON.
#[tauri::command]
async fn webauthn_native_authenticate(
    app: tauri::AppHandle,
    options: serde_json::Value,
) -> Result<serde_json::Value, String> {
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        webauthn_native_run(app, options, webauthn_apple::Ceremony::Authenticate).await
    }
    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    {
        let _ = (app, options);
        Err("native security key support is not available on this platform".to_string())
    }
}

#[tauri::command]
async fn webauthn_status(state: State<'_, AppState>) -> Result<bool, String> {
    let tok = state.token().ok_or("not signed in")?;
    adapters::webauthn_status(&state.http, &state.regional_base_url(), &tok)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn webauthn_register_start(state: State<'_, AppState>) -> Result<serde_json::Value, String> {
    let tok = state.token().ok_or("not signed in")?;
    adapters::webauthn_register_start(&state.http, &state.regional_base_url(), &tok)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn webauthn_register_finish(
    state: State<'_, AppState>,
    state_id: String,
    credential: serde_json::Value,
    label: Option<String>,
) -> Result<(), String> {
    let tok = state.token().ok_or("not signed in")?;
    adapters::webauthn_register_finish(
        &state.http,
        &state.regional_base_url(),
        &tok,
        &state_id,
        credential,
        label.as_deref(),
    )
    .await
    .map_err(|e| e.to_string())
}

#[tauri::command]
async fn webauthn_authenticate_start(
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let tok = state.token().ok_or("not signed in")?;
    adapters::webauthn_authenticate_start(&state.http, &state.regional_base_url(), &tok)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn verify_step_up_webauthn(
    state: State<'_, AppState>,
    purpose: String,
    state_id: String,
    credential: serde_json::Value,
) -> Result<String, String> {
    let tok = state.token().ok_or("not signed in")?;
    adapters::verify_step_up_webauthn(
        &state.http,
        &state.regional_base_url(),
        &tok,
        &purpose,
        &state_id,
        credential,
    )
    .await
    .map_err(|e| e.to_string())
}

// E-7 StepUp: Touch ID/Face ID biometric-only factor (owner-directed 2026-07-28).
// Deliberately NOT the WebAuthn/passkey path — Apple's platform-authenticator
// passkey ceremony falls back to the account password when biometry is
// unavailable, which defeats the point. This uses the lower-level Keychain +
// LocalAuthentication API directly: a Secure Enclave EC key created with access
// control `biometryCurrentSet` and NO `devicePasscode` fallback flag, so a
// failed/cancelled Touch ID fails the step-up outright, never degrades to a
// weaker secret. `[T:developer.apple.com/forums/thread/786171 — SE access needs
// an App ID authorised by a profile; a real signed app bundle satisfies this
// where a bare CLI binary can't]`
#[cfg(any(target_os = "macos", target_os = "ios"))]
const PLATFORM_KEY_LABEL: &str = "com.ankayma.app.stepup.touchid";

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn platform_key_access_control(
) -> Result<security_framework::access_control::SecAccessControl, String> {
    use security_framework::access_control::SecAccessControl;
    // Apple Security.framework SecAccessControlCreateFlags (SecAccessControl.h):
    // kSecAccessControlBiometryCurrentSet = 1u<<3, kSecAccessControlPrivateKeyUsage
    // = 1u<<30. Deliberately NOT combined with kSecAccessControlDevicePasscode
    // (1u<<4) or kSecAccessControlUserPresence (1u<<0) — those allow passcode
    // fallback, which this factor exists specifically to avoid.
    const K_SEC_ACCESS_CONTROL_BIOMETRY_CURRENT_SET: usize = 1 << 3;
    const K_SEC_ACCESS_CONTROL_PRIVATE_KEY_USAGE: usize = 1 << 30;
    SecAccessControl::create_with_flags(
        K_SEC_ACCESS_CONTROL_BIOMETRY_CURRENT_SET | K_SEC_ACCESS_CONTROL_PRIVATE_KEY_USAGE,
    )
    .map_err(|e| format!("create_with_flags failed: {e:?}"))
}

/// Ask LocalAuthentication whether biometrics can be used AT ALL before starting
/// anything, and translate the refusal into something a person can act on.
///
/// Worth the extra call: the common failure is not a broken install, it is a MacBook
/// with the lid shut on an external display. The Touch ID sensor is on the built-in
/// keyboard, so the OS has no way to read a fingerprint and cancels the operation
/// without ever showing a prompt — `LAError.systemCancel` (-4). Other Apple apps quietly
/// fall back to a password in that state, which is why nothing looks broken elsewhere.
/// Surfacing the raw `CFError` for that is a bad message for an ordinary situation, and
/// it cost most of a debugging session to recognise. [T — reproduced 2026-07-29/30:
/// unavailable with the lid closed, works with it open, no code change in between]
#[cfg(any(target_os = "macos", target_os = "ios"))]
fn biometrics_unavailable_reason() -> Option<String> {
    use objc2_local_authentication::{LAContext, LAPolicy};
    let ctx = unsafe { LAContext::new() };
    // Biometrics ONLY — never DeviceOwnerAuthentication, which would offer the account
    // password as a fallback. This factor exists precisely to avoid that (A.1.10).
    let checked =
        unsafe { ctx.canEvaluatePolicy_error(LAPolicy::DeviceOwnerAuthenticationWithBiometrics) };
    let e = match checked {
        Ok(()) => return None,
        Err(e) => e,
    };
    let code = e.code();
    eprintln!(
        "[stepup/platform-key] biometrics unavailable: LAError {code}: {}",
        e.localizedDescription()
    );
    // LAError codes (LAError.h): -5 passcodeNotSet, -6 biometryNotAvailable,
    // -7 biometryNotEnrolled, -8 biometryLockout.
    //
    // The -6 wording is macOS-specific on purpose: a lid shut over an external display is
    // by far the most likely way to reach it there, and naming that saves the reader the
    // debugging session it cost us. On iOS the sensor cannot be "unavailable" for a
    // physical reason, so keep that message plain.
    #[cfg(target_os = "macos")]
    const NAME: &str = "Touch ID";
    #[cfg(target_os = "ios")]
    const NAME: &str = "Face ID / Touch ID";
    Some(match code {
        #[cfg(target_os = "macos")]
        -6 => "Touch ID isn't available right now. If your Mac's lid is closed while you \
               use an external display, open the lid — the sensor is on the built-in keyboard."
            .to_owned(),
        #[cfg(target_os = "ios")]
        -6 => format!("{NAME} isn't available on this device right now."),
        -7 => {
            format!("{NAME} isn't set up on this device yet. Add it in Settings, then try again.")
        }
        -8 => format!(
            "{NAME} is locked after too many failed attempts. Unlock this device with your \
             passcode first, then try again."
        ),
        -5 => format!("{NAME} needs a passcode set on this device."),
        _ => format!("{NAME} isn't available here (LocalAuthentication error {code})."),
    })
}

/// Create the Secure Enclave key with the biometric constraint ACTUALLY attached.
///
/// Hand-built rather than through `security-framework`'s `GenerateKeyOptions`, because
/// that helper pushes `kSecPrivateKeyAttrs` — the sub-dictionary carrying
/// `kSecAttrAccessControl` and `kSecAttrIsPermanent` — only inside a
/// `cfg(target_os = "macos")` block (3.7.0 `src/key.rs:451`, the sole push site; there is
/// no iOS branch anywhere in that file). On iOS the biometric constraint was therefore
/// dropped in silence: the key was created unprotected, signed with no user presence, and
/// the control plane accepted it as a valid AAL2 factor while the UI called it Face ID.
/// Verified on an iPhone 11 / iOS 18.7.8 with 1.1.29 — enrolment never prompted once.
///
/// Building the parameters here puts both platforms on one path that demonstrably carries
/// the ACL, so the divergence cannot come back through a crate upgrade either.
/// macOS deliberately does NOT share this: its `GenerateKeyOptions` path does attach the
/// ACL, and it is verified prompting and signing on hardware. Rewriting a working, proven
/// security control to share code with a broken one trades a real guarantee for tidiness.
/// [T:developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave]
#[cfg(target_os = "ios")]
fn create_platform_key() -> Result<security_framework::key::SecKey, String> {
    use core_foundation::base::{CFTypeRef, TCFType, ToVoid};
    use core_foundation::boolean::CFBoolean;
    use core_foundation::dictionary::CFMutableDictionary;
    use core_foundation::error::CFError;
    use core_foundation::number::CFNumber;
    use core_foundation::string::CFString;
    use security_framework::key::SecKey;
    use security_framework_sys::item::{
        kSecAttrAccessControl, kSecAttrIsPermanent, kSecAttrKeySizeInBits, kSecAttrKeyType,
        kSecAttrKeyTypeECSECPrimeRandom, kSecAttrLabel, kSecAttrTokenID,
        kSecAttrTokenIDSecureEnclave, kSecPrivateKeyAttrs,
    };
    use security_framework_sys::key::SecKeyCreateRandomKey;

    let access_control = platform_key_access_control()?;
    let label = CFString::new(PLATFORM_KEY_LABEL);
    let size = CFNumber::from(256i32);

    // The ACL lives HERE, on the private key, not at the top level — that placement is
    // the entire point of this function.
    let private_attrs = CFMutableDictionary::from_CFType_pairs(&[
        (
            unsafe { kSecAttrIsPermanent }.to_void(),
            CFBoolean::true_value().to_void(),
        ),
        (
            unsafe { kSecAttrAccessControl }.to_void(),
            access_control.to_void(),
        ),
    ]);

    let pairs = vec![
        (
            unsafe { kSecAttrKeyType }.to_void(),
            unsafe { kSecAttrKeyTypeECSECPrimeRandom }.to_void(),
        ),
        (unsafe { kSecAttrKeySizeInBits }.to_void(), size.to_void()),
        (
            unsafe { kSecAttrTokenID }.to_void(),
            unsafe { kSecAttrTokenIDSecureEnclave }.to_void(),
        ),
        (unsafe { kSecAttrLabel }.to_void(), label.to_void()),
        (
            unsafe { kSecPrivateKeyAttrs }.to_void(),
            private_attrs.to_void(),
        ),
    ];
    // No kSecUseDataProtectionKeychain here: iOS has only that keychain, and naming it
    // is not permitted on the platform.

    let params = CFMutableDictionary::from_CFType_pairs(&pairs).to_immutable();
    let mut error: core_foundation::error::CFErrorRef = std::ptr::null_mut();
    let raw = unsafe { SecKeyCreateRandomKey(params.as_concrete_TypeRef(), &mut error) };
    if raw.is_null() {
        let e = unsafe { CFError::wrap_under_create_rule(error) };
        return Err(format!("SecKeyCreateRandomKey failed: {e:?}"));
    }
    Ok(unsafe { SecKey::wrap_under_create_rule(raw as CFTypeRef as _) })
}

/// macOS key creation — unchanged from the version verified on hardware. Kept separate
/// from the iOS implementation above on purpose: this one works, and sharing a body with
/// the platform that needed rewriting would put a proven control at risk for no gain.
#[cfg(target_os = "macos")]
fn create_platform_key() -> Result<security_framework::key::SecKey, String> {
    use security_framework::item::Location;
    use security_framework::key::{GenerateKeyOptions, KeyType, SecKey, Token};

    let access_control = platform_key_access_control()?;
    let mut options = GenerateKeyOptions::default();
    options
        .set_key_type(KeyType::ec())
        .set_token(Token::SecureEnclave)
        .set_label(PLATFORM_KEY_LABEL.to_string())
        // security-framework derives kSecAttrIsPermanent from `location`, so leaving it
        // unset creates the key and drops the private half on the floor. It is also the
        // only keychain Secure Enclave keys may live in.
        .set_location(Location::DataProtectionKeychain)
        .set_access_control(access_control);
    SecKey::new(&options).map_err(|e| format!("SecKey::new failed: {e:?}"))
}

/// Find this app's previously-enrolled Secure Enclave key by its stable label,
/// so `platform_key_sign_challenge` signs with the SAME key `platform_key_enroll`
/// registered server-side (not a freshly-generated one).
#[cfg(any(target_os = "macos", target_os = "ios"))]
/// `auth_ctx` is a retained `LAContext` pointer, or null.
///
/// Signing with a `biometryCurrentSet` Secure Enclave key needs an explicit
/// authentication context. Without one the OS builds an implicit context for the
/// operation and immediately cancels it off the main thread — observed as
/// `com.apple.LocalAuthentication` code -4 (`LAError.systemCancel`, "Authentication
/// canceled"), with no Touch ID prompt ever shown. The documented fix is to create and
/// RETAIN an LAContext and hand it over as `kSecUseAuthenticationContext` on the query
/// that fetches the key; the returned key reference carries it into the signature.
/// Callers that only test for existence pass null — they never trigger biometrics.
/// [T:developer.apple.com/forums/thread/84309 + security-framework src/item.rs:486]
fn find_platform_key(
    auth_ctx: *mut std::os::raw::c_void,
) -> Result<Option<security_framework::key::SecKey>, String> {
    use security_framework::item::{
        ItemClass, ItemSearchOptions, KeyClass, Reference, SearchResult,
    };
    // SecItemCopyMatching returns errSecItemNotFound (-25300) when the label
    // has never been enrolled — that is the empty case, not a hard failure.
    // Treating it as Err made "Set up Touch ID" fail before SecKey::new ran.
    // [T:security-framework ItemSearchOptions::search + errSecItemNotFound]
    const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;
    // Must search the SAME keychain the key was written to. Secure Enclave keys can
    // only live in the data protection keychain, and a search without this looks in the
    // legacy file keychain instead and finds nothing — which is precisely how an
    // enrolled key appeared to vanish. `ignore_legacy_keychains()` is what sets
    // kSecUseDataProtectionKeychain on the query; ItemSearchOptions has no `location`
    // setter (that field belongs to ItemAddOptions).
    // [T:security-framework-3.7.0 src/item.rs:384 sets kSecUseDataProtectionKeychain]
    let mut opts = ItemSearchOptions::new();
    opts.class(ItemClass::key())
        .key_class(KeyClass::private())
        .label(PLATFORM_KEY_LABEL)
        .load_refs(true);
    // macOS only, in both senses: security-framework compiles this method solely for
    // macOS, and iOS has no legacy keychain to steer away from — the data protection
    // keychain is the only one there, so the query already looks in the right place.
    #[cfg(target_os = "macos")]
    opts.ignore_legacy_keychains();
    if !auth_ctx.is_null() {
        use core_foundation::base::TCFType;
        // wrap_under_GET_rule retains, balancing the Retained<LAContext> the caller
        // still owns. The deprecated `authentication_context` takes a CREATE rule
        // (consumes a +1) and would over-release a pointer we did not hand ownership of.
        // SAFETY: auth_ctx is a live LAContext the caller keeps alive past the signature.
        let ctx =
            unsafe { core_foundation::base::CFType::wrap_under_get_rule(auth_ctx as *const _) };
        opts.local_authentication_context(Some(ctx));
    }
    let results = match opts.search() {
        Ok(r) => r,
        Err(e) if e.code() == ERR_SEC_ITEM_NOT_FOUND => return Ok(None),
        Err(e) => return Err(format!("keychain search failed: {e:?}")),
    };
    for r in results {
        if let SearchResult::Ref(Reference::Key(k)) = r {
            return Ok(Some(k));
        }
    }
    Ok(None)
}

/// Drop this device's Secure Enclave key so the next enrolment makes a fresh one.
///
/// Needed because a `biometryCurrentSet` key is permanently invalidated the moment the
/// user's enrolled fingerprints change — and, as this session discovered the hard way,
/// a key created under different entitlements can become unusable to a later build:
/// signing fails with `LAError.systemCancel` and no prompt is ever shown. Without a way
/// to discard it the factor is stuck forever, because enrolment used to reuse whatever
/// key it found. Deleting is safe: the private half never leaves the Secure Enclave and
/// cannot be backed up, so there is nothing to preserve, and the server keeps accepting
/// the other keys on the account.
#[cfg(any(target_os = "macos", target_os = "ios"))]
fn delete_platform_key() -> Result<(), String> {
    use security_framework::item::{ItemClass, ItemSearchOptions, KeyClass};
    const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;
    let mut opts = ItemSearchOptions::new();
    opts.class(ItemClass::key())
        .key_class(KeyClass::private())
        .label(PLATFORM_KEY_LABEL);
    // See find_platform_key: macOS-only method, and iOS needs no equivalent.
    #[cfg(target_os = "macos")]
    opts.ignore_legacy_keychains();
    match opts.delete() {
        Ok(()) => Ok(()),
        // Nothing enrolled is the same end state as a successful delete.
        Err(e) if e.code() == ERR_SEC_ITEM_NOT_FOUND => Ok(()),
        Err(e) => Err(format!("could not remove the old Touch ID key: {e:?}")),
    }
}

/// Create (or reuse) the Secure Enclave key and register its public half with
/// the control plane. Key creation itself does not prompt Touch ID (only a
/// SIGN operation does, per `platform_key_sign_challenge`) — the OS defers the
/// biometric check to first use.
/// Label stored alongside a newly enrolled biometric key — e.g. "Face ID · Bao's
/// iPhone", "Touch ID · MacBook Air".
///
/// Every key from every device used to register as the literal string "Touch ID".
/// That was harmless only for as long as a key could never be taken back: the moment
/// the settings screen lists keys so one can be removed, four identical rows named
/// "Touch ID" pose a question nobody can answer. The user cannot tell which device
/// they are revoking, and the server cannot help: it stores no device identity of its
/// own, so this label is the only thing that ever distinguished one key from another.
///
/// The biometry name comes from `LAContext`, not from the build target. An iPad or an
/// older iPhone authenticates with Touch ID and a Mac never has Face ID, so deciding
/// from `target_os` would print a confident lie on hardware the user owns.
/// [T:LAContext.biometryType — documented as populated once canEvaluatePolicy has run
///  for a biometric policy; LABiometryType::{TouchID = 1, FaceID = 2}]
#[cfg(any(target_os = "macos", target_os = "ios"))]
fn biometric_key_label() -> String {
    use objc2_local_authentication::{LABiometryType, LAContext, LAPolicy};
    let ctx = unsafe { LAContext::new() };
    // biometryType reads .none until a policy evaluation has been attempted; this
    // asks whether biometry COULD be used and never prompts the user.
    let _ =
        unsafe { ctx.canEvaluatePolicy_error(LAPolicy::DeviceOwnerAuthenticationWithBiometrics) };
    let biometry = match unsafe { ctx.biometryType() } {
        LABiometryType::FaceID => "Face ID",
        LABiometryType::TouchID => "Touch ID",
        // Optic ID and whatever Apple adds next: name the device, don't invent a
        // biometry that may not be what the user is actually presenting.
        _ => "Biometrics",
    };
    format!("{biometry} · {}", device_hostname())
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
#[tauri::command]
async fn platform_key_enroll(state: State<'_, AppState>) -> Result<(), String> {
    let tok = state.token().ok_or("not signed in")?;
    // Check before creating anything: enrolling a key this Mac cannot sign with would
    // leave the account advertising a factor it cannot produce.
    if let Some(reason) = biometrics_unavailable_reason() {
        return Err(reason);
    }

    let public_key_b64 = tauri::async_runtime::spawn_blocking(move || -> Result<String, String> {
        // Enrolment is an explicit "set this up on this device" action, so it must not
        // silently reuse a key it cannot verify is still usable — that is exactly how an
        // unusable key survived across builds and left the factor permanently broken
        // with no way out. Always start from a fresh key.
        delete_platform_key()?;
        let key = match find_platform_key(std::ptr::null_mut())? {
            Some(k) => k,
            None => create_platform_key()?,
        };
        // Prove the key can actually SIGN before telling the user (and the server) that
        // Touch ID is set up. Key *generation* never prompts — the OS defers the
        // biometric check to first use — so without this, enrolment succeeds silently on
        // a key that may be unusable, and the failure only surfaces later at the moment
        // the factor is genuinely needed, where it is swallowed as a fallback to an
        // emailed code. That is exactly how a completely non-functional factor reported
        // itself as "Registered". The test signature also gives the user the Touch ID
        // prompt they rightly expect while setting up a fingerprint factor.
        {
            use objc2::rc::Retained;
            use security_framework::key::Algorithm;
            let ctx = unsafe { objc2_local_authentication::LAContext::new() };
            unsafe {
                ctx.setLocalizedReason(&objc2_foundation::NSString::from_str(
                    "set up this device as a step-up factor",
                ))
            };
            let ctx_ptr = Retained::as_ptr(&ctx) as *mut std::os::raw::c_void;
            let probe = find_platform_key(ctx_ptr)?
                .ok_or("the new Touch ID key vanished right after it was created")?;
            if let Err(e) = probe.create_signature(
                Algorithm::ECDSASignatureMessageX962SHA256,
                b"ankayma-enrollment-probe",
            ) {
                eprintln!("[stepup/platform-key] enrolment probe failed: {e:?}");
                // Leave nothing half-enrolled behind: a key we cannot sign with is worse
                // than none, because status would report the factor as available.
                let _ = delete_platform_key();
                return Err(format!("Touch ID could not be set up: {e:?}"));
            }
            drop(ctx);
        }

        let public = key.public_key().ok_or("key has no public half")?;
        let raw = public
            .external_representation()
            .ok_or("no external representation")?;
        use base64::Engine;
        Ok(base64::engine::general_purpose::STANDARD.encode(raw.to_vec()))
    })
    .await
    .map_err(|e| format!("task join error: {e:?}"))??;

    adapters::platform_key_register(
        &state.http,
        &state.regional_base_url(),
        &tok,
        &public_key_b64,
        Some(&biometric_key_label()),
    )
    .await
    .map_err(|e| e.to_string())
}

/// Full step-up ceremony in one round trip: mint a challenge, sign it locally
/// (Touch ID gates the sign — cancel/fail returns an error, never a password
/// prompt), verify server-side, return the proof_token. Mirrors
/// `verify_step_up_totp`'s shape (purpose in, proof_token out) but — unlike a
/// typed code — there's nothing for the frontend to collect from the user.
#[cfg(any(target_os = "macos", target_os = "ios"))]
#[tauri::command]
async fn platform_key_sign_challenge(
    state: State<'_, AppState>,
    purpose: String,
) -> Result<String, String> {
    use security_framework::key::Algorithm;
    let tok = state.token().ok_or("not signed in")?;
    // Fail before minting a server challenge we cannot answer. The caller falls through to
    // TOTP/OTP on any error here, which is right — a lid-shut Mac must not block the
    // action — but the reason still belongs in the log rather than nowhere.
    if let Some(reason) = biometrics_unavailable_reason() {
        return Err(reason);
    }

    // Every failure below is swallowed by the caller (stepup.ts falls through to
    // TOTP/OTP so a dead sensor never blocks the user), so log the reason here or a
    // completely broken factor is indistinguishable from a working one that the user
    // declined. [P.3 — this silence hid a non-functional factor for weeks]
    let (challenge_id, nonce_b64) = match adapters::platform_key_challenge(
        &state.http,
        &state.regional_base_url(),
        &tok,
        &purpose,
    )
    .await
    {
        Ok(v) => v,
        Err(e) => {
            eprintln!("[stepup/platform-key] challenge failed for {purpose}: {e}");
            return Err(e.to_string());
        }
    };

    let signature_b64 = tauri::async_runtime::spawn_blocking(move || -> Result<String, String> {
        use base64::Engine;
        let nonce = base64::engine::general_purpose::STANDARD
            .decode(&nonce_b64)
            .map_err(|e| format!("bad nonce from server: {e}"))?;
        // Create + retain the context BEFORE the lookup, and keep it alive past the
        // signature — dropping it early is the same as never passing one.
        use objc2::rc::Retained;
        let ctx = unsafe { objc2_local_authentication::LAContext::new() };
        unsafe {
            ctx.setLocalizedReason(&objc2_foundation::NSString::from_str(
                "confirm this sensitive action",
            ))
        };
        let ctx_ptr = Retained::as_ptr(&ctx) as *mut std::os::raw::c_void;

        let key = match find_platform_key(ctx_ptr) {
            Ok(Some(k)) => k,
            Ok(None) => {
                eprintln!("[stepup/platform-key] no key found in the keychain");
                return Err("no Touch ID key enrolled".into());
            }
            Err(e) => {
                eprintln!("[stepup/platform-key] keychain search failed: {e}");
                return Err(e);
            }
        };
        let sig = key
            .create_signature(Algorithm::ECDSASignatureMessageX962SHA256, &nonce)
            .map_err(|e| {
                eprintln!("[stepup/platform-key] sign failed: {e:?}");
                format!("Touch ID sign failed/cancelled: {e:?}")
            })?;
        drop(ctx); // explicit: the context must outlive the signature, not the lookup
        Ok(base64::engine::general_purpose::STANDARD.encode(sig))
    })
    .await
    .map_err(|e| format!("task join error: {e:?}"))??;

    adapters::verify_step_up_platform_key(
        &state.http,
        &state.regional_base_url(),
        &tok,
        &purpose,
        &challenge_id,
        &signature_b64,
    )
    .await
    .map_err(|e| {
        eprintln!("[stepup/platform-key] server rejected the signature: {e}");
        e.to_string()
    })
}

/// Whether Touch ID step-up is usable **on this device**.
///
/// The server answer alone is not that question. `platform_stepup_keys` is keyed on
/// `key_id` with only an index on `user_id` — many keys per user is the intended
/// design, one per machine, since the private half lives in that machine's Secure
/// Enclave and cannot move. So "the account has a platform key" says nothing about
/// whether *this* Mac can produce a signature.
///
/// Asking the server only produced a dead end: on a Mac that had never enrolled but
/// whose account had a key from elsewhere, the UI hid the enrol button (nothing to
/// set up) while `platform_key_sign_challenge` would have failed with "no Touch ID
/// key enrolled" at the moment the factor was actually needed. Requiring the local
/// key too means an unenrolled Mac is offered enrolment, which registers an
/// additional key for the account — exactly what the schema is shaped for, and a
/// plain INSERT server-side, so it overwrites nothing. [T: migration 035 has no
/// unique constraint on user_id; platform_key_register INSERTs a fresh key_id]
#[cfg(any(target_os = "macos", target_os = "ios"))]
#[tauri::command]
async fn platform_key_status(state: State<'_, AppState>) -> Result<bool, String> {
    let tok = state.token().ok_or("not signed in")?;
    let on_server = adapters::platform_key_status(&state.http, &state.regional_base_url(), &tok)
        .await
        .map_err(|e| e.to_string())?;
    Ok(on_server && find_platform_key(std::ptr::null_mut())?.is_some())
}

/// List and remove enrolled step-up factors.
///
/// Deliberately NOT gated behind `cfg(macos/ios)` like enrolment and signing are.
/// Those need a Secure Enclave on this machine; these are pure account operations.
/// A key enrolled on a phone that was lost has to be removable from whatever device
/// the user still has, and gating removal on owning the hardware would mean the keys
/// most urgently needing removal are exactly the ones nothing can reach.
#[tauri::command]
async fn platform_key_list(
    state: State<'_, AppState>,
) -> Result<Vec<adapters::StepUpFactor>, String> {
    let tok = state.token().ok_or("not signed in")?;
    adapters::platform_key_list(&state.http, &state.regional_base_url(), &tok)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn security_key_list(
    state: State<'_, AppState>,
) -> Result<Vec<adapters::StepUpFactor>, String> {
    let tok = state.token().ok_or("not signed in")?;
    adapters::security_key_list(&state.http, &state.regional_base_url(), &tok)
        .await
        .map_err(|e| e.to_string())
}

/// Remove one Touch ID/Face ID key. `proof_token` comes from the step-up ceremony
/// the frontend runs after the first call comes back STEP_UP_REQUIRED.
#[tauri::command]
async fn platform_key_remove(
    state: State<'_, AppState>,
    key_id: String,
    proof_token: Option<String>,
) -> Result<(), String> {
    let tok = state.token().ok_or("not signed in")?;
    adapters::platform_key_delete(
        &state.http,
        &state.regional_base_url(),
        &tok,
        &key_id,
        proof_token.as_deref(),
    )
    .await
    .map_err(|e| e.to_string())?;
    // The local Secure Enclave key is now an orphan in the other direction: the
    // server no longer knows it, so it can never satisfy a step-up again. Clearing
    // it keeps `platform_key_status` (server AND local) honest, and means the enrol
    // button reappears instead of the UI insisting a dead factor is set up.
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        let _ = delete_platform_key();
    }
    Ok(())
}

/// Remove one FIDO2 security key. The server answers 409 if this is the last one
/// and the plan floors at AAL3 — nothing weaker could authorize enrolling a
/// replacement, so it refuses rather than stranding the account.
#[tauri::command]
async fn security_key_remove(
    state: State<'_, AppState>,
    credential_id: String,
    proof_token: Option<String>,
) -> Result<(), String> {
    let tok = state.token().ok_or("not signed in")?;
    adapters::security_key_delete(
        &state.http,
        &state.regional_base_url(),
        &tok,
        &credential_id,
        proof_token.as_deref(),
    )
    .await
    .map_err(|e| e.to_string())
}

#[cfg(not(any(target_os = "macos", target_os = "ios")))]
#[tauri::command]
async fn platform_key_enroll(_state: State<'_, AppState>) -> Result<(), String> {
    Err("Face ID / Touch ID step-up is not available on this platform".into())
}

#[cfg(not(any(target_os = "macos", target_os = "ios")))]
#[tauri::command]
async fn platform_key_sign_challenge(
    _state: State<'_, AppState>,
    _purpose: String,
) -> Result<String, String> {
    Err("Face ID / Touch ID step-up is not available on this platform".into())
}

#[cfg(not(any(target_os = "macos", target_os = "ios")))]
#[tauri::command]
async fn platform_key_status(_state: State<'_, AppState>) -> Result<bool, String> {
    Ok(false)
}

/// Recipient side of the node-invite (`ankayma://join?token=…`): enroll THIS device
/// into the invite's tenant using only the join token. No session is required — the
/// token IS the authorization to join (A.1.10/A.1.22), so this works whether or not
/// the user is signed in. Mirrors the in-process bookkeeping of `connect_inner`
/// (persist identity for the privileged-daemon handoff, then publish the node).
#[tauri::command]
async fn join_enroll_node(
    app: AppHandle,
    state: State<'_, AppState>,
    join_token: String,
    hostname: String,
) -> Result<Option<AuthState>, String> {
    let join_token = join_token.trim().to_string();
    if join_token.is_empty() {
        return Err("join token is empty".into());
    }
    let hostname = {
        let h = hostname.trim();
        if h.is_empty() {
            device_hostname()
        } else {
            h.to_string()
        }
    };

    // Fresh WireGuard identity for this device, same as a first-device enroll. The
    // MACHINE identity is not fresh — it is whatever this device has always had, and
    // presenting it here is what lets an invite re-admit a device an administrator
    // previously revoked.
    let state_dir = handoff_state_dir(state.inner());
    let kp = WgKeypair::generate();
    let machine = machine_key::MachineKey::load_or_create(&state_dir)
        .map_err(|e| format!("cannot load this device's identity: {e}"))?;
    let proof = machine
        .proof_now(&kp.public_b64)
        .map_err(|e| format!("cannot prove this device's identity: {e}"))?;
    let req = adapters::JoinEnrollRequest {
        join_token,
        public_key: kp.public_b64.clone(),
        hostname,
        endpoint: None,
        // An app device joining its own tenant is not a server node. [T:Part B §B.1.4]
        workload_kind: None,
        platform: Some(std::env::consts::OS.to_string()),
        machine_proof: Some(proof),
    };
    let resp = adapters::enroll_via_join_token(&state.http, &state.regional_base_url(), &req)
        .await
        .map_err(|e| e.to_string())?;
    // [T:devices.md "no second GitHub login"] The CP mints a session for the invite
    // owner on redeem so this device signs into their account with no second OAuth.
    // Older CPs omit it → None → the UI guides the user to sign in first.
    let session_token = resp.session_token.clone();

    // Handoff: persist this identity so a reconnect reuses THIS node — no
    // duplicate enroll. iOS→app data dir, desktop→~/.ankayma. [T:A.1.10 / up.rs]
    if let Err(e) = write_handoff_state_to(
        &state_dir,
        &kp.private_b64,
        &kp.public_b64,
        &resp.node_id,
        &resp.overlay_ip,
        resp.node_service_token.as_deref(),
        resp.token_expires_at.as_deref(),
    ) {
        log::warn!("handoff state not written ({e}); a reconnect would re-enroll");
    }

    *state.node.lock().expect("node lock poisoned") = Some(EnrolledNode {
        private_b64: kp.private_b64,
        public_b64: kp.public_b64,
        node_id: resp.node_id,
        overlay_ip: resp.overlay_ip,
        peers: resp.peers,
    });
    apply_connection_change(&app);

    // Sign into the owner's account from the minted session (no second GitHub login).
    // apply_session_token only validates + stores the session (it does NOT re-enroll a
    // node), so it composes cleanly on top of the node we just enrolled.
    match session_token {
        Some(tok) => {
            let user = apply_session_token(&app, tok).await?;
            Ok(Some(AuthState::Authenticated { user }))
        }
        None => Ok(None),
    }
}

// --- Data plane (milestone 1.2 — privileged daemon handoff) ---
// The GUI cannot open a utun device (root-only on macOS), so it enrolls on the
// control plane (no privilege) and hands the identity to the `agent` daemon,
// which owns the kernel tunnel (utun + boringtun). Mirrors up.rs `AgentState`.

const DATAPLANE_LISTEN_PORT: u16 = 51820; // WireGuard default; matches agent-daemon

/// Persist the enrolled identity to `<dir>/agent.json` so a reconnect reuses THIS
/// node instead of enrolling a second one. `dir` comes from `handoff_state_dir`
/// (desktop: ~/.ankayma, shared with the `agent up` daemon; iOS: app data dir).
/// Shape mirrors `agent-daemon::up::AgentState`. Body testable without touching
/// the process-global HOME.
fn write_handoff_state_to(
    dir: &std::path::Path,
    private_b64: &str,
    public_b64: &str,
    node_id: &str,
    overlay_ip: &str,
    service_token: Option<&str>,
    token_expires_at: Option<&str>,
) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("mkdir ~/.ankayma: {e}"))?;
    // Persist the scoped node service token (D.11) too — agent-daemon reads it from
    // here, and without it `agent up` reports "no node service token" and cannot
    // bring the tunnel up from the GUI's enrollment. Mirrors agent-daemon's
    // AgentState write. [T:agent-daemon/src/up.rs:1015 service_token persist]
    let state = serde_json::json!({
        "private_b64": private_b64,
        "public_b64": public_b64,
        "node_id": node_id,
        "overlay_ip": overlay_ip,
        "listen_port": DATAPLANE_LISTEN_PORT,
        "service_token": service_token,
        "token_expires_at": token_expires_at,
    });
    let bytes = serde_json::to_vec_pretty(&state).map_err(|e| e.to_string())?;
    let path = dir.join("agent.json");
    // mode 0o600: the file carries the WG private key — must not be readable
    // by other local users. Mirrors agent-daemon up.rs, which writes the SAME
    // file with the same permissions [T:agent-daemon/src/up.rs write path].
    #[cfg(unix)]
    let mut f = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&path)
            .map_err(|e| format!("create agent.json: {e}"))?
    };
    // mode() above only applies on create — a pre-existing agent.json written
    // by an older build kept its 0644, so force 0600 on the open handle too.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        f.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("chmod agent.json: {e}"))?;
    }
    #[cfg(not(unix))]
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&path)
        .map_err(|e| format!("create agent.json: {e}"))?;
    use std::io::Write;
    f.write_all(&bytes)
        .map_err(|e| format!("write agent.json: {e}"))
}

/// Locate the `agent` daemon binary — next to this app (bundled) or a dev build.
/// On Windows the bundled sidecar is `agent.exe`; joining a bare `agent` missed it.
fn locate_agent_binary() -> Result<std::path::PathBuf, String> {
    let exe_name = if cfg!(windows) { "agent.exe" } else { "agent" };
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let sib = dir.join(exe_name);
            if sib.exists() {
                return Ok(sib);
            }
        }
    }
    for base in [
        "target/debug",
        "target/release",
        "../../target/debug",
        "../../target/release",
    ] {
        let pb = std::path::PathBuf::from(base).join(exe_name);
        if pb.exists() {
            return Ok(pb.canonicalize().unwrap_or(pb));
        }
    }
    Err("agent daemon binary not found (looked next to the app and in target/)".into())
}

/// Root-owned LaunchDaemon IPC (A.1.7 gap 1). Replaces the earlier osascript
/// `with administrator privileges` quick-fix, which prompted for the admin
/// password on EVERY connect/disconnect, couldn't be scripted/automated, and
/// (per docs/hotfix-macos-dataplane-gaps.md) is a pattern Apple rejects from a
/// sandboxed App Store build. `com.ankayma.helper` installs once via
/// SMAppService (one admin prompt total, not per action) and stays resident;
/// the GUI then just talks to its Unix socket. See
/// `gui/src-tauri/macos/PrivilegedHelper/src/main.rs` for the daemon itself.
#[cfg(target_os = "macos")]
mod helper_ipc {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    const SOCKET_PATH: &str = "/var/run/com.ankayma.helper.sock";
    const HELPER_PLIST_NAME: &str = "com.ankayma.helper.plist";

    /// Idempotent via `status()`, NOT via matching `register()`'s error variant —
    /// live-tested 2026-07-01 and a repeat `SMAppService.register()` call on an
    /// already-registered daemon surfaced as a bare "unknown error 1", not
    /// smappservice-rs's mapped `AlreadyRegistered`. [A] that crate's
    /// ServiceManagementError enum (0.1.3) reuses the legacy `SMErrors.h`
    /// (SMJobBless) numeric codes, which don't line up with what the modern
    /// SMAppService API actually returns — checking status first sidesteps the
    /// mismatch entirely instead of depending on it. macOS 13+ only.
    /// Whether the helper's control socket is actually answering — the ground
    /// truth that the daemon is loaded AND running, which `status()` alone does
    /// NOT guarantee (see below).
    fn socket_live() -> bool {
        UnixStream::connect(SOCKET_PATH).is_ok()
    }

    pub fn ensure_registered() -> Result<(), String> {
        use smappservice_rs::{AppService, ServiceStatus, ServiceType};
        // Ground truth first: if the privileged helper is already answering its
        // socket, it's installed and running — use it, whatever SMAppService's
        // BTM bookkeeping says. This makes Connect robust to a helper installed
        // by any means (SMAppService, a manual LaunchDaemon, an MDM push) and
        // sidesteps smappservice-rs 0.1.3's unreliable status()/register() error
        // mapping when BTM state is stale after reinstall/re-sign churn.
        if socket_live() {
            return Ok(());
        }
        let svc = AppService::new(ServiceType::Daemon {
            plist_name: HELPER_PLIST_NAME,
        });
        match svc.status() {
            // `Enabled` in the Background Task Manager DB does NOT prove launchd
            // has the CURRENT app generation's job loaded: after a reinstall /
            // re-sign / reboot, BTM can still read "enabled" (a stale generation)
            // while no daemon is actually running and the socket is absent
            // (observed 2026-07-03: app gen 3, helper registration gen 1, socket
            // missing → "connect helper: No such file or directory"). If the
            // socket is dead, force a re-register (unregister → register) so
            // launchd reloads the job for this generation. `[T:A.1.7 dataplane]`
            ServiceStatus::Enabled => {
                if socket_live() {
                    return Ok(());
                }
                let _ = svc.unregister(); // best-effort clear of the stale job
                svc.register()
                    .map_err(|e| format!("re-register helper daemon (stale registration): {e}"))
            }
            ServiceStatus::RequiresApproval => {
                AppService::open_system_settings_login_items();
                Err(
                    "helper daemon needs approval — turn on Ankayma under System Settings > General > Login Items & Extensions > App Background Activity, then try again"
                        .into(),
                )
            }
            ServiceStatus::NotRegistered | ServiceStatus::NotFound => svc
                .register()
                .map_err(|e| format!("register helper daemon: {e}")),
        }
    }

    /// Read-only pre-flight check: is the privileged helper ready to serve — either
    /// already answering its socket, or registered AND enabled in the Background Task
    /// Manager? Never mutates state and never prompts, so the UI can poll it freely
    /// (unlike `ensure_registered`, whose `Enabled`-but-dead-socket branch re-registers).
    pub fn preflight_ready() -> bool {
        use smappservice_rs::{AppService, ServiceStatus, ServiceType};
        if socket_live() {
            return true;
        }
        let svc = AppService::new(ServiceType::Daemon {
            plist_name: HELPER_PLIST_NAME,
        });
        matches!(svc.status(), ServiceStatus::Enabled)
    }

    /// Pre-flight request, run from the onboarding card BEFORE the first Connect:
    /// register the helper if needed and, when the user still has to flip the System
    /// Settings switch, deep-link them straight to it. Unlike `ensure_registered`,
    /// `RequiresApproval` is NOT an error here — the card polls `preflight_ready`
    /// until the toggle is on. Mirrors how iOS asks for the VPN configuration at
    /// setup rather than at connect time.
    pub fn preflight_request() -> Result<(), String> {
        use smappservice_rs::{AppService, ServiceStatus, ServiceType};
        if socket_live() {
            return Ok(());
        }
        let svc = AppService::new(ServiceType::Daemon {
            plist_name: HELPER_PLIST_NAME,
        });
        match svc.status() {
            ServiceStatus::Enabled => Ok(()),
            ServiceStatus::RequiresApproval => {
                AppService::open_system_settings_login_items();
                Ok(())
            }
            ServiceStatus::NotRegistered | ServiceStatus::NotFound => {
                svc.register()
                    .map_err(|e| format!("register helper daemon: {e}"))?;
                // A fresh registration lands in RequiresApproval — take the user to
                // the switch so they don't have to hunt for it.
                if matches!(svc.status(), ServiceStatus::RequiresApproval) {
                    AppService::open_system_settings_login_items();
                }
                Ok(())
            }
        }
    }

    #[derive(serde::Serialize)]
    #[serde(tag = "command", rename_all = "lowercase")]
    enum Request<'a> {
        Start {
            agent_bin: &'a str,
            token: &'a str,
            control_plane: &'a str,
            home: &'a str,
            /// The enrolled identity (agent.json content). The daemon's state lives
            /// root-owned under /Library/Ankayma (launchd gives root daemons no
            /// $HOME), so the handoff rides the IPC request instead of a shared
            /// ~/.ankayma. See docs/daemon-state-dir.md.
            state_json: &'a str,
        },
        Stop {
            home: &'a str,
        },
        /// Ask the root helper for the tail of the two daemon logs (user-triggered
        /// diagnostics). Only the owning user (authorized by home-dir ownership) can
        /// read their own agent's root-owned logs.
        Readlogtail {
            home: &'a str,
        },
    }

    #[derive(serde::Deserialize, Default)]
    struct Response {
        ok: bool,
        error: Option<String>,
        #[serde(default)]
        agent_log: Option<String>,
        #[serde(default)]
        helper_log: Option<String>,
    }

    /// Round-trip one request and return the parsed `Response` (log fields intact).
    fn send_raw(req: &Request) -> Result<Response, String> {
        // First launch after ensure_registered() races launchd actually binding
        // the socket — retry briefly instead of failing the user's first click.
        let mut last_err = String::new();
        let mut stream = None;
        for _ in 0..10 {
            match UnixStream::connect(SOCKET_PATH) {
                Ok(s) => {
                    stream = Some(s);
                    break;
                }
                Err(e) => {
                    last_err = e.to_string();
                    std::thread::sleep(Duration::from_millis(200));
                }
            }
        }
        let mut stream = stream.ok_or_else(|| format!("connect helper: {last_err}"))?;
        stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
        let body = serde_json::to_string(req).map_err(|e| e.to_string())?;
        writeln!(stream, "{body}").map_err(|e| format!("send helper: {e}"))?;
        let mut line = String::new();
        BufReader::new(&stream)
            .read_line(&mut line)
            .map_err(|e| format!("read helper: {e}"))?;
        serde_json::from_str(line.trim()).map_err(|e| format!("bad helper response: {e}"))
    }

    fn send(req: &Request) -> Result<(), String> {
        let resp = send_raw(req)?;
        if resp.ok {
            Ok(())
        } else {
            Err(resp
                .error
                .unwrap_or_else(|| "helper reported failure".into()))
        }
    }

    /// (agent.log tail, helper.log tail) from the root helper — for the diagnostics
    /// bundle. Best-effort: the caller degrades gracefully if the helper is absent.
    pub fn read_log_tail(home: &str) -> Result<(String, String), String> {
        let resp = send_raw(&Request::Readlogtail { home })?;
        if !resp.ok {
            return Err(resp
                .error
                .unwrap_or_else(|| "helper reported failure".into()));
        }
        Ok((
            resp.agent_log.unwrap_or_default(),
            resp.helper_log.unwrap_or_default(),
        ))
    }

    pub fn start(
        agent_bin: &str,
        token: &str,
        control_plane: &str,
        home: &str,
        state_json: &str,
    ) -> Result<(), String> {
        send(&Request::Start {
            agent_bin,
            token,
            control_plane,
            home,
            state_json,
        })
    }

    pub fn stop(home: &str) -> Result<(), String> {
        send(&Request::Stop { home })
    }
}

/// Launch the privileged `agent` daemon (utun + boringtun need root) via the
/// `com.ankayma.helper` LaunchDaemon. First call registers the daemon (one
/// admin prompt); every call after that is password-free.
#[cfg(target_os = "macos")]
fn bring_up_dataplane(
    agent_bin: &std::path::Path,
    token: &str,
    control_plane: &str,
) -> Result<(), String> {
    helper_ipc::ensure_registered()?;
    let home = std::env::var("HOME").map_err(|_| "HOME not set".to_string())?;
    // The enrolled identity rides the IPC request; the daemon keeps its own copy
    // under /Library/Ankayma. Reading the caller's ~/.ankayma from the root daemon
    // never reliably worked (launchd strips $HOME) and is CWE-59 surface besides.
    let state_json = std::fs::read_to_string(
        std::path::Path::new(&home)
            .join(".ankayma")
            .join("agent.json"),
    )
    .map_err(|e| format!("read enrolled identity for the daemon handoff: {e}"))?;
    helper_ipc::start(
        &agent_bin.to_string_lossy(),
        token,
        control_plane,
        &home,
        &state_json,
    )
}

/// Windows: the `Ankayma` service (LocalSystem, always running — see
/// `docs/windows-daemon-lifecycle-decision.md`) already holds the Wintun
/// adapter; this just asks it, over the named pipe, to bring a tunnel up for
/// `token`/`control_plane` — **no elevation, no UAC**, unlike the old
/// `Start-Process … -Verb RunAs` this replaces. `ensure_installed` is the one
/// remaining elevation point, and only the very first time this device ever
/// connects (no-op, no prompt, on every call after that). `[T:A.1.3]`
#[cfg(target_os = "windows")]
fn bring_up_dataplane(
    agent_bin: &std::path::Path,
    token: &str,
    control_plane: &str,
) -> Result<(), String> {
    win_service_install::ensure_installed(agent_bin)?;
    win_service_client::connect(token, control_plane)
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn bring_up_dataplane(_b: &std::path::Path, _t: &str, _c: &str) -> Result<(), String> {
    Err("data plane is macOS-only at milestone 1.2".into())
}

/// Hand the enrolled identity to the privileged daemon so a real WireGuard tunnel
/// comes up. Enroll (`connect`) first; macOS prompts for admin once.
#[tauri::command]
async fn start_dataplane(state: State<'_, AppState>) -> Result<(), String> {
    start_dataplane_inner(&state).await
}

/// Body of `start_dataplane`, callable from non-command contexts too — the tray
/// Connect used to run `connect_inner` alone, which enrolled but never brought
/// the tunnel up (one more way to a green UI over a dead data plane).
async fn start_dataplane_inner(state: &AppState) -> Result<(), String> {
    let tok = state.token().ok_or("not signed in")?;
    if state.node.lock().expect("node lock poisoned").is_none() {
        return Err("not connected — enroll first".into());
    }
    let bin = locate_agent_binary()?;
    // bring_up_dataplane blocks (UnixStream connect retry loop with
    // thread::sleep); run it off the async runtime so it doesn't stall the
    // Tauri executor (audit 2026-07-02).
    let base_url = state.regional_base_url();
    let outcome =
        tauri::async_runtime::spawn_blocking(move || bring_up_dataplane(&bin, &tok, &base_url))
            .await
            .map_err(|e| format!("dataplane task panicked: {e}"))?;
    // Feed current_connection's settle window: success = daemon starting now
    // (grant it DATAPLANE_SETTLE_SECS to write the first snapshot); failure = an
    // already-expired stamp, so the state reads DataplaneDown immediately instead
    // of "Connecting" forever.
    #[cfg(not(any(target_os = "ios", target_os = "android")))]
    {
        let stamp = if outcome.is_ok() {
            std::time::Instant::now()
        } else {
            std::time::Instant::now()
                .checked_sub(std::time::Duration::from_secs(DATAPLANE_SETTLE_SECS + 1))
                .unwrap_or_else(std::time::Instant::now)
        };
        *state
            .dataplane_started
            .lock()
            .expect("dataplane_started lock poisoned") = Some(stamp);
    }
    outcome
}

/// Tear down the data plane (stop the privileged daemon). Killing a root-owned
/// process needs admin — macOS prompts once. Prefer the recorded PID (clean),
/// fall back to a name match. Plain sync fn (no `.await` inside) so it's callable
/// from non-command contexts too: tray disconnect (A.1.7 gap 3) and app-exit
/// cleanup (A.1.7 gap 2), not just the `stop_dataplane` Tauri command.
#[cfg(target_os = "macos")]
fn stop_dataplane_inner() -> Result<(), String> {
    let home = std::env::var("HOME").unwrap_or_default();
    helper_ipc::stop(&home)
}

/// Windows: a `Disconnect` over the named pipe to the always-on `Ankayma`
/// service — **no elevation** (replaces the old elevated `taskkill /IM
/// agent.exe /F`, which returned before the kill, or its UAC prompt, actually
/// resolved). Verified: the reply only comes back once the service's
/// supervisor has actually finished `Child::kill()` + `Child::wait()` on the
/// real child process — nothing left to guess via `tasklist` afterward.
/// `docs/windows-daemon-lifecycle-decision.md`
#[cfg(target_os = "windows")]
fn stop_dataplane_inner() -> Result<(), String> {
    win_service_client::disconnect()
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn stop_dataplane_inner() -> Result<(), String> {
    Err("data plane is macOS-only".into())
}

#[tauri::command]
async fn stop_dataplane() -> Result<(), String> {
    stop_dataplane_inner()
}

/// [F-2] "Open in Terminal" — launch a full external terminal (Terminal.app,
/// iTerm2, or any app that runs `.command` files) on the SAME mesh transport as the
/// in-app terminal (`agent ssh --mesh`, identity-bound — no key, no password). For
/// power users who want their terminal's features. Desktop only (iOS has none).
/// The session token is NEVER inlined — the launcher reads it from the 0600 file at
/// run time. `[T:f2 §H.2.2]`
#[tauri::command]
async fn open_ssh_terminal(
    state: State<'_, AppState>,
    node_id: String,
    login: Option<String>,
    terminal_app: Option<String>,
) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        state.token().ok_or("not signed in")?;
        // node_id/login are interpolated into a shell line — allowlist, don't escape.
        let ok = |s: &str| {
            !s.is_empty()
                && s.chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
        };
        if !ok(&node_id) {
            return Err("invalid node id".into());
        }
        if let Some(l) = login.as_deref() {
            if !ok(l) {
                return Err("invalid login".into());
            }
        }
        // The terminal app name (e.g. "Terminal", "iTerm", "iTerm2", "Ghostty").
        let app = terminal_app.unwrap_or_else(|| "Terminal".to_string());
        if app.is_empty()
            || !app
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, ' ' | '_' | '-' | '.'))
        {
            return Err("invalid terminal app".into());
        }
        let bin = locate_agent_binary()?;
        let session = session_file_path(&state.data_dir);
        // Identity-bound mesh transport (same as the in-app terminal): no static key,
        // no password. Token read from the 0600 file at run time.
        let mut inner = format!(
            "ANKAYMA_TOKEN=\"$(cat '{}')\" '{}' ssh {node_id} --mesh --allow-unpinned --control-plane {}",
            session.display(),
            bin.display(),
            state.regional_base_url()
        );
        if let Some(l) = login.as_deref() {
            inner.push_str(&format!(" --login {l}"));
        }
        // A `.command` launcher runs in Terminal.app, iTerm2, Ghostty, … so any
        // terminal works via `open -a <App>` (vs. Terminal-only AppleScript).
        let script = format!("#!/bin/sh\nclear\n{inner}\n");
        let path = std::env::temp_dir().join(format!("ankayma-ssh-{node_id}.command"));
        std::fs::write(&path, script).map_err(|e| format!("write launcher: {e}"))?;
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700));
        }
        let status = std::process::Command::new("open")
            .arg("-a")
            .arg(&app)
            .arg(&path)
            .status()
            .map_err(|e| format!("launch {app}: {e}"))?;
        if !status.success() {
            return Err(format!("could not open \"{app}\" — is it installed?"));
        }
        Ok(())
    }
    #[cfg(target_os = "windows")]
    {
        state.token().ok_or("not signed in")?;
        // node_id/login are interpolated into a command line — allowlist, don't escape.
        let ok = |s: &str| {
            !s.is_empty()
                && s.chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
        };
        if !ok(&node_id) {
            return Err("invalid node id".into());
        }
        if let Some(l) = login.as_deref() {
            if !ok(l) {
                return Err("invalid login".into());
            }
        }
        let app = terminal_app.unwrap_or_else(|| "cmd".to_string());
        let bin = locate_agent_binary()?;
        let session = session_file_path(&state.data_dir);
        // .bat launcher: read the 0600 token file at run time (never inline the
        // token), then run the identity-bound mesh SSH — same transport as the
        // in-app terminal (no static key, no password). `[T:f2 §H.2.2]`
        let mut inner = format!(
            "@echo off\r\nset /p ANKAYMA_TOKEN=<\"{}\"\r\n\"{}\" ssh {node_id} --mesh --allow-unpinned --control-plane {}",
            session.display(),
            bin.display(),
            state.regional_base_url()
        );
        if let Some(l) = login.as_deref() {
            inner.push_str(&format!(" --login {l}"));
        }
        inner.push_str("\r\n");
        let path = std::env::temp_dir().join(format!("ankayma-ssh-{node_id}.bat"));
        std::fs::write(&path, inner).map_err(|e| format!("write launcher: {e}"))?;
        let bat = path.to_string_lossy().to_string();
        let title = format!("Ankayma SSH - {node_id}");
        // Open the chosen Windows terminal running the launcher. `cmd /k` keeps the
        // window after the session ends so errors stay readable.
        let launch = match app.as_str() {
            "wt" | "Windows Terminal" => std::process::Command::new("wt.exe")
                .args(["cmd", "/k", &bat])
                .status(),
            "powershell" | "PowerShell" => std::process::Command::new("cmd")
                .args([
                    "/c",
                    "start",
                    &title,
                    "powershell",
                    "-NoExit",
                    "-Command",
                    &format!("& '{bat}'"),
                ])
                .status(),
            _ => std::process::Command::new("cmd")
                .args(["/c", "start", &title, "cmd", "/k", &bat])
                .status(),
        };
        let status = launch.map_err(|e| format!("launch {app}: {e}"))?;
        if !status.success() {
            return Err(format!("could not open \"{app}\" — is it installed?"));
        }
        Ok(())
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        let _ = (node_id, login, terminal_app);
        Err("external terminal is desktop-only".into())
    }
}

/// [F-2 §H.2.2] Open an in-app SSH terminal to a node using the pure-Rust mesh
/// transport (russh) — works on desktop AND iOS/iPad (no system Terminal needed).
/// Returns a session id; the read side streams `ssh_data_<id>` events (base64) to
/// xterm.js, and `ssh_write`/`ssh_resize`/`ssh_close` drive it. `[T:f2 §H.1]`
#[tauri::command]
#[allow(clippy::too_many_arguments)] // a Tauri command's args are its JS call shape
async fn ssh_open(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    node_id: String,
    login: Option<String>,
    root: bool,
    proof: Option<String>,
    cols: u32,
    rows: u32,
) -> Result<String, String> {
    use agent_core::ssh_client::{MeshSshKey, SshConnectOptions, SshEvent, SshSession};
    use base64::Engine as _;
    use tauri::Emitter;

    let token = state.token().ok_or("not signed in")?;

    // 1. Resolve the target + anchor the session in the ledger (never sees the stream).
    let resp = agent_core::adapters::open_ssh_session(
        &state.http,
        &state.regional_base_url(),
        &token,
        &domain::SshSessionRequest {
            node_id: node_id.clone(),
            login: login.clone(),
        },
    )
    .await
    .map_err(|e| format!("open ssh session: {e}"))?;

    // 2. Optional root elevation grant (§H.4). F0 owner instant; F1+ carries `proof`.
    let elevate_grant = if root {
        let g = agent_core::adapters::elevate_ssh_session(
            &state.http,
            &state.regional_base_url(),
            &token,
            &domain::SshElevateRequest {
                node_id: node_id.clone(),
                persona: "root".to_string(),
                duration_secs: None,
                proof_token: proof,
            },
        )
        .await
        .map_err(|e| format!("request elevation: {e}"))?;
        Some(g.grant)
    } else {
        None
    };

    // 3. Connect with the device's mesh-SSH key (A.1.3 — no password/static key).
    let key_path = handoff_state_dir(&state).join("mesh-ssh-ed25519");
    let key = MeshSshKey::load_or_generate(&key_path).map_err(|e| format!("mesh ssh key: {e}"))?;
    // Client login is always the shared user; root elevation happens server-side via
    // the grant (§H.4), not by changing the SSH login.
    let effective_login = resp
        .login
        .clone()
        .or(login)
        .unwrap_or_else(|| "ankayma".to_string());
    let mut opts = SshConnectOptions::new(resp.overlay_ip.clone(), effective_login);
    opts.port = resp.ssh_port.unwrap_or(22022);
    opts.expected_host_key = resp.server_host_key.clone();
    // Until the control plane returns a host-key pin, allow TOFU (honest — the
    // overlay transport already authenticates the peer). `[A]`
    opts.allow_unpinned = opts.expected_host_key.is_none();
    opts.elevate_grant = elevate_grant;
    opts.cols = cols.max(1);
    opts.rows = rows.max(1);

    let mut session = SshSession::connect(&opts, &key)
        .await
        .map_err(|e| format!("mesh ssh: {e}"))?;

    // 4. Register the write handle + pump the read side to xterm.js.
    let id = format!(
        "ssh{}",
        state
            .ssh_seq
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    );
    state
        .ssh_sessions
        .lock()
        .expect("ssh_sessions lock")
        .insert(id.clone(), session.input());

    let ev = format!("ssh_data_{id}");
    let end_ev = format!("ssh_end_{id}");
    let app2 = app.clone();
    tauri::async_runtime::spawn(async move {
        let b64 = base64::engine::general_purpose::STANDARD;
        while let Some(event) = session.recv().await {
            match event {
                SshEvent::Data(bytes) => {
                    let _ = app2.emit(&ev, b64.encode(&bytes));
                }
                SshEvent::Eof => {}
                SshEvent::Exit(_) | SshEvent::Disconnected => break,
            }
        }
        let _ = app2.emit(&end_ev, ());
    });

    Ok(id)
}

/// Feed keystrokes (base64) to a live terminal. `[T:f2 §H.2.2]`
#[tauri::command]
async fn ssh_write(state: State<'_, AppState>, id: String, data_b64: String) -> Result<(), String> {
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(data_b64.as_bytes())
        .map_err(|_| "bad base64 input")?;
    let input = state
        .ssh_sessions
        .lock()
        .expect("ssh_sessions lock")
        .get(&id)
        .cloned();
    match input {
        Some(inp) => inp.write(&bytes).await.map_err(|e| e.to_string()),
        None => Err("no such session".into()),
    }
}

/// Report an xterm.js window resize to the remote PTY.
#[tauri::command]
async fn ssh_resize(
    state: State<'_, AppState>,
    id: String,
    cols: u32,
    rows: u32,
) -> Result<(), String> {
    let input = state
        .ssh_sessions
        .lock()
        .expect("ssh_sessions lock")
        .get(&id)
        .cloned();
    match input {
        Some(inp) => inp.resize(cols, rows).await.map_err(|e| e.to_string()),
        None => Ok(()),
    }
}

/// Close a terminal session and drop its write handle.
#[tauri::command]
async fn ssh_close(state: State<'_, AppState>, id: String) -> Result<(), String> {
    let input = state
        .ssh_sessions
        .lock()
        .expect("ssh_sessions lock")
        .remove(&id);
    if let Some(inp) = input {
        let _ = inp.close().await;
    }
    Ok(())
}

// ── User-triggered diagnostics (bug report) ────────────────────────────────────
// The user hits "Send diagnostics" on a Tunnel-down card; the client gathers
// connection-level operational metadata (daemon log tails + status snapshot +
// version/OS/connection state) — NEVER keys, tokens, or data-plane payload
// [T:A.1.1] — shows it for review, and POSTs only on explicit per-send consent.
// No background stream: the vendor stays off the data path (P.3 honest).

/// A short error code distilled from the log tail — only a well-formed `(os error N)`
/// becomes `oserrorN`, never free log text, so the code field can carry no PII.
fn diag_error_code(agent_log: &str) -> Option<String> {
    let line = agent_log
        .lines()
        .rev()
        .find(|l| l.to_ascii_lowercase().contains("error"))?;
    let i = line.find("os error ")?;
    let n: String = line[i + 9..]
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    (!n.is_empty()).then(|| format!("oserror{n}"))
}

/// macOS reads the two root-owned daemon logs through the privileged helper; other
/// desktops run the daemon as the user (no root logs to fetch here).
fn diag_log_tails() -> (String, String) {
    #[cfg(target_os = "macos")]
    {
        match helper_ipc::read_log_tail(&agent_core::home_root()) {
            Ok(pair) => pair,
            Err(e) => (format!("(log tail unavailable: {e})"), String::new()),
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        (String::new(), String::new())
    }
}

fn build_diagnostic_bundle(
    app: &tauri::AppHandle,
    state: &AppState,
    category: Option<String>,
) -> serde_json::Value {
    let conn_label = match current_connection(state) {
        ConnectionState::Connected { .. } => "connected",
        ConnectionState::Connecting => "connecting",
        ConnectionState::DataplaneDown { .. } => "dataplane_down",
        ConnectionState::Disconnected => "disconnected",
    };
    let category = category
        .filter(|c| {
            [
                "daemon-start",
                "daemon-crash",
                "handshake",
                "dns",
                "relay",
                "other",
            ]
            .contains(&c.as_str())
        })
        .unwrap_or_else(|| "other".to_string());
    let (agent_log, helper_log) = diag_log_tails();
    let snapshot = std::fs::read(freshest_status_path())
        .ok()
        .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok());
    serde_json::json!({
        "report_id": agent_core::random_report_id(),
        "category": category,
        "code": diag_error_code(&agent_log),
        "platform": format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
        "app_version": app.package_info().version.to_string(),
        "agent_version": agent_core::VERSION,
        "connection_state": conn_label,
        "status_snapshot": snapshot,
        "agent_log_tail": agent_log,
        "helper_log_tail": helper_log,
    })
}

/// Build the diagnostic bundle for the user to REVIEW (does not send). Cached so the
/// subsequent `diagnostics_send` transmits exactly what was shown — consent is per
/// that exact content.
#[tauri::command]
async fn diagnostics_build(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    category: Option<String>,
) -> Result<serde_json::Value, String> {
    let bundle = build_diagnostic_bundle(&app, &state, category);
    *state
        .pending_diagnostic
        .lock()
        .expect("pending_diagnostic lock poisoned") = Some(bundle.clone());
    Ok(bundle)
}

/// Send the previewed bundle after the user consents. Session-authed; no retry loop
/// (offline/failure surfaces to the user — nothing runs in the background). Returns
/// the report id the user quotes to support.
#[tauri::command]
async fn diagnostics_send(state: State<'_, AppState>) -> Result<String, String> {
    let bundle = state
        .pending_diagnostic
        .lock()
        .expect("pending_diagnostic lock poisoned")
        .clone()
        .ok_or("build the diagnostic report first")?;
    let token = state.token().ok_or("sign in to send diagnostics")?;
    let base = state.regional_base_url();
    let report_id = agent_core::adapters::post_diagnostics(&state.http, &base, &token, &bundle)
        .await
        .map_err(|e| match e {
            agent_core::adapters::ApiError::Status(429) => {
                "you've sent several reports recently — please try again later".to_string()
            }
            other => other.to_string(),
        })?;
    *state
        .pending_diagnostic
        .lock()
        .expect("pending_diagnostic lock poisoned") = None;
    Ok(report_id)
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
    // One resolver for the snapshot location on every platform — on macOS the
    // daemon now writes it under /Library/Ankayma, not ~/.ankayma (the daemon has
    // no $HOME; docs/daemon-state-dir.md).
    let Ok(bytes) = std::fs::read(freshest_status_path()) else {
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
        // 3× the 15s heartbeat — one missed tick must not flap "running" off
        // (same threshold as current_connection / the F-5 path proof). [T:F-5]
        running: age <= 45,
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

/// Open a Lemon Squeezy hosted checkout for `plan` (e.g. "F0-Plus", "F1-25"). Account-first:
/// the control plane stamps THIS caller's tenant into the checkout from the bearer session,
/// so the paid webhook activates the right tenant — the client never handles a variant id or
/// billing identity. Billing logic lives in the control plane [T:A.1.1]; we forward the plan
/// key, get a URL, and open it in the system browser.
#[tauri::command]
async fn open_billing_checkout(state: State<'_, AppState>, plan: String) -> Result<(), String> {
    let tok = state.token().ok_or("not signed in")?;
    let checkout_url =
        adapters::billing_checkout(&state.http, &state.regional_base_url(), &tok, &plan)
            .await
            .map_err(|e| e.to_string())?;
    open_url(&checkout_url)
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
    adapters::list_ci_policies(&state.http, &state.regional_base_url(), &tok)
        .await
        .map_err(|e| e.to_string())
}

// [F-1 viewer] CI deploy history for the Services page — recent CiDeployAccess
// ledger events, optionally for one node. Read-only (A.1.8). Owner/admin default;
// TODO[A]: per-member view grant khi F1 multi-user roles land.
#[tauri::command]
async fn ci_history(
    node: Option<String>,
    state: State<'_, AppState>,
) -> Result<Vec<domain::CiRun>, String> {
    let tok = state.token().ok_or("not signed in")?;
    adapters::ci_history(
        &state.http,
        &state.regional_base_url(),
        &tok,
        node.as_deref(),
    )
    .await
    .map_err(|e| e.to_string())
}

/// [F-2 viewer] SSH session receipts for a node — the signed half of NoKey SSH.
#[tauri::command]
async fn ssh_history(
    node: Option<String>,
    state: State<'_, AppState>,
) -> Result<Vec<domain::SshSession>, String> {
    let tok = state.token().ok_or("not signed in")?;
    adapters::ssh_history(
        &state.http,
        &state.regional_base_url(),
        &tok,
        node.as_deref(),
    )
    .await
    .map_err(|e| e.to_string())
}

#[tauri::command]
async fn add_ci_policy(
    req: CiPolicyDraft,
    state: State<'_, AppState>,
    proof_token: Option<String>,
) -> Result<(), String> {
    let tok = state.token().ok_or("not signed in")?;
    let nonempty = |s: Option<String>| s.filter(|v| !v.trim().is_empty());
    let body = domain::CiPolicyReq {
        issuer: req.issuer,
        repo: req.repo,
        git_ref: nonempty(req.git_ref),
        environment: nonempty(req.environment),
        target_hostname: nonempty(req.target_hostname),
    };
    // Paid tiers gate a deploy-policy change behind a step-up (E-7): the first call
    // returns STEP_UP_REQUIRED, the GUI runs the flow and retries with a proof.
    adapters::register_ci_policy(
        &state.http,
        &state.regional_base_url(),
        &tok,
        &body,
        proof_token.as_deref(),
    )
    .await
    .map_err(|e| e.to_string())
}

#[tauri::command]
async fn delete_ci_policy(
    repo: String,
    state: State<'_, AppState>,
    proof_token: Option<String>,
) -> Result<(), String> {
    let tok = state.token().ok_or("not signed in")?;
    adapters::delete_ci_policy(
        &state.http,
        &state.regional_base_url(),
        &tok,
        &repo,
        proof_token.as_deref(),
    )
    .await
    .map_err(|e| e.to_string())
}

// ── F-3 branded subdomains ────────────────────────────────────────────────────

#[tauri::command]
async fn list_subdomains(state: State<'_, AppState>) -> Result<Vec<domain::Subdomain>, String> {
    let tok = state.token().ok_or("not signed in")?;
    adapters::list_subdomains(&state.http, &state.regional_base_url(), &tok)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn create_subdomain(
    label: String,
    target_node_id: String,
    target_port: u16,
    state: State<'_, AppState>,
    proof_token: Option<String>,
) -> Result<String, String> {
    let tok = state.token().ok_or("not signed in")?;
    let req = domain::SubdomainReq {
        label: label.trim().to_string(),
        target_node_id,
        target_port,
    };
    adapters::register_subdomain(
        &state.http,
        &state.regional_base_url(),
        &tok,
        &req,
        proof_token.as_deref(),
    )
    .await
    .map_err(|e| e.to_string())
}

#[tauri::command]
async fn get_subdomain_cert(
    fqdn: String,
    state: State<'_, AppState>,
) -> Result<domain::SubdomainCert, String> {
    let tok = state.token().ok_or("not signed in")?;
    adapters::get_subdomain_cert(&state.http, &state.regional_base_url(), &tok, &fqdn)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn delete_subdomain(
    label: String,
    state: State<'_, AppState>,
    proof_token: Option<String>,
) -> Result<(), String> {
    let tok = state.token().ok_or("not signed in")?;
    adapters::delete_subdomain(
        &state.http,
        &state.regional_base_url(),
        &tok,
        &label,
        proof_token.as_deref(),
    )
    .await
    .map_err(|e| e.to_string())
}

/// Open a branded name in the browser. It resolves only on an enrolled device once
/// the mesh resolver is active. Prefer HTTPS when the caller knows TLS is ready
/// (`cert_status == issued`); pass `scheme: "http"` to fall back when it is not —
/// HTTP relay is available without a cert. Default remains HTTPS.
#[tauri::command]
async fn open_subdomain(fqdn: String, scheme: Option<String>) -> Result<(), String> {
    let scheme = match scheme.as_deref() {
        Some("http") => "http",
        _ => "https",
    };
    open_url(&format!("{scheme}://{fqdn}"))
}

/// The label reserved for the one-click sample demo. A bare constant, not
/// user input — the whole point is zero typing.
const SAMPLE_DEMO_LABEL: &str = "demo";

/// One-click "Publish a sample demo": map the bundled static page — served by
/// the DAEMON on a fixed port (`agent_core::sample_demo`, bound once at
/// `agent up` startup, not by this GUI process) — onto this node exactly
/// like any other F-3 subdomain — no new control-plane surface, no
/// `tls_relay` change. Reuses an existing `demo`-labeled entry pointed at
/// this node instead of minting a second one on repeat clicks (ND-R6
/// subdomain cap is scarce on F0).
#[tauri::command]
async fn publish_sample_demo(
    state: State<'_, AppState>,
    proof_token: Option<String>,
) -> Result<String, String> {
    let tok = state.token().ok_or("not signed in")?;
    let node_id = state
        .node
        .lock()
        .expect("node lock")
        .as_ref()
        .map(|n| n.node_id.clone())
        .ok_or("enroll and connect a device first")?;

    let port = agent_core::sample_demo::configured_port();

    let existing = adapters::list_subdomains(&state.http, &state.regional_base_url(), &tok)
        .await
        .map_err(|e| e.to_string())?;
    if let Some(found) = existing
        .iter()
        .find(|s| s.target_node_id == node_id && s.label.starts_with(SAMPLE_DEMO_LABEL))
    {
        return Ok(found.fqdn.clone());
    }

    let req = domain::SubdomainReq {
        label: SAMPLE_DEMO_LABEL.to_string(),
        target_node_id: node_id,
        target_port: port,
    };
    match adapters::register_subdomain(
        &state.http,
        &state.regional_base_url(),
        &tok,
        &req,
        proof_token.as_deref(),
    )
    .await
    {
        Ok(fqdn) => Ok(fqdn),
        // The plain label is taken (by someone else's demo, or a race) — one
        // suffixed retry per the spec ("reuse or suffix demo-2"); reuse already
        // handled above.
        Err(adapters::ApiError::Server { status: 409, .. }) => {
            let suffixed = domain::SubdomainReq {
                label: format!("{SAMPLE_DEMO_LABEL}-2"),
                ..req
            };
            adapters::register_subdomain(
                &state.http,
                &state.regional_base_url(),
                &tok,
                &suffixed,
                proof_token.as_deref(),
            )
            .await
            .map_err(|e| e.to_string())
        }
        Err(e) => Err(e.to_string()),
    }
}

/// Tear down the sample demo: remove the subdomain mapping (same endpoint as
/// a normal `delete_subdomain`). The daemon's loopback responder (fixed
/// port, started once at `agent up` startup — see `sample_demo` module doc)
/// keeps running; nothing outside the host can dial it directly, and with no
/// subdomain mapping left, no name routes to it either.
#[tauri::command]
async fn unpublish_sample_demo(
    label: String,
    state: State<'_, AppState>,
    proof_token: Option<String>,
) -> Result<(), String> {
    let tok = state.token().ok_or("not signed in")?;
    adapters::delete_subdomain(
        &state.http,
        &state.regional_base_url(),
        &tok,
        &label,
        proof_token.as_deref(),
    )
    .await
    .map_err(|e| e.to_string())
}

// ── F1 team membership ────────────────────────────────────────────────────────

#[tauri::command]
async fn list_members(state: State<'_, AppState>) -> Result<domain::MembersView, String> {
    let tok = state.token().ok_or("not signed in")?;
    adapters::list_members(&state.http, &state.regional_base_url(), &tok)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn invite_member(
    state: State<'_, AppState>,
    email: String,
    seat_type: Option<String>,
    ttl_seconds: Option<u64>,
    proof_token: Option<String>,
) -> Result<String, String> {
    let tok = state.token().ok_or("not signed in")?;
    adapters::invite_member(
        &state.http,
        &state.regional_base_url(),
        &tok,
        email.trim(),
        seat_type.as_deref(),
        ttl_seconds,
        proof_token.as_deref(),
    )
    .await
    .map_err(|e| e.to_string())
}

/// Drain the held `ankayma://join-team?token=…` invite token. The welcome page calls
/// this on cold start: the `join-team-pending` event fired before the JS listener
/// registered (and was lost), but the token is safely held in the Rust mutex until
/// explicitly drained. Returns None if not present or already consumed.
#[tauri::command]
async fn take_pending_join_team(state: State<'_, AppState>) -> Result<Option<String>, String> {
    Ok(state.take_pending_join_team())
}

/// Drain the held `ankayma://join?token=…` NODE-invite token (Cases C/D).
///
/// Without this the signed-out branch had no way to reach the token at all: it is only
/// handed to the frontend from `check_auth_state`, and only once the session validates.
/// A device that has never been signed in — which is every second device of an account
/// whose identity root is email, not GitHub — therefore parked the token in the mutex and
/// showed a GitHub sign-in button the user could not satisfy. The dead end was total, and
/// it hit exactly the enrolment path the QR flow exists for ("scan and you're in").
///
/// Redeeming needs no session: `POST /api/v1/enrollment/join` is token-bearer, and the
/// control plane mints the invite owner's session as part of the response, so the new
/// device ends up signed in without a second login.
#[tauri::command]
async fn take_pending_join_node(state: State<'_, AppState>) -> Result<Option<String>, String> {
    Ok(state.take_pending_join_node())
}

/// Member magic-link join (no session, no OTP): redeem the emailed invite token — which
/// IS the credential — to mint + store an email-rooted session → signed in. ZERO confirm
/// at redeem (Part D §A invite-flow §Cases, doc lines 28-30). [T:Part D §A]
/// `method` is the deferred-deeplink channel (clipboard/referrer/short_code/deeplink/…)
/// reported to the control plane for join analytics; optional.
#[tauri::command]
async fn join_team_link(
    app: AppHandle,
    state: State<'_, AppState>,
    token: String,
    method: Option<String>,
) -> Result<AuthState, String> {
    let session = adapters::join_team_link(
        &state.http,
        &state.regional_base_url(),
        token.trim(),
        method.as_deref(),
    )
    .await
    .map_err(|e| e.to_string())?;
    let user = apply_session_token(&app, session).await?;
    Ok(AuthState::Authenticated { user })
}

/// First-run InviteResolver: Install Referrer (Android) → clipboard `ankayma-invite:`.
/// Returns None when no channel has a credential (UI falls back to short code / paste).
#[tauri::command]
async fn resolve_deferred_invite() -> Result<Option<deferred_invite::DeferredInvite>, String> {
    // Native clipboard/referrer is sync and short; run off the async worker so we
    // never block the UI runtime. No direct `tokio` dep — use Tauri's runtime.
    tauri::async_runtime::spawn_blocking(deferred_invite::resolve_deferred_invite)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn join_team(invite: String, state: State<'_, AppState>) -> Result<(), String> {
    let tok = state.token().ok_or("not signed in")?;
    adapters::join_team(&state.http, &state.regional_base_url(), &tok, invite.trim())
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn remove_member(
    user_id: String,
    state: State<'_, AppState>,
    proof_token: Option<String>,
) -> Result<(), String> {
    let tok = state.token().ok_or("not signed in")?;
    adapters::remove_member(
        &state.http,
        &state.regional_base_url(),
        &tok,
        &user_id,
        proof_token.as_deref(),
    )
    .await
    .map_err(|e| e.to_string())
}

/// Admin resets a member's TOTP (admin-mediated recovery, H.9). Called WITHOUT a
/// proof first → CP returns STEP_UP_REQUIRED:manage_member_factor → runWithStepUp
/// supplies the admin's proof. [T:Part D §H.9]
#[tauri::command]
async fn reset_member_totp(
    user_id: String,
    state: State<'_, AppState>,
    proof_token: Option<String>,
) -> Result<(), String> {
    let tok = state.token().ok_or("not signed in")?;
    adapters::reset_member_totp(
        &state.http,
        &state.regional_base_url(),
        &tok,
        &user_id,
        proof_token.as_deref(),
    )
    .await
    .map_err(|e| e.to_string())
}

// ── PolicyBlock access + my-access ────────────────────────────────────────────

#[tauri::command]
async fn get_policy(state: State<'_, AppState>) -> Result<domain::PolicyView, String> {
    let tok = state.token().ok_or("not signed in")?;
    adapters::get_policy(&state.http, &state.regional_base_url(), &tok)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn submit_policy(
    body: String,
    state: State<'_, AppState>,
    proof_token: Option<String>,
) -> Result<(), String> {
    let tok = state.token().ok_or("not signed in")?;
    adapters::submit_policy(
        &state.http,
        &state.regional_base_url(),
        &tok,
        &body,
        proof_token.as_deref(),
    )
    .await
    .map_err(|e| e.to_string())
}

#[tauri::command]
async fn my_access(state: State<'_, AppState>) -> Result<domain::MyAccess, String> {
    let tok = state.token().ok_or("not signed in")?;
    adapters::my_access(&state.http, &state.regional_base_url(), &tok)
        .await
        .map_err(|e| e.to_string())
}

/// Remove one of the tenant's own mesh nodes (retire a device). Tenant-scoped on
/// the control plane (A.1.6). If it's THIS device, also drop the local identity
/// so the next connect enrolls cleanly.
#[tauri::command]
async fn delete_node(
    node_id: String,
    state: State<'_, AppState>,
    proof_token: Option<String>,
) -> Result<(), String> {
    // Multi-user tenant gates revoke behind a step-up (Part D §Authority): first call
    // without proof returns STEP_UP_REQUIRED; the GUI runs the step-up flow and retries.
    let tok = state.token().ok_or("not signed in")?;
    adapters::delete_node(
        &state.http,
        &state.regional_base_url(),
        &tok,
        &node_id,
        proof_token.as_deref(),
    )
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
        let home = agent_core::home_root();
        let _ = std::fs::remove_file(format!("{home}/.ankayma/agent.json"));
    }
    Ok(())
}

/// Tenant node roster for the deploy-target picker. Reuses `GET /api/v1/peers`.
#[tauri::command]
async fn list_nodes(state: State<'_, AppState>) -> Result<Vec<domain::NodeBrief>, String> {
    let tok = state.token().ok_or("not signed in")?;
    // Use the management endpoint (GET /api/v1/nodes) instead of /peers:
    // server-side role filter returns all nodes for admin, own nodes for member.
    // [T:A.1.2 + Part D §D.10.3 — no cross-member node visibility]
    adapters::list_nodes(&state.http, &state.regional_base_url(), &tok)
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
    let status_text = match &conn {
        ConnectionState::Connected { .. } => "● Connected",
        ConnectionState::Connecting => "Connecting…",
        ConnectionState::Disconnected => "○ Disconnected",
        ConnectionState::DataplaneDown { .. } => "⚠ Tunnel down",
    };
    let status = MenuItem::with_id(app, "status", status_text, false, None::<&str>)?;
    let toggle = MenuItem::with_id(
        app,
        "toggle",
        match &conn {
            ConnectionState::Connected { .. } => "Disconnect",
            ConnectionState::DataplaneDown { .. } => "Reconnect",
            _ => "Connect",
        },
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
                    // Stop the daemon first (A.1.7 — a "disconnected" UI must not
                    // leave a live tunnel behind). Failure doesn't block clearing
                    // UI state; just warn, matching stop_dataplane's own semantics.
                    if let Err(e) = stop_dataplane_inner() {
                        log::warn!("tray disconnect: stop daemon failed: {e}");
                    }
                    disconnect_inner(&state);
                } else {
                    // Enroll AND bring the tunnel up — connect_inner alone only
                    // talks to the control plane; without start_dataplane the UI
                    // said Connected while no daemon ran.
                    match connect_inner(&state).await {
                        Ok(()) => {
                            if let Err(e) = start_dataplane_inner(&state).await {
                                log::error!("tray connect: start dataplane failed: {e}");
                            }
                        }
                        Err(e) => log::error!("tray connect failed: {e}"),
                    }
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

// --- Auto-update (desktop, release builds — see run()) ---

/// Which update channel this machine follows: the contents of `~/.ankayma/update-channel`,
/// or "stable" when that file is absent — which is every machine except the ones a tester
/// deliberately opts in.
///
/// A file rather than a setting in the UI, on purpose. This is not a preference: a machine
/// on `beta` receives builds that nobody has confirmed yet, so switching should take a
/// deliberate act, not a stray tap. It also keeps the binary identical on both channels —
/// baking the endpoint in at build time would mean the build under test is not the build
/// that gets promoted, which defeats the point of testing it.
#[cfg(all(desktop, not(debug_assertions)))]
fn update_channel() -> String {
    std::env::var("HOME")
        .ok()
        .map(std::path::PathBuf::from)
        .map(|h| h.join(".ankayma/update-channel"))
        .and_then(|p| std::fs::read_to_string(p).ok())
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "stable".to_string())
}

#[cfg(all(desktop, not(debug_assertions)))]
async fn check_for_update(app: AppHandle) -> tauri_plugin_updater::Result<()> {
    // AppHandle::restart() is inherent to tauri core (2.11+) — no
    // tauri-plugin-process/ProcessExt needed [T — that plugin only exports
    // `init()`; verified via docs.rs, no ProcessExt at its crate root].
    use tauri_plugin_updater::UpdaterExt;

    // Endpoints can be overridden at runtime, which is what makes one binary able to
    // follow either channel. [T:v2.tauri.app/plugin/updater — "setting the URLs … at
    // runtime allows more dynamic updates such as separate release channels"]
    let mut builder = app.updater_builder();
    let channel = update_channel();
    if channel != "stable" {
        // Only the tarball path differs; the manifest and signature scheme are identical,
        // so a beta machine exercises the exact delivery path a stable one will.
        let url = format!("https://get.ankayma.com/macos/{channel}/latest.json");
        log::info!("update channel: {channel} ({url})");
        match url.parse() {
            Ok(u) => builder = builder.endpoints(vec![u])?,
            // A typo in the channel file must not strand the machine with no updates at
            // all — fall back to stable and say so.
            Err(e) => log::warn!("bad update-channel {channel:?} ({e}) — using stable"),
        }
    }

    let Some(update) = builder.build()?.check().await? else {
        return Ok(());
    };
    log::info!("update available: {}", update.version);

    // Windows: stop the always-on service (verified — bounded poll until SCM
    // reports STOPPED) BEFORE the updater overwrites agent.exe, so the binary
    // is provably not in use. This is what makes "the old daemon survives the
    // upgrade" (the original bug report) structurally impossible rather than
    // merely less likely. `docs/windows-daemon-lifecycle-decision.md`
    #[cfg(target_os = "windows")]
    {
        tauri::async_runtime::spawn_blocking(win_service_install::stop_service_verified)
            .await
            .map_err(|e| std::io::Error::other(format!("stop-service task panicked: {e}")))?
            .map_err(std::io::Error::other)?;
    }

    update
        .download_and_install(|_chunk_len, _total_len| {}, || {})
        .await?;

    // Explicit restart so the new version is live immediately — otherwise the
    // user would need to reboot for `start_type: Automatic` to pick it up at
    // next boot. Best-effort: a failure here just means "starts on next boot"
    // rather than blocking the (already-succeeded) update from completing.
    #[cfg(target_os = "windows")]
    match tauri::async_runtime::spawn_blocking(win_service_install::start_service).await {
        Ok(Err(e)) => {
            log::warn!("post-update service restart failed (will start on next boot): {e}")
        }
        Err(e) => log::warn!("post-update service restart task panicked: {e}"),
        Ok(Ok(())) => {}
    }

    app.restart();
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
        builder = builder
            .plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| {
                show_main_window(app);
            }))
            // Auto-update (Part D release pipeline §3.3): checks `plugins.updater.endpoints`
            // in tauri.conf.json, verifies the minisign signature, and swaps the binary.
            // Relaunch via AppHandle::restart() (inherent to tauri core).
            .plugin(tauri_plugin_updater::Builder::new().build());
    }

    // [scan-qr] In-app QR scan for the node-invite flow (welcome). Mobile-only:
    // the plugin drives the native camera scanner (iOS AVFoundation / Android
    // MLKit). Not registered on desktop (no camera scanner there → paste flow).
    #[cfg(mobile)]
    {
        builder = builder.plugin(tauri_plugin_barcode_scanner::init());
    }

    builder
        .plugin(tauri_plugin_deep_link::init())
        .setup(|app| {
            // app_data_dir() is platform-aware: on iOS it resolves to the app
            // sandbox container; on macOS to ~/Library/Application Support/<id>.
            // Fallback to $HOME/.ankayma so cargo run / CI still works. [T:A.1.9]
            let data_dir = app.path().app_data_dir().unwrap_or_else(|_| {
                std::path::PathBuf::from(agent_core::home_root()).join(".ankayma")
            });
            app.manage(AppState::new(data_dir));

            // iOS: start tracking the installed tunnel's status so the UI shows the
            // real state on launch. [T:A.1.9]
            #[cfg(target_os = "ios")]
            vpn::prime();

            // iOS: WKWebView's scroll view defaults to
            // contentInsetAdjustmentBehavior = .automatic, which reserves the
            // home-indicator safe area NATIVELY — on top of our CSS
            // env(safe-area-inset-*) (app.html sets viewport-fit=cover). The two
            // stack, so the fixed bottom tab bar gets pushed up off the screen edge
            // with a dead strip beneath it. Set .never so CSS env() is the single
            // source of truth for insets and the bar sits flush at the bottom.
            // [T:WKWebView UIScrollView.contentInsetAdjustmentBehavior]
            // Ref: WebKit inset behavior + viewport-fit=cover.
            #[cfg(target_os = "ios")]
            {
                use objc2::msg_send;
                use objc2::runtime::AnyObject;
                if let Some(win) = app.webview_windows().values().next().cloned() {
                    let _ = win.with_webview(|webview| unsafe {
                        let wk = webview.inner() as *mut AnyObject;
                        if wk.is_null() {
                            return;
                        }
                        let scroll: *mut AnyObject = msg_send![wk, scrollView];
                        if !scroll.is_null() {
                            // UIScrollViewContentInsetAdjustmentNever = 2
                            let _: () =
                                msg_send![scroll, setContentInsetAdjustmentBehavior: 2_isize];
                        }
                    });
                }
            }

            // Route `ankayma://auth?token=…` straight into sign-in (no copy/paste).
            {
                use tauri_plugin_deep_link::DeepLinkExt;
                let handle = app.handle().clone();
                app.deep_link()
                    .on_open_url(move |event| handle_deep_links(&handle, event.urls()));
                // Cold start: the app was launched *by* the deep link, before the
                // webview exists. handle_deep_links holds the token; the frontend's
                // first check_auth_state adopts it and lands on the dashboard.
                if let Ok(Some(urls)) = app.deep_link().get_current() {
                    handle_deep_links(&app.handle().clone(), urls);
                }
                // Dev on macOS (unbundled): also register the scheme at runtime so a
                // running `tauri dev` instance receives the URL, not just a stale
                // bundle. Harmless if the Info.plist already registered it.
                #[cfg(all(debug_assertions, target_os = "macos"))]
                let _ = app.deep_link().register_all();
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

            // Data-plane liveness watcher: the connection state can change with NO
            // user action (daemon crash, kill, stale heartbeat), and nothing else
            // re-emits it — the old UI stayed "Connected" for hours over a dead
            // tunnel. Poll the derived state and broadcast only on transitions.
            #[cfg(desktop)]
            {
                let handle = app.handle().clone();
                std::thread::spawn(move || {
                    let mut last: Option<String> = None;
                    loop {
                        std::thread::sleep(std::time::Duration::from_secs(5));
                        let conn = current_connection(&handle.state::<AppState>());
                        // Compare on the serialized form — cheap, and covers every
                        // field without a PartialEq impl.
                        let tag = serde_json::to_string(&conn).unwrap_or_default();
                        if last.as_deref() != Some(&tag) {
                            last = Some(tag);
                            apply_connection_change(&handle);
                        }
                    }
                });
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

            // Silent check-download-install-restart, release builds only — dev
            // runs aren't signed so `check()` would just fail noisily every launch.
            #[cfg(all(desktop, not(debug_assertions)))]
            {
                let handle = app.handle().clone();
                tauri::async_runtime::spawn(async move {
                    if let Err(e) = check_for_update(handle).await {
                        log::warn!("update check failed: {e}");
                    }
                });
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
            poll_login,
            take_pending_join_team,
            take_pending_join_node,
            join_team_link,
            resolve_deferred_invite,
            submit_session_token,
            sign_out,
            get_connection_status,
            connect,
            disconnect,
            get_quota,
            get_node_info,
            get_path_proof,
            probe_reachable,
            list_ci_policies,
            ci_history,
            ssh_history,
            add_ci_policy,
            delete_ci_policy,
            list_nodes,
            delete_node,
            create_join_link,
            get_server_enroll_command,
            request_step_up,
            verify_step_up,
            verify_step_up_totp,
            totp_status,
            totp_enroll,
            totp_confirm,
            totp_disable,
            webauthn_status,
            webauthn_native_available,
            webauthn_native_register,
            webauthn_native_authenticate,
            webauthn_register_start,
            webauthn_register_finish,
            webauthn_authenticate_start,
            verify_step_up_webauthn,
            platform_key_enroll,
            platform_key_list,
            platform_key_remove,
            security_key_list,
            security_key_remove,
            platform_key_sign_challenge,
            platform_key_status,
            join_enroll_node,
            start_dataplane,
            stop_dataplane,
            open_ssh_terminal,
            ssh_open,
            ssh_write,
            ssh_resize,
            ssh_close,
            get_dataplane_status,
            diagnostics_build,
            diagnostics_send,
            track_event,
            open_billing_checkout,
            list_subdomains,
            create_subdomain,
            delete_subdomain,
            open_subdomain,
            get_subdomain_cert,
            publish_sample_demo,
            unpublish_sample_demo,
            list_members,
            invite_member,
            join_team,
            remove_member,
            reset_member_totp,
            get_policy,
            submit_policy,
            my_access,
            get_platform,
            vpn::vpn_connect,
            vpn::vpn_disconnect,
            vpn::vpn_status,
            preflight::preflight_status,
            preflight::preflight_request,
        ])
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(|_app_handle, event| {
            // App quit must not orphan the privileged daemon (A.1.7 gap 2): the
            // daemon is launched detached (`&`), so plain process exit leaves it
            // running until reboot. RunEvent::Exit fires right before the process
            // dies — still time for one last cleanup call. stop_dataplane_inner is
            // plain sync (no async runtime needed at this point in shutdown).
            #[cfg(desktop)]
            if let tauri::RunEvent::Exit = event {
                if let Err(e) = stop_dataplane_inner() {
                    log::warn!("app exit: stop daemon failed: {e}");
                }
            }
        });
}

#[cfg(test)]
mod tests {
    use super::{
        is_region_handoff, parse_deep_link, region_from_handoff, DeepLinkKind,
        REGION_HANDOFF_PREFIX,
    };

    // Build a hand-off blob the way the control plane does: rhf1.<b64url(json)>.<sig>.
    // The client only reads `region`; the sig segment is opaque here.
    fn handoff_blob(region: &str) -> String {
        use base64::Engine as _;
        let json = format!(r#"{{"v":1,"region":"{region}","nonce":"x","iat":1}}"#);
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json);
        format!("{REGION_HANDOFF_PREFIX}{payload}.c2ln")
    }

    #[test]
    fn region_handoff_is_detected_and_parsed() {
        let blob = handoff_blob("uae");
        assert!(is_region_handoff(&blob));
        assert_eq!(region_from_handoff(&blob).as_deref(), Some("uae"));
    }

    #[test]
    fn plain_session_token_is_not_a_handoff() {
        let tok = "a3f9c0d1e2b3a4f5a6b7c8d9e0f1a2b3";
        assert!(!is_region_handoff(tok));
        assert_eq!(region_from_handoff(tok), None);
    }

    #[test]
    fn malformed_handoff_yields_no_region() {
        assert_eq!(region_from_handoff("rhf1.not-base64!.sig"), None);
        assert_eq!(region_from_handoff("rhf1.onlyonesegment"), None);
    }

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("ankayma-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    // The round trip that keeps one device on one node: what enroll persists is
    // exactly what the next Connect re-enrolls with. A mismatch here means the
    // control plane sees an unknown public key and mints a duplicate node.
    #[test]
    fn stored_keypair_round_trips_through_the_handoff_file() {
        let dir = scratch("handoff-roundtrip");
        super::write_handoff_state_to(
            &dir,
            "priv-b64",
            "pub-b64",
            "node-1",
            "100.64.0.1",
            None,
            None,
        )
        .expect("handoff write succeeds");
        let kp = super::load_stored_keypair_from(&dir).expect("keypair is recovered");
        assert_eq!(kp.private_b64, "priv-b64");
        assert_eq!(kp.public_b64, "pub-b64");
    }

    // Regression guard for the duplicate-node bug. `None` means "no identity yet"
    // and makes the caller generate a fresh key — so it must be returned ONLY when
    // no usable identity exists, never as a fallback for a read/parse hiccup that
    // happens to sit next to a perfectly good key.
    #[test]
    fn missing_or_corrupt_handoff_yields_no_keypair() {
        let dir = scratch("handoff-corrupt");
        assert!(
            super::load_stored_keypair_from(&dir).is_none(),
            "no file yet → no identity"
        );
        std::fs::create_dir_all(&dir).expect("mkdir");
        std::fs::write(dir.join("agent.json"), b"{ not json").expect("write garbage");
        assert!(
            super::load_stored_keypair_from(&dir).is_none(),
            "unparseable file → no identity"
        );
        // A file that parses but lacks the key fields is equally unusable.
        std::fs::write(dir.join("agent.json"), br#"{"node_id":"node-1"}"#).expect("write partial");
        assert!(
            super::load_stored_keypair_from(&dir).is_none(),
            "no keypair fields → no identity"
        );
    }

    // agent.json carries the WG private key; anything wider than 0600 leaks
    // the node identity to other local users (regression guard — this path
    // used plain fs::write until 2026-07-02).
    #[cfg(unix)]
    #[test]
    fn handoff_state_is_written_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("ankayma-handoff-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        super::write_handoff_state_to(
            &dir,
            "privkey",
            "pubkey",
            "node-1",
            "100.64.0.1",
            None,
            None,
        )
        .expect("handoff write succeeds");
        let mode = std::fs::metadata(dir.join("agent.json"))
            .expect("agent.json exists")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "agent.json must be owner-only");
        // Migration path: a pre-existing agent.json from an older build may be
        // 0644 — a rewrite must tighten it, since OpenOptions::mode() only
        // applies on create.
        std::fs::set_permissions(
            dir.join("agent.json"),
            std::fs::Permissions::from_mode(0o644),
        )
        .expect("widen perms for migration test");
        super::write_handoff_state_to(
            &dir,
            "privkey2",
            "pubkey2",
            "node-1",
            "100.64.0.1",
            None,
            None,
        )
        .expect("handoff rewrite succeeds");
        let mode = std::fs::metadata(dir.join("agent.json"))
            .expect("agent.json exists")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn kind_token(s: &str) -> Option<(DeepLinkKind, String)> {
        parse_deep_link(&url::Url::parse(s).expect("test url parses"))
    }

    #[test]
    fn auth_link_routes_to_auth() {
        let (kind, tok) = kind_token("ankayma://auth?token=sess123").expect("auth link parses");
        assert!(matches!(kind, DeepLinkKind::Auth));
        assert_eq!(tok, "sess123");
    }

    #[test]
    fn join_team_link_routes_to_join_team() {
        let (kind, tok) =
            kind_token("ankayma://join-team?token=inv456").expect("join-team link parses");
        assert!(matches!(kind, DeepLinkKind::JoinTeam));
        assert_eq!(tok, "inv456");
    }

    #[test]
    fn join_node_link_routes_to_join_node() {
        let (kind, tok) =
            kind_token("ankayma://join?token=node789&tenant=t1").expect("join link parses");
        assert!(matches!(kind, DeepLinkKind::JoinNode));
        assert_eq!(tok, "node789");
    }

    #[test]
    fn unknown_host_is_rejected() {
        // A previously-accepted shape: scheme matched but host is none of the three.
        // Must NOT be adopted as any flow (regression guard for the old bug where a
        // join token was mistaken for a session token).
        assert!(kind_token("ankayma://wat?token=x").is_none());
    }

    #[test]
    fn missing_or_empty_token_is_rejected() {
        assert!(kind_token("ankayma://auth").is_none());
        assert!(kind_token("ankayma://auth?token=").is_none());
    }

    #[test]
    fn foreign_scheme_is_rejected() {
        assert!(kind_token("https://auth?token=x").is_none());
    }
}
