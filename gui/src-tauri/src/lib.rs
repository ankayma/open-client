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

// Android VPN bridge (frontend → AnkaymaVpnService via JNI). Owns the TUN fd, the
// in-process WireGuard pump, and the control-plane bypass proxy. [T:A.1.9, F-3]
#[cfg(target_os = "android")]
mod vpn_android;

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
            pending_token: Mutex::new(None),
            pending_join_team: Mutex::new(None),
            pending_join_node: Mutex::new(None),
            ssh_sessions: Mutex::new(std::collections::HashMap::new()),
            ssh_seq: std::sync::atomic::AtomicU64::new(0),
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

/// Where the node identity (agent.json) is persisted. On iOS AND Android this MUST
/// be the app data dir: `$HOME` in either sandbox is not a stable, persistent,
/// writable location, so a handoff written there is lost (or never written) between
/// launches — which made every Connect enroll a BRAND-NEW node with a fresh
/// WireGuard key (roster filled with duplicate nodes; peers that already knew the
/// old key dropped the new handshakes → tunnel stuck at rx 0). On desktop it MUST
/// stay under `$HOME/.ankayma` because the privileged `agent up` daemon reads it
/// from there. `[T:A.1.10]`
fn handoff_state_dir(state: &AppState) -> std::path::PathBuf {
    #[cfg(any(target_os = "ios", target_os = "android"))]
    {
        return state.data_dir.join(".ankayma");
    }
    #[cfg(not(any(target_os = "ios", target_os = "android")))]
    {
        let _ = state;
        // One resolver for every entrypoint (HOME on unix, USERPROFILE on Windows) so
        // the GUI and the privileged `agent up` daemon read the same ~/.ankayma.
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
/// wall" (E-6 device-key model; [T:decision/session-reauth-device-key-2026-07-18]).
/// Returns the refreshed user, or None if this device cannot re-auth: no enrolled node
/// in memory (never connected this run), or the CP rejects the proof (device revoked /
/// legacy). None → the caller does a real logout + disconnect.
async fn try_reauth_via_device_key(app: &AppHandle, state: &AppState) -> Option<User> {
    // Node identity: the in-memory enrolled node if we connected this run, else recover it
    // from the persisted handoff (agent.json). The disk fallback is what makes re-auth work
    // on a COLD START — after the app is killed and reopened, `state.node` is empty, but the
    // durable node_id + WG pubkey (and the machine key) are still on disk, so we re-mint a
    // session with no second sign-in. [T:decision/session-reauth-device-key-2026-07-18 + A.1.10]
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
    // against the gateway would 401. [T:decision/session-reauth-device-key-2026-07-18 §5]
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
            // no second sign-in, no dropped tunnel. [T:decision/session-reauth-…-07-18]
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
async fn probe_reachable(targets: Vec<String>) -> Result<Vec<bool>, String> {
    // Blocking connects on a blocking thread so the async runtime isn't stalled; each
    // target gets its own thread so the batch runs concurrently (~3s worst case).
    tauri::async_runtime::spawn_blocking(move || {
        use std::io::ErrorKind;
        use std::net::{TcpStream, ToSocketAddrs};
        use std::time::Duration;
        // Embedded mesh-SSH port; only RST-vs-timeout matters, so the port need not be
        // open — a closed port still returns a RST, which proves the host is reachable.
        const PROBE_PORT: u16 = 22022;
        const PROBE_TIMEOUT: Duration = Duration::from_secs(3);
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
                        None => return false,
                    };
                    match TcpStream::connect_timeout(&addr, PROBE_TIMEOUT) {
                        Ok(_) => true,
                        Err(e) => e.kind() == ErrorKind::ConnectionRefused,
                    }
                })
            })
            .collect();
        threads
            .into_iter()
            .map(|t| t.join().unwrap_or(false))
            .collect::<Vec<bool>>()
    })
    .await
    .map_err(|e| format!("probe task failed: {e}"))
}

/// Path of the data-plane status snapshot the GUI reads for path-proof. On iOS the Packet
/// Tunnel extension (a SEPARATE process) writes it into the App Group container, so the app
/// must read from there, not its own sandbox HOME; the `connect`-side config passes the
/// SAME path to the extension so both agree. Every other platform uses the daemon's
/// `~/.ankayma/agent-status.json`. [T:F-5]
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
    std::path::PathBuf::from(agent_core::home_root()).join(".ankayma/agent-status.json")
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
    // every other platform reads the daemon's `~/.ankayma/agent-status.json`.
    let path = status_snapshot_path();
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
) -> Result<String, String> {
    // Build the server-enroll command from a SCOPED, single-use join token (E-3) —
    // NOT the session token. The caller mints it behind a step-up, exactly like the
    // device invite link, so this command never carries the user's full credential.
    // The agent enrolls the server as AppServer itself. [T:P.3 + part-d-invite-flow §Authority]
    if join_token.is_empty() {
        return Err("missing enrollment token".into());
    }
    Ok(format!(
        "agent up --join-token {join_token} --control-plane {}",
        state.regional_base_url()
    ))
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
/// F0-Plus/F1) and retries WITH the proof. [T:e7-recovery-model-2026-07-20]
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
// The register/assert ceremony itself runs in the frontend via
// `navigator.credentials` (Tauri's webview exposes it); these commands are
// opaque JSON pass-throughs to the control plane.

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
                    "helper daemon needs approval — enable Ankayma in System Settings > Login Items, then try again"
                        .into(),
                )
            }
            ServiceStatus::NotRegistered | ServiceStatus::NotFound => svc
                .register()
                .map_err(|e| format!("register helper daemon: {e}")),
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
        },
        Stop {
            home: &'a str,
        },
    }

    #[derive(serde::Deserialize)]
    struct Response {
        ok: bool,
        error: Option<String>,
    }

    fn send(req: &Request) -> Result<(), String> {
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
        let resp: Response =
            serde_json::from_str(line.trim()).map_err(|e| format!("bad helper response: {e}"))?;
        if resp.ok {
            Ok(())
        } else {
            Err(resp
                .error
                .unwrap_or_else(|| "helper reported failure".into()))
        }
    }

    pub fn start(
        agent_bin: &str,
        token: &str,
        control_plane: &str,
        home: &str,
    ) -> Result<(), String> {
        send(&Request::Start {
            agent_bin,
            token,
            control_plane,
            home,
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
    helper_ipc::start(&agent_bin.to_string_lossy(), token, control_plane, &home)
}

/// Windows: the Wintun adapter needs admin and the GUI runs unelevated, so launch
/// the agent via ShellExecute "runas" (one UAC prompt — the Windows analogue of the
/// macOS admin prompt). Pass the session token the same way the macOS helper does:
/// the GUI's `connect` enroll writes identity to agent.json but not the scoped node
/// service token, so `agent up` needs `--token` to refresh it. The elevated process
/// is owned by the elevated context, not this one, so the tunnel stays up after we
/// return; `waitForEstablished` polls the status file the daemon writes. `[T:A.1.3]`
///
/// TODO[A]: the token rides the elevated command line (visible to local admins in
/// the process list). macOS hands it over IPC; a private Windows handoff (env-file
/// the elevated agent reads, like the VPS `up.env`) is the follow-up. Verify-by:
/// spawn with no `--token` on the cmdline and the tunnel still comes up.
#[cfg(target_os = "windows")]
fn bring_up_dataplane(
    agent_bin: &std::path::Path,
    token: &str,
    control_plane: &str,
) -> Result<(), String> {
    let bin = agent_bin.to_string_lossy().replace('\'', "''");
    let cp = control_plane.replace('\'', "''");
    let tok = token.replace('\'', "''");
    let ps = format!(
        "Start-Process -FilePath '{bin}' -ArgumentList \
         'up','--token','{tok}','--control-plane','{cp}' -Verb RunAs -WindowStyle Hidden"
    );
    let status = std::process::Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &ps])
        .status()
        .map_err(|e| format!("launch elevated agent: {e}"))?;
    if !status.success() {
        return Err("could not start the agent daemon (was the UAC prompt declined?)".into());
    }
    Ok(())
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
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
    // bring_up_dataplane blocks (UnixStream connect retry loop with
    // thread::sleep); run it off the async runtime so it doesn't stall the
    // Tauri executor (audit 2026-07-02).
    let base_url = state.regional_base_url();
    tauri::async_runtime::spawn_blocking(move || bring_up_dataplane(&bin, &tok, &base_url))
        .await
        .map_err(|e| format!("dataplane task panicked: {e}"))?
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

/// Windows: the agent runs elevated, so tearing it down needs elevation too (one
/// UAC prompt). Best-effort — a missing daemon is not an error.
#[cfg(target_os = "windows")]
fn stop_dataplane_inner() -> Result<(), String> {
    let _ = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Start-Process taskkill -ArgumentList '/IM','agent.exe','/F' -Verb RunAs -WindowStyle Hidden",
        ])
        .status();
    Ok(())
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
    // HOME on unix, USERPROFILE on Windows (unset HOME made this report the tunnel
    // down on Windows even while the daemon was up). [T:agent_core::home_root]
    let home = agent_core::home_root();
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
/// the mesh resolver is active; TLS works once the node's own relay has an issued
/// cert (see `get_subdomain_cert` / `cert_status`) — best-effort until then.
#[tauri::command]
async fn open_subdomain(fqdn: String) -> Result<(), String> {
    open_url(&format!("https://{fqdn}"))
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

/// Member magic-link join (no session, no OTP): redeem the emailed invite token — which
/// IS the credential — to mint + store an email-rooted session → signed in. ZERO confirm
/// at redeem (Part D §A invite-flow §Cases, doc lines 28-30). [T:Part D §A]
#[tauri::command]
async fn join_team_link(
    app: AppHandle,
    state: State<'_, AppState>,
    token: String,
) -> Result<AuthState, String> {
    let session = adapters::join_team_link(&state.http, &state.regional_base_url(), token.trim())
        .await
        .map_err(|e| e.to_string())?;
    let user = apply_session_token(&app, session).await?;
    Ok(AuthState::Authenticated { user })
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
/// supplies the admin's proof. [T:e7-recovery-model-2026-07-20.md]
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
                    // Stop the daemon first (A.1.7 — a "disconnected" UI must not
                    // leave a live tunnel behind). Failure doesn't block clearing
                    // UI state; just warn, matching stop_dataplane's own semantics.
                    if let Err(e) = stop_dataplane_inner() {
                        log::warn!("tray disconnect: stop daemon failed: {e}");
                    }
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

// --- Auto-update (desktop, release builds — see run()) ---

#[cfg(all(desktop, not(debug_assertions)))]
async fn check_for_update(app: AppHandle) -> tauri_plugin_updater::Result<()> {
    // AppHandle::restart() is inherent to tauri core (2.11+) — no
    // tauri-plugin-process/ProcessExt needed [T — that plugin only exports
    // `init()`; verified via docs.rs, no ProcessExt at its crate root].
    use tauri_plugin_updater::UpdaterExt;

    let Some(update) = app.updater()?.check().await? else {
        return Ok(());
    };
    log::info!("update available: {}", update.version);
    update
        .download_and_install(|_chunk_len, _total_len| {}, || {})
        .await?;
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
            join_team_link,
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
            webauthn_register_start,
            webauthn_register_finish,
            webauthn_authenticate_start,
            verify_step_up_webauthn,
            join_enroll_node,
            start_dataplane,
            stop_dataplane,
            open_ssh_terminal,
            ssh_open,
            ssh_write,
            ssh_resize,
            ssh_close,
            get_dataplane_status,
            track_event,
            open_billing_checkout,
            list_subdomains,
            create_subdomain,
            delete_subdomain,
            open_subdomain,
            get_subdomain_cert,
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
