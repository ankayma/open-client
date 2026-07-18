// Tauri IPC wrapper — thin layer over @tauri-apps/api
// All agent-core interactions go through commands defined in gui/src-tauri/src/lib.rs
// [T:A.1.1] client calls control-plane via agent-core, never directly

import type {
  AuthState,
  ConnectionState,
  Quota,
  NodeInfo,
  PathProof,
  CiPolicy,
  CiPolicyDraft,
  CiRun,
  SshSession,
  PeerBrief,
  Subdomain,
  SubdomainCert,
  MembersView,
  PolicyView,
  MyAccess,
} from "./types";

// Runtime check — @tauri-apps/api works in Tauri webview and stubs gracefully in browser
async function invoke<T>(
  cmd: string,
  args?: Record<string, unknown>,
): Promise<T> {
  const { invoke: tauriInvoke } = await import("@tauri-apps/api/core");
  return tauriInvoke<T>(cmd, args);
}

export async function checkAuthState(): Promise<AuthState> {
  return invoke<AuthState>("check_auth_state");
}

export async function signInGithub(nonce: string): Promise<void> {
  return invoke("sign_in_github", { nonce });
}

// Poll the OAuth handoff: returns the signed-in state once the browser login
// completes (token parked under `nonce`), or null while still pending.
export async function pollLogin(nonce: string): Promise<AuthState | null> {
  return invoke<AuthState | null>("poll_login", { nonce });
}

// After OAuth in the browser, the user pastes the session token shown on the
// success page. The backend validates it against the control plane.
export async function submitSessionToken(token: string): Promise<AuthState> {
  return invoke<AuthState>("submit_session_token", { token });
}

export async function signOut(): Promise<void> {
  return invoke("sign_out");
}

export async function getConnectionStatus(): Promise<ConnectionState> {
  return invoke<ConnectionState>("get_connection_status");
}

export async function connect(): Promise<void> {
  return invoke("connect");
}

export async function disconnect(): Promise<void> {
  return invoke("disconnect");
}

// [milestone 1.2] Hand the enrolled identity to the privileged daemon so a real
// WireGuard tunnel comes up (utun + boringtun need root → macOS admin prompt).
// Enroll (connect) first. macOS-only at 1.1.
export async function startDataplane(): Promise<void> {
  return invoke("start_dataplane");
}

export async function stopDataplane(): Promise<void> {
  return invoke("stop_dataplane");
}

// [slice 2] Live data-plane status from the daemon heartbeat file. `running` is
// true only while the daemon is actually up (fresh heartbeat) — reflects the REAL
// tunnel, not just enrollment.
export interface DataplaneStatus {
  running: boolean;
  pid: number | null;
  age_secs: number | null;
  peers: { hostname: string; overlay_ip: string; endpoint: string | null }[];
}

export async function getDataplaneStatus(): Promise<DataplaneStatus> {
  return invoke<DataplaneStatus>("get_dataplane_status");
}

// iOS VPN — enroll + bring up the Packet Tunnel via the Network Extension (the
// data plane runs in-app on iOS, not a privileged daemon). On desktop these reject
// ("iOS-only"); desktop uses startDataplane/the agent daemon instead.
export interface VpnStatus {
  // "invalid" | "disconnected" | "connecting" | "connected" | "reasserting" | "disconnecting"
  status: string;
  // Real peer count in the roster handed to the tunnel (0 when disconnected).
  peer_count: number;
}

export async function vpnConnect(): Promise<void> {
  return invoke("vpn_connect");
}

export async function vpnDisconnect(): Promise<void> {
  return invoke("vpn_disconnect");
}

export async function vpnStatus(): Promise<VpnStatus> {
  return invoke<VpnStatus>("vpn_status");
}

// Target OS ("ios" | "macos" | "linux" | "windows"). Used to pick the connect path:
// iOS brings the tunnel up in-app (Packet Tunnel), desktop uses the agent daemon.
export async function getPlatform(): Promise<string> {
  return invoke<string>("get_platform");
}

export async function getQuota(): Promise<Quota> {
  return invoke<Quota>("get_quota");
}

export async function getNodeInfo(): Promise<NodeInfo> {
  return invoke<NodeInfo>("get_node_info");
}

// [F-5 "Prove it"] Surface the data path: peer-to-peer, vendor off the path (A.1.1).
export async function getPathProof(): Promise<PathProof> {
  return invoke<PathProof>("get_path_proof");
}

// Active reachability: TCP-probe overlay IPs (connect/refused → reachable, timeout →
// unreachable). More accurate than the lagging handshake age for gating SSH/Open.
export async function probeReachable(targets: string[]): Promise<boolean[]> {
  return invoke<boolean[]>("probe_reachable", { targets });
}

// [A] stub — control-plane receives event via agent-core relay (milestone 1.2)
export async function trackEvent(
  name: string,
  props?: Record<string, string>,
): Promise<void> {
  return invoke("track_event", { name, props: props ?? {} });
}

// [03b] CI/CD deploy policy (F0). Every call is session-authed in agent-core.
export async function listCiPolicies(): Promise<CiPolicy[]> {
  return invoke<CiPolicy[]>("list_ci_policies");
}

export async function addCiPolicy(req: CiPolicyDraft, proof?: StepUpProof): Promise<void> {
  return invoke("add_ci_policy", { req, proofToken: proof?.proofToken });
}

// [F-1 viewer] Recent CI deploy runs from the tenant's audit ledger, optionally
// narrowed to one node hostname. Read-only (A.1.8); admin/owner default.
export async function ciHistory(node?: string): Promise<CiRun[]> {
  return invoke<CiRun[]>("ci_history", { node: node ?? null });
}

export async function sshHistory(node?: string): Promise<SshSession[]> {
  return invoke<SshSession[]>("ssh_history", { node: node ?? null });
}

export async function deleteCiPolicy(repo: string, proof?: StepUpProof): Promise<void> {
  return invoke("delete_ci_policy", { repo, proofToken: proof?.proofToken });
}

export async function listNodes(): Promise<PeerBrief[]> {
  return invoke<PeerBrief[]>("list_nodes");
}

// [F-2] Open an external terminal (Terminal.app / iTerm2 / any `.command`-capable
// app) on the same mesh transport — desktop-only "open external" for power users.
export async function openSshTerminal(
  nodeId: string,
  login?: string,
  terminalApp?: string
): Promise<void> {
  return invoke("open_ssh_terminal", {
    nodeId,
    login: login ?? null,
    terminalApp: terminalApp ?? null,
  });
}

// [F-2 §H.2.2] In-app SSH terminal (xterm.js over the mesh russh transport) —
// desktop AND iOS/iPad. `ssh_open` returns a session id; subscribe to the
// `ssh_data_<id>` (base64 bytes) and `ssh_end_<id>` events.
export async function sshOpen(
  nodeId: string,
  cols: number,
  rows: number,
  opts?: { login?: string; root?: boolean; proof?: string }
): Promise<string> {
  return invoke<string>("ssh_open", {
    nodeId,
    login: opts?.login ?? null,
    root: opts?.root ?? false,
    proof: opts?.proof ?? null,
    cols,
    rows,
  });
}

export async function sshWrite(id: string, dataB64: string): Promise<void> {
  return invoke("ssh_write", { id, dataB64 });
}

export async function sshResize(id: string, cols: number, rows: number): Promise<void> {
  return invoke("ssh_resize", { id, cols, rows });
}

export async function sshClose(id: string): Promise<void> {
  return invoke("ssh_close", { id });
}

// A step-up proof carried on a sensitive action in a multi-user tenant — the
// result of solving a challenge via `verifyStepUp`. [T:Part D §H.5]
export interface StepUpProof {
  proofToken: string;
}

// Ask the control plane to email an OTP for `purpose` (e.g. 'enroll_node',
// 'revoke_node', 'invite_member', 'remove_member'); returns the challenge_id to
// pass to `verifyStepUp`. [Part D §Authority model]
export async function requestStepUp(purpose: string): Promise<string> {
  return invoke<string>("request_step_up", { purpose });
}

// Exchange a solved OTP challenge for a short-lived, purpose-scoped proof_token
// — the generalized step-up interface every gated action retries with.
// [T:Part D §H.5]
export async function verifyStepUp(purpose: string, challengeId: string, code: string): Promise<string> {
  return invoke<string>("verify_step_up", { purpose, challengeId, code });
}

// Same exchange as verifyStepUp, but against the enrolled TOTP secret — no
// challenge_id, no email round trip. [T:Part D §H.8 Phase 2]
export async function verifyStepUpTotp(purpose: string, code: string): Promise<string> {
  return invoke<string>("verify_step_up_totp", { purpose, code });
}

// Whether the signed-in user has a confirmed TOTP credential — drives whether
// the step-up modal goes straight to code entry (TOTP) or requests an emailed
// code first (OTP).
export async function totpStatus(): Promise<boolean> {
  return invoke<boolean>("totp_status");
}

// Mint a fresh (unconfirmed) TOTP secret. Returns [otpauthUrl, base32Secret]
// for the authenticator app (manual entry — no QR image dependency).
export async function totpEnroll(): Promise<[string, string]> {
  return invoke<[string, string]>("totp_enroll");
}

// Prove the enrolled secret works; returns the 10 one-time backup codes
// (H.9 recovery) — shown once, never retrievable again.
export async function totpConfirm(code: string): Promise<string[]> {
  return invoke<string[]>("totp_confirm", { code });
}

// WebAuthn / YubiKey (E-7 StepUp Phase 3 — AAL3). The actual register/assert
// ceremony runs in $lib/webauthn.ts via the browser's navigator.credentials
// API; these are opaque JSON pass-throughs to the control plane.

export async function webauthnStatus(): Promise<boolean> {
  return invoke<boolean>("webauthn_status");
}

export async function webauthnRegisterStart(): Promise<any> {
  return invoke("webauthn_register_start");
}

export async function webauthnRegisterFinish(stateId: string, credential: any, label?: string): Promise<void> {
  return invoke("webauthn_register_finish", { stateId, credential, label });
}

export async function webauthnAuthenticateStart(): Promise<any> {
  return invoke("webauthn_authenticate_start");
}

export async function verifyStepUpWebauthn(purpose: string, stateId: string, credential: any): Promise<string> {
  return invoke<string>("verify_step_up_webauthn", { purpose, stateId, credential });
}

// Remove one of the tenant's own mesh nodes (retire a device). Tenant-scoped. In a
// multi-user tenant the server gates this behind a step-up — pass `proof` on retry.
export async function deleteNode(nodeId: string, proof?: StepUpProof): Promise<void> {
  return invoke("delete_node", {
    nodeId,
    proofToken: proof?.proofToken,
  });
}

// F-3 branded subdomains (private-default; map a name onto a mesh node).
export async function listSubdomains(): Promise<Subdomain[]> {
  return invoke<Subdomain[]>("list_subdomains");
}

export async function createSubdomain(
  label: string,
  targetNodeId: string,
  targetPort: number,
  proof?: StepUpProof,
): Promise<string> {
  return invoke<string>("create_subdomain", {
    label,
    targetNodeId,
    targetPort,
    proofToken: proof?.proofToken,
  });
}

export async function deleteSubdomain(label: string, proof?: StepUpProof): Promise<void> {
  return invoke("delete_subdomain", { label, proofToken: proof?.proofToken });
}

export async function openSubdomain(fqdn: string): Promise<void> {
  return invoke("open_subdomain", { fqdn });
}

// Auto-TLS (Slice 3) issuance-state poll — fallback to the cert_issued SSE push.
export async function getSubdomainCert(fqdn: string): Promise<SubdomainCert> {
  return invoke<SubdomainCert>("get_subdomain_cert", { fqdn });
}

// F1 team membership.
export async function listMembers(): Promise<MembersView> {
  return invoke<MembersView>("list_members");
}
// Invite a member BY EMAIL — the join link is delivered to that email (Part D §A).
// `ttlSeconds` (optional) overrides the server's default member-invite TTL. Admin
// action, gated behind a step-up — pass `proof` on retry (M-1).
export async function inviteMember(
  email: string,
  ttlSeconds?: number,
  proof?: StepUpProof,
): Promise<string> {
  return invoke<string>("invite_member", { email, ttlSeconds, proofToken: proof?.proofToken });
}
export async function joinTeam(invite: string): Promise<void> {
  return invoke("join_team", { invite });
}

// Member magic-link join (no GitHub, no OTP): the emailed invite token IS the credential —
// redeem it to become an email-rooted member and get signed in. ZERO confirm (Part D §A).
export async function joinTeamLink(token: string): Promise<AuthState> {
  return invoke<AuthState>("join_team_link", { token });
}
// Drain the pending join-team invite token from Rust. The welcome page calls this on
// cold start: the JS event fires before the listener registers (and is lost), but the
// Rust mutex holds the token until this command explicitly drains it.
export async function takePendingJoinTeam(): Promise<string | null> {
  return invoke<string | null>("take_pending_join_team");
}
// Offboard a member (admin). Gated behind a step-up — pass `proof` on retry (M-4).
export async function removeMember(userId: string, proof?: StepUpProof): Promise<void> {
  return invoke("remove_member", { userId, proofToken: proof?.proofToken });
}

// Mint a single-use `ankayma://join?token=…` node-enrollment link. `ttlSeconds`
// (optional) overrides the server default; the control plane clamps the range. In a
// multi-user tenant the server gates this behind a step-up — pass `proof` on retry.
export async function createJoinLink(ttlSeconds?: number, proof?: StepUpProof): Promise<string> {
  return invoke<string>("create_join_link", {
    ttlSeconds,
    proofToken: proof?.proofToken,
  });
}

// Headless node (server/VPS) enrollment: a copy-paste `agent up --join-token …`
// command for a shell with no Ankayma app. `joinToken` is a scoped, single-use
// enrollment token the caller minted behind a step-up — never the session token.
export async function getServerEnrollCommand(joinToken: string): Promise<string> {
  return invoke<string>("get_server_enroll_command", { joinToken });
}

// Recipient side of a node invite (`ankayma://join?token=…`): enroll THIS device into
// the invite's tenant using only the join token. When the CP mints a session on redeem,
// returns the AuthState to adopt — signs into the owner's account with NO second GitHub
// login (devices.md). Older CPs that don't yet mint a session return null: the device is
// enrolled, but the caller must guide the user to sign in. [T:devices.md / invite-flow]
export async function joinEnrollNode(joinToken: string, hostname: string): Promise<AuthState | null> {
  return invoke<AuthState | null>("join_enroll_node", { joinToken, hostname });
}

// PolicyBlock access + my-access catalog.
export async function getPolicy(): Promise<PolicyView> {
  return invoke<PolicyView>("get_policy");
}
export async function submitPolicy(body: string, proof?: StepUpProof): Promise<void> {
  return invoke("submit_policy", { body, proofToken: proof?.proofToken });
}
export async function myAccess(): Promise<MyAccess> {
  return invoke<MyAccess>("my_access");
}
