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
  PeerBrief,
  Subdomain,
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

export async function signInGithub(): Promise<void> {
  return invoke("sign_in_github");
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

export async function addCiPolicy(req: CiPolicyDraft): Promise<void> {
  return invoke("add_ci_policy", { req });
}

export async function deleteCiPolicy(repo: string): Promise<void> {
  return invoke("delete_ci_policy", { repo });
}

export async function listNodes(): Promise<PeerBrief[]> {
  return invoke<PeerBrief[]>("list_nodes");
}

// A step-up proof (OTP) carried on a sensitive action in a multi-user tenant.
export interface StepUpProof {
  challengeId: string;
  code: string;
}

// Ask the control plane to email an OTP for `purpose` ('enroll_node' | 'revoke_node');
// returns the challenge_id to pass back at the action. [Part D §Authority model]
export async function requestStepUp(purpose: string): Promise<string> {
  return invoke<string>("request_step_up", { purpose });
}

// Remove one of the tenant's own mesh nodes (retire a device). Tenant-scoped. In a
// multi-user tenant the server gates this behind a step-up — pass `proof` on retry.
export async function deleteNode(nodeId: string, proof?: StepUpProof): Promise<void> {
  return invoke("delete_node", {
    nodeId,
    challengeId: proof?.challengeId,
    code: proof?.code,
  });
}

// F-3 branded subdomains (private-default; map a name onto a mesh node).
export async function listSubdomains(): Promise<Subdomain[]> {
  return invoke<Subdomain[]>("list_subdomains");
}

export async function createSubdomain(
  label: string,
  targetNodeId: string,
): Promise<string> {
  return invoke<string>("create_subdomain", { label, targetNodeId });
}

export async function deleteSubdomain(label: string): Promise<void> {
  return invoke("delete_subdomain", { label });
}

export async function openSubdomain(fqdn: string): Promise<void> {
  return invoke("open_subdomain", { fqdn });
}

// F1 team membership.
export async function listMembers(): Promise<MembersView> {
  return invoke<MembersView>("list_members");
}
// `ttlSeconds` (optional) overrides the server's default member-invite TTL; the
// control plane clamps it to the allowed range. [A] invite-flow §TTL policy.
export async function inviteMember(ttlSeconds?: number): Promise<string> {
  return invoke<string>("invite_member", { ttlSeconds });
}
export async function joinTeam(invite: string): Promise<void> {
  return invoke("join_team", { invite });
}
export async function removeMember(userId: string): Promise<void> {
  return invoke("remove_member", { userId });
}

// Mint a single-use `ankayma://join?token=…` node-enrollment link. `ttlSeconds`
// (optional) overrides the server default; the control plane clamps the range. In a
// multi-user tenant the server gates this behind a step-up — pass `proof` on retry.
export async function createJoinLink(ttlSeconds?: number, proof?: StepUpProof): Promise<string> {
  return invoke<string>("create_join_link", {
    ttlSeconds,
    challengeId: proof?.challengeId,
    code: proof?.code,
  });
}

// Recipient side of a node invite (`ankayma://join?token=…`): enroll THIS device
// into the invite's tenant using only the join token (no session). [A] invite-flow.
export async function joinEnrollNode(joinToken: string, hostname: string): Promise<void> {
  return invoke("join_enroll_node", { joinToken, hostname });
}

// PolicyBlock access + my-access catalog.
export async function getPolicy(): Promise<PolicyView> {
  return invoke<PolicyView>("get_policy");
}
export async function submitPolicy(body: string): Promise<void> {
  return invoke("submit_policy", { body });
}
export async function myAccess(): Promise<MyAccess> {
  return invoke<MyAccess>("my_access");
}
