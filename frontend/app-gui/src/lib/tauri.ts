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
	PeerBrief
} from './types';

// Runtime check — @tauri-apps/api works in Tauri webview and stubs gracefully in browser
async function invoke<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
	const { invoke: tauriInvoke } = await import('@tauri-apps/api/core');
	return tauriInvoke<T>(cmd, args);
}

export async function checkAuthState(): Promise<AuthState> {
	return invoke<AuthState>('check_auth_state');
}

export async function signInGithub(): Promise<void> {
	return invoke('sign_in_github');
}

// After OAuth in the browser, the user pastes the session token shown on the
// success page. The backend validates it against the control plane.
export async function submitSessionToken(token: string): Promise<AuthState> {
	return invoke<AuthState>('submit_session_token', { token });
}

export async function signOut(): Promise<void> {
	return invoke('sign_out');
}

export async function getConnectionStatus(): Promise<ConnectionState> {
	return invoke<ConnectionState>('get_connection_status');
}

export async function connect(): Promise<void> {
	return invoke('connect');
}

export async function disconnect(): Promise<void> {
	return invoke('disconnect');
}

// [milestone 1.2] Hand the enrolled identity to the privileged daemon so a real
// WireGuard tunnel comes up (utun + boringtun need root → macOS admin prompt).
// Enroll (connect) first. macOS-only at 1.1.
export async function startDataplane(): Promise<void> {
	return invoke('start_dataplane');
}

export async function stopDataplane(): Promise<void> {
	return invoke('stop_dataplane');
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
	return invoke<DataplaneStatus>('get_dataplane_status');
}

export async function getQuota(): Promise<Quota> {
	return invoke<Quota>('get_quota');
}

export async function getNodeInfo(): Promise<NodeInfo> {
	return invoke<NodeInfo>('get_node_info');
}

// [F-5 "Prove it"] Surface the data path: peer-to-peer, vendor off the path (A.1.1).
export async function getPathProof(): Promise<PathProof> {
	return invoke<PathProof>('get_path_proof');
}

// [A] stub — control-plane receives event via agent-core relay (milestone 1.2)
export async function trackEvent(name: string, props?: Record<string, string>): Promise<void> {
	return invoke('track_event', { name, props: props ?? {} });
}

// [03b] CI/CD deploy policy (F0). Every call is session-authed in agent-core.
export async function listCiPolicies(): Promise<CiPolicy[]> {
	return invoke<CiPolicy[]>('list_ci_policies');
}

export async function addCiPolicy(req: CiPolicyDraft): Promise<void> {
	return invoke('add_ci_policy', { req });
}

export async function deleteCiPolicy(repo: string): Promise<void> {
	return invoke('delete_ci_policy', { repo });
}

export async function listNodes(): Promise<PeerBrief[]> {
	return invoke<PeerBrief[]>('list_nodes');
}
