// Tauri IPC wrapper — thin layer over @tauri-apps/api
// All agent-core interactions go through commands defined in gui/src-tauri/src/lib.rs
// [T:A.1.1] client calls control-plane via agent-core, never directly

import type { AuthState, ConnectionState, Quota, NodeInfo } from './types';

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

export async function getQuota(): Promise<Quota> {
	return invoke<Quota>('get_quota');
}

export async function getNodeInfo(): Promise<NodeInfo> {
	return invoke<NodeInfo>('get_node_info');
}
