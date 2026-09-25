// Formatting shared by the two overview surfaces — the tenant one (admin) and each
// user's own. One dashboard read-model, two scopes: the labels, the target-name
// precedence and the TTL maths must read identically on both, so they live here
// rather than being copied per page. [T:part-d-tenant-dashboard.md §H.1-H.2]
import type { OverviewActivity, OverviewGrant, OverviewDelegation } from './types';

export type ActionKind = 'ssh' | 'open' | 'cicd' | 'elevate' | 'member' | 'node' | 'service' | 'other';

// event_type → a short ACTION label + which glyph. Unknown types fall back to the raw
// type so nothing is hidden. [T:audit_events event set]
export function action(ev: string): { label: string; kind: ActionKind } {
	switch (ev) {
		case 'SshSessionOpened': return { label: 'SSH', kind: 'ssh' };
		// The private-URL visit: the request is peer-to-peer, so the app reports it
		// (POST /api/v1/subdomains/{fqdn}/opened) — nothing else can see it.
		case 'ServiceOpened': return { label: 'Open', kind: 'open' };
		case 'ElevationGranted': return { label: 'Elevate', kind: 'elevate' };
		case 'CiArtifactPublished':
		case 'CiDeployPolicyRegistered':
		case 'CiDeployPolicyRemoved': return { label: 'CI/CD', kind: 'cicd' };
		case 'CiDeployDenied':
		case 'CiArtifactDenied': return { label: 'Denied', kind: 'other' };
		case 'NodeEnrolled':
		case 'NodeRevoked':
		case 'NodeKeyRotated': return { label: 'Node', kind: 'node' };
		case 'MemberJoined':
		case 'MemberRemoved':
		case 'MemberInviteRevoked': return { label: 'Member', kind: 'member' };
		case 'SubdomainRegistered':
		case 'SubdomainRemoved':
		case 'ServiceTagsDeclared':
		case 'ServiceDataClassDeclared': return { label: 'Service', kind: 'service' };
		case 'GrantTerminated': return { label: 'Session end', kind: 'ssh' };
		case 'CommandApprovalRequested':
		case 'CommandApprovalDecided': return { label: 'Approval', kind: 'elevate' };
		case 'StepUpDowngradeRefused': return { label: 'Denied', kind: 'other' };
		case 'AuthFactorDisabled':
		case 'MemberFactorReset':
		case 'VendorFactorReset': return { label: 'Factor', kind: 'member' };
		case 'PolicyBlockSubmitted': return { label: 'Policy', kind: 'cicd' };
		case 'AgentIdentityIssued':
		case 'DelegationWithdrawn': return { label: 'Delegate', kind: 'cicd' };
		default: return { label: ev, kind: 'other' };
	}
}

// Best-effort target from the event payload — the CP shapes payload per event, so try
// the common keys and fall back to blank rather than inventing a value.
export function target(a: OverviewActivity): string {
	const p = a.payload as Record<string, unknown> | null;
	if (!p || typeof p !== 'object') return '';
	// Most specific NAME first: a row about a service should read as the service, not
	// as the node id it happens to sit on.
	for (const k of ['fqdn', 'subdomain', 'label', 'hostname', 'node_id', 'node', 'email', 'repo', 'actor_id']) {
		const v = p[k];
		if (typeof v === 'string' && v) return v;
	}
	return '';
}

export function actorOf(a: OverviewActivity): string {
	const p = a.payload as Record<string, unknown> | null;
	if (p && typeof p === 'object') {
		for (const k of ['email', 'actor_id', 'user_id', 'github_login', 'opened_by']) {
			const v = p[k];
			if (typeof v === 'string' && v) return v;
		}
	}
	// Resolved through the grant by the control plane. A dash is the honest answer
	// when no human is attached to the event — the grant's own id is not a name.
	return a.actor || '—';
}

// A ledger row carries a DATE, not just a clock time: "10:51" is unreadable as evidence
// the moment the list spans midnight, and an auditor reading a row has to know the day
// without counting back from the top of the page.
export function clockTime(iso: string): string {
	const d = new Date(iso);
	if (isNaN(d.getTime())) return iso;
	const p = (n: number) => String(n).padStart(2, '0');
	return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
}

// TTL remaining, in "12m" / "45s" / "expired" form, recomputed as `now` ticks.
export function remaining(iso: string, now: number): string {
	const end = new Date(iso).getTime();
	if (isNaN(end)) return '';
	const ms = end - now;
	if (ms <= 0) return 'expired';
	const s = Math.floor(ms / 1000);
	if (s < 60) return `${s}s left`;
	const m = Math.floor(s / 60);
	if (m < 60) return `${m}m left`;
	return `${Math.floor(m / 60)}h ${m % 60}m left`;
}

// How full the TTL bar is: fraction of the grant's lifetime still remaining.
export function ttlPct(g: OverviewGrant | OverviewDelegation, now: number): number {
	const startIso = 'issued_at' in g ? g.issued_at : g.opened_at;
	const end = new Date(g.expires_at).getTime();
	const start = new Date(startIso).getTime();
	if (isNaN(end) || isNaN(start) || end <= start) return 0;
	const pct = ((end - now) / (end - start)) * 100;
	return Math.max(0, Math.min(100, pct));
}

export function short(id: string, n = 10): string {
	return id.length > n ? id.slice(0, n) + '…' : id;
}
