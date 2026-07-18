import { writable } from 'svelte/store';
import type { AuthState, ConnectionState, Quota } from './types';
import type { ThemeId } from './theme';
import type { Lang } from './i18n';

export const auth = writable<AuthState>({ status: 'unauthenticated' });

// The signed-in user's role in the active tenant ("admin" | "member"), as reported by
// `myAccess()` (the same value the Services page shows as a role chip). Null until first
// loaded. Used to hide admin-only chrome (e.g. the Admin tab) from members — a UX gate;
// the server still enforces authorization on every admin action. [reuse, no CP change]
export const myRole = writable<string | null>(null);

export const connection = writable<ConnectionState>({ status: 'disconnected' });

export const quota = writable<Quota | null>(null);

// A deep-link invite captured by the Rust side and handed over (once authenticated)
// via the `join-team-pending` / `join-node-pending` events. The target page consumes
// it on mount and resets this to null. See Part D (invite flow).
export interface PendingInvite {
	type: 'join-team' | 'join-node';
	token: string;
}
export const pendingInvite = writable<PendingInvite | null>(null);

const storedTheme = (typeof localStorage !== 'undefined' && localStorage.getItem('ankayma_theme')) || 'tokyo-night';
const storedLang  = (typeof localStorage !== 'undefined' && localStorage.getItem('ankayma_lang'))  || 'vn';
export const activeTheme = writable<ThemeId>(storedTheme as ThemeId);
export const activeLang  = writable<Lang>(storedLang as Lang);
