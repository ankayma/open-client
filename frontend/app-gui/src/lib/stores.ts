import { writable } from 'svelte/store';
import type { AuthState, ConnectionState, Quota } from './types';
import type { ThemeId } from './theme';
import type { Lang } from './i18n';

export const auth = writable<AuthState>({ status: 'unauthenticated' });

export const connection = writable<ConnectionState>({ status: 'disconnected' });

export const quota = writable<Quota | null>(null);

const storedTheme = (typeof localStorage !== 'undefined' && localStorage.getItem('ankayma_theme')) || 'tokyo-night';
const storedLang  = (typeof localStorage !== 'undefined' && localStorage.getItem('ankayma_lang'))  || 'vn';
export const activeTheme = writable<ThemeId>(storedTheme as ThemeId);
export const activeLang  = writable<Lang>(storedLang as Lang);
