import { writable } from 'svelte/store';
import type { AuthState, ConnectionState, Quota } from './types';

export const auth = writable<AuthState>({ status: 'unauthenticated' });

export const connection = writable<ConnectionState>({ status: 'disconnected' });

export const quota = writable<Quota | null>(null);
