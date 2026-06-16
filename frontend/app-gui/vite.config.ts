import adapter from '@sveltejs/adapter-static';
import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vite';

const tauri_host = process.env.TAURI_DEV_HOST;

export default defineConfig({
	plugins: [
		sveltekit({
			compilerOptions: {
				runes: ({ filename }) =>
					filename.split(/[/\\]/).includes('node_modules') ? undefined : true
			},
			// [T:Part D §D.3] Tauri 2 SPA — static adapter, no SSR
			adapter: adapter({
				pages: 'build',
				assets: 'build',
				fallback: 'index.html',
				precompress: false,
				strict: true
			})
		})
	],
	// [T:tauri@2.x] Allow Tauri dev host for mobile dev server
	server: {
		port: 5173,
		strictPort: true,
		host: tauri_host || false,
		hmr: tauri_host ? { protocol: 'ws', host: tauri_host, port: 5183 } : undefined
	},
	clearScreen: false
});
