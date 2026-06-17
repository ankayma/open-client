import adapter from '@sveltejs/adapter-static';
import { vitePreprocess } from '@sveltejs/vite-plugin-svelte';

// [T:Part D §D.3] Tauri 2 loads a static SPA: no SSR/prerender (see +layout.ts),
// adapter-static with an index.html fallback so client-side routing works in the
// webview. [T:svelte.dev/docs/kit/single-page-apps]
/** @type {import('@sveltejs/kit').Config} */
const config = {
	preprocess: vitePreprocess(),
	kit: {
		adapter: adapter({ fallback: 'index.html' })
	}
};

export default config;
