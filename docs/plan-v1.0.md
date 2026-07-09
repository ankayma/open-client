# UI Work — Design v1.0

List of tasks to complete for the client to reach design v1.0.  
Each item can be implemented independently. Order within each group = priority order.

---

## Brand Assets

**A-1** ✓ `gui/src-tauri/icons/` — icons have been replaced with official brand assets.  
Source file: `gui/src-tauri/icons/icon_source.png` (750×750, teal gradient "An" monogram).

**A-2** ✓ Welcome screen — uses `static/ankayma_icon.png` (750×750, 666 KB).  
Logo lockup (2.2 MB) is not used in the app — removed from `static/`.

> `favicon.svg` in `static/` — pure vector, keep as-is.  
> `ankayma_app_icon_with_label.png` — for App Store listing only, not used in the app.

---

## Design System

**DS-1** `src/lib/theme.ts` — new file  
14 themes, `applyTheme(id)`, `THEME_PAIRS` (dark↔light pairs), `SEC_DARK`/`SEC_LIGHT` fixed token sets.  
`applyTheme(id)` writes `THEMES[id].vars` to `document.documentElement` (CSS vars on `:root`).

**DS-2** `src/lib/i18n.ts` — new file  
VN/EN string catalog (`STRINGS`), `ACTION_ICONS` record (action → lucide icon mapping).  
Usage pattern in routes: `import { activeLang } from '$lib/stores'; import { STRINGS } from '$lib/i18n';` → use `STRINGS[$activeLang]['key']` directly in the template. Do not use a wrapper function.

**DS-3** `src/lib/stores.ts` — additions  
Add `activeTheme` and `activeLang` with persistence via `localStorage`:
```ts
const storedTheme = (typeof localStorage !== 'undefined' && localStorage.getItem('ankayma_theme')) || 'tokyo-night';
const storedLang  = (typeof localStorage !== 'undefined' && localStorage.getItem('ankayma_lang'))  || 'vn';
export const activeTheme = writable<ThemeId>(storedTheme as ThemeId);
export const activeLang  = writable<Lang>(storedLang as Lang);
```
In `+layout.svelte` `onMount`: subscribe to both stores — on each change call `applyTheme()` and write back to `localStorage`. Do not remove `auth`, `connection`, `quota`.

**DS-4** `src/routes/+layout.svelte` — CSS additions  
Add to `:global(:root)`:
- `--sec-allow`, `--sec-deny`, `--sec-info` (fixed layer, not overridden by theme)
- `--btn-secondary-bg/border/text`, `--btn-danger-bg/border/text`, `--btn-warn-bg/border/text` (component tokens)

**DS-5** `src/routes/+layout.svelte` — button classes  
Add globals: `.btn-primary`, `.btn-secondary`, `.btn-danger`, `.btn-warn`, `.btn-ghost`.  
Uses component tokens from DS-4. Current routes use inline `<button>` styles — once these classes exist, migrate gradually.

---

## Layout / Sidebar

**L-1** User chip — add to the bottom of the sidebar  
Circular avatar with initials from email. Background color varies by `tier`.  
Display email + tier label (`F0`, `F0+`, `F1 Starter`).

**L-2** Admin sub-nav — add to sidebar when signed in  
Items: Devices · Members.

**L-3** Theme toggle + Language toggle — add to sidebar  
Two small buttons (`.pref-btn`) next to the user chip.  
Theme toggle: sun/moon icon — tap to switch between exactly the 2 themes in the pair (`THEME_PAIRS`), not a 14-theme picker. Example: `tokyo-night ↔ nord-light`. Calls `activeTheme.set(THEME_PAIRS[current])`.  
Lang toggle: displays `VN` / `EN` — tap to flip between the 2 values, calls `activeLang.set(...)`.  
Both changes automatically persist via the subscribe set up in DS-3.

---

## Components

**C-1** `src/lib/components/PathChain.svelte` — new component  
Modal displaying proof-of-path: list of peers on the data path, each with hostname, overlay IP, direct/relay status, endpoint. Badge colors use `--sec-*` tokens.  
Uses the `PathProof` + `PathPeer` types already defined in `src/lib/types.ts`.

---

## Routes

> For each route: keep the existing `<style>` block intact, only switch data bindings to Tauri IPC. Do not rewrite CSS.

**R-2** `/settings` — apply full design  
Missing: 3-section layout (Account · Security · Network), node info display, public key display.  
Data source: `getNodeInfo()` — already present in `tauri.ts`.

**R-3** `/devices` — apply design layout  
Missing: node status badges using `--sec-*` tokens, action buttons using `.btn-danger`/`.btn-secondary` (DS-5).  
Data source: `listNodes()`, `deleteNode()`, `getNodeInfo()` — already present in `tauri.ts`.

**R-4** `/members` — CSS polish  
Current page is feature-complete: `listMembers()`, `inviteMember()`, `joinTeam()`, `removeMember()` — all have backend and UI.  
Only missing: `.btn-danger` class for the remove button (pending DS-5), role badge styling.  
No logic or data fetching changes needed.
