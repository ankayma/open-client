# Auth deep-link sign-in — build-spec

> For the **client repo** (public) + **control-plane tasks** (separate repo, CLOSED).
> Goal: after signing in with GitHub in the browser, clicking **"Open Ankayma"** opens the app directly **with the session token** — **no more manual copy/paste of the token**.
> `[T]` = verifiable · `[A]` = assumption · `[A-p]` = pending with a verification path.
> Code/identifier = English; explanations = English.
> Repo layout: GUI = `frontend/app-gui` (Svelte 5 + SvelteKit) + `gui/src-tauri` (Tauri 2) + `crates/agent-core`. Control-plane = separate repo, accessed only via HTTP + **deep-link URL contract** below.

-----

## ⚠️ Guard box (read first)

- This **does NOT** change the auth mechanism: still GitHub OAuth at the control-plane, still issues the **same `session_token`** as currently (validated via `GET /api/v1/session`). Only changes **how the token is delivered from browser to app**: instead of showing it for the user to copy → push via **custom URL scheme** `ankayma://`.
- **Copy/paste is NOT removed** — kept as fallback ("If the app didn't open"). Deep-link is the happy path, not the only path.
- Token still **lives only in app RAM** (as currently — `AppState.session`, not persisted). Deep-link does not add a new place to store the token.

-----

## 1. Current problem

Current flow (2 screens, manual):
1. App `sign_in_github` → opens browser to `https://cp.ankayma.com/auth/github` (`gui/src-tauri/src/lib.rs:229`). `[T]`
2. Browser completes OAuth → page shows **"Signed in as …"** + token + **"Open Ankayma"** button. This button currently **cannot open the app** (app has not registered any scheme) → user must copy the token.
3. App switches to "Paste session token" screen → user pastes → `submit_session_token` validates + stores (`lib.rs:237`). `[T]`

→ Eliminate the copy/paste step: the "Open Ankayma" button opens `ankayma://auth?token=…`, the app receives the token automatically.

-----

## 2. Deep-link URL contract (SHARED part — agreed between client & control-plane)

**Scheme + shape — this is the full contract:**

```
ankayma://auth?token=<SESSION_TOKEN>
```

- Scheme: `ankayma` (lowercase). Host/path: `auth`. Query param **`token`** = exactly the `session_token` that the control-plane currently shows for the user to copy (token format unchanged).
- `token` must be **URL-encoded** (current token is hex `[0-9a-f]` so there are no special characters in practice, but CP **should still** `encodeURIComponent` for safety). `[A]`
- App parses `token`, validates via `GET /api/v1/session` (Bearer), exactly like `submit_session_token`. Invalid/expired token → app shows error + falls back to paste screen. `[T]`
- The same URL works on **desktop (macOS) and mobile (iOS/Android)** — only the OS scheme routing differs.

-----

## 3. CONTROL-PLANE tasks (CLOSED repo) — what needs to be done

The OAuth result page (page that shows "Signed in as …" + token) needs **1 change**: make the **"Open Ankayma"** button point to the deep-link.

**3.1 "Open Ankayma" button** — change to an anchor that opens the scheme:

```html
<!-- token = the session token just issued; MUST encodeURIComponent -->
<a class="btn-primary" href="ankayma://auth?token=ENCODED_TOKEN">Open Ankayma</a>
```

or auto-open when the page loads (smoother UX, still keep the button as fallback):

```html
<script>
  const token = "…";                      // server render
  const deeplink = "ankayma://auth?token=" + encodeURIComponent(token);
  // attempt to open app automatically; if OS has no app, that's fine — user clicks button/copies
  location.href = deeplink;
</script>
```

**3.2 Keep** the token display + "If the app didn't open, copy your session token" text as fallback (in case app not installed / scheme not registered / browser blocks auto-redirect). **Do not** remove.

**3.3 NO changes needed** to `/auth/github`, `/api/v1/session`, or token format. No `redirect_uri` needed, no loopback needed. Just 1 `href` line on the result page.

> Note for CP: some browsers block `location.href = "custom://"` if not triggered by a user gesture. Prefer **anchor `<a href>`** (user click) as the primary mechanism; auto-redirect is just a bonus.

-----

## 4. CLIENT tasks (this repo) — what needs to be done

### 4.1 Register the `ankayma://` scheme
- Add plugin: `tauri-plugin-deep-link` (v2) — registers the scheme + receives URLs. Also add `tauri-plugin-single-instance` (desktop) so that when a deep-link is opened while the app is running, it **focuses the existing instance** + forwards the URL instead of opening a second app. `[A]` (single-instance must be the **first** plugin registered, per Tauri docs).
- `tauri.conf.json` → `plugins.deep-link.desktop.schemes = ["ankayma"]` (and `mobile` accordingly). The bundler will automatically write `CFBundleURLTypes` to Info.plist (macOS/iOS) + intent-filter (Android). `[A-p]` (verify Info.plist after `cargo tauri build`).
- Capability: add `deep-link:default` to `gui/src-tauri/capabilities/*.json`.

### 4.2 Handle URL when received
- In `setup()`: `app.deep_link().on_open_url(|event| { … })`.
- Parse each URL: scheme == `ankayma`, host == `auth`, extract query `token`.
- Refactor the logic of `submit_session_token` (`lib.rs:237`) into a shared helper `apply_session_token(app, token)`:
  - validate `adapters::session_info` → set `email` + `token` in `AppState` → `apply_connection_change(app)`.
- After token is OK: `show_main_window(app)` (show + focus) and emit new event **`signed-in`** carrying `AuthState::Authenticated{user}`.

### 4.3 Frontend receives event
- `frontend/app-gui/src/routes/+layout.svelte`: add listener `listen('signed-in', …)` → `auth.set(payload)` + `goto('/dashboard')` (handles the case where deep-link arrives **after** `onMount`/`checkAuthState` has already run).
- `welcome/+page.svelte`: keep the paste screen as fallback. (Optional: change hint text to "Click 'Open Ankayma' in the browser — the app will open automatically. If it doesn't open, paste your token below.")

### 4.4 Verify `[T]`
- macOS: `cargo tauri build --bundles app`, open once to let LaunchServices register the scheme, then `open "ankayma://auth?token=<real-token>"` → app focuses + goes to dashboard, without going through the paste screen.
- Invalid token: `open "ankayma://auth?token=bad"` → app shows error, falls back to paste screen, does not crash.
- Already running (window hidden in tray) → open deep-link → focuses the correct instance (single-instance), does not open a second app.

-----

## 5. Security / risks (noted to not forget)

- **Token in URL scheme**: custom scheme can be registered by another app on the machine with the same name (`ankayma://`) and "hijack" the URL → read the token. This is an inherent limitation of custom-scheme deep-links (Tailscale and many desktop apps accept this). Accepted for F0. `[A]`
  - **Future upgrade (if stricter security needed)**: per RFC 8252 — app opens HTTP loopback server `127.0.0.1:<random>`, passes `redirect_uri=http://127.0.0.1:<port>/cb` to CP, CP redirects token to loopback. Avoids scheme hijacking, but requires CP to support `redirect_uri` + app to run a temporary server. **Out of scope for this version.**
- Token **is not** written to disk/log. When logging the URL (debug) must **redact** `token` (`ankayma://auth?token=***`).
- App **always** validates token with the control-plane before trusting it (already present in `submit_session_token` / `check_auth_state`). Deep-link does not skip this validation step.

-----

## 6. Division summary

| Side | Task |
|---|---|
| **Control-plane** (CLOSED) | OAuth result page: "Open Ankayma" button → `href="ankayma://auth?token=<encodeURIComponent(token)>"`. Keep copy-token section as fallback. No API/token changes. |
| **Client** (this repo) | Register `ankayma://` scheme (deep-link + single-instance plugin), handle `on_open_url` → validate + store token + focus window + emit `signed-in`; frontend listens to `signed-in` → goto `/dashboard`. Keep paste screen as fallback. |
