# Client GUI build-spec — CI/CD policy management (F0)

> This version is for the **client repo** (public). Spec for coding the client-side GUI + CLI.
> Control-plane is a **separate repo (CLOSED)** — you interact with it only **via HTTP API**; you do not need (and do not have) its internal details. The "control-plane internals / storage / ledger" belong to the vendor-side spec, not this public repo.
> `[T]` = verifiable · `[A]` = assumption · `[A-p]` = pending with a verification path.
> Code/identifier = English; explanation = English.
> Repo layout: GUI = `frontend/app-gui` (Svelte 5 + SvelteKit) + `gui/src-tauri` (Tauri 2 command layer) + `crates/agent-core` (adapters/domain). CLI = binary `agent` (`crates/agent-daemon`).

-----

## ⚠️ Guard box (read first — prevent misunderstanding)

F0 CI/CD policy management **MUST NOT** add:
1. ❌ a dedicated "admin agent" to change policies.
2. ❌ requiring policy changes to go through the GUI.
3. ❌ step-up / re-auth when changing policy.
4. ❌ a role/RBAC layer for F0.

**Rationale**: an enrolled device (already signed in) **is** the admin identity (A.1.3). Authorization is already resolved by control-plane via session + default-deny (A.1.6) + ledger (A.1.8). The GUI is **one optional surface on par with the CLI**, NOT the only gate. If you find yourself designing "who can change policy" as a new capability → **STOP** (that is future team-governance, pulled into the wrong layer — P.5).

What **IS** kept (about *rule content*, not *who/interface*): client validates safe-by-default, **fail at create** — pin `repo` + (`ref` OR `environment`), no wildcards. Default = tightest valid scope. (Server also enforces this — client validation is just early UX.)

-----

## Part 1 — CI/CD policy management GUI (buildable NOW)

Control-plane endpoints are live (verified e2e on `cp.ankayma.com`). This part can be coded right now.

### 1.1 API contract (HTTP — this is everything the client needs to know about the control-plane)

All calls are session-authed: header `Authorization: Bearer <session_token>` (token obtained from `submit_session_token`).
Default base URL: `https://cp.ankayma.com` (override with `ANKAYMA_CONTROL_PLANE`).

| Method · Path | Purpose | Request body | Response |
|---|---|---|---|
| `POST /api/v1/ci/policy` | Create / update rule (upsert by `repo`) | `{issuer, repo, ref, environment?, target_hostname?}` | `200 {ok:true, repo}` · `400` violates safe-by-default / bad issuer · `404` target_hostname is not a tenant node · `409` repo belongs to another tenant / quota exceeded |
| `GET /api/v1/ci/policy` | List tenant rules | — | `200 {policies:[{repo, issuer, ref, environment, target_hostname, created_at}]}` |
| `DELETE /api/v1/ci/policy/{owner}/{repo}` | Delete rule (tenant-scoped) | — (repo in path; accepts `owner/name`) | `200 {ok:true, repo}` · `404` if not found |
| `GET /api/v1/peers` | List tenant nodes (for target picker) | — | `200 {peers:[{node_id, public_key, overlay_ip, hostname, endpoint?}]}` |

Notes:
- `issuer` ∈ {`"github"`, `"gitlab"`}. `ref` example: `refs/heads/main`. `environment` example: `prod`. `repo` = `owner/name` (github) / `group/project` (gitlab) — always contains ≥1 `/` (DELETE uses path catch-all).
- **Edit = re-`POST`** (server upserts by `repo`). No separate `PUT`.
- **Safe-by-default is enforced by the server** (fail-at-create). Client validation (1.3) is only for early error reporting; **do not** treat client validation as a security barrier, **do not** remove it (UX). When server returns `400/409` → display the **verbatim `error`** from the response (do not hide it).
- All tenant-scoped: a device can only see/edit its own tenant's policies (server handles this; client does not need to check).

> **Getting a session token for manual testing:** sign in via GitHub OAuth through the GUI (`sign_in_github` → paste token), that token serves as the Bearer for all calls above.

### 1.2 Screens

**Route `/policies` — "CI/CD Deploy Rules"**
- List each rule: `repo` · `issuer` (github/gitlab badge) · scope (`ref` or `environment`) · `target_hostname` (`—` if null) · `created_at`.
- Empty-state: "No deploy rules yet." + **"Add rule"** button + equivalent CLI hint line (`agent ci-policy add …`) — reinforcing that "GUI is one surface, not the only gate".
- Each row: tap → edit; menu/swipe → delete (confirm dialog).
- **"Add rule"** button → `/policies/new`.

**Route `/policies/new` (create) and `/policies/[repo]` (edit) — shared form**
- Fields:
  - `issuer`: select (github / gitlab). Default github.
  - `repo`: text `owner/name`.
  - **scope**: radio [Ref | Environment] + 1 input. **Exactly ONE** of the two (not both empty, not both filled). Default = Ref (tightest scope — specific branch).
  - `target node`: dropdown from `GET /api/v1/peers` (displays `hostname`); optional.
- Submit:
  - Client-validate (1.3) → on failure block + show inline error, do NOT call API.
  - Call `POST /api/v1/ci/policy`. Server `400/409` → display verbatim `error`.
  - Success → navigate to `/policies`, **re-fetch** list.
- Edit: pre-fill from list data; submit = re-POST (upsert).

**Delete**: confirm → `DELETE /api/v1/ci/policy/{owner}/{repo}` → re-fetch.

### 1.3 Client-side validation (UX-only, mirror server)

```
function validatePolicyDraft(d):
  errors = []
  if !d.repo || d.repo.includes('*')   → "repo: exact owner/name, no wildcard"
  if !d.repo.includes('/')             → "repo: must be owner/name format"
  hasRef = d.ref && !d.ref.includes('*')
  hasEnv = d.environment && !d.environment.includes('*')
  if !(hasRef XOR hasEnv)              → "choose exactly ONE: ref or environment (no wildcard)"
  if d.issuer not in {github, gitlab}  → "issuer: github | gitlab"
  return errors
```

### 1.4 Tauri commands to add — `gui/src-tauri/src/lib.rs`

Each command takes `state.token()` (existing pattern), returns `Result<T, String>`:
```rust
#[tauri::command] async fn list_ci_policies(state) -> Result<Vec<CiPolicy>, String>
#[tauri::command] async fn add_ci_policy(req: CiPolicyDraft, state) -> Result<(), String>
#[tauri::command] async fn delete_ci_policy(repo: String, state) -> Result<(), String>
#[tauri::command] async fn list_nodes(state) -> Result<Vec<PeerBrief>, String>  // reuse GET /peers
```
Register in `invoke_handler![…]`. Structs `CiPolicy`/`CiPolicyDraft`/`PeerBrief` = Serialize/Deserialize mirrors of the wire shape in §1.1.

### 1.5 agent-core adapters to add — `crates/agent-core/src/adapters.rs`

```rust
pub async fn list_ci_policies(http, base_url, session_token) -> Result<Vec<CiPolicy>, ApiError>      // GET, bearer
pub async fn register_ci_policy(http, base_url, session_token, &CiPolicyReq) -> Result<(), ApiError> // POST, bearer
pub async fn delete_ci_policy(http, base_url, session_token, repo: &str) -> Result<(), ApiError>      // DELETE, bearer
// peers(): already present (adapters::peers) — reuse for target picker.
```
Domain types `crates/agent-core/src/domain.rs`: `CiPolicy` (Deserialize), `CiPolicyReq` (Serialize). Add a wire-shape parse test (following the pattern of `enroll_response_parses_control_plane_shape`).

### 1.6 frontend wiring — `frontend/app-gui/src/lib/`
- `types.ts`: `CiPolicy`, `CiPolicyDraft`, `PeerBrief`.
- `tauri.ts`: `listCiPolicies()`, `addCiPolicy(d)`, `deleteCiPolicy(repo)`, `listNodes()`.
- Routes `/policies`, `/policies/new`, `/policies/[repo]` following the style of `routes/dashboard/+page.svelte` (CSS vars `--c-surface`/`--c-border`/`--c-accent`…).

### 1.7 CLI parity (same data)
Binary is `agent`. Add subcommand `agent ci-policy {add|list|rm}` (dispatch in `crates/agent-daemon/src/main.rs`, new module `ci_policy.rs`) calling the same adapters as §1.5. GUI and CLI produce **the same data** — neither is a required gate.

### 1.8 Acceptance (client)
1. Create a valid rule (repo+ref+target) → appears in list after re-fetch.
2. Wildcard rule (`repo=you/*` or `ref=*`) → client blocks; if client is bypassed, server returns `400`, GUI displays reason.
3. Both ref and environment empty → block.
4. Delete → disappears from list; re-call `GET` to confirm.
5. Target picker only lists the tenant's own nodes (from `/peers`).
6. All operations require a session; wrong/missing token → `401`, GUI prompts re-login.
7. **No** role/approve/step-up UI (guard box).

-----

## Part 2 — node/access view + node description (design, NOT YET buildable)

This part awaits control-plane endpoint additions (vendor-side, not yet landed). Documented here so the client is ready; **do not code until the endpoints are live**.

### 2.1 Waiting on control-plane (vendor-side)
- `GET /api/v1/my-access` → "what can I reach" (server computes, returns reachable nodes + services). **Not yet landed.**
- Node `description` (free-text cosmetic) + `PATCH` endpoint to edit. **Not yet landed.**
- The default "nodes with the same owner can reach each other" has been confirmed by the owner — so the Mine view will have content as soon as the endpoint lands.

### 2.2 View (F0 = **Mine** zone only)
- Organization axis: **Mine / Near / Far**. **F0 single-user ⇒ Mine only** (owner = `You`, fully expanded). Near = team (later), Far = enterprise (later).
- Each row: anchor = node name (`display_name`) → owner label (`You`) → meta (tier/type) → **action leaf = service** (the tap-to-connect unit, pre-fills target).
- Empty-state when 0 reachable: "No access to anything yet — …" (not an error; this is default-deny A.1.6 when no rules exist).
- Server does **not** return live tunnels; client only renders the static list the server provides.

### 2.3 node `description` (cosmetic)
- Free text, edited via `PATCH` (when the endpoint is available); shown in node detail.
- **Persistent** (server stores in DB) — a "saved" UX is correct. In F0 there is **no** "description change history".

-----

## Client-side data model (keep in mind when coding)

- GUI **does not maintain authoritative client-side cache** — only holds session token + node state in-memory. All data is a **projection read from control-plane via agent-core** (GUI does not call control-plane directly — A.1.4).
- **After each mutation (add/edit/delete) → re-fetch list.** Do not maintain parallel state that can drift. Data *does* persist — on the control-plane side, not in the GUI.
- `my-access` (when available): always fetch fresh, no caching. Empty = default-deny, not an error.
- "Policy change history" (who changed what) = future feature (requires a dedicated control-plane endpoint); not in F0.

-----

## Out of scope (DO NOT build in F0)
- Near/Far zones, large-scale filter/search → team (Near) / enterprise (Far).
- Advanced policy authoring UI (custom rules beyond CI deploy) → team-tier.
- Audit/metadata change history → enterprise.
- Team RBAC / tenant-level role-scoped inventory → team-tier (keep at enrollment-level, not query-level).

-----

## Implemented (client) — Part 1 (2026-06-22)

Summary of UI and client features coded for Part 1 (everything goes through `agent-core` — GUI does not call control-plane directly, A.1.4). Part 2 has **not** been built yet (awaiting vendor-side endpoints).

### Backend (Rust)
- `crates/agent-core/src/domain.rs`: `CiPolicy` (Deserialize+Serialize) + `CiPolicyReq` (Serialize), field `git_ref` ↔ JSON key `ref`. Test wire-shape `ci_policy_parses_list_shape_and_req_serializes_ref`.
- `crates/agent-core/src/adapters.rs`: `list_ci_policies` (GET) · `register_ci_policy` (POST upsert) · `delete_ci_policy` (DELETE path catch-all). Added `ApiError::Server{status,message}` + helper `expect_ok` → **display verbatim `error`** from 400/409 (§1.1). `peers()` reused for target picker.
- `gui/src-tauri/src/lib.rs`: 4 commands `list_ci_policies` · `add_ci_policy` · `delete_ci_policy` · `list_nodes` (+ struct `CiPolicyDraft`, empty→None to preserve ref XOR environment); registered in `invoke_handler!`.

### GUI (Svelte 5 / SvelteKit, `frontend/app-gui`)
- `lib/types.ts`: `CiPolicy` · `CiPolicyDraft` · `PeerBrief`. `lib/tauri.ts`: `listCiPolicies` · `addCiPolicy` · `deleteCiPolicy` · `listNodes`.
- **Route `/policies`** — "CI/CD Deploy Rules": list (badge issuer · scope ref/env · target · ), empty-state with CLI hint, row tap→edit, delete button + confirm dialog, re-fetch after mutation, display verbatim server errors.
- **Route `/policies/new`** + **`/policies/[...repo]`** (edit, rest param = `owner/name`): share component `lib/PolicyForm.svelte`. Form: issuer select · repo (readonly when editing) · scope radio [Ref|Environment] + 1 input · target node dropdown (from `list_nodes`). Client-validate §1.3 (no wildcard, ref XOR env) — on failure **do not** call API.
- **Navigation**: desktop sidebar adds a "Deploy Rules" item; dashboard adds a "CI/CD Deploy Rules" quick-action (to allow mobile/iOS access).

### CLI parity (`agent`)
- `crates/agent-daemon/src/ci_policy.rs` + dispatch `ci-policy` in `main.rs`: `agent ci-policy {list|add|rm}` — same adapters as §1.5, token via `--token`/`$ANKAYMA_TOKEN`. GUI and CLI produce **the same data** (§1.7).

### Verify
- `cargo fmt --check` · `cargo clippy --workspace --all-targets -- -D warnings` · `cargo test --workspace` — **green**. Clippy clean on desktop **and** `aarch64-apple-ios-sim` (tray/desktop gated `#[cfg(desktop)]`).
- **cp.ankayma.com (2026-06-22)**: `GET /api/v1/ci/policy|peers|session` → `401 {"error":"unauthorized"}` (correct — session required); `POST /api/v1/ci/policy` (no body) → `422 missing field "issuer"` (endpoint live, correct shape). Happy-path (GitHub sign-in → create/edit/delete rule) = human QC on desktop + iOS sim.
- Acceptance §1.8: (1)–(5) logic is coded (re-fetch, client+server validate, target from `/peers`); (6) 401 → prompts re-login; (7) **no** role/approve/step-up UI (guard box compliant).

## Log
- 2026-06-22 — Created client-safe version (HTTP API only + GUI/CLI design). Part 1 buildable now (endpoints live + verified e2e on cp.ankayma.com). Part 2 (my-access + description) awaiting vendor-side endpoints. Full vendor-side spec (including control-plane internals) lives in the control-plane repo (closed), not in this public repo.
- 2026-06-22 — **Part 1 implemented** (client): agent-core adapters/domain + Tauri commands + GUI routes `/policies[/new|/[...repo]]` + CLI `agent ci-policy`. Lint/tests green; cp.ankayma.com endpoints verified live. See "Implemented (client)" section above.
