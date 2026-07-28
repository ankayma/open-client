# Windows daemon lifecycle — decision record: migrate `agent.exe` to a Windows Service

> **Created**: 2026-07-28
> **Status**: all 5 commits' worth of code written (not yet committed to git —
> pending your review). `up.rs` itself ended up untouched (see the "child
> process, not in-process cancellation" note below) — new files instead:
> `crates/agent-daemon/src/{win_supervisor,ipc_protocol,win_ipc,win_service}.rs`,
> `gui/src-tauri/src/{win_service_client,win_service_install}.rs`, plus the
> `start_agent()` dedup in the macOS helper.
> **Scope**: `crates/agent-daemon` (new files, `main.rs` dispatch only) +
> `gui/src-tauri/src/lib.rs` Windows branches + `gui/src-tauri/macos/PrivilegedHelper`
> **No owner ratification needed** — implementation fix, not a Part A invariant change.
> **Verification status**: `win_supervisor`/`ipc_protocol` (cross-platform logic)
> and the macOS helper fix are compiler- and test-verified on this machine.
> `win_ipc`/`win_service` (agent-daemon) and `win_service_client`/
> `win_service_install` (gui) are Windows-only (`#[cfg(target_os = "windows")]`)
> and could **not** be compiler-checked here — cross-compiling to
> `x86_64-pc-windows-msvc` fails at `ring`'s C build step (no Windows SDK on this
> Mac). Every Win32 call was written against the real API signatures read
> directly from the locally-cached `windows-sys`/`windows-service`/`tokio`
> source, not from memory — but a real Windows build + the manual test sequence
> in Verification below is still required before merging.

## The bug that triggered this

A Windows user upgraded ankayma (install dated 2026-07-21 → release ~1.1.19/1.1.20).
Mesh still showed "Connected", but a branded-subdomain link failed in Chrome (both
`http://` and `https://` tried) while `ping` to the same hostname worked. The owner
of that subdomain could open it fine, ruling out a server-side cert/relay race.
Diagnosis pointed at **a stale `agent.exe` from before the upgrade surviving
alongside or instead of the new one**.

Root cause, confirmed by code review:

1. `stop_dataplane_inner()` (Windows, `gui/src-tauri/src/lib.rs`, at the time
   ~2160-2171) killed the daemon via a **non-blocking**
   `Start-Process taskkill … -Verb RunAs` (no `-Wait`) — it returned before the
   elevated kill (or its UAC prompt) was actually resolved. Called on every
   disconnect, app-exit, and — critically — the **silent auto-updater's** restart
   (`check_for_update`).
2. **No single-instance guard** anywhere in `crates/agent-daemon/src/up.rs` /
   `main.rs` — nothing stopped two `agent.exe up` processes from running
   concurrently, and a fresh launch never checked for / evicted a stale prior
   instance.

## Why a patch (mutex + verified-kill) was rejected in favor of a rewrite

An initial draft patched around the two symptoms directly (`CreateMutexW`
single-instance guard + a verified/blocking `taskkill`, validated against
Microsoft's own docs on `CreateMutexW`/`ERROR_ALREADY_EXISTS` and `TerminateProcess`
semantics). That patch is technically sound but still home-grown plumbing on top of
an architecture (spawn an elevated ad-hoc process, kill it by image name) that this
repo's own macOS side does **not** use — macOS already runs the equivalent daemon as
a proper OS-managed service (`SMAppService`/launchd, `com.ankayma.helper` +
`helper_ipc`, see `docs/hotfix-macos-dataplane-gaps.md`).

Researched how the two closest reference products solve the identical problem on
Windows:

- **Tailscale**: `tailscaled` runs as a **registered Windows Service**, from boot,
  idle until told to bring a tunnel up. Control/IPC is a **named pipe**
  (`\\.\pipe\tailscale\tailscaled`) — the GUI/CLI never starts/stops the *service*
  for everyday use, only sends it commands, and it verifies the caller's identity
  per-connection (`checkConnIdentityLocked()`), not just a pipe ACL.
- **Firezone**: splits into a dedicated **"Tunnel service"** (a real Windows
  Service) + a separate GUI process.
- Both run their macOS daemon under **launchd** — same pattern this repo already
  has.

Decision: bring Windows to the same shape (root-cause fix), rather than continuing
to patch around an ad-hoc elevated-process model. Sources: [Tailscaled Daemon Architecture](https://deepwiki.com/tailscale/tailscale/5.1-tailscaled-daemon-architecture) · [Firezone Windows Client](https://www.firezone.dev/kb/client-apps/windows-gui-client) · [CreateMutexW](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-createmutexw) · [TerminateProcess](https://learn.microsoft.com/tr-tr/windows/desktop/api/processthreadsapi/nf-processthreadsapi-terminateprocess)

## Decision

Migrate `agent.exe` on Windows to a registered **Windows Service**:

- Account: **`LocalSystem`** — standard for an always-resident tunnel daemon,
  matches Tailscale. Accepted trade-off: bigger standing privilege than today's
  "elevated only while the interactive admin user is connected" model, in exchange
  for structurally eliminating the stale/duplicate-process bug class and enabling
  start-at-boot.
- `start_type: Automatic` — full Tailscale-style model (always on, idle until told
  to connect), not the smaller "keep today's per-connect start/stop" alternative.
- Everyday Connect/Disconnect/Status goes over a **named pipe**
  (`\\.\pipe\Ankayma\ctl`), not SCM start/stop — this is what removes UAC from every
  connect after the one-time install. Per-connection identity verification
  (`ImpersonateNamedPipeClient` + token SID check against the active interactive
  session or Administrator) is the real authorization boundary here, not the pipe's
  ACL alone, since a `Connect` message carries a bearer session token in-band.
- **`up.rs`/`serve_dataplane` stay completely untouched.** Initial draft planned to
  refactor `run()` into an in-process idle⇄connected supervisor, but
  `serve_dataplane` spawns several bare OS threads with no cancellation mechanism
  (`agent_core::pump::spawn_tx/rx/timers`, `disco::run_discovery`/`run_rendezvous`,
  `resolver::serve`, the `tls_relay` listener, the embedded SSH server) — making
  that cancellable would mean touching `agent_core::pump`, which is **shared with
  the iOS Packet Tunnel extension**, contradicting the "iOS unaffected" blast-radius
  claim. Instead: a new Windows-only supervisor (registered as the Service) spawns
  `agent.exe up` as a **real child process** on `Connect`, and on `Disconnect` /
  `SERVICE_CONTROL_STOP` calls `child.kill()` + `child.wait()` — a genuine
  parent-child wait gives verified-stop for free (no `tasklist` polling needed).
  Hard-kill is fine here: the existing NRPT/route setup is already delete-first
  idempotent (self-heals on the next Connect) and the GUI already treats a stale
  `agent-status.json` as "down". `agent up` (the CLI, used on macOS/Linux/CI/dev)
  is entirely unmodified.
- Upgrade flow (`check_for_update`) stops the service (verified via
  `query_status()` polling to `Stopped`) **before** the binary gets overwritten —
  this is what makes "old daemon survives the upgrade" structurally impossible
  rather than merely less likely.
- New dependency: [`windows-service`](https://crates.io/crates/windows-service)
  (Windows-only) — flagged and approved as part of this decision.
- **Migration safety net**: a pre-migration ankayma install ran `agent up` as a
  bare elevated process, never registered with SCM — so on the device's very
  first transition onto this architecture, `service_exists()` being false does
  not just mean "never installed," it can also mean "the OLD bare process from
  before this fix might still be alive" (per the original bug report, it could
  survive an upgrade). `win_service_install::evict_pre_migration_agent_processes()`
  (an elevated, waited `taskkill /IM agent.exe /F`, tolerant of "nothing to
  kill") runs in exactly the two places this matters: inside `ensure_installed`
  right before the service is first created, and inside `stop_service_verified`
  when called by the auto-updater before the service has ever been created
  (the very first auto-update onto this version can land before the user ever
  clicks Connect). Deliberately **not** run unconditionally on every call — once
  the service exists, the only `agent.exe` that should ever be running is the
  supervisor's own tracked child, and a blind `taskkill /F` there would kill a
  live, legitimate tunnel instead of a stale one.

**Blast radius**: `crates/agent-daemon/Cargo.toml` only targets `macos`/`linux`/
`windows` — iOS and Android never link this crate (they embed `agent-core` directly
via `crates/agent-ios-ptp` and `gui/src-tauri/src/vpn_android.rs`), so they are
unaffected. With the child-process supervisor design above, `up.rs`/`serve_dataplane`
are untouched, so this is now Windows-only end to end — no macOS/Linux regression
risk either.

Also bundled: the same class of gap exists on macOS —
`start_agent()` (`gui/src-tauri/macos/PrivilegedHelper/src/main.rs`) spawns
`agent up` unconditionally with no check for an existing live instance. Fixed by
reusing the existing `PID_PATH` + `is_agent_process()` verified-PID machinery
`stop_agent()` already has.

## Where the full implementation plan lives

The step-by-step plan (exact files/functions, protocol shape, security notes,
commit breakdown, open packaging question) was written during a Claude Code
planning session — see the session's plan file for full detail; this record exists
so the *decision* and its rationale survive independent of that ephemeral file.
Implementation commits (one concern per commit, per this repo's convention):

1. `feat(agent-daemon): Windows-only supervisor that spawns/kills agent up as a child process (Command channel), up.rs untouched`
2. `feat(agent-daemon): Windows named-pipe control IPC with per-connection identity verification`
3. `feat(agent-daemon): Windows Service entry point (agent service) — LocalSystem, auto-start, wired to SCM stop`
4. `feat(gui): Windows install-once (create_service) + drive connect/disconnect/upgrade through the named pipe instead of Start-Process/taskkill`
5. `fix(macos-helper): start_agent evicts a stale live agent process before spawning (reuses PID_PATH + is_agent_process)`

## Open item not yet resolved

Repo has **no real Windows installer** today (`packaging/windows/build-ankayma-windows.bat`
only builds binaries; no `.nsi`/`.wxs` found) — service install is driven from the
GUI's own first-run flow (`ServiceManager::create_service` called directly from
Rust) until/unless a real installer exists. Revisit if that changes.
