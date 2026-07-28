//! win_service_install — one-time SCM registration + the upgrade-time
//! stop/start of the `Ankayma` Windows Service (Change 4 of the Windows daemon
//! lifecycle decision, `docs/windows-daemon-lifecycle-decision.md`).
//!
//! Deliberately shells out to `sc.exe` rather than calling the
//! `windows-service` crate's `ServiceManager` API directly: creating,
//! starting, or stopping a `LocalSystem` service needs an SCM handle opened
//! with admin rights, and Rust can't elevate a single function call — only
//! the whole process. The GUI runs unelevated by default (same reasoning as
//! the pre-existing `Start-Process … -Verb RunAs` pattern this replaces for
//! the data-plane launch), so each privileged step here spawns one elevated
//! `sc.exe` invocation, exactly mirroring that existing style, instead of
//! re-launching the entire GUI elevated.
//!
//! Querying status (`sc query`) needs no elevation — `SERVICE_QUERY_STATUS` is
//! granted to Authenticated Users by SCM's own default ACL — so
//! `service_exists`/`wait_for_state` run unelevated.
//!
//! ⚠️ Not yet built or exercised on a real Windows host — see the plan's
//! Verification section.

#![cfg(target_os = "windows")]

use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

const SERVICE_NAME: &str = "Ankayma";

/// Run one elevated command and wait for it to actually finish (`-Wait`) —
/// the same fix Change 1's stop path needed for the old `taskkill`: a
/// non-waited `Start-Process -Verb RunAs` returns before the elevated action,
/// or its UAC prompt, is resolved.
fn run_elevated_wait(exe: &str, args: &[&str]) -> Result<(), String> {
    let arg_list = args
        .iter()
        .map(|a| format!("'{}'", a.replace('\'', "''")))
        .collect::<Vec<_>>()
        .join(",");
    let ps = format!(
        "Start-Process -FilePath '{exe}' -ArgumentList {arg_list} -Verb RunAs -WindowStyle Hidden -Wait"
    );
    let status = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &ps])
        .status()
        .map_err(|e| format!("launch elevated {exe}: {e}"))?;
    if !status.success() {
        return Err(format!("elevated {exe} exited {status} (UAC declined?)"));
    }
    Ok(())
}

/// Unelevated: `SERVICE_QUERY_STATUS` is available to any local user by SCM's
/// default ACL.
fn query_state() -> Option<String> {
    let out = Command::new("sc")
        .args(["query", SERVICE_NAME])
        .output()
        .ok()?;
    if !out.status.success() {
        return None; // not installed, or sc itself failed
    }
    let text = String::from_utf8_lossy(&out.stdout);
    // `sc query` prints a line like "        STATE              : 4  RUNNING".
    text.lines()
        .find(|l| l.trim_start().starts_with("STATE"))
        .and_then(|l| l.split_whitespace().last())
        .map(str::to_string)
}

pub fn service_exists() -> bool {
    query_state().is_some()
}

/// Migration safety net: a version of ankayma from *before* this Windows
/// Service migration ran `agent up` as a bare elevated process (spawned via
/// `Start-Process … -Verb RunAs`, never registered with SCM) — and per the
/// original bug report, that process could survive an upgrade because the old
/// `stop_dataplane_inner` didn't wait for its own `taskkill` to actually
/// finish. `service_exists()` being false doesn't just mean "never installed"
/// — on an upgrade from a pre-migration version, it can also mean "the OLD
/// bare process might still be alive, holding the Wintun adapter / NRPT rule /
/// port 53, invisible to and unmanaged by the new service." Call this ONLY
/// where the caller has already confirmed `!service_exists()`, so it can never
/// fire against a legitimate, currently-tracked child of an already-installed
/// service. Best-effort: "nothing to kill" is success, not an error.
fn evict_pre_migration_agent_processes() -> Result<(), String> {
    let arg_list = "'/IM','agent.exe','/F'";
    let ps = format!(
        "Start-Process -FilePath 'taskkill' -ArgumentList {arg_list} -Verb RunAs -WindowStyle Hidden -Wait"
    );
    // Not run_elevated_wait: taskkill's own exit code is 128 ("process not
    // found") when there's nothing to kill, which is success here, not a
    // failure to surface — Start-Process's own exit status is what would
    // signal a real problem (e.g. UAC declined), and that's still best-effort
    // at this specific step (a rare failure here shouldn't block install/update;
    // the real, hard-verified stop is the service-based one right after).
    let _ = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &ps])
        .status();
    Ok(())
}

/// One-time install: register `Ankayma` as an `Automatic`, `LocalSystem`
/// Windows Service (SCM then guarantees single-instance and start-at-boot —
/// see the decision doc) and start it immediately so the mesh works without
/// requiring a reboot first. No-op (and no elevation prompt) if already
/// installed.
pub fn ensure_installed(agent_bin: &Path) -> Result<(), String> {
    if service_exists() {
        return Ok(());
    }
    // First-ever transition onto the service architecture on this device —
    // clear out any pre-migration bare `agent.exe` before registering the
    // service, so it never has to fight the new one for the Wintun adapter.
    evict_pre_migration_agent_processes()?;
    let bin_path = format!("{} service", agent_bin.to_string_lossy());
    run_elevated_wait(
        "sc.exe",
        &[
            "create",
            SERVICE_NAME,
            "binPath=",
            &bin_path,
            "start=",
            "auto",
            "obj=",
            "LocalSystem",
            "DisplayName=",
            "Ankayma Mesh",
        ],
    )?;
    run_elevated_wait("sc.exe", &["start", SERVICE_NAME])
}

/// Verified stop for the auto-updater: waits (bounded) until `sc query`
/// actually reports `STOPPED` before returning `Ok`, so the caller only
/// overwrites `agent.exe` once SCM confirms nothing has it open — the fix for
/// the original "old daemon survives the upgrade" bug, at the root this time.
pub fn stop_service_verified() -> Result<(), String> {
    if !service_exists() {
        // The very first auto-update onto this architecture can land before
        // the user ever clicks Connect — the service hasn't been created yet,
        // so there's nothing for THIS function to stop, but a pre-migration
        // bare `agent.exe` could still be holding the binary file open (the
        // original bug, recurring right at the migration moment otherwise).
        return evict_pre_migration_agent_processes();
    }
    run_elevated_wait("sc.exe", &["stop", SERVICE_NAME])?;
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if query_state().as_deref() == Some("STOPPED") {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(300));
    }
    Err("service did not report STOPPED within 10s".into())
}

/// Restart after an upgrade replaces the binary — explicit, so the user isn't
/// asked to reboot to pick up the new version.
pub fn start_service() -> Result<(), String> {
    run_elevated_wait("sc.exe", &["start", SERVICE_NAME])
}
