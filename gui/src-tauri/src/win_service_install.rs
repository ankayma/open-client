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

/// One-time install: register `Ankayma` as an `Automatic`, `LocalSystem`
/// Windows Service (SCM then guarantees single-instance and start-at-boot —
/// see the decision doc) and start it immediately so the mesh works without
/// requiring a reboot first. No-op (and no elevation prompt) if already
/// installed.
pub fn ensure_installed(agent_bin: &Path) -> Result<(), String> {
    if service_exists() {
        return Ok(());
    }
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
        return Ok(());
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
