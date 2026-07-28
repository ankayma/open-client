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

/// Run one elevated command and wait for it to actually finish (`-Wait`),
/// verifying the ELEVATED process's own exit code — not just that the outer,
/// unelevated `powershell.exe` launched and returned.
///
/// Confirmed missing the hard way (T490, real end-to-end test): `-Wait` alone
/// only fixes Change 1's original bug (a non-waited `Start-Process -Verb
/// RunAs` returning before the elevated action resolves) — it does **not**
/// verify the elevated command actually succeeded. Without `-PassThru` +
/// propagating `$p.ExitCode`, the outer `powershell.exe` exits 0 regardless of
/// whether `sc.exe create` itself succeeded, and — worse — if the UAC prompt
/// is declined, `Start-Process` throws inside the script but that exception
/// alone still didn't turn into a non-zero exit here either. Net effect: a
/// declined/failed elevation was silently treated as success, so
/// `ensure_installed` returned `Ok(())` without ever actually creating the
/// service, and the very next step (`win_service_client::connect`) failed
/// with a confusing "is the Ankayma service running?" instead of the real
/// "the UAC prompt was declined" cause.
fn run_elevated_wait(exe: &str, args: &[&str]) -> Result<(), String> {
    // Build ONE Win32-command-line-style string ourselves, rather than handing
    // `-ArgumentList` a PowerShell array. Confirmed the hard way (T490): given
    // an array, `Start-Process` does not reliably quote elements containing
    // spaces for the *child* process — `sc.exe create`'s `binPath=` value
    // (`C:\Program Files\Ankayma\agent.exe service`, which has two spaces) got
    // torn into multiple separate argv entries, and sc.exe failed to parse
    // its own command line (exit 1639) — silently, since nothing upstream
    // caught that either before this fix. Building the exact command line
    // ourselves and passing it as a single string removes the ambiguity.
    let arg_string = args
        .iter()
        .map(|a| win32_quote_arg(a))
        .collect::<Vec<_>>()
        .join(" ");
    // `-PassThru` returns the elevated process object so `-Wait` gives us
    // something to read `.ExitCode` from; `exit $p.ExitCode` propagates it as
    // THIS script's own exit code. A declined/failed UAC prompt makes
    // `Start-Process` itself throw — caught and turned into a distinct
    // non-zero exit (1223 = ERROR_CANCELLED) rather than silently exiting 0.
    let ps = format!(
        "try {{ \
           $p = Start-Process -FilePath '{exe}' -ArgumentList '{arg_string_escaped}' -Verb RunAs -WindowStyle Hidden -Wait -PassThru; \
           exit $p.ExitCode \
         }} catch {{ \
           Write-Error $_; \
           exit 1223 \
         }}",
        arg_string_escaped = arg_string.replace('\'', "''"),
    );
    let status = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &ps])
        .status()
        .map_err(|e| format!("launch elevated {exe}: {e}"))?;
    if !status.success() {
        return Err(format!(
            "elevated {exe} {} exited {status} (UAC declined, or the command itself failed)",
            args.join(" ")
        ));
    }
    Ok(())
}

/// Quote one argument the way the standard Win32 C-runtime argv parser (the
/// one `sc.exe` and virtually every other Windows executable uses) expects,
/// so a value containing spaces (a `C:\Program Files\...` path, in practice)
/// survives as ONE argument rather than being split apart by the child
/// process's own command-line parsing. Simplified for this crate's actual
/// inputs (plain paths/words, no embedded `"` — every arg here is a literal
/// or a filesystem path): wrap in `"…"` whenever the argument contains
/// whitespace, escaping any literal `"` defensively even though none of our
/// current call sites produce one.
/// `[T:Win32 CommandLineToArgvW argv-quoting convention]`
fn win32_quote_arg(arg: &str) -> String {
    if arg.is_empty() || arg.chars().any(char::is_whitespace) {
        format!("\"{}\"", arg.replace('"', "\\\""))
    } else {
        arg.to_string()
    }
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
    // Not run_elevated_wait: taskkill's own exit code (0 = killed, 128 =
    // "process not found") isn't meaningfully distinguishable here without
    // -PassThru anyway (see run_elevated_wait's doc comment on why plain
    // Start-Process -Wait doesn't surface the elevated command's real outcome
    // — confirmed on T490), and this step is genuinely best-effort by design:
    // a failure here (UAC declined, taskkill itself failing) shouldn't block
    // install/update — the real, hard-verified stop is the service-based one
    // right after, once the service actually exists.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quotes_args_with_spaces_but_not_plain_words() {
        assert_eq!(win32_quote_arg("auto"), "auto");
        assert_eq!(win32_quote_arg("LocalSystem"), "LocalSystem");
        assert_eq!(
            win32_quote_arg(r"C:\Program Files\Ankayma\agent.exe service"),
            r#""C:\Program Files\Ankayma\agent.exe service""#
        );
        assert_eq!(win32_quote_arg("Ankayma Mesh"), "\"Ankayma Mesh\"");
    }

    #[test]
    fn quoted_args_join_into_the_exact_sc_create_command_line() {
        let args = [
            "create",
            "Ankayma",
            "binPath=",
            r"C:\Program Files\Ankayma\agent.exe service",
            "start=",
            "auto",
            "obj=",
            "LocalSystem",
            "DisplayName=",
            "Ankayma Mesh",
        ];
        let joined = args
            .iter()
            .map(|a| win32_quote_arg(a))
            .collect::<Vec<_>>()
            .join(" ");
        assert_eq!(
            joined,
            r#"create Ankayma binPath= "C:\Program Files\Ankayma\agent.exe service" start= auto obj= LocalSystem DisplayName= "Ankayma Mesh""#
        );
    }
}
