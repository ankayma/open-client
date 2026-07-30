//! win_service_headless — SCM entry point for `agent service-headless`.
//!
//! Registers `AnkaymaHeadless` with the Service Control Manager (LocalSystem),
//! then immediately spawns `agent up --state-dir <ANKAYMA_STATE_DIR>` as a child
//! process and keeps it running for the service's whole lifetime — respawning it
//! if it exits before a stop was requested. This is deliberately a *different*
//! service from `Ankayma` (win_service.rs): that one waits idle for a `Connect`
//! message over a named pipe sent by the GUI, which is the right model for a
//! desktop user toggling a tunnel, and the wrong one for a server that should
//! come up on its own at boot with nobody watching a tray icon. The two
//! services coexist under different names; this file does not touch
//! win_service.rs / win_ipc.rs / win_supervisor.rs.
//!
//! Not built on top of `win_supervisor::Supervisor` — that type models
//! credential-diffing Connect/Disconnect toggling for the GUI's IPC protocol,
//! which has no counterpart here: the enrollment token is only needed once, at
//! install time (`scripts/install-windows.ps1` runs `agent up --join-token <T>
//! --control-plane <cp> --state-dir <dir>` once, in the background, just long
//! enough for `AgentState` to persist, then kills it — before this service is
//! ever registered). Every later start of this service — including every
//! reboot — runs `agent up --state-dir <dir>` with no token, reusing the
//! `AgentState` that first run persisted (see up.rs's `load_or_enroll`, and its
//! own comment on `--join-token` being "the headless server path"). A plain
//! spawn+monitor+restart loop is the closer match to systemd's
//! `Restart=on-failure` (packaging/ankayma-agent.service), which is the
//! semantics this service exists to mirror on Windows.
//!
//! ⚠️ Not yet exercised on a real Windows host as of writing. The
//! release-windows-headless.yml CI smoke test verifies SCM install/start/stop
//! on a real Windows runner but not that the child's tunnel actually comes up
//! — that needs a real control-plane + join token, out of CI's reach, and
//! still wants a manual test on real hardware before this is trusted in
//! production.

#![cfg(target_os = "windows")]

use std::ffi::OsString;
use std::process::{Child, Command};
use std::sync::mpsc;
use std::time::Duration;

use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{
    self, ServiceControlHandlerResult, ServiceStatusHandle,
};
use windows_service::{define_windows_service, service_dispatcher};

const SERVICE_NAME: &str = "AnkaymaHeadless";

/// Matches `win_supervisor::CHILD_STATE_DIR` — the well-known system state dir,
/// not `agent up`'s own `$HOME`/`%USERPROFILE%`-first default, for the same
/// reason documented there: a service account's environment is not the
/// interactive user's, and the install script (`install-windows.ps1`) writes
/// the first-run `AgentState` to this exact path.
const STATE_DIR: &str = r"C:\ProgramData\Ankayma";

const RESTART_DELAY: Duration = Duration::from_secs(2);

define_windows_service!(ffi_service_main, service_main);

/// Entry point for the `agent service-headless` subcommand (`main.rs`). Blocks
/// for the service's entire lifetime — control only returns once SCM has asked
/// it to stop.
pub fn run() -> windows_service::Result<()> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
}

fn service_main(_arguments: Vec<OsString>) {
    if let Err(e) = run_service() {
        eprintln!("agent service-headless: {e}");
    }
}

fn run_service() -> windows_service::Result<()> {
    let (stop_tx, stop_rx) = mpsc::channel::<()>();

    // Runs on the SCM's own callback thread — must not block; only sends and
    // returns immediately (MSDN control-handler contract, same as win_service.rs).
    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop => {
                let _ = stop_tx.send(());
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };
    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)?;
    status_handle.set_service_status(running_status())?;

    supervise(&stop_rx, &status_handle);

    status_handle.set_service_status(stopped_status())?;
    Ok(())
}

/// Spawn `agent up --state-dir STATE_DIR`; if it exits before `stop_rx` fires,
/// wait `RESTART_DELAY` and spawn it again. Returns once a stop was requested
/// (child killed and waited-on first) or the control-handler channel itself
/// disconnects (defensive — should not normally happen).
///
/// A failure to spawn at all (missing exe, bad state dir) is treated as fatal
/// here, unlike `win_ipc::serve`'s bind failure in the GUI service
/// (win_service.rs), which only `eprintln!`s and leaves the service "Running".
/// Nobody is watching a tray icon on a headless server — `sc.exe`/external
/// monitoring needs a real signal, so this exits the process non-zero instead.
fn supervise(stop_rx: &mpsc::Receiver<()>, status_handle: &ServiceStatusHandle) {
    loop {
        let mut child = match spawn_agent_up() {
            Ok(c) => c,
            Err(e) => {
                eprintln!("agent service-headless: failed to spawn `agent up`: {e}");
                std::process::exit(1);
            }
        };

        loop {
            match stop_rx.recv_timeout(Duration::from_millis(500)) {
                Ok(()) => {
                    let _ = status_handle.set_service_status(stop_pending_status());
                    let _ = child.kill();
                    let _ = child.wait();
                    return;
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    if let Ok(Some(exit)) = child.try_wait() {
                        eprintln!(
                            "agent service-headless: `agent up` exited ({exit}), restarting in {RESTART_DELAY:?}"
                        );
                        break;
                    }
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => return,
            }
        }
        std::thread::sleep(RESTART_DELAY);
    }
}

fn spawn_agent_up() -> std::io::Result<Child> {
    let exe = std::env::current_exe()?;
    Command::new(exe)
        .arg("up")
        .arg("--state-dir")
        .arg(STATE_DIR)
        .spawn()
}

fn running_status() -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    }
}

fn stop_pending_status() -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::StopPending,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 1,
        // Generous: kill+wait on a real child (agent up, which itself tears down
        // utun/routes/threads on exit) is not instant.
        wait_hint: Duration::from_secs(10),
        process_id: None,
    }
}

fn stopped_status() -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    }
}
