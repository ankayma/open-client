//! win_service — SCM entry point for `agent service` (Change 3 of the Windows
//! daemon lifecycle decision, `docs/windows-daemon-lifecycle-decision.md`).
//! Registers `Ankayma` with the Service Control Manager (LocalSystem, installed
//! by the GUI's one-time setup — Change 4), then drives the named-pipe
//! supervisor (`win_ipc` + `win_supervisor`) for the service's whole lifetime.
//!
//! `service_dispatcher::start` hands `service_main` its own thread (spawned by
//! the SCM plumbing, distinct from whatever called `win_service::run()`), so
//! the async named-pipe listener gets its own dedicated tokio runtime here
//! rather than assuming one is already active on this thread.
//!
//! ⚠️ Not yet built or exercised on a real Windows host (this workspace is
//! developed on macOS) — see the plan's Verification section. `windows-service`
//! and `windows-sys`'s own APIs are used per their documented examples; review
//! carefully before shipping.

#![cfg(target_os = "windows")]

use std::ffi::OsString;
use std::sync::Arc;
use std::time::Duration;

use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::{define_windows_service, service_dispatcher};

use crate::win_ipc;
use crate::win_supervisor::Supervisor;

const SERVICE_NAME: &str = "Ankayma";

define_windows_service!(ffi_service_main, service_main);

/// Entry point for the `agent service` subcommand (`main.rs`). Registers with
/// the SCM and blocks for the service's entire lifetime — control only returns
/// once the service has been asked to stop (uninstall, upgrade, shutdown).
pub fn run() -> windows_service::Result<()> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
}

fn service_main(_arguments: Vec<OsString>) {
    if let Err(e) = run_service() {
        eprintln!("agent service: {e}");
    }
}

fn run_service() -> windows_service::Result<()> {
    let supervisor = Arc::new(Supervisor::new());

    // The control handler runs on the SCM's own callback thread, entirely
    // outside the tokio runtime spun up below — a plain std channel is what
    // actually crosses that boundary; the handler itself only sends and
    // returns immediately (MSDN: a control handler must not block).
    let (stop_tx, stop_rx) = std::sync::mpsc::channel::<()>();

    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop => {
                let _ = stop_tx.send(());
                ServiceControlHandlerResult::NoError
            }
            // Every service must accept Interrogate even as a no-op.
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };
    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)?;

    status_handle.set_service_status(running_status())?;

    // service_main runs on a thread SCM spawned for us — it does not inherit
    // any runtime from whatever process launched `agent service`, so the
    // named-pipe listener needs its own.
    let rt = tokio::runtime::Runtime::new().map_err(|e| {
        windows_service::Error::Winapi(std::io::Error::other(format!(
            "build tokio runtime for the service: {e}"
        )))
    })?;
    let ipc_supervisor = supervisor.clone();
    rt.spawn(async move {
        if let Err(e) = win_ipc::serve(ipc_supervisor).await {
            eprintln!("agent service: named-pipe listener exited: {e}");
        }
    });

    // Block this thread until SERVICE_CONTROL_STOP fires the channel above.
    let _ = stop_rx.recv();

    status_handle.set_service_status(stop_pending_status())?;
    // Off the SCM callback thread now — safe to do the (bounded, but not
    // instant: a real Child::wait()) teardown here rather than inside the
    // control handler.
    supervisor.disconnect();

    status_handle.set_service_status(stopped_status())?;
    Ok(())
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
        // Generous: `disconnect()` waits on a real child process exit.
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
