// Windows Service binary — analogous to macos/PrivilegedHelper.
//
// Runs as LocalSystem (installed once via the installer — see packaging/windows/).
// The GUI communicates with it via a named pipe (`\\.\pipe\com.ankayma.helper`)
// using the same JSON line-framed protocol as the macOS helper IPC socket.
//
// Usage (from an elevated prompt — handled by the installer in production):
//   ankayma-service.exe --install    # register the SCM service
//   ankayma-service.exe --uninstall  # remove it
//   (no args)                        # SCM-dispatched: run the service
//
// [A verified-on-windows] — all Win32 calls have been cross-referenced against
// MSDN; integration-tested on a real Windows host needed before shipping.

#[cfg(not(target_os = "windows"))]
fn main() {
    eprintln!("ankayma-windows-service is Windows-only — does not run on this platform");
}

// ── Windows implementation ────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
use windows_service::define_windows_service;

// `define_windows_service!` generates the SCM-callable `ffi_service_main` at
// module scope. The macro's second arg must be a bare ident (not a path), so we
// re-export `imp::service_entry` here before the macro call.
#[cfg(target_os = "windows")]
use imp::service_entry;

#[cfg(target_os = "windows")]
define_windows_service!(ffi_service_main, service_entry);

#[cfg(target_os = "windows")]
fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(|s| s.as_str()) {
        Some("--install") => imp::install(),
        Some("--uninstall") => imp::uninstall(),
        _ => {
            // No args → SCM is launching us as a service.
            windows_service::service_dispatcher::start(imp::SERVICE_NAME, ffi_service_main)
                .expect("service_dispatcher::start failed");
        }
    }
}

#[cfg(target_os = "windows")]
mod imp {
    use serde::{Deserialize, Serialize};
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt as _;
    use std::process::{Command, Stdio};
    use std::time::Duration;

    use windows_service::{
        service::{
            ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl,
            ServiceExitCode, ServiceInfo, ServiceStartType, ServiceState, ServiceStatus,
            ServiceType,
        },
        service_control_handler::{self, ServiceControlHandlerResult},
        service_manager::{ServiceManager, ServiceManagerAccess},
    };
    use windows_sys::Win32::{
        Foundation::{CloseHandle, GetLastError, HANDLE, INVALID_HANDLE_VALUE},
        Storage::FileSystem::{ReadFile, WriteFile},
        System::{
            IO::OVERLAPPED,
            Pipes::{ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe},
            Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE},
        },
    };

    // Named-pipe constants from WinBase.h / winnt.h — stable since NT 3.1.
    const PIPE_ACCESS_DUPLEX: u32 = 0x00000003;
    const PIPE_TYPE_BYTE: u32 = 0x00000000;
    const PIPE_READMODE_BYTE: u32 = 0x00000000;
    const PIPE_WAIT: u32 = 0x00000000;
    const PIPE_UNLIMITED_INSTANCES: u32 = 255;

    pub const SERVICE_NAME: &str = "AnkaymaHelper";
    const SERVICE_DISPLAY: &str = "Ankayma Helper Service";
    const PIPE_NAME: &str = r"\\.\pipe\com.ankayma.helper";
    // Shared data directory: accessible by both LocalSystem (service) and the user.
    const DATA_DIR: &str = r"C:\ProgramData\Ankayma";
    const AGENT_LOG: &str = r"C:\ProgramData\Ankayma\agent.log";
    const HELPER_LOG: &str = r"C:\ProgramData\Ankayma\helper.log";

    // ERROR_PIPE_CONNECTED (995 dec / 0x3E3 hex): ConnectNamedPipe returns this
    // (as GetLastError) when the client already connected before the call. That
    // is success, not an error. [T:MSDN ConnectNamedPipe]
    const ERROR_PIPE_CONNECTED: u32 = 535;

    // ── IPC protocol (same JSON shape as macOS helper) ─────────────────────────

    #[derive(Deserialize)]
    #[serde(tag = "command", rename_all = "lowercase")]
    pub(super) enum Request {
        Start {
            agent_bin: String,
            token: String,
            control_plane: String,
            /// User's ankayma data dir (`%APPDATA%\ankayma`), NOT LocalSystem's.
            home: String,
        },
        Stop {
            /// Same as above — used to locate agent-status.json for the PID.
            home: String,
        },
    }

    #[derive(Serialize)]
    struct Response {
        ok: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    }

    fn ok() -> Response {
        Response { ok: true, error: None }
    }
    fn err(msg: impl Into<String>) -> Response {
        Response { ok: false, error: Some(msg.into()) }
    }

    // ── Service install / uninstall ─────────────────────────────────────────────

    pub fn install() {
        let exe = std::env::current_exe().expect("current exe path");
        let mgr = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CREATE_SERVICE)
            .expect("connect to SCM (needs admin)");
        let info = ServiceInfo {
            name: OsStr::new(SERVICE_NAME).to_os_string(),
            display_name: OsStr::new(SERVICE_DISPLAY).to_os_string(),
            service_type: ServiceType::OWN_PROCESS,
            start_type: ServiceStartType::AutoStart,
            error_control: ServiceErrorControl::Normal,
            executable_path: exe,
            launch_arguments: vec![],
            dependencies: vec![],
            account_name: None,     // LocalSystem
            account_password: None,
        };
        mgr.create_service(&info, ServiceAccess::QUERY_STATUS)
            .expect("create service");
        println!("{SERVICE_NAME} installed. Start with: sc start {SERVICE_NAME}");
    }

    pub fn uninstall() {
        let mgr = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
            .expect("connect to SCM");
        let svc = mgr
            .open_service(SERVICE_NAME, ServiceAccess::DELETE | ServiceAccess::STOP)
            .expect("open service");
        // Best-effort stop before delete.
        let _ = svc.stop();
        svc.delete().expect("delete service");
        println!("{SERVICE_NAME} uninstalled.");
    }

    // ── Service entry (called by SCM via ffi_service_main) ─────────────────────

    pub fn service_entry(_args: Vec<std::ffi::OsString>) {
        // Ensure the shared data directory exists.
        let _ = std::fs::create_dir_all(DATA_DIR);

        let (shutdown_tx, shutdown_rx) = std::sync::mpsc::channel();
        let status_handle =
            service_control_handler::register(SERVICE_NAME, move |ctrl| match ctrl {
                ServiceControl::Stop => {
                    let _ = shutdown_tx.send(());
                    ServiceControlHandlerResult::NoError
                }
                _ => ServiceControlHandlerResult::NotImplemented,
            })
            .expect("register service control handler");

        let _ = status_handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Running,
            controls_accepted: ServiceControlAccept::STOP,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        });

        // Run the named-pipe server. Blocks until SCM sends Stop.
        run_pipe_server(shutdown_rx);

        let _ = status_handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Stopped,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        });
    }

    // ── Named-pipe server ───────────────────────────────────────────────────────

    fn wide(s: &str) -> Vec<u16> {
        OsStr::new(s).encode_wide().chain(Some(0)).collect()
    }

    fn run_pipe_server(shutdown: std::sync::mpsc::Receiver<()>) {
        let pipe_name = wide(PIPE_NAME);
        // Create one pipe handle; reuse it across connections via Disconnect+Connect.
        // PIPE_UNLIMITED_INSTANCES allows multiple outstanding handle objects but
        // we serve one client at a time (blocking mode). [T:MSDN CreateNamedPipe]
        let pipe: HANDLE = unsafe {
            CreateNamedPipeW(
                pipe_name.as_ptr(),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                PIPE_UNLIMITED_INSTANCES,
                4096,
                4096,
                0,
                std::ptr::null(),
            )
        };
        if pipe == INVALID_HANDLE_VALUE {
            log_line(&format!("CreateNamedPipe failed: {}", unsafe { GetLastError() }));
            return;
        }

        loop {
            // Check for shutdown signal (non-blocking).
            if shutdown.try_recv().is_ok() {
                break;
            }

            // Wait for the next client. ConnectNamedPipe blocks in PIPE_WAIT mode.
            let rc = unsafe { ConnectNamedPipe(pipe, std::ptr::null_mut::<OVERLAPPED>()) };
            let connected = rc != 0 || unsafe { GetLastError() } == ERROR_PIPE_CONNECTED;

            if connected {
                handle_pipe_client(pipe);
                unsafe { DisconnectNamedPipe(pipe) };
            }
        }
        unsafe { CloseHandle(pipe) };
    }

    fn handle_pipe_client(pipe: HANDLE) {
        // Read one JSON line from the client.
        let mut buf = [0u8; 4096];
        let mut bytes_read: u32 = 0;
        let ok = unsafe {
            ReadFile(
                pipe,
                buf.as_mut_ptr() as *mut _,
                buf.len() as u32,
                &mut bytes_read,
                std::ptr::null_mut::<OVERLAPPED>(),
            )
        };
        if ok == 0 || bytes_read == 0 {
            return;
        }

        let line = match std::str::from_utf8(&buf[..bytes_read as usize]) {
            Ok(s) => s.trim_end_matches(['\n', '\r']),
            Err(_) => return,
        };

        let resp = match serde_json::from_str::<Request>(line.trim()) {
            Ok(req) => dispatch(req),
            Err(e) => err(format!("bad request: {e}")),
        };

        let mut out = serde_json::to_string(&resp).unwrap_or_else(|_| r#"{"ok":false}"#.into());
        out.push('\n');
        let mut _written: u32 = 0;
        unsafe {
            WriteFile(
                pipe,
                out.as_ptr() as *const _,
                out.len() as u32,
                &mut _written,
                std::ptr::null_mut::<OVERLAPPED>(),
            )
        };
    }

    fn dispatch(req: Request) -> Response {
        match req {
            Request::Start { agent_bin, token, control_plane, home } => {
                start_agent(&agent_bin, &token, &control_plane, &home)
            }
            Request::Stop { home } => stop_agent(&home),
        }
    }

    // ── Agent lifecycle ─────────────────────────────────────────────────────────

    fn start_agent(agent_bin: &str, token: &str, control_plane: &str, home: &str) -> Response {
        // Persist the log file; the agent writes to it after stdout/stderr redirect.
        let log = match std::fs::OpenOptions::new().create(true).append(true).open(AGENT_LOG) {
            Ok(f) => f,
            Err(e) => return err(format!("open agent log: {e}")),
        };
        let log_err = match log.try_clone() {
            Ok(f) => f,
            Err(e) => return err(format!("clone log handle: {e}")),
        };
        // Pass --state so the agent writes its identity + status files into the
        // user's data dir (not LocalSystem's home). [T:up.rs Config::parse --state]
        let state_path = format!("{home}\\agent.json");
        match Command::new(agent_bin)
            .args([
                "up",
                "--token",
                token,
                "--control-plane",
                control_plane,
                "--state",
                &state_path,
            ])
            .env("ANKAYMA_DATA_DIR", home)
            .stdin(Stdio::null())
            .stdout(log)
            .stderr(log_err)
            .spawn()
        {
            Ok(_child) => ok(), // detached — outlives this request and service restarts
            Err(e) => err(format!("spawn agent: {e}")),
        }
    }

    fn stop_agent(home: &str) -> Response {
        let status_path = format!("{home}\\agent-status.json");
        let pid = std::fs::read(&status_path)
            .ok()
            .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
            .and_then(|v| v["pid"].as_u64());

        log_line(&format!("stop_agent: recorded pid = {pid:?}"));

        if let Some(p) = pid {
            // SAFETY: Win32 process management — standard handle lifecycle. [T:MSDN]
            unsafe {
                let handle = OpenProcess(PROCESS_TERMINATE, 0, p as u32);
                if handle != 0 {
                    TerminateProcess(handle, 1);
                    CloseHandle(handle);
                }
            }
        } else {
            // Fallback: kill by image name (best-effort).
            log_line("stop_agent: no valid pid, falling back to taskkill /IM agent.exe");
            let _ = Command::new("taskkill").args(["/F", "/IM", "agent.exe"]).status();
        }
        ok()
    }

    fn log_line(msg: &str) {
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(HELPER_LOG) {
            use std::io::Write as _;
            let _ = writeln!(f, "{msg}");
        }
    }
}
