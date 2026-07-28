//! win_ipc — named-pipe control channel for the Windows Service supervisor
//! (Change 2 of the Windows daemon lifecycle decision,
//! `docs/windows-daemon-lifecycle-decision.md`). Windows-only; wire format and
//! the pure authorization decision live in `ipc_protocol` (cross-platform,
//! unit-tested there).
//!
//! Everyday Connect/Disconnect/Status from the GUI goes over this pipe instead
//! of SCM start/stop or an elevated `Start-Process` — the service (LocalSystem,
//! always running) is already up; the GUI just talks to it. Mirrors Tailscale's
//! `\\.\pipe\tailscale\tailscaled` LocalAPI model.
//!
//! Security: the pipe's own ACL only gates "who can connect at all"
//! (Authenticated Users, via the SDDL below). The real authorization boundary
//! is the per-connection identity check in `identity_authorized` — `Connect`
//! carries a bearer session token in-band to a LocalSystem-privileged process,
//! so every accepted connection is checked against the currently active
//! interactive (console) session **before a single command byte is read**. An
//! unauthorized peer gets the pipe dropped silently — no response, so it learns
//! nothing about why. `[T:Win32 ImpersonateNamedPipeClient/OpenThreadToken/
//! GetTokenInformation/WTSGetActiveConsoleSessionId — docs.microsoft.com Win32 API]`
//!
//! ⚠️ Not yet built or exercised on a real Windows host (this workspace is
//! developed on macOS) — see the plan's Verification section. Review the Win32
//! call sequence carefully before shipping; this is Critical-intensity code
//! per the T/A discipline (crypto/platform `#[cfg]`).

#![cfg(target_os = "windows")]

use std::ffi::c_void;
use std::os::windows::io::AsRawHandle;
use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};

use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, HANDLE};
use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
use windows_sys::Win32::Security::{
    GetTokenInformation, RevertToSelf, TokenSessionId, SECURITY_ATTRIBUTES, TOKEN_QUERY,
};
use windows_sys::Win32::System::Pipes::ImpersonateNamedPipeClient;
use windows_sys::Win32::System::RemoteDesktop::WTSGetActiveConsoleSessionId;
use windows_sys::Win32::System::Threading::{GetCurrentThread, OpenThreadToken};

use crate::ipc_protocol::{encode_response, parse_request, session_authorized, Request, Response};
use crate::win_supervisor::{ConnectOutcome, Supervisor};

pub const PIPE_NAME: &str = r"\\.\pipe\Ankayma\ctl";

/// Owns the `PSECURITY_DESCRIPTOR` buffer `ConvertStringSecurityDescriptorToSecurityDescriptorW`
/// allocates (must live at least as long as every `SECURITY_ATTRIBUTES` built
/// from it, and every `NamedPipeServer` created with those attributes) and the
/// `SECURITY_ATTRIBUTES` wrapper `CreateNamedPipeW` actually wants.
struct SecurityDescriptor {
    /// Allocated by `ConvertStringSecurityDescriptorToSecurityDescriptorW`
    /// (LocalAlloc'd internally) — freed with `LocalFree` on drop.
    descriptor: *mut c_void,
    attrs: SECURITY_ATTRIBUTES,
}

// SAFETY: `descriptor`/`attrs` are only ever read (never mutated after
// construction) and the pointer they hold is process-local heap memory with no
// thread-affinity — sharing the (immutable) descriptor across the tasks that
// each `create_pipe` call borrows it from is sound.
unsafe impl Send for SecurityDescriptor {}
unsafe impl Sync for SecurityDescriptor {}

impl SecurityDescriptor {
    /// `D:(A;;GRGW;;;AU)` — allow Authenticated Users generic read+write (i.e.
    /// "can connect to this pipe at all"). This is the coarse gate; the real
    /// authorization is `identity_authorized` below, run per-connection.
    /// `[T:Win32 SDDL string format — docs.microsoft.com/windows/win32/secauthz/ace-strings]`
    fn authenticated_users_rw() -> std::io::Result<Self> {
        const SDDL: &str = "D:(A;;GRGW;;;AU)";
        let wide: Vec<u16> = SDDL.encode_utf16().chain(std::iter::once(0)).collect();
        let mut descriptor: *mut c_void = std::ptr::null_mut();
        // SAFETY: `wide` is a live, NUL-terminated UTF-16 buffer for the
        // duration of this call; `descriptor`/`size` are valid out-params.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                1, // SDDL_REVISION_1
                &mut descriptor,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 || descriptor.is_null() {
            return Err(std::io::Error::last_os_error());
        }
        let attrs = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor,
            bInheritHandle: 0,
        };
        Ok(Self { descriptor, attrs })
    }

    fn attrs_ptr(&self) -> *mut c_void {
        &self.attrs as *const SECURITY_ATTRIBUTES as *mut c_void
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        // SAFETY: `self.descriptor` was allocated by
        // ConvertStringSecurityDescriptorToSecurityDescriptorW, which the Win32
        // docs say must be freed with LocalFree — freed exactly once, here.
        unsafe {
            LocalFree(self.descriptor as _);
        }
    }
}

fn create_pipe(first_instance: bool, sd: &SecurityDescriptor) -> std::io::Result<NamedPipeServer> {
    // SAFETY: `sd.attrs_ptr()` points at a live `SECURITY_ATTRIBUTES` owned by
    // `sd`, which the caller (`serve`'s loop) keeps alive for as long as any
    // pipe instance created from it exists.
    unsafe {
        ServerOptions::new()
            .first_pipe_instance(first_instance)
            .create_with_security_attributes_raw(PIPE_NAME, sd.attrs_ptr())
    }
}

/// Serve forever. Each accepted connection is identity-checked before any
/// command is read.
pub async fn serve(supervisor: Arc<Supervisor>) -> std::io::Result<()> {
    let sd = SecurityDescriptor::authenticated_users_rw()?;
    // `first_pipe_instance(true)` on the very first create: fail fast rather
    // than silently coexisting if something else already registered this pipe
    // name (pipe-squatting) — a real error here should surface, not be masked
    // by quietly becoming the Nth instance.
    let mut server = create_pipe(true, &sd)?;
    loop {
        server.connect().await?;
        let connected = server;
        // Tokio's documented pattern: queue the next instance BEFORE handing
        // the connected one off, so a client can never race a moment where no
        // instance is listening. `[T:tokio named_pipe module docs]`
        server = create_pipe(false, &sd)?;

        let supervisor = supervisor.clone();
        tokio::spawn(async move {
            if !identity_authorized(&connected) {
                eprintln!("win_ipc: rejected a connection from an unauthorized session");
                return; // drop the pipe with no response — don't confirm/deny anything
            }
            if let Err(e) = handle_connection(connected, &supervisor).await {
                eprintln!("win_ipc: connection error: {e}");
            }
        });
    }
}

/// Read the connecting client's session id via impersonation and compare it to
/// the active console session. The impersonation window is kept as short as
/// possible: revert immediately after reading the one piece of information
/// needed, before doing anything else on this thread.
fn identity_authorized(pipe: &NamedPipeServer) -> bool {
    let pipe_handle = pipe.as_raw_handle() as HANDLE;

    // SAFETY: `pipe_handle` is a live, valid named-pipe server handle owned by
    // `pipe` for the duration of this call (borrowed, not consumed) — the
    // documented way to read a connected client's identity on a pipe.
    if unsafe { ImpersonateNamedPipeClient(pipe_handle) } == 0 {
        return false;
    }

    let session_id = read_impersonated_session_id();

    // SAFETY: matches the successful ImpersonateNamedPipeClient above — always
    // reverts, on every path, so this thread never keeps running under the
    // client's token past this point.
    unsafe {
        RevertToSelf();
    }

    let Some(session_id) = session_id else {
        return false;
    };
    // SAFETY: no arguments; a plain Win32 query.
    let active = unsafe { WTSGetActiveConsoleSessionId() };
    session_authorized(session_id, active)
}

/// Must only be called while this thread is impersonating the pipe client
/// (between `ImpersonateNamedPipeClient` and `RevertToSelf`).
fn read_impersonated_session_id() -> Option<u32> {
    // SAFETY: GetCurrentThread never fails (returns a pseudo-handle, no cleanup
    // needed); OpenThreadToken's out-param `token` is a valid local, only read
    // if the call reports success.
    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        // openasself=TRUE (1): open the thread's own (impersonation) token as
        // the caller, not the process's primary token.
        if OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) == 0 {
            return None;
        }
        let mut session_id: u32 = 0;
        let mut ret_len: u32 = 0;
        let ok = GetTokenInformation(
            token,
            TokenSessionId,
            &mut session_id as *mut u32 as *mut c_void,
            std::mem::size_of::<u32>() as u32,
            &mut ret_len,
        );
        CloseHandle(token);
        if ok != 0 {
            Some(session_id)
        } else {
            None
        }
    }
}

async fn handle_connection(pipe: NamedPipeServer, supervisor: &Supervisor) -> std::io::Result<()> {
    let (rh, mut wh) = tokio::io::split(pipe);
    let mut lines = BufReader::new(rh).lines();
    while let Some(line) = lines.next_line().await? {
        let resp = match parse_request(&line) {
            Some(req) => dispatch(req, supervisor),
            None => Response::err("malformed request"),
        };
        wh.write_all(encode_response(&resp).as_bytes()).await?;
        wh.write_all(b"\n").await?;
    }
    Ok(())
}

fn dispatch(req: Request, supervisor: &Supervisor) -> Response {
    match req {
        Request::Connect {
            token,
            control_plane,
        } => match supervisor.connect(&token, &control_plane) {
            Ok(ConnectOutcome::Connected) => Response::ok_status(true),
            Ok(ConnectOutcome::AlreadyConnected) => Response::ok_status(true),
            Err(e) => Response::err(format!("connect failed: {e}")),
        },
        Request::Disconnect => {
            supervisor.disconnect();
            Response::ok_status(false)
        }
        Request::Status => Response::ok_status(supervisor.is_connected()),
    }
}
