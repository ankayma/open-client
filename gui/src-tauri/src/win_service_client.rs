//! win_service_client — GUI-side client for the Windows Service supervisor's
//! named-pipe control channel (Change 4 of the Windows daemon lifecycle
//! decision, `docs/windows-daemon-lifecycle-decision.md`). Blocking Win32 file
//! I/O (`CreateFileW`/`ReadFile`/`WriteFile`), not tokio's async named pipe:
//! every caller here (`bring_up_dataplane`, `stop_dataplane_inner`) is already
//! a sync fn run via `spawn_blocking`, matching that existing style rather
//! than pulling tokio's Windows named-pipe support into this crate too.
//!
//! Wire format is duplicated (not shared via a crate dependency) from
//! `agent-daemon`'s `ipc_protocol` — it's 3 small JSON shapes, and this crate
//! doesn't otherwise depend on `agent-daemon` as a library (A.3.1 hexagonal
//! seam: GUI is its own crate). Keep the two in sync by hand if the protocol
//! ever changes.
//!
//! ⚠️ Not yet built or exercised on a real Windows host (this workspace is
//! developed on macOS) — see the plan's Verification section.

#![cfg(target_os = "windows")]

use std::os::windows::ffi::OsStrExt;
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_PIPE_BUSY, GENERIC_READ, GENERIC_WRITE, HANDLE,
    INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, ReadFile, WriteFile, FILE_ATTRIBUTE_NORMAL, OPEN_EXISTING,
    SECURITY_IMPERSONATION, SECURITY_SQOS_PRESENT,
};
use windows_sys::Win32::System::Pipes::WaitNamedPipeW;

const PIPE_NAME: &str = r"\\.\pipe\Ankayma\ctl";
/// Total time budget for "every instance is busy right now" retries — the
/// service always keeps one spare instance queued (win_ipc's `serve` loop), so
/// this should only ever need the immediate attempt in practice; the retry
/// exists for the rare race right as another client connects.
const BUSY_RETRY_BUDGET: Duration = Duration::from_secs(3);

fn wide(s: &str) -> Vec<u16> {
    std::ffi::OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

struct PipeHandle(HANDLE);

impl Drop for PipeHandle {
    fn drop(&mut self) {
        // SAFETY: `self.0` is a valid, open handle for the lifetime of this
        // struct — closed exactly once, here.
        unsafe {
            CloseHandle(self.0);
        }
    }
}

fn open_pipe() -> Result<PipeHandle, String> {
    let name = wide(PIPE_NAME);
    let deadline = Instant::now() + BUSY_RETRY_BUDGET;
    loop {
        // SAFETY: `name` is a live, NUL-terminated UTF-16 buffer for the
        // duration of this call; no other lifetime requirements.
        //
        // SECURITY_SQOS_PRESENT | SECURITY_IMPERSONATION is not optional here:
        // without it, the server's `ImpersonateNamedPipeClient` call fails
        // with ERROR_ALREADY_EXISTS (183) — confirmed on a real Windows host
        // (T490) via a bare CreateFileW client that omitted these flags, which
        // is exactly what this function used to do. A client that doesn't
        // request impersonation-level access simply cannot be impersonated by
        // the server, by Win32 design — the flag is the client's consent to
        // be impersonated at all, which every legitimate caller of this
        // in-band-bearer-token protocol needs to grant.
        // `[T:Win32 CreateFile SECURITY_SQOS_PRESENT/SECURITY_IMPERSONATION —
        // docs.microsoft.com/windows/win32/api/fileapi/nf-fileapi-createfilew]`
        let handle = unsafe {
            CreateFileW(
                name.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL | SECURITY_SQOS_PRESENT | SECURITY_IMPERSONATION,
                std::ptr::null_mut(),
            )
        };
        if handle != INVALID_HANDLE_VALUE {
            return Ok(PipeHandle(handle));
        }
        let err = unsafe { GetLastError() };
        if err != ERROR_PIPE_BUSY || Instant::now() >= deadline {
            return Err(format!(
                "connect to {PIPE_NAME} failed (os error {err}) — is the Ankayma service running?"
            ));
        }
        // SAFETY: `name` still live; 200ms is an arbitrary short wait,
        // matching WaitNamedPipeW's documented "how long to wait for an
        // instance to free up" contract.
        unsafe {
            WaitNamedPipeW(name.as_ptr(), 200);
        }
    }
}

fn write_line(pipe: &PipeHandle, line: &str) -> Result<(), String> {
    let mut buf = line.as_bytes().to_vec();
    buf.push(b'\n');
    let mut written: u32 = 0;
    // SAFETY: `buf` is a live buffer of `buf.len()` bytes for the duration of
    // this call; `written` is a valid local out-param.
    let ok = unsafe {
        WriteFile(
            pipe.0,
            buf.as_ptr(),
            buf.len() as u32,
            &mut written,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(format!("write to {PIPE_NAME} failed: {}", unsafe {
            GetLastError()
        }));
    }
    Ok(())
}

/// Read until the first `\n` (the service replies with exactly one JSON line
/// per request) or the buffer fills — 4KiB is generous for `{"ok":...}`.
fn read_line(pipe: &PipeHandle) -> Result<String, String> {
    let mut out = Vec::new();
    let mut chunk = [0u8; 256];
    loop {
        let mut read: u32 = 0;
        // SAFETY: `chunk` is a live 256-byte buffer for the duration of this
        // call; `read` is a valid local out-param.
        let ok = unsafe {
            ReadFile(
                pipe.0,
                chunk.as_mut_ptr(),
                chunk.len() as u32,
                &mut read,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(format!("read from {PIPE_NAME} failed: {}", unsafe {
                GetLastError()
            }));
        }
        if read == 0 {
            break;
        }
        out.extend_from_slice(&chunk[..read as usize]);
        if out.contains(&b'\n') || out.len() > 4096 {
            break;
        }
    }
    String::from_utf8(out).map_err(|e| format!("non-UTF8 response: {e}"))
}

/// One request/response round trip over the pipe. `request_json` must be a
/// single JSON object matching `agent_daemon::ipc_protocol::Request`.
fn call(request_json: &str) -> Result<serde_json::Value, String> {
    let pipe = open_pipe()?;
    write_line(&pipe, request_json)?;
    let line = read_line(&pipe)?;
    serde_json::from_str(line.trim()).map_err(|e| format!("malformed response {line:?}: {e}"))
}

fn expect_ok(resp: serde_json::Value) -> Result<serde_json::Value, String> {
    if resp.get("ok").and_then(|v| v.as_bool()) == Some(true) {
        Ok(resp)
    } else {
        let err = resp
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown error");
        Err(err.to_string())
    }
}

/// Bring the tunnel up: the equivalent of the old `Start-Process agent.exe up
/// -Verb RunAs` — but no elevation here, since the service (LocalSystem,
/// already running) does the actual work; this just asks it to.
pub fn connect(token: &str, control_plane: &str) -> Result<(), String> {
    let req = serde_json::json!({
        "cmd": "connect",
        "token": token,
        "control_plane": control_plane,
    });
    expect_ok(call(&req.to_string())?)?;
    Ok(())
}

/// Tear the tunnel down. Verified: the reply only comes back once the service
/// has actually finished `Supervisor::disconnect()` (kill + wait on the real
/// child process) — unlike the old `taskkill`-based `stop_dataplane_inner`,
/// there's nothing left to poll or guess about afterward.
pub fn disconnect() -> Result<(), String> {
    let req = serde_json::json!({ "cmd": "disconnect" });
    expect_ok(call(&req.to_string())?)?;
    Ok(())
}

/// `true` if the service reports a live tunnel right now.
pub fn is_connected() -> Result<bool, String> {
    let req = serde_json::json!({ "cmd": "status" });
    let resp = expect_ok(call(&req.to_string())?)?;
    Ok(resp
        .get("connected")
        .and_then(|v| v.as_bool())
        .unwrap_or(false))
}
