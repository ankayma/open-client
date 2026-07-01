// Root LaunchDaemon (installed once via SMAppService, see docs/hotfix-macos-dataplane-gaps.md
// Gap 1). Runs forever as root so the GUI never needs a per-connect/disconnect
// admin password prompt — the osascript `with administrator privileges`
// quick-fix it replaces couldn't be scripted/automated and Apple rejects
// `osascript` from a sandboxed App Store build.
//
// [A] IPC is a plain Unix domain socket, NOT literal XPC as the hotfix doc first
// sketched — the only maintained Rust XPC binding (`xpc-connection`, 2018) is
// stale and one-directional (client-side only); a listener-side daemon would need
// hand-rolled libxpc FFI. A root-owned UDS with per-request peer-uid + home-dir
// ownership authorization gives the same security property (only the owning
// user's GUI can command it) with std-library reliability. Live-tested on a
// signed .app install cycle 2026-07-01 (registration + start/stop round-trip
// confirmed); hot-reloading the running daemon after a rebuild still needs a
// reboot/logout — `launchctl kickstart` did not pick up a replaced binary.

// `libc::getpeereid` is a BSD/macOS-only symbol (Linux has no equivalent, it uses
// SO_PEERCRED instead), so this whole binary is gated behind target_os = "macos".
// It still needs to exist as a no-op on other platforms because it's a Cargo
// workspace member and `cargo test --workspace` runs on Linux CI (.gitlab-ci.yml).
#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("ankayma-helper is macOS-only");
}

#[cfg(target_os = "macos")]
fn main() {
    imp::run();
}

#[cfg(target_os = "macos")]
mod imp {

    use serde::{Deserialize, Serialize};
    use std::fs;
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::os::unix::io::AsRawFd;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::process::{Command, Stdio};

    const SOCKET_PATH: &str = "/var/run/com.ankayma.helper.sock";
    const LOG_PATH: &str = "/tmp/ankayma-helper.log";
    const AGENT_LOG_PATH: &str = "/tmp/ankayma-agent.log";

    #[derive(Deserialize)]
    #[serde(tag = "command", rename_all = "lowercase")]
    enum Request {
        Start {
            agent_bin: String,
            token: String,
            control_plane: String,
            home: String,
        },
        Stop {
            home: String,
        },
    }

    #[derive(Serialize)]
    struct Response {
        ok: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    }

    pub fn run() {
        let _ = fs::remove_file(SOCKET_PATH);
        let listener = match UnixListener::bind(SOCKET_PATH) {
            Ok(l) => l,
            Err(e) => {
                log_line(&format!("bind {SOCKET_PATH} failed: {e}"));
                std::process::exit(1);
            }
        };
        // World-connectable: the real check is per-request (authorize()), not the
        // socket file mode. [A] revisit if this ever serves a multi-seat host.
        let _ = fs::set_permissions(SOCKET_PATH, fs::Permissions::from_mode(0o666));

        for stream in listener.incoming().flatten() {
            handle_client(stream);
        }
    }

    fn handle_client(mut stream: UnixStream) {
        let peer_uid = match peer_uid(&stream) {
            Ok(u) => u,
            Err(e) => {
                log_line(&format!("getpeereid failed: {e}"));
                return;
            }
        };
        let mut line = String::new();
        if BufReader::new(&stream).read_line(&mut line).is_err() || line.trim().is_empty() {
            return;
        }
        let resp = match serde_json::from_str::<Request>(line.trim()) {
            Ok(req) => dispatch(req, peer_uid),
            Err(e) => Response {
                ok: false,
                error: Some(format!("bad request: {e}")),
            },
        };
        let out = serde_json::to_string(&resp).unwrap_or_else(|_| "{\"ok\":false}".into());
        let _ = writeln!(stream, "{out}");
    }

    fn dispatch(req: Request, peer_uid: u32) -> Response {
        let home = match &req {
            Request::Start { home, .. } => home.clone(),
            Request::Stop { home } => home.clone(),
        };
        if let Err(e) = authorize(&home, peer_uid) {
            return Response {
                ok: false,
                error: Some(e),
            };
        }
        let outcome = match req {
            Request::Start {
                agent_bin,
                token,
                control_plane,
                ..
            } => start_agent(&agent_bin, &token, &control_plane),
            Request::Stop { home } => stop_agent(&home),
        };
        match outcome {
            Ok(()) => Response {
                ok: true,
                error: None,
            },
            Err(e) => Response {
                ok: false,
                error: Some(e),
            },
        }
    }

    /// A caller may only act on the home directory it actually owns — stops a
    /// stranger local process from puppeting another user's agent daemon through
    /// the world-connectable socket. [T:getpeereid(3)-macOS syscall — man 3 getpeereid]
    fn authorize(home: &str, peer_uid: u32) -> Result<(), String> {
        let meta = fs::metadata(home).map_err(|e| format!("stat {home}: {e}"))?;
        if meta.uid() != peer_uid {
            return Err("caller does not own the claimed home directory".into());
        }
        Ok(())
    }

    /// Spawn the agent daemon directly — no shell, so no shell-metacharacter risk
    /// (the osascript quick-fix it replaces had to single-quote around this).
    fn start_agent(agent_bin: &str, token: &str, control_plane: &str) -> Result<(), String> {
        let log = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(AGENT_LOG_PATH)
            .map_err(|e| format!("open {AGENT_LOG_PATH}: {e}"))?;
        let log_err = log.try_clone().map_err(|e| e.to_string())?;
        Command::new(agent_bin)
            .args(["up", "--token", token, "--control-plane", control_plane])
            .stdin(Stdio::null())
            .stdout(log)
            .stderr(log_err)
            .spawn()
            // Intentionally not reaped/waited: it must outlive this request and this
            // helper daemon's own restarts, same detach semantics the osascript `&`
            // version had.
            .map(|_child| ())
            .map_err(|e| format!("spawn agent: {e}"))
    }

    /// [T:kill(2)] SIGTERM the recorded pid, then verify it actually died and
    /// escalate to SIGKILL if not — live-tested 2026-07-01 against an agent
    /// process that had been launched via the old
    /// `osascript … with administrator privileges` quick-fix and survived a
    /// plain SIGTERM (`kill()` returned success, but the process lived on;
    /// `agent`'s own signal handling only listens for SIGINT via
    /// `tokio::signal::ctrl_c()` — see `crates/agent-daemon/src/up.rs`,
    /// SIGTERM has no app-level handler and the ancestor authorization
    /// trampoline may leave SIGTERM ignored across exec()). Falls back to a
    /// name match if the recorded pid is stale.
    fn stop_agent(home: &str) -> Result<(), String> {
        let pid = fs::read(format!("{home}/.ankayma/agent-status.json"))
            .ok()
            .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
            .and_then(|v| v.get("pid").and_then(|p| p.as_u64()));
        log_line(&format!("stop_agent: recorded pid = {pid:?}"));
        let mut killed = false;
        if let Some(p) = pid {
            let pid = p as libc::pid_t;
            let ret = unsafe { libc::kill(pid, libc::SIGTERM) };
            log_line(&format!("stop_agent: kill({pid}, SIGTERM) = {ret}"));
            if ret == 0 {
                std::thread::sleep(std::time::Duration::from_millis(500));
                let still_alive = unsafe { libc::kill(pid, 0) == 0 };
                if still_alive {
                    log_line(&format!(
                        "stop_agent: pid {pid} survived SIGTERM, escalating to SIGKILL"
                    ));
                    unsafe { libc::kill(pid, libc::SIGKILL) };
                }
                killed = true;
            }
        }
        if !killed {
            log_line("stop_agent: no valid recorded pid, falling back to pkill -f 'agent up'");
            let _ = Command::new("pkill").args(["-f", "agent up"]).status();
        }
        Ok(())
    }

    fn peer_uid(stream: &UnixStream) -> Result<u32, String> {
        let fd = stream.as_raw_fd();
        let mut uid: libc::uid_t = 0;
        let mut gid: libc::gid_t = 0;
        let ret = unsafe { libc::getpeereid(fd, &mut uid, &mut gid) };
        if ret != 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        Ok(uid)
    }

    fn log_line(msg: &str) {
        if let Ok(mut f) = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(LOG_PATH)
        {
            let _ = writeln!(f, "{msg}");
        }
    }
} // mod imp
