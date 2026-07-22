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
// workspace member and `cargo test --workspace` runs on Linux CI (GitHub Actions,
// .github/workflows/ci.yml).
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
    // Root-owned log dir — NOT /tmp: a fixed world-writable /tmp path lets any
    // local user pre-plant a symlink for root to append through, and makes the
    // agent's connection-level log world-readable. /var/log requires root to
    // create, and the files are opened 0600 + O_NOFOLLOW (see open_log).
    const LOG_DIR: &str = "/var/log/ankayma";
    const LOG_PATH: &str = "/var/log/ankayma/helper.log";
    const AGENT_LOG_PATH: &str = "/var/log/ankayma/agent.log";
    /// Pid of the agent WE spawned, recorded root-owned at spawn time so
    /// stop_agent never has to trust the caller-writable status file.
    const PID_PATH: &str = "/var/run/com.ankayma.agent.pid";
    /// Root-owned state dir for the agent daemon, passed via `--state-dir` — NEVER
    /// via `$HOME`: launchd strips `$HOME` from root daemons (macOS ≥ Catalina), so
    /// the agent's home-relative fallback landed on the sealed read-only system
    /// volume and it died at startup. And root resolving paths inside a
    /// caller-owned home dir is symlink-attack surface (CWE-59) — the same reason
    /// open_log is O_NOFOLLOW. See docs/daemon-state-dir.md.
    const AGENT_STATE_DIR: &str = "/Library/Ankayma";

    #[derive(Deserialize)]
    #[serde(tag = "command", rename_all = "lowercase")]
    enum Request {
        Start {
            agent_bin: String,
            token: String,
            control_plane: String,
            home: String,
            /// The GUI's enrolled identity (agent.json content) — the handoff that
            /// used to happen implicitly by sharing `~/.ankayma`. Optional so a
            /// request from an older GUI build still parses.
            #[serde(default)]
            state_json: Option<String>,
        },
        Stop {
            home: String,
        },
        /// Return the tail of the two ROOT-OWNED daemon logs so the owning user can
        /// build a diagnostic bundle (user-triggered bug report). The caller never
        /// supplies a path — only the two fixed files under LOG_DIR are ever read,
        /// so this can't be turned into an arbitrary-file-read-as-root primitive.
        Readlogtail {
            home: String,
        },
    }

    #[derive(Serialize, Default)]
    struct Response {
        ok: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        error: Option<String>,
        /// Tail of `/var/log/ankayma/agent.log` — set only by `Readlogtail`.
        #[serde(skip_serializing_if = "Option::is_none")]
        agent_log: Option<String>,
        /// Tail of `/var/log/ankayma/helper.log` — set only by `Readlogtail`.
        #[serde(skip_serializing_if = "Option::is_none")]
        helper_log: Option<String>,
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
                ..Default::default()
            },
        };
        let out = serde_json::to_string(&resp).unwrap_or_else(|_| "{\"ok\":false}".into());
        let _ = writeln!(stream, "{out}");
    }

    fn dispatch(req: Request, peer_uid: u32) -> Response {
        let home = match &req {
            Request::Start { home, .. } => home.clone(),
            Request::Stop { home } => home.clone(),
            Request::Readlogtail { home } => home.clone(),
        };
        if let Err(e) = authorize(&home, peer_uid) {
            return Response {
                ok: false,
                error: Some(e),
                ..Default::default()
            };
        }
        // ReadLogTail returns data, not a unit outcome — handle it separately.
        if let Request::Readlogtail { .. } = req {
            return Response {
                ok: true,
                agent_log: Some(read_log_tail(AGENT_LOG_PATH)),
                helper_log: Some(read_log_tail(LOG_PATH)),
                ..Default::default()
            };
        }
        let outcome = match req {
            Request::Start {
                agent_bin,
                token,
                control_plane,
                state_json,
                ..
            } => start_agent(&agent_bin, &token, &control_plane, state_json.as_deref()),
            Request::Stop { home } => stop_agent(&home),
            Request::Readlogtail { .. } => unreachable!("handled above"),
        };
        match outcome {
            Ok(()) => Response {
                ok: true,
                error: None,
                ..Default::default()
            },
            Err(e) => Response {
                ok: false,
                error: Some(e),
                ..Default::default()
            },
        }
    }

    /// Last `LOG_TAIL_LINES` lines of a FIXED root-owned log (never a caller path).
    /// O_NOFOLLOW so a planted symlink can't redirect the read; a missing/unreadable
    /// file yields a short marker, never an error (a bug report is best-effort).
    fn read_log_tail(path: &str) -> String {
        const LOG_TAIL_LINES: usize = 200;
        use std::os::unix::fs::OpenOptionsExt;
        let file = match fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
        {
            Ok(f) => f,
            Err(e) => return format!("(no {path}: {e})"),
        };
        let lines: Vec<String> = BufReader::new(file).lines().map_while(Result::ok).collect();
        let start = lines.len().saturating_sub(LOG_TAIL_LINES);
        lines[start..].join("\n")
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

    /// Open a log file under LOG_DIR: 0600, append, and O_NOFOLLOW so root
    /// never writes through a planted symlink. [T:open(2)-macOS O_NOFOLLOW]
    fn open_log(path: &str) -> std::io::Result<fs::File> {
        use std::os::unix::fs::OpenOptionsExt;
        fs::create_dir_all(LOG_DIR)?;
        fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
    }

    /// Seed the daemon's agent.json from the GUI's enrolled identity — replaces the
    /// implicit handoff of both processes reading one `~/.ankayma`. Written only when
    /// the daemon has no state yet or the node identity changed (new tenant, rotated
    /// WireGuard key): once seeded, the daemon's copy is the living one — its
    /// background token renewal rewrites it, and a renewal invalidates the previous
    /// token server-side, so overwriting with the GUI's older copy would hand the
    /// daemon a dead credential.
    fn seed_state(incoming_json: &str) -> Result<(), String> {
        use std::os::unix::fs::OpenOptionsExt;
        #[derive(Deserialize)]
        struct Identity {
            node_id: String,
            public_b64: String,
        }
        let incoming: Identity =
            serde_json::from_str(incoming_json).map_err(|e| format!("bad state_json: {e}"))?;
        let path = format!("{AGENT_STATE_DIR}/agent.json");
        let same_identity = fs::read(&path)
            .ok()
            .and_then(|b| serde_json::from_slice::<Identity>(&b).ok())
            .is_some_and(|cur| {
                cur.node_id == incoming.node_id && cur.public_b64 == incoming.public_b64
            });
        if same_identity {
            return Ok(());
        }
        let mut f = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)
            .map_err(|e| format!("open {path}: {e}"))?;
        f.write_all(incoming_json.as_bytes())
            .map_err(|e| format!("write {path}: {e}"))?;
        Ok(())
    }

    /// Spawn the agent daemon directly — no shell, so no shell-metacharacter risk
    /// (the osascript quick-fix it replaces had to single-quote around this).
    fn start_agent(
        agent_bin: &str,
        token: &str,
        control_plane: &str,
        state_json: Option<&str>,
    ) -> Result<(), String> {
        // 0755 dir: agent.json inside stays 0600 (seed_state), while the status
        // snapshot the daemon writes is world-readable on purpose — the GUI's
        // path-proof panel reads it, and it carries connection-level metadata only.
        fs::create_dir_all(AGENT_STATE_DIR)
            .map_err(|e| format!("create {AGENT_STATE_DIR}: {e}"))?;
        let _ = fs::set_permissions(AGENT_STATE_DIR, fs::Permissions::from_mode(0o755));
        if let Some(json) = state_json {
            seed_state(json)?;
        }
        let log = open_log(AGENT_LOG_PATH).map_err(|e| format!("open {AGENT_LOG_PATH}: {e}"))?;
        let log_err = log.try_clone().map_err(|e| e.to_string())?;
        let child = Command::new(agent_bin)
            .args([
                "up",
                "--control-plane",
                control_plane,
                "--state-dir",
                AGENT_STATE_DIR,
            ])
            // Token via env, never argv: argv of the long-lived root `agent up`
            // process is world-visible in `ps` for the whole tunnel lifetime; a
            // root process's environment is not. `agent up` already reads
            // $ANKAYMA_TOKEN [T:agent-daemon/src/up.rs Config::parse].
            .env("ANKAYMA_TOKEN", token)
            .stdin(Stdio::null())
            .stdout(log)
            .stderr(log_err)
            .spawn()
            // Intentionally not reaped/waited: it must outlive this request and this
            // helper daemon's own restarts, same detach semantics the osascript `&`
            // version had.
            .map_err(|e| format!("spawn agent: {e}"))?;
        // Record the pid root-side; best-effort — stop_agent still verifies the
        // target executable before signalling, so a missing file only means
        // falling back to the (verified) status-file pid.
        let _ = fs::write(PID_PATH, child.id().to_string());
        let _ = fs::set_permissions(PID_PATH, fs::Permissions::from_mode(0o600));
        Ok(())
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
        // Pid sources in trust order: the root-owned file WE wrote at spawn,
        // then the daemon's status file — /Library/Ankayma (root-owned, current
        // builds) before ~/.ankayma (caller-writable, agents started by older
        // builds). Either way the pid is only signalled after is_agent_process
        // confirms the executable — the home status file is attacker-controlled
        // (caller owns it), and pids get reused, so an unverified kill is a
        // kill-as-root primitive.
        let recorded = fs::read_to_string(PID_PATH)
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok());
        let claimed = fs::read(format!("{AGENT_STATE_DIR}/agent-status.json"))
            .ok()
            .or_else(|| fs::read(format!("{home}/.ankayma/agent-status.json")).ok())
            .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
            .and_then(|v| v.get("pid").and_then(|p| p.as_u64()));
        log_line(&format!(
            "stop_agent: helper-recorded pid = {recorded:?}, status-file pid = {claimed:?}"
        ));
        let mut killed = false;
        for pid in [recorded, claimed].into_iter().flatten() {
            // pid 0 signals our own process group and pid 1 is launchd — never
            // valid agent pids regardless of what a file claims. [T:kill(2)]
            if pid <= 1 || pid > libc::pid_t::MAX as u64 {
                continue;
            }
            let pid = pid as libc::pid_t;
            if !is_agent_process(pid) {
                log_line(&format!(
                    "stop_agent: pid {pid} is not the agent binary, refusing to signal it"
                ));
                continue;
            }
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
                break;
            }
        }
        if killed {
            let _ = fs::remove_file(PID_PATH);
        } else {
            // Scoped fallback for stale pids: -U 0 restricts the match to
            // root-owned processes (the agent always runs as root) — an
            // unscoped `pkill -f 'agent up'` would kill ANY user's process
            // whose argv happens to contain the pattern.
            log_line("stop_agent: no valid recorded pid, falling back to pkill -U 0 -f 'agent up'");
            let _ = Command::new("pkill")
                .args(["-U", "0", "-f", "agent up"])
                .status();
            let _ = fs::remove_file(PID_PATH);
        }
        Ok(())
    }

    /// True iff `pid` currently runs an executable named `agent`.
    /// [T:proc_pidpath — macOS libproc; returns the executable path length]
    fn is_agent_process(pid: libc::pid_t) -> bool {
        // PROC_PIDPATHINFO_MAXSIZE (4 * MAXPATHLEN) per libproc.h.
        let mut buf = [0u8; 4096];
        let n = unsafe {
            libc::proc_pidpath(pid, buf.as_mut_ptr() as *mut libc::c_void, buf.len() as u32)
        };
        if n <= 0 {
            return false;
        }
        let path = String::from_utf8_lossy(&buf[..n as usize]).into_owned();
        std::path::Path::new(&path)
            .file_name()
            .is_some_and(|f| f == "agent")
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
        if let Ok(mut f) = open_log(LOG_PATH) {
            let _ = writeln!(f, "{msg}");
        }
    }

    #[cfg(test)]
    mod tests {
        // The kill-guard's whole point: a pid whose executable is NOT the
        // agent must never be signalled, no matter which file named it.
        #[test]
        fn own_test_process_is_not_the_agent() {
            assert!(!super::is_agent_process(std::process::id() as libc::pid_t));
        }

        #[test]
        fn launchd_is_not_the_agent() {
            assert!(!super::is_agent_process(1));
        }

        #[test]
        fn dead_pid_is_not_the_agent() {
            // pid_t::MAX is far above macOS's pid ceiling (~99999) — proc_pidpath
            // fails, so the guard refuses.
            assert!(!super::is_agent_process(libc::pid_t::MAX));
        }
    }
} // mod imp
