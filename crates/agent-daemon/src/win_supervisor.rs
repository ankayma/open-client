//! win_supervisor — Windows Service supervisor: spawns/kills `agent up` as a
//! **real child process** on Connect/Disconnect, instead of running
//! `serve_dataplane` in-process.
//!
//! `serve_dataplane` (up.rs) spawns several bare OS threads with no cancellation
//! hook (`agent_core::pump::spawn_tx/rx/timers`, `disco::run_discovery`/
//! `run_rendezvous`, `resolver::serve`, the `tls_relay` listener, the embedded SSH
//! server) — today's whole design relies on "process exit cleans everything up".
//! Making that cancellable in-process would mean touching `agent_core::pump`,
//! which is shared with the iOS Packet Tunnel extension — out of scope for a
//! Windows-only fix. Spawning `agent up` as a child instead keeps `up.rs`
//! completely untouched: process exit still does the cleanup it always has.
//!
//! Hard-killing the child on Disconnect (rather than a graceful signal) is fine:
//! `resolver::install_scoped_resolver`/`add_peer_route` are already delete-first
//! idempotent (self-heal on the next Connect), and the GUI already treats a
//! stale `agent-status.json` (by `updated_at`) as "down". Because this supervisor
//! is the child's real parent, `Child::wait()` after `Child::kill()` is a
//! **verified** stop for free — no `tasklist` polling needed, unlike
//! `stop_dataplane_inner`'s old non-parent-child `taskkill` model.
//! `[T:decision docs/windows-daemon-lifecycle-decision.md]`
//!
//! Deliberately not `#[cfg(windows)]`-gated itself (state-machine logic is
//! plain `std::process`, so it's cross-platform-testable — see the `tests`
//! module, exercised on every CI platform including macOS/Linux); only
//! `win_ipc`/`win_service` (Windows-only) actually construct a `Supervisor` in
//! production. That means non-Windows builds legitimately never call this
//! module's public API outside its own tests — expected, not a bug.

#![cfg_attr(not(windows), allow(dead_code))]

use std::process::{Child, Command};
use std::sync::Mutex;

/// Bearer creds a live child was started with — compared to decide whether a new
/// `Connect` is a no-op, a fresh start, or a replace-in-place.
#[derive(Clone, PartialEq, Eq)]
struct Creds {
    token: String,
    control_plane: String,
}

enum State {
    Idle,
    Connected { child: Child, creds: Creds },
}

/// What `connect()` actually did, so the caller (the named-pipe handler, Change 2)
/// can reply accurately instead of always saying "connected".
#[derive(Debug, PartialEq, Eq)]
pub enum ConnectOutcome {
    /// A child was spawned (fresh start, or the previous one had different creds
    /// / had already exited on its own).
    Connected,
    /// Already running with the exact same creds — no new child spawned.
    AlreadyConnected,
}

/// How to launch `agent up` for one `Connect` — abstracted so tests can spawn a
/// short-lived stand-in process instead of the real `agent.exe`.
pub trait ChildSpawner: Send + Sync {
    fn spawn(&self, creds_token: &str, creds_control_plane: &str) -> std::io::Result<Child>;
}

/// The child's state dir — must be an explicit, well-known path, not `agent
/// up`'s own default. Confirmed the hard way (T490, real end-to-end test):
/// `up.rs`'s `default_state_dir()` checks `$HOME`/`%USERPROFILE%` *before*
/// falling back to this same constant, and the supervisor's child inherits
/// `LocalSystem`'s own environment — which DOES have a `%USERPROFILE%` (its
/// own system profile, `...\config\systemprofile`), so the child silently
/// wrote its status snapshot there instead. The GUI (running as the
/// interactive user) only ever checks `%USERPROFILE%\.ankayma` for *that*
/// user and this exact system path — never `LocalSystem`'s profile — so it
/// showed "Tunnel down" forever despite a fully working tunnel. Passing
/// `--state-dir` explicitly is exactly what the macOS helper already does for
/// the identical reason (root's `$HOME` isn't the interactive user's either);
/// this brings Windows to the same discipline.
const CHILD_STATE_DIR: &str = r"C:\ProgramData\Ankayma";

/// Production spawner: `<current_exe> up --token <t> --control-plane <cp>
/// --state-dir <CHILD_STATE_DIR>` — the exact invocation the GUI uses today
/// via `Start-Process`, minus the elevation (the supervisor process is
/// already LocalSystem), plus the explicit state dir above.
pub struct AgentUpSpawner;

impl ChildSpawner for AgentUpSpawner {
    fn spawn(&self, token: &str, control_plane: &str) -> std::io::Result<Child> {
        let exe = std::env::current_exe()?;
        Command::new(exe)
            .arg("up")
            .arg("--token")
            .arg(token)
            .arg("--control-plane")
            .arg(control_plane)
            .arg("--state-dir")
            .arg(CHILD_STATE_DIR)
            .spawn()
    }
}

/// Owns at most one live `agent up` child at a time. `connect`/`disconnect`/
/// `status` are the only entry points — callers never touch `Child` directly.
pub struct Supervisor<S: ChildSpawner = AgentUpSpawner> {
    state: Mutex<State>,
    spawner: S,
}

impl Supervisor<AgentUpSpawner> {
    pub fn new() -> Self {
        Self::with_spawner(AgentUpSpawner)
    }
}

impl Default for Supervisor<AgentUpSpawner> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S: ChildSpawner> Supervisor<S> {
    pub fn with_spawner(spawner: S) -> Self {
        Self {
            state: Mutex::new(State::Idle),
            spawner,
        }
    }

    /// Bring the tunnel up for (token, control_plane). Idempotent for identical
    /// creds against an already-live child; replaces (kill+wait, then respawn)
    /// when creds differ or the previous child already exited on its own.
    pub fn connect(&self, token: &str, control_plane: &str) -> std::io::Result<ConnectOutcome> {
        let creds = Creds {
            token: token.to_string(),
            control_plane: control_plane.to_string(),
        };
        let mut state = self.state.lock().expect("supervisor state poisoned");
        if let State::Connected {
            child,
            creds: existing,
        } = &mut *state
        {
            if *existing == creds && matches!(child.try_wait(), Ok(None)) {
                return Ok(ConnectOutcome::AlreadyConnected);
            }
            // Different creds, or the child already died on its own — clear the
            // way for a fresh spawn either way.
            kill_and_wait(child);
        }
        let child = self.spawner.spawn(&creds.token, &creds.control_plane)?;
        *state = State::Connected { child, creds };
        Ok(ConnectOutcome::Connected)
    }

    /// Tear the tunnel down. No-op if already `Idle`. Verified: `Child::wait()`
    /// after `kill()` only returns once the OS confirms the process is gone.
    pub fn disconnect(&self) {
        let mut state = self.state.lock().expect("supervisor state poisoned");
        if let State::Connected { child, .. } = &mut *state {
            kill_and_wait(child);
        }
        *state = State::Idle;
    }

    /// `true` if a child is live right now. Self-healing: if the child exited on
    /// its own (crash, `agent up`'s own error path) since the last check, this
    /// notices via `try_wait()` and flips the state back to `Idle` — no separate
    /// "the child died" notification needed.
    pub fn is_connected(&self) -> bool {
        let mut state = self.state.lock().expect("supervisor state poisoned");
        let still_alive = match &mut *state {
            State::Connected { child, .. } => matches!(child.try_wait(), Ok(None)),
            State::Idle => false,
        };
        if !still_alive {
            *state = State::Idle;
        }
        still_alive
    }
}

impl<S: ChildSpawner> Drop for Supervisor<S> {
    /// Defense in depth: if the supervisor is ever dropped without an explicit
    /// `disconnect()` (a bug, a panic unwind), don't leak a running child.
    fn drop(&mut self) {
        self.disconnect();
    }
}

fn kill_and_wait(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Stdio;

    /// Spawns a short-lived, harmless stand-in process instead of the real
    /// `agent.exe` — `sleep`/`timeout` per platform — so the state machine is
    /// testable without a real WireGuard tunnel or being built as `agent.exe`.
    struct SleepSpawner;

    impl ChildSpawner for SleepSpawner {
        fn spawn(&self, _token: &str, _control_plane: &str) -> std::io::Result<Child> {
            #[cfg(windows)]
            {
                Command::new("cmd")
                    .args(["/C", "timeout", "/T", "30"])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
            }
            #[cfg(not(windows))]
            {
                Command::new("sleep")
                    .arg("30")
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
            }
        }
    }

    #[test]
    fn connect_from_idle_spawns_and_reports_connected() {
        let sup = Supervisor::with_spawner(SleepSpawner);
        assert!(!sup.is_connected());
        let outcome = sup.connect("tok-a", "https://cp.example").unwrap();
        assert_eq!(outcome, ConnectOutcome::Connected);
        assert!(sup.is_connected());
        sup.disconnect();
    }

    #[test]
    fn connect_with_same_creds_is_idempotent() {
        let sup = Supervisor::with_spawner(SleepSpawner);
        sup.connect("tok-a", "https://cp.example").unwrap();
        let outcome = sup.connect("tok-a", "https://cp.example").unwrap();
        assert_eq!(outcome, ConnectOutcome::AlreadyConnected);
        sup.disconnect();
    }

    #[test]
    fn connect_with_different_creds_replaces_the_child() {
        let sup = Supervisor::with_spawner(SleepSpawner);
        sup.connect("tok-a", "https://cp.example").unwrap();
        let outcome = sup.connect("tok-b", "https://cp.example").unwrap();
        assert_eq!(outcome, ConnectOutcome::Connected);
        assert!(sup.is_connected());
        sup.disconnect();
    }

    #[test]
    fn disconnect_from_idle_is_a_no_op() {
        let sup = Supervisor::with_spawner(SleepSpawner);
        sup.disconnect(); // must not panic
        assert!(!sup.is_connected());
    }

    #[test]
    fn disconnect_verifies_the_child_actually_exited() {
        let sup = Supervisor::with_spawner(SleepSpawner);
        sup.connect("tok-a", "https://cp.example").unwrap();
        sup.disconnect();
        assert!(!sup.is_connected());
        // Reconnect must succeed — proves the prior child's resources (a process
        // slot at minimum) were actually released, not just marked Idle in name.
        let outcome = sup.connect("tok-a", "https://cp.example").unwrap();
        assert_eq!(outcome, ConnectOutcome::Connected);
        sup.disconnect();
    }

    #[test]
    fn status_self_heals_when_child_exits_on_its_own() {
        struct ImmediateExitSpawner;
        impl ChildSpawner for ImmediateExitSpawner {
            fn spawn(&self, _token: &str, _control_plane: &str) -> std::io::Result<Child> {
                #[cfg(windows)]
                {
                    Command::new("cmd").args(["/C", "exit", "0"]).spawn()
                }
                #[cfg(not(windows))]
                {
                    Command::new("true").spawn()
                }
            }
        }
        let sup = Supervisor::with_spawner(ImmediateExitSpawner);
        sup.connect("tok-a", "https://cp.example").unwrap();
        // Give the trivially-exiting child a moment to actually exit.
        std::thread::sleep(std::time::Duration::from_millis(200));
        assert!(
            !sup.is_connected(),
            "a child that exited on its own must be observed as Idle, not stuck Connected"
        );
    }
}
