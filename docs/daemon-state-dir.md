# Daemon state directory — why `--state-dir`, and why `/Library/Ankayma`

**Status:** shipped (agent `--state-dir` / `ANKAYMA_STATE_DIR`; macOS helper passes
`/Library/Ankayma`). **Scope:** the privileged `agent up` daemon. The user-side CLI
(`agent ssh`) and the GUI keep their per-user state under `~/.ankayma`.

## The failure this fixes

On macOS the GUI starts the data plane through the `com.ankayma.helper`
LaunchDaemon, which spawns `agent up` as root. The agent used to resolve its state
directory as `$HOME/.ankayma`, falling back to the **relative** `./.ankayma` when
`$HOME` was unset.

Both halves of that contract are false for a launchd daemon:

- launchd does **not** populate `$HOME` (or the rest of the user environment) for
  root daemons — undocumented but confirmed behavior since macOS Catalina
  ([Apple Developer Forums thread 681550][forums-681550]).
- A launchd daemon starts with its working directory at `/`, and since Catalina the
  system volume is a **sealed, read-only** APFS volume
  ([Apple: About the read-only system volume][apple-rosv]).

So the daemon resolved its state to `/.ankayma`, failed with `Read-only file system
(os error 30)` while creating its first state file, and exited — while the GUI,
whose "Connected" state tracked control-plane enrollment, kept showing a live
connection. One machine with a working data plane and one without could show the
exact same UI.

The deeper design smell: a system daemon owned per-user files. Apple's guidance is
that daemons run in the **system context** and must not assume any user session's
environment ([Daemons and Services Programming Guide][apple-daemons]).

## Standard practice

System daemons keep their state in a **root-owned system location**, selected by an
explicit flag or unit directive — never derived from a login environment:

- The Filesystem Hierarchy Standard defines `/var/lib/<package>` as the home for
  "state information: persistent data modified by programs as they run"
  ([FHS 3.0 §5.8][fhs-varlib]).
- systemd encodes the same contract as `StateDirectory=`, which provisions
  `/var/lib/<name>` for a system service ([systemd.exec][systemd-statedir]).
- On macOS, system-wide application data belongs under the local `/Library`
  domain, not in any user's home ([File System Programming Guide][apple-library]).

The GUI is a client of the daemon; it never shares a home-directory state file
with it. That is the model this change adopts.

## Why not just set `$HOME` on the spawned agent

It would have made the symptom go away — the helper knows the caller's home — but
it re-creates a **root process writing under a user-owned directory**. That is
classic CWE-59 (improper link resolution) surface: the owning user can replace a
path component with a symlink and redirect root's writes. Real-world escalations of
exactly this shape: [CVE-2026-31979 (Himmelblau)][cve-himmelblau],
[CVE-2021-44730 (snapd)][cve-snapd]. The helper already refuses to append logs
through symlinks (`O_NOFOLLOW`) for the same reason; handing the daemon a
user-owned state dir would have reopened the class elsewhere.

## The design

### Resolution order (`agent up` only)

1. `--state-dir <dir>` / `ANKAYMA_STATE_DIR` — explicit wins. The macOS helper
   always passes `/Library/Ankayma`.
2. `$HOME/.ankayma` (`%USERPROFILE%` on Windows) — every existing install that ran
   with a real home keeps its state exactly where it already is.
3. Platform system-state directory — `/Library/Ankayma` (macOS),
   `/var/lib/ankayma` (Linux and other unix), `C:\ProgramData\Ankayma` (Windows).
   The old silent `./.ankayma` fallback is gone; the daemon also logs the resolved
   directory at startup and fails with the path in the error if it cannot create it.

Everything the daemon persists lives under this one directory: `agent.json`,
`machine.key` (only on daemon-owned enrollments, e.g. headless servers),
`agent-status.json`, `ssh-host-ed25519`, `certs/`.

### macOS layout and permissions

```
/Library/Ankayma/            root:wheel 0755
├── agent.json               0600  node identity + node service token
├── agent-status.json        0644  live data-plane snapshot (see below)
├── ssh-host-ed25519         0600  embedded SSH server host key
└── certs/                   per-FQDN TLS material for owned subdomains
```

`agent-status.json` is world-readable **on purpose**: the unprivileged GUI reads it
for the path-proof panel. It carries connection-level metadata only (hostnames,
overlay addresses, endpoints, handshake age, byte counters) — never keys, tokens,
or payload.

### Identity handoff (GUI → daemon)

The GUI enrolls as the user and keeps its own copy of the identity in
`~/.ankayma`. On Start, the enrolled `agent.json` content rides the helper IPC
request (`state_json`); the helper — already authenticating the caller by peer UID
and home-directory ownership — seeds `/Library/Ankayma/agent.json` (0600,
`O_NOFOLLOW`) and spawns the agent with `--state-dir /Library/Ankayma`.

The seed is written only when the daemon has no state yet **or the node identity
(node id + WireGuard public key) changed** — a new tenant after sign-out, or a
rotated key. Once seeded, the daemon's copy is the living one: its background
service-token renewal rewrites it, and a renewal invalidates the previous token
server-side, so blindly overwriting it with the GUI's older copy would hand the
daemon a dead credential.

Root never reads or writes anything under the caller's home.

### Migration

- Existing installs whose daemon ran with a real `$HOME` (Linux systemd with
  `User=`-style setups, manually run `sudo agent up` from a login shell) resolve to
  the same `~/.ankayma` as before — no change, no re-enroll.
- macOS GUI installs migrate transparently on the next Connect: the seed carries
  the **same** node identity the GUI already enrolled, so no duplicate node
  appears in the roster.
- Follow-up (not in this change): point the packaged Linux unit at
  `/var/lib/ankayma` via `StateDirectory=`/`Environment=ANKAYMA_STATE_DIR`, with a
  one-shot move of any existing state.

## References

- [Apple Developer Forums — Environment variables for launchctl daemons][forums-681550]
- [Apple — About the read-only system volume in macOS Catalina][apple-rosv]
- [Apple — Daemons and Services Programming Guide][apple-daemons]
- [FHS 3.0 §5.8 — `/var/lib`: variable state information][fhs-varlib]
- [systemd.exec — `StateDirectory=`][systemd-statedir]
- [Apple — File System Programming Guide: macOS library directories][apple-library]
- [MITRE — CWE-59: Improper Link Resolution Before File Access][cwe-59]
- [Akamai — CVE-2026-31979: symlink root privilege escalation in Himmelblau][cve-himmelblau]
- [SentinelOne — CVE-2021-44730: snapd privilege escalation][cve-snapd]

[forums-681550]: https://developer.apple.com/forums/thread/681550
[apple-rosv]: https://support.apple.com/en-us/101400
[apple-daemons]: https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/Introduction.html
[fhs-varlib]: https://refspecs.linuxfoundation.org/FHS_3.0/fhs/ch05s08.html
[systemd-statedir]: https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html#RuntimeDirectory=
[apple-library]: https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/MacOSXDirectories/MacOSXDirectories.html
[cwe-59]: https://cwe.mitre.org/data/definitions/59.html
[cve-himmelblau]: https://www.akamai.com/blog/security-research/cve-2026-31979-symlink-root-privilege-escalation-himmelblau
[cve-snapd]: https://www.sentinelone.com/vulnerability-database/cve-2021-44730/
