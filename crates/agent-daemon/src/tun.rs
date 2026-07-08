//! tun — OS plumbing for the WireGuard data plane: a layer-3 tunnel device.
//! OPEN, intensity **Critical** (platform `#[cfg]` + raw syscalls / Wintun API).
//!
//! Platform support:
//!   macOS  — raw PF_SYSTEM/UTUN_CONTROL socket (`utunN` device). Requires root.
//!   Linux  — /dev/net/tun + TUNSETIFF (`ankN` device). Requires CAP_NET_ADMIN.
//!   Windows — Wintun named adapter. Requires LocalSystem (service) or admin.
//!   others  — runtime error stub; daemon still compiles (A.1.9).
//!
//! The `TunDevice` type is platform-dependent: Unix targets expose a raw fd via
//! `raw_fd()`; Windows exposes a `wintun::Session` Arc via `session()`. The pump
//! threads for each platform read the right accessor. `[T:A.1.9]`

use std::io;
#[cfg(target_os = "windows")]
use std::sync::Arc;

/// A point-to-point layer-3 tunnel device.
///
/// On Unix: backed by an open fd. Read/write via `tundev::read_packet` /
/// `tundev::write_packet` (platform framing stripped/added there). `[T:A.1.9]`
///
/// On Windows: backed by a Wintun session. Read/write via the Wintun ring-buffer
/// API in `pump_wintun`. `[T:A.1.9]`
pub struct TunDevice {
    name: String,
    #[cfg(unix)]
    fd: i32,
    #[cfg(target_os = "windows")]
    session: Arc<wintun::Session>,
    /// Keep the adapter alive for the process lifetime on Windows (dropping it
    /// deletes the Wintun adapter). On Unix this field doesn't exist.
    #[cfg(target_os = "windows")]
    _adapter: wintun::Adapter,
}

impl TunDevice {
    /// Interface name, e.g. `utun4` (macOS), `ank0` (Linux), `Ankayma` (Windows).
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Raw fd — used by the Unix fd-based pump threads. `[T:A.1.9]`
    #[cfg(unix)]
    pub fn raw_fd(&self) -> i32 {
        self.fd
    }

    /// Wintun session — used by the Windows pump threads (`pump_wintun`). `[T:A.1.9]`
    #[cfg(target_os = "windows")]
    pub fn session(&self) -> Arc<wintun::Session> {
        self.session.clone()
    }
}

#[cfg(target_os = "macos")]
mod imp {
    use super::TunDevice;
    use std::io;
    use std::mem;

    // [T:Apple-XNU sys/kern_control.h] utun is a kernel control attached over a
    // PF_SYSTEM/SYSPROTO_CONTROL socket named "com.apple.net.utun_control".
    const UTUN_CONTROL_NAME: &[u8] = b"com.apple.net.utun_control";
    const UTUN_OPT_IFNAME: libc::c_int = 2; // [T:Apple-XNU net/if_utun.h]

    /// Open a fresh utun device (kernel picks the unit). Requires root.
    /// `[T:Apple-XNU net/if_utun.h]` control-socket attach sequence.
    pub fn open() -> io::Result<TunDevice> {
        // SAFETY: thin wrappers over documented BSD/XNU syscalls; every pointer
        // points at a live, correctly-sized stack value and lengths match.
        unsafe {
            let fd = libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, libc::SYSPROTO_CONTROL);
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }

            // Resolve the utun control id by name.
            let mut info: libc::ctl_info = mem::zeroed();
            for (i, b) in UTUN_CONTROL_NAME.iter().enumerate() {
                info.ctl_name[i] = *b as libc::c_char;
            }
            if libc::ioctl(fd, libc::CTLIOCGINFO, &mut info) < 0 {
                let e = io::Error::last_os_error();
                libc::close(fd);
                return Err(e);
            }

            // Connect to the control: sc_unit = 0 → kernel assigns a free utunN.
            let mut addr: libc::sockaddr_ctl = mem::zeroed();
            addr.sc_len = mem::size_of::<libc::sockaddr_ctl>() as libc::c_uchar;
            addr.sc_family = libc::AF_SYSTEM as libc::c_uchar;
            addr.ss_sysaddr = libc::AF_SYS_CONTROL as u16;
            addr.sc_id = info.ctl_id;
            addr.sc_unit = 0;
            let rc = libc::connect(
                fd,
                &addr as *const libc::sockaddr_ctl as *const libc::sockaddr,
                mem::size_of::<libc::sockaddr_ctl>() as libc::socklen_t,
            );
            if rc < 0 {
                let e = io::Error::last_os_error();
                libc::close(fd);
                return Err(e);
            }

            // Read back the assigned interface name (utunN).
            let mut name_buf = [0u8; 64];
            let mut name_len = name_buf.len() as libc::socklen_t;
            if libc::getsockopt(
                fd,
                libc::SYSPROTO_CONTROL,
                UTUN_OPT_IFNAME,
                name_buf.as_mut_ptr() as *mut libc::c_void,
                &mut name_len,
            ) < 0
            {
                let e = io::Error::last_os_error();
                libc::close(fd);
                return Err(e);
            }
            let name = String::from_utf8_lossy(&name_buf[..name_len.saturating_sub(1) as usize])
                .into_owned();

            Ok(TunDevice { fd, name })
        }
    }

    // read_packet/write_packet moved to `agent_core::tundev` (shared by the daemon
    // pump + the iOS Packet Tunnel extension). `[T:A.1.9]`
}

#[cfg(target_os = "linux")]
mod imp {
    use super::TunDevice;
    use std::ffi::CStr;
    use std::io;
    use std::mem;
    use std::os::raw::{c_char, c_short, c_void};

    // [T:linux/if_tun.h] TUNSETIFF = _IOW('T', 202, int) = 0x400454ca; flags.
    // libc::ioctl's request arg type differs by C library: glibc = c_ulong,
    // musl = c_int. Type the constant to match each so the call needs no cast
    // (the value fits i32, so both are exact). [T:libc-0.2 Ioctl per target_env]
    #[cfg(target_env = "musl")]
    const TUNSETIFF: libc::c_int = 0x4004_54ca;
    #[cfg(not(target_env = "musl"))]
    const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
    const IFF_TUN: c_short = 0x0001; // [T:linux/if_tun.h] layer-3 tun (no ethernet)
    const IFF_NO_PI: c_short = 0x1000; // [T:linux/if_tun.h] no 4-byte packet-info prefix

    // [T:linux/if.h] struct ifreq is 40 bytes: 16-byte name + a 24-byte union; we
    // only touch ifr_name + ifr_flags (a c_short at the start of the union).
    #[repr(C)]
    struct IfReq {
        ifr_name: [c_char; 16],
        ifr_flags: c_short,
        _pad: [u8; 22],
    }

    /// Open `/dev/net/tun` and create a layer-3 tun interface. `IFF_NO_PI` means
    /// read/write carry **bare IP packets** (no 4-byte framing). Requires root /
    /// `CAP_NET_ADMIN`. `[T:linux/Documentation/networking/tuntap.rst]`
    pub fn open() -> io::Result<TunDevice> {
        // SAFETY: documented Linux syscalls; pointers reference live local values.
        unsafe {
            let fd = libc::open(b"/dev/net/tun\0".as_ptr() as *const c_char, libc::O_RDWR);
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            let mut req: IfReq = mem::zeroed();
            // "ank%d" → the kernel substitutes the next free unit (ank0, ank1, …).
            for (i, b) in b"ank%d".iter().enumerate() {
                req.ifr_name[i] = *b as c_char;
            }
            req.ifr_flags = IFF_TUN | IFF_NO_PI;
            if libc::ioctl(fd, TUNSETIFF, &mut req as *mut IfReq as *mut c_void) < 0 {
                let e = io::Error::last_os_error();
                libc::close(fd);
                return Err(e);
            }
            let name = CStr::from_ptr(req.ifr_name.as_ptr())
                .to_string_lossy()
                .into_owned();
            Ok(TunDevice { fd, name })
        }
    }

    // read_packet/write_packet moved to `agent_core::tundev` (shared by the daemon
    // pump + the iOS Packet Tunnel extension). `[T:A.1.9]`
}

#[cfg(target_os = "windows")]
mod imp {
    use super::TunDevice;
    use std::io;
    use std::sync::Arc;

    const ADAPTER_NAME: &str = "Ankayma";
    const TUNNEL_TYPE: &str = "Wintun";
    // 4 MiB ring buffer — same as Tailscale's default. `[A verified-on-windows]`
    const RING_CAPACITY: u32 = 0x400000;

    /// Open (or create) the Wintun adapter and start a session.
    ///
    /// Requires the service to run as LocalSystem (or admin) so the Wintun driver
    /// can install the virtual NIC. `wintun.dll` must reside in the same directory
    /// as the service executable (placed there by the installer). `[T:wintun.net]`
    ///
    /// `[A verified-on-windows]` — tested integration needed on a real Windows host.
    pub fn open() -> io::Result<TunDevice> {
        // Load wintun.dll from the directory of the running executable.
        // The installer places it there alongside ankayma-service.exe and agent.exe.
        let lib = unsafe { wintun::load_from_path("wintun.dll") }.map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("load wintun.dll: {e} — ensure wintun.dll is in the install dir"),
            )
        })?;

        // Try to open an existing adapter first (idempotent across service restarts);
        // create a new one if it doesn't exist yet. Wintun adapters persist in the
        // registry between reboots if not explicitly deleted. `[T:wintun.net]`
        let adapter = wintun::Adapter::open(&lib, ADAPTER_NAME)
            .or_else(|_| wintun::Adapter::create(&lib, ADAPTER_NAME, TUNNEL_TYPE, None))
            .map_err(|e| {
                io::Error::new(io::ErrorKind::Other, format!("Wintun adapter: {e}"))
            })?;

        let session = adapter.start_session(RING_CAPACITY).map_err(|e| {
            io::Error::new(io::ErrorKind::Other, format!("Wintun start_session: {e}"))
        })?;

        Ok(TunDevice {
            name: ADAPTER_NAME.to_string(),
            session: Arc::new(session),
            _adapter: adapter,
        })
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
mod imp {
    use super::TunDevice;
    use std::io;

    pub fn open() -> io::Result<TunDevice> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "kernel tun data plane is implemented for macOS, Linux, and Windows [T:A.1.9]",
        ))
    }
}

/// Open a fresh layer-3 tunnel device (root/SYSTEM required).
pub fn open() -> io::Result<TunDevice> {
    imp::open()
}
