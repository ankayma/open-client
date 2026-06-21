//! tun — OS plumbing for the WireGuard data plane: a layer-3 utun device.
//! OPEN, intensity **Critical** (platform `#[cfg]` + raw syscalls).
//!
//! macOS only for now (milestone-1.1 demo target). Other platforms compile to a
//! stub that returns an error at runtime, so the daemon still builds on all 5
//! targets (A.1.9). `[T:A.1.9]` Linux/Windows/iOS/Android utun adapters land later.

use std::io;

/// A point-to-point layer-3 tunnel device. Read/write carry **bare IP packets**
/// (the platform 4-byte framing is added/stripped inside this module).
pub struct TunDevice {
    fd: i32,
    name: String,
}

impl TunDevice {
    /// Interface name, e.g. `utun4`.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Raw fd — read/write happen from separate threads (one reads, one writes),
    /// which is safe on a single utun fd.
    pub fn raw_fd(&self) -> i32 {
        self.fd
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

    /// Read one IP packet, stripping the 4-byte address-family header utun
    /// prepends. `[T:Apple-XNU net/if_utun.h]` framing = 4-byte AF (big-endian).
    pub fn read_packet(fd: i32, buf: &mut [u8]) -> io::Result<usize> {
        let mut framed = [0u8; 2048];
        // SAFETY: read into a valid local buffer with a correct length.
        let n = unsafe {
            libc::read(
                fd,
                framed.as_mut_ptr() as *mut libc::c_void,
                framed.len().min(buf.len() + 4),
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        let n = n as usize;
        if n < 4 {
            return Ok(0);
        }
        let payload = &framed[4..n];
        buf[..payload.len()].copy_from_slice(payload);
        Ok(payload.len())
    }

    /// Write one IPv4 packet, prepending the 4-byte AF_INET header utun expects.
    pub fn write_packet(fd: i32, packet: &[u8]) -> io::Result<usize> {
        let mut framed = Vec::with_capacity(packet.len() + 4);
        framed.extend_from_slice(&(libc::AF_INET as u32).to_be_bytes()); // [T:Apple-XNU] AF in network order
        framed.extend_from_slice(packet);
        // SAFETY: write from a valid local buffer with a correct length.
        let n = unsafe { libc::write(fd, framed.as_ptr() as *const libc::c_void, framed.len()) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(n as usize)
    }
}

#[cfg(target_os = "linux")]
mod imp {
    use super::TunDevice;
    use std::ffi::CStr;
    use std::io;
    use std::mem;
    use std::os::raw::{c_char, c_short, c_void};

    // [T:linux/if_tun.h] TUNSETIFF = _IOW('T', 202, int) = 0x400454ca; flags.
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

    /// Read one bare IP packet (IFF_NO_PI → no framing to strip).
    pub fn read_packet(fd: i32, buf: &mut [u8]) -> io::Result<usize> {
        // SAFETY: read into a valid local buffer with its real length.
        let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut c_void, buf.len()) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(n as usize)
    }

    /// Write one bare IP packet (works for IPv4 and IPv6 — the kernel reads the
    /// version nibble; IFF_NO_PI means no AF prefix is needed).
    pub fn write_packet(fd: i32, packet: &[u8]) -> io::Result<usize> {
        // SAFETY: write from a valid local buffer with its real length.
        let n = unsafe { libc::write(fd, packet.as_ptr() as *const c_void, packet.len()) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(n as usize)
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
mod imp {
    use super::TunDevice;
    use std::io;

    pub fn open() -> io::Result<TunDevice> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "kernel tun data plane is implemented for macOS + Linux [T:A.1.9]",
        ))
    }
    pub fn read_packet(_fd: i32, _buf: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "no tun device on this platform",
        ))
    }
    pub fn write_packet(_fd: i32, _packet: &[u8]) -> io::Result<usize> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "no tun device on this platform",
        ))
    }
}

/// Open a fresh layer-3 tunnel device (root required on macOS).
pub fn open() -> io::Result<TunDevice> {
    imp::open()
}

/// Read one bare IP packet from the device.
pub fn read_packet(fd: i32, buf: &mut [u8]) -> io::Result<usize> {
    imp::read_packet(fd, buf)
}

/// Write one bare IPv4 packet to the device.
pub fn write_packet(fd: i32, packet: &[u8]) -> io::Result<usize> {
    imp::write_packet(fd, packet)
}
