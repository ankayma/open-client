//! tundev — fd-level packet I/O for the layer-3 tunnel device. OPEN, intensity
//! **Critical** (platform `#[cfg]` + raw read/write syscalls).
//!
//! This is the plumbing over an **already-open** tun fd: the OS-specific framing
//! for reading/writing bare IP packets. *Creating* the device stays with the host
//! that can: agent-daemon opens utun (macOS) or `/dev/net/tun` (Linux). On iOS the
//! fd is handed to us by the Network Extension's `packetFlow` (a utun fd — same
//! 4-byte address-family framing as macOS), so **iOS shares the macOS impl**. That
//! split is exactly why this lives in agent-core (the OPEN lib): the iOS Packet
//! Tunnel extension reuses the same pump without depending on the daemon binary.
//! `[T:A.1.9]`

use std::io;

/// Read one bare IP packet from the tunnel fd (framing stripped per platform).
pub fn read_packet(fd: i32, buf: &mut [u8]) -> io::Result<usize> {
    imp::read_packet(fd, buf)
}

/// Write one bare IP packet to the tunnel fd (framing added per platform).
pub fn write_packet(fd: i32, packet: &[u8]) -> io::Result<usize> {
    imp::write_packet(fd, packet)
}

// macOS + iOS: utun prepends a 4-byte address-family header. Both get the fd as a
// utun device (iOS via the extension's tunnelFileDescriptor), so framing is
// identical. `[T:Apple-XNU net/if_utun.h]`
#[cfg(any(target_os = "macos", target_os = "ios"))]
mod imp {
    use std::io;

    /// Read one IP packet, stripping the 4-byte AF header utun prepends (big-endian).
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

// Linux + Android: IFF_NO_PI / VpnService → bare IP packets, no framing.
#[cfg(any(target_os = "linux", target_os = "android"))]
mod imp {
    use std::io;
    use std::os::raw::c_void;

    pub fn read_packet(fd: i32, buf: &mut [u8]) -> io::Result<usize> {
        // SAFETY: read into a valid local buffer with its real length.
        let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut c_void, buf.len()) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(n as usize)
    }

    pub fn write_packet(fd: i32, packet: &[u8]) -> io::Result<usize> {
        // SAFETY: write from a valid local buffer with its real length.
        let n = unsafe { libc::write(fd, packet.as_ptr() as *const c_void, packet.len()) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(n as usize)
    }
}

// Windows et al.: no tun fd plumbing yet — error at runtime, still compile
// (A.1.9). `[T:A.1.9]`
#[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "linux", target_os = "android")))]
mod imp {
    use std::io;

    pub fn read_packet(_fd: i32, _buf: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "no tun fd plumbing on this platform",
        ))
    }
    pub fn write_packet(_fd: i32, _packet: &[u8]) -> io::Result<usize> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "no tun fd plumbing on this platform",
        ))
    }
}
