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

/// A handle to the OPEN tunnel device the pump drives. macOS/iOS/Linux/Android all
/// hand us a POSIX fd (same read/write, per-platform framing); Windows' Wintun gives
/// a *session* (a ring buffer + a ready event), NEVER a POSIX fd. This enum is the
/// abstraction that lets `pump::spawn_tx`/`spawn_rx` (and the DNS-reply path) drive
/// either kind without the old `fd: i32` assumption. Clone is cheap — `Fd` is Copy,
/// `Wintun` is an `Arc` — so tx, rx, and the DNS path can each hold one.
/// [T:gate A.0-a refactor; part-d-client-platform-architecture.md §H.8.1]
#[derive(Clone)]
pub enum TunHandle {
    /// POSIX tunnel fd — utun (macOS/iOS), `/dev/net/tun` (Linux), or the Android
    /// `VpnService` ParcelFileDescriptor. Read/write go through the `imp` framing.
    Fd(i32),
    /// Windows: a Wintun session, shared (`Arc`) across the pump threads.
    #[cfg(target_os = "windows")]
    Wintun(std::sync::Arc<wintun::Session>),
}

impl TunHandle {
    /// Read one bare IP packet (framing stripped per platform).
    pub fn read_packet(&self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            TunHandle::Fd(fd) => imp::read_packet(*fd, buf),
            #[cfg(target_os = "windows")]
            TunHandle::Wintun(sess) => win::read_packet(sess, buf),
        }
    }

    /// Write one bare IP packet (framing added per platform).
    pub fn write_packet(&self, packet: &[u8]) -> io::Result<usize> {
        match self {
            TunHandle::Fd(fd) => imp::write_packet(*fd, packet),
            #[cfg(target_os = "windows")]
            TunHandle::Wintun(sess) => win::write_packet(sess, packet),
        }
    }
}

// macOS + iOS: utun prepends a 4-byte address-family header. Both get the fd as a
// utun device (iOS via the extension's tunnelFileDescriptor), so framing is
// identical. `[T:Apple-XNU net/if_utun.h]`
//
// The fd may be NON-BLOCKING: the iOS `packetFlow` fd is managed by Apple's own
// dispatch machinery and read() returns EAGAIN the moment the queued packets are
// drained. Treating that as a fatal error killed the pump's tun-read thread right
// after the first packet on-device (2026-07-03: exactly one `tun→pkt` line per
// connect, then silence, while mDNSResponder kept retrying queries into utun5) —
// which looked exactly like "iOS stops routing DNS to us". The reference stack
// keeps the fd non-blocking and WAITS for readiness instead (wireguard-go wraps
// the same stolen fd in os.File → Go netpoller polls it
// `[T:wireguard-go tun/tun_darwin.go — CreateTUNFromFile]`). We do the same with
// poll(2): EAGAIN/EWOULDBLOCK → poll for readiness → retry; EINTR → retry.
// `[T:poll(2); POSIX read(2) EAGAIN on O_NONBLOCK]`
#[cfg(any(target_os = "macos", target_os = "ios"))]
mod imp {
    use std::io;

    /// Block until `fd` is ready for `events` (POLLIN/POLLOUT). Infinite timeout —
    /// each pump loop owns a dedicated thread. EINTR retries.
    fn wait_ready(fd: i32, events: libc::c_short) -> io::Result<()> {
        loop {
            let mut pfd = libc::pollfd {
                fd,
                events,
                revents: 0,
            };
            // SAFETY: one valid pollfd, count 1, blocking indefinitely.
            let r = unsafe { libc::poll(&mut pfd, 1, -1) };
            if r >= 0 {
                return Ok(());
            }
            let e = io::Error::last_os_error();
            if e.kind() != io::ErrorKind::Interrupted {
                return Err(e);
            }
        }
    }

    /// Read one IP packet, stripping the 4-byte AF header utun prepends (big-endian).
    /// Blocking semantics regardless of the fd's O_NONBLOCK flag (poll-and-retry).
    pub fn read_packet(fd: i32, buf: &mut [u8]) -> io::Result<usize> {
        let mut framed = [0u8; 2048];
        loop {
            // SAFETY: read into a valid local buffer with a correct length.
            let n = unsafe {
                libc::read(
                    fd,
                    framed.as_mut_ptr() as *mut libc::c_void,
                    framed.len().min(buf.len() + 4),
                )
            };
            if n >= 0 {
                let n = n as usize;
                if n < 4 {
                    return Ok(0);
                }
                let payload = &framed[4..n];
                buf[..payload.len()].copy_from_slice(payload);
                return Ok(payload.len());
            }
            let e = io::Error::last_os_error();
            match e.kind() {
                io::ErrorKind::Interrupted => continue, // EINTR — retry
                io::ErrorKind::WouldBlock => wait_ready(fd, libc::POLLIN)?, // EAGAIN — wait
                _ => return Err(e),
            }
        }
    }

    /// Write one bare IP packet, prepending the 4-byte AF header utun expects —
    /// AF_INET or AF_INET6 by the packet's version nibble. Getting this wrong is
    /// silent: the kernel drops the mis-framed packet, the interface counts no
    /// input, and the sender sees 100% loss (2026-07-03 incident — the overlay is
    /// IPv6 ULA, but every inbound packet was framed AF_INET). `[T:Apple-XNU net/if_utun.h]`
    /// Same poll-and-retry as `read_packet` for a non-blocking fd.
    pub fn write_packet(fd: i32, packet: &[u8]) -> io::Result<usize> {
        let af = match packet.first().map(|b| b >> 4) {
            Some(6) => libc::AF_INET6,
            _ => libc::AF_INET,
        };
        let mut framed = Vec::with_capacity(packet.len() + 4);
        framed.extend_from_slice(&(af as u32).to_be_bytes()); // [T:Apple-XNU] AF in network order
        framed.extend_from_slice(packet);
        loop {
            // SAFETY: write from a valid local buffer with a correct length.
            let n =
                unsafe { libc::write(fd, framed.as_ptr() as *const libc::c_void, framed.len()) };
            if n >= 0 {
                return Ok(n as usize);
            }
            let e = io::Error::last_os_error();
            match e.kind() {
                io::ErrorKind::Interrupted => continue, // EINTR — retry
                io::ErrorKind::WouldBlock => wait_ready(fd, libc::POLLOUT)?, // EAGAIN — wait
                _ => return Err(e),
            }
        }
    }
}

// Linux: IFF_NO_PI → read/write carry bare IP packets, no framing.
#[cfg(target_os = "linux")]
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

// The EAGAIN/poll path is exactly what a non-blocking iOS packetFlow fd exercises;
// pipes give the same read/write + O_NONBLOCK semantics without needing a utun.
#[cfg(all(test, any(target_os = "macos", target_os = "ios")))]
mod tests {
    use super::*;

    /// A non-blocking pipe: read side must NOT kill the reader with WouldBlock —
    /// `read_packet` waits via poll(2) and returns the packet written later. This
    /// is the on-device failure of 2026-07-03 (tun-read thread died on the first
    /// EAGAIN from the packetFlow fd) pinned as a unit test.
    #[test]
    fn read_packet_survives_eagain_on_nonblocking_fd() {
        let mut fds = [0i32; 2];
        // SAFETY: valid 2-int array for pipe(2).
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let (rfd, wfd) = (fds[0], fds[1]);
        // SAFETY: valid fd; set O_NONBLOCK like the iOS packetFlow fd.
        unsafe {
            let fl = libc::fcntl(rfd, libc::F_GETFL);
            assert_eq!(libc::fcntl(rfd, libc::F_SETFL, fl | libc::O_NONBLOCK), 0);
        }

        let reader = std::thread::spawn(move || {
            let mut buf = [0u8; 128];
            read_packet(rfd, &mut buf).map(|n| buf[..n].to_vec())
        });
        // Give the reader time to hit EAGAIN and park in poll before data arrives.
        std::thread::sleep(std::time::Duration::from_millis(50));
        let framed: &[u8] = &[0, 0, 0, 2, 0x45, 0xAA, 0xBB]; // AF_INET + 3 payload bytes
                                                             // SAFETY: write from a valid local buffer with its real length.
        let w = unsafe { libc::write(wfd, framed.as_ptr() as *const libc::c_void, framed.len()) };
        assert_eq!(w, framed.len() as isize);

        let got = reader
            .join()
            .unwrap()
            .expect("read after EAGAIN must succeed");
        assert_eq!(
            got,
            vec![0x45, 0xAA, 0xBB],
            "AF header stripped, payload intact"
        );
        // SAFETY: fds owned by this test.
        unsafe {
            libc::close(rfd);
            libc::close(wfd);
        }
    }
}

// Windows/Android et al.: no tun fd plumbing yet — error at runtime, still compile
// (A.1.9). `[T:A.1.9]`
#[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "linux")))]
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

// Windows: Wintun session I/O. Wintun is an NDIS L3 adapter with a ring buffer;
// packets are BARE IP (no framing, like Linux IFF_NO_PI). receive_blocking() /
// allocate_send_packet() take `&Arc<Session>`, which is exactly what TunHandle::Wintun
// holds — so the pump's read/write map straight onto them. [T:wintun@0.5; §H.6]
#[cfg(target_os = "windows")]
mod win {
    use std::io;
    use std::sync::Arc;

    /// Block until Wintun has a packet, copy the bare IP bytes out. Mirrors the utun
    /// poll-and-return contract the pump expects.
    pub fn read_packet(sess: &Arc<wintun::Session>, buf: &mut [u8]) -> io::Result<usize> {
        match sess.receive_blocking() {
            Ok(packet) => {
                let bytes = packet.bytes();
                let n = bytes.len().min(buf.len());
                buf[..n].copy_from_slice(&bytes[..n]);
                Ok(n)
            }
            Err(e) => Err(io::Error::other(format!("wintun receive: {e}"))),
        }
    }

    /// Allocate a send packet from the ring, copy the bare IP bytes in, send it.
    pub fn write_packet(sess: &Arc<wintun::Session>, packet: &[u8]) -> io::Result<usize> {
        let len = packet.len();
        match sess.allocate_send_packet(len as u16) {
            Ok(mut send) => {
                send.bytes_mut().copy_from_slice(packet);
                sess.send_packet(send);
                Ok(len)
            }
            Err(e) => Err(io::Error::other(format!("wintun allocate_send: {e}"))),
        }
    }
}
