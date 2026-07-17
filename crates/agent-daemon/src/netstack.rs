//! netstack — userspace TCP/IP data plane for `agent ci-deploy` on hosted CI
//! runners. OPEN, intensity **Critical** (raw packet plumbing + WireGuard).
//!
//! A SaaS CI runner (GitHub/GitLab hosted) is an unprivileged container: no
//! `/dev/net/tun`, no `CAP_NET_ADMIN`, so the kernel-TUN data plane in `tun.rs`
//! cannot run there. This module carries the deploy's TCP traffic over the *same*
//! boringtun WireGuard tunnel using a **userspace** TCP/IP stack (smoltcp),
//! exposed to the deploy command as a local SOCKS5 proxy. No kernel TUN, no root —
//! so `agent ci-deploy` runs in a hosted CI container. `[T:Part C §H.3.3 B-3]`
//! `[T:R3 #12]` This is the slice Part C left `[A]` ("transport userspace + NAT").
//!
//! Data path:
//!   deploy.sh → SOCKS5 (127.0.0.1) → smoltcp TCP socket → inner IP packet →
//!   boringtun encapsulate → UDP → target ;  reverse on the way back.
//!
//! Crypto is unchanged (the same `Tunn` as the kernel path, A.1.4); only the OS
//! plumbing differs — kernel utun replaced by an in-process smoltcp interface.

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::Arc;
use std::time::Duration;

use agent_core::domain::PeerInfo;
use agent_core::tunnel::{make_tunn, PublicKey, StaticSecret, Tunn, TunnResult};
use anyhow::{anyhow, bail, Context, Result};

use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::phy::{self, Device, DeviceCapabilities, Medium};
use smoltcp::socket::tcp;
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint};

use crate::up::AgentState;

/// Inner overlay MTU — conservative so a full inner packet + WireGuard overhead
/// still fits under a 1500-byte path. `[T:WireGuard]`
const MTU: usize = 1380;
/// Per-socket buffer; ssh/rsync are throughput-friendly with 64 KiB windows.
const SOCK_BUF: usize = 64 * 1024;
/// Poll cadence for the single-threaded smoltcp engine. `[A] verify: deploy
/// throughput is fine at this tick; lower it if rsync feels slow over the tunnel.`
const TICK: Duration = Duration::from_millis(3);
/// How long to let a freshly-built ci-deploy tunnel settle before running the deploy
/// command. This wait is UNCONDITIONAL — ⚠️ DO NOT "optimize" it to proceed the moment
/// the WireGuard handshake completes.
///
/// That exact optimization (commit 2f44d6b, 2026-07-04) BROKE every ci-deploy:
/// `handshake_established()` turns true when the *initiator* (this runner) receives the
/// handshake response (~0.3s), but the userspace tunnel is not yet carrying data BOTH
/// ways at that instant — the runner's first TCP SYN never reaches the target's embedded
/// SSH, and the deploy hangs to the 1h job timeout. Empirically confirmed 2026-07-15: a
/// steady kernel-path peer connects to the same target:22022 fine (ping 0% loss, TCP OK),
/// while a proceed-at-0.3s ci-deploy to the same node hangs. The last green deploy
/// (2026-06-30, commit 3db1443) used this full unconditional settle. Keep it that way;
/// if you want it faster, gate on "received a data packet back from the peer", not on the
/// handshake flag alone. `[T: regression 2f44d6b, reverted 2026-07-15]`
const HANDSHAKE_SETTLE: Duration = Duration::from_secs(8);

/// A SOCKS5-accepted local connection handed to the engine to bridge over the
/// tunnel: the requested overlay destination + the local client stream.
struct PendingConn {
    dst: IpEndpoint,
    stream: TcpStream,
}

/// Run a secretless deploy from a hosted CI runner: bring up the userspace tunnel
/// to `target`, expose a SOCKS5 proxy, run `exec` (which reaches the target via the
/// proxy), then tear down. Blocking — call from `spawn_blocking`. `[T:Part C §H.3.3]`
pub fn run_deploy(state: &AgentState, target: PeerInfo, exec: Option<Vec<String>>) -> Result<()> {
    // Resolve the target's reachable bits.
    let target_endpoint: SocketAddr = target
        .endpoint
        .as_deref()
        .ok_or_else(|| anyhow!("deploy target has no reachable endpoint from the control plane"))?
        .parse()
        .with_context(|| format!("parse target endpoint {:?}", target.endpoint))?;
    let target_overlay: IpAddr = target
        .overlay_ip
        .parse()
        .with_context(|| format!("parse target overlay ip {}", target.overlay_ip))?;
    let target_pub_bytes = agent_core::key_bytes_from_b64(&target.public_key)
        .map_err(|e| anyhow!("target public key invalid: {e:?}"))?;
    let self_overlay: IpAddr = state
        .overlay_ip
        .parse()
        .with_context(|| format!("parse our overlay ip {}", state.overlay_ip))?;
    let private_bytes = agent_core::key_bytes_from_b64(&state.private_b64)
        .map_err(|e| anyhow!("our private key invalid: {e:?}"))?;

    // UDP socket for the encrypted WireGuard traffic. Ephemeral source port — the
    // target learns our endpoint from the handshake (we are behind the runner's
    // NAT; boringtun roaming handles the reply path). `[T:WireGuard]`
    let udp = UdpSocket::bind(("0.0.0.0", 0)).context("bind udp socket for tunnel")?;
    udp.set_nonblocking(true).context("set udp nonblocking")?;
    let udp = Arc::new(udp);

    // boringtun tunnel toward the single target peer (sender index 1).
    let static_private = StaticSecret::from(private_bytes);
    let peer_pub = PublicKey::from(target_pub_bytes);
    // Keepalive 25s: the CI runner always sits behind the runner's NAT, and a
    // deploy can go quiet >60s (build steps) before pushing again — keep the
    // mapping alive for the session's short life. `[T:wireguard.com/quickstart]`
    let tunn = make_tunn(static_private, peer_pub, 1, Some(25));

    // SOCKS5 listener on loopback; the deploy command points at this.
    let socks = TcpListener::bind(("127.0.0.1", 0)).context("bind SOCKS5 listener")?;
    let socks_addr = socks.local_addr().context("read SOCKS5 listen addr")?;

    let running = Arc::new(AtomicBool::new(true));
    let (conn_tx, conn_rx) = mpsc::channel::<PendingConn>();

    // SOCKS5 accept thread → hands accepted connections to the engine.
    let accept_handle = {
        let running = running.clone();
        let conn_tx = conn_tx.clone();
        std::thread::spawn(move || socks_accept_loop(socks, conn_tx, running))
    };

    // Engine thread: owns smoltcp + boringtun + the UDP socket; runs the poll loop.
    // `handshake_done` is set by the engine when the Noise handshake completes.
    let handshake_done = Arc::new(AtomicBool::new(false));
    let engine_handle = {
        let udp = udp.clone();
        let running = running.clone();
        let handshake_done = handshake_done.clone();
        std::thread::spawn(move || {
            engine_loop(
                udp,
                tunn,
                target_endpoint,
                self_overlay,
                target_overlay,
                conn_rx,
                running,
                handshake_done,
            )
        })
    };

    // Wait the FULL settle window, unconditionally — see HANDSHAKE_SETTLE. Proceeding
    // early on `handshake_done` alone raced the tunnel's two-way readiness and hung the
    // deploy (regression 2f44d6b). `handshake_done` is read ONLY to log what happened; it
    // MUST NOT gate this wait. If you're here to make it faster: gate on data received
    // back from the peer, never on the handshake flag.
    std::thread::sleep(HANDSHAKE_SETTLE);
    if handshake_done.load(Ordering::SeqCst) {
        println!(
            "handshake done; settled {}s — running deploy",
            HANDSHAKE_SETTLE.as_secs()
        );
    } else {
        eprintln!(
            "warning: no handshake within {}s — running deploy anyway (may fail to connect)",
            HANDSHAKE_SETTLE.as_secs()
        );
    }

    let result = match exec {
        Some(parts) if !parts.is_empty() => {
            let mut cmd = std::process::Command::new(&parts[0]);
            cmd.args(&parts[1..]);
            // [T:Part C §H.3.3] hand the proxy + target to the deploy command. The
            // overlay IP is reachable ONLY through the SOCKS proxy (no kernel route).
            cmd.env("ANKAYMA_SOCKS_PROXY", socks_addr.to_string());
            cmd.env("ANKAYMA_OVERLAY_IP", &state.overlay_ip);
            cmd.env("ANKAYMA_TARGET_IP", &target.overlay_ip);
            cmd.env("ANKAYMA_TARGET_HOST", &target.hostname);
            println!("tunnel up (userspace). SOCKS5 proxy at {socks_addr}; running deploy.");
            let status = cmd
                .status()
                .with_context(|| format!("run deploy command: {}", parts.join(" ")));
            match status {
                Ok(s) if s.success() => {
                    println!("deploy command finished ok; tearing down tunnel.");
                    Ok(())
                }
                Ok(s) => Err(anyhow!("deploy command exited with {s}")),
                Err(e) => Err(e),
            }
        }
        _ => {
            println!("tunnel up (userspace). SOCKS5 proxy at {socks_addr}; no --exec, holding (Ctrl-C to stop).");
            // No command: park so a human can drive the proxy; SIGINT ends the process.
            while running.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_secs(1));
            }
            Ok(())
        }
    };

    // Tear down: signal both threads and join.
    running.store(false, Ordering::SeqCst);
    // Nudge the accept thread out of its blocking accept() by self-connecting.
    let _ = TcpStream::connect(socks_addr);
    let _ = accept_handle.join();
    let _ = engine_handle.join();
    result
}

/// Accept SOCKS5 connections, perform the handshake, and forward each to the
/// engine. One short-lived thread per accept does the (blocking) handshake so a
/// slow client can't stall the listener.
fn socks_accept_loop(
    listener: TcpListener,
    conn_tx: Sender<PendingConn>,
    running: Arc<AtomicBool>,
) {
    for stream in listener.incoming() {
        if !running.load(Ordering::SeqCst) {
            break;
        }
        let Ok(stream) = stream else { continue };
        let conn_tx = conn_tx.clone();
        std::thread::spawn(move || match socks5_handshake(stream) {
            Ok((dst, stream)) => {
                let _ = conn_tx.send(PendingConn { dst, stream });
            }
            Err(e) => eprintln!("socks5: rejected connection: {e}"),
        });
    }
}

/// Perform the SOCKS5 no-auth CONNECT handshake; return the requested overlay
/// destination and the (still open) client stream. `[T:RFC-1928]`
fn socks5_handshake(mut stream: TcpStream) -> Result<(IpEndpoint, TcpStream)> {
    stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
    // Greeting: VER=5, NMETHODS, METHODS[NMETHODS].
    let mut head = [0u8; 2];
    stream.read_exact(&mut head).context("socks5 greeting")?;
    if head[0] != 0x05 {
        bail!("not SOCKS5 (ver={})", head[0]);
    }
    let mut methods = vec![0u8; head[1] as usize];
    stream.read_exact(&mut methods).context("socks5 methods")?;
    // Reply: VER=5, METHOD=0 (no auth).
    stream
        .write_all(&[0x05, 0x00])
        .context("socks5 method reply")?;

    // Request: VER=5, CMD, RSV, ATYP, DST.ADDR, DST.PORT.
    let dst = read_connect_target(&mut stream)?;

    // Success reply: VER, REP=0, RSV, ATYP=IPv4, BND.ADDR=0, BND.PORT=0.
    stream
        .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .context("socks5 success reply")?;
    stream.set_read_timeout(None).ok();
    Ok((dst, stream))
}

/// Read the SOCKS5 CONNECT request body and return the target endpoint. Pure-ish
/// (reads from `r`); factored out so the address parsing is unit-testable.
/// `[T:RFC-1928 §4]`
fn read_connect_target<R: Read>(r: &mut R) -> Result<IpEndpoint> {
    let mut hdr = [0u8; 4]; // VER, CMD, RSV, ATYP
    r.read_exact(&mut hdr).context("socks5 request header")?;
    if hdr[0] != 0x05 {
        bail!("socks5 request bad version {}", hdr[0]);
    }
    if hdr[1] != 0x01 {
        bail!("socks5 only CONNECT supported (cmd={})", hdr[1]);
    }
    let addr: IpAddr = match hdr[3] {
        0x01 => {
            let mut b = [0u8; 4];
            r.read_exact(&mut b).context("socks5 ipv4 addr")?;
            IpAddr::from(b)
        }
        0x04 => {
            let mut b = [0u8; 16];
            r.read_exact(&mut b).context("socks5 ipv6 addr")?;
            IpAddr::from(b)
        }
        0x03 => {
            // Domain names can't be resolved inside the overlay; the deploy must
            // target the overlay IP directly. `[T:A.1.2 need-to-know]`
            bail!("socks5 domain target unsupported — connect to the overlay IP");
        }
        other => bail!("socks5 unknown atyp {other}"),
    };
    let mut port = [0u8; 2];
    r.read_exact(&mut port).context("socks5 port")?;
    let port = u16::from_be_bytes(port);
    Ok(IpEndpoint::new(to_smoltcp_addr(addr), port))
}

fn to_smoltcp_addr(ip: IpAddr) -> IpAddress {
    match ip {
        IpAddr::V4(v4) => IpAddress::Ipv4(v4),
        IpAddr::V6(v6) => IpAddress::Ipv6(v6),
    }
}

/// One bridged connection: a smoltcp TCP socket paired with the local client
/// stream, plus the half-close bookkeeping the relay needs.
struct Bridge {
    handle: smoltcp::iface::SocketHandle,
    stream: TcpStream,
    /// Bytes read from the client, waiting to be pushed into the smoltcp socket.
    to_socket: VecDeque<u8>,
    /// Bytes recv'd from the smoltcp socket, waiting to be written to the client.
    to_stream: VecDeque<u8>,
    /// The client closed its write side (EOF); flush `to_socket`, then FIN.
    client_eof: bool,
    /// We've sent FIN to the smoltcp socket already.
    socket_closed: bool,
}

/// The single-threaded engine: drives smoltcp + boringtun over the UDP socket,
/// accepts new bridges, and relays bytes until `running` clears. `[T:A.1.1]`
/// data plane is direct runner↔target; the control plane never sees this traffic.
#[allow(clippy::too_many_arguments)]
fn engine_loop(
    udp: Arc<UdpSocket>,
    mut tunn: Tunn,
    target_endpoint: SocketAddr,
    self_overlay: IpAddr,
    target_overlay: IpAddr,
    conn_rx: Receiver<PendingConn>,
    running: Arc<AtomicBool>,
    handshake_done: Arc<AtomicBool>,
) {
    // smoltcp interface (Medium::Ip — no ethernet/link layer over WireGuard).
    let mut device = VirtualDevice::new();
    let mut config = Config::new(HardwareAddress::Ip);
    config.random_seed = rand::random();
    let mut iface = Interface::new(config, &mut device, Instant::now());

    // Our overlay address; per-peer host prefix (/32 or /128) like the kernel path.
    iface.update_ip_addrs(|addrs| {
        let cidr = match self_overlay {
            IpAddr::V4(v4) => IpCidr::new(IpAddress::Ipv4(v4), 32),
            IpAddr::V6(v6) => IpCidr::new(IpAddress::Ipv6(v6), 128),
        };
        let _ = addrs.push(cidr);
    });
    // Single peer: a default route via the target reaches every overlay address we
    // care about (point-to-point deploy). `[T:A.1.2]` only this one node is dialable.
    match target_overlay {
        IpAddr::V4(v4) => {
            let _ = iface.routes_mut().add_default_ipv4_route(v4);
        }
        IpAddr::V6(v6) => {
            let _ = iface.routes_mut().add_default_ipv6_route(v6);
        }
    }

    let mut sockets = SocketSet::new(Vec::new());
    let mut bridges: Vec<Bridge> = Vec::new();
    let mut next_local_port: u16 = 49152;

    // Kick the handshake so connectivity is up before the first data packet.
    let mut hbuf = [0u8; 2048];
    if let TunnResult::WriteToNetwork(p) = tunn.format_handshake_initiation(&mut hbuf, false) {
        let _ = udp.send_to(p, target_endpoint);
    }

    let mut udp_buf = [0u8; 2048];
    let mut decap_out = [0u8; 2048];

    // Diagnostic instrumentation for the ci-deploy send-path bug (runner SYN not reaching
    // the target's embedded SSH). Gated on ANKAYMA_NETSTACK_DEBUG so ONE traced run shows
    // exactly where a packet dies — smoltcp didn't emit / encapsulate dropped it / it was
    // sent but no reply came back — instead of burning CI to guess.
    // `[T: memory nosecret-cideploy-mesh-unproven — trace, don't guess]`
    let debug = std::env::var("ANKAYMA_NETSTACK_DEBUG").is_ok();
    let mut dbg_out: u64 = 0;
    let mut dbg_in: u64 = 0;
    let mut dbg_encap_drop: u64 = 0;
    let mut dbg_last = std::time::Instant::now();

    while running.load(Ordering::SeqCst) {
        // Flag handshake completion for run_deploy's settle wait (G-6).
        if !handshake_done.load(Ordering::SeqCst)
            && agent_core::tunnel::handshake_established(&tunn)
        {
            handshake_done.store(true, Ordering::SeqCst);
        }
        // 1. Drain inbound UDP → boringtun decapsulate → smoltcp rx queue.
        loop {
            match udp.recv_from(&mut udp_buf) {
                Ok((n, _src)) => {
                    let mut res = tunn.decapsulate(None, &udp_buf[..n], &mut decap_out);
                    loop {
                        match res {
                            TunnResult::WriteToNetwork(pkt) => {
                                let _ = udp.send_to(pkt, target_endpoint);
                                res = tunn.decapsulate(None, &[], &mut decap_out);
                            }
                            TunnResult::WriteToTunnelV4(pkt, _)
                            | TunnResult::WriteToTunnelV6(pkt, _) => {
                                dbg_in += 1;
                                device.inbound.push_back(pkt.to_vec());
                                break;
                            }
                            _ => break,
                        }
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => {
                    eprintln!("udp recv error: {e}");
                    break;
                }
            }
        }

        // 2. Accept new bridges from the SOCKS thread.
        while let Ok(pending) = conn_rx.try_recv() {
            let rx = tcp::SocketBuffer::new(vec![0u8; SOCK_BUF]);
            let tx = tcp::SocketBuffer::new(vec![0u8; SOCK_BUF]);
            let mut socket = tcp::Socket::new(rx, tx);
            let local_port = next_local_port;
            next_local_port = next_local_port.checked_add(1).unwrap_or(49152);
            match socket.connect(iface.context(), pending.dst, local_port) {
                Ok(()) => {
                    let _ = pending.stream.set_nonblocking(true);
                    let handle = sockets.add(socket);
                    bridges.push(Bridge {
                        handle,
                        stream: pending.stream,
                        to_socket: VecDeque::new(),
                        to_stream: VecDeque::new(),
                        client_eof: false,
                        socket_closed: false,
                    });
                }
                Err(e) => eprintln!("netstack: connect to {} failed: {e}", pending.dst),
            }
        }

        // 3. Read from each client stream into its to_socket buffer (nonblocking).
        for b in bridges.iter_mut() {
            if b.client_eof {
                continue;
            }
            let mut tmp = [0u8; 16 * 1024];
            match b.stream.read(&mut tmp) {
                Ok(0) => b.client_eof = true,
                Ok(n) => b.to_socket.extend(&tmp[..n]),
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(_) => b.client_eof = true,
            }
        }

        // 4. Poll smoltcp.
        let _ = iface.poll(Instant::now(), &mut device, &mut sockets);

        // 5. Move bytes between smoltcp sockets and client streams.
        for b in bridges.iter_mut() {
            let socket = sockets.get_mut::<tcp::Socket>(b.handle);

            // client → socket
            if socket.can_send() && !b.to_socket.is_empty() {
                let (front, _) = b.to_socket.as_slices();
                if !front.is_empty() {
                    if let Ok(sent) = socket.send_slice(front) {
                        b.to_socket.drain(..sent);
                    }
                }
            }
            // client EOF and nothing left to send → FIN the socket.
            if b.client_eof && b.to_socket.is_empty() && !b.socket_closed {
                socket.close();
                b.socket_closed = true;
            }

            // socket → client buffer
            if socket.can_recv() {
                let _ = socket.recv(|data| {
                    b.to_stream.extend(data.iter().copied());
                    (data.len(), ())
                });
            }
        }

        // 6. Flush to_stream buffers to the client streams (nonblocking).
        for b in bridges.iter_mut() {
            loop {
                let (front, _) = b.to_stream.as_slices();
                if front.is_empty() {
                    break;
                }
                match b.stream.write(front) {
                    Ok(0) => break,
                    Ok(n) => {
                        b.to_stream.drain(..n);
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(_) => {
                        b.to_stream.clear();
                        break;
                    }
                }
            }
        }

        // 7. Encapsulate smoltcp's outbound IP packets and send over UDP.
        while let Some(pkt) = device.outbound.pop_front() {
            let mut enc = [0u8; 2048];
            match tunn.encapsulate(&pkt, &mut enc) {
                TunnResult::WriteToNetwork(out) => {
                    dbg_out += 1;
                    if debug && dbg_out <= 6 {
                        eprintln!(
                            "[netstack] encapsulate ok: inner {}B → {}B ciphertext → udp {target_endpoint}",
                            pkt.len(),
                            out.len()
                        );
                    }
                    let _ = udp.send_to(out, target_endpoint);
                }
                TunnResult::Err(e) => eprintln!("encapsulate error: {e:?}"),
                // Anything else (e.g. session not ready → packet buffered/dropped by
                // boringtun) means smoltcp emitted a packet the tunnel did NOT put on the
                // wire. For a SYN that is exactly the "deploy hangs" failure mode.
                _ => {
                    dbg_encap_drop += 1;
                    if debug {
                        eprintln!(
                            "[netstack] ⚠ encapsulate produced no wire packet — {}B inner DROPPED (session not ready?)",
                            pkt.len()
                        );
                    }
                }
            }
        }

        // 8. Drive WireGuard timers (rekey/keepalive/handshake retries).
        if let TunnResult::WriteToNetwork(p) = tunn.update_timers(&mut hbuf) {
            let _ = udp.send_to(p, target_endpoint);
        }

        // 9. Reap finished bridges: client gone and socket drained/closed.
        bridges.retain(|b| {
            let socket = sockets.get::<tcp::Socket>(b.handle);
            let socket_done = !socket.is_active() && !socket.may_recv();
            !(socket_done && b.to_stream.is_empty())
        });

        // Diagnostic heartbeat (ANKAYMA_NETSTACK_DEBUG): socket state pinpoints the failure —
        // `SynSent` with out>0,in=0 = SYN left but no SYN-ACK came back (target / return path);
        // out=0 with a bridge = smoltcp emitted nothing; encap_drop>0 = tunnel swallowed it.
        if debug && dbg_last.elapsed() >= Duration::from_secs(2) {
            dbg_last = std::time::Instant::now();
            let states: Vec<String> = bridges
                .iter()
                .map(|b| format!("{:?}", sockets.get::<tcp::Socket>(b.handle).state()))
                .collect();
            eprintln!(
                "[netstack] out={dbg_out} in={dbg_in} encap_drop={dbg_encap_drop} bridges={} states={states:?} handshake={}",
                bridges.len(),
                handshake_done.load(Ordering::SeqCst)
            );
        }

        std::thread::sleep(TICK);
    }
}

// ---------------------------------------------------------------------------
// smoltcp Device backed by in-process packet queues (no OS device).
// `inbound`  = decrypted IP packets from the peer, fed to smoltcp.
// `outbound` = IP packets smoltcp wants to send; the engine encapsulates them.
// ---------------------------------------------------------------------------

struct VirtualDevice {
    inbound: VecDeque<Vec<u8>>,
    outbound: VecDeque<Vec<u8>>,
}

impl VirtualDevice {
    fn new() -> Self {
        Self {
            inbound: VecDeque::new(),
            outbound: VecDeque::new(),
        }
    }
}

impl Device for VirtualDevice {
    type RxToken<'a> = VirtRxToken;
    type TxToken<'a> = VirtTxToken<'a>;

    fn receive(&mut self, _t: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let buf = self.inbound.pop_front()?;
        Some((
            VirtRxToken { buf },
            VirtTxToken {
                outbound: &mut self.outbound,
            },
        ))
    }

    fn transmit(&mut self, _t: Instant) -> Option<Self::TxToken<'_>> {
        Some(VirtTxToken {
            outbound: &mut self.outbound,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = MTU;
        caps
    }
}

struct VirtRxToken {
    buf: Vec<u8>,
}

impl phy::RxToken for VirtRxToken {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.buf)
    }
}

struct VirtTxToken<'a> {
    outbound: &'a mut VecDeque<Vec<u8>>,
}

impl phy::TxToken for VirtTxToken<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut buf = vec![0u8; len];
        let r = f(&mut buf);
        self.outbound.push_back(buf);
        r
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn parses_socks5_connect_ipv4() {
        // CONNECT 100.64.0.2:22
        let body = [0x05, 0x01, 0x00, 0x01, 100, 64, 0, 2, 0x00, 0x16];
        let mut r = Cursor::new(body);
        let ep = read_connect_target(&mut r).unwrap();
        assert_eq!(ep.addr, IpAddress::Ipv4("100.64.0.2".parse().unwrap()));
        assert_eq!(ep.port, 22);
    }

    #[test]
    fn parses_socks5_connect_ipv6() {
        let v6: std::net::Ipv6Addr = "fd00:a11a::2".parse().unwrap();
        let mut body = vec![0x05, 0x01, 0x00, 0x04];
        body.extend_from_slice(&v6.octets());
        body.extend_from_slice(&873u16.to_be_bytes());
        let mut r = Cursor::new(body);
        let ep = read_connect_target(&mut r).unwrap();
        assert_eq!(ep.addr, IpAddress::Ipv6(v6));
        assert_eq!(ep.port, 873);
    }

    #[test]
    fn rejects_non_connect_and_domain() {
        // BIND command (0x02) rejected.
        let bind = [0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        assert!(read_connect_target(&mut Cursor::new(bind)).is_err());
        // Domain atyp rejected (overlay has no name resolution).
        let dom = [0x05, 0x01, 0x00, 0x03, 0x01, b'x', 0x00, 0x16];
        assert!(read_connect_target(&mut Cursor::new(dom)).is_err());
    }
}
