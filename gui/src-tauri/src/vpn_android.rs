//! Android VPN bridge — mirrors the iOS agent-ios-ptp pattern but in-process.
//!
//! Flow:
//!   Kotlin AnkaymaVpnService.establish() → nativeStart(tunFd, configJson) → pump
//!   Tauri vpn_connect → start_service() → Kotlin startForegroundService(intent)
//!
//! Context bootstrap: MainActivity calls initAndroidVpn(appContext) on startup so
//! start_service / stop_service have a JVM handle to call Java from Rust threads.

use std::net::UdpSocket;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use agent_core::domain::PeerInfo;
use agent_core::pump;
use agent_core::tunnel::StaticSecret;
use jni::objects::{GlobalRef, JObject, JString, JValue};
use jni::sys::{jint, jlong};
use jni::JNIEnv;

// Stored once by initAndroidVpn; used by start_service / stop_service (Rust→Java).
static JAVA_VM: OnceLock<jni::JavaVM> = OnceLock::new();
static APP_CONTEXT: OnceLock<GlobalRef> = OnceLock::new();
// Updated each time nativeStart is called — stores the VpnService instance so
// background threads can call protect() on new DNS-forwarding sockets. [T:F-3]
static VPN_SERVICE_REF: std::sync::Mutex<Option<GlobalRef>> = std::sync::Mutex::new(None);
// Upstream (non-VPN) DNS server for the forward hook — a bare `fn` can't capture it.
static UPSTREAM_DNS: Mutex<Option<String>> = Mutex::new(None);

pub static VPN_RUNNING: AtomicBool = AtomicBool::new(false);

/// Keeps the WireGuard pump alive. Dropping closes the UDP socket → threads exit.
struct VpnHandle {
    _udp: Arc<UdpSocket>,
    _peers: pump::Peers,
}

#[derive(serde::Deserialize, Default)]
struct DnsRecord {
    fqdn: String,
    overlay_ip: String,
}

#[derive(serde::Deserialize)]
struct Config {
    private_key_b64: String,
    overlay_ip: String,
    #[serde(default = "default_port")]
    listen_port: u16,
    #[serde(default)]
    peers: Vec<PeerInfo>,
    /// F-3 private-name table: fqdn → overlay IP. `build_config`'s `resolve` field.
    #[serde(default)]
    resolve: Vec<DnsRecord>,
    /// Upstream public resolvers for non-private names (`build_config` sends an array;
    /// the Android forward hook uses the first). [T:F-3]
    #[serde(default)]
    upstream_dns: Vec<String>,
}

/// Forward a raw DNS query via Kotlin AnkaymaVpnService.forwardDns().
/// Kotlin calls `network.bindSocket()` on the non-VPN network, which reliably
/// bypasses the TUN on all OEM firmware (unlike protect()+UdpSocket). [T:F-3]
fn forward_dns_via_kotlin(payload: Vec<u8>, upstream_ip: &str) -> Option<Vec<u8>> {
    let vm = JAVA_VM.get()?;
    let mut env = vm.attach_current_thread().ok()?;
    let guard = VPN_SERVICE_REF.lock().ok()?;
    let service = guard.as_ref()?;
    let j_payload = env.byte_array_from_slice(&payload).ok()?;
    let j_upstream = env.new_string(upstream_ip).ok()?;
    let result = env
        .call_method(
            service.as_obj(),
            "forwardDns",
            "([BLjava/lang/String;)[B",
            &[JValue::Object(&j_payload), JValue::Object(&j_upstream)],
        )
        .ok()?;
    let obj = result.l().ok()?;
    if obj.is_null() {
        return None;
    }
    let jarr: jni::objects::JByteArray = obj.into();
    let bytes = env.convert_byte_array(&jarr).ok()?;
    if bytes.is_empty() {
        None
    } else {
        Some(bytes)
    }
}

fn default_port() -> u16 {
    51820
}

/// Platform DNS-forward hook (fits `pump::set_dns_forward_hook`). The pump parks the
/// original query under `token` and hands us the bare DNS bytes; we forward to the
/// device's real resolver via Kotlin `forwardDns()` on a spawned thread (the pump tx
/// loop must never block) and return the answer through `pump::dns_reply` — or
/// `pump::dns_fail` (→ SERVFAIL) so a public name is never silently dropped. [T:F-3]
fn android_dns_forward(token: u64, query: &[u8]) {
    let query = query.to_vec();
    std::thread::spawn(move || {
        let upstream = UPSTREAM_DNS
            .lock()
            .ok()
            .and_then(|g| g.clone())
            .unwrap_or_default();
        if upstream.is_empty() {
            pump::dns_fail(token);
            return;
        }
        match forward_dns_via_kotlin(query, &upstream) {
            Some(resp) => pump::dns_reply(token, &resp),
            None => pump::dns_fail(token),
        }
    });
}

/// Bind a socket fd to the underlying non-VPN network so its traffic bypasses the TUN,
/// via `AnkaymaVpnService.bindSocketToUnderlyingNetwork` (Kotlin `Network.bindSocket()`).
/// This is the reliable mechanism the DNS path already uses — `protect()` is silently
/// ignored on some OEM firmware, which black-holes large packets (PMTU stall). Must be
/// called BEFORE connect(). No-op (returns false) when the VPN isn't up, which is fine:
/// the socket then uses the normal default network. [T:F-3 bindSocket pattern]
fn bind_fd_to_underlying(fd: std::os::unix::io::RawFd) -> bool {
    let Some(vm) = JAVA_VM.get() else {
        return false;
    };
    let Ok(mut env) = vm.attach_current_thread() else {
        return false;
    };
    let guard = match VPN_SERVICE_REF.lock() {
        Ok(g) => g,
        Err(_) => return false,
    };
    let Some(service) = guard.as_ref() else {
        return false;
    };
    env.call_method(
        service.as_obj(),
        "bindSocketToUnderlyingNetwork",
        "(I)Z",
        &[JValue::Int(fd)],
    )
    .and_then(|v| v.z())
    .unwrap_or(false)
}

/// Local HTTP CONNECT proxy so the app's HTTPS to the (public) control plane bypasses
/// the full-tunnel VPN (0.0.0.0/0 + ::/0 would otherwise black-hole it). reqwest is
/// configured with `.proxy("http://127.0.0.1:<returned port>")`; for HTTPS it sends
/// `CONNECT host:443`, we dial that host on a protect()ed socket and splice bytes. TLS
/// is negotiated by reqwest end-to-end (SNI/cert = control-plane host) — the proxy never
/// sees plaintext — and loopback is never routed through the TUN, so this works whether
/// the VPN is up or down. A CONNECT proxy (not `.resolve()`) is required because reqwest
/// ignores the port of a `.resolve()` override and always dials the scheme default (443).
/// [T:protect-socket]
pub fn start_control_plane_proxy() -> std::io::Result<u16> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let local_port = listener.local_addr()?.port();
    std::thread::Builder::new()
        .name("cp-proxy".into())
        .spawn(move || {
            for conn in listener.incoming() {
                let Ok(client) = conn else { continue };
                std::thread::spawn(move || {
                    if let Err(e) = handle_connect(client) {
                        log::warn!("cp-proxy: {e}");
                    }
                });
            }
        })?;
    Ok(local_port)
}

/// Handle one `CONNECT host:port` request: dial the target on a protect()ed socket,
/// reply 200, then splice bytes both ways.
fn handle_connect(client: std::net::TcpStream) -> std::io::Result<()> {
    use std::io::{BufRead, BufReader, Write};
    let inv = |m: &str| std::io::Error::new(std::io::ErrorKind::InvalidData, m.to_string());

    // reqwest waits for our 200 before sending any TLS, so the BufReader can't over-read
    // into the tunnelled stream; we still splice via `reader` to drain any buffered bytes.
    let mut reader = BufReader::new(client.try_clone()?);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let target = line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| inv("bad CONNECT line"))?;
    let (host, port) = target
        .rsplit_once(':')
        .ok_or_else(|| inv("no port in CONNECT"))?;
    let port: u16 = port.trim().parse().map_err(|_| inv("bad CONNECT port"))?;
    let host = host.to_string();
    // Drain remaining request headers up to the blank line.
    loop {
        line.clear();
        let n = reader.read_line(&mut line)?;
        if n == 0 || line == "\r\n" || line == "\n" {
            break;
        }
    }

    let upstream = protected_connect(&host, port)?;
    let mut client_w = client;
    client_w.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")?;
    client_w.flush()?;

    // Splice both directions. Read via `reader` (not a fresh clone) so any bytes the
    // BufReader read ahead of the blank line are drained first.
    let mut u_write = upstream.try_clone()?;
    let up = std::thread::spawn(move || {
        let _ = std::io::copy(&mut reader, &mut u_write);
        let _ = u_write.shutdown(std::net::Shutdown::Write);
    });
    let mut u_read = upstream;
    let _ = std::io::copy(&mut u_read, &mut client_w);
    let _ = client_w.shutdown(std::net::Shutdown::Write);
    let _ = up.join();
    Ok(())
}

/// Resolve + dial `host:port` on a protect()ed socket (bypasses the VPN while up).
fn protected_connect(host: &str, port: u16) -> std::io::Result<std::net::TcpStream> {
    use std::net::ToSocketAddrs;
    // Resolves via the system resolver; while the VPN is up the query still reaches
    // the in-process DNS intercept, which forwards non-Ankayma names upstream.
    let addr = (host, port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "resolve failed"))?;
    let sock = socket2::Socket::new(
        socket2::Domain::for_address(addr),
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;
    let _ = bind_fd_to_underlying(sock.as_raw_fd());
    sock.connect_timeout(&addr.into(), std::time::Duration::from_secs(10))?;
    Ok(sock.into())
}

fn start_tunnel(
    env: &mut JNIEnv,
    service: &JObject,
    tun_fd: i32,
    config_json: &str,
) -> Result<Box<VpnHandle>, String> {
    // Store VpnService as a GlobalRef so background DNS-forwarding threads can
    // call protect() via JNI without holding the nativeStart JNI frame. [T:F-3]
    match env.new_global_ref(service) {
        Ok(g) => {
            *VPN_SERVICE_REF.lock().expect("vpn service lock") = Some(g);
        }
        Err(e) => log::error!("start_tunnel: new_global_ref for service: {e}"),
    }

    let cfg: Config = serde_json::from_str(config_json).map_err(|e| format!("config JSON: {e}"))?;

    let self_overlay: std::net::IpAddr = cfg
        .overlay_ip
        .parse()
        .map_err(|_| format!("bad overlay_ip: {}", cfg.overlay_ip))?;

    let key_bytes = agent_core::key_bytes_from_b64(&cfg.private_key_b64)
        .map_err(|e| format!("private key: {e:?}"))?;
    let static_private = StaticSecret::from(key_bytes);

    // SO_REUSEADDR so a reconnect can bind the same port immediately — the previous
    // pump's Arc<UdpSocket> may still be alive for a moment after nativeStop. [T:F-3]
    let udp = unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0);
        if fd < 0 {
            return Err(format!("socket(): {}", std::io::Error::last_os_error()));
        }
        let optval: libc::c_int = 1;
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            &optval as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
        let sin = libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: cfg.listen_port.to_be(),
            sin_addr: libc::in_addr { s_addr: 0 },
            sin_zero: [0; 8],
        };
        if libc::bind(
            fd,
            &sin as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        ) < 0
        {
            libc::close(fd);
            return Err(format!(
                "bind UDP 0.0.0.0:{}: {}",
                cfg.listen_port,
                std::io::Error::last_os_error()
            ));
        }
        UdpSocket::from_raw_fd(fd)
    };

    // Protect the UDP socket so WireGuard traffic doesn't loop through the tunnel.
    env.call_method(service, "protect", "(I)Z", &[JValue::Int(udp.as_raw_fd())])
        .map_err(|e| format!("protect socket: {e}"))?;

    let udp = Arc::new(udp);
    let peers: pump::Peers = Arc::new(Mutex::new(Vec::new()));
    let index = Arc::new(Mutex::new(0u32));

    pump::add_tunn_peers(
        &peers,
        &index,
        &static_private,
        self_overlay,
        &cfg.peers,
        &udp,
        Some(25),
    );

    // F-3 DNS: private mesh names answered in-process from `table`; every other name
    // forwarded to the device's real resolver via the platform hook (pump::DnsResponder
    // + set_dns_forward_hook), exactly like iOS — never NXDOMAIN a public name or the
    // OS drops our resolver. On Android the hook calls Kotlin `forwardDns()`
    // (ConnectivityManager.bindSocket → non-VPN network, reliable where protect() is
    // ignored) on a spawned thread, then pump::dns_reply / dns_fail (non-blocking).
    // Queries are addressed to the magic overlay IP fd00:a11a::53, which
    // AnkaymaVpnService adds as the VPN DNS server + routes into the TUN. [T:F-3]
    let dns = {
        use std::collections::HashMap;
        use std::net::IpAddr;
        let table: HashMap<String, IpAddr> = cfg
            .resolve
            .iter()
            .filter_map(|r| Some((r.fqdn.to_ascii_lowercase(), r.overlay_ip.parse().ok()?)))
            .collect();
        if table.is_empty() {
            None
        } else {
            // The forward hook is a bare `fn` (no captures) — stash the upstream DNS
            // (port stripped; forwardDns dials :53) in a static for it to read.
            if let Some(up) = cfg.upstream_dns.first() {
                let ip_only = up.split(':').next().unwrap_or(up.as_str()).to_string();
                *UPSTREAM_DNS.lock().expect("upstream dns lock") = Some(ip_only);
            }
            pump::set_dns_forward_hook(android_dns_forward);
            let magic: IpAddr = "fd00:a11a::53".parse().expect("magic dns ip");
            log::info!(
                "DNS responder: {} private records, self_ip {magic}",
                table.len()
            );
            Some(pump::DnsResponder {
                self_ip: magic,
                table: Arc::new(Mutex::new(table)),
                forward: true,
            })
        }
    };

    // spawn_tx/spawn_rx take a unified TunHandle now (was a raw fd); wrap the
    // Android VpnService descriptor. tun_fd is i32 (Copy) so it stays usable after.
    // `[T:agent_core::tundev::TunHandle::Fd]`
    // relay = None on this mobile path: NAT-fallback relay not activated here yet
    // (Decision D-T1) — direct-UDP only until the control plane distributes a relay
    // endpoint. `[T:D-T1]`
    let tun = agent_core::tundev::TunHandle::Fd(tun_fd);
    pump::spawn_tx(tun.clone(), udp.clone(), peers.clone(), None, dns);
    pump::spawn_rx(tun, udp.clone(), peers.clone());
    pump::spawn_timers(
        udp.clone(),
        peers.clone(),
        static_private.clone(),
        index.clone(),
        None,
    );

    Ok(Box::new(VpnHandle {
        _udp: udp,
        _peers: peers,
    }))
}

/// Called from MainActivity.onCreate — stores JVM + Application context for
/// later use in start_service / stop_service (Rust → Java direction).
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn Java_com_ankayma_app_MainActivity_initAndroidVpn(
    env: JNIEnv,
    _obj: JObject,
    app_context: JObject,
) {
    if let Ok(vm) = env.get_java_vm() {
        let _ = JAVA_VM.set(vm);
    }
    if let Ok(ctx_ref) = env.new_global_ref(app_context) {
        let _ = APP_CONTEXT.set(ctx_ref);
    }
}

/// JNI: called from AnkaymaVpnService once the TUN fd is established.
/// Returns an opaque handle (jlong) for nativeStop; 0 on failure.
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn Java_com_ankayma_app_AnkaymaVpnService_nativeStart(
    mut env: JNIEnv,
    service: JObject,
    tun_fd: jint,
    config_json: JString,
) -> jlong {
    let config_str: String = match env.get_string(&config_json) {
        Ok(s) => s.into(),
        Err(e) => {
            log::error!("nativeStart: get_string: {e}");
            return 0;
        }
    };
    match start_tunnel(&mut env, &service, tun_fd as i32, &config_str) {
        Ok(handle) => {
            VPN_RUNNING.store(true, Ordering::Relaxed);
            Box::into_raw(handle) as jlong
        }
        Err(e) => {
            log::error!("nativeStart failed: {e}");
            0
        }
    }
}

/// JNI: called from AnkaymaVpnService.onDestroy — drops the handle, stopping threads.
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn Java_com_ankayma_app_AnkaymaVpnService_nativeStop(
    _env: JNIEnv,
    _service: JObject,
    handle: jlong,
) {
    if handle == 0 {
        return;
    }
    drop(Box::from_raw(handle as *mut VpnHandle));
    // Release VpnService GlobalRef so the protect() callback can no longer fire.
    *VPN_SERVICE_REF.lock().expect("vpn service lock") = None;
    VPN_RUNNING.store(false, Ordering::Relaxed);
}

fn with_jni<F, R>(f: F) -> Result<R, String>
where
    F: FnOnce(&mut JNIEnv, &GlobalRef) -> Result<R, String>,
{
    let vm = JAVA_VM
        .get()
        .ok_or("JVM not initialized — ensure app fully started before vpn_connect")?;
    let ctx = APP_CONTEXT.get().ok_or("Android context not initialized")?;
    let mut env = vm
        .attach_current_thread()
        .map_err(|e| format!("attach JVM: {e}"))?;
    f(&mut env, ctx)
}

/// Start AnkaymaVpnService via ContextCompat.startForegroundService.
pub fn start_service(config_json: &str) -> Result<(), String> {
    let config_owned = config_json.to_string();
    with_jni(|env, ctx| {
        // Use setClassName(String) to avoid find_class — find_class from a Rust
        // thread uses the bootstrap class loader and cannot see app classes.
        let intent = env
            .new_object("android/content/Intent", "()V", &[])
            .map_err(|e| format!("new Intent: {e}"))?;
        let class_name = env
            .new_string("com.ankayma.app.AnkaymaVpnService")
            .map_err(|e| e.to_string())?;
        env.call_method(
            &intent,
            "setClassName",
            "(Landroid/content/Context;Ljava/lang/String;)Landroid/content/Intent;",
            &[JValue::Object(ctx.as_obj()), JValue::Object(&class_name)],
        )
        .map_err(|e| format!("setClassName: {e}"))?;

        let key = env.new_string("config_json").map_err(|e| e.to_string())?;
        let val = env.new_string(&config_owned).map_err(|e| e.to_string())?;
        env.call_method(
            &intent,
            "putExtra",
            "(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;",
            &[JValue::Object(&key), JValue::Object(&val)],
        )
        .map_err(|e| format!("putExtra: {e}"))?;

        // Context.startForegroundService (API 26+) — call directly on the
        // context object; avoids find_class on AndroidX ContextCompat which
        // is invisible to the bootstrap class loader on Rust threads.
        env.call_method(
            ctx.as_obj(),
            "startForegroundService",
            "(Landroid/content/Intent;)Landroid/content/ComponentName;",
            &[JValue::Object(&intent)],
        )
        .map_err(|e| format!("startForegroundService: {e}"))?;

        Ok(())
    })
}

/// Get the Android device model name (e.g. "moto g14") via Build.MODEL.
/// Returns None if JVM not yet initialized or JNI fails.
pub fn android_device_name() -> Option<String> {
    with_jni(|env, _ctx| {
        let model_obj = env
            .get_static_field("android/os/Build", "MODEL", "Ljava/lang/String;")
            .map_err(|e| e.to_string())?
            .l()
            .map_err(|e| e.to_string())?;
        let model: String = env
            .get_string(&JString::from(model_obj))
            .map_err(|e| e.to_string())?
            .into();
        Ok(model)
    })
    .ok()
}

/// Open a URL in the system browser via Android's ACTION_VIEW intent.
pub fn open_url(url: &str) -> Result<(), String> {
    let url_owned = url.to_string();
    with_jni(|env, ctx| {
        // Uri.parse(url)
        let url_jstr = env.new_string(&url_owned).map_err(|e| e.to_string())?;
        let uri = env
            .call_static_method(
                "android/net/Uri",
                "parse",
                "(Ljava/lang/String;)Landroid/net/Uri;",
                &[JValue::Object(&url_jstr)],
            )
            .map_err(|e| format!("Uri.parse: {e}"))?
            .l()
            .map_err(|e| format!("Uri object: {e}"))?;

        // new Intent(Intent.ACTION_VIEW, uri)
        let action = env
            .new_string("android.intent.action.VIEW")
            .map_err(|e| e.to_string())?;
        let intent = env
            .new_object(
                "android/content/Intent",
                "(Ljava/lang/String;Landroid/net/Uri;)V",
                &[JValue::Object(&action), JValue::Object(&uri)],
            )
            .map_err(|e| format!("new Intent: {e}"))?;

        // intent.addFlags(FLAG_ACTIVITY_NEW_TASK) — required when starting from non-Activity context
        env.call_method(
            &intent,
            "addFlags",
            "(I)Landroid/content/Intent;",
            &[JValue::Int(0x10000000)],
        )
        .map_err(|e| format!("addFlags: {e}"))?;

        env.call_method(
            ctx.as_obj(),
            "startActivity",
            "(Landroid/content/Intent;)V",
            &[JValue::Object(&intent)],
        )
        .map_err(|e| format!("startActivity: {e}"))?;

        Ok(())
    })
}

/// Stop AnkaymaVpnService by sending it the STOP action.
pub fn stop_service() -> Result<(), String> {
    with_jni(|env, ctx| {
        let intent = env
            .new_object("android/content/Intent", "()V", &[])
            .map_err(|e| format!("new Intent: {e}"))?;
        let class_name = env
            .new_string("com.ankayma.app.AnkaymaVpnService")
            .map_err(|e| e.to_string())?;
        env.call_method(
            &intent,
            "setClassName",
            "(Landroid/content/Context;Ljava/lang/String;)Landroid/content/Intent;",
            &[JValue::Object(ctx.as_obj()), JValue::Object(&class_name)],
        )
        .map_err(|e| format!("setClassName: {e}"))?;

        let stop_action = env
            .new_string("com.ankayma.app.VPN_STOP")
            .map_err(|e| e.to_string())?;
        env.call_method(
            &intent,
            "setAction",
            "(Ljava/lang/String;)Landroid/content/Intent;",
            &[JValue::Object(&stop_action)],
        )
        .map_err(|e| format!("setAction: {e}"))?;

        env.call_method(
            ctx.as_obj(),
            "startService",
            "(Landroid/content/Intent;)Landroid/content/ComponentName;",
            &[JValue::Object(&intent)],
        )
        .map_err(|e| format!("startService: {e}"))?;

        Ok(())
    })
}
