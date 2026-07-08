//! Android VPN bridge — mirrors the iOS agent-ios-ptp pattern but in-process.
//!
//! Flow:
//!   Kotlin AnkaymaVpnService.establish() → nativeStart(tunFd, configJson) → pump
//!   Tauri vpn_connect → start_service() → Kotlin startForegroundService(intent)
//!
//! Context bootstrap: MainActivity calls initAndroidVpn(appContext) on startup so
//! start_service / stop_service have a JVM handle to call Java from Rust threads.

use std::net::UdpSocket;
use std::os::unix::io::AsRawFd;
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

pub static VPN_RUNNING: AtomicBool = AtomicBool::new(false);

/// Keeps the WireGuard pump alive. Dropping closes the UDP socket → threads exit.
struct VpnHandle {
    _udp: Arc<UdpSocket>,
    _peers: pump::Peers,
}

#[derive(serde::Deserialize)]
struct Config {
    private_key_b64: String,
    overlay_ip: String,
    #[serde(default = "default_port")]
    listen_port: u16,
    #[serde(default)]
    peers: Vec<PeerInfo>,
}

fn default_port() -> u16 {
    51820
}

fn start_tunnel(
    env: &mut JNIEnv,
    service: &JObject,
    tun_fd: i32,
    config_json: &str,
) -> Result<Box<VpnHandle>, String> {
    let cfg: Config =
        serde_json::from_str(config_json).map_err(|e| format!("config JSON: {e}"))?;

    let self_overlay: std::net::IpAddr = cfg
        .overlay_ip
        .parse()
        .map_err(|_| format!("bad overlay_ip: {}", cfg.overlay_ip))?;

    let key_bytes = agent_core::key_bytes_from_b64(&cfg.private_key_b64)
        .map_err(|e| format!("private key: {e:?}"))?;
    let static_private = StaticSecret::from(key_bytes);

    let addr = format!("0.0.0.0:{}", cfg.listen_port);
    let udp = UdpSocket::bind(&addr).map_err(|e| format!("bind UDP {addr}: {e}"))?;

    // Protect the UDP socket so WireGuard traffic doesn't loop through the tunnel.
    let udp_fd = udp.as_raw_fd();
    env.call_method(service, "protect", "(I)Z", &[JValue::Int(udp_fd)])
        .map_err(|e| format!("protect socket: {e}"))?;

    let udp = Arc::new(udp);
    let peers: pump::Peers = Arc::new(Mutex::new(Vec::new()));
    let index = Arc::new(Mutex::new(0u32));

    pump::add_tunn_peers(&peers, &index, &static_private, self_overlay, &cfg.peers, &udp);

    pump::spawn_tx(tun_fd, udp.clone(), peers.clone());
    pump::spawn_rx(tun_fd, udp.clone(), peers.clone());
    pump::spawn_timers(udp.clone(), peers.clone());

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
    VPN_RUNNING.store(false, Ordering::Relaxed);
}

fn with_jni<F, R>(f: F) -> Result<R, String>
where
    F: FnOnce(&mut JNIEnv, &GlobalRef) -> Result<R, String>,
{
    let vm = JAVA_VM
        .get()
        .ok_or("JVM not initialized — ensure app fully started before vpn_connect")?;
    let ctx = APP_CONTEXT
        .get()
        .ok_or("Android context not initialized")?;
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
