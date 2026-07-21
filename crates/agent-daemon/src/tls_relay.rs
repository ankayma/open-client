//! tls_relay — F-3 auto-TLS (Slice 3): this node's own local TLS termination
//! for the branded subdomains it owns. `[T:A.1.1 + F-3 auto-TLS]`
//!
//! The node generates its own TLS keypair and only ever sends a CSR up — the
//! private key never leaves this machine, matching the NodeIdentity posture
//! (control-plane signs/forwards, never holds a private key). Once the
//! control plane hands back a signed cert chain (via SSE `cert_issued`, or the
//! `GET .../cert` poll fallback — belt-and-suspenders, per the resolver's own
//! stale-table lesson: a push channel alone isn't enough), this module writes
//! it to disk and terminates TLS on `(overlay_ip, 443)`, relaying decrypted
//! bytes to the local service on `127.0.0.1:target_port`. No HTTP parsing — a
//! raw byte relay after handshake, so no hyper/axum needed.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use agent_core::{adapters, reqwest};
use anyhow::{Context, Result};
use base64::Engine;

/// Relay listen ports — 443/80 by default, overridable via
/// `ANKAYMA_RELAY_HTTPS_PORT` / `ANKAYMA_RELAY_HTTP_PORT` for hosts where a
/// co-resident web server already holds the wildcard binds (a specific
/// `(overlay, 443)` bind loses to an existing `0.0.0.0:443`/`[::]:443`
/// listener). On such hosts the browser URL must carry the port —
/// `https://name:8443/` — an honest trade for coexisting on a shared box.
/// `[A: verify per-host — whether wildcard+specific can coexist depends on the
/// other server's socket options; the bind error in the journal is the signal]`
fn relay_https_port() -> u16 {
    std::env::var("ANKAYMA_RELAY_HTTPS_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(443)
}
fn relay_http_port() -> u16 {
    std::env::var("ANKAYMA_RELAY_HTTP_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(80)
}

fn cert_dir(fqdn: &str) -> PathBuf {
    let home = crate::up::home_root();
    PathBuf::from(format!("{home}/.ankayma/certs")).join(fqdn)
}
fn key_path(fqdn: &str) -> PathBuf {
    cert_dir(fqdn).join("key.pem")
}
fn cert_path(fqdn: &str) -> PathBuf {
    cert_dir(fqdn).join("cert.pem")
}

#[cfg(unix)]
fn chmod_600(p: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}
#[cfg(not(unix))]
fn chmod_600(_p: &Path) -> Result<()> {
    Ok(())
}

/// This node's persisted TLS keypair for `fqdn` — generated once, reused
/// across restarts so re-submitting the CSR (if ever needed) is idempotent:
/// same key → same public key → the control plane's row update is a no-op.
fn load_or_generate_keypair(fqdn: &str) -> Result<rcgen::KeyPair> {
    let p = key_path(fqdn);
    if let Ok(pem) = std::fs::read_to_string(&p) {
        return rcgen::KeyPair::from_pem(&pem).context("parse persisted TLS key");
    }
    let kp = rcgen::KeyPair::generate().context("generate TLS keypair")?;
    std::fs::create_dir_all(cert_dir(fqdn)).context("create cert dir")?;
    std::fs::write(&p, kp.serialize_pem()).context("persist TLS key")?;
    chmod_600(&p)?;
    Ok(kp)
}

fn build_csr_pem(fqdn: &str, keypair: &rcgen::KeyPair) -> Result<String> {
    let mut params = rcgen::CertificateParams::new(vec![fqdn.to_string()]).context("CSR params")?;
    // rcgen::CertificateParams::default() fills the Subject with a placeholder
    // CommonName ("rcgen self signed cert") meant for throwaway self-signed
    // certs — Let's Encrypt validates the CN if present and rejects a CSR
    // whose CN isn't a real identifier. The SAN list above is what ACME
    // actually authorizes against; clear the CN so it isn't checked at all.
    params.distinguished_name = rcgen::DistinguishedName::new();
    let csr = params.serialize_request(keypair).context("serialize CSR")?;
    csr.pem().context("PEM-encode CSR")
}

fn store_cert(fqdn: &str, cert_pem: &str) -> Result<()> {
    std::fs::create_dir_all(cert_dir(fqdn))?;
    let p = cert_path(fqdn);
    std::fs::write(&p, cert_pem)?;
    chmod_600(&p)?;
    Ok(())
}

fn load_cert(fqdn: &str) -> Option<String> {
    std::fs::read_to_string(cert_path(fqdn)).ok()
}

/// Split a PEM cert *chain* (possibly several `-----BEGIN CERTIFICATE-----`
/// blocks concatenated, as Let's Encrypt returns) into DER blocks. Dependency-
/// free beyond `base64` (already a workspace dep) — PEM is just base64 between
/// marker lines (RFC 7468), matching the dep-free precedent set for the DNS
/// resolver / QR encoder.
fn split_pem_certs(pem: &str) -> Result<Vec<Vec<u8>>> {
    let mut out = Vec::new();
    let mut body = String::new();
    let mut inside = false;
    for line in pem.lines() {
        if line.starts_with("-----BEGIN CERTIFICATE-----") {
            inside = true;
            body.clear();
        } else if line.starts_with("-----END CERTIFICATE-----") {
            inside = false;
            let der = base64::engine::general_purpose::STANDARD
                .decode(body.trim())
                .context("cert chain block is not valid PEM/base64")?;
            out.push(der);
        } else if inside {
            body.push_str(line.trim());
        }
    }
    if out.is_empty() {
        anyhow::bail!("no certificates found in PEM chain");
    }
    Ok(out)
}

/// Ensure `fqdn` has a keypair on disk and a CSR on file with the control
/// plane, unless it already has an issued cert locally (renewal is a separate,
/// control-plane-driven sweep — this path is only for first issuance).
pub async fn ensure_csr_submitted(
    http: &reqwest::Client,
    control_plane: &str,
    service_token: &str,
    fqdn: &str,
) -> Result<()> {
    if load_cert(fqdn).is_some() {
        return Ok(());
    }
    let keypair = load_or_generate_keypair(fqdn)?;
    let csr_pem = build_csr_pem(fqdn, &keypair)?;
    adapters::submit_subdomain_csr(
        http,
        control_plane,
        &adapters::NodeServiceToken(service_token.to_string()),
        fqdn,
        &csr_pem,
    )
    .await
    .map_err(|e| anyhow::anyhow!("submit CSR for {fqdn}: {e:?}"))
}

/// Poll `GET .../cert` once; persist it if issued. The fallback to the
/// `cert_issued` SSE push, same belt-and-suspenders reasoning as the resolver.
pub async fn poll_and_store(
    http: &reqwest::Client,
    control_plane: &str,
    token: &str,
    fqdn: &str,
) -> bool {
    if load_cert(fqdn).is_some() {
        return true;
    }
    match adapters::get_subdomain_cert(http, control_plane, token, fqdn).await {
        Ok(c) if c.cert_status == "issued" => match c.cert_pem {
            Some(pem) => match store_cert(fqdn, &pem) {
                Ok(()) => true,
                Err(e) => {
                    eprintln!("store cert for {fqdn} failed: {e}");
                    false
                }
            },
            None => false,
        },
        _ => false,
    }
}

/// Handle a `cert_issued` SSE push: persist immediately rather than waiting
/// for the next poll cycle.
pub fn on_cert_issued(fqdn: &str, cert_pem: &str) {
    if let Err(e) = store_cert(fqdn, cert_pem) {
        eprintln!("store cert for {fqdn} (from SSE) failed: {e}");
    }
}

/// Local relay listeners this node runs for the subdomains it owns. ONE shared
/// listener per port — `(overlay_ip, 80)` demuxed by the Host header and
/// `(overlay_ip, 443)` demuxed by SNI — with every owned fqdn just a row in the
/// shared route/cert tables. Per-fqdn listeners raced for the same port when a
/// node owned two subdomains (2026-07-03: the second bind failed and that relay
/// silently never served); an fqdn is a *name*, not a *port*.
#[derive(Clone, Default)]
pub struct Relay {
    /// fqdn → local target port. Read by BOTH shared listeners on every
    /// connection, so adding a subdomain never needs a new listener.
    routes: Arc<Mutex<HashMap<String, u16>>>,
    /// fqdn → certified key, resolved per-connection by SNI.
    certs: Arc<SniCerts>,
    /// Whether the shared listener on that port has been spawned (per process).
    http_listening: Arc<Mutex<bool>>,
    tls_listening: Arc<Mutex<bool>>,
    /// fqdns for which a CSR-submit-then-poll task has already been spawned
    /// this process run — guards against re-submitting the CSR (which would
    /// restart the control plane's ACME flow from scratch) every time the
    /// caller resyncs the resolve table (every reconnect cycle, up to 60s).
    attempted: Arc<Mutex<std::collections::HashSet<String>>>,
}

impl Relay {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register `fqdn` on the shared TLS listener at `(overlay_ip, 443)` if its
    /// cert is on disk: (re)load the certified key into the SNI table and make
    /// sure the listener is up. No-op without a cert — the CSR/poll loop calls
    /// this again once one lands. Safe to call every resync cycle; a renewal
    /// (new cert.pem on disk) is picked up by the reload on the next call.
    pub fn ensure_listener(&self, fqdn: &str, overlay_ip: IpAddr, target_port: u16) {
        let Some(cert_pem) = load_cert(fqdn) else {
            return;
        };
        let Ok(key_pem) = std::fs::read_to_string(key_path(fqdn)) else {
            return;
        };
        let ck = match certified_key(&cert_pem, &key_pem) {
            Ok(ck) => ck,
            Err(e) => {
                eprintln!("{fqdn}: cert on disk is unusable: {e}");
                return;
            }
        };
        let newly_added = self
            .certs
            .by_name
            .lock()
            .expect("sni table lock")
            .insert(fqdn.to_string(), ck)
            .is_none();
        self.routes
            .lock()
            .expect("route table lock")
            .insert(fqdn.to_string(), target_port);
        if newly_added {
            println!("TLS relay serving {fqdn} (SNI) -> 127.0.0.1:{target_port}");
        }

        let mut listening = self.tls_listening.lock().expect("tls listening lock");
        if *listening {
            return;
        }
        *listening = true;
        let certs = self.certs.clone();
        let routes = self.routes.clone();
        tokio::spawn(async move {
            if let Err(e) = run_tls_listener(overlay_ip, certs, routes).await {
                eprintln!("shared TLS relay listener exited: {e}");
            }
        });
    }

    /// Register `fqdn` on the shared plain-TCP listener at `(overlay_ip, 80)`.
    /// No cert required — the overlay link is already the private channel
    /// (vendor off the data path, A.1.1), so a name resolving over HTTP is the
    /// default; HTTPS via `ensure_listener` above is a nice-to-have (browser
    /// padlock / a target service that itself requires TLS), not a precondition
    /// for the name to work at all. `[T: founder decision 2026-07-02]`
    pub fn ensure_http_listener(&self, fqdn: &str, overlay_ip: IpAddr, target_port: u16) {
        self.routes
            .lock()
            .expect("route table lock")
            .insert(fqdn.to_string(), target_port);

        let mut listening = self.http_listening.lock().expect("http listening lock");
        if *listening {
            return;
        }
        *listening = true;
        let routes = self.routes.clone();
        tokio::spawn(async move {
            if let Err(e) = run_http_listener(overlay_ip, routes).await {
                eprintln!("shared HTTP relay listener exited: {e}");
            }
        });
    }

    /// Drive one subdomain this node owns from "no cert yet" to "listener
    /// running": submit its CSR (once per process run), poll until issued (or
    /// give up after ~10 minutes — a persistent failure needs a human to
    /// notice `cert_last_error` via `GET .../cert`, not an infinite retry
    /// loop), then start the relay. Safe to call every resync cycle — a
    /// second call for an already-attempted fqdn just re-checks the listener
    /// in case a cert landed via the `cert_issued` SSE push in the meantime.
    pub fn spawn_owner_task(
        &self,
        http: reqwest::Client,
        control_plane: String,
        service_token: String,
        fqdn: String,
        target_port: u16,
        overlay_ip: IpAddr,
    ) {
        {
            let mut attempted = self.attempted.lock().expect("relay attempted lock");
            if !attempted.insert(fqdn.clone()) {
                self.ensure_listener(&fqdn, overlay_ip, target_port);
                return;
            }
        }
        let relay = self.clone();
        tokio::spawn(async move {
            if let Err(e) = ensure_csr_submitted(&http, &control_plane, &service_token, &fqdn).await
            {
                eprintln!("{fqdn}: CSR submission failed: {e}");
            }
            for _ in 0..30 {
                if poll_and_store(&http, &control_plane, &service_token, &fqdn).await {
                    relay.ensure_listener(&fqdn, overlay_ip, target_port);
                    return;
                }
                tokio::time::sleep(std::time::Duration::from_secs(20)).await;
            }
            eprintln!(
                "{fqdn}: no cert after ~10 minutes of polling — check cert_last_error via \
                 GET /api/v1/subdomain/{fqdn}/cert"
            );
        });
    }
}

/// Per-SNI certificate table for the shared TLS listener: rustls asks
/// `resolve()` on every ClientHello and we answer with the cert of whichever
/// owned fqdn the client named. `[T:rustls@0.23 ResolvesServerCert]`
#[derive(Default)]
struct SniCerts {
    by_name: Mutex<HashMap<String, Arc<tokio_rustls::rustls::sign::CertifiedKey>>>,
}

impl std::fmt::Debug for SniCerts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let n = self.by_name.lock().map(|m| m.len()).unwrap_or(0);
        write!(f, "SniCerts({n} names)")
    }
}

impl tokio_rustls::rustls::server::ResolvesServerCert for SniCerts {
    fn resolve(
        &self,
        hello: tokio_rustls::rustls::server::ClientHello<'_>,
    ) -> Option<Arc<tokio_rustls::rustls::sign::CertifiedKey>> {
        let name = hello.server_name()?;
        self.by_name.lock().ok()?.get(name).cloned()
    }
}

/// Parse one fqdn's PEM cert chain + key into the rustls form the SNI resolver
/// serves. `ring` provider named explicitly — this process also links
/// `aws-lc-rs` transitively, and rustls panics on an ambiguous default.
fn certified_key(
    cert_pem: &str,
    key_pem: &str,
) -> Result<Arc<tokio_rustls::rustls::sign::CertifiedKey>> {
    use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

    let certs: Vec<CertificateDer<'static>> = split_pem_certs(cert_pem)?
        .into_iter()
        .map(CertificateDer::from)
        .collect();
    let keypair = rcgen::KeyPair::from_pem(key_pem).context("parse relay TLS key")?;
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(keypair.serialize_der()));
    let signing_key = tokio_rustls::rustls::crypto::ring::sign::any_supported_type(&key_der)
        .context("wrap TLS key for rustls")?;
    Ok(Arc::new(tokio_rustls::rustls::sign::CertifiedKey::new(
        certs,
        signing_key,
    )))
}

/// Extract the Host header (lowercased, port stripped) from a buffered HTTP
/// request head. Dependency-free, same posture as `split_pem_certs`. Returns
/// `None` until the header is present in the buffer.
fn parse_host(head: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(head).ok()?;
    for line in text.split("\r\n").skip(1) {
        if line.is_empty() {
            break; // end of headers — no Host found
        }
        let (name, value) = line.split_once(':')?;
        if name.eq_ignore_ascii_case("host") {
            let host = value.trim();
            let host = host.rsplit_once(':').map_or(host, |(h, port)| {
                // Only strip a real port suffix (not an IPv6 literal's colon).
                if port.chars().all(|c| c.is_ascii_digit()) {
                    h
                } else {
                    host
                }
            });
            return Some(host.to_ascii_lowercase());
        }
    }
    None
}

/// The ONE plain-TCP listener on `(overlay_ip, 80)`: peek the request head for
/// the Host header, route to that fqdn's local target port, then relay bytes.
/// `[T: founder decision 2026-07-02]`
async fn run_http_listener(
    overlay_ip: IpAddr,
    routes: Arc<Mutex<HashMap<String, u16>>>,
) -> Result<()> {
    let port = relay_http_port();
    let listener = tokio::net::TcpListener::bind(SocketAddr::new(overlay_ip, port))
        .await
        .with_context(|| format!("bind ({overlay_ip}, {port})"))?;
    println!("HTTP relay listening on ({overlay_ip}, {port}) — routed by Host header");

    loop {
        let (mut stream, peer) = listener.accept().await?;
        let routes = routes.clone();
        tokio::spawn(async move {
            // Buffer until the Host header shows up (request heads are small;
            // 8KB is the conventional server cap for the whole head).
            let mut head = vec![0u8; 8192];
            let mut n = 0;
            let host = loop {
                match stream.read(&mut head[n..]).await {
                    Ok(0) | Err(_) => return,
                    Ok(m) => n += m,
                }
                if let Some(h) = parse_host(&head[..n]) {
                    break h;
                }
                let headers_done = head[..n].windows(4).any(|w| w == b"\r\n\r\n");
                if headers_done || n == head.len() {
                    eprintln!("http relay: no Host header from {peer} — dropped");
                    return;
                }
            };
            let Some(target_port) = routes.lock().expect("route table lock").get(&host).copied()
            else {
                eprintln!("http relay: no route for Host {host} (from {peer}) — dropped");
                return;
            };
            let mut upstream =
                match tokio::net::TcpStream::connect(("127.0.0.1", target_port)).await {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!("{host}: connect to local service :{target_port} failed: {e}");
                        return;
                    }
                };
            // Replay the bytes we consumed while sniffing, then go transparent.
            if upstream.write_all(&head[..n]).await.is_err() {
                return;
            }
            if let Err(e) = tokio::io::copy_bidirectional(&mut stream, &mut upstream).await {
                eprintln!("{host}: http relay from {peer} ended: {e}");
            }
        });
    }
}

/// The ONE TLS listener on `(overlay_ip, 443)`: rustls picks the cert by SNI,
/// the accepted connection routes to that same name's local target port, then
/// it's a raw byte relay — no HTTP parsing after the handshake.
async fn run_tls_listener(
    overlay_ip: IpAddr,
    certs: Arc<SniCerts>,
    routes: Arc<Mutex<HashMap<String, u16>>>,
) -> Result<()> {
    use tokio_rustls::rustls::ServerConfig;

    let provider = std::sync::Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
    let config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .context("select TLS protocol versions")?
        .with_no_client_auth()
        .with_cert_resolver(certs);
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));

    let port = relay_https_port();
    let listener = tokio::net::TcpListener::bind(SocketAddr::new(overlay_ip, port))
        .await
        .with_context(|| format!("bind ({overlay_ip}, {port})"))?;
    println!("TLS relay listening on ({overlay_ip}, {port}) — cert + route by SNI");

    loop {
        let (stream, peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let routes = routes.clone();
        tokio::spawn(async move {
            let mut tls_stream = match acceptor.accept(stream).await {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("TLS handshake from {peer} failed: {e}");
                    return;
                }
            };
            let Some(name) = tls_stream.get_ref().1.server_name().map(str::to_owned) else {
                eprintln!("TLS relay: no SNI from {peer} — dropped");
                return;
            };
            let Some(target_port) = routes.lock().expect("route table lock").get(&name).copied()
            else {
                eprintln!("TLS relay: no route for {name} (from {peer}) — dropped");
                return;
            };
            let mut upstream =
                match tokio::net::TcpStream::connect(("127.0.0.1", target_port)).await {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!("{name}: connect to local service :{target_port} failed: {e}");
                        return;
                    }
                };
            // Raw byte relay — no HTTP parsing. The TLS handshake already
            // proved the cert chain to the caller; from here it's just bytes.
            if let Err(e) = tokio::io::copy_bidirectional(&mut tls_stream, &mut upstream).await {
                eprintln!("{name}: relay from {peer} ended: {e}");
            }
        });
    }
}
