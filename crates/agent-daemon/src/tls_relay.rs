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

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use agent_core::{adapters, reqwest};
use anyhow::{Context, Result};
use base64::Engine;

fn cert_dir(fqdn: &str) -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
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
    adapters::submit_subdomain_csr(http, control_plane, service_token, fqdn, &csr_pem)
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

/// Local TLS-terminating relay listeners this node runs for subdomains it
/// owns — one per fqdn, spawned once a cert is on disk, left running for the
/// process lifetime (cert renewal restarts just that one listener).
#[derive(Clone, Default)]
pub struct Relay {
    active: Arc<Mutex<std::collections::HashSet<String>>>,
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

    /// Start a listener for `fqdn` on `(overlay_ip, 443)` relaying to
    /// `127.0.0.1:target_port`, if a cert is on disk and none is running yet.
    /// No-op otherwise — the CSR/poll loop calls this again once a cert lands.
    pub fn ensure_listener(&self, fqdn: &str, overlay_ip: IpAddr, target_port: u16) {
        let mut active = self.active.lock().expect("relay set lock");
        if active.contains(fqdn) {
            return;
        }
        let Some(cert_pem) = load_cert(fqdn) else {
            return;
        };
        let Ok(key_pem) = std::fs::read_to_string(key_path(fqdn)) else {
            return;
        };
        active.insert(fqdn.to_string());
        let fqdn_owned = fqdn.to_string();
        tokio::spawn(async move {
            if let Err(e) =
                run_listener(&fqdn_owned, overlay_ip, target_port, &cert_pem, &key_pem).await
            {
                eprintln!("TLS relay for {fqdn_owned} exited: {e}");
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

fn tls_server_config(cert_pem: &str, key_pem: &str) -> Result<tokio_rustls::rustls::ServerConfig> {
    use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio_rustls::rustls::ServerConfig;

    let certs: Vec<CertificateDer<'static>> = split_pem_certs(cert_pem)?
        .into_iter()
        .map(CertificateDer::from)
        .collect();
    let keypair = rcgen::KeyPair::from_pem(key_pem).context("parse relay TLS key")?;
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(keypair.serialize_der()));
    ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("build rustls ServerConfig")
}

async fn run_listener(
    fqdn: &str,
    overlay_ip: IpAddr,
    target_port: u16,
    cert_pem: &str,
    key_pem: &str,
) -> Result<()> {
    let config = tls_server_config(cert_pem, key_pem)?;
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));

    let listener = tokio::net::TcpListener::bind(SocketAddr::new(overlay_ip, 443))
        .await
        .with_context(|| format!("bind ({overlay_ip}, 443) for {fqdn}"))?;
    println!("TLS relay for {fqdn}: ({overlay_ip}, 443) -> 127.0.0.1:{target_port}");

    loop {
        let (stream, peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let fqdn = fqdn.to_string();
        tokio::spawn(async move {
            let mut tls_stream = match acceptor.accept(stream).await {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("TLS handshake for {fqdn} from {peer} failed: {e}");
                    return;
                }
            };
            let mut upstream =
                match tokio::net::TcpStream::connect(("127.0.0.1", target_port)).await {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!("{fqdn}: connect to local service :{target_port} failed: {e}");
                        return;
                    }
                };
            // Raw byte relay — no HTTP parsing. The TLS handshake already
            // proved the cert chain to the caller; from here it's just bytes.
            if let Err(e) = tokio::io::copy_bidirectional(&mut tls_stream, &mut upstream).await {
                eprintln!("{fqdn}: relay from {peer} ended: {e}");
            }
        });
    }
}
