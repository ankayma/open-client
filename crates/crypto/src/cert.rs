//! cert — Layer 2 node-cert utilities (expiry, chain sanity check). OPEN crate.
//!
//! Intensity: **Critical** (CLAUDE.md T/A §). Every primitive is cited.
//! `[T:Part D §H.2 Step 1]` the node receives a
//! leaf cert + Provisioning CA from `EnrollResponse` (TH-A dynamic trust — no CA
//! pinned in the binary). This module gives the agent two checks:
//!   * `cert_expiry_days` — drive the "renew soon" warning (display only, 1.x).
//!   * `verify_cert_chain` — post-enroll sanity check that the leaf really is
//!     signed by the CA we were handed (catches CP misconfig at enroll time,
//!     NOT a substitute for rustls path validation at connect time).
//!
//! Parsing/verify via `x509-parser` — already in-tree pinned 0.18.1 as rcgen's
//! parser, so promoting it to a direct dep adds zero new supply-chain surface.
//! `[T:A.1.21]` (Spec §H.2 named `rustls-pki-types` here; that crate carries
//! type definitions only — it cannot read notAfter or check a signature — so
//! the working choice is x509-parser. Deviation recorded in the spec log.)

use x509_parser::certificate::X509Certificate;
use x509_parser::pem::Pem;
use x509_parser::time::ASN1Time;

/// Errors from cert parsing/validation. No cert material is embedded in the
/// variants — callers log these next to fqdn/node_id they already know.
#[derive(Debug, PartialEq, Eq)]
pub enum CertError {
    /// Input was not PEM, or contained no CERTIFICATE block.
    Pem,
    /// PEM decoded but the DER inside is not a valid X.509 certificate.
    Parse,
    /// Leaf or CA is outside its validity window (expired / not yet valid).
    ValidityWindow,
    /// No CA in the provided bundle signs the leaf.
    UntrustedSignature,
}

impl std::fmt::Display for CertError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CertError::Pem => write!(f, "not a PEM certificate"),
            CertError::Parse => write!(f, "PEM block is not a valid X.509 certificate"),
            CertError::ValidityWindow => write!(f, "certificate outside its validity window"),
            CertError::UntrustedSignature => {
                write!(f, "leaf certificate is not signed by the provided CA")
            }
        }
    }
}
impl std::error::Error for CertError {}

/// Parse every CERTIFICATE block in `pem` into owned DER blobs.
/// `[T:x509-parser@0.18.1-Pem::iter_from_buffer]` iterates concatenated PEM
/// blocks — a CA *chain* (root + intermediates) arrives as one string.
fn pem_blocks(pem: &str) -> Result<Vec<Pem>, CertError> {
    let blocks: Vec<Pem> = Pem::iter_from_buffer(pem.as_bytes())
        .filter_map(|p| p.ok())
        .filter(|p| p.label == "CERTIFICATE")
        .collect();
    if blocks.is_empty() {
        return Err(CertError::Pem);
    }
    Ok(blocks)
}

/// Days until the (first) certificate in `pem` expires. Negative = already
/// expired. Floor division: a cert expiring in 90m reports 0 days — the caller
/// warns on `< 30`, so rounding down errs on the early-warning side.
/// `[T:RFC-5280§4.1.2.5]` notAfter is the end of the validity period.
pub fn cert_expiry_days(pem: &str) -> Result<i64, CertError> {
    let blocks = pem_blocks(pem)?;
    let cert = blocks[0].parse_x509().map_err(|_| CertError::Parse)?;
    let not_after = cert.validity().not_after.timestamp();
    // [T:x509-parser@0.18.1-ASN1Time::now] same clock source as is_valid().
    let now = ASN1Time::now().timestamp();
    Ok((not_after - now).div_euclid(86_400))
}

/// RFC3339 UTC string of the (first) certificate's notAfter — persisted in
/// `agent.json` as `cert_expires_at` so the GUI can show it without reparsing.
pub fn cert_expiry_rfc3339(pem: &str) -> Result<String, CertError> {
    let blocks = pem_blocks(pem)?;
    let cert = blocks[0].parse_x509().map_err(|_| CertError::Parse)?;
    // [T:x509-parser@0.18.1-ASN1Time::to_datetime] wraps time::OffsetDateTime (UTC).
    cert.validity()
        .not_after
        .to_datetime()
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|_| CertError::Parse)
}

/// Post-enroll sanity check: the leaf is inside its validity window and is
/// signed by (at least) one certificate of the CA bundle.
///
/// `[T:RFC-5280§4.1.1.3]` signatureValue covers the DER tbsCertificate;
/// `[T:x509-parser@0.18.1-verify_signature]` checks it via ring (`verify`
/// feature — ECDSA P-256/P-384, Ed25519, RSA).
///
/// This is deliberately NOT full RFC 5280 path building (no basic-constraints /
/// key-usage / name-chaining walk): at connect time rustls performs real path
/// validation against this CA (`broker_client`, agent-core). Here we only fail
/// fast at enrollment if the CP handed us mismatched material. `[T per
/// Part D §H.2 Step 1 "sanity check post-enroll"]`
pub fn verify_cert_chain(leaf_pem: &str, ca_pem: &str) -> Result<(), CertError> {
    let leaf_blocks = pem_blocks(leaf_pem)?;
    let leaf = leaf_blocks[0].parse_x509().map_err(|_| CertError::Parse)?;
    if !leaf.validity().is_valid() {
        return Err(CertError::ValidityWindow);
    }

    let ca_blocks = pem_blocks(ca_pem)?;
    let mut saw_valid_ca = false;
    for block in &ca_blocks {
        let ca: X509Certificate<'_> = block.parse_x509().map_err(|_| CertError::Parse)?;
        if !ca.validity().is_valid() {
            continue;
        }
        saw_valid_ca = true;
        if leaf.verify_signature(Some(ca.public_key())).is_ok() {
            return Ok(());
        }
    }
    if saw_valid_ca {
        Err(CertError::UntrustedSignature)
    } else {
        // Every CA block parsed but none is time-valid — surface that as the
        // window problem it is, not as a bogus signature mismatch.
        Err(CertError::ValidityWindow)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{
        BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair, KeyUsagePurpose,
    };

    /// A CA + leaf signed by it, mirroring what the CP will hand back at
    /// enrollment (TenantCA-signed node cert + Provisioning CA chain).
    /// [T:rcgen@0.14-CertifiedIssuer] issuer wrapper derefs to Issuer for signing.
    fn ca_and_leaf(days_valid: i64) -> (String, String) {
        let ca_key = KeyPair::generate().unwrap(); // default ECDSA P-256
        let mut ca_params = CertificateParams::new(vec![]).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let ca = CertifiedIssuer::self_signed(ca_params, ca_key).unwrap();

        let leaf_key = KeyPair::generate().unwrap();
        let mut leaf_params = CertificateParams::new(vec!["node-1.test".to_string()]).unwrap();
        leaf_params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(days_valid);
        let leaf_cert = leaf_params.signed_by(&leaf_key, &ca).unwrap();

        (ca.pem(), leaf_cert.pem())
    }

    #[test]
    fn expiry_days_matches_generated_validity() {
        let (_ca, leaf) = ca_and_leaf(365);
        let days = cert_expiry_days(&leaf).unwrap();
        // Generated "now + 365d"; parsing shortly after gives 364 (floor).
        assert!((364..=365).contains(&days), "got {days}");
    }

    #[test]
    fn expiry_rfc3339_is_parseable_utc() {
        let (_ca, leaf) = ca_and_leaf(30);
        let s = cert_expiry_rfc3339(&leaf).unwrap();
        assert!(s.ends_with('Z'), "RFC3339 UTC expected, got {s}");
    }

    #[test]
    fn chain_verifies_when_leaf_signed_by_ca() {
        let (ca, leaf) = ca_and_leaf(365);
        assert_eq!(verify_cert_chain(&leaf, &ca), Ok(()));
    }

    #[test]
    fn chain_rejects_unrelated_ca() {
        let (_ca1, leaf) = ca_and_leaf(365);
        let (ca2, _leaf2) = ca_and_leaf(365);
        assert_eq!(
            verify_cert_chain(&leaf, &ca2),
            Err(CertError::UntrustedSignature)
        );
    }

    #[test]
    fn chain_accepts_bundle_with_matching_ca_anywhere() {
        let (ca1, leaf) = ca_and_leaf(365);
        let (ca2, _leaf2) = ca_and_leaf(365);
        let bundle = format!("{ca2}{ca1}");
        assert_eq!(verify_cert_chain(&leaf, &bundle), Ok(()));
    }

    #[test]
    fn rejects_non_pem_input() {
        assert_eq!(cert_expiry_days("not a cert"), Err(CertError::Pem));
        assert_eq!(
            verify_cert_chain("not a cert", "also not"),
            Err(CertError::Pem)
        );
    }
}
