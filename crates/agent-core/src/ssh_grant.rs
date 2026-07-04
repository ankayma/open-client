//! ssh_grant — F-2 root-elevation grant (Part D f2 §H.4, Lát 3).
//!
//! Intensity: **Critical** (CLAUDE.md T/A §) — this is the token that authorizes
//! root, on a security path.
//!
//! The mechanism (§H.4): the client asks the control plane to elevate; the CP
//! evaluates authz (owner-implicit persona at F0, or an AdminAccessPolicy at F1+,
//! plus AAL step-up above F0) and, if allowed, returns a **signed grant** — NOT a
//! password, NOT a standing sudoers entry. The node's embedded server verifies the
//! CP signature and only then opens a **root** PTY, time-boxed to `expires_at`
//! (≤15', A.1.7) with an audit line, auto-dropped at expiry. `[T:A.1.15 + A.1.21 +
//! P.2]` The signature is Ed25519 on STABLE crypto (ed25519-dalek), independent of
//! the SSH transport's key handling.
//!
//! Trust root: the CP holds one Ed25519 elevation signing key; its public half is
//! distributed to nodes (fetched at `agent up`). A node verifies every grant
//! against that key — so a node grants root ONLY on the CP's say-so, never on its
//! own, and a stolen/forged token without the CP key is worthless.

use anyhow::{anyhow, bail, Result};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

/// Hard cap on a grant's lifetime — root is time-boxed (A.1.7). `[T:f2 §H.4]`
pub const MAX_TTL_SECS: i64 = 900; // 15 minutes

/// A CP-signed authorization to elevate to root on one node, for one device, for a
/// bounded window. The payload is what the CP signs; the node verifies it.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ElevationGrant {
    /// The node this grant is valid on (must match the serving node).
    pub node_id: String,
    /// The persona granted — "root" at F0 (owner-implicit). F1+ personas (SRE/DBA)
    /// ride the same field.
    pub persona: String,
    /// The POSIX login to land when elevated (typically "root").
    pub login: String,
    /// Fingerprint of the requesting device's mesh-SSH key — binds the grant to the
    /// device that asked, so a leaked token can't be replayed from another device.
    pub device_fp: String,
    /// Ledger correlation id for the elevation event.
    pub session_id: String,
    /// Unix seconds when issued.
    pub issued_at: i64,
    /// Unix seconds when the grant expires (≤ issued_at + MAX_TTL_SECS).
    pub expires_at: i64,
}

/// Wire token = `base64url(payload_json) "." base64url(sig)`. Compact, printable,
/// safe to carry in an SSH env var.
fn encode_token(payload: &[u8], sig: &[u8]) -> String {
    format!(
        "{}.{}",
        STANDARD_NO_PAD.encode(payload),
        STANDARD_NO_PAD.encode(sig)
    )
}

fn decode_token(token: &str) -> Result<(Vec<u8>, Vec<u8>)> {
    let (p, s) = token
        .split_once('.')
        .ok_or_else(|| anyhow!("malformed grant token"))?;
    let payload = STANDARD_NO_PAD
        .decode(p)
        .map_err(|_| anyhow!("grant payload not base64"))?;
    let sig = STANDARD_NO_PAD
        .decode(s)
        .map_err(|_| anyhow!("grant signature not base64"))?;
    Ok((payload, sig))
}

/// Signs grants. Lives on the CONTROL PLANE (the CP has its own copy of this logic;
/// this impl also lets the agent tests exercise a full round-trip).
pub struct GrantSigner {
    key: SigningKey,
}

impl GrantSigner {
    /// Build from a 32-byte Ed25519 seed (the CP's persisted signing key).
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            key: SigningKey::from_bytes(seed),
        }
    }

    /// The public verifying key, base64url — this is what the CP publishes to nodes.
    pub fn public_base64(&self) -> String {
        STANDARD_NO_PAD.encode(self.key.verifying_key().to_bytes())
    }

    /// Sign a grant into its wire token.
    pub fn sign(&self, grant: &ElevationGrant) -> Result<String> {
        let payload = serde_json::to_vec(grant).map_err(|e| anyhow!("encode grant: {e}"))?;
        let sig = self.key.sign(&payload);
        Ok(encode_token(&payload, &sig.to_bytes()))
    }
}

/// Verifies grants. Lives on the NODE (the embedded server). Holds the CP's public
/// elevation key.
#[derive(Clone)]
pub struct GrantVerifier {
    key: VerifyingKey,
    node_id: String,
}

impl GrantVerifier {
    /// Build from the CP's base64url public key + the id of the node we serve.
    pub fn new(cp_pubkey_base64: &str, node_id: impl Into<String>) -> Result<Self> {
        let raw = STANDARD_NO_PAD
            .decode(cp_pubkey_base64.trim())
            .map_err(|_| anyhow!("CP elevation pubkey not base64"))?;
        let bytes: [u8; 32] = raw
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("CP elevation pubkey must be 32 bytes"))?;
        let key = VerifyingKey::from_bytes(&bytes)
            .map_err(|e| anyhow!("bad CP elevation pubkey: {e}"))?;
        Ok(Self {
            key,
            node_id: node_id.into(),
        })
    }

    /// Verify a grant token at time `now` (unix secs). Checks, in order: the CP
    /// signature, that the grant is for THIS node, that it hasn't expired, and that
    /// its lifetime is within the TTL cap (rejects an over-long grant even if the CP
    /// mis-signed one). Returns the validated grant on success.
    pub fn verify(&self, token: &str, now: i64) -> Result<ElevationGrant> {
        let (payload, sig_bytes) = decode_token(token)?;
        let sig_arr: [u8; 64] = sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("grant signature must be 64 bytes"))?;
        let sig = Signature::from_bytes(&sig_arr);
        self.key
            .verify(&payload, &sig)
            .map_err(|_| anyhow!("grant signature does not verify against the CP key"))?;

        let grant: ElevationGrant =
            serde_json::from_slice(&payload).map_err(|e| anyhow!("decode grant: {e}"))?;

        if grant.node_id != self.node_id {
            bail!(
                "grant is for node {}, not this node {}",
                grant.node_id,
                self.node_id
            );
        }
        if now >= grant.expires_at {
            bail!("grant expired at {} (now {})", grant.expires_at, now);
        }
        if grant.expires_at.saturating_sub(grant.issued_at) > MAX_TTL_SECS {
            bail!("grant lifetime exceeds the {}s cap", MAX_TTL_SECS);
        }
        Ok(grant)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signer() -> GrantSigner {
        // Deterministic test seed (not a real key).
        GrantSigner::from_seed(&[7u8; 32])
    }

    fn grant(node: &str, issued: i64, ttl: i64) -> ElevationGrant {
        ElevationGrant {
            node_id: node.to_string(),
            persona: "root".to_string(),
            login: "root".to_string(),
            device_fp: "SHA256:abc".to_string(),
            session_id: "elev_1".to_string(),
            issued_at: issued,
            expires_at: issued + ttl,
        }
    }

    #[test]
    fn round_trip_valid() {
        let s = signer();
        let v = GrantVerifier::new(&s.public_base64(), "node_7").unwrap();
        let token = s.sign(&grant("node_7", 1000, 600)).unwrap();
        let g = v.verify(&token, 1100).expect("valid grant should verify");
        assert_eq!(g.node_id, "node_7");
        assert_eq!(g.persona, "root");
    }

    #[test]
    fn rejects_expired() {
        let s = signer();
        let v = GrantVerifier::new(&s.public_base64(), "node_7").unwrap();
        let token = s.sign(&grant("node_7", 1000, 600)).unwrap();
        let err = v.verify(&token, 1601).unwrap_err(); // 1000+600=1600 < 1601
        assert!(err.to_string().contains("expired"), "{err}");
    }

    #[test]
    fn rejects_wrong_node() {
        let s = signer();
        let v = GrantVerifier::new(&s.public_base64(), "node_7").unwrap();
        let token = s.sign(&grant("node_OTHER", 1000, 600)).unwrap();
        let err = v.verify(&token, 1100).unwrap_err();
        assert!(err.to_string().contains("not this node"), "{err}");
    }

    #[test]
    fn rejects_overlong_ttl() {
        let s = signer();
        let v = GrantVerifier::new(&s.public_base64(), "node_7").unwrap();
        // 1000s > 900s cap
        let token = s.sign(&grant("node_7", 1000, 1000)).unwrap();
        let err = v.verify(&token, 1100).unwrap_err();
        assert!(err.to_string().contains("cap"), "{err}");
    }

    #[test]
    fn rejects_forged_signature() {
        let real = signer();
        let attacker = GrantSigner::from_seed(&[9u8; 32]);
        // Verifier trusts the REAL CP key; attacker signs their own grant.
        let v = GrantVerifier::new(&real.public_base64(), "node_7").unwrap();
        let token = attacker.sign(&grant("node_7", 1000, 600)).unwrap();
        let err = v.verify(&token, 1100).unwrap_err();
        assert!(err.to_string().contains("does not verify"), "{err}");
    }

    #[test]
    fn rejects_tampered_payload() {
        let s = signer();
        let v = GrantVerifier::new(&s.public_base64(), "node_7").unwrap();
        let token = s.sign(&grant("node_7", 1000, 600)).unwrap();
        // Flip a char in the payload segment → signature no longer matches.
        let (p, sig) = token.split_once('.').unwrap();
        let mut pv: Vec<char> = p.chars().collect();
        pv[0] = if pv[0] == 'A' { 'B' } else { 'A' };
        let tampered = format!("{}.{}", pv.into_iter().collect::<String>(), sig);
        assert!(v.verify(&tampered, 1100).is_err());
    }
}
