//! `crypto` — WireGuard key helpers, key handling. OPEN crate (Part D §D.2).
//!
//! Intensity: **Critical** (CLAUDE.md T/A §). Every primitive is cited.
//! WireGuard node identity is a Curve25519 (X25519) keypair; the `wg` tools
//! encode the 32-byte keys as standard base64. We match that encoding exactly
//! so keys are interoperable with stock WireGuard. `[T:WireGuard-whitepaper §2]`

use base64::{engine::general_purpose::STANDARD, Engine as _};
use rand_core::OsRng; // [T:rand_core@0.6.4-OsRng] CSPRNG seeded from OS entropy (getrandom)
use x25519_dalek::{PublicKey, StaticSecret}; // [T:x25519-dalek@2.0.1] X25519 — RFC 7748

/// A WireGuard keypair, base64-encoded exactly as `wg genkey` / `wg pubkey` emit.
///
/// `private_b64` is **secret** — never log it. We deliberately do NOT derive
/// `Debug` so the private key cannot leak through accidental `{:?}` formatting.
#[derive(Clone)]
pub struct WgKeypair {
    /// Standard-base64 of the 32-byte private scalar (clamped per RFC 7748).
    pub private_b64: String,
    /// Standard-base64 of the 32-byte public key.
    pub public_b64: String,
}

/// Errors decoding/validating a stored private key.
#[derive(Debug, PartialEq, Eq)]
pub enum KeyError {
    /// Input was not valid standard base64.
    Decode,
    /// Decoded bytes were not exactly 32 bytes (a Curve25519 key).
    Length,
}

impl WgKeypair {
    /// Generate a fresh keypair from OS entropy.
    /// `[T:RFC-7748§5]` X25519 key generation. `[T:x25519-dalek@2.0.1-StaticSecret]`
    /// `StaticSecret::random_from_rng` clamps the scalar per RFC 7748 internally.
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        WgKeypair {
            private_b64: STANDARD.encode(secret.to_bytes()),
            public_b64: STANDARD.encode(public.to_bytes()),
        }
    }

    /// Re-derive the public key from a stored base64 private key (e.g. after a
    /// daemon restart). `[T:RFC-7748§5]` public = X25519(private, basepoint).
    pub fn public_from_private_b64(private_b64: &str) -> Result<String, KeyError> {
        let bytes = STANDARD.decode(private_b64).map_err(|_| KeyError::Decode)?;
        let arr: [u8; 32] = bytes.try_into().map_err(|_| KeyError::Length)?;
        let secret = StaticSecret::from(arr);
        Ok(STANDARD.encode(PublicKey::from(&secret).to_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // base64 of 32 bytes = 44 chars (incl. one '=' pad). [T:RFC-4648] base64 sizing.
    #[test]
    fn keypair_has_wireguard_shape() {
        let kp = WgKeypair::generate();
        assert_eq!(
            kp.private_b64.len(),
            44,
            "WG private key is base64 of 32 bytes"
        );
        assert_eq!(
            kp.public_b64.len(),
            44,
            "WG public key is base64 of 32 bytes"
        );
        assert!(kp.private_b64.ends_with('='));
        assert!(kp.public_b64.ends_with('='));
    }

    #[test]
    fn public_derivation_matches_generated() {
        let kp = WgKeypair::generate();
        let derived = WgKeypair::public_from_private_b64(&kp.private_b64).unwrap();
        assert_eq!(
            derived, kp.public_b64,
            "re-derived pubkey must equal original"
        );
    }

    #[test]
    fn fresh_keys_are_distinct() {
        let a = WgKeypair::generate();
        let b = WgKeypair::generate();
        assert_ne!(a.private_b64, b.private_b64, "CSPRNG must not repeat");
    }

    #[test]
    fn rejects_malformed_private_key() {
        assert_eq!(
            WgKeypair::public_from_private_b64("not valid base64 !!!"),
            Err(KeyError::Decode)
        );
        // "YWJj" = base64("abc") = 3 bytes ≠ 32.
        assert_eq!(
            WgKeypair::public_from_private_b64("YWJj"),
            Err(KeyError::Length)
        );
    }
}
