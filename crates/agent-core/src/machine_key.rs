//! machine_key — this device's stable identity at enrollment.
//!
//! Intensity: **Critical** (CLAUDE.md T/A §) — the private key here is what lets this
//! device, and only this device, re-point its node at a new WireGuard key.
//!
//! A node used to be identified by its WireGuard public key, which lives in
//! `agent.json`. Every way that file could be lost — an unwritable state dir, a
//! corrupt write, a sign-out, a reinstall — made the next enrollment look like a
//! brand-new device to the control plane, and the tenant's roster filled with ghosts
//! of one machine.
//!
//! So identity moves to a **separate, longer-lived key**: a machine key, generated
//! once and never rotated, alongside the WireGuard key that rotates freely. This is
//! Tailscale's machine-key/node-key split.
//! `[T:tailscale.com/kb/1010/node-keys — "Generated when Tailscale is first
//! installed", "Identify the physical device", "Cannot be rotated"]`
//!
//! **Randomly generated, not derived from the hardware.** Deriving a device id from
//! machine attributes is what Apple's policy calls fingerprinting and forbids
//! outright, what Android's own guidance argues against, and what systemd declines to
//! do even for `/etc/machine-id` — which is itself a random value, and one its man
//! page says must never be sent over a network. Random-and-stored is the pattern the
//! platforms converged on. `[T:developer.apple.com/app-store/user-privacy-and-data-use
//! · developer.android.com/identity/user-data-ids · man 5 machine-id]`
//!
//! **A reinstall is a new device, and that is correct.** Losing this file loses the
//! identity; Tailscale behaves the same way. Recovering it would require the
//! fingerprinting the platforms forbid. Orphaned nodes are cleaned up from the roster
//! instead. `[T:P.3]`
//!
//! **A cloned disk image is one device.** Every clone inherits this file and claims
//! the same node, rotating its key over each other. systemd documents the identical
//! hazard for `/etc/machine-id` and the identical remedy: strip it from the image so
//! each instance generates its own on first boot. Do the same with `machine.key`; the
//! control plane's flap detector is the net for when nobody did.
//! `[T:systemd.io/BUILDING_IMAGES]`

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use ed25519_dalek::{Signer, SigningKey};
use rand::RngCore;
use serde::Serialize;
use std::path::{Path, PathBuf};

/// Filename inside the agent state directory, beside `agent.json`.
const MACHINE_KEY_FILE: &str = "machine.key";

/// What the device signs. The control plane verifies the signature over these exact
/// bytes, then reads the fields — so field order is ours to choose, but every field
/// the server binds on must be here or the signature secures nothing.
#[derive(Serialize)]
struct ProofPayload<'a> {
    machine_pubkey: &'a str,
    /// The WireGuard key this enrollment claims. Signing it is what stops a captured
    /// proof from being replayed onto a request that swaps in a different key.
    public_key: &'a str,
    issued_at: i64,
}

/// This device's enrollment identity. The private half never leaves the process.
pub struct MachineKey {
    signing: SigningKey,
}

impl MachineKey {
    /// Reuse the key in `dir/machine.key`, or generate and persist one.
    ///
    /// Deliberately does NOT live in `agent.json`: sign-out deletes that file (the
    /// mesh identity is tenant-bound), while the machine key outlives every tenant
    /// this device ever joins. Deleting it would recreate the duplicate-node bug at
    /// the next sign-in.
    pub fn load_or_create(dir: &Path) -> Result<Self> {
        let path = key_path(dir);
        if let Ok(text) = std::fs::read_to_string(&path) {
            let seed: [u8; 32] = STANDARD_NO_PAD
                .decode(text.trim())
                .map_err(|e| anyhow!("machine.key is not base64: {e}"))?
                .try_into()
                .map_err(|_| anyhow!("machine.key is not a 32-byte seed"))?;
            return Ok(Self {
                signing: SigningKey::from_bytes(&seed),
            });
        }

        // `rand::rng()` is a CSPRNG. `[T:rand@0.9-rng]`
        let mut seed = [0u8; 32];
        rand::rng().fill_bytes(&mut seed);
        let key = Self::from_seed(&seed);
        write_seed(&path, &seed).with_context(|| format!("persist {}", path.display()))?;
        Ok(key)
    }

    fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            signing: SigningKey::from_bytes(seed),
        }
    }

    /// Base64 (no pad) of the raw 32-byte Ed25519 public key — the form the control
    /// plane stores and matches on.
    pub fn public_b64(&self) -> String {
        STANDARD_NO_PAD.encode(self.signing.verifying_key().to_bytes())
    }

    /// A proof that this device is enrolling `public_key`, as
    /// `b64nopad(payload_json).b64nopad(signature)`. Same wire shape as `ssh_grant`
    /// — one token format in this codebase, not two. `[T:P.4]`
    pub fn proof(&self, public_key: &str, issued_at: i64) -> Result<String> {
        let machine_pubkey = self.public_b64();
        let payload = ProofPayload {
            machine_pubkey: &machine_pubkey,
            public_key,
            issued_at,
        };
        let bytes = serde_json::to_vec(&payload).context("serialize machine proof")?;
        let sig = self.signing.sign(&bytes);
        Ok(format!(
            "{}.{}",
            STANDARD_NO_PAD.encode(&bytes),
            STANDARD_NO_PAD.encode(sig.to_bytes())
        ))
    }

    /// Proof stamped with the current wall clock. The control plane rejects proofs
    /// far from its own clock, so a badly-set device clock surfaces as an enrollment
    /// error rather than silent misbehaviour.
    pub fn proof_now(&self, public_key: &str) -> Result<String> {
        self.proof(public_key, unix_now_secs())
    }
}

pub fn key_path(dir: &Path) -> PathBuf {
    dir.join(MACHINE_KEY_FILE)
}

fn unix_now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// 0600: the seed authorises rotating this node's WireGuard key. Another local user
/// holding it could re-point the node at their own key. Mirrors `agent.json`.
fn write_seed(path: &Path, seed: &[u8; 32]) -> std::io::Result<()> {
    use std::io::Write as _;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    // mode() applies only on create; tighten an older file written before this code.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    f.write_all(STANDARD_NO_PAD.encode(seed).as_bytes())?;
    f.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ankayma-mk-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        dir
    }

    // The property the whole design rests on: the identity outlives the process.
    #[test]
    fn the_key_is_generated_once_and_reused() {
        let dir = scratch("reuse");
        let first = MachineKey::load_or_create(&dir).expect("create");
        let second = MachineKey::load_or_create(&dir).expect("reuse");
        assert_eq!(first.public_b64(), second.public_b64());
    }

    // Two devices are two identities. A shared constant here would collapse the whole
    // tenant onto one node.
    #[test]
    fn separate_directories_get_separate_identities() {
        let a = MachineKey::load_or_create(&scratch("a")).expect("create");
        let b = MachineKey::load_or_create(&scratch("b")).expect("create");
        assert_ne!(a.public_b64(), b.public_b64());
    }

    #[cfg(unix)]
    #[test]
    fn the_seed_is_written_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = scratch("perms");
        MachineKey::load_or_create(&dir).expect("create");
        let mode = std::fs::metadata(key_path(&dir))
            .expect("machine.key exists")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "machine.key authorises key rotation");
    }

    // The proof must be verifiable by the control plane's half of this protocol:
    // signature over the payload bytes, payload naming the enrolled WireGuard key.
    #[test]
    fn the_proof_is_a_signature_over_the_payload_it_carries() {
        use ed25519_dalek::{Signature, VerifyingKey};

        let key = MachineKey::load_or_create(&scratch("proof")).expect("create");
        let token = key.proof("wg-key", 1_700_000_000).expect("sign");

        let (payload_b64, sig_b64) = token.split_once('.').expect("two parts");
        let payload = STANDARD_NO_PAD.decode(payload_b64).expect("payload b64");
        let sig: [u8; 64] = STANDARD_NO_PAD
            .decode(sig_b64)
            .expect("sig b64")
            .try_into()
            .expect("64 bytes");

        let pk: [u8; 32] = STANDARD_NO_PAD
            .decode(key.public_b64())
            .unwrap()
            .try_into()
            .unwrap();
        VerifyingKey::from_bytes(&pk)
            .unwrap()
            .verify_strict(&payload, &Signature::from_bytes(&sig))
            .expect("control plane accepts this proof");

        let v: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!(v["public_key"], "wg-key");
        assert_eq!(v["machine_pubkey"], key.public_b64());
        assert_eq!(v["issued_at"], 1_700_000_000);
    }

    // Interop vector. The control plane verifies these exact bytes, in another repo
    // that cannot import this code, so the two halves are pinned to each other by a
    // constant rather than by hope. The same literal appears in the control plane's
    // `machine_key` tests; if either side changes the payload, both go red.
    //
    // Seed [7u8; 32], WireGuard key "wg-public-key-b64", issued_at 1000.
    #[test]
    fn the_wire_format_matches_the_control_planes_verifier() {
        let key = MachineKey::from_seed(&[7u8; 32]);
        let token = key.proof("wg-public-key-b64", 1_000).expect("sign");
        assert_eq!(token, GOLDEN_PROOF, "enrollment wire format changed");
        assert_eq!(key.public_b64(), GOLDEN_MACHINE_PUBKEY);
    }

    const GOLDEN_MACHINE_PUBKEY: &str = "6kpsY+KcUgq+9VB7Ey7F+ZVHdq6+vnuSQh7qaRRG0iw";
    const GOLDEN_PROOF: &str = "eyJtYWNoaW5lX3B1YmtleSI6IjZrcHNZK0tjVWdxKzlWQjdFeTdGK1pWSGRxNit2bnVTUWg3cWFSUkcwaXciLCJwdWJsaWNfa2V5Ijoid2ctcHVibGljLWtleS1iNjQiLCJpc3N1ZWRfYXQiOjEwMDB9.cLbNYpkgYnMlTL3ZfVITUZZzaTRm/BPaC2/1FkhtUrYpIZ2LnunBtlYvDL29VEECb1sUlj4AhALILg+qZKaQAg";

    // A corrupt file must fail loudly. Silently regenerating would mint a new device
    // identity and, with it, the duplicate node this key exists to prevent.
    #[test]
    fn a_corrupt_seed_is_an_error_not_a_silent_new_identity() {
        let dir = scratch("corrupt");
        std::fs::write(key_path(&dir), b"not-base64!!").expect("write");
        assert!(MachineKey::load_or_create(&dir).is_err());

        std::fs::write(key_path(&dir), STANDARD_NO_PAD.encode(b"too-short")).expect("write");
        assert!(MachineKey::load_or_create(&dir).is_err());
    }
}
