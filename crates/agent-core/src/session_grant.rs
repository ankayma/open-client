//! session_grant — the node-side policy enforcement point for an AGENT SESSION grant.
//!
//! Intensity: **Critical** (CLAUDE.md T/A §) — this decides who may open a shell.
//!
//! The counterpart to [`crate::cmd_grant`] at the broad end of the same tier split: a
//! command grant authorises one command, once; a session grant authorises an AGENT
//! IDENTITY — not the human who owns the node — to open a session (interactive or
//! one-shot exec) on exactly one node, until it expires. Both are how a non-human actor
//! reaches this node at all; `Authorizer::TrustOverlay` answers a different question
//! ("is this key on the overlay + roster") that says nothing about WHICH identity is
//! connecting or for how long.
//!
//! **Only checked when the connecting client sets [`SESSION_GRANT_ENV`].** A human's own
//! `agent ssh <node>` never sets it, so that path is byte-for-byte unchanged — this is
//! additive enforcement for agent-kind connections, not a new gate on every connection.
//! A client that sets the env var but whose node has no verifier configured is refused,
//! never silently waved through: a token presented to a node that cannot check it would
//! let the control plane's mint-time promise go unenforced. `[T:A.1.6 fail-closed]`
//!
//! Same wire shape as [`crate::ssh_grant`] and [`crate::cmd_grant`]:
//! `b64nopad(json).b64nopad(sig)`, verified against the same CP key the node already
//! fetches. One shape, one parser, domain-separated by `purpose` rather than a second
//! key. `[T:P.4 + A.1.21]`

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

/// Env var the grant token rides in, mirroring `ANKAYMA_ELEVATE_GRANT`/`ANKAYMA_CMD_GRANT`.
pub const SESSION_GRANT_ENV: &str = "ANKAYMA_SESSION_GRANT";

/// What a node must declare before the control plane will issue an agent-session grant
/// scoped to it. Silence is not consent. `[T:A.1.6 fail-closed]`
pub const CAP_SESSION_GRANT: &str = "agent-session-v1";

/// Purpose string inside the signed payload — stops an elevation or command grant from
/// being replayed as a session grant, since all three share one signing key.
const PURPOSE: &str = "agent-session-v1";

/// A CP-signed authorisation for one agent identity to hold a session on one node.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct SessionGrant {
    /// Always [`PURPOSE`]. Checked on verify.
    pub purpose: String,
    pub grant_id: String,
    /// The node this grant is valid on.
    pub node_id: String,
    /// The non-human actor that holds it.
    pub actor_id: String,
    pub issued_at: i64,
    pub expires_at: i64,
}

/// Why a session was refused. Mirrors [`crate::cmd_grant::Refusal`]'s shape; kept as its
/// own type rather than shared because the two authorise different things and a refusal
/// reason here should never be mistaken for one about a command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// The token is not a session grant — malformed, wrong purpose, or not CP-signed.
    NotAuthorised(String),
}

impl Refusal {
    pub fn message(&self) -> String {
        match self {
            Refusal::NotAuthorised(why) => format!("session grant not accepted: {why}"),
        }
    }
}

fn encode_token(payload: &[u8], sig: &[u8]) -> String {
    format!(
        "{}.{}",
        STANDARD_NO_PAD.encode(payload),
        STANDARD_NO_PAD.encode(sig)
    )
}

/// Signs session grants. Lives on the CONTROL PLANE; present here so the node's tests can
/// exercise a real round trip rather than a mock that agrees with them.
pub struct SessionGrantSigner {
    key: SigningKey,
}

impl SessionGrantSigner {
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            key: SigningKey::from_bytes(seed),
        }
    }

    pub fn sign(&self, grant: &SessionGrant) -> Result<String> {
        let payload = serde_json::to_vec(grant).map_err(|e| anyhow!("encode grant: {e}"))?;
        let sig = self.key.sign(&payload);
        Ok(encode_token(&payload, &sig.to_bytes()))
    }
}

/// Verifies session grants. Lives on the NODE.
#[derive(Clone)]
pub struct SessionGrantVerifier {
    key: VerifyingKey,
    node_id: String,
}

impl SessionGrantVerifier {
    /// Built from the same CP public key the node already fetches for elevation and
    /// command grants, and the id of the node it serves.
    pub fn new(cp_pubkey_base64: &str, node_id: impl Into<String>) -> Result<Self> {
        let raw = STANDARD_NO_PAD
            .decode(cp_pubkey_base64.trim())
            .map_err(|_| anyhow!("CP pubkey not base64"))?;
        let bytes: [u8; 32] = raw
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("CP pubkey must be 32 bytes"))?;
        Ok(Self {
            key: VerifyingKey::from_bytes(&bytes).map_err(|e| anyhow!("bad CP pubkey: {e}"))?,
            node_id: node_id.into(),
        })
    }

    /// Verify a token and return the session it authorises. Signature first, so an
    /// unsigned caller learns nothing from the later checks.
    pub fn verify(&self, token: &str, now: i64) -> Result<SessionGrant, Refusal> {
        let bad = |m: &str| Refusal::NotAuthorised(m.to_string());

        let (p, s) = token
            .split_once('.')
            .ok_or_else(|| bad("malformed token"))?;
        let payload = STANDARD_NO_PAD
            .decode(p)
            .map_err(|_| bad("payload not base64"))?;
        let sig_bytes: [u8; 64] = STANDARD_NO_PAD
            .decode(s)
            .map_err(|_| bad("signature not base64"))?
            .as_slice()
            .try_into()
            .map_err(|_| bad("signature must be 64 bytes"))?;
        self.key
            .verify(&payload, &Signature::from_bytes(&sig_bytes))
            .map_err(|_| bad("signature does not verify against the CP key"))?;

        let g: SessionGrant =
            serde_json::from_slice(&payload).map_err(|_| bad("payload is not a session grant"))?;

        // Domain separation. The same key signs elevation and command grants too, and
        // only this field stops one being presented as another.
        if g.purpose != PURPOSE {
            return Err(bad("token is not a session grant"));
        }
        if g.node_id != self.node_id {
            return Err(bad("grant is for a different node"));
        }
        if now >= g.expires_at {
            return Err(bad("grant has expired"));
        }
        Ok(g)
    }
}

/// An enrolled AGENT IDENTITY's own signing key — the CLIENT-side counterpart to
/// [`SessionGrantVerifier`]. Lives here, not on the daemon/CLI side, for the same
/// dependency reason `machine_key`/`ssh_grant` do: this crate already carries
/// `ed25519-dalek`, and a signing key is exactly the kind of primitive that belongs
/// in the OPEN domain crate rather than duplicated per binary. `[T:A.1.21]`
///
/// Distinct from [`crate::machine_key::MachineKey`] on purpose: a machine key
/// identifies the PHYSICAL DEVICE running the daemon; this identifies the AGENT
/// IDENTITY a `--as` handle was enrolled under, and one device can hold several of
/// the latter (`claude-1`, `claude-2`, …) that must never be confused with each
/// other or with the device's own machine key.
pub struct AgentSessionKey {
    signing: SigningKey,
}

impl AgentSessionKey {
    /// Reuse the key at `path`, or generate and persist one (0600, mirrors
    /// `machine_key`'s load-or-create shape).
    pub fn load_or_create(path: &std::path::Path) -> Result<Self> {
        if let Ok(text) = std::fs::read_to_string(path) {
            let seed: [u8; 32] = STANDARD_NO_PAD
                .decode(text.trim())
                .map_err(|e| anyhow!("{} is not base64: {e}", path.display()))?
                .try_into()
                .map_err(|_| anyhow!("{} is not a 32-byte seed", path.display()))?;
            return Ok(Self {
                signing: SigningKey::from_bytes(&seed),
            });
        }
        let mut seed = [0u8; 32];
        use rand::RngCore as _;
        rand::rng().fill_bytes(&mut seed);
        write_seed_0600(path, &seed).map_err(|e| anyhow!("persist {}: {e}", path.display()))?;
        Ok(Self {
            signing: SigningKey::from_bytes(&seed),
        })
    }

    /// Base64 (no pad) of the raw 32-byte Ed25519 public key — what the control plane
    /// stores as `nodes.agent_session_pubkey` at enrollment and matches every later
    /// call against.
    pub fn public_b64(&self) -> String {
        STANDARD_NO_PAD.encode(self.signing.verifying_key().to_bytes())
    }

    /// A proof binding this signature to exactly one node id — the payload
    /// `anchor::resolve_anchor` (control plane) verifies before minting a session
    /// grant. Same wire shape as `machine_key`/`ssh_grant`: `b64nopad(json).b64nopad(sig)`.
    /// `[T:P.4]`
    pub fn proof(&self, self_node_id: &str, issued_at: i64) -> Result<String> {
        #[derive(Serialize)]
        struct Payload<'a> {
            agent_pubkey: &'a str,
            self_node_id: &'a str,
            issued_at: i64,
        }
        let agent_pubkey = self.public_b64();
        let payload = Payload {
            agent_pubkey: &agent_pubkey,
            self_node_id,
            issued_at,
        };
        let bytes = serde_json::to_vec(&payload).map_err(|e| anyhow!("encode proof: {e}"))?;
        let sig = self.signing.sign(&bytes);
        Ok(format!(
            "{}.{}",
            STANDARD_NO_PAD.encode(&bytes),
            STANDARD_NO_PAD.encode(sig.to_bytes())
        ))
    }
}

fn write_seed_0600(path: &std::path::Path, seed: &[u8; 32]) -> std::io::Result<()> {
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

    fn seed() -> [u8; 32] {
        [19u8; 32]
    }

    fn grant(node: &str) -> SessionGrant {
        SessionGrant {
            purpose: PURPOSE.to_string(),
            grant_id: "grant_x".into(),
            node_id: node.into(),
            actor_id: "act_a_1".into(),
            issued_at: 1_000,
            expires_at: 2_000,
        }
    }

    fn signer() -> SessionGrantSigner {
        SessionGrantSigner::from_seed(&seed())
    }

    fn verifier(node: &str) -> SessionGrantVerifier {
        let pk = SigningKey::from_bytes(&seed()).verifying_key().to_bytes();
        SessionGrantVerifier::new(&STANDARD_NO_PAD.encode(pk), node).expect("verifier")
    }

    #[test]
    fn a_grant_signed_for_this_node_verifies() {
        let g = grant("nd1");
        let token = signer().sign(&g).expect("sign");
        let got = verifier("nd1").verify(&token, 1_500).expect("verifies");
        assert_eq!(got.actor_id, g.actor_id);
    }

    // Same key signs elevation and command grants. Only `purpose` stops one being
    // replayed as a session grant, so it is checked rather than assumed.
    #[test]
    fn a_token_with_another_purpose_is_not_a_session_grant() {
        let mut g = grant("nd1");
        g.purpose = "cmd-grant-v1".into();
        let token = signer().sign(&g).expect("sign");
        assert!(matches!(
            verifier("nd1").verify(&token, 1_500),
            Err(Refusal::NotAuthorised(_))
        ));
    }

    #[test]
    fn a_grant_for_another_node_or_past_its_expiry_is_refused() {
        let g = grant("nd1");
        let token = signer().sign(&g).expect("sign");
        assert!(matches!(
            verifier("nd2").verify(&token, 1_500),
            Err(Refusal::NotAuthorised(_))
        ));
        assert!(matches!(
            verifier("nd1").verify(&token, 2_000),
            Err(Refusal::NotAuthorised(_))
        ));
    }

    #[test]
    fn a_forged_signature_is_refused() {
        let g = grant("nd1");
        let token = SessionGrantSigner::from_seed(&[88u8; 32])
            .sign(&g)
            .expect("sign");
        assert!(matches!(
            verifier("nd1").verify(&token, 1_500),
            Err(Refusal::NotAuthorised(_))
        ));
    }

    #[test]
    fn a_tampered_payload_fails_the_signature() {
        let g = grant("nd1");
        let token = signer().sign(&g).expect("sign");
        let (payload_b64, sig_b64) = token.split_once('.').unwrap();
        let mut bytes = STANDARD_NO_PAD.decode(payload_b64).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        let tampered = format!("{}.{sig_b64}", STANDARD_NO_PAD.encode(&bytes));
        assert!(matches!(
            verifier("nd1").verify(&tampered, 1_500),
            Err(Refusal::NotAuthorised(_))
        ));
    }
}
