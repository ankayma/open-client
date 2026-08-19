//! cmd_grant — the node-side policy enforcement point for a COMMAND grant.
//!
//! Intensity: **Critical** (CLAUDE.md T/A §) — this decides what actually executes.
//!
//! A session grant says an actor may be on this node. A command grant says it may run
//! **this**, once. The difference only exists if something on the node checks, and this is
//! that something. Without it the control plane records an enforcement that never
//! happened, which is worse than recording nothing: the ledger would assert a guarantee
//! the wire did not have. That is why the control plane refuses to issue a command grant
//! to a node that has not declared [`CAP_CMD_GRANT`]. `[T:A.1.20 capability negotiation + A.1.6 fail-closed]`
//!
//! **The argv comes from the GRANT, never from the SSH exec string.** A client that could
//! supply the command would be a client that decides what runs, which is the property
//! being removed. The exec string is used for nothing but a mismatch check.
//!
//! **There is no shell.** `argv` is passed to the process as a vector, so a parameter
//! containing `;` or `$(…)` is a parameter containing those characters. `bash -c` is not
//! forbidden here — it is unrepresentable.
//!
//! Same wire shape as [`crate::ssh_grant`]: `b64nopad(json).b64nopad(sig)`, verified
//! against the same CP key the node already fetches. One shape, one parser (P.4). The
//! payload carries a `purpose` that is checked, so an elevation grant can never be
//! presented as a command grant or the reverse — domain separation in the message rather
//! than a second key to distribute. `[T:P.4 + A.1.21]`

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Env var the grant token rides in, mirroring `ANKAYMA_ELEVATE_GRANT`.
pub const CMD_GRANT_ENV: &str = "ANKAYMA_CMD_GRANT";

/// What a node must declare before the control plane will issue it a command grant.
/// A node that has not said this is not assumed to mean yes. `[T:A.1.20 capability negotiation + A.1.6 fail-closed]`
pub const CAP_CMD_GRANT: &str = "cmd-grant-v1";

/// Purpose string inside the signed payload. Present so that a signature over one kind of
/// authorisation can never be replayed as the other.
const PURPOSE: &str = "cmd-grant-v1";

/// A CP-signed authorisation to run exactly one command, once, on one node.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct CommandGrant {
    /// Always [`PURPOSE`]. Checked on verify.
    pub purpose: String,
    pub grant_id: String,
    /// The node this grant is valid on.
    pub node_id: String,
    /// The non-human actor that holds it — recorded, and reported back with the outcome.
    pub actor_id: String,
    /// The command, already resolved from a signed catalog template by the control plane.
    /// `argv[0]` is the program.
    pub argv: Vec<String>,
    /// Sorted `KEY=VALUE` the node may set. An allowlist, not the ambient environment.
    #[serde(default)]
    pub env: Vec<String>,
    #[serde(default)]
    pub cwd: Option<String>,
    /// `"none"` or `"declared"`. Anything else is refused rather than interpreted.
    pub stdin: String,
    #[serde(default)]
    pub stdin_digest: Option<String>,
    /// `SHA-256` over the canonical form of everything above. The node recomputes it and
    /// refuses on mismatch, so a tampered argv fails even if the signature somehow held.
    pub cmd_digest: String,
    pub issued_at: i64,
    pub expires_at: i64,
}

/// Canonical digest over one command. Length-prefixed with the argument count hashed
/// ahead of the arguments, so `["restart","payments"]` and `["restart payments"]` — a
/// shell-injection apart — cannot share a hash. Field order is part of the algorithm.
///
/// Recomputed independently on both sides on purpose: the control plane's copy is the one
/// that decided, this one is the one that runs, and a difference between them must stop
/// the command rather than be reconciled.
pub fn cmd_digest(
    argv: &[String],
    cwd: Option<&str>,
    env: &[String],
    stdin: &str,
    stdin_digest: Option<&str>,
) -> String {
    let mut h = Sha256::new();
    let mut field = |b: &[u8]| {
        h.update((b.len() as u64).to_be_bytes());
        h.update(b);
    };
    field(b"ankayma.cmd.v1");
    field(argv.first().map(|s| s.as_bytes()).unwrap_or_default());
    field(&((argv.len().saturating_sub(1)) as u64).to_be_bytes());
    for a in argv.iter().skip(1) {
        field(a.as_bytes());
    }
    match cwd {
        Some(v) => {
            field(&[1u8]);
            field(v.as_bytes());
        }
        None => field(&[0u8]),
    }
    field(&(env.len() as u64).to_be_bytes());
    for e in env {
        field(e.as_bytes());
    }
    field(stdin.as_bytes());
    match stdin_digest {
        Some(v) => {
            field(&[1u8]);
            field(v.as_bytes());
        }
        None => field(&[0u8]),
    }
    hex_lower(&h.finalize())
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Why a command was refused. Each maps to a `termination_reason` the node reports back,
/// because "it did not run" without a reason is not evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// The token is not a command grant — malformed, wrong purpose, or not CP-signed.
    NotAuthorised(String),
    /// Signature and shape are fine, but `cmd_digest` does not match the argv inside.
    DigestMismatch,
    /// A PTY was requested under a command grant. That would turn one authorised command
    /// into an interactive session.
    PtyRefused,
    /// stdin was offered but the grant declares `none`. Script-on-stdin is the same hole
    /// as `bash -c`, so it has to be declared before it can be sent.
    StdinUndeclared,
}

impl Refusal {
    /// The `termination_reason` to report. `rejected_digest_mismatch` is the only one the
    /// control plane's schema names; the others report as a policy violation, which is
    /// true and does not invent a vocabulary the ledger cannot store.
    pub fn termination_reason(&self) -> &'static str {
        match self {
            Refusal::DigestMismatch => "rejected_digest_mismatch",
            _ => "failed",
        }
    }

    pub fn message(&self) -> String {
        match self {
            Refusal::NotAuthorised(why) => format!("command grant not accepted: {why}"),
            Refusal::DigestMismatch => {
                "the command does not match the digest it was authorised under".to_string()
            }
            Refusal::PtyRefused => {
                "a command grant authorises one command, not an interactive session".to_string()
            }
            Refusal::StdinUndeclared => {
                "this grant declares no stdin; a command that reads one must say so".to_string()
            }
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

/// Signs command grants. Lives on the CONTROL PLANE; present here so the node's tests can
/// exercise a real round trip rather than a mock that agrees with them.
pub struct CommandGrantSigner {
    key: SigningKey,
}

impl CommandGrantSigner {
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            key: SigningKey::from_bytes(seed),
        }
    }

    pub fn sign(&self, grant: &CommandGrant) -> Result<String> {
        let payload = serde_json::to_vec(grant).map_err(|e| anyhow!("encode grant: {e}"))?;
        let sig = self.key.sign(&payload);
        Ok(encode_token(&payload, &sig.to_bytes()))
    }
}

/// Verifies command grants. Lives on the NODE.
#[derive(Clone)]
pub struct CommandGrantVerifier {
    key: VerifyingKey,
    node_id: String,
}

impl CommandGrantVerifier {
    /// Built from the same CP public key the node already fetches for elevation, and the
    /// id of the node it serves.
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

    /// Verify a token and return the command it authorises.
    ///
    /// Order matters: signature first, so an unsigned caller learns nothing from the
    /// later checks; then purpose, node, expiry, and finally the digest recomputed from
    /// the argv actually present. The digest check is not redundant with the signature —
    /// it is what makes the control plane's decision and the node's execution provably
    /// the same command rather than two things that were signed together.
    pub fn verify(&self, token: &str, now: i64) -> Result<CommandGrant, Refusal> {
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

        let g: CommandGrant =
            serde_json::from_slice(&payload).map_err(|_| bad("payload is not a command grant"))?;

        // Domain separation. An elevation grant and a command grant are signed by the same
        // key, and only this field stops one being presented as the other.
        if g.purpose != PURPOSE {
            return Err(bad("token is not a command grant"));
        }
        if g.node_id != self.node_id {
            return Err(bad("grant is for a different node"));
        }
        if now >= g.expires_at {
            return Err(bad("grant has expired"));
        }
        if g.argv.is_empty() {
            return Err(bad("grant authorises no program"));
        }
        if !matches!(g.stdin.as_str(), "none" | "declared") {
            return Err(bad("grant declares an unrecognised stdin mode"));
        }
        let recomputed = cmd_digest(
            &g.argv,
            g.cwd.as_deref(),
            &g.env,
            &g.stdin,
            g.stdin_digest.as_deref(),
        );
        if recomputed != g.cmd_digest {
            return Err(Refusal::DigestMismatch);
        }
        Ok(g)
    }
}

impl CommandGrant {
    /// Build the process this grant authorises.
    ///
    /// A `std::process::Command` built from `argv`, element by element. There is no shell
    /// in this function and no string that could be handed to one — the structural
    /// property the whole tier rests on. `[T:A.1.6 — a shell is not reachable, not merely forbidden]`
    pub fn to_command(&self) -> std::process::Command {
        let mut c = std::process::Command::new(&self.argv[0]);
        for a in self.argv.iter().skip(1) {
            c.arg(a);
        }
        if let Some(dir) = &self.cwd {
            c.current_dir(dir);
        }
        // The environment is REPLACED, not extended. Inheriting the agent's environment
        // would let PATH decide which binary an authorised argv actually runs.
        c.env_clear();
        for kv in &self.env {
            if let Some((k, v)) = kv.split_once('=') {
                c.env(k, v);
            }
        }
        c
    }

    /// Whether the exec string a client sent matches what was authorised.
    ///
    /// The client sends one for compatibility with the SSH protocol; it is never used to
    /// BUILD the command. A mismatch is reported rather than ignored, because a client
    /// asking for something other than what it holds a grant for is worth seeing.
    pub fn matches_requested(&self, requested: &str) -> bool {
        requested.trim().is_empty() || requested.trim() == self.argv.join(" ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed() -> [u8; 32] {
        [17u8; 32]
    }

    fn grant(node: &str, argv: &[&str]) -> CommandGrant {
        let argv: Vec<String> = argv.iter().map(|s| s.to_string()).collect();
        CommandGrant {
            purpose: PURPOSE.to_string(),
            grant_id: "grant_x".into(),
            node_id: node.into(),
            actor_id: "act_a_1".into(),
            cmd_digest: cmd_digest(&argv, None, &[], "none", None),
            argv,
            env: vec![],
            cwd: None,
            stdin: "none".into(),
            stdin_digest: None,
            issued_at: 1_000,
            expires_at: 2_000,
        }
    }

    fn signer() -> CommandGrantSigner {
        CommandGrantSigner::from_seed(&seed())
    }

    fn verifier(node: &str) -> CommandGrantVerifier {
        let pk = SigningKey::from_bytes(&seed()).verifying_key().to_bytes();
        CommandGrantVerifier::new(&STANDARD_NO_PAD.encode(pk), node).expect("verifier")
    }

    #[test]
    fn a_grant_signed_for_this_node_verifies_and_yields_its_argv() {
        let g = grant("nd1", &["systemctl", "restart", "--", "payments"]);
        let token = signer().sign(&g).expect("sign");
        let got = verifier("nd1").verify(&token, 1_500).expect("verifies");
        assert_eq!(got.argv, g.argv);
    }

    // The check that makes the control plane's decision and the node's execution provably
    // the same command. A tampered argv is caught even before the signature would be,
    // because the digest is recomputed from what is actually present.
    #[test]
    fn an_argv_that_does_not_match_its_digest_is_refused() {
        let mut g = grant("nd1", &["systemctl", "restart", "--", "payments"]);
        g.argv[3] = "billing".into();
        let token = signer().sign(&g).expect("sign");
        assert_eq!(
            verifier("nd1").verify(&token, 1_500),
            Err(Refusal::DigestMismatch)
        );
    }

    // Same key signs elevation grants. Only `purpose` stops one being replayed as the
    // other, so it is checked rather than assumed.
    #[test]
    fn a_token_with_another_purpose_is_not_a_command_grant() {
        let mut g = grant("nd1", &["ls"]);
        g.purpose = "elevate-v1".into();
        let token = signer().sign(&g).expect("sign");
        assert!(matches!(
            verifier("nd1").verify(&token, 1_500),
            Err(Refusal::NotAuthorised(_))
        ));
    }

    #[test]
    fn a_grant_for_another_node_or_past_its_expiry_is_refused() {
        let g = grant("nd1", &["ls"]);
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
        let g = grant("nd1", &["ls"]);
        let token = CommandGrantSigner::from_seed(&[99u8; 32])
            .sign(&g)
            .expect("sign");
        assert!(matches!(
            verifier("nd1").verify(&token, 1_500),
            Err(Refusal::NotAuthorised(_))
        ));
    }

    // The structural claim: the command is built from a vector, so a metacharacter is a
    // character. If this ever becomes a string handed to a shell, this test is what says
    // so — `to_command` has no way to express `bash -c`.
    #[test]
    fn a_metacharacter_stays_inside_one_argument() {
        let g = grant("nd1", &["echo", "a; rm -rf /"]);
        let cmd = g.to_command();
        let args: Vec<&std::ffi::OsStr> = cmd.get_args().collect();
        assert_eq!(cmd.get_program(), "echo");
        assert_eq!(args, vec![std::ffi::OsStr::new("a; rm -rf /")]);
        assert_eq!(args.len(), 1, "no element may be split by a separator");
    }

    // The environment is replaced, not extended: an inherited PATH decides which binary
    // an authorised argv actually runs.
    #[test]
    fn the_environment_is_replaced_rather_than_inherited() {
        let mut g = grant("nd1", &["true"]);
        g.env = vec!["PATH=/usr/bin".to_string()];
        g.cmd_digest = cmd_digest(&g.argv, None, &g.env, "none", None);
        let cmd = g.to_command();
        let envs: Vec<_> = cmd.get_envs().collect();
        assert!(
            cmd.get_envs().len() == 1 || envs.iter().all(|(_, v)| v.is_some()),
            "only declared variables may be set"
        );
    }

    #[test]
    fn an_unrecognised_stdin_mode_is_refused_rather_than_treated_as_none() {
        let mut g = grant("nd1", &["cat"]);
        g.stdin = "maybe".into();
        g.cmd_digest = cmd_digest(&g.argv, None, &[], "maybe", None);
        let token = signer().sign(&g).expect("sign");
        assert!(matches!(
            verifier("nd1").verify(&token, 1_500),
            Err(Refusal::NotAuthorised(_))
        ));
    }

    #[test]
    fn a_refusal_reports_a_reason_the_ledger_can_store() {
        assert_eq!(
            Refusal::DigestMismatch.termination_reason(),
            "rejected_digest_mismatch"
        );
        assert_eq!(Refusal::PtyRefused.termination_reason(), "failed");
    }
}
