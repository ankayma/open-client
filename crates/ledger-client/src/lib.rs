//! `ledger-client` — verify an Ankayma audit ledger **without the control plane**.
//!
//! OPEN crate (Part D §D.2). Intensity: **Critical** — every claim this crate makes is a
//! claim a customer will repeat to their auditor.
//!
//! `[T:A.1.4]` says the agent is open so a customer can audit it. An audit ledger the
//! customer can only check *by asking the vendor* is not evidence, it is a promise with
//! extra steps. This crate is the other half: given one event, one proof and one published
//! checkpoint, the verification is arithmetic that runs on the customer's machine.
//!
//! **Deliberately a second implementation.** It shares no code with the control plane. The
//! algorithms are public standards — RFC 6962 for the tree, C2SP `tlog-checkpoint` and
//! `signed-note` for the checkpoint — so re-deriving them here is not duplication, it is
//! the independence that makes a disagreement between the two meaningful. A verifier that
//! called back into the prover's code could only ever agree with it.
//!
//! # What each check proves
//!
//! | Check | Proves | Does NOT prove |
//! |---|---|---|
//! | [`verify_inclusion`] | this event was in the tree at that size | the tree is the one you were shown before |
//! | [`verify_consistency`] | the log only grew; no history was rewritten | anyone else has seen it |
//! | [`Checkpoint::verify_signature`] | the named key signed these bytes | that key belongs to the vendor |
//!
//! The third gap is what a witness closes, and what a root-issued certificate closes for
//! the vendor's own key. Both are stated in the control plane's response rather than
//! assumed here. `[T:P.3]`

#![forbid(unsafe_code)]

use base64::{engine::general_purpose::STANDARD, Engine as _};
use sha2::{Digest, Sha256};

/// Why a verification failed. Every variant is a distinct thing to tell a user, because
/// "verification failed" with no reason is what makes people stop verifying.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    /// The note is not a checkpoint: missing lines, or no blank separator.
    MalformedCheckpoint(&'static str),
    /// A field was not the base64 or decimal it had to be.
    MalformedField(&'static str),
    /// Signature line present but not in `— <name> <base64>` form.
    MalformedSignature,
    /// No signature line names the key the caller asked about.
    NoSignatureFromKey,
    /// The named key did not sign these bytes.
    BadSignature,
    /// The proof does not fold to the published root.
    RootMismatch,
    /// A proof was longer or shorter than the tree shape requires.
    ProofShape(&'static str),
    /// Sizes that cannot describe growth.
    BadRange(&'static str),
}

// ── RFC 6962 tree ─────────────────────────────────────────────────────────────
// Leaves and interior nodes carry different prefixes; an odd node is promoted, never
// duplicated. Both matter: without domain separation an interior node can be presented as
// a leaf, and duplicating an odd leaf is CVE-2012-2459, where two different trees share a
// root. `[T:RFC 6962 §2.1]`

/// `SHA-256(0x00 || data)`.
pub fn leaf_hash(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x00u8]);
    h.update(data);
    h.finalize().into()
}

fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x01u8]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

fn split_point(n: usize) -> usize {
    let mut k = 1;
    while k * 2 < n {
        k *= 2;
    }
    k
}

/// The root over `leaves`, or `None` for an empty tree — an empty log has no root, and
/// returning zeros would make "nothing was logged" verify as "a tree of nothing".
pub fn root(leaves: &[[u8; 32]]) -> Option<[u8; 32]> {
    if leaves.is_empty() {
        return None;
    }
    let mut level = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i + 1 < level.len() {
            next.push(node_hash(&level[i], &level[i + 1]));
            i += 2;
        }
        if i < level.len() {
            next.push(level[i]);
        }
        level = next;
    }
    Some(level[0])
}

/// One step of an inclusion proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProofStep {
    pub sibling: [u8; 32],
    /// `true` when the sibling is the LEFT child, i.e. the running hash is the right one.
    pub sibling_is_left: bool,
}

/// Fold `leaf` with its proof and compare against the published root.
///
/// This is the whole of offline inclusion verification. Everything the caller needs is the
/// leaf, the path and the root — not the other events, and not us.
pub fn verify_inclusion(
    leaf: &[u8; 32],
    steps: &[ProofStep],
    expected_root: &[u8; 32],
) -> Result<(), VerifyError> {
    let mut acc = *leaf;
    for s in steps {
        acc = if s.sibling_is_left {
            node_hash(&s.sibling, &acc)
        } else {
            node_hash(&acc, &s.sibling)
        };
    }
    if &acc == expected_root {
        Ok(())
    } else {
        Err(VerifyError::RootMismatch)
    }
}

/// Rebuild both roots from a consistency proof — the exact inverse of RFC 6962's
/// `SUBPROOF`, written that way on purpose: a consistency check that is subtly wrong
/// declares a rewritten history consistent, which is worse than having no check.
fn rebuild(
    m: usize,
    n: usize,
    have_old: bool,
    it: &mut core::slice::Iter<'_, [u8; 32]>,
    old_root: &[u8; 32],
) -> Option<([u8; 32], [u8; 32])> {
    if m == n {
        let h = if have_old { *old_root } else { *it.next()? };
        return Some((h, h));
    }
    let k = split_point(n);
    if m <= k {
        let (old, new_left) = rebuild(m, k, have_old, it, old_root)?;
        let right = *it.next()?;
        Some((old, node_hash(&new_left, &right)))
    } else {
        let (old_right, new_right) = rebuild(m - k, n - k, false, it, old_root)?;
        let left = *it.next()?;
        Some((node_hash(&left, &old_right), node_hash(&left, &new_right)))
    }
}

/// Check that the tree at size `n` extends the tree at size `m`.
///
/// This is the check that catches a **split view** — a log showing one history to one
/// reader and a different one to another. Inclusion proofs alone cannot: both stories are
/// internally consistent, and every event in each verifies.
pub fn verify_consistency(
    m: usize,
    n: usize,
    old_root: &[u8; 32],
    new_root: &[u8; 32],
    proof: &[[u8; 32]],
) -> Result<(), VerifyError> {
    if m == 0 {
        return Err(VerifyError::BadRange(
            "size zero has no root to be consistent with",
        ));
    }
    if m > n {
        return Err(VerifyError::BadRange(
            "a smaller tree cannot extend a larger one",
        ));
    }
    if m == n {
        return if proof.is_empty() && old_root == new_root {
            Ok(())
        } else {
            Err(VerifyError::RootMismatch)
        };
    }
    let mut it = proof.iter();
    let (old, new) =
        rebuild(m, n, true, &mut it, old_root).ok_or(VerifyError::ProofShape("proof too short"))?;
    if it.next().is_some() {
        // An over-long proof means prover and verifier disagree about the tree's shape.
        // Accepting the prefix that folded correctly would accept an argument nobody made.
        return Err(VerifyError::ProofShape("proof too long"));
    }
    if &old != old_root || &new != new_root {
        return Err(VerifyError::RootMismatch);
    }
    Ok(())
}

// ── C2SP checkpoint ───────────────────────────────────────────────────────────

/// A parsed `tlog-checkpoint` signed note.
///
/// `body` is retained verbatim because it is what the signature covers; rebuilding it from
/// the parsed fields would be a second definition of the same bytes, and any difference
/// between them would show up as a signature failure nobody could explain.
#[derive(Debug, Clone)]
pub struct Checkpoint {
    pub origin: String,
    pub tree_size: u64,
    pub root: [u8; 32],
    /// Exactly the bytes that were signed: the note text including its final newline and
    /// excluding the blank separator line. `[T:c2sp.org/signed-note]`
    pub body: String,
    /// `(key name, key id, signature)` for each signature line.
    pub signatures: Vec<(String, [u8; 4], [u8; 64])>,
}

impl Checkpoint {
    /// Parse a note. Strict: a checkpoint that does not parse is not a checkpoint we should
    /// try to make sense of.
    pub fn parse(note: &str) -> Result<Self, VerifyError> {
        let sep = note
            .find("\n\n")
            .ok_or(VerifyError::MalformedCheckpoint("no blank separator line"))?;
        let body = note[..sep + 1].to_string();
        let mut lines = body.lines();
        let origin = lines
            .next()
            .ok_or(VerifyError::MalformedCheckpoint("no origin line"))?
            .to_string();
        let tree_size: u64 = lines
            .next()
            .ok_or(VerifyError::MalformedCheckpoint("no tree size line"))?
            .parse()
            .map_err(|_| VerifyError::MalformedField("tree size is not a decimal integer"))?;
        let root_b64 = lines
            .next()
            .ok_or(VerifyError::MalformedCheckpoint("no root hash line"))?;
        let root: [u8; 32] = STANDARD
            .decode(root_b64)
            .map_err(|_| VerifyError::MalformedField("root hash is not base64"))?
            .try_into()
            .map_err(|_| VerifyError::MalformedField("root hash is not 32 bytes"))?;

        let mut signatures = Vec::new();
        for line in note[sep + 2..].lines().filter(|l| !l.is_empty()) {
            // `— <key name> base64(key_id || signature)`. The separator is an em dash,
            // U+2014 — a reader splitting on a hyphen finds nothing and reports an
            // unsigned checkpoint, which is a confusing way to be wrong.
            let rest = line
                .strip_prefix('\u{2014}')
                .ok_or(VerifyError::MalformedSignature)?
                .trim_start();
            let (name, payload_b64) = rest
                .split_once(' ')
                .ok_or(VerifyError::MalformedSignature)?;
            let payload = STANDARD
                .decode(payload_b64.trim())
                .map_err(|_| VerifyError::MalformedSignature)?;
            if payload.len() != 68 {
                return Err(VerifyError::MalformedSignature);
            }
            let mut key_id = [0u8; 4];
            key_id.copy_from_slice(&payload[..4]);
            let mut sig = [0u8; 64];
            sig.copy_from_slice(&payload[4..]);
            signatures.push((name.to_string(), key_id, sig));
        }
        Ok(Checkpoint {
            origin,
            tree_size,
            root,
            body,
            signatures,
        })
    }

    /// Verify that `public_key`, published under `key_name`, signed this checkpoint.
    ///
    /// The key id is recomputed from the name and the key rather than trusted from the
    /// line, so a signature cannot be matched to a key it was not made under.
    /// `[T:c2sp.org/signed-note]`
    pub fn verify_signature(
        &self,
        key_name: &str,
        public_key: &[u8; 32],
    ) -> Result<(), VerifyError> {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

        let want_id = key_id(key_name, public_key);
        let key = VerifyingKey::from_bytes(public_key)
            .map_err(|_| VerifyError::MalformedField("public key is not a valid Ed25519 point"))?;
        let mut saw_key = false;
        for (name, id, sig) in &self.signatures {
            if name != key_name || id != &want_id {
                continue;
            }
            saw_key = true;
            // verify_strict rejects small-order keys that plain verify accepts. On a path
            // whose whole job is to be believed, that malleability is not worth the
            // microseconds. `[T:ed25519-dalek@2 — VerifyingKey::verify_strict]`
            if key
                .verify_strict(self.body.as_bytes(), &Signature::from_bytes(sig))
                .is_ok()
            {
                return Ok(());
            }
            let _ = key.verify(self.body.as_bytes(), &Signature::from_bytes(sig));
        }
        if saw_key {
            Err(VerifyError::BadSignature)
        } else {
            Err(VerifyError::NoSignatureFromKey)
        }
    }
}

/// `key_id = SHA-256(key_name || 0x0A || 0x01 || public_key)[..4]`, the signed-note
/// construction for Ed25519. Bound to the NAME as well as the key, so the same key
/// published under a different origin is a different signer.
pub fn key_id(key_name: &str, public_key: &[u8; 32]) -> [u8; 4] {
    let mut h = Sha256::new();
    h.update(key_name.as_bytes());
    h.update([0x0A, 0x01]);
    h.update(public_key);
    let d = h.finalize();
    [d[0], d[1], d[2], d[3]]
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn leaves(n: usize) -> Vec<[u8; 32]> {
        (0..n).map(|i| leaf_hash(&[i as u8])).collect()
    }

    /// The RFC's recursive definition, transcribed. An independent verifier has to be
    /// checkable against the spec, not against the implementation it is verifying.
    fn mth(l: &[[u8; 32]]) -> [u8; 32] {
        match l.len() {
            1 => l[0],
            n => {
                let k = split_point(n);
                node_hash(&mth(&l[..k]), &mth(&l[k..]))
            }
        }
    }

    fn inclusion_proof(l: &[[u8; 32]], index: usize) -> Vec<ProofStep> {
        let mut steps = Vec::new();
        let mut level = l.to_vec();
        let mut idx = index;
        while level.len() > 1 {
            let mut next = Vec::new();
            let mut i = 0;
            while i + 1 < level.len() {
                if idx == i {
                    steps.push(ProofStep {
                        sibling: level[i + 1],
                        sibling_is_left: false,
                    });
                } else if idx == i + 1 {
                    steps.push(ProofStep {
                        sibling: level[i],
                        sibling_is_left: true,
                    });
                }
                next.push(node_hash(&level[i], &level[i + 1]));
                i += 2;
            }
            if i < level.len() {
                next.push(level[i]);
            }
            idx /= 2;
            level = next;
        }
        steps
    }

    fn consistency_proof(l: &[[u8; 32]], m: usize) -> Vec<[u8; 32]> {
        fn sub(m: usize, l: &[[u8; 32]], b: bool, out: &mut Vec<[u8; 32]>) {
            let n = l.len();
            if m == n {
                if !b {
                    out.push(root(l).expect("non-empty"));
                }
                return;
            }
            let k = split_point(n);
            if m <= k {
                sub(m, &l[..k], b, out);
                out.push(root(&l[k..]).expect("non-empty"));
            } else {
                sub(m - k, &l[k..], false, out);
                out.push(root(&l[..k]).expect("non-empty"));
            }
        }
        let mut out = Vec::new();
        sub(m, l, true, &mut out);
        out
    }

    #[test]
    fn root_matches_the_rfc_reference_definition() {
        for n in 1..=64 {
            let l = leaves(n);
            assert_eq!(root(&l).expect("non-empty"), mth(&l), "size {n}");
        }
    }

    #[test]
    fn every_leaf_folds_into_the_root() {
        for n in [1usize, 2, 3, 5, 8, 13, 21] {
            let l = leaves(n);
            let r = root(&l).expect("non-empty");
            for i in 0..n {
                assert_eq!(verify_inclusion(&l[i], &inclusion_proof(&l, i), &r), Ok(()));
            }
        }
    }

    // A leaf that was never in the tree must not verify, or the root proves nothing.
    #[test]
    fn a_leaf_that_was_never_logged_does_not_verify() {
        let l = leaves(8);
        let r = root(&l).expect("root");
        let p = inclusion_proof(&l, 3);
        assert_eq!(
            verify_inclusion(&leaf_hash(b"never logged"), &p, &r),
            Err(VerifyError::RootMismatch)
        );
    }

    #[test]
    fn every_prefix_is_consistent_with_every_larger_tree() {
        for n in 1..=32 {
            let l = leaves(n);
            let new_root = root(&l).expect("root");
            for m in 1..=n {
                let old_root = root(&l[..m]).expect("root");
                let p = consistency_proof(&l, m);
                assert_eq!(
                    verify_consistency(m, n, &old_root, &new_root, &p),
                    Ok(()),
                    "m={m} n={n}"
                );
            }
        }
    }

    // The attack this crate exists to let a customer detect on their own.
    #[test]
    fn a_rewritten_history_is_caught() {
        let honest = leaves(16);
        let published = root(&honest[..8]).expect("root");
        let mut rewritten = honest.clone();
        rewritten[2] = leaf_hash(b"swapped after publication");
        let forged_root = root(&rewritten).expect("root");
        let forged_proof = consistency_proof(&rewritten, 8);
        assert!(verify_consistency(8, 16, &published, &forged_root, &forged_proof).is_err());
    }

    #[test]
    fn a_shrinking_log_is_not_a_growing_one() {
        let l = leaves(10);
        let big = root(&l).expect("root");
        let small = root(&l[..4]).expect("root");
        assert!(matches!(
            verify_consistency(10, 4, &big, &small, &[]),
            Err(VerifyError::BadRange(_))
        ));
    }

    fn signed_note(key: &SigningKey, origin: &str, size: u64, r: &[u8; 32]) -> String {
        let body = format!("{origin}\n{size}\n{}\n", STANDARD.encode(r));
        let sig = key.sign(body.as_bytes());
        let pk = key.verifying_key().to_bytes();
        let mut payload = Vec::new();
        payload.extend_from_slice(&key_id(origin, &pk));
        payload.extend_from_slice(&sig.to_bytes());
        format!("{body}\n\u{2014} {origin} {}\n", STANDARD.encode(&payload))
    }

    #[test]
    fn a_checkpoint_parses_and_its_signature_verifies() {
        let key = SigningKey::from_bytes(&[3u8; 32]);
        let origin = "ankayma.com/personal/t_demo";
        let r = root(&leaves(9)).expect("root");
        let note = signed_note(&key, origin, 9, &r);

        let cp = Checkpoint::parse(&note).expect("parses");
        assert_eq!(cp.origin, origin);
        assert_eq!(cp.tree_size, 9);
        assert_eq!(cp.root, r);
        assert_eq!(
            cp.verify_signature(origin, &key.verifying_key().to_bytes()),
            Ok(())
        );
    }

    // Another key's signature must not pass, and the failure must say WHICH failure it is:
    // "nobody by that name signed" and "they signed and it is wrong" are different
    // incidents.
    #[test]
    fn a_signature_from_another_key_is_refused_with_the_right_reason() {
        let real = SigningKey::from_bytes(&[3u8; 32]);
        let other = SigningKey::from_bytes(&[4u8; 32]);
        let origin = "ankayma.com/personal/t_demo";
        let note = signed_note(&real, origin, 4, &root(&leaves(4)).expect("root"));
        let cp = Checkpoint::parse(&note).expect("parses");

        assert_eq!(
            cp.verify_signature(origin, &other.verifying_key().to_bytes()),
            Err(VerifyError::NoSignatureFromKey)
        );
        assert_eq!(
            cp.verify_signature(
                "ankayma.com/personal/someone-else",
                &real.verifying_key().to_bytes()
            ),
            Err(VerifyError::NoSignatureFromKey)
        );
    }

    // The body is what was signed. Editing the tree size and re-presenting the old
    // signature must fail — this is the tamper case a customer is actually checking for.
    #[test]
    fn an_edited_checkpoint_fails_its_own_signature() {
        let key = SigningKey::from_bytes(&[3u8; 32]);
        let origin = "ankayma.com/personal/t_demo";
        let note = signed_note(&key, origin, 9, &root(&leaves(9)).expect("root"));
        let tampered = note.replacen("\n9\n", "\n99\n", 1);

        let cp = Checkpoint::parse(&tampered).expect("still parses");
        assert_eq!(cp.tree_size, 99);
        assert_eq!(
            cp.verify_signature(origin, &key.verifying_key().to_bytes()),
            Err(VerifyError::BadSignature)
        );
    }

    #[test]
    fn a_malformed_note_is_refused_rather_than_guessed_at() {
        assert!(matches!(
            Checkpoint::parse("one line only\n"),
            Err(VerifyError::MalformedCheckpoint(_))
        ));
        assert!(matches!(
            Checkpoint::parse("origin\nnot-a-number\nAAAA\n\n"),
            Err(VerifyError::MalformedField(_))
        ));
        assert!(matches!(
            Checkpoint::parse("origin\n1\n!!!not-base64!!!\n\n"),
            Err(VerifyError::MalformedField(_))
        ));
        // A hyphen instead of an em dash: the signature line is not in the format, and
        // saying so beats silently reporting an unsigned checkpoint.
        assert!(matches!(
            Checkpoint::parse(
                "origin\n1\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n\n- x AAAA\n"
            ),
            Err(VerifyError::MalformedSignature)
        ));
    }
}

/// Interoperability fixtures.
///
/// The value of a second implementation is that it can DISAGREE with the first. These pin
/// the exact bytes both sides must produce, so a drift on either side breaks a test rather
/// than a customer's verification months later.
#[cfg(test)]
mod interop {
    use super::*;
    use ed25519_dalek::SigningKey;

    /// Signing key seed `[3u8; 32]`, origin below, tree size 9, root = RFC 6962 root over
    /// leaves `leaf_hash([i])` for i in 0..9. The control plane's `audit::checkpoint`
    /// module asserts the identical string.
    pub const GOLDEN_ORIGIN: &str = "ankayma.com/personal:authorization:t_golden";

    fn golden_leaves() -> Vec<[u8; 32]> {
        (0..9u8).map(|i| leaf_hash(&[i])).collect()
    }

    #[test]
    fn the_golden_checkpoint_is_stable() {
        let r = root(&golden_leaves()).expect("root");
        let body = format!("{GOLDEN_ORIGIN}\n9\n{}\n", STANDARD.encode(r));
        assert_eq!(
            body,
            "ankayma.com/personal:authorization:t_golden\n9\n\
             FiohwiMOAoTqOMuHOe5Lt1lHoazV1SnGOOwGiWn7PEo=\n",
            "the checkpoint body is a wire format; changing it breaks every verifier"
        );

        let key = SigningKey::from_bytes(&[3u8; 32]);
        let pk = key.verifying_key().to_bytes();
        assert_eq!(
            STANDARD.encode(key_id(GOLDEN_ORIGIN, &pk)),
            "pbE/tg==",
            "the key id binds the name and the key; both sides must derive it alike"
        );
    }
}
