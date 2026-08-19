//! exec_outcome — telling the control plane what a command grant actually did.
//!
//! Intensity: **Critical** (CLAUDE.md T/A §) — this is the only observation of an
//! execution that ever reaches the ledger. The control plane is not on the data path
//! (A.1.1) and therefore cannot see any of it.
//!
//! **Fail-static.** If the control plane is unreachable the command still runs — the node
//! does not need permission it already holds — and the outcome is queued and retried.
//! `[T:A.1.1]`
//!
//! **A lost outcome degrades to an honest state, not a wrong one.** The control plane
//! closes a command grant that expires without a report as `outcome_unreported`, never as
//! `completed`. So a queue that does not survive a restart costs precision, not
//! correctness: "we never heard back" remains true. That is why this is an in-memory queue
//! and not a disk spool — a spool would turn "unreported" into "reported late", which is
//! worth building when someone needs that precision and not before (P.8).
//! `[A — no disk spool; revisit when a tenant needs late reports rather than honest gaps]`

use serde::Serialize;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

/// How many outcomes may wait for a control plane that is not answering.
///
/// Bounded because an unbounded queue turns a control-plane outage into a node memory
/// leak. When it overflows the OLDEST is dropped: a newer outcome is the one an operator
/// is waiting on, and the dropped one still resolves — as `outcome_unreported`, which is
/// the truth. `[A — not calibrated]`
const MAX_QUEUED: usize = 256;

/// What the node observed. Field names match the control plane's `/api/v1/exec/outcome`.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ExecOutcome {
    pub grant_id: String,
    /// `completed` · `failed` · `rejected_digest_mismatch` — the only three a node can
    /// know. `expired`, `revoked` and `parent_terminated` are the control plane's own
    /// conclusions, and a node reporting one would be overwriting the reason its
    /// authority was withdrawn.
    pub termination_reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes_out: Option<i64>,
    /// WHICH enforcement point measured the volumetrics. Named, because the control plane
    /// cannot measure them and a NULL there must read as "nobody did", not as zero.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub measured_by: Option<String>,
}

impl ExecOutcome {
    /// What an exit code means, without embellishment.
    ///
    /// Zero completed; anything else failed. The node does not interpret further — an
    /// exit code of 2 from one program and from another mean different things, and
    /// guessing which would put an opinion in the ledger.
    pub fn from_exit(grant_id: impl Into<String>, code: i32, node_id: &str, bytes: i64) -> Self {
        Self {
            grant_id: grant_id.into(),
            termination_reason: if code == 0 { "completed" } else { "failed" }.to_string(),
            exit_code: Some(code),
            bytes_out: Some(bytes),
            measured_by: Some(format!("pep:{node_id}")),
        }
    }

    /// A command the node REFUSED to run. Stronger evidence than a permit, so it is
    /// reported with no volumetrics at all rather than with zeros — nothing ran, and
    /// zero bytes out would look like something that ran and produced nothing.
    pub fn refused(grant_id: impl Into<String>, reason: &str, node_id: &str) -> Self {
        Self {
            grant_id: grant_id.into(),
            termination_reason: reason.to_string(),
            exit_code: None,
            bytes_out: None,
            measured_by: Some(format!("pep:{node_id}")),
        }
    }
}

/// A bounded queue of outcomes waiting to be delivered.
#[derive(Clone, Default)]
pub struct OutcomeQueue {
    inner: Arc<Mutex<VecDeque<ExecOutcome>>>,
}

impl OutcomeQueue {
    pub fn new() -> Self {
        Self::default()
    }

    /// Queue an outcome, dropping the oldest if the queue is full.
    ///
    /// Returns whether anything was dropped, so the caller can say so out loud rather
    /// than lose an outcome silently.
    pub fn push(&self, outcome: ExecOutcome) -> bool {
        let mut q = self.inner.lock().expect("outcome queue poisoned");
        let dropped = q.len() >= MAX_QUEUED;
        if dropped {
            q.pop_front();
        }
        q.push_back(outcome);
        dropped
    }

    /// Take everything currently queued, oldest first.
    pub fn drain(&self) -> Vec<ExecOutcome> {
        let mut q = self.inner.lock().expect("outcome queue poisoned");
        q.drain(..).collect()
    }

    /// Put an outcome back at the FRONT after a failed delivery, so ordering survives a
    /// retry — an operator reading the ledger should see them in the order they happened.
    pub fn requeue_front(&self, outcome: ExecOutcome) {
        let mut q = self.inner.lock().expect("outcome queue poisoned");
        if q.len() >= MAX_QUEUED {
            q.pop_back();
        }
        q.push_front(outcome);
    }

    pub fn len(&self) -> usize {
        self.inner.lock().expect("outcome queue poisoned").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn outcome(id: &str) -> ExecOutcome {
        ExecOutcome::from_exit(id, 0, "nd1", 12)
    }

    #[test]
    fn an_exit_code_is_reported_without_interpretation() {
        let ok = ExecOutcome::from_exit("g", 0, "nd1", 5);
        assert_eq!(ok.termination_reason, "completed");
        let bad = ExecOutcome::from_exit("g", 2, "nd1", 5);
        assert_eq!(bad.termination_reason, "failed");
        assert_eq!(
            bad.exit_code,
            Some(2),
            "the code itself is reported, not a verdict"
        );
    }

    // Nothing ran, so there is nothing to measure. Zero bytes would read as a command
    // that ran and produced no output, which is a different fact.
    #[test]
    fn a_refusal_carries_no_volumetrics() {
        let r = ExecOutcome::refused("g", "rejected_digest_mismatch", "nd1");
        assert_eq!(r.exit_code, None);
        assert_eq!(r.bytes_out, None);
        assert_eq!(r.measured_by.as_deref(), Some("pep:nd1"));
    }

    // An unbounded queue turns a control-plane outage into a node memory leak. The oldest
    // goes, because the newest is the one someone is waiting on — and the dropped one
    // still resolves honestly as `outcome_unreported`.
    #[test]
    fn the_queue_is_bounded_and_drops_the_oldest() {
        let q = OutcomeQueue::new();
        for i in 0..MAX_QUEUED {
            assert!(!q.push(outcome(&format!("g{i}"))), "no drop while it fits");
        }
        assert!(
            q.push(outcome("newest")),
            "overflow must be reported, not silent"
        );
        assert_eq!(q.len(), MAX_QUEUED);
        let all = q.drain();
        assert_eq!(
            all.first().expect("non-empty").grant_id,
            "g1",
            "oldest went"
        );
        assert_eq!(all.last().expect("non-empty").grant_id, "newest");
    }

    // Order survives a failed delivery: an operator reading the ledger should see the
    // outcomes in the order they happened, not in the order the network recovered.
    #[test]
    fn a_failed_delivery_goes_back_to_the_front() {
        let q = OutcomeQueue::new();
        q.push(outcome("first"));
        q.push(outcome("second"));
        let mut batch = q.drain();
        let head = batch.remove(0);
        for left in batch.into_iter().rev() {
            q.requeue_front(left);
        }
        q.requeue_front(head);
        let after = q.drain();
        assert_eq!(
            after
                .iter()
                .map(|o| o.grant_id.as_str())
                .collect::<Vec<_>>(),
            vec!["first", "second"]
        );
    }

    // The three a node can know, and nothing else. Reporting `expired` would let a node
    // overwrite the reason the control plane withdrew its authority.
    #[test]
    fn only_reasons_a_node_can_observe_are_constructible() {
        for code in [0, 1, 127] {
            let o = ExecOutcome::from_exit("g", code, "nd1", 0);
            assert!(matches!(
                o.termination_reason.as_str(),
                "completed" | "failed"
            ));
        }
    }
}
