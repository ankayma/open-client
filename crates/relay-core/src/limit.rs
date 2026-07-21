//! Token-bucket rate limiting, one bucket per connection.
//!
//! Overflow means drop-the-frame, never block: the relay carries UDP-semantics
//! traffic and the inner WireGuard session absorbs loss.

use std::time::Instant;

pub struct TokenBucket {
    capacity: f64,
    tokens: f64,
    refill_per_sec: f64,
    last: Instant,
}

impl TokenBucket {
    pub fn new(capacity: f64, refill_per_sec: f64) -> Self {
        TokenBucket {
            capacity,
            tokens: capacity,
            refill_per_sec,
            last: Instant::now(),
        }
    }

    pub fn allow(&mut self, cost: f64) -> bool {
        self.allow_at(cost, Instant::now())
    }

    /// Clock-injectable core, so tests never sleep.
    pub fn allow_at(&mut self, cost: f64, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + elapsed * self.refill_per_sec).min(self.capacity);
        if self.tokens >= cost {
            self.tokens -= cost;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn burst_then_deny_then_refill() {
        let t0 = Instant::now();
        let mut b = TokenBucket::new(2.0, 1.0);
        assert!(b.allow_at(1.0, t0));
        assert!(b.allow_at(1.0, t0));
        assert!(!b.allow_at(1.0, t0)); // bucket drained
        let t1 = t0 + Duration::from_secs(1);
        assert!(b.allow_at(1.0, t1)); // one token refilled
        assert!(!b.allow_at(1.0, t1));
    }

    #[test]
    fn refill_never_exceeds_capacity() {
        let t0 = Instant::now();
        let mut b = TokenBucket::new(2.0, 1.0);
        let t_much_later = t0 + Duration::from_secs(3600);
        assert!(b.allow_at(2.0, t_much_later));
        assert!(!b.allow_at(1.0, t_much_later)); // capped at capacity, not 3600
    }
}
