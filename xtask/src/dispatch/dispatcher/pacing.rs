//! When the next GitHub pass runs. A session the dispatcher started that ends brings the pass
//! forward to now, so the step its end allows starts at once (owner instruction 30). The poll
//! interval is the fallback for changes made elsewhere, with jitter so many dispatchers never
//! call GitHub in step; after a failed pass the next one backs off with full jitter (P15), and a
//! session's end does not cut that wait short.

use std::time::{Duration, Instant};

use crate::dispatch::policy::Policy;
use crate::orchestrate::ids;

pub(super) struct Pacing {
    next: Instant,
    /// GitHub passes failed in a row, for the backoff.
    failed: u32,
}

impl Pacing {
    /// The first pass is due at once.
    pub(super) fn new() -> Pacing {
        Pacing {
            next: Instant::now(),
            failed: 0,
        }
    }

    pub(super) fn due(&self) -> bool {
        Instant::now() >= self.next
    }

    pub(super) fn passed(&mut self, policy: &Policy) {
        self.failed = 0;
        self.next = Instant::now() + jittered(policy.poll, policy.poll_jitter);
    }

    /// Returns the backoff the next pass waits out.
    pub(super) fn failed(&mut self, policy: &Policy) -> Duration {
        self.failed = self.failed.saturating_add(1);
        let wait = backoff(policy.backoff_base, policy.backoff_cap, self.failed);
        self.next = Instant::now() + wait;
        wait
    }

    pub(super) fn session_ended(&mut self) {
        if self.failed == 0 {
            self.next = Instant::now();
        }
    }
}

/// `poll` plus or minus up to `jitter`, never more than `poll` itself, so dispatchers started
/// together spread their reads.
fn jittered(poll: Duration, jitter: Duration) -> Duration {
    let millis = u64::try_from(poll.as_millis()).unwrap_or(u64::MAX);
    let spread = u64::try_from(jitter.as_millis())
        .unwrap_or(u64::MAX)
        .min(millis);
    let offset = ids::below(spread.saturating_mul(2).saturating_add(1));
    Duration::from_millis(millis.saturating_sub(spread).saturating_add(offset))
}

/// Full-jitter exponential backoff after `failures` failed passes in a row: a uniform wait up to
/// `min(cap, base * 2^failures)`. The loop's one-second session poll keeps a zero wait from
/// spinning.
fn backoff(base: Duration, cap: Duration, failures: u32) -> Duration {
    let base = u64::try_from(base.as_millis()).unwrap_or(u64::MAX);
    let cap = u64::try_from(cap.as_millis()).unwrap_or(u64::MAX);
    let ceiling = base.saturating_mul(2u64.saturating_pow(failures)).min(cap);
    Duration::from_millis(ids::below(ceiling.saturating_add(1)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dispatch::policy::tests::HARNESS;
    use crate::testkit::TempRepo;

    #[test]
    fn a_session_that_ends_brings_the_pass_forward_except_during_a_backoff() {
        let temp = TempRepo::create();
        temp.write(".agents/harness.toml", HARNESS);
        temp.write(
            ".agents/kit/usage.toml",
            "[item]\nmax_attempts = 2\nmax_review_rounds = 3\nverdict_hours = 24\n",
        );
        let policy = Policy::load(&temp.repo(), None).unwrap();
        let mut pacing = Pacing::new();
        pacing.passed(&policy);
        assert!(
            !pacing.due(),
            "the pass after one that worked is due at once"
        );
        pacing.session_ended();
        assert!(pacing.due(), "the pass waits out the poll interval");
        let failed = Instant::now();
        let wait = pacing.failed(&policy);
        pacing.session_ended();
        assert!(
            !pacing.due() || failed.elapsed() >= wait,
            "a session's end cut a backoff of {wait:?} short"
        );
    }

    #[test]
    fn the_backoff_grows_with_full_jitter_up_to_its_cap() {
        for failures in [1, 2, 5, 40, u32::MAX] {
            let wait = backoff(Duration::from_secs(30), Duration::from_secs(900), failures);
            let grown = 30u64.saturating_mul(2u64.saturating_pow(failures)).min(900);
            assert!(
                wait <= Duration::from_secs(grown),
                "{failures}: {wait:?} above {grown} s"
            );
        }
        let poll = jittered(Duration::from_secs(60), Duration::from_secs(6));
        assert!(poll >= Duration::from_secs(54) && poll <= Duration::from_secs(66));
        assert_eq!(
            jittered(Duration::from_secs(60), Duration::ZERO),
            Duration::from_secs(60)
        );
    }
}
