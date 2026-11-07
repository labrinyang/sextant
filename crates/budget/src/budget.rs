use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// Cooperative deadline shared by every CPU-heavy phase of one quote.
///
/// The HTTP timeout alone cannot preempt synchronous route search. A clone of
/// this value follows the quote onto the bounded blocking pool, and the request
/// handler also cancels it when its outer timeout wins.
#[derive(Clone, Debug)]
pub struct SolverBudget {
    deadline: Option<Instant>,
    cancelled: Arc<AtomicBool>,
}

impl SolverBudget {
    pub fn unlimited() -> Self {
        Self {
            deadline: None,
            cancelled: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn for_duration(duration: Duration) -> Self {
        Self {
            deadline: Some(Instant::now() + duration),
            cancelled: Arc::new(AtomicBool::new(false)),
        }
    }

    #[inline]
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    #[inline]
    pub fn is_bounded(&self) -> bool {
        self.deadline.is_some()
    }

    /// Wall-clock time left before this budget expires. A cancelled budget
    /// reports zero even when it was originally unlimited, so optional async
    /// work can decline immediately instead of waiting for another checkpoint.
    #[inline]
    pub fn remaining(&self) -> Option<Duration> {
        if self.cancelled.load(Ordering::Acquire) {
            return Some(Duration::ZERO);
        }
        self.deadline
            .map(|deadline| deadline.saturating_duration_since(Instant::now()))
    }

    /// The child expires earlier without cancelling its parent. Explicit
    /// request cancellation still reaches every continuation through the same
    /// token; expiration of optional work does not set that token.
    pub fn with_time_reserve(&self, reserve: Duration) -> Option<Self> {
        if self.cancelled.load(Ordering::Acquire) {
            return None;
        }
        let deadline = match self.deadline {
            Some(parent) => {
                let child = parent.checked_sub(reserve)?;
                if child <= Instant::now() {
                    return None;
                }
                Some(child)
            }
            None => None,
        };
        Some(Self {
            deadline,
            cancelled: self.cancelled.clone(),
        })
    }

    /// Clamp a continuation to an external quote/anchor expiry. It shares the
    /// request cancellation token and cannot extend an existing deadline.
    pub fn with_deadline(&self, deadline: Instant) -> Self {
        Self {
            deadline: Some(
                self.deadline
                    .map_or(deadline, |current| current.min(deadline)),
            ),
            cancelled: self.cancelled.clone(),
        }
    }

    #[inline]
    pub fn checkpoint(&self, stage: &'static str) -> anyhow::Result<()> {
        if self.cancelled.load(Ordering::Acquire)
            || self
                .deadline
                .is_some_and(|deadline| Instant::now() >= deadline)
        {
            return Err(SolverBudgetExceeded { stage }.into());
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SolverBudgetExceeded {
    pub stage: &'static str,
}

impl fmt::Display for SolverBudgetExceeded {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "solver compute deadline exceeded during {}", self.stage)
    }
}

impl std::error::Error for SolverBudgetExceeded {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancellation_is_shared_across_clones() {
        let budget = SolverBudget::unlimited();
        let clone = budget.clone();
        budget.cancel();
        let error = clone.checkpoint("test").unwrap_err();
        assert!(error.downcast_ref::<SolverBudgetExceeded>().is_some());
    }

    #[test]
    fn expired_deadline_is_typed() {
        let budget = SolverBudget::for_duration(Duration::ZERO);
        let error = budget.checkpoint("route search").unwrap_err();
        assert_eq!(
            error.downcast_ref::<SolverBudgetExceeded>(),
            Some(&SolverBudgetExceeded {
                stage: "route search"
            })
        );
    }

    #[test]
    fn remaining_is_zero_after_cancellation() {
        let budget = SolverBudget::unlimited();
        assert_eq!(budget.remaining(), None);

        budget.cancel();

        assert_eq!(budget.remaining(), Some(Duration::ZERO));
    }

    #[test]
    fn earlier_child_deadline_does_not_cancel_parent_work() {
        let parent = SolverBudget::for_duration(Duration::from_secs(10));
        let mut child = parent.with_time_reserve(Duration::from_secs(2)).unwrap();
        assert_eq!(
            child.deadline,
            parent.deadline.unwrap().checked_sub(Duration::from_secs(2))
        );
        // Force only the child clock to expiry; no wall-clock sleep or race.
        child.deadline = Some(Instant::now());
        assert!(child.checkpoint("optional search").is_err());
        assert!(parent.checkpoint("final verification").is_ok());
        assert!(!parent.cancelled.load(Ordering::Acquire));
        parent.cancel();
        assert!(child.checkpoint("cancelled child").is_err());
    }

    #[test]
    fn impossible_or_cancelled_time_reserve_is_not_admitted() {
        let parent = SolverBudget::for_duration(Duration::from_secs(1));
        assert!(parent.with_time_reserve(Duration::from_secs(1)).is_none());
        let unlimited = SolverBudget::unlimited();
        let child = unlimited.with_time_reserve(Duration::from_secs(2)).unwrap();
        assert_eq!(child.remaining(), None);
        child.cancel();
        assert!(unlimited.checkpoint("request cancelled").is_err());
        assert!(unlimited.with_time_reserve(Duration::ZERO).is_none());
    }

    #[test]
    fn explicit_deadline_only_tightens_and_preserves_cancellation() {
        let parent = SolverBudget::for_duration(Duration::from_secs(10));
        let expiry = Instant::now() + Duration::from_secs(1);
        let child = parent.with_deadline(expiry);
        assert_eq!(child.deadline, Some(expiry));
        assert_eq!(
            child
                .with_deadline(expiry + Duration::from_secs(20))
                .deadline,
            Some(expiry)
        );
        assert_eq!(
            parent
                .with_deadline(parent.deadline.unwrap() + Duration::from_secs(1))
                .deadline,
            parent.deadline
        );
        child.cancel();
        assert!(parent.checkpoint("same request cancellation").is_err());
        assert!(child.checkpoint("same quote expiry").is_err());

        let unlimited = SolverBudget::unlimited();
        assert!(
            unlimited
                .with_deadline(Instant::now())
                .checkpoint("expired quote")
                .is_err()
        );
        assert!(unlimited.checkpoint("parent still unlimited").is_ok());
    }
}
