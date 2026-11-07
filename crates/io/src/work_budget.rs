//! Request-wide work accounting. Refreshes and cloned continuations share counters.

use crate::budget::SolverBudget;
use anyhow::Context;
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct WorkCharge {
    pub candidates: u64,
    pub steps: u64,
    pub ticks: u64,
    pub quote_samples: u64,
    /// Physical provider dispatch attempts, including RPC and Native HTTP.
    /// Cache hits and coalesced followers do not dispatch or spend this count.
    pub rpc_calls: u64,
    /// Observed provider payload bytes: serialized decoded RPC results/errors
    /// or Native HTTP body chunks and serialized quota coordination request /
    /// response bodies, excluding HTTP headers and wire framing.
    pub rpc_bytes: u64,
    pub fact_reads: u64,
    /// Canonical decoded fact bytes consumed, including cache/lease hits.
    pub fact_bytes: u64,
    /// Encoded transaction calldata admitted before program evaluation.
    pub payload_bytes: u64,
    pub vm_instructions: u64,
    pub verifications: u64,
    pub restarts: u64,
    pub model_updates: u64,
    pub solver_iterations: u64,
    pub credit_probes: u64,
    pub rfq_requotes: u64,
    /// Time occupying an admitted blocking worker, excluding its queue wait.
    /// This measures wall time in the worker, not platform thread CPU time.
    pub compute_ns: u64,
}

pub type WorkLimits = WorkCharge;

#[derive(Debug)]
pub struct WorkLimitExceeded {
    pub stage: &'static str,
}
impl std::fmt::Display for WorkLimitExceeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "request work limit exceeded during {}", self.stage)
    }
}
impl std::error::Error for WorkLimitExceeded {}

impl WorkCharge {
    pub fn bounded_default() -> Self {
        Self {
            candidates: 64,
            steps: 16_384,
            ticks: 1_000_000,
            quote_samples: 64,
            rpc_calls: 512,
            rpc_bytes: 8 * 1024 * 1024,
            fact_reads: 512,
            fact_bytes: 8 * 1024 * 1024,
            payload_bytes: 8 * 1024 * 1024,
            vm_instructions: 50_000_000,
            verifications: 8,
            restarts: 2,
            model_updates: 4096,
            solver_iterations: 4096,
            credit_probes: 64,
            rfq_requotes: 64,
            compute_ns: 120_000_000_000,
        }
    }

    fn add(self, other: Self) -> anyhow::Result<Self> {
        macro_rules! sum {
            ($field:ident) => {
                self.$field
                    .checked_add(other.$field)
                    .with_context(|| concat!("work counter overflow: ", stringify!($field)))?
            };
        }
        Ok(Self {
            candidates: sum!(candidates),
            steps: sum!(steps),
            ticks: sum!(ticks),
            quote_samples: sum!(quote_samples),
            rpc_calls: sum!(rpc_calls),
            rpc_bytes: sum!(rpc_bytes),
            fact_reads: sum!(fact_reads),
            fact_bytes: sum!(fact_bytes),
            payload_bytes: sum!(payload_bytes),
            vm_instructions: sum!(vm_instructions),
            verifications: sum!(verifications),
            restarts: sum!(restarts),
            model_updates: sum!(model_updates),
            solver_iterations: sum!(solver_iterations),
            credit_probes: sum!(credit_probes),
            rfq_requotes: sum!(rfq_requotes),
            compute_ns: sum!(compute_ns),
        })
    }

    fn fits(self, limit: Self) -> bool {
        self.candidates <= limit.candidates
            && self.steps <= limit.steps
            && self.ticks <= limit.ticks
            && self.quote_samples <= limit.quote_samples
            && self.rpc_calls <= limit.rpc_calls
            && self.rpc_bytes <= limit.rpc_bytes
            && self.fact_reads <= limit.fact_reads
            && self.fact_bytes <= limit.fact_bytes
            && self.payload_bytes <= limit.payload_bytes
            && self.vm_instructions <= limit.vm_instructions
            && self.verifications <= limit.verifications
            && self.restarts <= limit.restarts
            && self.model_updates <= limit.model_updates
            && self.solver_iterations <= limit.solver_iterations
            && self.credit_probes <= limit.credit_probes
            && self.rfq_requotes <= limit.rfq_requotes
            && self.compute_ns <= limit.compute_ns
    }

    fn subtract(self, reserve: Self) -> Option<Self> {
        macro_rules! subtract {
            ($field:ident) => {
                self.$field.checked_sub(reserve.$field)?
            };
        }
        Some(Self {
            candidates: subtract!(candidates),
            steps: subtract!(steps),
            ticks: subtract!(ticks),
            quote_samples: subtract!(quote_samples),
            rpc_calls: subtract!(rpc_calls),
            rpc_bytes: subtract!(rpc_bytes),
            fact_reads: subtract!(fact_reads),
            fact_bytes: subtract!(fact_bytes),
            payload_bytes: subtract!(payload_bytes),
            vm_instructions: subtract!(vm_instructions),
            verifications: subtract!(verifications),
            restarts: subtract!(restarts),
            model_updates: subtract!(model_updates),
            solver_iterations: subtract!(solver_iterations),
            credit_probes: subtract!(credit_probes),
            rfq_requotes: subtract!(rfq_requotes),
            compute_ns: subtract!(compute_ns),
        })
    }
}

#[derive(Clone, Debug)]
pub struct WorkBudget {
    deadline: SolverBudget,
    limits: WorkLimits,
    used: Arc<Mutex<WorkCharge>>,
}

impl WorkBudget {
    pub fn new(deadline: SolverBudget, limits: WorkLimits) -> Self {
        Self {
            deadline,
            limits,
            used: Arc::new(Mutex::new(WorkCharge::default())),
        }
    }

    pub fn bounded(deadline: SolverBudget) -> Self {
        let mut limits = WorkLimits::bounded_default();
        if let Some(remaining) = deadline.remaining() {
            limits.compute_ns = limits
                .compute_ns
                .min(u64::try_from(remaining.as_nanos()).unwrap_or(u64::MAX));
        }
        Self::new(deadline, limits)
    }

    pub fn checkpoint(&self, stage: &'static str) -> anyhow::Result<()> {
        self.deadline.checkpoint(stage)
    }

    /// Atomic vector admission: a failed charge does not spend other dimensions.
    pub fn charge(&self, charge: WorkCharge, stage: &'static str) -> anyhow::Result<()> {
        self.checkpoint(stage)?;
        let mut used = self.used.lock().expect("request work accounting lock");
        let next = used.add(charge)?;
        if !next.fits(self.limits) {
            return Err(WorkLimitExceeded { stage }.into());
        }
        *used = next;
        Ok(())
    }

    pub fn admit_compute(&self, stage: &'static str) -> anyhow::Result<()> {
        self.checkpoint(stage)?;
        if self.used().compute_ns >= self.limits.compute_ns {
            return Err(WorkLimitExceeded { stage }.into());
        }
        Ok(())
    }

    /// A running worker checks its measured, not-yet-recorded occupancy at
    /// cooperative checkpoints. Recording remains the physical owner's job.
    pub fn checkpoint_compute_duration(
        &self,
        elapsed: Duration,
        stage: &'static str,
    ) -> anyhow::Result<()> {
        self.checkpoint(stage)?;
        let elapsed_ns = u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX);
        if self.used().compute_ns.saturating_add(elapsed_ns) >= self.limits.compute_ns {
            return Err(WorkLimitExceeded { stage }.into());
        }
        Ok(())
    }

    /// Record work that already happened, including rejected or cancelled
    /// operations. Unlike admission charges, an overrun stays visible. A
    /// cooperative worker must check its deadline during bounded work and
    /// return before another compute operation can be admitted.
    pub fn record_compute_duration(
        &self,
        elapsed: Duration,
        stage: &'static str,
    ) -> anyhow::Result<()> {
        let compute_ns = u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX).max(1);
        self.record_observed(
            WorkCharge {
                compute_ns,
                ..Default::default()
            },
            stage,
        )
    }

    /// Record an already dispatched provider/coordinator request, including cleanup
    /// after cancellation. Admission for new work still uses `charge` before send.
    pub fn record_rpc_dispatch_attempt(&self, stage: &'static str) -> anyhow::Result<()> {
        self.record_observed(
            WorkCharge {
                rpc_calls: 1,
                ..Default::default()
            },
            stage,
        )
    }

    pub fn record_rpc_response_bytes(
        &self,
        bytes: usize,
        stage: &'static str,
    ) -> anyhow::Result<()> {
        self.record_observed(
            WorkCharge {
                rpc_bytes: bytes as u64,
                ..Default::default()
            },
            stage,
        )
    }

    fn record_observed(&self, charge: WorkCharge, stage: &'static str) -> anyhow::Result<()> {
        let exceeded = {
            let mut used = self.used.lock().expect("request work accounting lock");
            *used = used.add(charge)?;
            !used.fits(self.limits)
        };
        if exceeded {
            return Err(WorkLimitExceeded { stage }.into());
        }
        self.checkpoint(stage)
    }

    pub fn used(&self) -> WorkCharge {
        *self.used.lock().expect("request work accounting lock")
    }
    pub fn limits(&self) -> WorkLimits {
        self.limits
    }
    /// Views share one physical account and can only lower its original
    /// ceilings. The constructors cannot attach another request's counters.
    pub fn is_view_of(&self, parent: &Self) -> bool {
        Arc::ptr_eq(&self.used, &parent.used) && self.limits.fits(parent.limits)
    }

    /// Public singleflight work has its own lifetime once admitted. Retain its
    /// initiating request's physical account and ceilings without inheriting
    /// that waiter's cancellation; other consumers have their own wait budget.
    pub fn shared_owner_view(&self, deadline: std::time::Instant) -> Self {
        Self {
            deadline: SolverBudget::for_duration(
                deadline.saturating_duration_since(std::time::Instant::now()),
            ),
            limits: self.limits,
            used: self.used.clone(),
        }
    }
    pub fn remaining_time(&self) -> Option<Duration> {
        self.deadline.remaining()
    }
    /// Preserve the HTTP cancellation token when using inherited AMM math.
    pub fn solver_budget(&self) -> SolverBudget {
        self.deadline.clone()
    }

    pub fn with_deadline(&self, deadline: std::time::Instant) -> Self {
        Self {
            deadline: self.deadline.with_deadline(deadline),
            limits: self.limits,
            used: self.used.clone(),
        }
    }
    pub fn cancel(&self) {
        self.deadline.cancel();
    }

    /// Optional work shares all spending and cancellation, with strictly lower
    /// absolute ceilings and an earlier deadline. It cannot consume the work
    /// reserved for the parent's final verification or reset already spent work.
    pub fn with_finalization_reserve(&self, reserve: WorkCharge, time: Duration) -> Option<Self> {
        let limits = self.limits.subtract(reserve)?;
        let deadline = self.deadline.with_time_reserve(time)?;
        if !self.used().fits(limits) {
            return None;
        }
        Some(Self {
            deadline,
            limits,
            used: self.used.clone(),
        })
    }

    /// Stop a waiter at this view's deadline or request cancellation. Dropping
    /// the waiter does not cancel a separately owned physical RPC dispatch.
    pub async fn run<T>(
        &self,
        stage: &'static str,
        future: impl std::future::Future<Output = T>,
    ) -> anyhow::Result<T> {
        self.checkpoint(stage)?;
        tokio::pin!(future);
        let monitor = async {
            loop {
                let delay = self
                    .remaining_time()
                    .unwrap_or(Duration::from_millis(25))
                    .min(Duration::from_millis(25));
                tokio::time::sleep(delay).await;
                if let Err(error) = self.checkpoint(stage) {
                    return error;
                }
            }
        };
        let result = tokio::select! {
            result = &mut future => result,
            error = monitor => return Err(error),
        };
        self.checkpoint(stage)?;
        Ok(result)
    }

    pub fn admit_optional(&self, expected: Duration, finalization_reserve: Duration) -> bool {
        self.remaining_time().is_none_or(|remaining| {
            expected
                .checked_add(finalization_reserve)
                .is_some_and(|cost| cost <= remaining)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn optional_waiter_expires_without_cancelling_parent_or_releasing_physical_owner() {
        let parent = WorkBudget::bounded(SolverBudget::for_duration(Duration::from_secs(2)));
        let child = parent
            .with_finalization_reserve(WorkCharge::default(), Duration::from_millis(1950))
            .unwrap();
        let gate = crate::rpc_dispatch::RpcDispatch::for_scope(
            alloy_primitives::B256::repeat_byte(206),
            1,
            100,
        )
        .unwrap();
        let (done, wait) = tokio::sync::oneshot::channel();
        let result = child
            .run(
                "optional provider wait",
                gate.run(async move {
                    wait.await?;
                    Ok(())
                }),
            )
            .await;
        assert!(
            result
                .unwrap_err()
                .is::<crate::budget::SolverBudgetExceeded>()
        );
        assert!(parent.checkpoint("parent final verification").is_ok());
        assert!(gate.run(async { Ok(()) }).await.is_err());
        done.send(()).unwrap();
        tokio::time::sleep(Duration::from_millis(5)).await;
        assert!(gate.run(async { Ok(()) }).await.is_ok());
    }

    #[tokio::test]
    async fn request_cancellation_interrupts_an_unlimited_pending_waiter() {
        let parent = WorkBudget::bounded(SolverBudget::unlimited());
        let child = parent
            .with_finalization_reserve(WorkCharge::default(), Duration::ZERO)
            .unwrap();
        let cancel = parent.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(5)).await;
            cancel.cancel();
        });
        let result = tokio::time::timeout(
            Duration::from_millis(200),
            child.run("cancelled provider wait", std::future::pending::<()>()),
        )
        .await
        .unwrap();
        assert!(
            result
                .unwrap_err()
                .is::<crate::budget::SolverBudgetExceeded>()
        );
        assert!(parent.checkpoint("also cancelled").is_err());
    }

    #[test]
    fn clones_and_restarts_share_counters() {
        let limits = WorkLimits {
            candidates: 2,
            restarts: 1,
            ..WorkLimits::default()
        };
        let first = WorkBudget::new(SolverBudget::unlimited(), limits);
        let second = first.clone();
        first
            .charge(
                WorkCharge {
                    candidates: 1,
                    ..Default::default()
                },
                "first",
            )
            .unwrap();
        second
            .charge(
                WorkCharge {
                    restarts: 1,
                    candidates: 1,
                    ..Default::default()
                },
                "restart",
            )
            .unwrap();
        assert!(
            first
                .charge(
                    WorkCharge {
                        candidates: 1,
                        ..Default::default()
                    },
                    "third"
                )
                .is_err()
        );
        assert_eq!(first.used(), second.used());
    }

    #[test]
    fn failed_vector_charge_is_atomic() {
        let budget = WorkBudget::new(
            SolverBudget::unlimited(),
            WorkLimits {
                steps: 1,
                ..Default::default()
            },
        );
        assert!(
            budget
                .charge(
                    WorkCharge {
                        steps: 1,
                        rpc_calls: 1,
                        ..Default::default()
                    },
                    "bad"
                )
                .is_err()
        );
        assert_eq!(budget.used(), WorkCharge::default());
    }

    #[test]
    fn rfq_local_repairs_do_not_consume_anchor_restarts() {
        let budget = WorkBudget::bounded(SolverBudget::unlimited());
        budget
            .charge(
                WorkCharge {
                    credit_probes: 3,
                    rfq_requotes: 3,
                    ..Default::default()
                },
                "three local RFQ edges",
            )
            .unwrap();
        assert_eq!(budget.used().restarts, 0);
        assert_eq!(budget.used().credit_probes, 3);
        assert_eq!(budget.used().rfq_requotes, 3);
        assert!(
            budget
                .charge(
                    WorkCharge {
                        credit_probes: 62,
                        ..Default::default()
                    },
                    "probe cap"
                )
                .is_err()
        );
        assert_eq!(budget.used().credit_probes, 3);
    }

    #[test]
    fn measured_worker_overrun_and_cancelled_work_remain_accounted() {
        let budget = WorkBudget::new(
            SolverBudget::unlimited(),
            WorkLimits {
                compute_ns: 10,
                ..Default::default()
            },
        );
        budget.admit_compute("first worker").unwrap();
        assert!(
            budget
                .record_compute_duration(Duration::from_nanos(11), "first worker")
                .is_err()
        );
        assert_eq!(budget.used().compute_ns, 11);
        assert!(budget.admit_compute("second worker").is_err());

        let cancelled = WorkBudget::bounded(SolverBudget::unlimited());
        cancelled.cancel();
        assert!(
            cancelled
                .record_compute_duration(Duration::from_nanos(7), "cancelled worker")
                .is_err()
        );
        assert_eq!(cancelled.used().compute_ns, 7);
    }

    #[test]
    fn default_compute_ceiling_preserves_the_existing_request_deadline() {
        let bounded = WorkBudget::bounded(SolverBudget::for_duration(Duration::from_secs(3)));
        assert!(bounded.limits().compute_ns > 0);
        assert!(bounded.limits().compute_ns <= 3_000_000_000);
        assert_eq!(
            WorkBudget::bounded(SolverBudget::unlimited())
                .limits()
                .compute_ns,
            120_000_000_000
        );
        assert_eq!(
            WorkBudget::new(
                SolverBudget::unlimited(),
                WorkLimits {
                    compute_ns: 17,
                    ..Default::default()
                }
            )
            .limits()
            .compute_ns,
            17
        );
    }

    #[test]
    fn quote_expiry_view_retains_counters_limits_and_request_cancellation() {
        let parent = WorkBudget::bounded(SolverBudget::for_duration(Duration::from_secs(10)));
        parent
            .charge(
                WorkCharge {
                    quote_samples: 1,
                    ..Default::default()
                },
                "incumbent evaluation",
            )
            .unwrap();
        let expiry = std::time::Instant::now();
        let child = parent.with_deadline(expiry);
        assert!(child.is_view_of(&parent));
        assert_eq!(child.limits(), parent.limits());
        assert_eq!(child.used(), parent.used());
        assert!(
            child
                .with_deadline(expiry + Duration::from_secs(20))
                .checkpoint("cannot extend expired quote")
                .is_err()
        );
        assert!(parent.checkpoint("root finalization reserve").is_ok());
        child.cancel();
        assert!(parent.checkpoint("same request cancellation").is_err());
        assert_eq!(parent.used().quote_samples, 1);
    }

    #[test]
    fn cancelling_any_continuation_cancels_all() {
        let budget = WorkBudget::bounded(SolverBudget::unlimited());
        budget.clone().cancel();
        assert!(budget.checkpoint("cancelled").is_err());
        assert!(!budget.admit_optional(Duration::ZERO, Duration::from_millis(1)));
    }

    #[test]
    fn optional_child_cannot_spend_reserved_parent_rpc_work_or_reset_usage() {
        let parent = WorkBudget::new(
            SolverBudget::unlimited(),
            WorkLimits {
                rpc_calls: 40,
                rpc_bytes: 256 * 1024,
                ..Default::default()
            },
        );
        parent
            .charge(
                WorkCharge {
                    rpc_calls: 2,
                    rpc_bytes: 1024,
                    ..Default::default()
                },
                "initial facts",
            )
            .unwrap();
        let child = parent
            .with_finalization_reserve(
                WorkCharge {
                    rpc_calls: 32,
                    rpc_bytes: 128 * 1024,
                    ..Default::default()
                },
                Duration::from_secs(2),
            )
            .unwrap();
        assert_eq!(child.used(), parent.used());
        assert_eq!(child.limits().rpc_calls, 8);
        child
            .charge(
                WorkCharge {
                    rpc_calls: 6,
                    rpc_bytes: 127 * 1024,
                    ..Default::default()
                },
                "optional hydration",
            )
            .unwrap();
        let before = parent.used();
        assert!(
            child
                .charge(
                    WorkCharge {
                        rpc_calls: 1,
                        rpc_bytes: 1,
                        ..Default::default()
                    },
                    "would consume reserve"
                )
                .is_err()
        );
        assert_eq!(parent.used(), before);
        parent
            .charge(
                WorkCharge {
                    rpc_calls: 32,
                    rpc_bytes: 128 * 1024,
                    ..Default::default()
                },
                "final verification",
            )
            .unwrap();
        assert_eq!(child.used(), parent.used());
        assert_eq!(parent.used().rpc_calls, 40);
        assert_eq!(parent.used().rpc_bytes, 256 * 1024);
    }

    #[test]
    fn reserve_rejects_spent_or_oversized_limits_and_shares_cancellation() {
        let parent = WorkBudget::bounded(SolverBudget::unlimited());
        assert!(
            parent
                .with_finalization_reserve(
                    WorkCharge {
                        rpc_calls: parent.limits().rpc_calls + 1,
                        ..Default::default()
                    },
                    Duration::ZERO
                )
                .is_none()
        );
        let child = parent
            .with_finalization_reserve(
                WorkCharge {
                    rpc_calls: 32,
                    ..Default::default()
                },
                Duration::from_secs(2),
            )
            .unwrap();
        parent
            .charge(
                WorkCharge {
                    rpc_calls: parent.limits().rpc_calls - 31,
                    ..Default::default()
                },
                "parent outside optional lane",
            )
            .unwrap();
        assert!(
            parent
                .with_finalization_reserve(
                    WorkCharge {
                        rpc_calls: 32,
                        ..Default::default()
                    },
                    Duration::ZERO
                )
                .is_none()
        );
        child.cancel();
        assert!(parent.checkpoint("cancelled final work").is_err());
    }
}
#[test]
fn dispatched_cleanup_is_recorded_after_cancellation_and_limit_exhaustion() {
    let work = WorkBudget::new(
        SolverBudget::unlimited(),
        WorkLimits {
            rpc_calls: 1,
            ..Default::default()
        },
    );
    work.record_rpc_dispatch_attempt("first dispatched cleanup")
        .unwrap();
    work.cancel();
    let error = work
        .record_rpc_dispatch_attempt("second dispatched cleanup")
        .unwrap_err();
    assert!(error.downcast_ref::<WorkLimitExceeded>().is_some());
    assert_eq!(work.used().rpc_calls, 2);

    let canceled = WorkBudget::bounded(SolverBudget::unlimited());
    canceled.cancel();
    assert!(
        canceled
            .record_rpc_dispatch_attempt("already sent after cancel")
            .is_err()
    );
    assert_eq!(canceled.used().rpc_calls, 1);
    assert!(
        canceled
            .charge(
                WorkCharge {
                    rpc_calls: 1,
                    ..Default::default()
                },
                "new dispatch"
            )
            .is_err()
    );
    assert_eq!(canceled.used().rpc_calls, 1);
}
