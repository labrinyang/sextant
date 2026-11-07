use crate::rpc::{RpcUnavailable, RpcUncertain};
use anyhow::{Context, ensure};
use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// How long a dispatch whose outcome is unknown keeps its slot when nothing
/// else is configured. A provider has long stopped working on an abandoned
/// request by then.
pub const DEFAULT_UNCERTAIN_RELEASE: Duration = Duration::from_secs(60);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DispatchLimits {
    pub maximum_active: usize,
    pub maximum_per_second: usize,
    /// How long a request may wait, in arrival order, for a slot and a place
    /// in the per-second window before it is refused. Zero refuses at once.
    pub admission_wait: Duration,
    /// How long a dispatch whose outcome is unknown keeps its slot before it
    /// returns on its own. The operator can release it sooner.
    pub uncertain_release: Duration,
}

struct State {
    recent: VecDeque<Instant>,
    admitting: usize,
    unknown: Vec<(u64, OwnedSemaphorePermit)>,
    next_unknown: u64,
    unknown_epoch: u64,
    dispatched: u64,
    rejected_rate: u64,
    rejected_active: u64,
    released_unknown: u64,
}
struct Inner {
    slots: Arc<Semaphore>,
    state: Mutex<State>,
    limits: DispatchLimits,
}

impl Inner {
    /// Return one unknown dispatch's slot once its quarantine has passed,
    /// unless the operator already released it.
    fn release_unknown(&self, id: u64) {
        let mut state = self.state.lock().expect("RPC dispatch debt");
        if let Some(index) = state.unknown.iter().position(|(entry, _)| *entry == id) {
            let (_, permit) = state.unknown.swap_remove(index);
            state.released_unknown = state.released_unknown.saturating_add(1);
            drop(state);
            drop(permit);
        }
    }
}
/// A local admission reserves capacity without claiming a provider dispatch.
/// Budget rejection or unwinding before dispatch releases both reservations.
struct Admission {
    permit: Option<OwnedSemaphorePermit>,
    inner: Arc<Inner>,
}
impl Admission {
    fn dispatch(mut self) -> DispatchPermit {
        let mut state = self.inner.state.lock().expect("RPC dispatch state");
        state.admitting -= 1;
        state.recent.push_back(Instant::now());
        state.dispatched = state.dispatched.saturating_add(1);
        drop(state);
        DispatchPermit {
            permit: self.permit.take(),
            inner: self.inner.clone(),
        }
    }
}
impl Drop for Admission {
    fn drop(&mut self) {
        if let Some(permit) = self.permit.take() {
            let mut state = self.inner.state.lock().expect("RPC dispatch state");
            state.admitting -= 1;
            drop(state);
            drop(permit);
        }
    }
}
struct DispatchPermit {
    permit: Option<OwnedSemaphorePermit>,
    inner: Arc<Inner>,
}
impl DispatchPermit {
    fn terminal(&mut self) {
        drop(self.permit.take());
    }
}
impl Drop for DispatchPermit {
    fn drop(&mut self) {
        if let Some(permit) = self.permit.take() {
            let mut state = self.inner.state.lock().expect("RPC dispatch debt");
            let id = state.next_unknown;
            state.next_unknown = id.checked_add(1).expect("RPC dispatch ids exhausted");
            state.unknown.push((id, permit));
            state.unknown_epoch = state
                .unknown_epoch
                .checked_add(1)
                .expect("RPC dispatch epoch exhausted");
            drop(state);
            // Outside a runtime the debt waits for the operator instead.
            if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                let inner = Arc::downgrade(&self.inner);
                let quarantine = self.inner.limits.uncertain_release;
                runtime.spawn(async move {
                    tokio::time::sleep(quarantine).await;
                    if let Some(inner) = inner.upgrade() {
                        inner.release_unknown(id);
                    }
                });
            }
        }
    }
}
#[derive(Clone)]
pub struct RpcDispatch {
    inner: Arc<Inner>,
}

/// Scope-wide gauges and cumulative counters. Reading this snapshot neither
/// acquires capacity nor changes the rolling rate window.
#[derive(Clone, Copy, Debug, Default, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcDispatchUsage {
    pub maximum_active: usize,
    pub maximum_per_second: usize,
    /// Includes local admissions, running owners and unresolved dispatches.
    pub slots_used: usize,
    pub admitting: usize,
    pub recent_rate_used: usize,
    pub unknown_dispatches: usize,
    pub unknown_epoch: u64,
    /// Unknown dispatches whose quarantine passed and whose slot returned.
    pub released_unknown: u64,
    pub dispatched: u64,
    pub rejected_rate: u64,
    pub rejected_active: u64,
    pub admission_wait_ms: u64,
    pub uncertain_release_secs: u64,
}

#[derive(Debug)]
pub struct RpcCapacity;
impl std::fmt::Display for RpcCapacity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RPC dispatch capacity exhausted")
    }
}
impl std::error::Error for RpcCapacity {}

impl RpcDispatch {
    /// Limits that refuse at once when full; tests use them to observe
    /// refusals.
    pub fn for_scope(
        scope: alloy_primitives::B256,
        maximum_active: usize,
        maximum_per_second: usize,
    ) -> anyhow::Result<Self> {
        Self::with_limits(
            scope,
            DispatchLimits {
                maximum_active,
                maximum_per_second,
                admission_wait: Duration::ZERO,
                uncertain_release: DEFAULT_UNCERTAIN_RELEASE,
            },
        )
    }

    pub fn with_limits(
        scope: alloy_primitives::B256,
        limits: DispatchLimits,
    ) -> anyhow::Result<Self> {
        let DispatchLimits {
            maximum_active,
            maximum_per_second,
            admission_wait,
            uncertain_release,
        } = limits;
        ensure!(
            (1..=1024).contains(&maximum_active) && (1..=100_000).contains(&maximum_per_second),
            "RPC dispatch limits exceed bounded policy"
        );
        ensure!(
            admission_wait <= Duration::from_secs(60)
                && (Duration::from_secs(1)..=Duration::from_secs(3_600))
                    .contains(&uncertain_release),
            "RPC dispatch waits exceed bounded policy"
        );
        static SCOPES: OnceLock<Mutex<HashMap<alloy_primitives::B256, Weak<Inner>>>> =
            OnceLock::new();
        let mut scopes = SCOPES
            .get_or_init(Default::default)
            .lock()
            .expect("RPC quota registry");
        scopes.retain(|_, scope| scope.strong_count() > 0);
        let inner = scopes
            .get(&scope)
            .and_then(Weak::upgrade)
            .unwrap_or_else(|| {
                let inner = Arc::new(Inner {
                    slots: Arc::new(Semaphore::new(maximum_active)),
                    state: Mutex::new(State {
                        recent: VecDeque::new(),
                        admitting: 0,
                        unknown: Vec::new(),
                        next_unknown: 0,
                        unknown_epoch: 0,
                        dispatched: 0,
                        rejected_rate: 0,
                        rejected_active: 0,
                        released_unknown: 0,
                    }),
                    limits,
                });
                scopes.insert(scope, Arc::downgrade(&inner));
                inner
            });
        ensure!(
            inner.limits == limits,
            "RPC quota group has inconsistent configured limits"
        );
        Ok(Self { inner })
    }

    /// Reserve a place in the per-second window for a slot already held, or
    /// say how long until the oldest dispatch leaves the window.
    fn reserve_rate(
        &self,
        permit: OwnedSemaphorePermit,
    ) -> Result<Admission, (OwnedSemaphorePermit, Duration)> {
        let mut state = self.inner.state.lock().expect("RPC dispatch state");
        let now = Instant::now();
        let window = Duration::from_secs(1);
        while state
            .recent
            .front()
            .is_some_and(|time| now.duration_since(*time) >= window)
        {
            state.recent.pop_front();
        }
        if state.recent.len() + state.admitting >= self.inner.limits.maximum_per_second {
            // Reservations still being dispatched leave no timestamp to wait
            // for; look again shortly.
            let wait = state
                .recent
                .front()
                .map_or(Duration::from_millis(5), |oldest| {
                    window.saturating_sub(now.duration_since(*oldest))
                });
            return Err((permit, wait.max(Duration::from_millis(1))));
        }
        state.admitting += 1;
        Ok(Admission {
            permit: Some(permit),
            inner: self.inner.clone(),
        })
    }

    fn count_rejection(&self, rate: bool) {
        let mut state = self.inner.state.lock().expect("RPC dispatch state");
        if rate {
            state.rejected_rate = state.rejected_rate.saturating_add(1);
        } else {
            state.rejected_active = state.rejected_active.saturating_add(1);
        }
    }

    /// Admit now or refuse.
    fn try_admit(&self) -> anyhow::Result<Admission> {
        let Ok(permit) = self.inner.slots.clone().try_acquire_owned() else {
            self.count_rejection(false);
            return Err(RpcCapacity.into());
        };
        self.reserve_rate(permit).map_err(|_| {
            self.count_rejection(true);
            RpcCapacity.into()
        })
    }

    /// Admit in arrival order, waiting up to the configured bound for a slot
    /// and then for room in the per-second window. A burst queues instead of
    /// failing part-way through a request; only a wait past the bound is
    /// refused. Dropping the future while it waits gives back what it held.
    async fn admit(&self) -> anyhow::Result<Admission> {
        let wait = self.inner.limits.admission_wait;
        if wait.is_zero() {
            return self.try_admit();
        }
        let deadline = tokio::time::Instant::now() + wait;
        let permit = match self.inner.slots.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                match tokio::time::timeout_at(deadline, self.inner.slots.clone().acquire_owned())
                    .await
                {
                    Ok(Ok(permit)) => permit,
                    _ => {
                        self.count_rejection(false);
                        return Err(RpcCapacity.into());
                    }
                }
            }
        };
        let mut permit = permit;
        loop {
            match self.reserve_rate(permit) {
                Ok(admission) => return Ok(admission),
                Err((held, retry_in)) => {
                    if tokio::time::Instant::now() + retry_in > deadline {
                        drop(held);
                        self.count_rejection(true);
                        return Err(RpcCapacity.into());
                    }
                    tokio::time::sleep(retry_in).await;
                    permit = held;
                }
            }
        }
    }

    pub async fn run<T, F>(&self, operation: F) -> anyhow::Result<T>
    where
        T: Send + 'static,
        F: Future<Output = anyhow::Result<T>> + Send + 'static,
    {
        self.run_with_admission(|| Ok(()), operation).await
    }

    /// Account only after local capacity has been reserved. The synchronous
    /// callback runs without a state lock, inside the detached physical owner,
    /// immediately before provider polling. Failure releases unstarted capacity
    /// without spending rate quota or recording an uncertain dispatch.
    pub async fn run_with_admission<T, F, A>(
        &self,
        before_dispatch: A,
        operation: F,
    ) -> anyhow::Result<T>
    where
        T: Send + 'static,
        F: Future<Output = anyhow::Result<T>> + Send + 'static,
        A: FnOnce() -> anyhow::Result<()> + Send + 'static,
    {
        // Boxed so a request waiting for admission does not carry its whole
        // provider future inline in every caller's state machine.
        let operation = Box::pin(operation);
        let admission = self.admit().await?;
        let owner = tokio::spawn(async move {
            before_dispatch()?;
            let mut permit = admission.dispatch();
            let result = operation.await;
            let uncertain = result
                .as_ref()
                .err()
                .is_some_and(|error| error.downcast_ref::<RpcUncertain>().is_some());
            if !uncertain {
                permit.terminal();
            }
            result
        });
        owner.await.context(RpcUnavailable("RPC dispatch owner"))?
    }

    pub fn unknown_dispatches(&self) -> usize {
        self.inner
            .state
            .lock()
            .expect("RPC dispatch state")
            .unknown
            .len()
    }

    pub fn unknown_epoch(&self) -> u64 {
        self.inner
            .state
            .lock()
            .expect("RPC dispatch state")
            .unknown_epoch
    }

    pub fn usage(&self) -> RpcDispatchUsage {
        let state = self.inner.state.lock().expect("RPC dispatch state");
        let now = Instant::now();
        RpcDispatchUsage {
            maximum_active: self.inner.limits.maximum_active,
            maximum_per_second: self.inner.limits.maximum_per_second,
            slots_used: self.inner.limits.maximum_active - self.inner.slots.available_permits(),
            admitting: state.admitting,
            recent_rate_used: state
                .recent
                .iter()
                .filter(|time| now.duration_since(**time) < Duration::from_secs(1))
                .count(),
            unknown_dispatches: state.unknown.len(),
            unknown_epoch: state.unknown_epoch,
            released_unknown: state.released_unknown,
            dispatched: state.dispatched,
            rejected_rate: state.rejected_rate,
            rejected_active: state.rejected_active,
            admission_wait_ms: self.inner.limits.admission_wait.as_millis() as u64,
            uncertain_release_secs: self.inner.limits.uncertain_release.as_secs(),
        }
    }

    /// Only the separately authenticated operator channel may reconcile debt,
    /// after provider-confirmed termination of every unresolved request.
    /// A stale epoch cannot release newly incurred debt. Active owners and
    /// per-second dispatch quota remain charged.
    pub fn reconcile_unknown(&self, expected_epoch: u64) -> anyhow::Result<usize> {
        let mut state = self.inner.state.lock().expect("RPC dispatch state");
        ensure!(
            state.unknown_epoch == expected_epoch,
            "rpc_recovery_epoch_conflict"
        );
        let count = state.unknown.len();
        let next = state
            .unknown_epoch
            .checked_add(1)
            .context("RPC dispatch epoch exhausted")?;
        state.unknown.clear();
        state.unknown_epoch = next;
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[tokio::test]
    async fn pre_dispatch_unwind_releases_capacity_without_unknown_debt() {
        let gate = RpcDispatch::for_scope(alloy_primitives::B256::repeat_byte(214), 1, 1).unwrap();
        let polled = Arc::new(AtomicBool::new(false));
        let operation_polled = polled.clone();
        let error = gate
            .run_with_admission(|| panic!("pre-dispatch fixture panic"), async move {
                operation_polled.store(true, Ordering::Release);
                Ok(())
            })
            .await
            .unwrap_err();
        assert!(error.is::<RpcUnavailable>());
        assert!(!polled.load(Ordering::Acquire));
        assert_eq!(gate.unknown_dispatches(), 0);
        assert_eq!(gate.unknown_epoch(), 0);
        let usage = gate.usage();
        assert_eq!(usage.slots_used, 0);
        assert_eq!(usage.admitting, 0);
        assert_eq!(usage.dispatched, 0);
        assert_eq!(usage.recent_rate_used, 0);
        assert!(gate.run(async { Ok(()) }).await.is_ok());
    }

    #[test]
    fn outstanding_admissions_reserve_rate_capacity_until_released() {
        let gate = RpcDispatch::for_scope(alloy_primitives::B256::repeat_byte(215), 2, 1).unwrap();
        let admission = gate.try_admit().unwrap();
        let usage = gate.usage();
        assert_eq!(usage.maximum_active, 2);
        assert_eq!(usage.maximum_per_second, 1);
        assert_eq!(usage.slots_used, 1);
        assert_eq!(usage.admitting, 1);
        assert_eq!(usage.recent_rate_used, 0);
        assert_eq!(usage.dispatched, 0);
        assert!(gate.try_admit().is_err());
        assert_eq!(gate.usage().rejected_rate, 1);
        assert_eq!(gate.usage().rejected_active, 0);
        drop(admission);
        assert_eq!(gate.usage().slots_used, 0);
        assert_eq!(gate.usage().admitting, 0);
        assert!(gate.try_admit().is_ok());
        assert_eq!(gate.unknown_dispatches(), 0);
    }

    #[test]
    fn usage_observes_the_current_rate_window_without_mutating_it() {
        let gate = RpcDispatch::for_scope(alloy_primitives::B256::repeat_byte(216), 2, 10).unwrap();
        let now = Instant::now();
        gate.inner
            .state
            .lock()
            .unwrap()
            .recent
            .extend([now - Duration::from_secs(2), now]);
        let usage = gate.usage();
        assert_eq!(usage.recent_rate_used, 1);
        assert_eq!(usage.slots_used, 0);
        assert_eq!(usage.dispatched, 0);
        assert_eq!(gate.inner.state.lock().unwrap().recent.len(), 2);
    }

    #[tokio::test]
    async fn usage_distinguishes_running_and_unresolved_physical_dispatches() {
        let gate = RpcDispatch::for_scope(alloy_primitives::B256::repeat_byte(217), 1, 10).unwrap();
        let (started, running) = tokio::sync::oneshot::channel();
        let (done, finish) = tokio::sync::oneshot::channel();
        let owner_gate = gate.clone();
        let owner = tokio::spawn(async move {
            owner_gate
                .run(async move {
                    started.send(()).unwrap();
                    finish.await?;
                    Err::<(), _>(RpcUncertain("fixture").into())
                })
                .await
        });
        running.await.unwrap();
        let usage = gate.usage();
        assert_eq!(usage.slots_used, 1);
        assert_eq!(usage.admitting, 0);
        assert_eq!(usage.dispatched, 1);
        assert_eq!(usage.recent_rate_used, 1);
        assert_eq!(usage.unknown_dispatches, 0);
        assert!(gate.run(async { Ok(()) }).await.is_err());
        assert_eq!(gate.usage().rejected_active, 1);
        assert_eq!(gate.usage().rejected_rate, 0);
        done.send(()).unwrap();
        assert!(owner.await.unwrap().is_err());
        let usage = gate.usage();
        assert_eq!(usage.slots_used, 1);
        assert_eq!(usage.dispatched, 1);
        assert_eq!(usage.unknown_dispatches, 1);
        assert_eq!(usage.unknown_epoch, 1);
        gate.reconcile_unknown(usage.unknown_epoch).unwrap();
        let recovered = gate.usage();
        assert_eq!(recovered.slots_used, 0);
        assert_eq!(recovered.unknown_dispatches, 0);
        assert_eq!(recovered.dispatched, 1);
        assert_eq!(recovered.recent_rate_used, 1);
    }

    #[tokio::test]
    async fn waiter_cancellation_does_not_release_an_active_provider_request() {
        let gate = RpcDispatch::for_scope(alloy_primitives::B256::repeat_byte(201), 1, 10).unwrap();
        let complete = Arc::new(AtomicBool::new(false));
        let owner_gate = gate.clone();
        let owner_complete = complete.clone();
        let caller = tokio::spawn(async move {
            owner_gate
                .run(async move {
                    tokio::time::sleep(Duration::from_millis(40)).await;
                    owner_complete.store(true, Ordering::Release);
                    Ok(())
                })
                .await
        });
        tokio::time::sleep(Duration::from_millis(5)).await;
        caller.abort();
        assert!(gate.run(async { Ok(()) }).await.is_err());
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(complete.load(Ordering::Acquire));
        assert!(gate.run(async { Ok(()) }).await.is_ok());
    }
    #[tokio::test]
    async fn uncertain_transport_completion_stays_charged() {
        let gate = RpcDispatch::for_scope(alloy_primitives::B256::repeat_byte(202), 1, 10).unwrap();
        let result: Result<(), _> = gate
            .run(async { Err(anyhow::anyhow!("timeout").context(RpcUncertain("eth_call"))) })
            .await;
        assert!(result.is_err());
        assert_eq!(gate.unknown_dispatches(), 1);
        assert!(gate.run(async { Ok(()) }).await.is_err());
    }
    #[tokio::test]
    async fn a_valid_execution_revert_is_terminal_and_releases_its_slot() {
        let gate = RpcDispatch::for_scope(alloy_primitives::B256::repeat_byte(203), 1, 10).unwrap();
        let result: Result<(), _> = gate
            .run(async {
                Err(anyhow::anyhow!("revert").context(crate::rpc::RpcRejected("eth_call")))
            })
            .await;
        assert!(result.is_err());
        assert_eq!(gate.unknown_dispatches(), 0);
        assert!(gate.run(async { Ok(()) }).await.is_ok());
    }
    fn waiting_gate(scope: u8, active: usize, rate: usize, wait_ms: u64) -> RpcDispatch {
        RpcDispatch::with_limits(
            alloy_primitives::B256::repeat_byte(scope),
            DispatchLimits {
                maximum_active: active,
                maximum_per_second: rate,
                admission_wait: Duration::from_millis(wait_ms),
                uncertain_release: Duration::from_secs(5),
            },
        )
        .unwrap()
    }

    #[tokio::test]
    async fn a_full_gate_queues_a_request_instead_of_refusing_it() {
        let gate = waiting_gate(230, 1, 100, 2_000);
        let (started, running) = tokio::sync::oneshot::channel();
        let holder = gate.clone();
        let owner = tokio::spawn(async move {
            holder
                .run(async move {
                    started.send(()).unwrap();
                    tokio::time::sleep(Duration::from_millis(30)).await;
                    Ok(1)
                })
                .await
        });
        running.await.unwrap();
        assert_eq!(gate.run(async { Ok(2) }).await.unwrap(), 2);
        assert_eq!(owner.await.unwrap().unwrap(), 1);
        let usage = gate.usage();
        assert_eq!(usage.rejected_active, 0);
        assert_eq!(usage.dispatched, 2);
        assert_eq!(usage.slots_used, 0);
        assert_eq!(usage.admission_wait_ms, 2_000);
    }

    #[tokio::test]
    async fn the_wait_for_a_slot_is_bounded() {
        let gate = waiting_gate(231, 1, 100, 20);
        let (started, running) = tokio::sync::oneshot::channel();
        let (done, finish) = tokio::sync::oneshot::channel::<()>();
        let holder = gate.clone();
        let owner = tokio::spawn(async move {
            holder
                .run(async move {
                    started.send(()).unwrap();
                    finish.await?;
                    Ok(())
                })
                .await
        });
        running.await.unwrap();
        let error = gate.run(async { Ok(()) }).await.unwrap_err();
        assert!(error.is::<RpcCapacity>());
        assert_eq!(gate.usage().rejected_active, 1);
        assert_eq!(gate.usage().admitting, 0);
        done.send(()).unwrap();
        owner.await.unwrap().unwrap();
        assert_eq!(gate.usage().slots_used, 0);
    }

    #[tokio::test]
    async fn a_full_rate_window_waits_for_its_oldest_dispatch() {
        let gate = waiting_gate(232, 2, 1, 1_000);
        // The window's only dispatch leaves it 40 ms from now.
        gate.inner
            .state
            .lock()
            .unwrap()
            .recent
            .push_back(Instant::now() - Duration::from_millis(960));
        let started = Instant::now();
        gate.run(async { Ok(()) }).await.unwrap();
        assert!(started.elapsed() >= Duration::from_millis(30));
        assert_eq!(gate.usage().rejected_rate, 0);

        // A window that cannot clear within the bound is refused at once.
        let short = waiting_gate(233, 2, 1, 10);
        short
            .inner
            .state
            .lock()
            .unwrap()
            .recent
            .push_back(Instant::now());
        let error = short.run(async { Ok(()) }).await.unwrap_err();
        assert!(error.is::<RpcCapacity>());
        assert_eq!(short.usage().rejected_rate, 1);
        assert_eq!(short.usage().slots_used, 0);
    }

    #[tokio::test]
    async fn a_dropped_waiter_gives_back_its_place() {
        let gate = waiting_gate(234, 1, 100, 5_000);
        let (started, running) = tokio::sync::oneshot::channel();
        let (done, finish) = tokio::sync::oneshot::channel::<()>();
        let holder = gate.clone();
        let owner = tokio::spawn(async move {
            holder
                .run(async move {
                    started.send(()).unwrap();
                    finish.await?;
                    Ok(())
                })
                .await
        });
        running.await.unwrap();
        let waiter = gate.clone();
        let polled = Arc::new(AtomicBool::new(false));
        let operation_polled = polled.clone();
        let queued = tokio::spawn(async move {
            waiter
                .run(async move {
                    operation_polled.store(true, Ordering::Release);
                    Ok(())
                })
                .await
        });
        tokio::time::sleep(Duration::from_millis(10)).await;
        queued.abort();
        assert!(queued.await.unwrap_err().is_cancelled());
        done.send(()).unwrap();
        owner.await.unwrap().unwrap();
        assert!(!polled.load(Ordering::Acquire));
        let usage = gate.usage();
        assert_eq!(usage.slots_used, 0);
        assert_eq!(usage.admitting, 0);
        assert_eq!(usage.dispatched, 1);
    }

    #[tokio::test(start_paused = true)]
    async fn an_uncertain_dispatch_returns_its_slot_after_the_quarantine() {
        let gate = waiting_gate(235, 1, 100, 0);
        let result: Result<(), _> = gate
            .run(async { Err(RpcUncertain("fixture").into()) })
            .await;
        assert!(result.is_err());
        assert_eq!(gate.unknown_dispatches(), 1);
        assert!(gate.run(async { Ok(()) }).await.is_err());

        tokio::time::sleep(Duration::from_secs(5) + Duration::from_millis(1)).await;
        assert_eq!(gate.unknown_dispatches(), 0);
        assert_eq!(gate.usage().released_unknown, 1);
        assert!(gate.run(async { Ok(()) }).await.is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn an_operator_release_wins_over_the_quarantine_timer() {
        let gate = waiting_gate(236, 2, 100, 0);
        let result: Result<(), _> = gate
            .run(async { Err(RpcUncertain("fixture").into()) })
            .await;
        assert!(result.is_err());
        let epoch = gate.unknown_epoch();
        assert_eq!(gate.reconcile_unknown(epoch).unwrap(), 1);
        tokio::time::sleep(Duration::from_secs(6)).await;
        // The timer found nothing to release, so no slot was returned twice.
        assert_eq!(gate.usage().released_unknown, 0);
        assert_eq!(gate.inner.slots.available_permits(), 2);
    }

    #[test]
    fn waits_are_bounded_by_policy() {
        for (wait, release) in [(61_000, 60), (0, 0), (0, 3_601)] {
            assert!(
                RpcDispatch::with_limits(
                    alloy_primitives::B256::repeat_byte(237),
                    DispatchLimits {
                        maximum_active: 1,
                        maximum_per_second: 1,
                        admission_wait: Duration::from_millis(wait),
                        uncertain_release: Duration::from_secs(release),
                    },
                )
                .is_err()
            );
        }
    }

    #[tokio::test]
    async fn owner_panic_retains_unknown_physical_dispatch() {
        let gate = RpcDispatch::for_scope(alloy_primitives::B256::repeat_byte(204), 1, 10).unwrap();
        let result: Result<(), _> = gate.run(async { panic!("fixture panic") }).await;
        assert!(result.is_err());
        assert_eq!(gate.unknown_dispatches(), 1);
    }

    #[tokio::test]
    async fn recovery_is_epoch_guarded_and_does_not_release_active_owners() {
        let gate =
            RpcDispatch::for_scope(alloy_primitives::B256::repeat_byte(205), 2, 100).unwrap();
        let result: Result<(), _> = gate
            .run(async { Err(RpcUncertain("fixture").into()) })
            .await;
        assert!(result.is_err());
        let epoch = gate.unknown_epoch();
        let (done, wait) = tokio::sync::oneshot::channel();
        let active = gate.clone();
        let owner = tokio::spawn(async move {
            active
                .run(async move {
                    wait.await?;
                    Ok(())
                })
                .await
        });
        while gate.inner.slots.available_permits() > 0 {
            tokio::task::yield_now().await;
        }
        assert!(gate.reconcile_unknown(epoch + 1).is_err());
        assert_eq!(gate.reconcile_unknown(epoch).unwrap(), 1);
        assert_eq!(gate.inner.slots.available_permits(), 1);
        assert!(gate.reconcile_unknown(epoch).is_err());
        let result: Result<(), _> = gate
            .run(async { Err(RpcUncertain("new fixture").into()) })
            .await;
        assert!(result.is_err());
        assert!(gate.reconcile_unknown(epoch).is_err());
        assert_eq!(gate.unknown_dispatches(), 1);
        done.send(()).unwrap();
        owner.await.unwrap().unwrap();
    }
}
