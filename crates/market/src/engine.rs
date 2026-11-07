// Resident state engine: recently-quoted pairs stay hot in memory.
//
// A quote leases its (unordered) token pair for LEASE. While the lease
// lives AND the pair is in demand, a per-pair refresher replaces its
// snapshot at about 1.5s of age by subtracting twice the previous pull
// duration from its next delay. Slow pulls retain a 200ms floor; fast pulls no
// longer busy-poll the RPC. Snapshots are published wait-free through ArcSwap.
// A cold pair, or one whose snapshot has aged past STALE, is pulled inline by
// the quote — the same
// state::snapshot the refresher runs, not a second implementation — which
// then (re)ignites the refresher. A per-pair shared future single-flights
// cold and stale pulls, including failures and background-refresher races.
//
// The refresher is a PREFETCH BET, and the lease alone is the wrong stake.
// It pulls on its own clock and wins only when a quote arrives to read what
// it fetched; every pull nobody reads is overwritten unread and pure upstream
// cost. Below roughly its own pull rate that bet always loses, because the
// STALE gate already serves those same quotes off the previous quote's pull
// at one pull each — so a slow caller pays for a prefetch that buys it
// nothing. Measured in production before this gate existed: one leased pair
// cost ~42 pulls/min (~336 upstream calls/min) while the terminal quoted it
// four times a minute, and a browser tab left open renewed the lease forever.
// So the refresher now runs only while a pair is genuinely being quoted at
// the rate that makes prefetching pay, and idles dark otherwise.
//
// Liveness recovery is deliberately single-mechanism: a refresher that
// stops (RPC error, or a lease bump lost to the exit race) just lets the
// snapshot age out, and the next quote's stale pull revives the pair.
// Expired idle entries are removed on the next lookup, and a hard resident
// cap prevents arbitrary token pairs from growing memory without bound.

use crate::chain::ChainProfile;
#[cfg(any(test, feature = "testing"))]
use crate::chain::ROBINHOOD_PROFILE;
use crate::freshness::{FINISH_GRACE, STALE};
use crate::indexer::IndexerClient;
use crate::rpc::{Rpc, sanitized_error};
use crate::snapshot::{ScreeningPools, Snapshot};
use crate::state;
use crate::topology::IndexerError;
use crate::universe::RouteUniverse;
use alloy::eips::BlockId;
use alloy_primitives::Address;
use arc_swap::ArcSwapOption;
use futures_util::FutureExt;
use futures_util::future::{BoxFuture, Shared};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::{Mutex as AsyncMutex, Semaphore};

const LEASE: Duration = Duration::from_secs(60);
const FLOOR: Duration = Duration::from_millis(200);
/// The age at which the refresher's next snapshot replaces the current one,
/// inside `STALE` with room for a slow pull.
const REFRESH_TARGET: Duration = Duration::from_millis(1_500);
const MAX_PAIRS: usize = 256;

/// How many recent arrivals define "in demand", and the window they must fall
/// within. A pair refreshes only while its last DEMAND_SAMPLES quotes all
/// landed inside DEMAND_WINDOW — roughly one quote per 1.25s, comparable to
/// the refresher's own ~1.4s cycle, which is exactly the rate at which a
/// prefetched snapshot is more likely read than overwritten.
///
/// The window is deliberately wider than a single inter-quote gap. The real
/// client polls a pair every 15s and doubles each poll with a 1% impact probe,
/// so arrivals come as bursts of two: any rule reading one gap sees the ~0ms
/// inside a burst and mistakes idle polling for load. Requiring EIGHT arrivals
/// to fit in ten seconds reads a burst of two as the idle traffic it is, while
/// someone actually working an order clears it easily.
const DEMAND_SAMPLES: usize = 8;
const DEMAND_WINDOW: Duration = Duration::from_secs(10);

/// Empty slot in the arrival ring. Not 0: `now_ms` is measured from engine
/// construction, so a quote can legitimately land at millisecond 0.
const NO_ARRIVAL: u64 = u64::MAX;

/// A snapshot plus its publication instant.
pub struct Stamped {
    pub snap: Snapshot,
    /// Priced-but-unroutable pool state; empty unless screening is enabled.
    pub screening: ScreeningPools,
    pub universe: RouteUniverse,
    /// The candidates a resident quote may admit once probed, with the state
    /// to read their pools. `None` off the resident state.
    pub widening: Option<Arc<crate::resident::Widening>>,
    pub topology_fences: Option<crate::topology::CatalogFences>,
    block_id: BlockId,
    block_timestamp: u64,
    at: Instant,
    /// When the block was first read: the instant its timestamp is projected
    /// forward from.
    observed_at: Instant,
    rpc_calls: u64,
}

impl Stamped {
    /// A resident snapshot's pools for one pair. `at` is the last time the
    /// resident reader found this block still the head, which is what makes
    /// it fresh: no RPC ran for this quote. `observed_at` is when the reader
    /// first read the block, as a pulled snapshot's is.
    pub(crate) fn resident(start: crate::resident::ResidentStart) -> Arc<Self> {
        let crate::resident::ResidentStart {
            start,
            widening,
            block_id,
            block_timestamp,
            at,
            observed_at,
        } = start;
        Arc::new(Stamped {
            snap: start.snapshot,
            screening: ScreeningPools::default(),
            universe: start.universe,
            widening: Some(widening),
            topology_fences: None,
            block_id,
            block_timestamp,
            at,
            observed_at,
            rpc_calls: 0,
        })
    }

    fn new(observed: state::ObservedSnapshot, rpc_calls: u64) -> Arc<Self> {
        Arc::new(Stamped {
            snap: observed.snapshot,
            screening: observed.screening,
            universe: observed.universe,
            widening: None,
            topology_fences: observed.topology_fences,
            block_id: observed.block_id,
            block_timestamp: observed.block_timestamp,
            at: observed.observed_at,
            observed_at: observed.observed_at,
            rpc_calls,
        })
    }

    /// The same block's stamp over a wider resident graph.
    pub fn widened(&self, graph: crate::resident::Widened) -> Arc<Self> {
        Arc::new(Stamped {
            snap: graph.snapshot,
            screening: ScreeningPools::default(),
            universe: graph.universe,
            widening: self.widening.clone(),
            topology_fences: self.topology_fences,
            block_id: self.block_id,
            block_timestamp: self.block_timestamp,
            at: self.at,
            observed_at: self.observed_at,
            rpc_calls: self.rpc_calls,
        })
    }

    pub fn age(&self) -> Duration {
        self.at.elapsed()
    }

    pub fn is_fresh(&self) -> bool {
        self.age() <= STALE
    }

    /// Young enough for a quote that started while it was fresh to finish.
    pub fn is_fresh_to_finish(&self) -> bool {
        self.age() <= STALE + FINISH_GRACE
    }

    pub fn block_id(&self) -> BlockId {
        self.block_id
    }

    /// Consensus timestamp of the pinned block.
    pub fn block_timestamp(&self) -> u64 {
        self.block_timestamp
    }

    /// Project the pinned block's consensus timestamp forward with a
    /// monotonic duration. This remains in the chain's time domain even when
    /// the host wall clock is skewed.
    pub fn chain_now(&self) -> u64 {
        self.block_timestamp
            .saturating_add(self.observed_at.elapsed().as_secs())
    }

    pub fn rpc_calls(&self) -> u64 {
        self.rpc_calls
    }
}

#[derive(Clone)]
enum PullFailure {
    Capacity,
    Rpc(&'static str),
    Rejected(&'static str),
    Indexer(IndexerError),
    Integrity(crate::state::UpstreamIntegrityError),
    Other(Arc<str>),
}

impl PullFailure {
    fn capture(error: anyhow::Error) -> Self {
        if error.is::<crate::rpc_dispatch::RpcCapacity>() {
            Self::Capacity
        } else if let Some(error) = error.downcast_ref::<crate::rpc::RpcUnavailable>() {
            Self::Rpc(error.0)
        } else if let Some(error) = error.downcast_ref::<crate::rpc::RpcRejected>() {
            Self::Rejected(error.0)
        } else if let Some(error) = error.downcast_ref::<IndexerError>() {
            Self::Indexer(error.clone())
        } else if let Some(error) = error.downcast_ref::<crate::state::UpstreamIntegrityError>() {
            Self::Integrity(error.clone())
        } else {
            Self::Other(format!("{error:#}").into())
        }
    }

    fn into_error(self) -> anyhow::Error {
        match self {
            Self::Capacity => crate::rpc_dispatch::RpcCapacity.into(),
            Self::Rpc(method) => {
                anyhow::anyhow!("shared snapshot pull").context(crate::rpc::RpcUnavailable(method))
            }
            Self::Rejected(method) => {
                anyhow::anyhow!("shared snapshot pull").context(crate::rpc::RpcRejected(method))
            }
            Self::Indexer(error) => anyhow::Error::new(error).context("shared snapshot pull"),
            Self::Integrity(error) => anyhow::Error::new(error).context("shared snapshot pull"),
            Self::Other(message) => anyhow::anyhow!("{message}"),
        }
    }
}

type PullResult = Result<(Arc<Stamped>, Duration), PullFailure>;
type PullFuture = Shared<BoxFuture<'static, PullResult>>;

struct Inflight {
    id: u64,
    future: PullFuture,
}

#[derive(Default)]
struct PullGate {
    next_id: u64,
    inflight: Option<Inflight>,
}

struct Pair {
    snap: ArcSwapOption<Stamped>,
    pulling: AsyncMutex<PullGate>,
    /// lease deadline in millis since Engine.start; fetch_max keeps it monotonic
    lease: AtomicU64,
    pull_ms: AtomicU64,
    refreshing: AtomicBool,
    /// Ring of the last DEMAND_SAMPLES quote arrivals, in millis since
    /// Engine.start. `next` indexes the slot to overwrite, which is also the
    /// oldest retained arrival.
    arrivals: Mutex<([u64; DEMAND_SAMPLES], usize)>,
}

impl Pair {
    fn new() -> Self {
        Self {
            snap: ArcSwapOption::empty(),
            pulling: AsyncMutex::new(PullGate::default()),
            lease: AtomicU64::new(0),
            pull_ms: AtomicU64::new(0),
            refreshing: AtomicBool::new(false),
            arrivals: Mutex::new(([NO_ARRIVAL; DEMAND_SAMPLES], 0)),
        }
    }

    fn observe_quote(&self, now_ms: u64) {
        let mut ring = self.arrivals.lock().expect("arrivals lock");
        let (slots, next) = &mut *ring;
        slots[*next] = now_ms;
        *next = (*next + 1) % DEMAND_SAMPLES;
    }

    /// Whether quotes are arriving fast enough that prefetching pays for
    /// itself. False for a cold pair, for idle polling, and for a burst that
    /// has since stopped — the oldest retained arrival ages out of the window
    /// on its own, so a refresher checking this each cycle exits when demand
    /// dies without needing anyone to tell it.
    fn in_demand(&self, now_ms: u64) -> bool {
        let ring = self.arrivals.lock().expect("arrivals lock");
        let (slots, next) = &*ring;
        let oldest = slots[*next];
        oldest != NO_ARRIVAL && now_ms.saturating_sub(oldest) <= DEMAND_WINDOW.as_millis() as u64
    }

    /// The refresher's continuation condition: someone still holds the lease,
    /// and they are still quoting fast enough to read what it prefetches.
    fn worth_refreshing(&self, now_ms: u64) -> bool {
        self.leased(now_ms) && self.in_demand(now_ms)
    }

    fn bump(&self, now_ms: u64) {
        self.lease
            .fetch_max(now_ms + LEASE.as_millis() as u64, Ordering::AcqRel);
    }

    fn leased(&self, now_ms: u64) -> bool {
        now_ms <= self.lease.load(Ordering::Acquire)
    }

    fn record_pull(&self, elapsed: Duration) {
        self.pull_ms
            .store(elapsed.as_millis() as u64, Ordering::Release);
    }

    /// The wait between one pull's end and the next pull's start. A snapshot
    /// is as old as its pull when it lands, and is replaced when the next pull
    /// lands, one pull, one wait and one more pull after its own began; so the
    /// wait is `REFRESH_TARGET` less two pulls. Until 16 Oct 2026 it was less
    /// one, which replaced a snapshot at 1.5 s plus a pull: past `STALE` once
    /// pulls took over 500 ms, as some do at 130 ms of RTT.
    fn refresh_delay(&self) -> Duration {
        let pull = Duration::from_millis(self.pull_ms.load(Ordering::Acquire));
        REFRESH_TARGET.saturating_sub(pull * 2).max(FLOOR)
    }

    async fn finish_pull(&self, id: u64) {
        let mut gate = self.pulling.lock().await;
        if gate.inflight.as_ref().is_some_and(|pull| pull.id == id) {
            gate.inflight = None;
        }
    }

    async fn publish_pull(&self, id: u64, result: &PullResult) {
        let mut gate = self.pulling.lock().await;
        if gate.inflight.as_ref().is_some_and(|pull| pull.id == id) {
            if let Ok((snapshot, elapsed)) = result {
                self.record_pull(*elapsed);
                self.snap.store(Some(snapshot.clone()));
            }
            gate.inflight = None;
        }
    }
}

pub struct PairStatus {
    pub tokens: (Address, Address),
    pub block: u64,
    pub age: Duration,
    pub hot: bool,
}

pub struct Engine {
    profile: &'static ChainProfile,
    rpc: Rpc,
    resident: Option<Arc<crate::resident::Resident>>,
    /// Where the pulls come from: the profile's discovery, with its indexer.
    source: Arc<dyn SnapshotSource>,
    start: Instant,
    pairs: Mutex<HashMap<(Address, Address), Arc<Pair>>>,
    pull_slots: Arc<Semaphore>,
    refresh_enabled: bool,
    pin_block: Option<u64>,
}

/// Where a quote may take its snapshot from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SnapshotScope {
    /// The resident pools when they cover the pair, the pair's own pull
    /// otherwise.
    Any,
    /// The pair's own pull only: the resident pools covered the pair and found
    /// no route, and pools off their list may still have one.
    PairOnly,
}

fn canon(a: Address, b: Address) -> (Address, Address) {
    if a <= b { (a, b) } else { (b, a) }
}

/// Where an engine's pulls come from: one observed snapshot of the pair
/// `(a, b)`, read over `rpc` (the pull's own scoped probe of the engine's
/// RPC) at `pin_block`, or at the head when it is `None`.
pub(crate) trait SnapshotSource: Send + Sync {
    fn pull<'a>(
        &'a self,
        rpc: &'a Rpc,
        a: Address,
        b: Address,
        pin_block: Option<u64>,
    ) -> BoxFuture<'a, anyhow::Result<state::ObservedSnapshot>>;
}

/// The production source: the profile's discovery, with the indexer and the
/// resident list the engine was built with.
struct StatePull {
    profile: &'static ChainProfile,
    indexer: Option<Arc<IndexerClient>>,
    /// Where a pull finds its skeletons through resident connectors.
    resident: Option<Arc<crate::resident::Resident>>,
}

impl SnapshotSource for StatePull {
    fn pull<'a>(
        &'a self,
        rpc: &'a Rpc,
        a: Address,
        b: Address,
        pin_block: Option<u64>,
    ) -> BoxFuture<'a, anyhow::Result<state::ObservedSnapshot>> {
        state::snapshot_at_observed_for(
            self.profile,
            rpc,
            self.indexer.as_deref(),
            a,
            b,
            pin_block,
            self.resident
                .as_deref()
                .map(|resident| resident as &dyn state::ListedPaths),
        )
        .boxed()
    }
}

struct PullContext {
    source: Arc<dyn SnapshotSource>,
    rpc: Rpc,
    pull_slots: Arc<Semaphore>,
    pin_block: Option<u64>,
}

#[derive(Clone, Copy)]
enum PullAdmission {
    Wait,
    IfAvailable,
}

async fn start_pull(
    gate: &mut PullGate,
    pair_guard: Arc<Pair>,
    key: (Address, Address),
    context: PullContext,
    admission: PullAdmission,
) -> Option<(u64, PullFuture)> {
    if let Some(pull) = &gate.inflight {
        return Some((pull.id, pull.future.clone()));
    }

    // Queue in the caller's task so cancellation before admission cannot leave
    // detached work behind. Refreshers are already background tasks, so they
    // skip a busy cycle instead of creating their own admission backlog.
    let permit = match admission {
        PullAdmission::Wait => Arc::clone(&context.pull_slots)
            .acquire_owned()
            .await
            .expect("snapshot semaphore is never closed"),
        PullAdmission::IfAvailable => Arc::clone(&context.pull_slots).try_acquire_owned().ok()?,
    };
    let id = gate.next_id;
    gate.next_id += 1;
    let rpc = context.rpc.scoped_probe();
    // Once admitted, the owner is spawned before its result is shared. HTTP
    // cancellation may drop every waiter, but it must never stop an active pull
    // or prevent a successful snapshot from being published. Publishing under
    // the generation gate also prevents a delayed waiter from moving ArcSwap
    // back to an older block.
    let owner = tokio::spawn(async move {
        let _permit = permit;
        let result = async {
            let started = Instant::now();
            let observed = context
                .source
                .pull(&rpc, key.0, key.1, context.pin_block)
                .await
                .map_err(PullFailure::capture)?;
            Ok((
                Stamped::new(observed, rpc.probed_calls()),
                started.elapsed(),
            ))
        }
        .await;
        // Keep the Pair resident until this owner has released its snapshot
        // permit and all upstream work is complete. Otherwise a cancelled
        // waiter could leave a detached owner behind while cache churn evicts
        // its only admission record and starts unbounded replacements.
        pair_guard.publish_pull(id, &result).await;
        result
    });
    let future = async move {
        owner.await.unwrap_or_else(|error| {
            Err(PullFailure::Other(
                format!("snapshot owner task failed: {error}").into(),
            ))
        })
    }
    .boxed()
    .shared();
    gate.inflight = Some(Inflight {
        id,
        future: future.clone(),
    });
    Some((id, future))
}

impl Engine {
    #[cfg(any(test, feature = "testing"))]
    pub fn new(rpc: Rpc) -> Arc<Engine> {
        Self::for_profile(rpc, &ROBINHOOD_PROFILE)
    }

    pub fn for_profile(rpc: Rpc, profile: &'static ChainProfile) -> Arc<Engine> {
        Self::build(rpc, profile, None, true, None)
    }

    /// Production constructor for profiles whose discovery source is an
    /// explicit process dependency rather than a chain-global singleton.
    pub fn for_profile_with_indexer(
        rpc: Rpc,
        profile: &'static ChainProfile,
        indexer: Option<Arc<IndexerClient>>,
    ) -> Arc<Engine> {
        Self::build(rpc, profile, indexer, true, None)
    }

    /// The production constructor with resident pool state in front of the
    /// per-pair pulls. The caller starts the resident reader.
    pub fn for_profile_with_resident(
        rpc: Rpc,
        profile: &'static ChainProfile,
        indexer: Option<Arc<IndexerClient>>,
        resident: Option<Arc<crate::resident::Resident>>,
    ) -> Arc<Engine> {
        let snapshot_concurrency = rpc.snapshot_concurrency();
        let source = Arc::new(StatePull {
            profile,
            indexer,
            resident: resident.clone(),
        });
        Arc::new(Engine {
            profile,
            rpc,
            resident,
            source,
            start: Instant::now(),
            pairs: Mutex::new(HashMap::new()),
            pull_slots: Arc::new(Semaphore::new(snapshot_concurrency)),
            refresh_enabled: true,
            pin_block: None,
        })
    }

    #[cfg(any(test, feature = "testing"))]
    pub fn new_pinned(rpc: Rpc, block: u64) -> Arc<Engine> {
        Self::for_profile_pinned(rpc, &ROBINHOOD_PROFILE, None, block)
    }

    /// Pinned-block constructor for any execution profile. Indexer-backed
    /// profiles (BSC) need their discovery client here exactly as the live
    /// server builds it, or a pinned quote silently measures a different
    /// universe than production.
    pub fn for_profile_pinned(
        rpc: Rpc,
        profile: &'static ChainProfile,
        indexer: Option<Arc<IndexerClient>>,
        block: u64,
    ) -> Arc<Engine> {
        Self::build(rpc, profile, indexer, false, Some(block))
    }

    fn build(
        rpc: Rpc,
        profile: &'static ChainProfile,
        indexer: Option<Arc<IndexerClient>>,
        refresh_enabled: bool,
        pin_block: Option<u64>,
    ) -> Arc<Engine> {
        let snapshot_concurrency = rpc.snapshot_concurrency();
        let source = Arc::new(StatePull {
            profile,
            indexer,
            resident: None,
        });
        Arc::new(Engine {
            profile,
            rpc,
            resident: None,
            source,
            start: Instant::now(),
            pairs: Mutex::new(HashMap::new()),
            pull_slots: Arc::new(Semaphore::new(snapshot_concurrency)),
            refresh_enabled,
            pin_block,
        })
    }

    pub fn profile(&self) -> &'static ChainProfile {
        self.profile
    }

    pub fn rpc(&self) -> &Rpc {
        &self.rpc
    }

    pub fn resident(&self) -> Option<&Arc<crate::resident::Resident>> {
        self.resident.as_ref()
    }

    /// `snapshot_from`, served from the resident pools when `scope` allows it
    /// and they cover the pair, with source `"resident"`.
    pub async fn snapshot_scoped(
        self: &Arc<Self>,
        a: Address,
        b: Address,
        min_block: u64,
        scope: SnapshotScope,
    ) -> anyhow::Result<(Arc<Stamped>, &'static str)> {
        if scope == SnapshotScope::Any
            && let Some(resident) = &self.resident
            && let Some(start) = resident.start_for(a, b, min_block).await
        {
            return Ok((Stamped::resident(start), "resident"));
        }
        self.snapshot_from(a, b, min_block).await
    }

    #[cfg(any(test, feature = "testing"))]
    pub fn cache_snapshot_for_test(
        &self,
        a: Address,
        b: Address,
        observed: state::ObservedSnapshot,
    ) -> Arc<Stamped> {
        let stamped = Stamped::new(observed, 0);
        let pair = self.pair(canon(a, b)).expect("test snapshot pair");
        pair.bump(self.now_ms());
        pair.snap.store(Some(stamped.clone()));
        stamped
    }

    fn now_ms(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }

    fn pull_context(&self) -> PullContext {
        PullContext {
            source: self.source.clone(),
            rpc: self.rpc.clone(),
            pull_slots: self.pull_slots.clone(),
            pin_block: self.pin_block,
        }
    }

    fn pair(&self, key: (Address, Address)) -> anyhow::Result<Arc<Pair>> {
        let now = self.now_ms();
        let mut pairs = self.pairs.lock().expect("pairs lock");
        pairs.retain(|_, pair| pair.leased(now) || Arc::strong_count(pair) > 1);
        if let Some(pair) = pairs.get(&key) {
            return Ok(pair.clone());
        }
        if pairs.len() >= MAX_PAIRS
            && let Some(oldest) = pairs
                .iter()
                .filter(|(_, pair)| {
                    Arc::strong_count(pair) == 1 && !pair.refreshing.load(Ordering::Acquire)
                })
                .min_by_key(|(tokens, pair)| (pair.lease.load(Ordering::Acquire), **tokens))
                .map(|(tokens, _)| *tokens)
        {
            pairs.remove(&oldest);
        }
        anyhow::ensure!(
            pairs.len() < MAX_PAIRS,
            "all resident pair slots are active"
        );
        let pair = Arc::new(Pair::new());
        pairs.insert(key, pair.clone());
        Ok(pair)
    }

    /// Hot snapshot for the token pair, plus where it came from: `"memory"`
    /// for a fresh in-memory hit, `"pull"` when this call fetched it.
    pub async fn snapshot(
        self: &Arc<Self>,
        a: Address,
        b: Address,
    ) -> anyhow::Result<(Arc<Stamped>, &'static str)> {
        self.snapshot_from(a, b, 0).await
    }

    /// `snapshot`, from block `min_block` or later: a fresh snapshot of an
    /// earlier block is pulled again. A quote whose transaction failed its
    /// check at a later block than it was priced on asks for this. A pull
    /// already in flight may predate that block, so a second pull follows
    /// when the first one comes back older.
    pub async fn snapshot_from(
        self: &Arc<Self>,
        a: Address,
        b: Address,
        min_block: u64,
    ) -> anyhow::Result<(Arc<Stamped>, &'static str)> {
        let (stamped, source) = self.snapshot_once(a, b, min_block).await?;
        if stamped.snap.block >= min_block {
            return Ok((stamped, source));
        }
        self.snapshot_once(a, b, min_block).await
    }

    async fn snapshot_once(
        self: &Arc<Self>,
        a: Address,
        b: Address,
        min_block: u64,
    ) -> anyhow::Result<(Arc<Stamped>, &'static str)> {
        let key = canon(a, b);
        let pair = self.pair(key)?;
        let now = self.now_ms();
        pair.bump(now);
        pair.observe_quote(now);
        let usable = |s: &Stamped| s.is_fresh() && s.snap.block >= min_block;

        if let Some(s) = pair.snap.load_full()
            && usable(&s)
        {
            self.ignite(key, &pair);
            return Ok((s, "memory"));
        }

        let (id, pull) = {
            let mut gate = pair.pulling.lock().await;
            if let Some(s) = pair.snap.load_full()
                && usable(&s)
            {
                drop(gate);
                pair.bump(self.now_ms());
                self.ignite(key, &pair);
                return Ok((s, "memory"));
            }
            start_pull(
                &mut gate,
                pair.clone(),
                key,
                self.pull_context(),
                PullAdmission::Wait,
            )
            .await
            .expect("waiting snapshot admission always starts or joins a pull")
        };

        let result = pull.await;
        pair.finish_pull(id).await;

        let (s, _) = match result {
            Ok(result) => result,
            Err(error) => return Err(error.into_error()),
        };
        // A slow cold/stale pull must not consume the lease it just earned.
        pair.bump(self.now_ms());
        self.ignite(key, &pair);
        Ok((s, "pull"))
    }

    /// Spawn the pair's refresher unless one is already alive — and only for a
    /// pair being quoted fast enough for prefetching to pay. A slow caller is
    /// served by the STALE gate off its own previous pull, at one pull each,
    /// instead of a background loop pulling on its own clock for nobody.
    fn ignite(self: &Arc<Self>, key: (Address, Address), pair: &Arc<Pair>) {
        if !self.refresh_enabled {
            return;
        }
        if !pair.in_demand(self.now_ms()) {
            return;
        }
        if !pair.refreshing.swap(true, Ordering::AcqRel) {
            tokio::spawn(refresh(self.clone(), key, pair.clone()));
        }
    }

    pub fn status(&self) -> Vec<PairStatus> {
        let now = self.now_ms();
        let pairs = self.pairs.lock().expect("pairs lock");
        let mut out: Vec<PairStatus> = pairs
            .iter()
            .filter_map(|(key, p)| {
                p.snap.load_full().map(|s| PairStatus {
                    tokens: *key,
                    block: s.snap.block,
                    age: s.age(),
                    hot: p.leased(now) && p.refreshing.load(Ordering::Acquire),
                })
            })
            .collect();
        out.sort_by_key(|s| s.tokens);
        out
    }
}

async fn refresh(engine: Arc<Engine>, key: (Address, Address), pair: Arc<Pair>) {
    while pair.worth_refreshing(engine.now_ms()) {
        tokio::time::sleep(pair.refresh_delay()).await;
        if !pair.worth_refreshing(engine.now_ms()) {
            break;
        }
        let observed = pair.snap.load_full().expect("refresher pair snapshot");
        let started = {
            let mut gate = pair.pulling.lock().await;
            if !pair.worth_refreshing(engine.now_ms()) {
                break;
            }
            let current = pair.snap.load_full().expect("refresher pair snapshot");
            if !Arc::ptr_eq(&observed, &current) {
                // A foreground pull completed while this refresher waited.
                continue;
            }
            start_pull(
                &mut gate,
                pair.clone(),
                key,
                engine.pull_context(),
                PullAdmission::IfAvailable,
            )
            .await
        };
        let Some((id, pull)) = started else {
            continue;
        };

        let result = pull.await;
        pair.finish_pull(id).await;

        match result {
            Ok(_) => {}
            Err(error) => {
                let e = error.into_error();
                tracing::info!(
                    "engine: refresher for {:#x}/{:#x} stopped: {}",
                    key.0,
                    key.1,
                    sanitized_error(&e)
                );
                break;
            }
        }
    }
    pair.refreshing.store(false, Ordering::Release);
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::address;
    use futures_util::future::join_all;
    use std::sync::atomic::AtomicUsize;

    #[test]
    fn lease_bump_is_monotonic() {
        let p = Pair::new();
        p.snap.store(Some(Stamped::new(
            state::ObservedSnapshot {
                screening: Default::default(),
                snapshot: Snapshot {
                    block: 1,
                    settler: None,
                    v3: vec![],
                    v2: vec![],
                    ekubo: vec![],
                },
                universe: RouteUniverse::profile_only(
                    &ROBINHOOD_PROFILE,
                    Address::repeat_byte(0x11),
                    Address::repeat_byte(0x22),
                )
                .unwrap(),
                topology_fences: None,
                block_id: BlockId::number(1),
                block_timestamp: 1_000,
                observed_at: Instant::now(),
            },
            0,
        )));
        p.bump(1_000);
        assert!(p.leased(61_000));
        assert!(!p.leased(61_001));
        p.bump(30_000);
        p.bump(2_000); // an out-of-order bump must never shorten the lease
        assert!(p.leased(90_000));
        assert!(!p.leased(90_001));
    }

    #[test]
    fn pair_key_ignores_direction() {
        let a = address!("0bd7d308f8e1639fab988df18a8011f41eacad73");
        let b = address!("5fc5360d0400a0fd4f2af552add042d716f1d168");
        assert_eq!(canon(a, b), canon(b, a));
        assert_eq!(canon(a, b), (a, b));
    }

    #[tokio::test]
    async fn cache_snapshot_for_test_seeds_a_leased_pair() {
        let engine = Engine::new(Rpc::connect("http://127.0.0.1:1").unwrap());
        let a = Address::repeat_byte(0x11);
        let b = Address::repeat_byte(0x22);
        let seeded = engine.cache_snapshot_for_test(
            a,
            b,
            state::ObservedSnapshot {
                screening: Default::default(),
                snapshot: Snapshot {
                    block: 7,
                    settler: None,
                    v3: vec![],
                    v2: vec![],
                    ekubo: vec![],
                },
                universe: RouteUniverse::profile_only(&ROBINHOOD_PROFILE, a, b).unwrap(),
                topology_fences: None,
                block_id: BlockId::number(7),
                block_timestamp: 1_000,
                observed_at: Instant::now(),
            },
        );
        drop(seeded);
        tokio::time::sleep(Duration::from_millis(2)).await;

        let (loaded, source) = engine.snapshot(a, b).await.unwrap();

        assert_eq!(loaded.snap.block, 7);
        assert_eq!(source, "memory");
    }

    #[test]
    fn refresh_delay_targets_fresh_publication_without_busy_polling() {
        let p = Pair::new();
        assert_eq!(p.refresh_delay(), REFRESH_TARGET);
        p.record_pull(Duration::from_millis(250));
        assert_eq!(p.refresh_delay(), Duration::from_millis(1_000));
        // Replaced at 250 + 1,000 + 250 ms of age.
        assert_eq!(
            Duration::from_millis(250) * 2 + p.refresh_delay(),
            REFRESH_TARGET
        );
        p.record_pull(Duration::from_millis(400));
        assert_eq!(p.refresh_delay(), Duration::from_millis(700));
        p.record_pull(Duration::from_millis(1_400));
        assert_eq!(p.refresh_delay(), FLOOR);
        p.record_pull(Duration::from_secs(3));
        assert_eq!(p.refresh_delay(), FLOOR);
    }

    #[tokio::test]
    async fn only_the_current_pull_generation_can_publish() {
        let pair = Pair::new();
        let snapshot = |block| {
            Stamped::new(
                state::ObservedSnapshot {
                    screening: Default::default(),
                    snapshot: Snapshot {
                        block,
                        settler: None,
                        v3: vec![],
                        v2: vec![],
                        ekubo: vec![],
                    },
                    universe: RouteUniverse::profile_only(
                        &ROBINHOOD_PROFILE,
                        Address::repeat_byte(0x11),
                        Address::repeat_byte(0x22),
                    )
                    .unwrap(),
                    topology_fences: None,
                    block_id: BlockId::number(block),
                    block_timestamp: 1_000 + block,
                    observed_at: Instant::now(),
                },
                1,
            )
        };
        let old = snapshot(1);
        let current = snapshot(2);
        let current_result: PullResult = Ok((current.clone(), Duration::from_millis(5)));
        let current_future = {
            let result = current_result.clone();
            async move { result }.boxed().shared()
        };
        pair.pulling.lock().await.inflight = Some(Inflight {
            id: 2,
            future: current_future,
        });

        pair.publish_pull(1, &Ok((old, Duration::from_secs(1))))
            .await;

        assert!(pair.snap.load_full().is_none());
        assert_eq!(pair.pulling.lock().await.inflight.as_ref().unwrap().id, 2);
        assert_eq!(pair.pull_ms.load(Ordering::Acquire), 0);

        pair.publish_pull(2, &current_result).await;
        assert_eq!(pair.snap.load_full().unwrap().snap.block, 2);
        assert!(pair.pulling.lock().await.inflight.is_none());
        assert_eq!(pair.pull_ms.load(Ordering::Acquire), 5);
    }

    #[test]
    fn one_quote_on_a_cold_pair_is_not_demand() {
        let p = Pair::new();
        for i in 0..DEMAND_SAMPLES as u64 - 1 {
            p.observe_quote(i * 10);
            assert!(!p.in_demand(i * 10), "{} arrivals read as demand", i + 1);
        }
    }

    /// The traffic that motivated the gate: the terminal polls a pair every
    /// 15s and doubles each poll with a 1% impact probe. Before the gate this
    /// pinned the lease forever and cost ~336 upstream calls/min for four
    /// quotes. It must never read as demand, no matter how long it runs.
    #[test]
    fn terminal_poll_cadence_never_reads_as_demand() {
        let p = Pair::new();
        for poll in 0..20u64 {
            let now = poll * 15_000;
            p.observe_quote(now);
            p.observe_quote(now + 30); // the impact probe, same instant
            assert!(
                !p.in_demand(now + 30),
                "idle 15s polling read as demand at poll {poll}"
            );
        }
    }

    #[test]
    fn sustained_quoting_is_demand_and_lapses_when_it_stops() {
        let p = Pair::new();
        for i in 0..DEMAND_SAMPLES as u64 {
            p.observe_quote(i * 500); // two quotes a second
        }
        let last = (DEMAND_SAMPLES as u64 - 1) * 500;
        assert!(p.in_demand(last));

        // The oldest retained arrival ages out on its own: nobody has to tell
        // the refresher that the burst ended.
        assert!(!p.in_demand(DEMAND_WINDOW.as_millis() as u64 + 1));
    }

    /// Would panic with "no reactor running" if the demand gate failed to
    /// stop the spawn, so this asserts the gate itself and not just a flag.
    #[test]
    fn idle_polling_leaves_the_refresher_dark() {
        let engine = Engine::new(Rpc::connect("http://127.0.0.1:1").unwrap());
        let key = canon(Address::ZERO, Address::repeat_byte(0x11));
        let pair = engine.pair(key).unwrap();
        let now = engine.now_ms();
        pair.bump(now);
        pair.observe_quote(now);

        engine.ignite(key, &pair);

        assert!(
            engine.refresh_enabled,
            "the gate, not the pin, must stop it"
        );
        assert!(!pair.refreshing.load(Ordering::Acquire));
    }

    #[test]
    fn pinned_engine_disables_refresher_and_records_block() {
        let engine = Engine::new_pinned(Rpc::connect("http://127.0.0.1:1").unwrap(), 42);
        let key = canon(Address::ZERO, Address::repeat_byte(0x11));
        let pair = engine.pair(key).unwrap();

        engine.ignite(key, &pair);

        assert_eq!(engine.pin_block, Some(42));
        assert!(!engine.refresh_enabled);
        assert!(!pair.refreshing.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn indexer_profile_without_client_fails_before_touching_its_rpc() {
        let engine = Engine::for_profile(
            Rpc::connect("http://127.0.0.1:1").unwrap(),
            &crate::chain::BSC_PROFILE,
        );
        let error = match engine
            .snapshot(Address::repeat_byte(0x11), Address::repeat_byte(0x22))
            .await
        {
            Ok(_) => panic!("indexer-less profile unexpectedly reached a snapshot"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("pool indexer is not configured"));
        assert!(error.downcast_ref::<crate::rpc::RpcUnavailable>().is_none());
    }

    fn observed(observed_at: Instant) -> state::ObservedSnapshot {
        state::ObservedSnapshot {
            screening: Default::default(),
            snapshot: Snapshot {
                block: 1,
                settler: None,
                v3: vec![],
                v2: vec![],
                ekubo: vec![],
            },
            universe: RouteUniverse::profile_only(
                &ROBINHOOD_PROFILE,
                Address::repeat_byte(0x11),
                Address::repeat_byte(0x22),
            )
            .unwrap(),
            topology_fences: None,
            block_id: BlockId::number(1),
            block_timestamp: 1_000,
            observed_at,
        }
    }

    #[tokio::test]
    async fn a_quote_started_on_a_fresh_snapshot_may_finish_just_past_the_bound() {
        let engine = Engine::for_profile(
            Rpc::connect("http://127.0.0.1:1").unwrap(),
            &ROBINHOOD_PROFILE,
        );
        let (a, b) = (Address::repeat_byte(0x11), Address::repeat_byte(0x22));
        // Served from memory up to the bound.
        let old = engine.cache_snapshot_for_test(
            a,
            b,
            observed(Instant::now() - STALE + Duration::from_millis(50)),
        );
        let (served, source) = engine.snapshot(a, b).await.unwrap();
        assert_eq!(source, "memory");
        assert!(Arc::ptr_eq(&served, &old));
        // A quote that started on it finishes within the grace, never past it.
        let past = Stamped::new(observed(Instant::now() - STALE - FINISH_GRACE / 2), 0);
        assert!(!past.is_fresh() && past.is_fresh_to_finish());
        let gone = Stamped::new(
            observed(Instant::now() - STALE - FINISH_GRACE - Duration::from_millis(50)),
            0,
        );
        assert!(!gone.is_fresh_to_finish());
        // Past the bound, memory no longer serves it: the engine pulls.
        engine.cache_snapshot_for_test(
            a,
            b,
            observed(Instant::now() - STALE - Duration::from_millis(1)),
        );
        assert!(engine.snapshot(a, b).await.is_err());
    }

    #[test]
    fn snapshot_age_starts_when_the_lens_observes_its_block() {
        let observed_at = Instant::now() - Duration::from_secs(3);
        let stamped = Stamped::new(
            state::ObservedSnapshot {
                screening: Default::default(),
                snapshot: Snapshot {
                    block: 1,
                    settler: None,
                    v3: vec![],
                    v2: vec![],
                    ekubo: vec![],
                },
                universe: RouteUniverse::profile_only(
                    &ROBINHOOD_PROFILE,
                    Address::repeat_byte(0x11),
                    Address::repeat_byte(0x22),
                )
                .unwrap(),
                topology_fences: None,
                block_id: BlockId::number(1),
                block_timestamp: 1_000,
                observed_at,
            },
            17,
        );
        assert!(stamped.age() >= Duration::from_secs(3));
        assert!(!stamped.is_fresh());
        assert!(stamped.chain_now() >= 1_003);
        assert_eq!(stamped.rpc_calls(), 17);
    }

    #[test]
    fn shared_rpc_capacity_keeps_local_admission_classification() {
        let original = anyhow::Error::new(crate::rpc_dispatch::RpcCapacity)
            .context("snapshot provider admission");
        let captured = PullFailure::capture(original);
        for shared in [captured.clone().into_error(), captured.into_error()] {
            assert!(shared.is::<crate::rpc_dispatch::RpcCapacity>());
            assert!(!shared.is::<crate::rpc::RpcUnavailable>());
            assert!(!shared.is::<crate::rpc::RpcRejected>());
        }
    }

    #[test]
    fn shared_rpc_failure_keeps_upstream_classification() {
        let original =
            anyhow::anyhow!("transport details").context(crate::rpc::RpcUnavailable("eth_call"));
        let shared = PullFailure::capture(original).clone().into_error();
        assert_eq!(
            shared
                .downcast_ref::<crate::rpc::RpcUnavailable>()
                .map(|error| error.0),
            Some("eth_call")
        );
        assert_eq!(sanitized_error(&shared), "upstream rpc failed: eth_call");
    }

    #[test]
    fn shared_rpc_rejection_keeps_upstream_classification() {
        let original =
            anyhow::anyhow!("execution details").context(crate::rpc::RpcRejected("eth_call"));
        let shared = PullFailure::capture(original).clone().into_error();
        assert_eq!(
            shared
                .downcast_ref::<crate::rpc::RpcRejected>()
                .map(|error| error.0),
            Some("eth_call")
        );
        assert!(
            shared
                .downcast_ref::<crate::rpc::RpcUnavailable>()
                .is_none()
        );
    }

    #[test]
    fn shared_integrity_failure_keeps_upstream_classification() {
        let original = anyhow::Error::new(crate::state::UpstreamIntegrityError::test_only(
            "factory identity mismatch",
        ));
        let shared = PullFailure::capture(original).clone().into_error();
        assert!(
            shared
                .downcast_ref::<crate::state::UpstreamIntegrityError>()
                .is_some()
        );
    }

    /// A source that counts its pulls and fails each one after `delay`: the
    /// tests below measure the engine's own contract (one pull per pair, the
    /// permit released, no detached work), not how many calls a discovery
    /// makes before it fails.
    struct FailingSource {
        pulls: AtomicUsize,
        delay: Duration,
    }

    impl FailingSource {
        fn new(delay: Duration) -> Arc<Self> {
            Arc::new(Self {
                pulls: AtomicUsize::new(0),
                delay,
            })
        }
    }

    impl SnapshotSource for FailingSource {
        fn pull<'a>(
            &'a self,
            _rpc: &'a Rpc,
            _a: Address,
            _b: Address,
            _pin_block: Option<u64>,
        ) -> BoxFuture<'a, anyhow::Result<state::ObservedSnapshot>> {
            async move {
                self.pulls.fetch_add(1, Ordering::Relaxed);
                tokio::time::sleep(self.delay).await;
                Err(anyhow::anyhow!("forced failure"))
            }
            .boxed()
        }
    }

    /// An engine like `Engine::new`'s, pulling from `source`.
    fn engine_with_source(source: Arc<dyn SnapshotSource>) -> Arc<Engine> {
        let rpc = Rpc::connect("http://127.0.0.1:1").unwrap();
        let snapshot_concurrency = rpc.snapshot_concurrency();
        Arc::new(Engine {
            profile: &ROBINHOOD_PROFILE,
            rpc,
            resident: None,
            source,
            start: Instant::now(),
            pairs: Mutex::new(HashMap::new()),
            pull_slots: Arc::new(Semaphore::new(snapshot_concurrency)),
            refresh_enabled: true,
            pin_block: None,
        })
    }

    #[tokio::test]
    async fn failed_cold_pull_is_shared_by_all_waiters() {
        let source = FailingSource::new(Duration::from_millis(100));
        let engine = engine_with_source(source.clone());
        let a = Address::repeat_byte(0x11);
        let b = Address::repeat_byte(0x22);

        let results = join_all((0..5).map(|_| engine.snapshot(a, b))).await;

        assert!(results.iter().all(Result::is_err));
        assert_eq!(source.pulls.load(Ordering::Relaxed), 1);
        assert_eq!(engine.pairs.lock().expect("pairs lock").len(), 1);
    }

    #[tokio::test]
    async fn cancelled_waiter_cannot_pin_a_snapshot_permit() {
        let source = FailingSource::new(Duration::from_millis(100));
        let slots = Arc::new(Semaphore::new(1));
        let pair = Arc::new(Pair::new());
        let (_, pull) = {
            let mut gate = pair.pulling.lock().await;
            start_pull(
                &mut gate,
                pair.clone(),
                canon(Address::repeat_byte(0x31), Address::repeat_byte(0x32)),
                PullContext {
                    source: source.clone(),
                    rpc: Rpc::connect("http://127.0.0.1:1").unwrap(),
                    pull_slots: slots.clone(),
                    pin_block: None,
                },
                PullAdmission::Wait,
            )
            .await
            .expect("available test permit starts a pull")
        };

        assert!(
            tokio::time::timeout(Duration::from_millis(10), pull)
                .await
                .is_err(),
            "the waiter must cancel while the pull is in flight"
        );
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let pull_finished = pair.pulling.lock().await.inflight.is_none();
                if slots.available_permits() > 0 && pull_finished {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("spawned snapshot owner must release its permit and clear its generation");
        assert_eq!(source.pulls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn cancelled_admission_waiter_does_not_leave_detached_work() {
        let rpc = Rpc::connect("http://127.0.0.1:1").unwrap();
        let engine = Engine::new(rpc.clone());
        let owner_key = canon(Address::ZERO, test_address(1));
        let owner_pair = engine.pair(owner_key).unwrap();
        let slots = Arc::new(Semaphore::new(0));
        let timed_out = tokio::time::timeout(Duration::from_millis(10), async {
            let mut gate = owner_pair.pulling.lock().await;
            start_pull(
                &mut gate,
                owner_pair.clone(),
                owner_key,
                PullContext {
                    source: FailingSource::new(Duration::ZERO),
                    rpc,
                    pull_slots: slots,
                    pin_block: None,
                },
                PullAdmission::Wait,
            )
            .await
        })
        .await;

        assert!(timed_out.is_err(), "pull admission unexpectedly succeeded");
        assert!(owner_pair.pulling.lock().await.inflight.is_none());
        assert_eq!(Arc::strong_count(&owner_pair), 2);
        drop(owner_pair);

        for value in 2..=u16::try_from(MAX_PAIRS + 32).unwrap() {
            let pair = engine
                .pair(canon(Address::ZERO, test_address(value)))
                .unwrap();
            pair.bump(engine.now_ms());
        }
        {
            let pairs = engine.pairs.lock().expect("pairs lock");
            assert_eq!(pairs.len(), MAX_PAIRS);
            assert!(
                !pairs.contains_key(&owner_key),
                "a cancelled admission waiter left its pair non-evictable"
            );
        }
    }

    #[tokio::test]
    async fn busy_refresher_skips_instead_of_queueing_detached_work() {
        let pair = Arc::new(Pair::new());
        let mut gate = PullGate::default();
        let started = start_pull(
            &mut gate,
            pair.clone(),
            canon(Address::ZERO, test_address(1)),
            PullContext {
                source: FailingSource::new(Duration::ZERO),
                rpc: Rpc::connect("http://127.0.0.1:1").unwrap(),
                pull_slots: Arc::new(Semaphore::new(0)),
                pin_block: None,
            },
            PullAdmission::IfAvailable,
        )
        .await;

        assert!(started.is_none());
        assert!(gate.inflight.is_none());
        assert_eq!(Arc::strong_count(&pair), 1);
    }

    fn test_address(value: u16) -> Address {
        let mut bytes = [0u8; 20];
        bytes[18..].copy_from_slice(&value.to_be_bytes());
        Address::from(bytes)
    }

    #[test]
    fn resident_pair_cache_is_bounded_and_evicts_the_oldest_idle_entry() {
        let rpc = Rpc::connect("http://127.0.0.1:1").unwrap();
        let engine = Engine::new(rpc);
        let lease_base = engine.now_ms() + 1_000_000;
        for value in 1..=u16::try_from(MAX_PAIRS).unwrap() {
            let pair = engine
                .pair(canon(Address::ZERO, test_address(value)))
                .unwrap();
            pair.lease
                .store(lease_base + u64::from(value), Ordering::Release);
        }
        assert_eq!(engine.pairs.lock().expect("pairs lock").len(), MAX_PAIRS);
        let expired_key = canon(Address::ZERO, test_address(1));
        engine
            .pair(canon(
                Address::ZERO,
                test_address(u16::try_from(MAX_PAIRS + 1).unwrap()),
            ))
            .unwrap();
        let pairs = engine.pairs.lock().expect("pairs lock");
        assert_eq!(pairs.len(), MAX_PAIRS);
        assert!(!pairs.contains_key(&expired_key));
    }
}
