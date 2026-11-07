//! Resident pool state: every pool on the resident list, read at each new
//! block and held in memory, so a quote for a pair the list covers reads no
//! chain state of its own.
//!
//! The list comes from `SOLVER_RESIDENT_POOL_LIST_URL`: a JSON array of
//! address pools in the indexer's wire shape (`list_row`), fetched every ten
//! minutes. A pool new to it is proved against the profile's venue table (and
//! the Settler's CREATE2 identity) at a pinned block, exactly as the per-pair
//! path proves the pools its indexer or factories name; one no longer listed
//! leaves. When the list cannot be read, the last one stays. A pool joins from
//! the next block after it is proved.
//!
//! Each new block is read at its hash and published whole, only when complete
//! and newer than what is published. A pool that emitted none of the events
//! that move its state since the last read keeps the state that read found
//! (`carry`); only the pools that did, pools new to the list, and pools of a
//! venue not known to carry are read again: the headers between the last
//! read and the head in one JSON-RPC batch, `eth_getLogs` for each block by
//! hash and those events in another, then one Lens call per 128 pools read. The Settler is read
//! by one multicall beside them. Every pool is read whole after a reorg, a
//! gap of more than `MAX_STEP_BLOCKS`, a failed log read, and at least every
//! `SOLVER_RESIDENT_FULL_READ_MS` (a minute; `0` reads every block whole). A
//! whole read after a linked step is also an audit: a pool that logged
//! nothing must read as it was carried, and one that does not is counted as
//! drift. A head check that finds the published block still the head keeps
//! it fresh.
//!
//! A pair is quoted from here when both its tokens trade in the published
//! state and some route skeleton has a pool on every edge. Otherwise, or when
//! the state is older than the freshness bound, the per-pair path quotes it.
//!
//! Routes go through the profile's connectors, and through the resident ones
//! (`SOLVER_RESIDENT_CONNECTORS`) where they have pools here. A quote starts
//! from the profile's connectors and admits the others where probing their
//! skeletons finds them better than its own best route ([`Widening`]); none is
//! routed for having fitted a budget. A pool that fails the liquidity test
//! (`Liquidity`) is left out of a quote's graph where it would only carry the
//! trade to another token. The per-pair path, whose discovery covers only the
//! profile's connectors, takes skeletons through the resident ones from here,
//! where they have pools.

mod carry;
mod graph;
mod liquidity;
mod reader;
mod settings;
mod widening;

use crate::catalog::IndexedEvmDiscovery;
use crate::chain::ChainProfile;
#[cfg(test)]
use crate::engine::Stamped;
use crate::freshness::STALE;
use crate::rpc::{CanonicalBlock, Rpc, sanitized_error};
use crate::snapshot::Snapshot;
use crate::universe::{RESIDENT_MAX_PAIRS, RouteUniverse};
use alloy::eips::BlockId;
use alloy_primitives::Address;
use anyhow::{Context, ensure};
use arc_swap::ArcSwapOption;
pub use graph::*;
use liquidity::Liquidity;
use reader::{List, run};
use serde_json::{Value, json};
pub use settings::*;
use std::collections::{BTreeSet, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::watch;
use tokio::task::JoinHandle;
pub use widening::*;

const LIST_TIMEOUT: Duration = Duration::from_secs(15);
/// How long a quote that must price from a later block waits for the reader.
const MIN_BLOCK_WAIT: Duration = Duration::from_secs(3);

/// Published pools by family, counted in the state a quote reads.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PoolCounts {
    pub v3: usize,
    pub v2: usize,
}

impl PoolCounts {
    fn of(snapshot: &Snapshot) -> Self {
        Self {
            v3: snapshot.v3.len(),
            v2: snapshot.v2.len(),
        }
    }
}

/// One block's state of every listed pool.
struct State {
    snapshot: Snapshot,
    canonical: CanonicalBlock,
    tokens: HashSet<Address>,
    counts: PoolCounts,
    /// The pools that touch a resident connector.
    listed: ListedGraph,
    /// Pools that failed the liquidity test (`Liquidity`), as of this block.
    thin: Arc<HashSet<Address>>,
    /// When the head check that found this block began.
    observed: Instant,
    /// When a head check last found this block still the head, or when the
    /// check that found it began.
    confirmed: Mutex<Instant>,
}

impl State {
    fn new(
        snapshot: Snapshot,
        canonical: CanonicalBlock,
        connectors: &[Address],
        observed: Instant,
    ) -> Self {
        let edges: Vec<(Address, Address)> = snapshot
            .v3
            .iter()
            .map(|(pool, _)| (pool.token0, pool.token1))
            .chain(
                snapshot
                    .v2
                    .iter()
                    .map(|(pool, _)| (pool.token0, pool.token1)),
            )
            .collect();
        let tokens = edges.iter().flat_map(|&(a, b)| [a, b]).collect();
        let listed = ListedGraph::new(edges, connectors);
        let counts = PoolCounts::of(&snapshot);
        Self {
            snapshot,
            canonical,
            tokens,
            counts,
            listed,
            thin: Arc::default(),
            observed,
            confirmed: Mutex::new(observed),
        }
    }

    fn confirmed_at(&self) -> Instant {
        *self.confirmed.lock().expect("resident confirmation")
    }

    /// Never moves back: a slow check that began earlier cannot age it.
    fn confirm(&self, at: Instant) {
        let mut confirmed = self.confirmed.lock().expect("resident confirmation");
        *confirmed = (*confirmed).max(at);
    }

    /// The pools on `universe`'s edges, in the order a per-pair snapshot of
    /// the same universe lists them: by pair and address, V3 then V2.
    fn subset(&self, universe: &RouteUniverse) -> Snapshot {
        let pairs: HashSet<(Address, Address)> = universe
            .pairs()
            .iter()
            .map(|&(a, b)| canonical(a, b))
            .collect();
        let on_graph =
            |token0: Address, token1: Address| pairs.contains(&canonical(token0, token1));
        Snapshot {
            block: self.snapshot.block,
            settler: self.snapshot.settler,
            v3: self
                .snapshot
                .v3
                .iter()
                .filter(|(pool, _)| on_graph(pool.token0, pool.token1))
                .cloned()
                .collect(),
            v2: self
                .snapshot
                .v2
                .iter()
                .filter(|(pool, _)| on_graph(pool.token0, pool.token1))
                .cloned()
                .collect(),
            ekubo: Vec::new(),
        }
    }
}

#[derive(Default)]
struct Health {
    head_seen: u64,
    reads: u64,
    failures: u64,
    last_read_ms: Option<u64>,
    last_error: Option<(String, Instant)>,
    list_at: Option<Instant>,
    list_pools: usize,
    list_rejected: usize,
    /// Reads of every pool, and reads of only the pools that logged.
    whole_reads: u64,
    carried_reads: u64,
    /// Pools read again by the last carried read.
    last_reread: Option<usize>,
    /// Log reads that failed, each sending its step to a whole read.
    log_failures: u64,
    /// Pools a whole read checked against their carried state, and those
    /// that did not match.
    audited: u64,
    drifted: u64,
}

pub struct Resident {
    profile: &'static ChainProfile,
    discovery: &'static IndexedEvmDiscovery,
    rpc: Rpc,
    settings: Settings,
    /// The static connectors every quote starts from.
    statics: Vec<Address>,
    /// Every connector a route may pass through: the static ones, then those
    /// admitted where they have pools.
    connectors: Vec<Address>,
    http: reqwest::Client,
    current: ArcSwapOption<State>,
    published: watch::Sender<u64>,
    health: Mutex<Health>,
    liquidity: Mutex<Liquidity>,
}

impl Resident {
    /// Starts from the profile's connectors, and admits the configured
    /// resident ones where they have pools.
    pub fn new(
        profile: &'static ChainProfile,
        rpc: Rpc,
        settings: Settings,
    ) -> anyhow::Result<Arc<Self>> {
        let statics = profile.connectors.to_vec();
        let others = settings
            .connectors
            .iter()
            .copied()
            .filter(|connector| !statics.contains(connector))
            .collect();
        Self::with_connectors(profile, rpc, settings, statics, others)
    }

    /// `statics` start every quote; `others` are admitted where they have
    /// pools.
    pub fn with_connectors(
        profile: &'static ChainProfile,
        rpc: Rpc,
        settings: Settings,
        statics: Vec<Address>,
        others: Vec<Address>,
    ) -> anyhow::Result<Arc<Self>> {
        let discovery = profile
            .indexed_discovery()
            .context("resident pools need a profile with an IndexedEvm venue table")?;
        let k = statics.len();
        ensure!(
            (k + 2) * (k + 1) / 2 <= RESIDENT_MAX_PAIRS,
            "{k} static resident connectors span more than {RESIDENT_MAX_PAIRS} pairs"
        );
        let connectors: Vec<Address> = statics.iter().chain(&others).copied().collect();
        for (index, connector) in connectors.iter().enumerate() {
            ensure!(
                *connector != Address::ZERO && !connectors[..index].contains(connector),
                "resident connectors must be distinct tokens"
            );
        }
        let http = reqwest::Client::builder()
            .timeout(LIST_TIMEOUT)
            .build()
            .context("building the pool list client")?;
        let (published, _) = watch::channel(0);
        Ok(Arc::new(Self {
            profile,
            discovery,
            rpc,
            settings,
            statics,
            connectors,
            http,
            current: ArcSwapOption::empty(),
            published,
            health: Mutex::new(Health::default()),
            liquidity: Mutex::new(Liquidity::default()),
        }))
    }

    pub fn connectors(&self) -> &[Address] {
        &self.connectors
    }

    /// Start the reader. It runs for the life of the process.
    pub fn spawn(self: &Arc<Self>) -> JoinHandle<()> {
        tokio::spawn(run(self.clone()))
    }

    fn note_error(&self, error: &anyhow::Error) {
        let message = sanitized_error(error);
        tracing::info!("resident: {message}");
        let mut health = self.health.lock().expect("resident health");
        health.failures += 1;
        health.last_error = Some((message, Instant::now()));
    }

    fn publish(&self, mut state: State, read: Duration) {
        state.thin = self.thin_pools(&state.snapshot);
        let number = state.canonical.number;
        {
            let mut health = self.health.lock().expect("resident health");
            health.reads += 1;
            health.last_read_ms = Some(read.as_millis() as u64);
        }
        self.current.store(Some(Arc::new(state)));
        self.published.send_replace(number);
    }

    /// The published block, when there is one.
    pub fn block(&self) -> Option<u64> {
        self.current
            .load()
            .as_ref()
            .map(|state| state.canonical.number)
    }

    /// The resident pools on `a`/`b`'s starting route graph, as a snapshot a
    /// quote can use, with the candidates it may widen into; or `None` for
    /// the per-pair path: no fresh state from `min_block` on, a token no
    /// listed pool trades, or no skeleton with a pool on every edge even with
    /// every candidate admitted.
    pub async fn start_for(&self, a: Address, b: Address, min_block: u64) -> Option<ResidentStart> {
        let state = self.state_from(min_block).await?;
        let at = state.confirmed_at();
        if at.elapsed() > STALE {
            return None;
        }
        let (token0, token1) = canonical(a, b);
        if token0 == token1 || !state.tokens.contains(&token0) || !state.tokens.contains(&token1) {
            return None;
        }
        let mut widening = Widening {
            state: state.clone(),
            profile: self.profile,
            endpoints: (token0, token1),
            statics: self.statics.clone(),
            bases: self.connectors.clone(),
            candidates: state.listed.paths(&self.statics, token0, token1),
            admitted: BTreeSet::new(),
            left_out: 0,
            thin_left_out: 0,
            thin_kept: false,
        };
        let seed = widening.graph(&widening.admitted).ok()?;
        // Candidates are probed against the seed's plan, so the seed must
        // route; otherwise the quote starts with every candidate admitted, as
        // the per-pair path does.
        let start = if routable(&seed.snapshot, &seed.universe) {
            seed
        } else {
            widening.admitted = widening.connectors().into_iter().collect();
            widening.graph(&widening.admitted).ok()?
        };
        if !routable(&start.snapshot, &start.universe) {
            return None;
        }
        widening.left_out = start.left_out;
        widening.thin_left_out = start.thin_left_out;
        widening.thin_kept = start.thin_kept;
        Some(ResidentStart {
            start,
            widening: Arc::new(widening),
            block_id: BlockId::hash_canonical(state.canonical.hash),
            block_timestamp: state.canonical.timestamp,
            at,
            observed_at: state.observed,
        })
    }

    /// Skeletons from `a` to `b` beside `statics`, for the per-pair path,
    /// through this state's connectors outside `statics`, where the list has
    /// their pools. They name pools, not their
    /// state, so any published block serves, however old; with none published
    /// there are none.
    pub fn listed_paths(&self, statics: &[Address], a: Address, b: Address) -> Vec<Vec<Address>> {
        self.current
            .load()
            .as_ref()
            .map(|state| state.listed.paths(statics, a, b))
            .unwrap_or_default()
    }

    async fn state_from(&self, min_block: u64) -> Option<Arc<State>> {
        let state = self.current.load_full()?;
        if state.canonical.number >= min_block {
            return Some(state);
        }
        let mut published = self.published.subscribe();
        tokio::time::timeout(
            MIN_BLOCK_WAIT,
            published.wait_for(|number| *number >= min_block),
        )
        .await
        .ok()?
        .ok()?;
        self.current
            .load_full()
            .filter(|state| state.canonical.number >= min_block)
    }

    /// The pools of the published state that failed the liquidity test.
    pub fn thin(&self) -> Arc<HashSet<Address>> {
        self.current
            .load()
            .as_ref()
            .map(|state| state.thin.clone())
            .unwrap_or_default()
    }

    /// `/health`'s view of the reader.
    pub fn health(&self) -> Value {
        let state = self.current.load_full();
        let tested_at = self.liquidity.lock().expect("resident liquidity").tested_at;
        let health = self.health.lock().expect("resident health");
        let age = state.as_ref().map(|state| state.confirmed_at().elapsed());
        json!({
            "enabled": true,
            "ready": age.is_some_and(|age| age <= STALE),
            "block": state.as_ref().map(|state| state.canonical.number),
            "headSeen": health.head_seen,
            "blocksBehind": state.as_ref().map(|state| health.head_seen.saturating_sub(state.canonical.number)),
            "ageMs": age.map(|age| age.as_millis() as u64),
            "pools": state.as_ref().map(|state| state.counts),
            "tokens": state.as_ref().map(|state| state.tokens.len()),
            "connectors": self.connectors.len(),
            "reads": health.reads,
            "failures": health.failures,
            "lastReadMs": health.last_read_ms,
            "lastError": health.last_error.as_ref().map(|(message, _)| message.clone()),
            "lastErrorAgeMs": health.last_error.as_ref().map(|(_, at)| at.elapsed().as_millis() as u64),
            "list": {
                "ageMs": health.list_at.map(|at| at.elapsed().as_millis() as u64),
                "pools": health.list_pools,
                "rejected": health.list_rejected,
            },
            "carry": {
                "fullReadMs": self.settings.full_read.map(|every| every.as_millis() as u64),
                "wholeReads": health.whole_reads,
                "carriedReads": health.carried_reads,
                "lastReread": health.last_reread,
                "logFailures": health.log_failures,
                "audited": health.audited,
                "drifted": health.drifted,
            },
            "thinPools": state.as_ref().map(|state| state.thin.len()),
            "liquidityTestAgeMs": tested_at.map(|at| at.elapsed().as_millis() as u64),
        })
    }

    /// Gauges for `/metrics`.
    pub fn prometheus(&self, out: &mut String) {
        let state = self.current.load_full();
        let health = self.health.lock().expect("resident health");
        let age = state
            .as_ref()
            .map(|state| state.confirmed_at().elapsed().as_millis() as u64);
        out.push_str("# HELP solver_resident_ready Resident pool state is fresh enough to quote from.\n# TYPE solver_resident_ready gauge\n");
        out.push_str(&format!(
            "solver_resident_ready {}\n",
            u8::from(age.is_some_and(|age| age <= STALE.as_millis() as u64))
        ));
        out.push_str("# HELP solver_resident_age_ms Since the resident state was last confirmed at the head.\n# TYPE solver_resident_age_ms gauge\n");
        out.push_str(&format!("solver_resident_age_ms {}\n", age.unwrap_or(0)));
        out.push_str("# HELP solver_resident_blocks_behind Blocks between the newest head seen and the published state.\n# TYPE solver_resident_blocks_behind gauge\n");
        out.push_str(&format!(
            "solver_resident_blocks_behind {}\n",
            state.as_ref().map_or(0, |state| health
                .head_seen
                .saturating_sub(state.canonical.number))
        ));
        out.push_str("# HELP solver_resident_thin_pools Resident pools that failed the liquidity test.\n# TYPE solver_resident_thin_pools gauge\n");
        out.push_str(&format!(
            "solver_resident_thin_pools {}\n",
            state.as_ref().map_or(0, |state| state.thin.len())
        ));
        out.push_str("# HELP solver_resident_reads_total Blocks read and published.\n# TYPE solver_resident_reads_total counter\n");
        out.push_str(&format!("solver_resident_reads_total {}\n", health.reads));
        out.push_str("# HELP solver_resident_failures_total Failed reader steps.\n# TYPE solver_resident_failures_total counter\n");
        out.push_str(&format!(
            "solver_resident_failures_total {}\n",
            health.failures
        ));
        for (name, help, value) in [
            (
                "solver_resident_whole_reads_total",
                "Blocks whose pools were all read.",
                health.whole_reads,
            ),
            (
                "solver_resident_carried_reads_total",
                "Blocks read from logs: the pools that logged read, the rest carried.",
                health.carried_reads,
            ),
            (
                "solver_resident_log_failures_total",
                "Failed log reads, each sending its block to a whole read.",
                health.log_failures,
            ),
            (
                "solver_resident_audited_pools_total",
                "Silent pools a whole read checked against their carried state.",
                health.audited,
            ),
            (
                "solver_resident_drifted_pools_total",
                "Audited pools whose state moved without a log.",
                health.drifted,
            ),
        ] {
            out.push_str(&format!(
                "# HELP {name} {help}\n# TYPE {name} counter\n{name} {value}\n"
            ));
        }
    }

    #[cfg(any(test, feature = "testing"))]
    pub fn publish_for_test(
        &self,
        snapshot: Snapshot,
        canonical: CanonicalBlock,
        confirmed: Instant,
    ) {
        let state = State::new(snapshot, canonical, &self.connectors, confirmed);
        self.publish(state, Duration::ZERO);
    }

    async fn step(&self, list: &mut List) -> anyhow::Result<()> {
        let observed_at = Instant::now();
        let header = self.rpc.canonical_header(BlockId::latest()).await?;
        {
            let mut health = self.health.lock().expect("resident health");
            health.head_seen = health.head_seen.max(header.block.number);
        }
        if let Some(current) = self.current.load_full() {
            if header.block.hash == current.canonical.hash {
                current.confirm(observed_at);
                return Ok(());
            }
            // A node behind the published block, or a sibling at its height:
            // neither is read, and neither keeps the published block fresh.
            if header.block.number <= current.canonical.number {
                return Ok(());
            }
        }
        if let Some(rows) = list.pending_rows.take()
            && let Err(error) = list.apply_rows(self, rows, header.block).await
        {
            self.note_error(&error.context("proving the new pool list"));
        }
        let started = Instant::now();
        let state = list.read(self, &header, observed_at).await?;
        self.publish(state, started.elapsed());
        Ok(())
    }
}

impl crate::state::ListedPaths for Resident {
    fn listed_paths(&self, statics: &[Address], a: Address, b: Address) -> Vec<Vec<Address>> {
        Resident::listed_paths(self, statics, a, b)
    }
}

#[cfg(test)]
impl Resident {
    pub(crate) async fn stamped_for(
        &self,
        a: Address,
        b: Address,
        min_block: u64,
    ) -> Option<Arc<Stamped>> {
        self.start_for(a, b, min_block).await.map(Stamped::resident)
    }
}

#[cfg(test)]
mod tests;
