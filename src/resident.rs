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

use crate::catalog::{CatalogProtocol, IndexedEvmDiscovery};
use crate::chain::ChainProfile;
#[cfg(test)]
use crate::engine::Stamped;
use crate::freshness::STALE;
use crate::pools::{V2Pool, V3Pool, V3State};
use crate::rpc::{CanonicalBlock, CanonicalHeader, Rpc, sanitized_error};
use crate::snapshot::Snapshot;
use crate::topology::AddressPoolTopology;
use crate::universe::{RESIDENT_MAX_PAIRS, RouteUniverse};
use alloy::eips::BlockId;
use alloy_primitives::{Address, U256};
use anyhow::{Context, ensure};
use arc_swap::ArcSwapOption;
use serde_json::{Value, json};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::watch;
use tokio::task::JoinHandle;

const LIST_REFRESH: Duration = Duration::from_secs(600);
const LIST_TIMEOUT: Duration = Duration::from_secs(15);
/// Pause after a failed list build before the next attempt.
const RETRY: Duration = Duration::from_secs(30);
/// How long a quote that must price from a later block waits for the reader.
const MIN_BLOCK_WAIT: Duration = Duration::from_secs(3);
/// How often every pool's liquidity is tested again. A pool new to the state
/// is tested in the block it arrives.
const LIQUIDITY_RETEST: Duration = Duration::from_secs(30 * 60);
/// The test's smaller trade, in dollars; the larger is twice it.
const LIQUIDITY_TEST_USD: u64 = 500;
/// How often every pool is read whole when logs say few changed.
const FULL_READ_DEFAULT: Duration = Duration::from_secs(60);
/// The most blocks one step carries state across; a longer gap is read whole.
/// A step asks for their headers in one batch and their logs in another, so
/// the bound is on the size of those answers, not on round trips.
const MAX_STEP_BLOCKS: u64 = 32;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Settings {
    pub list_url: String,
    pub poll: Duration,
    /// Connectors beyond the profile's own, admitted where they have pools.
    pub connectors: Vec<Address>,
    /// The longest every pool goes without being read whole; `None` reads
    /// every block whole and asks for no logs.
    pub full_read: Option<Duration>,
}

impl Settings {
    /// `None` when resident state is off, which it is unless
    /// `SOLVER_RESIDENT=on`; on, it needs `SOLVER_RESIDENT_POOL_LIST_URL`.
    pub fn from_env(profile: &ChainProfile) -> anyhow::Result<Option<Self>> {
        let read = |key| crate::chain::env_or(key, "");
        Self::parse(
            profile,
            &read("SOLVER_RESIDENT")?,
            &read("SOLVER_RESIDENT_POLL_MS")?,
            &read("SOLVER_RESIDENT_POOL_LIST_URL")?,
            &read("SOLVER_RESIDENT_CONNECTORS")?,
            &read("SOLVER_RESIDENT_FULL_READ_MS")?,
        )
    }

    fn parse(
        profile: &ChainProfile,
        mode: &str,
        poll_ms: &str,
        list_url: &str,
        connectors: &str,
        full_read_ms: &str,
    ) -> anyhow::Result<Option<Self>> {
        match mode.trim() {
            "" | "off" => return Ok(None),
            "on" => {}
            other => anyhow::bail!("SOLVER_RESIDENT={other:?} is invalid: use on or off"),
        }
        ensure!(
            profile.indexed_discovery().is_some(),
            "SOLVER_RESIDENT=on needs a profile with a venue table; {} has none",
            profile.key
        );
        let poll = match poll_ms.trim() {
            "" => 1_000,
            value => value
                .parse::<u64>()
                .with_context(|| format!("SOLVER_RESIDENT_POLL_MS={value:?} is invalid"))?,
        };
        ensure!(
            (200..=10_000).contains(&poll),
            "SOLVER_RESIDENT_POLL_MS must be 200 to 10000"
        );
        let list_url = list_url.trim();
        ensure!(
            !list_url.is_empty(),
            "SOLVER_RESIDENT=on needs SOLVER_RESIDENT_POOL_LIST_URL"
        );
        let parsed: reqwest::Url = list_url
            .parse()
            .context("SOLVER_RESIDENT_POOL_LIST_URL is not a URL")?;
        ensure!(
            matches!(parsed.scheme(), "https" | "http"),
            "SOLVER_RESIDENT_POOL_LIST_URL must be http(s)"
        );
        let connectors = connectors
            .split(',')
            .map(str::trim)
            .filter(|token| !token.is_empty())
            .map(|token| {
                token.parse::<Address>().with_context(|| {
                    format!("SOLVER_RESIDENT_CONNECTORS: {token:?} is not an address")
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        let full_read = match full_read_ms.trim() {
            "" => Some(FULL_READ_DEFAULT),
            "0" => None,
            value => {
                let ms = value.parse::<u64>().with_context(|| {
                    format!("SOLVER_RESIDENT_FULL_READ_MS={value:?} is invalid")
                })?;
                ensure!(
                    ms <= 3_600_000,
                    "SOLVER_RESIDENT_FULL_READ_MS must be 0 to 3600000"
                );
                Some(Duration::from_millis(ms))
            }
        };
        Ok(Some(Self {
            list_url: list_url.to_string(),
            poll: Duration::from_millis(poll),
            connectors,
            full_read,
        }))
    }
}

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

/// The listed pools that touch a resident connector.
#[derive(Clone, Debug, Default)]
pub struct ListedGraph {
    /// A connector's pool partners, and another token's connector partners.
    neighbors: HashMap<Address, BTreeSet<Address>>,
    /// The connectors with at least one pool.
    admitted: HashSet<Address>,
}

impl ListedGraph {
    /// From every pool's two tokens and the resident's connectors.
    pub fn new(
        edges: impl IntoIterator<Item = (Address, Address)>,
        connectors: &[Address],
    ) -> Self {
        let admitted = |token: &Address| connectors.contains(token);
        let mut graph = Self::default();
        for (a, b) in edges {
            if a == b || !(admitted(&a) || admitted(&b)) {
                continue;
            }
            graph.neighbors.entry(a).or_default().insert(b);
            graph.neighbors.entry(b).or_default().insert(a);
            for token in [a, b] {
                if admitted(&token) {
                    graph.admitted.insert(token);
                }
            }
        }
        graph
    }

    fn neighbors(&self, token: Address) -> impl Iterator<Item = Address> + '_ {
        self.neighbors.get(&token).into_iter().flatten().copied()
    }

    fn has_pool(&self, a: Address, b: Address) -> bool {
        self.neighbors.get(&a).is_some_and(|set| set.contains(&b))
    }

    /// Skeletons from `token_in` to `token_out` through at least one admitted
    /// connector that is not among `statics`, at most three hops: through `r`
    /// when it has pools with both endpoints; through `r` then a static
    /// connector `c` (or `c` then `r`) when `r` has pools with its endpoint
    /// and with `c`; through `r1` then `r2` when all three pools exist. The
    /// static connector's own pool with the far endpoint is left to the
    /// snapshot, as on a static skeleton.
    ///
    /// Ordered by length, then by the skeleton read in its smaller direction,
    /// so a pair and its reverse get the same skeletons, reversed, in the same
    /// order.
    pub fn paths(
        &self,
        statics: &[Address],
        token_in: Address,
        token_out: Address,
    ) -> Vec<Vec<Address>> {
        if token_in == token_out {
            return Vec::new();
        }
        let connector = |token: Address| {
            self.admitted.contains(&token)
                && !statics.contains(&token)
                && token != token_in
                && token != token_out
        };
        let fixed =
            |token: Address| statics.contains(&token) && token != token_in && token != token_out;
        let mut paths = BTreeSet::new();
        for r in self.neighbors(token_in).filter(|token| connector(*token)) {
            if self.has_pool(r, token_out) {
                paths.insert(vec![token_in, r, token_out]);
            }
            for c in self.neighbors(r) {
                if fixed(c) || (connector(c) && self.has_pool(c, token_out)) {
                    paths.insert(vec![token_in, r, c, token_out]);
                }
            }
        }
        for r in self.neighbors(token_out).filter(|token| connector(*token)) {
            for c in self.neighbors(r).filter(|token| fixed(*token)) {
                paths.insert(vec![token_in, c, r, token_out]);
            }
        }
        let mut paths: Vec<Vec<Address>> = paths.into_iter().collect();
        paths.sort_by_cached_key(|path| path_order(path));
        paths
    }
}

/// A skeleton's place in the order: its length, then its tokens read in the
/// smaller of its two directions.
pub(crate) fn path_order(path: &[Address]) -> (usize, Vec<Address>) {
    let forward = path.to_vec();
    let mut backward = forward.clone();
    backward.reverse();
    (path.len(), forward.min(backward))
}

/// Where a resident quote may widen: the skeletons through resident connectors
/// the list admits by their pools ([`ListedGraph`]) beside the static ones, and
/// the block's state to read their pools from.
///
/// A quote starts from the static skeletons. After each solve, every
/// candidate skeleton it does not route is probed: one minimum leg of the
/// input sent down it, through the best pool on each edge, with the pools the
/// plan traded in the state the plan left them. A candidate that delivers more
/// than the best skeleton the quote already routes, by at least the quote's
/// threshold, has its connectors admitted, and the quote is solved again on
/// the same block (`quotes.rs`). This is a route's reduced cost against the
/// served marginal rate, measured by exact simulation at the allocator's own
/// resolution: direction, depth and every pool on the route count, and a
/// skeleton is routed because the allocator could use it, not because it
/// fitted a budget. A pair the static skeletons cannot route starts with
/// every candidate admitted. Nothing carries over between quotes: the same
/// request at the same block widens the same way.
pub struct Widening {
    state: Arc<State>,
    profile: &'static ChainProfile,
    endpoints: (Address, Address),
    statics: Vec<Address>,
    /// Every connector, static or resident: a pool between one of these and
    /// another token is that token's market.
    bases: Vec<Address>,
    /// In `endpoints`' direction, ordered by `path_order`.
    candidates: Vec<Vec<Address>>,
    /// What the quote starts from.
    admitted: BTreeSet<Address>,
    /// Admitted skeletons the starting graph left out.
    left_out: usize,
    /// The starting graph's thin pools left out, and whether it kept them.
    thin_left_out: usize,
    thin_kept: bool,
}

/// One resident graph for a pair and the pools on it.
pub struct Widened {
    pub universe: RouteUniverse,
    pub snapshot: Snapshot,
    /// Admitted skeletons `RESIDENT_MAX_PAIRS` left out.
    pub left_out: usize,
    /// Pools on the graph's edges left out as thin connector hops.
    pub thin_left_out: usize,
    /// The graph took back the thin pools on edges nothing else serves,
    /// because it routed nothing without them.
    pub thin_kept: bool,
}

/// A pair's start on the resident state: its starting graph, the candidates
/// it may widen into, and the block read, for the engine to stamp.
pub struct ResidentStart {
    pub start: Widened,
    pub widening: Arc<Widening>,
    pub block_id: BlockId,
    pub block_timestamp: u64,
    pub at: Instant,
    pub observed_at: Instant,
}

/// A pool a probe may cross, in the state the probe sees.
enum Venue<'a> {
    V3(&'a V3Pool, &'a V3State),
    V2(&'a crate::pools::V2Pool, &'a crate::pools::V2State),
}

impl Venue<'_> {
    fn address(&self) -> Address {
        match self {
            Self::V3(pool, _) => pool.address,
            Self::V2(pool, _) => pool.address,
        }
    }

    fn tokens(&self) -> (Address, Address) {
        match self {
            Self::V3(pool, _) => (pool.token0, pool.token1),
            Self::V2(pool, _) => (pool.token0, pool.token1),
        }
    }

    /// What selling `amount` of `token` here delivers, if the pool fills it
    /// whole.
    fn out(&self, token: Address, amount: U256) -> Option<U256> {
        let out = match self {
            Self::V3(pool, state) => {
                crate::pools::sim_v3(pool, state, token == pool.token0, amount)
                    .ok()
                    .filter(|sim| sim.consumed == amount)?
                    .amount_out
            }
            Self::V2(pool, state) => {
                crate::pools::sim_v2(pool, state, token == pool.token0, amount)
                    .ok()?
                    .amount_out
            }
        };
        (!out.is_zero()).then_some(out)
    }
}

impl Widening {
    /// The connectors the candidates go through beyond the static ones, in
    /// the order the candidates first name them.
    pub fn connectors(&self) -> Vec<Address> {
        let mut connectors = Vec::new();
        for path in &self.candidates {
            for token in self.beyond(path) {
                if !connectors.contains(&token) {
                    connectors.push(token);
                }
            }
        }
        connectors
    }

    /// The connectors the quote starts with admitted.
    pub fn admitted(&self) -> &BTreeSet<Address> {
        &self.admitted
    }

    /// Admitted skeletons the starting graph left out.
    pub fn left_out(&self) -> usize {
        self.left_out
    }

    /// Thin pools the starting graph left out.
    pub fn thin_left_out(&self) -> usize {
        self.thin_left_out
    }

    /// The starting graph took back thin pools, routing nothing without them.
    pub fn thin_kept(&self) -> bool {
        self.thin_kept
    }

    fn beyond(&self, path: &[Address]) -> Vec<Address> {
        path[1..path.len() - 1]
            .iter()
            .copied()
            .filter(|token| !self.statics.contains(token))
            .collect()
    }

    /// The graph with every candidate whose connectors beyond the static ones
    /// are all in `admitted`, as many as fit within `RESIDENT_MAX_PAIRS`, and
    /// without the pools `leaves_out` names. When no skeleton routes without
    /// them, the thin pools on edges no other pool serves come back, which
    /// routes whatever the full graph routes; a thin pool beside one that
    /// passed stays out.
    pub fn graph(&self, admitted: &BTreeSet<Address>) -> anyhow::Result<Widened> {
        let mut graph = self.graph_with_thin(admitted)?;
        let mut narrow = self.without_thin(&graph.snapshot, None);
        if !routable(&narrow, &graph.universe) {
            let served = edges(&narrow);
            let narrowed = narrow.v3.len() + narrow.v2.len();
            narrow = self.without_thin(&graph.snapshot, Some(&served));
            graph.thin_kept = narrow.v3.len() + narrow.v2.len() > narrowed;
        }
        graph.thin_left_out =
            graph.snapshot.v3.len() + graph.snapshot.v2.len() - narrow.v3.len() - narrow.v2.len();
        graph.snapshot = narrow;
        Ok(graph)
    }

    /// `graph`, keeping every thin pool: for a quote the narrow graph routes
    /// but cannot fill.
    pub fn graph_with_thin(&self, admitted: &BTreeSet<Address>) -> anyhow::Result<Widened> {
        let (token0, token1) = self.endpoints;
        let taken: Vec<Vec<Address>> = self
            .candidates
            .iter()
            .filter(|path| {
                self.beyond(path)
                    .iter()
                    .all(|token| admitted.contains(token))
            })
            .cloned()
            .collect();
        let universe =
            RouteUniverse::resident(self.profile, &self.statics, &taken, token0, token1)?;
        let left_out = taken
            .iter()
            .filter(|path| !universe.token_paths().contains(path))
            .count();
        Ok(Widened {
            snapshot: self.state.subset(&universe),
            left_out,
            thin_left_out: 0,
            thin_kept: false,
            universe,
        })
    }

    /// Whether this quote leaves `pool` out: it failed the liquidity test, and
    /// none of the tokens it is the market of is one of the quote's own. A
    /// pool is the market of its tokens that are not connectors, or of both
    /// when both are, so any token can always be bought and sold through its
    /// own pools, however thin, while no route crosses a thin pool to reach
    /// some other token.
    fn leaves_out(&self, address: Address, token0: Address, token1: Address) -> bool {
        if !self.state.thin.contains(&address) {
            return false;
        }
        let (a, b) = self.endpoints;
        let own = |token: Address| token == a || token == b;
        match (self.bases.contains(&token0), self.bases.contains(&token1)) {
            (true, false) => !own(token1),
            (false, true) => !own(token0),
            _ => !own(token0) && !own(token1),
        }
    }

    /// `snapshot` without the pools `leaves_out` names, or, given the edges
    /// other pools already serve, without just those on such an edge.
    fn without_thin(
        &self,
        snapshot: &Snapshot,
        served: Option<&HashSet<(Address, Address)>>,
    ) -> Snapshot {
        let keep = |address: Address, token0: Address, token1: Address| {
            !self.leaves_out(address, token0, token1)
                || served.is_some_and(|served| !served.contains(&canonical(token0, token1)))
        };
        Snapshot {
            block: snapshot.block,
            settler: snapshot.settler,
            v3: snapshot
                .v3
                .iter()
                .filter(|(pool, _)| keep(pool.address, pool.token0, pool.token1))
                .cloned()
                .collect(),
            v2: snapshot
                .v2
                .iter()
                .filter(|(pool, _)| keep(pool.address, pool.token0, pool.token1))
                .cloned()
                .collect(),
            ekubo: snapshot.ekubo.clone(),
        }
    }

    /// The candidate skeletons, `token_in` first.
    fn oriented(&self, token_in: Address) -> Vec<Vec<Address>> {
        self.candidates
            .iter()
            .map(|path| {
                if path[0] == token_in {
                    path.clone()
                } else {
                    path.iter().rev().copied().collect()
                }
            })
            .collect()
    }

    /// The connectors to admit next, best first: those beyond `admitted` on
    /// each candidate skeleton `routed` lacks that could add at least
    /// `min_gain` to the quote.
    ///
    /// A probe sells an amount of `token_in` down a skeleton through the best
    /// pool on each edge; the pools of `served`, the snapshot the plan was
    /// solved on, are in `after`, the state the plan left them in. The quote's
    /// marginal rate is what `probe`, its smallest leg, fetches down the best
    /// skeleton in `routed`. A candidate's edge is how much more it fetches
    /// for `probe`, as a share of that. Output is concave in input, so no
    /// re-routing onto the candidate gains more per unit than that edge: more
    /// flow only narrows it. Where the candidate shares a hop with the routed
    /// skeletons, the flow it would take has already paid that hop, so the
    /// edge applies to the quote's output, not to what the hop pays at the
    /// margin. The edge times `quote` therefore bounds what admitting the
    /// candidate could add, and is weighed against `min_gain`. A candidate
    /// with no edge costs one probe.
    ///
    /// The edge is measured on the allocator's smallest leg, so a candidate
    /// better only below it is one the allocator could not use anyway.
    #[allow(clippy::too_many_arguments)] // the plan's world and the probe's terms
    pub fn worth_admitting(
        &self,
        admitted: &BTreeSet<Address>,
        served: &Snapshot,
        after: &crate::route::PlanStates,
        routed: &[Vec<Address>],
        token_in: Address,
        probe: U256,
        quote: U256,
        min_gain: U256,
    ) -> Vec<Address> {
        let candidates: Vec<Vec<Address>> = self
            .oriented(token_in)
            .into_iter()
            .filter(|path| {
                !routed.contains(path)
                    && self
                        .beyond(path)
                        .iter()
                        .any(|token| !admitted.contains(token))
            })
            .collect();
        if candidates.is_empty() || probe.is_zero() {
            return Vec::new();
        }
        let mut venues: HashMap<(Address, Address), Vec<Venue<'_>>> = HashMap::new();
        let mut seen: HashSet<Address> = HashSet::new();
        for (index, (pool, _)) in served.v3.iter().enumerate() {
            if let Some(state) = after.v3.get(index) {
                seen.insert(pool.address);
                venues
                    .entry(canonical(pool.token0, pool.token1))
                    .or_default()
                    .push(Venue::V3(pool, state));
            }
        }
        for (index, (pool, _)) in served.v2.iter().enumerate() {
            if let Some(state) = after.v2.get(index) {
                seen.insert(pool.address);
                venues
                    .entry(canonical(pool.token0, pool.token1))
                    .or_default()
                    .push(Venue::V2(pool, state));
            }
        }
        let wanted: HashSet<(Address, Address)> = candidates
            .iter()
            .flat_map(|path| path.windows(2).map(|edge| canonical(edge[0], edge[1])))
            .collect();
        // A pool the graph would leave out is not probed: admitting a
        // connector for it would add nothing the next graph could route.
        for (pool, state) in &self.state.snapshot.v3 {
            let pair = canonical(pool.token0, pool.token1);
            if wanted.contains(&pair)
                && !seen.contains(&pool.address)
                && !self.leaves_out(pool.address, pool.token0, pool.token1)
            {
                venues.entry(pair).or_default().push(Venue::V3(pool, state));
            }
        }
        for (pool, state) in &self.state.snapshot.v2 {
            let pair = canonical(pool.token0, pool.token1);
            if wanted.contains(&pair)
                && !seen.contains(&pool.address)
                && !self.leaves_out(pool.address, pool.token0, pool.token1)
            {
                venues.entry(pair).or_default().push(Venue::V2(pool, state));
            }
        }
        // Each hop's output only grows with its input, so the best pool at
        // each hop is the best single route down the skeleton.
        let deliver = |path: &[Address], amount: U256| -> Option<U256> {
            let mut amount = amount;
            for edge in path.windows(2) {
                amount = venues
                    .get(&canonical(edge[0], edge[1]))?
                    .iter()
                    .filter_map(|venue| venue.out(edge[0], amount))
                    .max()?;
            }
            Some(amount)
        };
        let best = routed
            .iter()
            .filter_map(|path| deliver(path, probe))
            .max()
            .unwrap_or_default();
        let mut gains: Vec<(U256, Vec<Address>)> = candidates
            .into_iter()
            .filter_map(|path| {
                let edge = deliver(&path, probe)?
                    .checked_sub(best)
                    .filter(|edge| !edge.is_zero())?;
                // With nothing routed to compare against, any delivery is an
                // edge without bound.
                let bound = if best.is_zero() {
                    U256::MAX
                } else {
                    edge.saturating_mul(quote) / best
                };
                (bound >= min_gain).then_some((bound, path))
            })
            .collect();
        gains.sort_by_key(|(gain, _)| std::cmp::Reverse(*gain));
        let mut promote = Vec::new();
        for (_, path) in gains {
            for token in self.beyond(&path) {
                if !admitted.contains(&token) && !promote.contains(&token) {
                    promote.push(token);
                }
            }
        }
        promote
    }
}

/// Jupiter's routing liquidity test (developers.jup.ag, "Market Listing",
/// read 16 Oct 2026), run on every resident pool: a pool passes when $500 of
/// its token, bought and sold straight back, loses under 30%, or else when
/// a $1,000 buy's unit price is within 20% of a $500 buy's. Both legs of a
/// test are priced on the same state, as two quotes. A pool is tested from
/// the side priced first, starting from the profile's stable
/// (`dollar_amounts`). A pool with no priced side is not tested. A pool that
/// failed is tested again at every block.
#[derive(Default)]
struct Liquidity {
    /// When every pool was last tested.
    tested_at: Option<Instant>,
    /// Pools tested since then.
    tested: HashSet<Address>,
    /// Those that failed.
    thin: Arc<HashSet<Address>>,
}

impl Resident {
    /// The pools of `snapshot` that failed the liquidity test: every pool
    /// again once `LIQUIDITY_RETEST` has passed, otherwise the ones it has not
    /// tested and the ones that failed. A pool often arrives empty and is
    /// funded a few blocks later, so a failure is checked again at every
    /// block, which costs a dozen pools' worth of arithmetic; a pass stands
    /// until the retest.
    fn thin_pools(&self, snapshot: &Snapshot) -> Arc<HashSet<Address>> {
        let mut liquidity = self.liquidity.lock().expect("resident liquidity");
        if liquidity
            .tested_at
            .is_none_or(|at| at.elapsed() >= LIQUIDITY_RETEST)
        {
            *liquidity = Liquidity {
                tested_at: Some(Instant::now()),
                ..Liquidity::default()
            };
        }
        let venues: Vec<Venue<'_>> = testable_venues(snapshot)
            .filter(|venue| {
                !liquidity.tested.contains(&venue.address())
                    || liquidity.thin.contains(&venue.address())
            })
            .collect();
        if venues.is_empty() {
            return liquidity.thin.clone();
        }
        let started = Instant::now();
        let dollars = dollar_amounts(snapshot, self.profile, &self.connectors, LIQUIDITY_TEST_USD);
        let new = venues
            .iter()
            .filter(|venue| !liquidity.tested.contains(&venue.address()))
            .count();
        let mut thin = HashSet::new();
        for venue in &venues {
            liquidity.tested.insert(venue.address());
            if fails_liquidity_test(venue, &dollars) {
                thin.insert(venue.address());
            }
        }
        if new > 0 || thin != *liquidity.thin {
            tracing::info!(
                "resident: liquidity test at block {}: {} pools tested ({new} new) in {} us, {} of {} thin",
                snapshot.block,
                venues.len(),
                started.elapsed().as_micros(),
                thin.len(),
                liquidity.tested.len()
            );
            liquidity.thin = Arc::new(thin);
        }
        liquidity.thin.clone()
    }
}

/// The V3 and V2 pools of `snapshot`, which the test can price.
fn testable_venues(snapshot: &Snapshot) -> impl Iterator<Item = Venue<'_>> {
    snapshot
        .v3
        .iter()
        .map(|(pool, state)| Venue::V3(pool, state))
        .chain(
            snapshot
                .v2
                .iter()
                .map(|(pool, state)| Venue::V2(pool, state)),
        )
}

/// `usd` dollars of each connector `snapshot` can price, in its smallest
/// unit, in the order they were priced: the profile's stable at face value,
/// then each other connector by what that much of a priced one buys of it
/// through the best pool between them that passes the test from the priced
/// side. A connector whose every path crosses a thin pool has no price: a
/// thin pool's price is the one a single trade can move.
fn dollar_amounts(
    snapshot: &Snapshot,
    profile: &ChainProfile,
    connectors: &[Address],
    usd: u64,
) -> Vec<(Address, U256)> {
    let mut priced = Vec::new();
    let Some(dollar) = U256::from(10u8).checked_pow(U256::from(profile.stable_decimals)) else {
        return priced;
    };
    priced.push((profile.stable, U256::from(usd) * dollar));
    let price = |priced: &[(Address, U256)], token: Address| {
        priced
            .iter()
            .find(|(priced, _)| *priced == token)
            .map(|(_, amount)| *amount)
    };
    for _ in 0..connectors.len() {
        let mut found: Vec<(Address, U256)> = Vec::new();
        for venue in testable_venues(snapshot) {
            let (token0, token1) = venue.tokens();
            for (from, to) in [(token0, token1), (token1, token0)] {
                if !connectors.contains(&to) || price(&priced, to).is_some() {
                    continue;
                }
                let Some(amount) = price(&priced, from) else {
                    continue;
                };
                if fails_from(&venue, from, to, amount) {
                    continue;
                }
                let Some(out) = venue.out(from, amount) else {
                    continue;
                };
                match found.iter_mut().find(|(token, _)| *token == to) {
                    Some((_, best)) => *best = (*best).max(out),
                    None => found.push((to, out)),
                }
            }
        }
        if found.is_empty() {
            break;
        }
        // In connector order, so the result does not hang on pool order.
        found.sort_by_key(|(token, _)| connectors.iter().position(|c| c == token));
        priced.extend(found);
    }
    priced
}

/// Whether `venue` fails the liquidity test, priced in whichever of its
/// tokens `dollars` priced first. A pool with neither side priced is not
/// tested.
fn fails_liquidity_test(venue: &Venue<'_>, dollars: &[(Address, U256)]) -> bool {
    let (token0, token1) = venue.tokens();
    let Some(&(quote, small)) = dollars
        .iter()
        .find(|(token, _)| *token == token0 || *token == token1)
    else {
        return false;
    };
    let token = if quote == token0 { token1 } else { token0 };
    fails_from(venue, quote, token, small)
}

/// The test proper: `small` of `quote` buys `token` and sells it straight
/// back, and a $1,000 buy is priced beside the $500 one. A pool that cannot
/// fill the trade fails.
fn fails_from(venue: &Venue<'_>, quote: Address, token: Address, small: U256) -> bool {
    let Some(bought) = venue.out(quote, small) else {
        return true;
    };
    let back = venue.out(token, bought).unwrap_or_default();
    // Under 30% lost on the round trip.
    if back.saturating_mul(U256::from(10u8)) > small.saturating_mul(U256::from(7u8)) {
        return false;
    }
    let Some(bought_twice) = venue.out(quote, small.saturating_mul(U256::from(2u8))) else {
        return true;
    };
    // The $1,000 unit price, 2·small / bought_twice, above 1.2 times the $500
    // one, small / bought.
    bought.saturating_mul(U256::from(5u8)) > bought_twice.saturating_mul(U256::from(3u8))
}

fn canonical(a: Address, b: Address) -> (Address, Address) {
    if a <= b { (a, b) } else { (b, a) }
}

/// The token pairs `snapshot` has a V3, CL or V2 pool on.
fn edges(snapshot: &Snapshot) -> HashSet<(Address, Address)> {
    snapshot
        .v3
        .iter()
        .map(|(pool, _)| (pool.token0, pool.token1))
        .chain(
            snapshot
                .v2
                .iter()
                .map(|(pool, _)| (pool.token0, pool.token1)),
        )
        .map(|(a, b)| canonical(a, b))
        .collect()
}

/// Some skeleton of `universe` has a pool on every edge of `snapshot`.
fn routable(snapshot: &Snapshot, universe: &RouteUniverse) -> bool {
    let present = edges(snapshot);
    universe.token_paths().iter().any(|path| {
        path.windows(2)
            .all(|edge| present.contains(&canonical(edge[0], edge[1])))
    })
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

    #[cfg(test)]
    pub(crate) fn publish_for_test(
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

async fn run(resident: Arc<Resident>) {
    let mut list: Option<List> = None;
    let mut fetch: Option<JoinHandle<anyhow::Result<Vec<AddressPoolTopology>>>> = None;
    let mut next_fetch = Instant::now() + LIST_REFRESH;
    loop {
        let started = Instant::now();
        let Some(current) = list.as_mut() else {
            match List::build(&resident).await {
                Ok(built) => {
                    tracing::info!(
                        "resident: list built: {} V3 and {} V2 pools proved, {} rejected",
                        built.v3.len(),
                        built.v2.len(),
                        built.rejected.len(),
                    );
                    list = Some(built);
                    next_fetch = Instant::now() + LIST_REFRESH;
                }
                Err(error) => {
                    resident.note_error(&error.context("building the pool list"));
                    tokio::time::sleep(RETRY).await;
                }
            }
            continue;
        };
        if fetch.as_ref().is_some_and(JoinHandle::is_finished) {
            match fetch.take().expect("checked").await {
                Ok(Ok(rows)) => current.pending_rows = Some(rows),
                Ok(Err(error)) => resident
                    .note_error(&error.context("fetching the pool list; keeping the last one")),
                Err(error) => resident.note_error(&anyhow::anyhow!(
                    "pool list fetch stopped: {error}; keeping the last one"
                )),
            }
        }
        if fetch.is_none() && Instant::now() >= next_fetch {
            fetch = Some(tokio::spawn(fetch_list(
                resident.http.clone(),
                resident.settings.list_url.clone(),
            )));
            next_fetch = Instant::now() + LIST_REFRESH;
        }
        if let Err(error) = resident.step(current).await {
            resident.note_error(&error);
        }
        tokio::time::sleep(resident.settings.poll.saturating_sub(started.elapsed())).await;
    }
}

/// The pools to read, with their identities. Owned by the reader.
struct List {
    /// Sorted by (token0, token1, address), the per-pair path's order.
    v3: Vec<V3Pool>,
    v2: Vec<V2Pool>,
    rejected: HashSet<Address>,
    pending_rows: Option<Vec<AddressPoolTopology>>,
    /// The last read, for the next to carry from.
    last: Option<carry::LastRead>,
}

impl List {
    async fn build(resident: &Resident) -> anyhow::Result<Self> {
        let header = resident.rpc.canonical_header(BlockId::latest()).await?;
        let mut list = Self {
            v3: Vec::new(),
            v2: Vec::new(),
            rejected: HashSet::new(),
            pending_rows: None,
            last: None,
        };
        let rows = fetch_list(resident.http.clone(), resident.settings.list_url.clone()).await?;
        list.apply_rows(resident, rows, header.block).await?;
        ensure!(
            !list.v3.is_empty() || !list.v2.is_empty(),
            "no pool on the list passed its identity check"
        );
        Ok(list)
    }

    /// Take a fresh list: prove the pools it adds, drop the ones it no longer
    /// lists.
    async fn apply_rows(
        &mut self,
        resident: &Resident,
        rows: Vec<AddressPoolTopology>,
        block: CanonicalBlock,
    ) -> anyhow::Result<()> {
        let listed: HashSet<Address> = rows.iter().map(|row| row.address).collect();
        let known: HashSet<Address> = self
            .v3
            .iter()
            .map(|pool| pool.address)
            .chain(self.v2.iter().map(|pool| pool.address))
            .collect();
        let fresh: Vec<AddressPoolTopology> = rows
            .into_iter()
            .filter(|row| !known.contains(&row.address) && !self.rejected.contains(&row.address))
            .collect();
        let (v3, v2, rejected) = crate::state::prove_listed_pools(
            resident.profile,
            resident.discovery,
            &resident.rpc,
            &fresh,
            block,
        )
        .await?;
        for (address, reason) in rejected {
            tracing::info!("resident: the list names {address:#x}; left out: {reason}");
            self.rejected.insert(address);
        }
        self.v3.retain(|pool| listed.contains(&pool.address));
        self.v3.extend(v3);
        self.v3
            .sort_by_key(|pool| (pool.token0, pool.token1, pool.address));
        self.v2.retain(|pool| listed.contains(&pool.address));
        self.v2.extend(v2);
        self.v2
            .sort_by_key(|pool| (pool.token0, pool.token1, pool.address));
        let mut health = resident.health.lock().expect("resident health");
        health.list_at = Some(Instant::now());
        health.list_pools = self.v3.len() + self.v2.len();
        health.list_rejected = self.rejected.len();
        Ok(())
    }

    /// One block's state of every listed pool: the pools that logged since
    /// the last read read again and the rest carried, or every pool read
    /// whole.
    async fn read(
        &mut self,
        resident: &Resident,
        head: &CanonicalHeader,
        observed_at: Instant,
    ) -> anyhow::Result<State> {
        let block = head.block;
        let listed: HashSet<Address> = self
            .v3
            .iter()
            .map(|pool| pool.address)
            .chain(self.v2.iter().map(|pool| pool.address))
            .collect();
        // Pools whose venue is not known to move only with `carry::MOVES`.
        let uncarried: HashSet<Address> = self
            .v3
            .iter()
            .filter(|pool| !carry::carries_v3(pool))
            .map(|pool| pool.address)
            .chain(
                self.v2
                    .iter()
                    .filter(|pool| !carry::carries_v2(pool))
                    .map(|pool| pool.address),
            )
            .collect();
        let pools = async {
            let changed = match (resident.settings.full_read, self.last.as_ref()) {
                (Some(_), Some(last)) => {
                    match changed_since(&resident.rpc, &last.block, head, &listed).await {
                        Ok(changed) => changed.map(|changed| &changed | &uncarried),
                        Err(error) => {
                            tracing::info!(
                                "resident: pool logs unread, reading every pool: {}",
                                sanitized_error(&error)
                            );
                            resident
                                .health
                                .lock()
                                .expect("resident health")
                                .log_failures += 1;
                            None
                        }
                    }
                }
                _ => None,
            };
            let carry_from = match (resident.settings.full_read, self.last.as_ref(), &changed) {
                (Some(every), Some(last), Some(changed)) if last.whole_at.elapsed() < every => {
                    Some((last, changed))
                }
                _ => None,
            };
            let Some((last, changed)) = carry_from else {
                let whole = read_pools(resident, &self.v3, &self.v2, block, observed_at).await?;
                let audit = match (self.last.as_ref(), &changed) {
                    (Some(last), Some(changed)) => {
                        Some(carry::audit(last, changed, &whole, &listed))
                    }
                    _ => None,
                };
                return anyhow::Ok((whole.v3, whole.v2, Read::Whole { audit }));
            };
            let read = carry::to_read(&listed, last, changed);
            let v3: Vec<V3Pool> = self
                .v3
                .iter()
                .filter(|pool| read.contains(&pool.address))
                .cloned()
                .collect();
            let v2: Vec<V2Pool> = self
                .v2
                .iter()
                .filter(|pool| read.contains(&pool.address))
                .cloned()
                .collect();
            let fresh = read_pools(resident, &v3, &v2, block, observed_at).await?;
            let (v3, v2) = carry::merge(&self.v3, &self.v2, &read, &fresh, last);
            Ok((
                v3,
                v2,
                Read::Carried {
                    reread: read.len(),
                    whole_at: last.whole_at,
                },
            ))
        };
        let (settler, (v3, v2, how)) = tokio::try_join!(read_settler(resident, block), pools)?;
        let whole_at = match &how {
            Read::Whole { .. } => observed_at,
            Read::Carried { whole_at, .. } => *whole_at,
        };
        self.last = Some(carry::LastRead::new(block, listed, &v3, &v2, whole_at));
        {
            let mut health = resident.health.lock().expect("resident health");
            match &how {
                Read::Whole { audit } => {
                    health.whole_reads += 1;
                    if let Some((checked, drifted)) = audit {
                        health.audited += *checked as u64;
                        health.drifted += drifted.len() as u64;
                    }
                }
                Read::Carried { reread, .. } => {
                    health.carried_reads += 1;
                    health.last_reread = Some(*reread);
                }
            }
        }
        if let Read::Whole {
            audit: Some((_, drifted)),
        } = &how
            && !drifted.is_empty()
        {
            tracing::warn!(
                "resident: {} pools moved at block {} without a log, now read whole: {}",
                drifted.len(),
                block.number,
                drifted
                    .iter()
                    .take(8)
                    .map(|address| format!("{address:#x}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        let snapshot = Snapshot {
            block: block.number,
            settler,
            v3,
            v2,
            ekubo: Vec::new(),
        };
        Ok(State::new(
            snapshot,
            block,
            &resident.connectors,
            observed_at,
        ))
    }
}

/// How a block's pools were read.
enum Read {
    /// Every pool, with the audit of the carry when the blocks since the
    /// last read were linked: pools checked, and those that drifted.
    Whole {
        audit: Option<(usize, Vec<Address>)>,
    },
    /// Only the pools that logged or are new; the rest carried.
    Carried { reread: usize, whole_at: Instant },
}

/// `v3` and `v2`'s state at `block`, one Lens read.
async fn read_pools(
    resident: &Resident,
    v3: &[V3Pool],
    v2: &[V2Pool],
    block: CanonicalBlock,
    observed_at: Instant,
) -> anyhow::Result<Snapshot> {
    if v3.is_empty() && v2.is_empty() {
        return Ok(Snapshot {
            block: block.number,
            settler: None,
            v3: Vec::new(),
            v2: Vec::new(),
            ekubo: Vec::new(),
        });
    }
    let words = crate::state::bitmap_words()?;
    let ret = crate::lens::peek_pinned(&resident.rpc, words, v3, v2, block, observed_at).await?;
    ensure!(
        ret.block_number == block.number && ret.block_id == BlockId::hash_canonical(block.hash),
        "resident Lens did not read the requested block"
    );
    crate::state::parse_resident_lens(v3, v2, &ret)
}

/// The Settler the registry names at `block`, when execution is enabled.
async fn read_settler(
    resident: &Resident,
    block: CanonicalBlock,
) -> anyhow::Result<Option<Address>> {
    let profile = resident.profile;
    if !profile.execution_enabled() {
        return Ok(None);
    }
    let rpc = &resident.rpc;
    let block_id = BlockId::hash_canonical(block.hash);
    let owner = rpc
        .multicall(
            vec![crate::state::execution_registry_call(profile)?],
            block_id,
        )
        .await?;
    let owner = owner.first().context("registry read is missing")?;
    Ok(
        crate::state::execution_identity_from(profile, rpc, block_id, owner)
            .await?
            .map(|identity| identity.settler),
    )
}

/// The pools of `pools` that moved in the blocks after `last` through
/// `head`. `None` when those blocks do not link to `last` (a reorg, or a node
/// on another branch) or span more than `MAX_STEP_BLOCKS`.
async fn changed_since(
    rpc: &Rpc,
    last: &CanonicalBlock,
    head: &CanonicalHeader,
    pools: &HashSet<Address>,
) -> anyhow::Result<Option<HashSet<Address>>> {
    let span = head.block.number.saturating_sub(last.number);
    if span == 0 || span > MAX_STEP_BLOCKS {
        return Ok(None);
    }
    let between = rpc
        .canonical_headers(last.number + 1..head.block.number)
        .await?;
    let Some(blocks) = carry::linked(last, &between, head) else {
        return Ok(None);
    };
    let answers = rpc
        .logs_batch(
            blocks
                .iter()
                .map(|block| json!({"blockHash": block.hash, "topics": [carry::MOVES]}))
                .collect(),
            head.block.number,
        )
        .await?;
    let changed = blocks
        .iter()
        .zip(&answers)
        .map(|(block, logs)| carry::logged(logs, block, pools))
        .collect::<anyhow::Result<Vec<_>>>()?;
    Ok(Some(changed.into_iter().flatten().collect()))
}

/// The pool list: a JSON array of address pools, each
/// `{"protocol", "address", "token0", "token1", "feePpm"}` with `protocol`
/// a venue id from the profile's table. Read whole or refused whole.
async fn fetch_list(
    http: reqwest::Client,
    url: String,
) -> anyhow::Result<Vec<AddressPoolTopology>> {
    let body: Value = http
        .get(&url)
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .map_err(|error| anyhow::anyhow!("pool list request failed: {}", error.without_url()))?
        .json()
        .await
        .map_err(|error| anyhow::anyhow!("pool list is not JSON: {}", error.without_url()))?;
    let items = body
        .as_array()
        .context("the pool list is not a JSON array")?;
    let mut seen = HashSet::new();
    let mut rows = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        let row = list_row(item).with_context(|| format!("pool list row {index}"))?;
        ensure!(
            seen.insert(row.address),
            "the pool list names {:#x} twice",
            row.address
        );
        rows.push(row);
    }
    ensure!(!rows.is_empty(), "the pool list is empty");
    Ok(rows)
}

fn list_row(item: &Value) -> anyhow::Result<AddressPoolTopology> {
    let address = |field: &str| -> anyhow::Result<Address> {
        item[field]
            .as_str()
            .with_context(|| format!("no {field}"))?
            .parse()
            .with_context(|| format!("{field} is not an address"))
    };
    let protocol = item["protocol"].as_str().context("no protocol")?;
    let protocol = CatalogProtocol::known(protocol)
        .filter(|protocol| *protocol != CatalogProtocol::UNIV4)
        .with_context(|| format!("{protocol:?} is not an address-pool protocol"))?;
    let fee_ppm = item["feePpm"]
        .as_u64()
        .and_then(|fee| u32::try_from(fee).ok())
        .filter(|fee| *fee < 1_000_000)
        .context("no valid feePpm")?;
    Ok(AddressPoolTopology {
        protocol,
        address: address("address")?,
        token0: address("token0")?,
        token1: address("token1")?,
        fee_ppm,
        tick_spacing: None,
        created_block: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::{FIXTURE_PROFILE, FIXTURE_USDC, FIXTURE_USDT0, FIXTURE_WETH};
    use crate::pools::{TickInfo, V2Protocol, V2State, V3ExecutionMeta, V3Protocol};
    use alloy_primitives::{B256, U256, address};
    use axum::{Router, routing::get};
    use std::collections::{BTreeSet, HashSet};

    const T1: Address = address!("1000000000000000000000000000000000000001");
    const T2: Address = address!("2000000000000000000000000000000000000002");

    fn v3(address: Address, a: Address, b: Address, spacing: i32) -> (V3Pool, V3State) {
        let (token0, token1) = canonical(a, b);
        (
            V3Pool {
                protocol: V3Protocol::UNIV3,
                address,
                token0,
                token1,
                fee_ppm: 3_000,
                tick_spacing: spacing,
                verify_pool_spacing: false,
                execution: Some(V3ExecutionMeta {
                    fork_id: 200,
                    pool_id: 3_000,
                }),
                v4: None,
                algebra: None,
            },
            V3State {
                sqrt_price: U256::from(1u128 << 96),
                tick: 0,
                liquidity: U256::from(1_000_000u64),
                ticks: Vec::<TickInfo>::new().into(),
                pos: 0,
                lo_cover: -887_272,
                hi_cover: 887_272,
            },
        )
    }

    fn v2(address: Address, a: Address, b: Address) -> (V2Pool, V2State) {
        let (token0, token1) = canonical(a, b);
        (
            V2Pool {
                protocol: V2Protocol::UNIV2,
                address,
                token0,
                token1,
                fee_bps: 35,
            },
            V2State {
                reserve0: U256::from(10u64).pow(U256::from(21u64)),
                reserve1: U256::from(10u64).pow(U256::from(21u64)),
            },
        )
    }

    fn block(number: u64) -> CanonicalBlock {
        CanonicalBlock {
            number,
            hash: B256::repeat_byte(number as u8),
            timestamp: 1_000 + number,
        }
    }

    /// A V2 pool holding `reserve_a` of `a` and `reserve_b` of `b`.
    fn v2_holding(
        address: Address,
        a: Address,
        b: Address,
        reserve_a: U256,
        reserve_b: U256,
    ) -> (V2Pool, V2State) {
        let (pool, _) = v2(address, a, b);
        let (reserve0, reserve1) = if pool.token0 == a {
            (reserve_a, reserve_b)
        } else {
            (reserve_b, reserve_a)
        };
        (pool, V2State { reserve0, reserve1 })
    }

    #[test]
    fn the_liquidity_test_passes_pools_from_about_two_thousand_dollars_a_side() {
        let usd = |dollars: u64| U256::from(dollars) * U256::from(1_000_000u64);
        let tokens = U256::from(10u64).pow(U256::from(24u64));
        let weth = U256::from(10u64).pow(U256::from(22u64));
        let snapshot = Snapshot {
            block: 7,
            settler: None,
            v3: vec![],
            v2: vec![
                // 2,500 USDT0 a WETH, $25M a side.
                v2_holding(
                    Address::repeat_byte(0xc0),
                    FIXTURE_WETH,
                    FIXTURE_USDT0,
                    weth,
                    usd(25_000_000),
                ),
                v2_holding(
                    Address::repeat_byte(0xc1),
                    T1,
                    FIXTURE_USDT0,
                    tokens,
                    usd(1_000_000),
                ),
                // A $500 round trip loses about 32%, but a $1,000 buy's unit
                // price is only 18% above a $500 one's.
                v2_holding(
                    Address::repeat_byte(0xc2),
                    T1,
                    FIXTURE_USDT0,
                    tokens,
                    usd(2_200),
                ),
                // About 40% lost and 25% dearer: thin.
                v2_holding(
                    Address::repeat_byte(0xc3),
                    T1,
                    FIXTURE_USDT0,
                    tokens,
                    usd(1_500),
                ),
                // No side has a dollar price: not tested.
                v2_holding(Address::repeat_byte(0xc4), T1, T2, tokens, U256::from(1u8)),
                // USDC's one pool to a priced token is thin, so USDC has no
                // dollar price, and its thin pool with T2 is not tested.
                v2_holding(
                    Address::repeat_byte(0xc6),
                    FIXTURE_USDC,
                    FIXTURE_USDT0,
                    U256::from(1_500_000_000u64),
                    usd(1_500),
                ),
                v2_holding(
                    Address::repeat_byte(0xc7),
                    FIXTURE_USDC,
                    T2,
                    U256::from(1_000_000_000u64),
                    tokens,
                ),
            ],
            ekubo: vec![],
        };
        let connectors = [FIXTURE_WETH, FIXTURE_USDT0, FIXTURE_USDC];
        let dollars = dollar_amounts(&snapshot, &FIXTURE_PROFILE, &connectors, LIQUIDITY_TEST_USD);
        assert_eq!(dollars[0], (FIXTURE_USDT0, usd(500)));
        // $500 of WETH is about 0.2 WETH, through the deep pool.
        let fifth = U256::from(2u64) * U256::from(10u64).pow(U256::from(17u64));
        assert_eq!(dollars[1].0, FIXTURE_WETH);
        assert!(dollars[1].1 < fifth && dollars[1].1 > fifth * U256::from(99) / U256::from(100));
        assert_eq!(dollars.len(), 2, "USDC is priced only through a thin pool");
        let thin: Vec<bool> = testable_venues(&snapshot)
            .map(|venue| fails_liquidity_test(&venue, &dollars))
            .collect();
        assert_eq!(thin, [false, false, false, true, false, true, false]);

        let resident = resident(connectors.to_vec());
        resident.publish_for_test(snapshot.clone(), block(7), Instant::now());
        assert_eq!(resident.health()["thinPools"], 2);
        assert!(resident.health()["liquidityTestAgeMs"].is_u64());
        let mut metrics = String::new();
        resident.prometheus(&mut metrics);
        assert!(metrics.contains("solver_resident_thin_pools 2\n"));
        // Published, every pool is tested; asked again, none is.
        let judged = resident.thin_pools(&snapshot);
        assert_eq!(
            *judged,
            HashSet::from([Address::repeat_byte(0xc3), Address::repeat_byte(0xc6)])
        );
        // Within the retest interval only new pools are tested.
        let mut grown = snapshot.clone();
        grown.v2.push(v2_holding(
            Address::repeat_byte(0xc5),
            T2,
            FIXTURE_USDT0,
            tokens,
            usd(100),
        ));
        assert_eq!(
            *resident.thin_pools(&grown),
            HashSet::from([
                Address::repeat_byte(0xc3),
                Address::repeat_byte(0xc5),
                Address::repeat_byte(0xc6)
            ])
        );
        let refill = |snapshot: &Snapshot, byte: u8, dollars: u64| {
            let mut next = snapshot.clone();
            next.v2
                .retain(|(pool, _)| pool.address != Address::repeat_byte(byte));
            next.v2.push(v2_holding(
                Address::repeat_byte(byte),
                T1,
                FIXTURE_USDT0,
                tokens,
                usd(dollars),
            ));
            next
        };
        // A thin pool funded since is tested again at the next block, and
        // passes.
        let funded = refill(&grown, 0xc3, 1_000_000);
        assert_eq!(
            *resident.thin_pools(&funded),
            HashSet::from([Address::repeat_byte(0xc5), Address::repeat_byte(0xc6)])
        );
        // A pass stands until the retest, however the pool has been drained
        // since; the retest catches it.
        let drained = refill(&funded, 0xc1, 100);
        assert!(
            !resident
                .thin_pools(&drained)
                .contains(&Address::repeat_byte(0xc1))
        );
        resident.liquidity.lock().unwrap().tested_at = None;
        assert!(
            resident
                .thin_pools(&drained)
                .contains(&Address::repeat_byte(0xc1))
        );
    }

    #[test]
    fn a_graph_that_needs_thin_pools_takes_back_only_those_on_bare_edges() {
        // L trades against WETH; R, a resident connector, against WETH through
        // a pool that passed and one that failed, and against USDT0 only
        // through one that failed. Without the failures nothing reaches USDT0,
        // so R's USDT0 pool comes back; the failed WETH pool, beside one that
        // passed, stays out.
        let resident_connector = Address::repeat_byte(0x4e);
        let token = Address::repeat_byte(0x4c);
        let at = Address::repeat_byte;
        let snapshot = Snapshot {
            block: 7,
            settler: Some(Address::repeat_byte(0x5e)),
            v3: vec![
                v3(at(0xe1), token, FIXTURE_WETH, 10),
                v3(at(0xe2), FIXTURE_WETH, resident_connector, 10),
                v3(at(0xe3), FIXTURE_WETH, resident_connector, 60),
                v3(at(0xe4), resident_connector, FIXTURE_USDT0, 10),
            ],
            v2: vec![],
            ekubo: vec![],
        };
        let statics = vec![FIXTURE_WETH, FIXTURE_USDT0];
        let mut state = State::new(
            snapshot,
            block(7),
            &[FIXTURE_WETH, FIXTURE_USDT0, resident_connector],
            Instant::now(),
        );
        state.thin = Arc::new(HashSet::from([at(0xe3), at(0xe4)]));
        let widening = Widening {
            state: Arc::new(state),
            profile: &FIXTURE_PROFILE,
            endpoints: (token, FIXTURE_USDT0),
            statics: statics.clone(),
            bases: statics,
            candidates: vec![vec![token, FIXTURE_WETH, resident_connector, FIXTURE_USDT0]],
            admitted: BTreeSet::new(),
            left_out: 0,
            thin_left_out: 0,
            thin_kept: false,
        };
        let admitted = BTreeSet::from([resident_connector]);
        let graph = widening.graph(&admitted).unwrap();
        let pools: HashSet<Address> = graph
            .snapshot
            .v3
            .iter()
            .map(|(pool, _)| pool.address)
            .collect();
        assert_eq!(pools, HashSet::from([at(0xe1), at(0xe2), at(0xe4)]));
        assert!(graph.thin_kept);
        assert_eq!(graph.thin_left_out, 1);
        // With every pool kept, the full graph is the same skeleton.
        let full = widening.graph_with_thin(&admitted).unwrap();
        assert_eq!(full.snapshot.v3.len(), 4);
        assert_eq!(full.universe.token_paths(), graph.universe.token_paths());
    }

    fn settings(connectors: Vec<Address>) -> Settings {
        Settings {
            list_url: "http://127.0.0.1:1/pools".to_string(),
            poll: Duration::from_millis(1_000),
            connectors,
            full_read: None,
        }
    }

    fn resident(statics: Vec<Address>) -> Arc<Resident> {
        resident_with(statics, Vec::new())
    }

    fn resident_with(statics: Vec<Address>, others: Vec<Address>) -> Arc<Resident> {
        let rpc = Rpc::connect("http://127.0.0.1:1").unwrap();
        Resident::with_connectors(&FIXTURE_PROFILE, rpc, settings(Vec::new()), statics, others)
            .unwrap()
    }

    /// Sorted by pair and address, as the reader keeps its list.
    fn sample() -> Snapshot {
        let mut v3_pools = vec![
            v3(Address::repeat_byte(0xa1), FIXTURE_WETH, FIXTURE_USDT0, 10),
            v3(Address::repeat_byte(0xa2), T1, FIXTURE_WETH, 60),
            v3(Address::repeat_byte(0xc1), FIXTURE_WETH, FIXTURE_USDT0, 200),
            v3(Address::repeat_byte(0xc3), T1, FIXTURE_WETH, 200),
        ];
        v3_pools.sort_by_key(|(pool, _)| (pool.token0, pool.token1, pool.address));
        Snapshot {
            block: 7,
            settler: Some(Address::repeat_byte(0x5e)),
            v3: v3_pools,
            v2: vec![v2(Address::repeat_byte(0xb1), T2, FIXTURE_USDT0)],
            ekubo: Vec::new(),
        }
    }

    #[test]
    fn resident_state_is_off_unless_configured() {
        let parse = |mode, poll, url, connectors| {
            Settings::parse(&FIXTURE_PROFILE, mode, poll, url, connectors, "")
        };
        assert!(parse("", "", "", "").unwrap().is_none());
        assert!(
            parse("off", "", "http://127.0.0.1:9/pools", "")
                .unwrap()
                .is_none()
        );
        assert!(parse("on", "", "", "").is_err(), "on needs a list");
        assert!(parse("yes", "", "", "").is_err());
        assert!(parse("on", "100", "http://127.0.0.1:9/pools", "").is_err());
        assert!(parse("on", "", "ftp://list", "").is_err());
        assert!(parse("on", "", "http://127.0.0.1:9/pools", "0xnope").is_err());
        assert!(
            Settings::parse(
                &crate::chain::ROBINHOOD_PROFILE,
                "on",
                "",
                "http://127.0.0.1:9/pools",
                "",
                ""
            )
            .is_err(),
            "Robinhood's discovery has no venue table"
        );
        let tuned = parse(
            "on",
            "500",
            "http://127.0.0.1:9/pools",
            &format!(" {FIXTURE_USDC:#x} ,, "),
        )
        .unwrap()
        .unwrap();
        assert_eq!(tuned.poll, Duration::from_millis(500));
        assert_eq!(tuned.list_url, "http://127.0.0.1:9/pools");
        assert_eq!(tuned.connectors, vec![FIXTURE_USDC]);
        assert_eq!(tuned.full_read, Some(Duration::from_secs(60)));
    }

    #[test]
    fn whole_reads_are_spaced_by_the_full_read_interval_or_every_block() {
        let full_read = |value| {
            Settings::parse(
                &FIXTURE_PROFILE,
                "on",
                "",
                "http://127.0.0.1:9/pools",
                "",
                value,
            )
            .map(|settings| settings.unwrap().full_read)
        };
        assert_eq!(full_read("").unwrap(), Some(Duration::from_secs(60)));
        assert_eq!(full_read("0").unwrap(), None, "every block read whole");
        assert_eq!(
            full_read(" 250 ").unwrap(),
            Some(Duration::from_millis(250))
        );
        assert!(full_read("3600001").is_err());
        assert!(full_read("soon").is_err());
    }

    #[test]
    fn configured_connectors_join_the_profiles_own() {
        let rpc = Rpc::connect("http://127.0.0.1:1").unwrap();
        let resident = Resident::new(
            &FIXTURE_PROFILE,
            rpc,
            settings(vec![FIXTURE_USDC, FIXTURE_WETH]),
        )
        .unwrap();
        let mut expected = FIXTURE_PROFILE.connectors.to_vec();
        expected.push(FIXTURE_USDC);
        assert_eq!(
            resident.connectors(),
            expected.as_slice(),
            "a static one is not repeated"
        );
        let many = |count: u8| {
            Resident::with_connectors(
                &FIXTURE_PROFILE,
                Rpc::connect("http://127.0.0.1:1").unwrap(),
                settings(Vec::new()),
                (1..=count).map(Address::repeat_byte).collect(),
                vec![FIXTURE_USDC],
            )
        };
        assert!(many(7).is_ok(), "seven static connectors span 36 pairs");
        assert!(many(8).is_err(), "eight span 45");
    }

    #[test]
    fn a_pair_gets_its_route_graph_in_the_lists_order() {
        let state = State::new(sample(), block(7), &[], Instant::now());
        let universe =
            RouteUniverse::resident(&FIXTURE_PROFILE, &[FIXTURE_WETH], &[], T1, FIXTURE_USDT0)
                .unwrap();
        let subset = state.subset(&universe);
        let addresses: Vec<Address> = subset.v3.iter().map(|(pool, _)| pool.address).collect();
        let expected: Vec<Address> = sample().v3.iter().map(|(pool, _)| pool.address).collect();
        assert_eq!(
            addresses, expected,
            "every V3 pool is on the graph, in list order"
        );
        assert!(subset.v2.is_empty(), "T2/USDT0 is off this graph");
        assert_eq!(subset.settler, Some(Address::repeat_byte(0x5e)));
        assert!(routable(&subset, &universe));
    }

    #[tokio::test]
    async fn a_quote_reads_the_resident_state_only_when_it_covers_and_routes_the_pair() {
        let resident = resident(vec![FIXTURE_WETH, FIXTURE_USDT0]);
        assert!(
            resident.stamped_for(T1, FIXTURE_USDT0, 0).await.is_none(),
            "nothing published"
        );
        resident.publish_for_test(sample(), block(7), Instant::now());

        let stamped = resident
            .stamped_for(FIXTURE_USDT0, T1, 0)
            .await
            .expect("covered");
        assert_eq!(stamped.snap.block, 7);
        assert_eq!(stamped.rpc_calls(), 0);
        assert!(stamped.universe.is_resident());
        assert_eq!(stamped.universe.endpoints(), canonical(T1, FIXTURE_USDT0));
        assert_eq!(stamped.block_id().as_block_hash(), Some(block(7).hash));

        // T2 trades only against USDT0; T1 only against WETH. Through WETH
        // and USDT0 they connect.
        assert!(resident.stamped_for(T1, T2, 0).await.is_some());
        // A token no listed pool trades goes to the per-pair path.
        let unknown = Address::repeat_byte(0x77);
        assert!(
            resident
                .stamped_for(unknown, FIXTURE_WETH, 0)
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn a_covered_pair_without_a_complete_skeleton_goes_to_the_per_pair_path() {
        // No connectors: T1 and T2 have no direct pool.
        let resident = resident(Vec::new());
        resident.publish_for_test(sample(), block(7), Instant::now());
        assert!(resident.stamped_for(T1, T2, 0).await.is_none());
        assert!(resident.stamped_for(T1, FIXTURE_WETH, 0).await.is_some());
    }

    #[tokio::test]
    async fn a_resident_connector_waits_beside_the_static_graph_until_admitted() {
        // USDC trades against WETH and USDT0.
        let mut snapshot = sample();
        for (pool, token) in [(0xa4, FIXTURE_WETH), (0xa5, FIXTURE_USDT0)] {
            snapshot
                .v3
                .push(v3(Address::repeat_byte(pool), token, FIXTURE_USDC, 10));
        }
        let rpc = Rpc::connect("http://127.0.0.1:1").unwrap();
        let resident = Resident::new(&FIXTURE_PROFILE, rpc, settings(vec![FIXTURE_USDC])).unwrap();
        resident.publish_for_test(snapshot, block(7), Instant::now());
        let stamped = resident
            .stamped_for(FIXTURE_WETH, FIXTURE_USDT0, 0)
            .await
            .expect("served from here");
        assert_eq!(
            canonical(FIXTURE_WETH, FIXTURE_USDT0),
            (FIXTURE_WETH, FIXTURE_USDT0)
        );
        let pools = |snapshot: &Snapshot| -> HashSet<Address> {
            snapshot.v3.iter().map(|(pool, _)| pool.address).collect()
        };
        // The quote starts from the static graph; USDC is a candidate.
        let through_usdc = vec![FIXTURE_WETH, FIXTURE_USDC, FIXTURE_USDT0];
        assert!(!stamped.universe.token_paths().contains(&through_usdc));
        assert!(stamped.universe.listed_connectors().is_empty());
        assert!(!pools(&stamped.snap).contains(&Address::repeat_byte(0xa4)));
        let widening = stamped.widening.as_deref().expect("a resident stamp");
        assert_eq!(widening.connectors(), vec![FIXTURE_USDC]);
        assert!(widening.admitted().is_empty());
        // Admitted, it is routed.
        let wide = widening
            .graph(&BTreeSet::from([FIXTURE_USDC]))
            .expect("the wider graph");
        assert!(wide.universe.token_paths().contains(&through_usdc));
        assert_eq!(wide.universe.listed_connectors(), vec![FIXTURE_USDC]);
        for pool in [0xa4, 0xa5] {
            assert!(pools(&wide.snapshot).contains(&Address::repeat_byte(pool)));
        }
        assert_eq!(wide.left_out, 0);
        // Its fingerprint is not the narrow graph's: a plan solved on one is
        // never certified against the other.
        assert_ne!(wide.universe.fingerprint(), stamped.universe.fingerprint());
        // The per-pair path, with only the profile's connectors, takes USDC
        // where the list has its pools.
        assert_eq!(
            resident.listed_paths(FIXTURE_PROFILE.connectors, FIXTURE_WETH, FIXTURE_USDT0),
            vec![through_usdc]
        );
    }

    #[tokio::test]
    async fn a_skeleton_through_two_candidates_is_routed_once_both_are_admitted() {
        // R1 trades against WETH and R2; R2 against R1 and USDT0.
        let (r1, r2) = (Address::repeat_byte(0x41), Address::repeat_byte(0x42));
        let mut snapshot = sample();
        for (pool, a, b) in [
            (0xa6, FIXTURE_WETH, r1),
            (0xa7, r1, r2),
            (0xa8, r2, FIXTURE_USDT0),
        ] {
            snapshot.v3.push(v3(Address::repeat_byte(pool), a, b, 10));
        }
        let resident = resident_with(vec![FIXTURE_WETH, FIXTURE_USDT0], vec![r1, r2]);
        resident.publish_for_test(snapshot, block(7), Instant::now());
        let stamped = resident
            .stamped_for(FIXTURE_WETH, FIXTURE_USDT0, 0)
            .await
            .expect("served from here");
        let widening = stamped.widening.as_deref().expect("a resident stamp");
        assert_eq!(widening.connectors(), vec![r1, r2]);
        let through = vec![FIXTURE_WETH, r1, r2, FIXTURE_USDT0];
        let alone = widening.graph(&BTreeSet::from([r1])).unwrap();
        assert!(!alone.universe.token_paths().contains(&through));
        let both = widening.graph(&BTreeSet::from([r1, r2])).unwrap();
        assert!(both.universe.token_paths().contains(&through));
    }

    #[tokio::test]
    async fn state_older_than_the_freshness_bound_is_not_served() {
        let resident = resident(vec![FIXTURE_WETH]);
        resident.publish_for_test(
            sample(),
            block(7),
            Instant::now() - STALE - Duration::from_millis(1),
        );
        assert!(resident.stamped_for(T1, FIXTURE_WETH, 0).await.is_none());
        // A head check that finds the block still the head makes it fresh.
        let state = resident.current.load_full().unwrap();
        state.confirm(Instant::now() - STALE * 3);
        assert!(
            resident.stamped_for(T1, FIXTURE_WETH, 0).await.is_none(),
            "never moves back"
        );
        state.confirm(Instant::now());
        assert!(resident.stamped_for(T1, FIXTURE_WETH, 0).await.is_some());
    }

    #[tokio::test]
    async fn chain_time_runs_from_the_first_read_of_the_block() {
        let resident = resident(vec![FIXTURE_WETH]);
        // Read 30 s ago and confirmed at every head check since: the chain is
        // 30 s past the block's timestamp, however recent the confirmation.
        resident.publish_for_test(sample(), block(7), Instant::now() - Duration::from_secs(30));
        resident
            .current
            .load_full()
            .unwrap()
            .confirm(Instant::now());
        let stamped = resident.stamped_for(T1, FIXTURE_WETH, 0).await.unwrap();
        assert!(stamped.is_fresh());
        assert_eq!(stamped.chain_now(), 1_007 + 30);
    }

    #[tokio::test(start_paused = true)]
    async fn a_later_block_is_waited_for_then_left_to_the_per_pair_path() {
        let resident = resident(vec![FIXTURE_WETH]);
        resident.publish_for_test(sample(), block(7), Instant::now());
        let waiter = {
            let resident = resident.clone();
            tokio::spawn(async move {
                resident
                    .stamped_for(T1, FIXTURE_WETH, 8)
                    .await
                    .map(|s| s.snap.block)
            })
        };
        tokio::task::yield_now().await;
        let mut next = sample();
        next.block = 8;
        resident.publish_for_test(next, block(8), Instant::now());
        assert_eq!(waiter.await.unwrap(), Some(8));
        let late = resident.stamped_for(T1, FIXTURE_WETH, 9);
        assert!(late.await.is_none(), "no block 9 within the wait");
    }

    #[test]
    fn counts_split_the_published_pools_by_family() {
        assert_eq!(PoolCounts::of(&sample()), PoolCounts { v3: 4, v2: 1 });
    }

    #[test]
    fn listed_skeletons_run_through_resident_connectors_only() {
        let (r, token, other) = (
            Address::repeat_byte(0x4e),
            Address::repeat_byte(0xaa),
            Address::repeat_byte(0xbb),
        );
        let statics = [FIXTURE_WETH, FIXTURE_USDT0];
        let graph = ListedGraph::new(
            [
                (FIXTURE_WETH, r),
                (FIXTURE_USDT0, r),
                (token, r),
                (FIXTURE_WETH, FIXTURE_USDT0),
                (other, FIXTURE_WETH),
            ],
            &[FIXTURE_WETH, FIXTURE_USDT0, r],
        );
        assert_eq!(
            graph.paths(&statics, FIXTURE_WETH, FIXTURE_USDT0),
            vec![vec![FIXTURE_WETH, r, FIXTURE_USDT0]]
        );
        let mut through_r = graph.paths(&statics, token, other);
        through_r.sort();
        let mut expected = vec![
            vec![token, r, FIXTURE_USDT0, other],
            vec![token, r, FIXTURE_WETH, other],
        ];
        expected.sort();
        assert_eq!(
            through_r, expected,
            "the static connector's pool with the far endpoint is left to the snapshot"
        );
        assert!(
            graph.paths(&statics, r, FIXTURE_USDT0).is_empty(),
            "an endpoint is not its own connector"
        );
        for (a, b) in [
            (token, FIXTURE_USDT0),
            (token, other),
            (FIXTURE_WETH, FIXTURE_USDT0),
        ] {
            let forward = graph.paths(&statics, a, b);
            let backward: Vec<Vec<Address>> = graph
                .paths(&statics, b, a)
                .into_iter()
                .map(|mut path| {
                    path.reverse();
                    path
                })
                .collect();
            assert_eq!(
                forward, backward,
                "a pair and its reverse get the same skeletons"
            );
        }
    }

    async fn serve_list(body: Value) -> (String, tokio::task::JoinHandle<()>) {
        let app = Router::new().route(
            "/pools",
            get(move || {
                let body = body.clone();
                async move { axum::Json(body) }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{address}/pools"), server)
    }

    fn row(address: Address, protocol: &str, fee: u64, token0: Address, token1: Address) -> Value {
        json!({
            "protocol": protocol,
            "address": format!("{address:#x}"),
            "token0": format!("{token0:#x}"),
            "token1": format!("{token1:#x}"),
            "feePpm": fee,
        })
    }

    #[tokio::test]
    async fn the_list_is_read_whole() {
        let (a, b) = (Address::repeat_byte(0x0a), Address::repeat_byte(0x0b));
        let (url, server) = serve_list(json!([
            row(Address::repeat_byte(0x31), "univ3", 500, a, b),
            row(Address::repeat_byte(0x32), "pancakev2", 2_500, a, b),
        ]))
        .await;
        let rows = fetch_list(reqwest::Client::new(), url).await.unwrap();
        server.abort();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].protocol, CatalogProtocol::UNIV3);
        assert_eq!(rows[0].fee_ppm, 500);
        assert_eq!(rows[1].protocol, CatalogProtocol::PANCAKEV2);
        assert_eq!((rows[1].token0, rows[1].token1), (a, b));
    }

    #[tokio::test]
    async fn a_bad_list_is_refused_whole() {
        let (a, b) = (Address::repeat_byte(0x0a), Address::repeat_byte(0x0b));
        let good = row(Address::repeat_byte(0x31), "univ3", 500, a, b);
        for (body, expected) in [
            (json!({"pools": []}), "not a JSON array"),
            (json!([]), "is empty"),
            (json!([good.clone(), good.clone()]), "twice"),
            (
                json!([
                    good.clone(),
                    row(Address::repeat_byte(0x33), "univ4", 500, a, b)
                ]),
                "not an address-pool protocol",
            ),
            (
                json!([
                    good.clone(),
                    row(Address::repeat_byte(0x34), "univ3", 1_000_000, a, b)
                ]),
                "feePpm",
            ),
            (json!([{"protocol": "univ3", "address": "nope"}]), "row 0"),
        ] {
            let (url, server) = serve_list(body).await;
            let error = fetch_list(reqwest::Client::new(), url).await.unwrap_err();
            server.abort();
            assert!(format!("{error:#}").contains(expected), "{error:#}");
        }
    }
}
