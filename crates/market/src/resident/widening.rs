use super::State;
use super::graph::{Venue, canonical, edges, routable};
use crate::chain::ChainProfile;
use crate::snapshot::Snapshot;
use crate::universe::RouteUniverse;
use alloy::eips::BlockId;
use alloy_primitives::{Address, U256};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::Arc;
use std::time::Instant;

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
    pub(super) state: Arc<State>,
    pub(super) profile: &'static ChainProfile,
    pub(super) endpoints: (Address, Address),
    pub(super) statics: Vec<Address>,
    /// Every connector, static or resident: a pool between one of these and
    /// another token is that token's market.
    pub(super) bases: Vec<Address>,
    /// In `endpoints`' direction, ordered by `path_order`.
    pub(super) candidates: Vec<Vec<Address>>,
    /// What the quote starts from.
    pub(super) admitted: BTreeSet<Address>,
    /// Admitted skeletons the starting graph left out.
    pub(super) left_out: usize,
    /// The starting graph's thin pools left out, and whether it kept them.
    pub(super) thin_left_out: usize,
    pub(super) thin_kept: bool,
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
