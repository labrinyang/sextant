use crate::pools::{V3Pool, V3State};
use crate::snapshot::Snapshot;
use crate::universe::RouteUniverse;
use alloy_primitives::{Address, U256};
use std::collections::{BTreeSet, HashMap, HashSet};

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

/// A pool a probe may cross, in the state the probe sees.
pub(super) enum Venue<'a> {
    V3(&'a V3Pool, &'a V3State),
    V2(&'a crate::pools::V2Pool, &'a crate::pools::V2State),
}

impl Venue<'_> {
    pub(super) fn address(&self) -> Address {
        match self {
            Self::V3(pool, _) => pool.address,
            Self::V2(pool, _) => pool.address,
        }
    }

    pub(super) fn tokens(&self) -> (Address, Address) {
        match self {
            Self::V3(pool, _) => (pool.token0, pool.token1),
            Self::V2(pool, _) => (pool.token0, pool.token1),
        }
    }

    /// What selling `amount` of `token` here delivers, if the pool fills it
    /// whole.
    pub(super) fn out(&self, token: Address, amount: U256) -> Option<U256> {
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

pub(super) fn canonical(a: Address, b: Address) -> (Address, Address) {
    if a <= b { (a, b) } else { (b, a) }
}

/// The token pairs `snapshot` has a V3, CL or V2 pool on.
pub(super) fn edges(snapshot: &Snapshot) -> HashSet<(Address, Address)> {
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
pub(super) fn routable(snapshot: &Snapshot, universe: &RouteUniverse) -> bool {
    let present = edges(snapshot);
    universe.token_paths().iter().any(|path| {
        path.windows(2)
            .all(|edge| present.contains(&canonical(edge[0], edge[1])))
    })
}
