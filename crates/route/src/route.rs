// Routing: path enumeration + optimal split.
//
// Splitting uses marginal-greedy chunk allocation on the exact pool simulators,
// followed by 1bp polishing on the executable objective. Shared pools interact
// through shared working state; the final plan is re-simulated sequentially in
// leg order — exactly how the Settler executes actions — and those numbers are
// the quote.

use crate::budget::SolverBudget;
use crate::chain::{ChainProfile, MAX_ROUTE_HOPS};
#[cfg(any(test, feature = "testing"))]
use crate::chain::{ROBINHOOD_PROFILE, route_token_paths};
use crate::ekubo::{EkuboSim, EkuboState, commit_ekubo, sim_ekubo};
use crate::pools::{
    V2Sim, V2State, V3Protocol, V3Sim, V3State, commit_v2, commit_v3, sim_v2, sim_v3,
};
use crate::snapshot::Snapshot;
use crate::universe::RouteUniverse;
use crate::v3math::muldiv;
use alloy_primitives::{Address, B256, U256};
use anyhow::{Context, bail, ensure};
use std::sync::LazyLock;

fn parse_bounded_u32_setting(
    key: &str,
    value: Option<&str>,
    default: u32,
    min: u32,
    max: u32,
) -> anyhow::Result<u32> {
    let value = match value {
        Some(value) => value
            .parse()
            .with_context(|| format!("{key} must be an unsigned 32-bit integer")),
        None => Ok(default),
    }?;
    ensure!(
        (min..=max).contains(&value),
        "{key} must be in {min}..={max}, got {value}"
    );
    Ok(value)
}

fn read_bounded_u32(key: &str, default: u32, min: u32, max: u32) -> anyhow::Result<u32> {
    match std::env::var(key) {
        Ok(value) => parse_bounded_u32_setting(key, Some(&value), default, min, max),
        Err(std::env::VarError::NotPresent) => {
            parse_bounded_u32_setting(key, None, default, min, max)
        }
        Err(error) => bail!("{key} is not valid Unicode: {error}"),
    }
}

fn parse_bool_setting(key: &str, value: Option<&str>, default: bool) -> anyhow::Result<bool> {
    match value {
        None => Ok(default),
        Some("0") => Ok(false),
        Some("1") => Ok(true),
        Some(value) => bail!("{key} must be 0 or 1, got {value:?}"),
    }
}

/// Greedy allocation granularity: the input is split into this many balanced
/// integer chunks (sizes differ by at most one). The greedy pass only has to
/// find the right SHAPE (which paths, roughly what share) — polish_plan then
/// refines the split to 1bp
/// resolution on the exact execution objective. SOLVER_ALLOC_CHUNKS.
/// 256 measured ≈+5bps over 64 on $900k trades (finer shape, more venues).
pub static ALLOC_CHUNKS: LazyLock<u32> =
    LazyLock::new(|| read_alloc_chunks().unwrap_or_else(|error| panic!("{error:#}")));
/// Legs below this share of the input are merged away — a leg's calldata/gas
/// overhead is not worth this fraction of the trade. Gas here is L2-cheap:
/// a 0.5% sliver that wins its marginal output beats the leg overhead on
/// any size where a sliver appears at all. SOLVER_MIN_SHARE_BPS.
pub static MIN_SHARE_BPS: LazyLock<u32> =
    LazyLock::new(|| read_min_share_bps().unwrap_or_else(|error| panic!("{error:#}")));

/// SOLVER_POLISH=0 disables the bps hill-climb — only for byte-parity replays
/// against the (pre-polish) Julia reference.
static POLISH: LazyLock<bool> =
    LazyLock::new(|| read_polish().unwrap_or_else(|error| panic!("{error:#}")));

/// `SOLVER_ALLOC_CHUNKS`, as a `Result` so startup can reject a typo without
/// tripping the `LazyLock`'s panic.
pub fn read_alloc_chunks() -> anyhow::Result<u32> {
    read_bounded_u32("SOLVER_ALLOC_CHUNKS", 256, 1, 4096)
}

/// `SOLVER_MIN_SHARE_BPS`, as a `Result` for startup validation.
pub fn read_min_share_bps() -> anyhow::Result<u32> {
    read_bounded_u32("SOLVER_MIN_SHARE_BPS", 50, 0, BPS_BASE)
}

/// `SOLVER_POLISH`, as a `Result` for startup validation.
pub fn read_polish() -> anyhow::Result<bool> {
    match std::env::var("SOLVER_POLISH") {
        Ok(value) => parse_bool_setting("SOLVER_POLISH", Some(&value), true),
        Err(std::env::VarError::NotPresent) => Ok(true),
        Err(error) => bail!("SOLVER_POLISH is not valid Unicode: {error}"),
    }
}

// The three-hop search remains bounded: at each constant-size probe it keeps
// only this many paths per token skeleton, and at most this many prefixes per
// final pool. The resulting shortlist joins direct/two-hop paths in the split
// allocator.
const THREE_HOP_TOP_K_PER_PROBE: usize = 12;
const THREE_HOP_PREFIXES_PER_FINAL: usize = 2;
const THREE_HOP_PROBE_DIVISORS: [u32; 6] = [1, 2, 4, 8, 16, 64];
/// Legs one split plan may carry.
///
/// The greedy can fund one leg per chunk, and the cost of carrying them lands
/// in quantization and polish, which are quadratic in the leg count: measured
/// on identical parallel pools in a release build by
/// `route::tests::time_the_quantized_solve`, 64 legs 5.8 ms, 128 legs 22.3 ms,
/// 200 legs 54.2 ms — against a warm quote served in single-digit ms. Every
/// plan production has been observed to ship is well inside this, so the budget
/// binds only where 128 candidates are genuinely competitive.
///
/// This is the rule the minimum-share floor was standing in for, stated so that
/// it does not depend on how many candidates were offered. A share threshold
/// culls more as the candidate set grows, which is what made the allocator
/// non-monotone in its own universe
/// (`the maintainers' research notes` §4); a constant budget keeps
/// `min(K, live)` legs whatever is on the table.
const MAX_SPLIT_LEGS: usize = 128;
/// Maximum direct/two-hop candidates materialized for one quote topology.
/// Exceeding it is an explicit work-limit error rather than unbounded allocation.
///
/// Doubled from 16,384 on 2026-08-07, and the reason is a measurement rather
/// than a margin. `state::connectors::admit_dynamic_work_for_counts` charges every dynamic
/// connector `left × right` against this same budget after the static skeleton
/// has taken its share, and on BSC's WBNB→USDC the skeleton alone costs
/// **15,942 of 16,384** — two static connectors whose 2-hop legs carry ~150
/// pools each once V4 is in scope. That left 442, against candidates needing
/// 165 to 700 apiece, so the pair served **one** dynamic connector out of five
/// offered and the one it kept was simply the cheapest.
///
/// Measured at 32,768 on that pair, five paired rounds against the old binary
/// with the order alternated: five connectors instead of one, and the quote
/// **+1.55 bp median** (1.08 to 2.04, positive every round). Latency +47% on
/// that shape and unchanged elsewhere — the gate only binds where the skeleton
/// is already dear, so both the cost and the benefit land on the same pairs.
///
/// 32,768 rather than 65,536: the measured need is 15,942 plus about 2,200 of
/// connectors, so this covers it with room while halving the worst case a
/// larger ceiling would admit. A skeleton above the cap is still a hard error,
/// and WBNB→USDC sat at 97% of the old one — the headroom is also what keeps a
/// slightly deeper pair from failing outright.
pub const BASELINE_PATH_CANDIDATE_CAP: usize = 32_768;
/// Maximum transient labels materialized for one skeleton edge at one probe.
/// Exceeding it is an explicit work-limit error, never a quality-degrading
/// truncation.
const THREE_HOP_PREFIX_WORK_CAP: usize = 16_384;

pub use crate::plan::{BPS_BASE, Hop, HopKind, Leg, LossRatio, Plan};

pub fn hops_between(snap: &Snapshot, tin: Address, tout: Address) -> Vec<Hop> {
    let mut out = Vec::new();
    for (i, (p, _)) in snap.v3.iter().enumerate() {
        if p.token0 == tin && p.token1 == tout {
            out.push(Hop {
                kind: HopKind::V3,
                index: i,
                zero_for_one: true,
                token_in: tin,
                token_out: tout,
            });
        }
        if p.token0 == tout && p.token1 == tin {
            out.push(Hop {
                kind: HopKind::V3,
                index: i,
                zero_for_one: false,
                token_in: tin,
                token_out: tout,
            });
        }
    }
    for (i, (p, _)) in snap.v2.iter().enumerate() {
        if p.token0 == tin && p.token1 == tout {
            out.push(Hop {
                kind: HopKind::V2,
                index: i,
                zero_for_one: true,
                token_in: tin,
                token_out: tout,
            });
        }
        if p.token0 == tout && p.token1 == tin {
            out.push(Hop {
                kind: HopKind::V2,
                index: i,
                zero_for_one: false,
                token_in: tin,
                token_out: tout,
            });
        }
    }
    for (i, (p, _)) in snap.ekubo.iter().enumerate() {
        if p.token0 == tin && p.token1 == tout {
            out.push(Hop {
                kind: HopKind::Ekubo,
                index: i,
                zero_for_one: true,
                token_in: tin,
                token_out: tout,
            });
        }
        if p.token0 == tout && p.token1 == tin {
            out.push(Hop {
                kind: HopKind::Ekubo,
                index: i,
                zero_for_one: false,
                token_in: tin,
                token_out: tout,
            });
        }
    }
    out
}

#[cfg(any(test, feature = "testing"))]
fn append_path_product(
    edge_hops: &[Vec<Hop>],
    edge: usize,
    path: &mut Vec<Hop>,
    paths: &mut Vec<Vec<Hop>>,
) {
    if edge == edge_hops.len() {
        paths.push(path.clone());
        return;
    }
    for hop in &edge_hops[edge] {
        path.push(hop.clone());
        append_path_product(edge_hops, edge + 1, path, paths);
        path.pop();
    }
}

#[cfg(any(test, feature = "testing"))]
pub fn enumerate_paths(snap: &Snapshot, tin: Address, tout: Address) -> Vec<Vec<Hop>> {
    let mut paths = Vec::new();
    for tokens in route_token_paths(tin, tout)
        .into_iter()
        .filter(|tokens| tokens.len() <= 3)
    {
        let edge_hops: Vec<Vec<Hop>> = tokens
            .windows(2)
            .map(|edge| hops_between(snap, edge[0], edge[1]))
            .collect();
        if edge_hops.iter().any(Vec::is_empty) {
            continue;
        }
        let mut path = Vec::with_capacity(edge_hops.len());
        append_path_product(&edge_hops, 0, &mut path, &mut paths);
    }
    debug_assert!(paths.iter().all(|path| path.len() <= 2));
    paths
}

fn append_prepared_path_product(
    edge_hops: &[Vec<Hop>],
    edge_indices: &[usize],
    edge: usize,
    path: &mut Vec<Hop>,
    paths: &mut Vec<Vec<Hop>>,
    budget: &SolverBudget,
) -> anyhow::Result<()> {
    if edge == edge_indices.len() {
        if paths.len().is_multiple_of(64) {
            budget.checkpoint("baseline candidate generation")?;
        }
        paths.push(path.clone());
        return Ok(());
    }
    for hop in &edge_hops[edge_indices[edge]] {
        path.push(hop.clone());
        append_prepared_path_product(edge_hops, edge_indices, edge + 1, path, paths, budget)?;
        path.pop();
    }
    Ok(())
}

/// Snapshot-bound route topology shared by the full-size and fair-size solves.
/// Pool order and token-skeleton order remain identical to `hops_between` and
/// `route_token_paths`; only the repeated full-snapshot scans are removed.
pub struct PreparedRoutes<'a> {
    snap: &'a Snapshot,
    universe_id: B256,
    budget: SolverBudget,
    edge_hops: Vec<Vec<Hop>>,
    baseline_paths: Vec<Vec<Hop>>,
    three_hop_edges: Vec<[usize; MAX_ROUTE_HOPS]>,
}

struct CandidatePathSets {
    combined: Vec<Vec<Hop>>,
    three_hop: Vec<Vec<Hop>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SeedDemand {
    Overall,
    Single,
    /// Only tests ask for both at once.
    #[cfg(test)]
    Both,
}

/// Requested executable seeds. A winning single candidate shares the overall
/// plan rather than cloning its paths, amounts and losses a second time.
#[derive(Debug, Default)]
pub struct SeedBatch {
    overall: Option<Plan>,
    distinct_single: Option<Plan>,
    single_is_overall: bool,
}

impl SeedBatch {
    pub fn overall(&self) -> Option<&Plan> {
        self.overall.as_ref()
    }

    #[cfg(test)]
    pub fn single(&self) -> Option<&Plan> {
        if self.single_is_overall {
            self.overall()
        } else {
            self.distinct_single.as_ref()
        }
    }

    fn into_overall(self) -> Option<Plan> {
        self.overall
    }

    fn into_single(self) -> Option<Plan> {
        if self.single_is_overall {
            self.overall
        } else {
            self.distinct_single
        }
    }
}

struct SeedCandidates {
    plans: Vec<Plan>,
    /// The full-size best-single is last, after the ordered family alternatives.
    single_index: Option<usize>,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct RouteWorkCounts {
    path_generations: usize,
    single_scans: usize,
    split_allocations: usize,
    quantizations: usize,
}

#[cfg(test)]
thread_local! {
    static ROUTE_WORK_COUNTS: std::cell::Cell<RouteWorkCounts> = const {
        std::cell::Cell::new(RouteWorkCounts {
            path_generations: 0,
            single_scans: 0,
            split_allocations: 0,
            quantizations: 0,
        })
    };
}

#[cfg(test)]
fn record_route_work(update: impl FnOnce(&mut RouteWorkCounts)) {
    ROUTE_WORK_COUNTS.with(|counts| {
        let mut next = counts.get();
        update(&mut next);
        counts.set(next);
    });
}

impl<'a> PreparedRoutes<'a> {
    #[cfg(any(test, feature = "testing"))]
    pub fn new(snap: &'a Snapshot, tin: Address, tout: Address) -> anyhow::Result<Self> {
        let universe = RouteUniverse::profile_only(&ROBINHOOD_PROFILE, tin, tout)?;
        Self::for_universe(snap, &universe)
    }

    /// Build against the connector set belonging to the instance profile.
    /// Keeping the profile at this seam prevents a BSC request from silently
    /// routing through Robinhood's WETH/USDG/VIRTUAL constants.
    pub fn for_profile(
        snap: &'a Snapshot,
        profile: &ChainProfile,
        tin: Address,
        tout: Address,
    ) -> anyhow::Result<Self> {
        Self::for_profile_with_budget(snap, profile, tin, tout, SolverBudget::unlimited())
    }

    /// Build against the instance profile while retaining the request's
    /// cooperative cancellation/deadline budget. Optional composed-route work
    /// must use this constructor so it cannot continue after the parent quote
    /// has timed out.
    pub fn for_profile_with_budget(
        snap: &'a Snapshot,
        profile: &ChainProfile,
        tin: Address,
        tout: Address,
        budget: SolverBudget,
    ) -> anyhow::Result<Self> {
        let universe = RouteUniverse::profile_only(profile, tin, tout)?;
        Self::for_universe_with_budget(snap, &universe, budget)
    }

    pub fn for_universe(snap: &'a Snapshot, universe: &RouteUniverse) -> anyhow::Result<Self> {
        Self::for_universe_with_budget(snap, universe, SolverBudget::unlimited())
    }

    pub fn for_universe_with_budget(
        snap: &'a Snapshot,
        universe: &RouteUniverse,
        budget: SolverBudget,
    ) -> anyhow::Result<Self> {
        Self::from_token_paths(snap, universe.token_paths(), universe.fingerprint(), budget)
    }

    /// Build over an explicit path set and a snapshot that MAY contain pools no
    /// served quote can reach.
    ///
    /// Screened pools are kept unroutable by two independent exclusions — out of
    /// `Snapshot`, and out of `RouteUniverse::token_paths` — and this is the one
    /// seam that undoes both on purpose. It exists for `counterfactual`, which
    /// measures what those pools would have been worth and returns amounts; the
    /// `Plan` produced here never leaves that module. A second caller wanting
    /// this constructor is a caller removing the guarantee, and should be read
    /// that way in review.
    pub fn for_shadow_paths(
        snap: &'a Snapshot,
        token_paths: &[Vec<Address>],
        universe_id: B256,
        budget: SolverBudget,
    ) -> anyhow::Result<Self> {
        Self::from_token_paths(snap, token_paths, universe_id, budget)
    }

    fn from_token_paths(
        snap: &'a Snapshot,
        token_paths: &[Vec<Address>],
        universe_id: B256,
        budget: SolverBudget,
    ) -> anyhow::Result<Self> {
        Self::from_token_paths_filtered(snap, token_paths, universe_id, budget, |_| true)
    }

    fn from_token_paths_filtered(
        snap: &'a Snapshot,
        token_paths: &[Vec<Address>],
        universe_id: B256,
        budget: SolverBudget,
        accepts: impl Fn(&Hop) -> bool,
    ) -> anyhow::Result<Self> {
        budget.checkpoint("route topology preparation")?;
        // `RouteUniverse` refuses longer skeletons, but `for_shadow_paths`
        // takes its paths as given: a skeleton outside 1..=MAX_ROUTE_HOPS hops
        // is an error here, never a panic further down.
        for tokens in token_paths {
            ensure!(
                (2..=MAX_ROUTE_HOPS + 1).contains(&tokens.len()),
                "route skeleton has {} hops; at most {MAX_ROUTE_HOPS} are routed",
                tokens.len().saturating_sub(1)
            );
        }
        let mut edges = Vec::new();
        let mut edge_indices = std::collections::HashMap::new();
        for (path_index, tokens) in token_paths.iter().enumerate() {
            if path_index.is_multiple_of(64) {
                budget.checkpoint("route topology preparation")?;
            }
            for edge in tokens.windows(2) {
                let key = (edge[0], edge[1]);
                if let std::collections::hash_map::Entry::Vacant(entry) = edge_indices.entry(key) {
                    entry.insert(edges.len());
                    edges.push(key);
                }
            }
        }

        let mut edge_hops = vec![Vec::new(); edges.len()];
        for (index, (pool, _)) in snap.v3.iter().enumerate() {
            if index.is_multiple_of(64) {
                budget.checkpoint("route topology preparation")?;
            }
            for (key, zero_for_one) in [
                ((pool.token0, pool.token1), true),
                ((pool.token1, pool.token0), false),
            ] {
                let Some(&edge) = edge_indices.get(&key) else {
                    continue;
                };
                let hop = Hop {
                    kind: HopKind::V3,
                    index,
                    zero_for_one,
                    token_in: key.0,
                    token_out: key.1,
                };
                if accepts(&hop) {
                    edge_hops[edge].push(hop);
                }
            }
        }
        for (index, (pool, _)) in snap.v2.iter().enumerate() {
            if index.is_multiple_of(64) {
                budget.checkpoint("route topology preparation")?;
            }
            for (key, zero_for_one) in [
                ((pool.token0, pool.token1), true),
                ((pool.token1, pool.token0), false),
            ] {
                let Some(&edge) = edge_indices.get(&key) else {
                    continue;
                };
                let hop = Hop {
                    kind: HopKind::V2,
                    index,
                    zero_for_one,
                    token_in: key.0,
                    token_out: key.1,
                };
                if accepts(&hop) {
                    edge_hops[edge].push(hop);
                }
            }
        }
        for (index, (pool, _)) in snap.ekubo.iter().enumerate() {
            if index.is_multiple_of(64) {
                budget.checkpoint("route topology preparation")?;
            }
            for (key, zero_for_one) in [
                ((pool.token0, pool.token1), true),
                ((pool.token1, pool.token0), false),
            ] {
                let Some(&edge) = edge_indices.get(&key) else {
                    continue;
                };
                let hop = Hop {
                    kind: HopKind::Ekubo,
                    index,
                    zero_for_one,
                    token_in: key.0,
                    token_out: key.1,
                };
                if accepts(&hop) {
                    edge_hops[edge].push(hop);
                }
            }
        }

        let mut baseline_paths = Vec::new();
        let mut three_hop_edges = Vec::new();
        for (path_index, tokens) in token_paths.iter().enumerate() {
            if path_index.is_multiple_of(64) {
                budget.checkpoint("route candidate generation")?;
            }
            let indices: Vec<usize> = tokens
                .windows(2)
                .map(|edge| edge_indices[&(edge[0], edge[1])])
                .collect();
            if indices.iter().any(|&edge| edge_hops[edge].is_empty()) {
                continue;
            }
            match indices.len() {
                1 | 2 => {
                    let added = indices.iter().try_fold(1usize, |count, &edge| {
                        count
                            .checked_mul(edge_hops[edge].len())
                            .context("baseline route candidate count overflow")
                    })?;
                    let total = baseline_paths
                        .len()
                        .checked_add(added)
                        .context("baseline route candidate count overflow")?;
                    ensure!(
                        total <= BASELINE_PATH_CANDIDATE_CAP,
                        "baseline route candidate limit exceeded: {total} > {BASELINE_PATH_CANDIDATE_CAP}"
                    );
                    let mut path = Vec::with_capacity(indices.len());
                    append_prepared_path_product(
                        &edge_hops,
                        &indices,
                        0,
                        &mut path,
                        &mut baseline_paths,
                        &budget,
                    )?;
                }
                MAX_ROUTE_HOPS => {
                    three_hop_edges.push(
                        indices
                            .try_into()
                            .expect("three-hop skeleton has exactly three edges"),
                    );
                }
                hops => {
                    bail!("route skeleton has {hops} hops; at most {MAX_ROUTE_HOPS} are routed")
                }
            }
        }

        Ok(Self {
            snap,
            universe_id,
            budget,
            edge_hops,
            baseline_paths,
            three_hop_edges,
        })
    }

    fn candidate_path_sets(
        &self,
        amount_in: U256,
        chunks: u32,
    ) -> anyhow::Result<CandidatePathSets> {
        #[cfg(test)]
        record_route_work(|counts| counts.path_generations += 1);
        self.budget.checkpoint("route candidate generation")?;
        ensure!(amount_in > U256::ZERO, "amount must be positive");
        ensure!(chunks > 0, "allocation chunks must be positive");
        let three_hop = three_hop_candidates(self, amount_in, chunks)?;
        let mut combined = self.baseline_paths.clone();
        combined.extend(three_hop.iter().cloned());
        Ok(CandidatePathSets {
            combined,
            three_hop,
        })
    }

    fn candidate_plans(
        &self,
        amount_in: U256,
        chunks: u32,
        min_share_bps: u32,
    ) -> anyhow::Result<Vec<Plan>> {
        Ok(self
            .seed_candidates(amount_in, chunks, min_share_bps, SeedDemand::Overall)?
            .plans)
    }

    fn seed_candidates(
        &self,
        amount_in: U256,
        chunks: u32,
        min_share_bps: u32,
        demand: SeedDemand,
    ) -> anyhow::Result<SeedCandidates> {
        if demand == SeedDemand::Single {
            // Single-only callers must not pay for split allocation or its
            // unrelated min-share validation and checkpoint.
            let paths = self.candidate_path_sets(amount_in, chunks)?.combined;
            let mut plans = Vec::with_capacity(1);
            if let Some(mut plan) =
                best_single_plan_with_budget(self.snap, &paths, amount_in, &self.budget)?
            {
                plan.universe_id = Some(self.universe_id);
                plans.push(plan);
            }
            let single_index = (!plans.is_empty()).then_some(0);
            return Ok(SeedCandidates {
                plans,
                single_index,
            });
        }
        self.budget.checkpoint("route allocation")?;
        ensure!(min_share_bps <= BPS_BASE, "minimum share exceeds 10000 bps");
        let CandidatePathSets {
            combined,
            three_hop,
        } = self.candidate_path_sets(amount_in, chunks)?;
        if combined.is_empty() {
            return Ok(SeedCandidates {
                plans: Vec::new(),
                single_index: None,
            });
        }

        let mut plans = Vec::with_capacity(4);
        if let Some(plan) = best_split_plan_with_budget(
            self.snap,
            &combined,
            amount_in,
            chunks,
            min_share_bps,
            &self.budget,
        )? {
            plans.push(plan);
        }
        // Keep family-specific alternatives until after bps quantization. The
        // combined greedy shape can be best before rounding yet lose after the
        // Settler's sequential floor divisions.
        if !self.baseline_paths.is_empty()
            && !three_hop.is_empty()
            && let Some(plan) = best_split_plan_with_budget(
                self.snap,
                &self.baseline_paths,
                amount_in,
                chunks,
                min_share_bps,
                &self.budget,
            )?
        {
            plans.push(plan);
        }
        if three_hop.len() > 1
            && let Some(plan) = best_split_plan_with_budget(
                self.snap,
                &three_hop,
                amount_in,
                chunks,
                min_share_bps,
                &self.budget,
            )?
        {
            plans.push(plan);
        }
        let mut single_index = None;
        if let Some(plan) =
            best_single_plan_with_budget(self.snap, &combined, amount_in, &self.budget)?
        {
            single_index = Some(plans.len());
            plans.push(plan);
        }
        for plan in &mut plans {
            plan.universe_id = Some(self.universe_id);
        }
        Ok(SeedCandidates {
            plans,
            single_index,
        })
    }

    /// Candidate selection before Settler bps quantization. Capacity shortage
    /// is `None`; simulator and arithmetic failures remain errors.
    pub fn try_solve(
        &self,
        amount_in: U256,
        chunks: u32,
        min_share_bps: u32,
    ) -> anyhow::Result<Option<Plan>> {
        let mut best: Option<Plan> = None;
        for candidate in self.candidate_plans(amount_in, chunks, min_share_bps)? {
            if best
                .as_ref()
                .is_none_or(|current| candidate.amount_out > current.amount_out)
            {
                best = Some(candidate);
            }
        }
        Ok(best)
    }

    pub fn solve(&self, amount_in: U256, chunks: u32, min_share_bps: u32) -> anyhow::Result<Plan> {
        self.try_solve(amount_in, chunks, min_share_bps)?
            .with_context(|| {
                if self.baseline_paths.is_empty() && self.three_hop_edges.is_empty() {
                    "no pools found for this pair"
                } else {
                    "no route can absorb this amount within modeled depth"
                }
            })
    }

    /// Compare only executable, exactly re-simulated bps plans. Callers that
    /// build Settler calldata should use this instead of `solve` followed by a
    /// single `quantized_plan`, so one rounded-out candidate cannot hide a
    /// viable alternative.
    pub fn try_solve_quantized(
        &self,
        amount_in: U256,
        chunks: u32,
        min_share_bps: u32,
    ) -> anyhow::Result<Option<Plan>> {
        Ok(self
            .solve_seed_batch(amount_in, chunks, min_share_bps, SeedDemand::Overall)?
            .into_overall())
    }

    /// Generate one universe and quantize each ordered candidate once. Both
    /// keeps the full-size single seed even when a split wins overall.
    pub fn solve_seed_batch(
        &self,
        amount_in: U256,
        chunks: u32,
        min_share_bps: u32,
        demand: SeedDemand,
    ) -> anyhow::Result<SeedBatch> {
        let SeedCandidates {
            plans,
            single_index,
        } = self.seed_candidates(amount_in, chunks, min_share_bps, demand)?;
        let mut batch = SeedBatch::default();
        // A candidate can repeat an earlier one: the combined plan that
        // already contains the three-hop paths is often the same plan as the
        // baseline-only alternative. Quantization is the expensive step, so a
        // repeat reuses the earlier result (the plan is a pure function of
        // the candidate and the snapshot).
        let mut quantized_before: Vec<(Plan, Option<Plan>)> = Vec::new();
        for (index, candidate) in plans.into_iter().enumerate() {
            if demand != SeedDemand::Single {
                self.budget.checkpoint("route quantization")?;
            }
            let quantized = match quantized_before.iter().find(|(plan, _)| *plan == candidate) {
                Some((_, cached)) => cached.clone(),
                None => {
                    let quantized = try_quantized_plan_with_budget(
                        self.snap,
                        &candidate,
                        amount_in,
                        &self.budget,
                    )?;
                    quantized_before.push((candidate, quantized.clone()));
                    quantized
                }
            };
            let Some(quantized) = quantized else {
                continue;
            };
            let is_single = single_index == Some(index);
            let wins_overall = demand != SeedDemand::Single
                && batch
                    .overall()
                    .is_none_or(|best| quantized.amount_out > best.amount_out);
            if is_single && demand != SeedDemand::Overall {
                // The tagged single is last; a strict tie retains the earlier
                // overall candidate. Identical results can share storage.
                if wins_overall {
                    batch.overall = Some(quantized);
                    batch.single_is_overall = true;
                } else if batch.overall() == Some(&quantized) {
                    batch.single_is_overall = true;
                } else {
                    batch.distinct_single = Some(quantized);
                }
            } else if wins_overall {
                batch.overall = Some(quantized);
            }
        }
        Ok(batch)
    }

    /// Best executable single leg in this universe. Composed RFQ routes use a
    /// linear AMM stage in the v1 response schema; keeping that constraint here
    /// prevents a split-then-join plan from being serialized as if Native were
    /// called once per AMM leg.
    pub fn try_solve_single_quantized(
        &self,
        amount_in: U256,
        chunks: u32,
    ) -> anyhow::Result<Option<Plan>> {
        Ok(self
            .solve_seed_batch(amount_in, chunks, 0, SeedDemand::Single)?
            .into_single())
    }
}

#[cfg(test)]
fn best_quantized_candidate(
    snap: &Snapshot,
    candidates: impl IntoIterator<Item = Plan>,
    amount_in: U256,
) -> anyhow::Result<Option<Plan>> {
    best_quantized_candidate_with_budget(snap, candidates, amount_in, &SolverBudget::unlimited())
}

/// Re-evaluate a plan built for one snapshot against another that CONTAINS it.
///
/// A `Hop` indexes into `Snapshot::v3`/`v2`, so this is only meaningful when the
/// target snapshot extends the source by appending — which is exactly what
/// `counterfactual::shadow_snapshot` does, and why this is `pub(crate)` for that
/// module rather than public.
///
/// It exists so a coverage solve can be seeded with a plan that is already known
/// feasible, making the widened side monotone by construction rather than by
/// hoping the heuristic finds what it was handed
/// (`the maintainers' research notes` §7 fix C). The returned plan
/// carries `universe_id`, so a seeded winner is labelled by the universe it was
/// re-evaluated in rather than the one it came from.
pub fn requantize_plan_in(
    snap: &Snapshot,
    plan: &Plan,
    amount_in: U256,
    universe_id: Option<B256>,
    budget: &SolverBudget,
) -> anyhow::Result<Option<Plan>> {
    Ok(
        try_quantized_plan_with_budget(snap, plan, amount_in, budget)?.map(|mut seeded| {
            seeded.universe_id = universe_id;
            seeded
        }),
    )
}

#[cfg(test)]
fn best_quantized_candidate_with_budget(
    snap: &Snapshot,
    candidates: impl IntoIterator<Item = Plan>,
    amount_in: U256,
    budget: &SolverBudget,
) -> anyhow::Result<Option<Plan>> {
    let mut best: Option<Plan> = None;
    for candidate in candidates {
        budget.checkpoint("route quantization")?;
        let Some(candidate) = try_quantized_plan_with_budget(snap, &candidate, amount_in, budget)?
        else {
            continue;
        };
        if best
            .as_ref()
            .is_none_or(|current| candidate.amount_out > current.amount_out)
        {
            best = Some(candidate);
        }
    }
    Ok(best)
}

#[derive(Clone)]
struct PathLabel {
    path: Vec<Hop>,
    amount_out: U256,
}

#[derive(Clone)]
enum PathExtension {
    Positive(PathLabel),
    TooSmall,
    TooLarge,
}

fn extend_path_label(
    snap: &Snapshot,
    prefix: &PathLabel,
    hop: &Hop,
) -> anyhow::Result<PathExtension> {
    let pool_input = prefix.amount_out;
    let pool_output = match hop.kind {
        HopKind::V3 => {
            let result = sim_v3(
                &snap.v3[hop.index].0,
                &snap.v3[hop.index].1,
                hop.zero_for_one,
                pool_input,
            )?;
            if result.consumed != pool_input {
                return Ok(PathExtension::TooLarge);
            }
            result.amount_out
        }
        HopKind::V2 => {
            sim_v2(
                &snap.v2[hop.index].0,
                &snap.v2[hop.index].1,
                hop.zero_for_one,
                pool_input,
            )?
            .amount_out
        }
        HopKind::Ekubo => {
            let result = sim_ekubo(
                &snap.ekubo[hop.index].0,
                &snap.ekubo[hop.index].1,
                hop.zero_for_one,
                pool_input,
            )?;
            if result.consumed != pool_input {
                return Ok(PathExtension::TooLarge);
            }
            result.amount_out
        }
    };
    if pool_output.is_zero() {
        return Ok(PathExtension::TooSmall);
    }
    let mut path = prefix.path.clone();
    path.push(hop.clone());
    Ok(PathExtension::Positive(PathLabel {
        path,
        amount_out: pool_output,
    }))
}

fn cached_path_extension<'a>(
    snap: &Snapshot,
    prefixes: &[PathLabel],
    hop: &Hop,
    cache: &'a mut std::collections::HashMap<usize, PathExtension>,
    index: usize,
) -> anyhow::Result<&'a PathExtension> {
    match cache.entry(index) {
        std::collections::hash_map::Entry::Occupied(entry) => Ok(entry.into_mut()),
        std::collections::hash_map::Entry::Vacant(entry) => {
            Ok(entry.insert(extend_path_label(snap, &prefixes[index], hop)?))
        }
    }
}

/// Prefix labels are sorted by the amount entering the final edge. For one
/// final pool, exact integer simulation has a contiguous feasibility shape:
/// TooSmall -> Positive -> TooLarge. Two binary searches locate the positive
/// interval; only its best `limit` labels are materialized.
fn best_final_extensions(
    snap: &Snapshot,
    prefixes: &[PathLabel],
    hop: &Hop,
    limit: usize,
    budget: &SolverBudget,
) -> anyhow::Result<Vec<PathLabel>> {
    budget.checkpoint("three-hop candidate search")?;
    if prefixes.is_empty() || limit == 0 {
        return Ok(Vec::new());
    }
    let mut cache = std::collections::HashMap::new();
    let mut lo = 0usize;
    let mut hi = prefixes.len();
    while lo < hi {
        budget.checkpoint("three-hop candidate search")?;
        let mid = lo + (hi - lo) / 2;
        if matches!(
            cached_path_extension(snap, prefixes, hop, &mut cache, mid)?,
            PathExtension::TooSmall
        ) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    if lo == prefixes.len() {
        return Ok(Vec::new());
    }
    if !matches!(
        cached_path_extension(snap, prefixes, hop, &mut cache, lo)?,
        PathExtension::Positive(_)
    ) {
        return Ok(Vec::new());
    }

    let mut executable = lo;
    let mut upper = prefixes.len();
    while executable + 1 < upper {
        budget.checkpoint("three-hop candidate search")?;
        let mid = executable + (upper - executable) / 2;
        match cached_path_extension(snap, prefixes, hop, &mut cache, mid)? {
            PathExtension::Positive(_) => {
                executable = mid;
            }
            PathExtension::TooLarge => upper = mid,
            PathExtension::TooSmall => executable = mid,
        }
    }

    let mut best = Vec::with_capacity(limit);
    for index in (lo..=executable).rev() {
        budget.checkpoint("three-hop candidate search")?;
        match cached_path_extension(snap, prefixes, hop, &mut cache, index)? {
            PathExtension::Positive(label) => best.push(label.clone()),
            PathExtension::TooSmall => break,
            PathExtension::TooLarge => continue,
        }
        if best.len() == limit {
            break;
        }
    }
    Ok(best)
}

/// Top three-hop paths for one input probe. All labels are retained through the
/// second edge; each final pool uses logarithmic feasibility searches and emits
/// only a constant number of paths. For edge pool counts (m1, m2, m3), work is
/// O(m1*m2 + m3*(log(m1*m2) + Kfinal)), not cubic.
fn three_hop_candidates_at(
    prepared: &PreparedRoutes<'_>,
    amount_in: U256,
) -> anyhow::Result<Vec<PathLabel>> {
    prepared
        .budget
        .checkpoint("three-hop candidate generation")?;
    let snap = prepared.snap;
    let mut candidates = Vec::new();
    for edges in &prepared.three_hop_edges {
        prepared
            .budget
            .checkpoint("three-hop candidate generation")?;
        let mut skeleton_candidates = Vec::new();
        let last_hops = &prepared.edge_hops[edges[MAX_ROUTE_HOPS - 1]];
        let mut prefixes = vec![PathLabel {
            path: Vec::with_capacity(MAX_ROUTE_HOPS),
            amount_out: amount_in,
        }];
        for &edge in &edges[..MAX_ROUTE_HOPS - 1] {
            let hops = &prepared.edge_hops[edge];
            let extension_count = prefixes
                .len()
                .checked_mul(hops.len())
                .context("three-hop prefix count overflow")?;
            ensure!(
                extension_count <= THREE_HOP_PREFIX_WORK_CAP,
                "three-hop prefix work cap ({THREE_HOP_PREFIX_WORK_CAP}) exceeded"
            );
            let mut next = Vec::with_capacity(extension_count);
            for (prefix_index, prefix) in prefixes.iter().enumerate() {
                if prefix_index.is_multiple_of(64) {
                    prepared.budget.checkpoint("three-hop prefix expansion")?;
                }
                for hop in hops {
                    if let PathExtension::Positive(label) = extend_path_label(snap, prefix, hop)? {
                        next.push(label);
                    }
                }
            }
            prefixes = next;
            if prefixes.is_empty() {
                break;
            }
        }
        if prefixes.is_empty() {
            continue;
        }
        prefixes.sort_by_key(|prefix| prefix.amount_out);
        for hop in last_hops {
            skeleton_candidates.extend(best_final_extensions(
                snap,
                &prefixes,
                hop,
                THREE_HOP_PREFIXES_PER_FINAL,
                &prepared.budget,
            )?);
        }
        // Stable sorting retains deterministic pool enumeration for equal
        // outputs. Applying the quota per skeleton prevents one connector
        // ordering from hiding every candidate from another.
        skeleton_candidates.sort_by_key(|candidate| std::cmp::Reverse(candidate.amount_out));
        skeleton_candidates.truncate(THREE_HOP_TOP_K_PER_PROBE);
        candidates.extend(skeleton_candidates);
    }
    Ok(candidates)
}

fn push_unique_amount(amounts: &mut Vec<U256>, amount: U256) {
    if !amount.is_zero() && !amounts.contains(&amount) {
        amounts.push(amount);
    }
}

fn three_hop_probe_amounts(amount_in: U256, chunks: u32) -> anyhow::Result<Vec<U256>> {
    ensure!(chunks > 0, "allocation chunks must be positive");
    let mut amounts = Vec::with_capacity(THREE_HOP_PROBE_DIVISORS.len() + 2);
    for divisor in THREE_HOP_PROBE_DIVISORS {
        push_unique_amount(&mut amounts, amount_in / U256::from(divisor));
    }
    let effective_chunks = if amount_in >= U256::from(chunks) {
        chunks
    } else {
        1
    };
    let base = amount_in / U256::from(effective_chunks);
    let remainder = amount_in % U256::from(effective_chunks);
    push_unique_amount(&mut amounts, base);
    if !remainder.is_zero() {
        push_unique_amount(
            &mut amounts,
            base.checked_add(U256::ONE)
                .context("chunk amount overflow")?,
        );
    }
    Ok(amounts)
}

/// A constant number of probes each contributes a bounded global top-K. This
/// catches paths valuable only for a partial fill while preserving the existing
/// non-cubic search bound.
fn three_hop_candidates(
    prepared: &PreparedRoutes<'_>,
    amount_in: U256,
    chunks: u32,
) -> anyhow::Result<Vec<Vec<Hop>>> {
    let mut paths = Vec::new();
    for probe in three_hop_probe_amounts(amount_in, chunks)? {
        prepared.budget.checkpoint("three-hop probe search")?;
        for candidate in three_hop_candidates_at(prepared, probe)? {
            if !paths.iter().any(|path| path == &candidate.path) {
                paths.push(candidate.path);
            }
        }
    }
    debug_assert!(paths.iter().all(|path| path.len() == MAX_ROUTE_HOPS));
    Ok(paths)
}

// ---- simulation over working copies ----

#[derive(Clone, Debug)]
pub enum SimResult {
    V3(V3Sim),
    V2(V2Sim),
    Ekubo(EkuboSim),
}

pub type Update = (Hop, SimResult);

/// Push `amt` through `path` against the working states. Returns (out, updates);
/// out is zero when the path cannot absorb the full amount (a pool ran dry or
/// left its modeled tick window) — such a path must not be allocated more input,
/// otherwise the leftover would strand inside the Settler.
fn sim_path(
    snap: &Snapshot,
    v3s: &[V3State],
    v2s: &[V2State],
    ekubos: &[EkuboState],
    path: &[Hop],
    amt: U256,
) -> anyhow::Result<(U256, Vec<Update>)> {
    sim_path_recording(snap, &(v3s, v2s, ekubos), path, amt, None)
}

/// The pool states a path is simulated against, by snapshot index.
trait WorkingStates {
    fn v3(&self, index: usize) -> Option<&V3State>;
    fn v2(&self, index: usize) -> Option<&V2State>;
    fn ekubo(&self, index: usize) -> Option<&EkuboState>;
}

impl WorkingStates for (&[V3State], &[V2State], &[EkuboState]) {
    fn v3(&self, index: usize) -> Option<&V3State> {
        self.0.get(index)
    }

    fn v2(&self, index: usize) -> Option<&V2State> {
        self.1.get(index)
    }

    fn ekubo(&self, index: usize) -> Option<&EkuboState> {
        self.2.get(index)
    }
}

fn sim_path_recording(
    snap: &Snapshot,
    states: &impl WorkingStates,
    path: &[Hop],
    amt: U256,
    mut losses: Option<&mut Vec<LossRatio>>,
) -> anyhow::Result<(U256, Vec<Update>)> {
    let mut x = amt;
    let mut updates = Vec::with_capacity(path.len());
    for hop in path {
        let pool_input = x;
        let pool_output = match hop.kind {
            HopKind::V3 => {
                let (pool, _) = snap.v3.get(hop.index).with_context(|| {
                    format!("route hop references missing v3 pool index {}", hop.index)
                })?;
                let state = states.v3(hop.index).with_context(|| {
                    format!("route hop references missing v3 state index {}", hop.index)
                })?;
                let (expected_in, expected_out) = if hop.zero_for_one {
                    (pool.token0, pool.token1)
                } else {
                    (pool.token1, pool.token0)
                };
                ensure!(
                    (hop.token_in, hop.token_out) == (expected_in, expected_out),
                    "route hop tokens/direction do not match v3 pool at index {}",
                    hop.index
                );
                let r = sim_v3(pool, state, hop.zero_for_one, pool_input)?;
                if r.consumed != pool_input {
                    return Ok((U256::ZERO, updates));
                }
                if let Some(losses) = losses.as_mut()
                    && !r.fee_amount.is_zero()
                {
                    losses.push(LossRatio {
                        gross: pool_input,
                        net: pool_input - r.fee_amount,
                    });
                }
                let amount_out = r.amount_out;
                updates.push((hop.clone(), SimResult::V3(r)));
                amount_out
            }
            HopKind::V2 => {
                let (pool, _) = snap.v2.get(hop.index).with_context(|| {
                    format!("route hop references missing v2 pool index {}", hop.index)
                })?;
                let state = states.v2(hop.index).with_context(|| {
                    format!("route hop references missing v2 state index {}", hop.index)
                })?;
                let (expected_in, expected_out) = if hop.zero_for_one {
                    (pool.token0, pool.token1)
                } else {
                    (pool.token1, pool.token0)
                };
                ensure!(
                    (hop.token_in, hop.token_out) == (expected_in, expected_out),
                    "route hop tokens/direction do not match v2 pool at index {}",
                    hop.index
                );
                let r = sim_v2(pool, state, hop.zero_for_one, pool_input)?;
                let amount_out = r.amount_out;
                updates.push((hop.clone(), SimResult::V2(r)));
                amount_out
            }
            HopKind::Ekubo => {
                let (pool, _) = snap.ekubo.get(hop.index).with_context(|| {
                    format!(
                        "route hop references missing Ekubo pool index {}",
                        hop.index
                    )
                })?;
                let state = states.ekubo(hop.index).with_context(|| {
                    format!(
                        "route hop references missing Ekubo state index {}",
                        hop.index
                    )
                })?;
                let (expected_in, expected_out) = if hop.zero_for_one {
                    (pool.token0, pool.token1)
                } else {
                    (pool.token1, pool.token0)
                };
                ensure!(
                    (hop.token_in, hop.token_out) == (expected_in, expected_out),
                    "route hop tokens/direction do not match Ekubo pool at index {}",
                    hop.index
                );
                let r = sim_ekubo(pool, state, hop.zero_for_one, pool_input)?;
                if r.consumed != pool_input {
                    return Ok((U256::ZERO, updates));
                }
                if let Some((gross, net)) = r.fee_loss
                    && let Some(losses) = losses.as_mut()
                {
                    losses.push(LossRatio { gross, net });
                }
                let amount_out = r.amount_out;
                updates.push((hop.clone(), SimResult::Ekubo(r)));
                amount_out
            }
        };
        x = pool_output;
        if x.is_zero() {
            return Ok((U256::ZERO, updates));
        }
    }
    Ok((x, updates))
}

fn commit_updates(
    v3s: &mut [V3State],
    v2s: &mut [V2State],
    ekubos: &mut [EkuboState],
    updates: &[Update],
) {
    for (hop, r) in updates {
        match r {
            SimResult::V3(r) => commit_v3(&mut v3s[hop.index], r),
            SimResult::V2(r) => commit_v2(&mut v2s[hop.index], r),
            SimResult::Ekubo(r) => commit_ekubo(&mut ekubos[hop.index], r),
        }
    }
}

/// Pool states after a plan executes, in snapshot index order.
pub struct PlanStates {
    pub v3: Vec<V3State>,
    pub v2: Vec<V2State>,
    pub ekubo: Vec<EkuboState>,
    /// Input each constant-product pool absorbed, by direction
    /// (`[token0 sold, token1 sold]`). A v2 fee stays in the reserves, so the
    /// slope of its swap curve depends on the trade size that produced the
    /// state — see `certificate::marginal_v2`.
    pub v2_input: Vec<[U256; 2]>,
}

/// Replay `plan` against the snapshot and keep what it did to every pool.
///
/// The certificate reads its dual point off these: weak duality is tight at
/// POST-trade marginal prices, so a bound built from the snapshot's untouched
/// prices would be loose by the whole price impact. Legs replay in plan order —
/// the order the Settler runs them — so shared pools compose exactly as they
/// did when the plan was priced.
pub fn plan_states(snap: &Snapshot, plan: &Plan) -> anyhow::Result<PlanStates> {
    let (mut v3s, mut v2s, mut ekubos) = working_states(snap);
    let mut v2_input = vec![[U256::ZERO; 2]; snap.v2.len()];
    let mut replayed_total = U256::ZERO;
    for leg in &plan.legs {
        ensure!(!leg.path.is_empty(), "plan contains an empty leg");
        ensure!(!leg.amount_in.is_zero(), "plan contains a zero-input leg");
        let (replayed_out, updates) =
            sim_path(snap, &v3s, &v2s, &ekubos, &leg.path, leg.amount_in)?;
        ensure!(
            updates.len() == leg.path.len() && !replayed_out.is_zero(),
            "plan leg is not fully executable against its snapshot"
        );
        ensure!(
            replayed_out == leg.amount_out,
            "plan leg output does not match exact snapshot replay"
        );
        replayed_total = replayed_total
            .checked_add(replayed_out)
            .context("plan replay output overflow")?;
        for (hop, result) in &updates {
            if let SimResult::V2(sim) = result {
                let before = v2s.get(hop.index).with_context(|| {
                    format!(
                        "plan replay references missing v2 state index {}",
                        hop.index
                    )
                })?;
                let (side, spent) = if hop.zero_for_one {
                    (0, sim.reserve0.saturating_sub(before.reserve0))
                } else {
                    (1, sim.reserve1.saturating_sub(before.reserve1))
                };
                let input = v2_input.get_mut(hop.index).with_context(|| {
                    format!(
                        "plan replay references missing v2 input index {}",
                        hop.index
                    )
                })?;
                input[side] = input[side]
                    .checked_add(spent)
                    .context("plan replay v2 input overflow")?;
            }
        }
        commit_updates(&mut v3s, &mut v2s, &mut ekubos, &updates);
    }
    ensure!(
        replayed_total == plan.amount_out,
        "plan output does not match exact snapshot replay"
    );
    Ok(PlanStates {
        v3: v3s,
        v2: v2s,
        ekubo: ekubos,
        v2_input,
    })
}

fn working_states(snap: &Snapshot) -> (Vec<V3State>, Vec<V2State>, Vec<EkuboState>) {
    (
        snap.v3.iter().map(|(_, s)| s.clone()).collect(),
        snap.v2.iter().map(|(_, s)| s.clone()).collect(),
        snap.ekubo.iter().map(|(_, s)| *s).collect(),
    )
}

fn balanced_chunk_amounts(amount_in: U256, chunks: u32) -> anyhow::Result<Vec<U256>> {
    ensure!(chunks > 0, "allocation chunks must be positive");
    ensure!(
        amount_in >= U256::from(chunks),
        "chunk count exceeds input amount"
    );
    let divisor = U256::from(chunks);
    let base = amount_in / divisor;
    let remainder =
        usize::try_from(amount_in % divisor).context("chunk remainder does not fit usize")?;
    let large = base
        .checked_add(U256::ONE)
        .context("chunk amount overflow")?;
    let mut amounts = Vec::with_capacity(chunks as usize);
    amounts.extend(std::iter::repeat_n(large, remainder));
    amounts.extend(std::iter::repeat_n(base, chunks as usize - remainder));
    Ok(amounts)
}

fn has_bidirectional_pool_use(paths: &[Vec<Hop>]) -> bool {
    let mut directions = std::collections::HashMap::new();
    for hop in paths.iter().flatten() {
        let key = (hop.kind, hop.index);
        match directions.entry(key) {
            std::collections::hash_map::Entry::Occupied(entry)
                if *entry.get() != hop.zero_for_one =>
            {
                return true;
            }
            std::collections::hash_map::Entry::Occupied(_) => {}
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(hop.zero_for_one);
            }
        }
    }
    false
}

#[cfg(test)]
fn greedy_alloc(
    snap: &Snapshot,
    paths: &[Vec<Hop>],
    amount_in: U256,
    chunks: u32,
) -> anyhow::Result<Option<Vec<U256>>> {
    greedy_alloc_with_budget(snap, paths, amount_in, chunks, &SolverBudget::unlimited())
}

fn greedy_alloc_with_budget(
    snap: &Snapshot,
    paths: &[Vec<Hop>],
    amount_in: U256,
    chunks: u32,
    budget: &SolverBudget,
) -> anyhow::Result<Option<Vec<U256>>> {
    budget.checkpoint("route allocation")?;
    if has_bidirectional_pool_use(paths) {
        return greedy_alloc_full_scan_with_budget(snap, paths, amount_in, chunks, budget);
    }
    let (mut v3s, mut v2s, mut ekubos) = working_states(snap);
    let chunk_amounts = balanced_chunk_amounts(amount_in, chunks)?;
    let mut alloc = vec![U256::ZERO; paths.len()];

    // Lazy greedy (CELF-style): a path's chunk output only ever DECREASES as
    // other chunks commit when every shared pool has one flow direction.
    // Bidirectional path sets take the exact invalidation allocator above.
    // Cached outputs are upper bounds: re-evaluate the heap top until its full
    // (output, tie-break) key stays on top.
    let mut heap: std::collections::BinaryHeap<(U256, std::cmp::Reverse<usize>)> =
        std::collections::BinaryHeap::new();
    let mut candidate_amount = None;
    for amount in chunk_amounts {
        budget.checkpoint("route allocation")?;
        if candidate_amount != Some(amount) {
            heap.clear();
            candidate_amount = Some(amount);
            // The balanced schedule has at most one size transition. A path
            // dry for a base+1 chunk may revive for a base chunk.
            for (i, path) in paths.iter().enumerate() {
                if i.is_multiple_of(64) {
                    budget.checkpoint("route allocation")?;
                }
                let (out, _) = sim_path(snap, &v3s, &v2s, &ekubos, path, amount)?;
                if !out.is_zero() {
                    heap.push((out, std::cmp::Reverse(i)));
                }
            }
        }
        let mut rescans = 0usize;
        loop {
            if rescans.is_multiple_of(64) {
                budget.checkpoint("route allocation")?;
            }
            rescans += 1;
            let Some((_, std::cmp::Reverse(i))) = heap.pop() else {
                return Ok(None);
            };
            let (out, updates) = sim_path(snap, &v3s, &v2s, &ekubos, &paths[i], amount)?;
            if out.is_zero() {
                continue;
            }
            let key = (out, std::cmp::Reverse(i));
            heap.push(key);
            if heap.peek() == Some(&key) {
                commit_updates(&mut v3s, &mut v2s, &mut ekubos, &updates);
                alloc[i] += amount;
                break;
            }
        }
    }
    Ok(Some(alloc))
}

/// Opposite-direction paths can improve after a pool is moved back toward
/// their side, which breaks the lazy-greedy upper-bound invariant. Pool-state
/// dependency invalidation keeps exact candidate values: after committing one
/// chunk, every path sharing a changed pool is recomputed.
#[cfg(test)]
fn greedy_alloc_full_scan(
    snap: &Snapshot,
    paths: &[Vec<Hop>],
    amount_in: U256,
    chunks: u32,
) -> anyhow::Result<Option<Vec<U256>>> {
    greedy_alloc_full_scan_with_budget(snap, paths, amount_in, chunks, &SolverBudget::unlimited())
}

fn greedy_alloc_full_scan_with_budget(
    snap: &Snapshot,
    paths: &[Vec<Hop>],
    amount_in: U256,
    chunks: u32,
    budget: &SolverBudget,
) -> anyhow::Result<Option<Vec<U256>>> {
    budget.checkpoint("bidirectional route allocation")?;
    let (mut v3s, mut v2s, mut ekubos) = working_states(snap);
    let chunk_amounts = balanced_chunk_amounts(amount_in, chunks)?;
    let mut alloc = vec![U256::ZERO; paths.len()];
    let mut v3_users = vec![Vec::new(); snap.v3.len()];
    let mut v2_users = vec![Vec::new(); snap.v2.len()];
    let mut ekubo_users = vec![Vec::new(); snap.ekubo.len()];
    for (path_index, path) in paths.iter().enumerate() {
        for hop in path {
            let users = match hop.kind {
                HopKind::V3 => &mut v3_users[hop.index],
                HopKind::V2 => &mut v2_users[hop.index],
                HopKind::Ekubo => &mut ekubo_users[hop.index],
            };
            if users.last() != Some(&path_index) {
                users.push(path_index);
            }
        }
    }

    let evaluate_all = |v3s: &[V3State], v2s: &[V2State], ekubos: &[EkuboState], amount: U256| {
        let mut results = Vec::with_capacity(paths.len());
        for (path_index, path) in paths.iter().enumerate() {
            if path_index.is_multiple_of(64) {
                budget.checkpoint("bidirectional route allocation")?;
            }
            results.push(sim_path(snap, v3s, v2s, ekubos, path, amount)?);
        }
        Ok::<_, anyhow::Error>(results)
    };
    let mut candidate_amount = None;
    let mut candidates = Vec::new();

    for (k, &amount) in chunk_amounts.iter().enumerate() {
        budget.checkpoint("bidirectional route allocation")?;
        if candidate_amount != Some(amount) {
            candidates = evaluate_all(&v3s, &v2s, &ekubos, amount)?;
            candidate_amount = Some(amount);
        }
        let mut best = None;
        let mut best_out = U256::ZERO;
        for (i, (out, _)) in candidates.iter().enumerate() {
            if *out > best_out {
                (best, best_out) = (Some(i), *out);
            }
        }
        let Some(best) = best else {
            return Ok(None);
        };
        commit_updates(&mut v3s, &mut v2s, &mut ekubos, &candidates[best].1);
        alloc[best] += amount;

        let Some(&next_amount) = chunk_amounts.get(k + 1) else {
            continue;
        };
        if next_amount != amount {
            continue;
        }

        let mut affected = vec![false; paths.len()];
        for hop in &paths[best] {
            let users = match hop.kind {
                HopKind::V3 => &v3_users[hop.index],
                HopKind::V2 => &v2_users[hop.index],
                HopKind::Ekubo => &ekubo_users[hop.index],
            };
            for &path_index in users {
                affected[path_index] = true;
            }
        }
        for (path_index, changed) in affected.into_iter().enumerate() {
            if changed {
                if path_index.is_multiple_of(64) {
                    budget.checkpoint("bidirectional route allocation")?;
                }
                candidates[path_index] =
                    sim_path(snap, &v3s, &v2s, &ekubos, &paths[path_index], amount)?;
            }
        }
    }
    Ok(Some(alloc))
}

/// Sequential re-simulation preserving the given leg order.
///
/// The states are the snapshot's, overlaid with those of the pools the legs
/// so far traded in. The polish clones a checkpoint for every candidate it
/// tries, so a clone copies those few pools, not the whole graph.
#[derive(Clone)]
struct ReplayState<'a> {
    snap: &'a Snapshot,
    v3s: Vec<(usize, V3State)>,
    v2s: Vec<(usize, V2State)>,
    ekubos: Vec<(usize, EkuboState)>,
    used_sheriff: std::collections::HashSet<Address>,
    legs: Vec<Leg>,
    total: U256,
}

impl WorkingStates for ReplayState<'_> {
    fn v3(&self, index: usize) -> Option<&V3State> {
        match self.v3s.iter().find(|(at, _)| *at == index) {
            Some((_, state)) => Some(state),
            None => self.snap.v3.get(index).map(|(_, state)| state),
        }
    }

    fn v2(&self, index: usize) -> Option<&V2State> {
        match self.v2s.iter().find(|(at, _)| *at == index) {
            Some((_, state)) => Some(state),
            None => self.snap.v2.get(index).map(|(_, state)| state),
        }
    }

    fn ekubo(&self, index: usize) -> Option<&EkuboState> {
        match self.ekubos.iter().find(|(at, _)| *at == index) {
            Some((_, state)) => Some(state),
            None => self.snap.ekubo.get(index).map(|(_, state)| state),
        }
    }
}

/// The overlay entry for `index`, copied from `base` on first write.
fn overlay<T: Clone>(
    touched: &mut Vec<(usize, T)>,
    index: usize,
    base: impl FnOnce() -> T,
) -> &mut T {
    let at = match touched.iter().position(|(at, _)| *at == index) {
        Some(at) => at,
        None => {
            touched.push((index, base()));
            touched.len() - 1
        }
    };
    &mut touched[at].1
}

impl<'a> ReplayState<'a> {
    fn new(snap: &'a Snapshot, capacity: usize) -> Self {
        Self {
            snap,
            v3s: Vec::new(),
            v2s: Vec::new(),
            ekubos: Vec::new(),
            used_sheriff: std::collections::HashSet::new(),
            legs: Vec::with_capacity(capacity),
            total: U256::ZERO,
        }
    }

    fn commit(&mut self, updates: &[Update]) {
        let snap = self.snap;
        for (hop, r) in updates {
            match r {
                SimResult::V3(r) => commit_v3(
                    overlay(&mut self.v3s, hop.index, || snap.v3[hop.index].1.clone()),
                    r,
                ),
                SimResult::V2(r) => commit_v2(
                    overlay(&mut self.v2s, hop.index, || snap.v2[hop.index].1.clone()),
                    r,
                ),
                SimResult::Ekubo(r) => commit_ekubo(
                    overlay(&mut self.ekubos, hop.index, || snap.ekubo[hop.index].1),
                    r,
                ),
            }
        }
    }

    fn push(&mut self, snap: &Snapshot, path: &[Hop], amount: U256) -> anyhow::Result<bool> {
        if amount.is_zero() {
            return Ok(true);
        }
        // Sheriff beforeSwap mutates its fee factors. Until that plugin state
        // is modeled, one snapshotted fee is valid for at most one pool swap.
        for hop in path {
            if hop.kind == HopKind::V3 {
                let pool = &snap.v3[hop.index].0;
                if pool.protocol == V3Protocol::SHERIFF && !self.used_sheriff.insert(pool.address) {
                    return Ok(false);
                }
            }
        }
        let mut losses = Vec::new();
        let (out, updates) = sim_path_recording(snap, &*self, path, amount, Some(&mut losses))?;
        if out.is_zero() {
            return Ok(false);
        }
        self.commit(&updates);
        self.legs.push(Leg {
            path: path.to_vec(),
            amount_in: amount,
            amount_out: out,
            losses,
            slice_bps: 0,
        });
        self.total += out;
        Ok(true)
    }

    fn into_plan(self) -> Plan {
        Plan {
            legs: self.legs,
            amount_out: self.total,
            universe_id: None,
        }
    }
}

fn resim_ordered(
    snap: &Snapshot,
    paths: &[Vec<Hop>],
    amounts: &[U256],
) -> anyhow::Result<Option<Plan>> {
    let mut replay = ReplayState::new(snap, paths.len());
    for (path, &amt) in paths.iter().zip(amounts) {
        if !replay.push(snap, path, amt)? {
            return Ok(None);
        }
    }
    Ok(Some(replay.into_plan()))
}

/// Re-simulation in descending-allocation order — the order actions will run in.
fn resim(snap: &Snapshot, paths: &[Vec<Hop>], alloc: &[U256]) -> anyhow::Result<Option<Plan>> {
    let mut order: Vec<usize> = (0..alloc.len()).filter(|&i| !alloc[i].is_zero()).collect();
    order.sort_by(|&a, &b| alloc[b].cmp(&alloc[a])); // stable: ties keep enumeration order
    let ordered_paths: Vec<Vec<Hop>> = order.iter().map(|&i| paths[i].clone()).collect();
    let ordered_amounts: Vec<U256> = order.iter().map(|&i| alloc[i]).collect();
    resim_ordered(snap, &ordered_paths, &ordered_amounts)
}

/// The exact amounts execution produces for a slice_bps vector: sequential
/// `floor(balance·bps/10⁴)` of the LIVE balance, remainder to the last leg.
fn amounts_of_bps(bps: &[u32], amount_in: U256) -> anyhow::Result<Vec<U256>> {
    let n = bps.len();
    let mut balance = amount_in;
    let mut amounts = vec![U256::ZERO; n];
    for i in 0..n {
        amounts[i] = if i == n - 1 {
            balance
        } else {
            muldiv(balance, U256::from(bps[i]), U256::from(BPS_BASE))?
        };
        balance -= amounts[i];
    }
    Ok(amounts)
}

/// Re-simulate exactly the slices a bps vector executes as. None when any leg
/// goes dry or drops (such a vector must not be chosen).
fn eval_bps(
    snap: &Snapshot,
    paths: &[Vec<Hop>],
    bps: &[u32],
    amount_in: U256,
) -> anyhow::Result<Option<Plan>> {
    let checkpoint = ReplayState::new(snap, paths.len());
    eval_bps_from_checkpoint(snap, paths, bps, amount_in, 0, &checkpoint)
}

fn eval_bps_from_checkpoint(
    snap: &Snapshot,
    paths: &[Vec<Hop>],
    bps: &[u32],
    amount_in: U256,
    start: usize,
    checkpoint: &ReplayState<'_>,
) -> anyhow::Result<Option<Plan>> {
    let amounts = amounts_of_bps(bps, amount_in)?;
    let mut replay = checkpoint.clone();
    for (path, &amount) in paths[start..].iter().zip(&amounts[start..]) {
        if !replay.push(snap, path, amount)? {
            return Ok(None);
        }
    }
    if replay.legs.len() != paths.len() {
        return Ok(None);
    }
    let q = replay.into_plan();
    Ok(Some(Plan {
        legs: q
            .legs
            .into_iter()
            .zip(bps)
            .map(|(l, &b)| Leg { slice_bps: b, ..l })
            .collect(),
        amount_out: q.amount_out,
        universe_id: None,
    }))
}

fn replay_prefix<'a>(
    snap: &'a Snapshot,
    paths: &[Vec<Hop>],
    bps: &[u32],
    amount_in: U256,
    end: usize,
) -> anyhow::Result<ReplayState<'a>> {
    let amounts = amounts_of_bps(bps, amount_in)?;
    let mut replay = ReplayState::new(snap, paths.len());
    for (path, &amount) in paths[..end].iter().zip(&amounts[..end]) {
        if !replay.push(snap, path, amount)? {
            bail!("executable polish prefix became invalid");
        }
    }
    Ok(replay)
}

/// Execution slices the input by sequential `bps` of the LIVE balance
/// (floor division), not by our planned amounts. Quantize the plan to exactly
/// those slices and re-simulate, so the quote IS the execution result. The
/// returned legs carry `slice_bps` — the encoder reads it, nothing else may.
pub fn try_quantized_plan(
    snap: &Snapshot,
    plan: &Plan,
    amount_in: U256,
) -> anyhow::Result<Option<Plan>> {
    try_quantized_plan_with_budget(snap, plan, amount_in, &SolverBudget::unlimited())
}

fn try_quantized_plan_with_budget(
    snap: &Snapshot,
    plan: &Plan,
    amount_in: U256,
    budget: &SolverBudget,
) -> anyhow::Result<Option<Plan>> {
    #[cfg(test)]
    record_route_work(|counts| counts.quantizations += 1);
    budget.checkpoint("route quantization")?;
    let n = plan.legs.len();
    let mut bps = vec![0u32; n];
    let mut remaining_planned = amount_in;
    for (i, leg) in plan.legs.iter().enumerate() {
        bps[i] = if i == n - 1 {
            BPS_BASE
        } else {
            u32::try_from(muldiv(
                U256::from(BPS_BASE),
                leg.amount_in,
                remaining_planned,
            )?)
            .context("slice bps out of range")?
        };
        remaining_planned -= leg.amount_in;
    }
    let paths: Vec<Vec<Hop>> = plan.legs.iter().map(|l| l.path.clone()).collect();
    let Some(q) = eval_bps(snap, &paths, &bps, amount_in)? else {
        return Ok(None);
    };
    let result = if *POLISH {
        polish_plan(snap, &paths, q, amount_in, budget).map(Some)
    } else {
        Ok(Some(q))
    }?;
    Ok(result.map(|mut quantized| {
        quantized.universe_id = plan.universe_id;
        quantized
    }))
}

pub fn quantized_plan(snap: &Snapshot, plan: &Plan, amount_in: U256) -> anyhow::Result<Plan> {
    try_quantized_plan(snap, plan, amount_in)?.context("quantized plan no longer executable")
}

/// Hill-climb the slice_bps vector on the exact execution objective. The
/// greedy allocation lands on a 1/ALLOC_CHUNKS grid (~156bp); the encoder's
/// resolution is 1bp — coordinate descent (coarse→fine steps) recovers the
/// difference. Output is monotone: never worse than the starting plan.
fn polish_plan(
    snap: &Snapshot,
    paths: &[Vec<Hop>],
    start: Plan,
    amount_in: U256,
    budget: &SolverBudget,
) -> anyhow::Result<Plan> {
    budget.checkpoint("route polish")?;
    let n = start.legs.len();
    if n < 2 {
        return Ok(start);
    }
    let mut best = start;
    let mut bps: Vec<u32> = best.legs.iter().map(|l| l.slice_bps).collect();
    let mut evals = 0;
    loop {
        budget.checkpoint("route polish")?;
        let mut improved = false;
        // the last leg always takes the remainder — only n-1 free dimensions
        for i in 0..n - 1 {
            let checkpoint = replay_prefix(snap, paths, &bps, amount_in, i)?;
            for step in [256i64, 64, 16, 4, 1] {
                for dir in [1i64, -1] {
                    budget.checkpoint("route polish")?;
                    let cand = i64::from(bps[i]) + dir * step;
                    if !(1..=i64::from(BPS_BASE) - 1).contains(&cand) {
                        continue;
                    }
                    let mut nb = bps.clone();
                    nb[i] = u32::try_from(cand).expect("bps in range");
                    evals += 1;
                    if let Some(p) =
                        eval_bps_from_checkpoint(snap, paths, &nb, amount_in, i, &checkpoint)?
                        && p.amount_out > best.amount_out
                    {
                        bps = nb;
                        best = p;
                        improved = true;
                    }
                }
            }
        }
        if !improved || evals > 2000 {
            return Ok(best);
        }
    }
}

#[cfg(test)]
fn best_single_plan(
    snap: &Snapshot,
    paths: &[Vec<Hop>],
    amount_in: U256,
) -> anyhow::Result<Option<Plan>> {
    best_single_plan_with_budget(snap, paths, amount_in, &SolverBudget::unlimited())
}

fn best_single_plan_with_budget(
    snap: &Snapshot,
    paths: &[Vec<Hop>],
    amount_in: U256,
    budget: &SolverBudget,
) -> anyhow::Result<Option<Plan>> {
    #[cfg(test)]
    record_route_work(|counts| counts.single_scans += 1);
    let mut best = None;
    for (path_index, path) in paths.iter().enumerate() {
        if path_index.is_multiple_of(64) {
            budget.checkpoint("single-route evaluation")?;
        }
        let Some(candidate) = resim(snap, std::slice::from_ref(path), &[amount_in])? else {
            continue;
        };
        if best
            .as_ref()
            .is_none_or(|current: &Plan| candidate.amount_out > current.amount_out)
        {
            best = Some(candidate);
        }
    }
    Ok(best)
}

#[cfg(test)]
fn best_split_plan(
    snap: &Snapshot,
    paths: &[Vec<Hop>],
    amount_in: U256,
    chunks: u32,
    min_share_bps: u32,
) -> anyhow::Result<Option<Plan>> {
    best_split_plan_with_budget(
        snap,
        paths,
        amount_in,
        chunks,
        min_share_bps,
        &SolverBudget::unlimited(),
    )
}

fn best_split_plan_with_budget(
    snap: &Snapshot,
    paths: &[Vec<Hop>],
    amount_in: U256,
    chunks: u32,
    min_share_bps: u32,
    budget: &SolverBudget,
) -> anyhow::Result<Option<Plan>> {
    #[cfg(test)]
    record_route_work(|counts| counts.split_allocations += 1);
    budget.checkpoint("split-route allocation")?;
    ensure!(chunks > 0, "allocation chunks must be positive");
    let nchunks = if amount_in >= U256::from(chunks) {
        chunks
    } else {
        1
    };
    let Some(mut alloc) = greedy_alloc_with_budget(snap, paths, amount_in, nchunks, budget)? else {
        return best_single_plan_with_budget(snap, paths, amount_in, budget);
    };

    // The leg budget goes first: it is the one rule here whose bite does not
    // depend on how many candidates were offered.
    let mut paths = std::borrow::Cow::Borrowed(paths);
    let funded: Vec<usize> = (0..alloc.len()).filter(|&i| !alloc[i].is_zero()).collect();
    if funded.len() > MAX_SPLIT_LEGS {
        paths = std::borrow::Cow::Owned(best_funded(&paths, &alloc, &funded, MAX_SPLIT_LEGS));
        let Some(trimmed) = greedy_alloc_with_budget(snap, &paths, amount_in, nchunks, budget)?
        else {
            return best_single_plan_with_budget(snap, &paths, amount_in, budget);
        };
        alloc = trimmed;
    }

    let mut plan = resim(snap, &paths, &alloc)?;

    let threshold = muldiv(amount_in, U256::from(min_share_bps), U256::from(BPS_BASE))?;
    let live: Vec<usize> = (0..alloc.len()).filter(|&i| !alloc[i].is_zero()).collect();
    if live.len() > 1 && live.iter().any(|&i| alloc[i] < threshold) {
        let mut strong: Vec<Vec<Hop>> = live
            .iter()
            .filter(|&&i| alloc[i] >= threshold)
            .map(|&i| paths[i].clone())
            .collect();
        if strong.is_empty() {
            // first index of the max, matching Julia's argmax tie-break
            let mut top = live[0];
            for &i in &live[1..] {
                if alloc[i] > alloc[top] {
                    top = i;
                }
            }
            strong = vec![paths[top].clone()];
        }
        // The cull is an offer, not a verdict. Dropping the legs under the floor
        // reallocates their flow onto worse marginals, and how much that costs
        // depends on how many candidates were on the table — which is what makes
        // the allocator non-monotone in its candidate set
        // (`the maintainers' research notes` §4). Keeping whichever
        // plan delivers more removes that dependence and can never lose output.
        // Ties go to the culled plan, so the floor still buys fewer legs
        // wherever fewer legs are free.
        if let Some(strong_alloc) =
            greedy_alloc_with_budget(snap, &strong, amount_in, nchunks, budget)?
            && let Some(culled) = resim(snap, &strong, &strong_alloc)?
            && plan
                .as_ref()
                .is_none_or(|current| culled.amount_out >= current.amount_out)
        {
            plan = Some(culled);
        }
    }

    if plan.is_none() {
        // Sequential order pushed a shared pool past its depth — fall back to
        // the best single path, which is always order-consistent.
        plan = best_single_plan_with_budget(snap, &paths, amount_in, budget)?;
    }
    Ok(plan)
}

/// The `limit` best-funded paths, richest first, first index winning ties.
///
/// Returned in the caller's own order so the re-solve enumerates them exactly
/// as the full set did, which keeps the greedy's tie-breaks where they were.
fn best_funded(
    paths: &[Vec<Hop>],
    alloc: &[U256],
    funded: &[usize],
    limit: usize,
) -> Vec<Vec<Hop>> {
    let mut order = funded.to_vec();
    order.sort_by(|&left, &right| alloc[right].cmp(&alloc[left]).then(left.cmp(&right)));
    order.truncate(limit);
    order.sort_unstable();
    order.into_iter().map(|i| paths[i].clone()).collect()
}

/// Best pre-quantization plan for callers that inspect allocator output.
/// Transaction-bearing quote paths must compare candidates through
/// `PreparedRoutes::try_solve_quantized` instead.
#[cfg(any(test, feature = "testing"))]
pub fn best_plan(
    snap: &Snapshot,
    tin: Address,
    tout: Address,
    amount_in: U256,
    chunks: u32,
    min_share_bps: u32,
) -> anyhow::Result<Plan> {
    PreparedRoutes::new(snap, tin, tout)?.solve(amount_in, chunks, min_share_bps)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::{FORK_SHERIFF, FORK_UNIV3, SLVR, USDG, WETH};
    use crate::pools::{AlgebraMeta, V2Pool, V2Protocol, V3Pool};
    use crate::v3math::{MAX_TICK, MIN_TICK};

    fn v2_pool(
        id: u8,
        token0: Address,
        token1: Address,
        reserve0: u64,
        reserve1: u64,
    ) -> (V2Pool, V2State) {
        (
            V2Pool {
                protocol: V2Protocol::UNIV2,
                address: Address::repeat_byte(id),
                token0,
                token1,
                fee_bps: 30,
            },
            V2State {
                reserve0: U256::from(reserve0),
                reserve1: U256::from(reserve1),
            },
        )
    }

    #[test]
    fn finds_a_route_that_only_exists_at_three_hops() {
        let token_in = Address::repeat_byte(0xa1);
        let token_out = Address::repeat_byte(0xb1);
        let snap = Snapshot {
            block: 1,
            settler: Some(Address::repeat_byte(0xfe)),
            v3: vec![],
            v2: vec![
                v2_pool(1, token_in, USDG, 1_000_000, 1_000_000),
                v2_pool(2, WETH, USDG, 1_000_000, 1_000_000),
                v2_pool(3, WETH, token_out, 1_000_000, 1_000_000),
            ],
            ekubo: vec![],
        };

        assert!(enumerate_paths(&snap, token_in, token_out).is_empty());
        let plan = best_plan(&snap, token_in, token_out, U256::from(1_000), 64, 50).unwrap();
        assert_eq!(plan.legs.len(), 1);
        assert_eq!(plan.legs[0].path.len(), 3);
        assert_eq!(
            plan.legs[0]
                .path
                .iter()
                .map(|hop| (hop.token_in, hop.token_out))
                .collect::<Vec<_>>(),
            vec![(token_in, USDG), (USDG, WETH), (WETH, token_out)]
        );
        assert!(!plan.legs[0].path[1].zero_for_one);
        assert!(plan.amount_out > U256::ZERO);
        let executable = quantized_plan(&snap, &plan, U256::from(1_000)).unwrap();
        assert!(executable.amount_out > U256::ZERO);
    }

    fn shallow_v3_pool(
        id: u8,
        token0: Address,
        token1: Address,
        liquidity: u64,
    ) -> (V3Pool, V3State) {
        (
            V3Pool {
                protocol: V3Protocol::UNIV3,
                address: Address::repeat_byte(id),
                token0,
                token1,
                fee_ppm: 500,
                tick_spacing: 1,
                verify_pool_spacing: false,
                execution: Some(crate::pools::V3ExecutionMeta {
                    fork_id: FORK_UNIV3,
                    pool_id: 500,
                }),
                v4: None,
                algebra: None,
            },
            V3State {
                sqrt_price: U256::ONE << 96usize,
                tick: 0,
                liquidity: U256::from(liquidity),
                ticks: Vec::new().into(),
                pos: 0,
                lo_cover: -256,
                hi_cover: 255,
            },
        )
    }

    fn multi_v2_snapshot() -> (Snapshot, Address) {
        let token_out = Address::repeat_byte(0xb7);
        let v2 = vec![
            v2_pool(11, SLVR, token_out, 5_000_000, 6_000_000),
            v2_pool(12, SLVR, token_out, 3_000_000, 4_000_000),
            v2_pool(13, SLVR, WETH, 8_000_000, 7_000_000),
            v2_pool(14, WETH, token_out, 7_000_000, 9_000_000),
            v2_pool(15, SLVR, USDG, 9_000_000, 6_000_000),
            v2_pool(16, USDG, token_out, 8_000_000, 10_000_000),
        ];
        (
            Snapshot {
                block: 1,
                settler: Some(Address::repeat_byte(0xfe)),
                v3: vec![],
                v2,
                ekubo: vec![],
            },
            token_out,
        )
    }

    fn baseline_product_snapshot(
        first_hops: usize,
        second_hops: usize,
    ) -> (Snapshot, Address, Address) {
        let token_in = Address::repeat_byte(0xa4);
        let token_out = Address::repeat_byte(0xb4);
        let mut v2 = Vec::with_capacity(first_hops + second_hops);
        for id in 0..first_hops {
            v2.push(v2_pool(id as u8, token_in, WETH, 1_000, 1_000));
        }
        for id in 0..second_hops {
            v2.push(v2_pool(
                (first_hops + id) as u8,
                WETH,
                token_out,
                1_000,
                1_000,
            ));
        }
        (
            Snapshot {
                block: 1,
                settler: Some(Address::repeat_byte(0xfe)),
                v3: vec![],
                v2,
                ekubo: vec![],
            },
            token_in,
            token_out,
        )
    }

    fn greedy_alloc_full_scan_reference(
        snap: &Snapshot,
        paths: &[Vec<Hop>],
        amount_in: U256,
        chunks: u32,
    ) -> anyhow::Result<Vec<U256>> {
        let (mut v3s, mut v2s, mut ekubos) = working_states(snap);
        let mut alloc = vec![U256::ZERO; paths.len()];
        for amount in balanced_chunk_amounts(amount_in, chunks)? {
            let mut best = None;
            let mut best_out = U256::ZERO;
            let mut best_updates = Vec::new();
            for (path_index, path) in paths.iter().enumerate() {
                let (out, updates) = sim_path(snap, &v3s, &v2s, &ekubos, path, amount)?;
                if out > best_out {
                    (best, best_out, best_updates) = (Some(path_index), out, updates);
                }
            }
            let best = best.context("reference allocator found no route")?;
            commit_updates(&mut v3s, &mut v2s, &mut ekubos, &best_updates);
            alloc[best] += amount;
        }
        Ok(alloc)
    }

    fn measure_route_work<T>(work: impl FnOnce() -> T) -> (T, RouteWorkCounts) {
        ROUTE_WORK_COUNTS.with(|counts| counts.set(RouteWorkCounts::default()));
        let result = work();
        (result, ROUTE_WORK_COUNTS.with(std::cell::Cell::get))
    }

    /// Independent old two-entry orchestration, rather than comparing the new
    /// API with its own compatibility wrappers.
    fn legacy_seed_pair(
        routes: &PreparedRoutes<'_>,
        amount: U256,
        chunks: u32,
        min_share_bps: u32,
    ) -> anyhow::Result<(Option<Plan>, Option<Plan>)> {
        let overall = best_quantized_candidate_with_budget(
            routes.snap,
            routes.candidate_plans(amount, chunks, min_share_bps)?,
            amount,
            &routes.budget,
        )?;
        let paths = routes.candidate_path_sets(amount, chunks)?.combined;
        let single =
            match best_single_plan_with_budget(routes.snap, &paths, amount, &routes.budget)? {
                Some(mut plan) => {
                    plan.universe_id = Some(routes.universe_id);
                    try_quantized_plan_with_budget(routes.snap, &plan, amount, &routes.budget)?
                }
                None => None,
            };
        Ok((overall, single))
    }

    #[test]
    fn a_skeleton_longer_than_the_hop_limit_is_an_error_not_a_panic() {
        let tokens: Vec<Address> = (0xc1..=0xc5).map(Address::repeat_byte).collect();
        let snap = Snapshot {
            block: 1,
            settler: Some(Address::repeat_byte(0xfe)),
            v3: vec![],
            v2: tokens
                .windows(2)
                .enumerate()
                .map(|(i, pair)| v2_pool(0x40 + i as u8, pair[0], pair[1], 1_000, 1_000))
                .collect(),
            ekubo: vec![],
        };
        for paths in [vec![tokens.clone()], vec![tokens[..1].to_vec()]] {
            let error = PreparedRoutes::for_shadow_paths(
                &snap,
                &paths,
                B256::ZERO,
                SolverBudget::unlimited(),
            )
            .err()
            .expect("a skeleton outside the hop limit is refused");
            assert!(
                error.to_string().contains("at most 3 are routed"),
                "{error}"
            );
        }
        // Four tokens, three hops: the longest skeleton routed.
        assert!(
            PreparedRoutes::for_shadow_paths(
                &snap,
                &[tokens[..4].to_vec()],
                B256::ZERO,
                SolverBudget::unlimited()
            )
            .is_ok()
        );
    }

    #[test]
    fn seed_batch_matches_two_entry_results_and_removes_repeated_work() {
        let token_in = Address::repeat_byte(0xa4);
        let token_out = Address::repeat_byte(0xb4);
        let snap = Snapshot {
            block: 1,
            settler: Some(Address::repeat_byte(0xfe)),
            v3: vec![],
            v2: vec![
                v2_pool(31, token_in, token_out, 1_000, 1_000),
                v2_pool(32, token_in, USDG, 1_000, 1_000),
                v2_pool(33, USDG, WETH, 1_000, 1_000),
                v2_pool(34, WETH, token_out, 1_000, 1_000),
            ],
            ekubo: vec![],
        };
        let routes = PreparedRoutes::new(&snap, token_in, token_out).unwrap();
        let mut saved_quantizations = false;
        for amount in [U256::ONE, U256::from(101), U256::from(1_000)] {
            let ((overall, single), legacy_work) =
                measure_route_work(|| legacy_seed_pair(&routes, amount, 64, 50).unwrap());
            let (batch, batch_work) = measure_route_work(|| {
                routes
                    .solve_seed_batch(amount, 64, 50, SeedDemand::Both)
                    .unwrap()
            });
            assert_eq!(batch.overall(), overall.as_ref());
            assert_eq!(batch.single(), single.as_ref());
            assert_eq!(batch_work.path_generations, 1);
            assert_eq!(legacy_work.path_generations, 2);
            assert_eq!(batch_work.single_scans + 1, legacy_work.single_scans);
            assert_eq!(batch_work.split_allocations, legacy_work.split_allocations);
            // The batch never quantizes more than the two legacy entries,
            // and a candidate that repeats an earlier plan is quantized once.
            let batch_quantizations = batch_work.quantizations + usize::from(single.is_some());
            assert!(batch_quantizations <= legacy_work.quantizations);
            saved_quantizations |= batch_quantizations < legacy_work.quantizations;
        }
        assert!(
            saved_quantizations,
            "a repeated candidate was quantized twice"
        );
    }

    #[test]
    fn seed_batch_single_only_skips_all_split_work() {
        let (snap, token_out) = multi_v2_snapshot();
        let routes = PreparedRoutes::new(&snap, SLVR, token_out).unwrap();
        let amount = U256::from(100_000);
        let expected = legacy_seed_pair(&routes, amount, 64, 0).unwrap().1;
        let (batch, work) = measure_route_work(|| {
            routes
                .solve_seed_batch(amount, 64, u32::MAX, SeedDemand::Single)
                .unwrap()
        });
        assert_eq!(batch.single(), expected.as_ref());
        assert!(batch.overall().is_none());
        assert_eq!(work.path_generations, 1);
        assert_eq!(work.single_scans, 1);
        assert_eq!(work.split_allocations, 0);
        assert_eq!(work.quantizations, 1);
        let error = routes
            .solve_seed_batch(amount, 64, u32::MAX, SeedDemand::Both)
            .unwrap_err();
        assert_eq!(error.to_string(), "minimum share exceeds 10000 bps");
    }

    #[test]
    fn seed_batch_keeps_first_single_tie_and_shares_identical_winner() {
        let token_in = Address::repeat_byte(0xaa);
        let token_out = Address::repeat_byte(0xbb);
        let mut snap = Snapshot {
            block: 1,
            settler: Some(Address::repeat_byte(0xfe)),
            v3: vec![],
            v2: vec![v2_pool(1, token_in, token_out, 1_000_000, 1_000_000)],
            ekubo: vec![],
        };
        let amount = U256::from(1_000);
        let routes = PreparedRoutes::new(&snap, token_in, token_out).unwrap();
        let batch = routes
            .solve_seed_batch(amount, 64, 0, SeedDemand::Both)
            .unwrap();
        assert!(std::ptr::eq(
            batch.overall().unwrap(),
            batch.single().unwrap()
        ));
        assert!(batch.distinct_single.is_none());

        snap.v2
            .push(v2_pool(2, token_in, token_out, 1_000_000, 1_000_000));
        let routes = PreparedRoutes::new(&snap, token_in, token_out).unwrap();
        let (overall, single) = legacy_seed_pair(&routes, amount, 64, 0).unwrap();
        let batch = routes
            .solve_seed_batch(amount, 64, 0, SeedDemand::Both)
            .unwrap();
        assert_eq!(batch.overall(), overall.as_ref());
        assert_eq!(batch.single(), single.as_ref());
        assert_eq!(batch.single().unwrap().legs[0].path[0].index, 0);
    }

    #[test]
    fn seed_batch_preserves_missing_single_and_empty_universe() {
        let token_in = Address::repeat_byte(0xa5);
        let token_out = Address::repeat_byte(0xb5);
        let snap = Snapshot {
            block: 1,
            settler: Some(Address::repeat_byte(0xfe)),
            v3: vec![
                shallow_v3_pool(43, WETH, token_out, 1_000_000),
                shallow_v3_pool(44, WETH, token_out, 1_000_000),
            ],
            v2: vec![
                v2_pool(41, token_in, USDG, 1_000_000_000_000, 1_000_000_000_000),
                v2_pool(42, USDG, WETH, 1_000_000_000_000, 1_000_000_000_000),
            ],
            ekubo: vec![],
        };
        let routes = PreparedRoutes::new(&snap, token_in, token_out).unwrap();
        let amount = U256::from(20_000);
        let (overall, single) = legacy_seed_pair(&routes, amount, 64, 0).unwrap();
        let batch = routes
            .solve_seed_batch(amount, 64, 0, SeedDemand::Both)
            .unwrap();
        assert!(batch.overall().is_some());
        assert!(batch.single().is_none());
        assert_eq!(batch.overall(), overall.as_ref());
        assert_eq!(batch.single(), single.as_ref());

        let empty = PreparedRoutes::new(&snap, Address::repeat_byte(0xcc), token_out).unwrap();
        for demand in [SeedDemand::Overall, SeedDemand::Single, SeedDemand::Both] {
            let batch = empty.solve_seed_batch(amount, 64, 0, demand).unwrap();
            assert!(batch.overall().is_none());
            assert!(batch.single().is_none());
        }
    }

    #[test]
    fn prepared_routes_preserve_baseline_order() {
        let (snap, token_out) = multi_v2_snapshot();
        let prepared = PreparedRoutes::new(&snap, SLVR, token_out).unwrap();
        assert_eq!(
            prepared.baseline_paths,
            enumerate_paths(&snap, SLVR, token_out)
        );
    }

    #[test]
    fn cancelled_budget_stops_route_work_cooperatively() {
        let (snap, token_out) = multi_v2_snapshot();
        let universe = RouteUniverse::profile_only(&ROBINHOOD_PROFILE, SLVR, token_out).unwrap();
        let budget = SolverBudget::unlimited();
        let prepared =
            PreparedRoutes::for_universe_with_budget(&snap, &universe, budget.clone()).unwrap();
        budget.cancel();

        let error = prepared
            .try_solve_quantized(U256::from(100_000u64), 64, 0)
            .unwrap_err();
        assert!(
            error
                .downcast_ref::<crate::budget::SolverBudgetExceeded>()
                .is_some()
        );
    }

    #[test]
    fn cancelled_budget_stops_profile_single_route_work() {
        let (snap, token_out) = multi_v2_snapshot();
        let budget = SolverBudget::unlimited();
        let prepared = PreparedRoutes::for_profile_with_budget(
            &snap,
            &ROBINHOOD_PROFILE,
            SLVR,
            token_out,
            budget.clone(),
        )
        .unwrap();
        budget.cancel();

        let error = prepared
            .try_solve_single_quantized(U256::from(100_000u64), 64)
            .unwrap_err();
        assert!(
            error
                .downcast_ref::<crate::budget::SolverBudgetExceeded>()
                .is_some()
        );
    }

    /// Derived from the cap rather than written beside it, so moving the cap
    /// cannot leave the boundary tests testing an old number.
    const BOUNDARY_RIGHT: usize = 256;
    const BOUNDARY_LEFT: usize = BASELINE_PATH_CANDIDATE_CAP / BOUNDARY_RIGHT;
    const _: () = assert!(
        BOUNDARY_LEFT * BOUNDARY_RIGHT == BASELINE_PATH_CANDIDATE_CAP,
        "the boundary fixture must land exactly on the cap"
    );

    #[test]
    fn baseline_candidate_limit_accepts_exact_boundary() {
        let (snap, token_in, token_out) = baseline_product_snapshot(BOUNDARY_LEFT, BOUNDARY_RIGHT);
        let prepared = PreparedRoutes::new(&snap, token_in, token_out).unwrap();
        assert_eq!(prepared.baseline_paths.len(), BASELINE_PATH_CANDIDATE_CAP);
    }

    #[test]
    fn baseline_candidate_limit_fails_explicitly() {
        let (snap, token_in, token_out) =
            baseline_product_snapshot(BOUNDARY_LEFT + 1, BOUNDARY_RIGHT);
        let error = best_plan(&snap, token_in, token_out, U256::ONE, 1, 0).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("baseline route candidate limit exceeded")
        );
    }

    #[test]
    fn invalid_numeric_route_setting_is_not_silently_defaulted() {
        assert_eq!(parse_bounded_u32_setting("X", None, 7, 1, 100).unwrap(), 7);
        assert_eq!(
            parse_bounded_u32_setting("X", Some("42"), 7, 1, 100).unwrap(),
            42
        );
        assert!(parse_bounded_u32_setting("X", Some("forty-two"), 7, 1, 100).is_err());
        assert!(parse_bounded_u32_setting("X", Some("0"), 7, 1, 100).is_err());
        assert!(parse_bounded_u32_setting("X", Some("101"), 7, 1, 100).is_err());
        assert!(parse_bool_setting("X", None, true).unwrap());
        assert!(!parse_bool_setting("X", Some("0"), true).unwrap());
        assert!(parse_bool_setting("X", Some("1"), false).unwrap());
        assert!(parse_bool_setting("X", Some("true"), true).is_err());
    }

    #[test]
    fn chunk_remainder_is_distributed_evenly() {
        let chunks = balanced_chunk_amounts(U256::from(511), 256).unwrap();
        assert_eq!(chunks.len(), 256);
        assert_eq!(chunks.iter().copied().sum::<U256>(), U256::from(511));
        assert_eq!(
            chunks
                .iter()
                .filter(|&&amount| amount == U256::from(2))
                .count(),
            255
        );
        assert_eq!(
            chunks.iter().filter(|&&amount| amount == U256::ONE).count(),
            1
        );
    }

    #[test]
    fn direct_and_three_hop_share_liquidity_in_one_plan() {
        let token_in = Address::repeat_byte(0xa4);
        let token_out = Address::repeat_byte(0xb4);
        let snap = Snapshot {
            block: 1,
            settler: Some(Address::repeat_byte(0xfe)),
            v3: vec![],
            v2: vec![
                v2_pool(31, token_in, token_out, 1_000, 1_000),
                v2_pool(32, token_in, USDG, 1_000, 1_000),
                v2_pool(33, USDG, WETH, 1_000, 1_000),
                v2_pool(34, WETH, token_out, 1_000, 1_000),
            ],
            ekubo: vec![],
        };
        let amount = U256::from(1_000);
        let routes = PreparedRoutes::new(&snap, token_in, token_out).unwrap();
        let direct = best_single_plan(&snap, &routes.baseline_paths, amount)
            .unwrap()
            .unwrap();
        let three_hop = three_hop_candidates(&routes, amount, 64).unwrap();
        let three_hop_full = best_single_plan(&snap, &three_hop, amount)
            .unwrap()
            .unwrap();
        let plan = routes.try_solve_quantized(amount, 64, 0).unwrap().unwrap();

        assert!(plan.legs.iter().any(|leg| leg.path.len() == 1));
        assert!(plan.legs.iter().any(|leg| leg.path.len() == 3));
        assert!(plan.amount_out > direct.amount_out);
        assert!(plan.amount_out > three_hop_full.amount_out);
    }

    #[test]
    fn three_hop_quota_is_applied_per_token_skeleton() {
        let token_in = Address::repeat_byte(0xa6);
        let token_out = Address::repeat_byte(0xb6);
        let mut v2 = Vec::new();

        // WETH -> USDG has thirteen strong prefixes and seven final pools.
        // With a global top-K, these paths occupy every slot and hide the
        // independent USDG -> WETH skeleton below.
        for id in 60..73 {
            v2.push(v2_pool(
                id,
                token_in,
                WETH,
                1_000_000_000_000,
                1_000_000_000_000,
            ));
        }
        v2.push(v2_pool(
            73,
            WETH,
            USDG,
            1_000_000_000_000,
            1_000_000_000_000,
        ));
        for id in 74..81 {
            v2.push(v2_pool(
                id,
                USDG,
                token_out,
                1_000_000_000_000,
                1_000_000_000_000,
            ));
        }

        // A slightly weaker but disjoint USDG -> WETH route must retain its
        // own skeleton quota.
        v2.push(v2_pool(
            81,
            token_in,
            USDG,
            1_000_000_000_000,
            900_000_000_000,
        ));
        v2.push(v2_pool(
            82,
            WETH,
            token_out,
            1_000_000_000_000,
            1_000_000_000_000,
        ));

        let snap = Snapshot {
            block: 1,
            settler: Some(Address::repeat_byte(0xfe)),
            v3: vec![],
            v2,
            ekubo: vec![],
        };
        let candidates = three_hop_candidates_at(
            &PreparedRoutes::new(&snap, token_in, token_out).unwrap(),
            U256::from(1_000),
        )
        .unwrap();

        assert!(candidates.len() > THREE_HOP_TOP_K_PER_PROBE);
        assert!(candidates.iter().any(|candidate| {
            candidate.path[0].token_out == USDG && candidate.path[1].token_out == WETH
        }));
    }

    #[test]
    fn three_hop_prefix_work_limit_fails_explicitly() {
        let token_in = Address::repeat_byte(0xa8);
        let token_out = Address::repeat_byte(0xb8);
        let mut v2 = Vec::new();
        for id in 0..129 {
            v2.push(v2_pool(id, token_in, WETH, 1_000_000, 1_000_000));
        }
        for id in 0..129 {
            v2.push(v2_pool(id, WETH, USDG, 1_000_000, 1_000_000));
        }
        v2.push(v2_pool(255, USDG, token_out, 1_000_000, 1_000_000));
        let snap = Snapshot {
            block: 1,
            settler: Some(Address::repeat_byte(0xfe)),
            v3: vec![],
            v2,
            ekubo: vec![],
        };

        let result = three_hop_candidates_at(
            &PreparedRoutes::new(&snap, token_in, token_out).unwrap(),
            U256::from(1_000),
        );
        let error = match result {
            Ok(_) => panic!("oversized three-hop prefix work was accepted"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("three-hop prefix work cap"));
    }

    #[test]
    fn multiple_partial_three_hop_paths_combine_their_capacity() {
        let token_in = Address::repeat_byte(0xa5);
        let token_out = Address::repeat_byte(0xb5);
        let snap = Snapshot {
            block: 1,
            settler: Some(Address::repeat_byte(0xfe)),
            v3: vec![
                shallow_v3_pool(43, WETH, token_out, 1_000_000),
                shallow_v3_pool(44, WETH, token_out, 1_000_000),
            ],
            v2: vec![
                v2_pool(41, token_in, USDG, 1_000_000_000_000, 1_000_000_000_000),
                v2_pool(42, USDG, WETH, 1_000_000_000_000, 1_000_000_000_000),
            ],
            ekubo: vec![],
        };
        let amount = U256::from(20_000);
        let routes = PreparedRoutes::new(&snap, token_in, token_out).unwrap();
        let three_hop = routes.candidate_path_sets(amount, 64).unwrap().three_hop;

        assert!(three_hop.len() >= 2);
        assert!(
            best_single_plan(&snap, &three_hop, amount)
                .unwrap()
                .is_none()
        );
        let plan = routes.try_solve(amount, 64, 0).unwrap().unwrap();
        assert!(plan.legs.len() >= 2);
        assert!(plan.legs.iter().all(|leg| leg.path.len() == 3));
        assert_eq!(
            plan.legs.iter().map(|leg| leg.amount_in).sum::<U256>(),
            amount
        );
    }

    #[test]
    fn dependency_invalidated_allocator_matches_full_scan() {
        let (snap, token_out) = multi_v2_snapshot();
        let paths = enumerate_paths(&snap, SLVR, token_out);
        assert!(paths.len() >= 4);
        for chunks in [1, 3, 16, 31] {
            let amount = U256::from(100_003u64);
            assert_eq!(
                greedy_alloc_full_scan(&snap, &paths, amount, chunks)
                    .unwrap()
                    .unwrap(),
                greedy_alloc_full_scan_reference(&snap, &paths, amount, chunks).unwrap()
            );
        }
    }

    #[test]
    fn lazy_allocator_recomputes_same_direction_shared_pool_marginals() {
        let token_in = Address::repeat_byte(0xa9);
        let token_out = Address::repeat_byte(0xb9);
        let snap = Snapshot {
            block: 1,
            settler: Some(Address::repeat_byte(0xfe)),
            v3: vec![],
            v2: vec![
                v2_pool(86, token_in, WETH, 1_000_000, 1_000_000),
                v2_pool(87, WETH, token_out, 1_000_000, 2_000_000),
                v2_pool(88, WETH, token_out, 900_000, 1_900_000),
            ],
            ekubo: vec![],
        };
        let paths = enumerate_paths(&snap, token_in, token_out);
        assert_eq!(paths.len(), 2);
        assert_eq!(paths[0][0].index, paths[1][0].index);

        for chunks in [3, 16, 31] {
            let amount = U256::from(100_003);
            assert_eq!(
                greedy_alloc(&snap, &paths, amount, chunks)
                    .unwrap()
                    .unwrap(),
                greedy_alloc_full_scan_reference(&snap, &paths, amount, chunks).unwrap()
            );
        }
    }

    #[test]
    fn equal_marginals_use_the_complete_deterministic_heap_key() {
        let token_in = Address::repeat_byte(0xaa);
        let token_out = Address::repeat_byte(0xba);
        let snap = Snapshot {
            block: 1,
            settler: Some(Address::repeat_byte(0xfe)),
            v3: vec![],
            v2: vec![
                v2_pool(89, token_in, token_out, 1_000_000, 1_000_000),
                v2_pool(90, token_in, token_out, 1_000_000, 1_000_000),
            ],
            ekubo: vec![],
        };
        let paths = enumerate_paths(&snap, token_in, token_out);
        let amount = U256::from(1_000);

        for _ in 0..16 {
            assert_eq!(
                greedy_alloc(&snap, &paths, amount, 1).unwrap().unwrap(),
                vec![amount, U256::ZERO]
            );
        }
    }

    #[test]
    fn simulation_errors_are_not_treated_as_capacity_shortage() {
        let token_in = Address::repeat_byte(0xab);
        let token_out = Address::repeat_byte(0xbb);
        let snap = Snapshot {
            block: 1,
            settler: Some(Address::repeat_byte(0xfe)),
            v3: vec![],
            v2: vec![(
                V2Pool {
                    protocol: V2Protocol::UNIV2,
                    address: Address::repeat_byte(91),
                    token0: token_in,
                    token1: token_out,
                    fee_bps: 30,
                },
                V2State {
                    reserve0: U256::MAX,
                    reserve1: U256::from(1_000),
                },
            )],
            ekubo: vec![],
        };

        let error = PreparedRoutes::new(&snap, token_in, token_out)
            .unwrap()
            .try_solve(U256::ONE, 1, 0)
            .unwrap_err();
        assert!(error.to_string().contains("v2 reserve overflow"));
    }

    #[test]
    fn winner_is_selected_after_settler_bps_quantization() {
        let token_in = Address::repeat_byte(0xa7);
        let token_out = Address::repeat_byte(0xb7);
        let snap = Snapshot {
            block: 1,
            settler: Some(Address::repeat_byte(0xfe)),
            v3: vec![],
            v2: vec![
                v2_pool(83, token_in, token_out, 407_919, 701_237),
                v2_pool(84, token_in, token_out, 903_571, 508_863),
                v2_pool(85, token_in, token_out, 500_000, 828_420),
            ],
            ekubo: vec![],
        };
        let hops = hops_between(&snap, token_in, token_out);
        let split_paths = [vec![hops[0].clone()], vec![hops[1].clone()]];
        let single_path = vec![hops[2].clone()];
        let amount = U256::from(100_003);
        let theoretical_winner =
            resim_ordered(&snap, &split_paths, &[U256::from(100_001), U256::from(2)])
                .unwrap()
                .unwrap();
        let executable_winner = resim_ordered(&snap, std::slice::from_ref(&single_path), &[amount])
            .unwrap()
            .unwrap();

        assert_eq!(theoretical_winner.amount_out, U256::from(137_730));
        assert_eq!(executable_winner.amount_out, U256::from(137_728));
        let quantized_theoretical = try_quantized_plan(&snap, &theoretical_winner, amount)
            .unwrap()
            .unwrap();
        assert_eq!(quantized_theoretical.amount_out, U256::from(137_725));

        let selected =
            best_quantized_candidate(&snap, [theoretical_winner, executable_winner], amount)
                .unwrap()
                .unwrap();
        assert_eq!(selected.amount_out, U256::from(137_728));
        assert_eq!(selected.legs.len(), 1);
        assert_eq!(selected.legs[0].path[0].index, 2);
    }

    #[test]
    fn polish_prefix_checkpoint_matches_full_replay() {
        let (snap, token_out) = multi_v2_snapshot();
        let amount = U256::from(100_003u64);
        let paths = enumerate_paths(&snap, SLVR, token_out);
        let mut allocation = vec![U256::ZERO; paths.len()];
        allocation[0] = U256::from(40_000u64);
        allocation[1] = U256::from(30_000u64);
        allocation[2] = U256::from(30_003u64);
        let plan = resim(&snap, &paths, &allocation)
            .unwrap()
            .expect("three-leg replay");
        let paths = plan
            .legs
            .iter()
            .map(|leg| leg.path.clone())
            .collect::<Vec<_>>();
        assert!(paths.len() >= 2);

        let mut bps = Vec::with_capacity(plan.legs.len());
        let mut remaining = amount;
        for (index, leg) in plan.legs.iter().enumerate() {
            bps.push(if index + 1 == plan.legs.len() {
                BPS_BASE
            } else {
                u32::try_from(muldiv(U256::from(BPS_BASE), leg.amount_in, remaining).unwrap())
                    .unwrap()
            });
            remaining -= leg.amount_in;
        }

        for index in 0..paths.len() - 1 {
            let checkpoint = replay_prefix(&snap, &paths, &bps, amount, index).unwrap();
            let mut candidate = bps.clone();
            candidate[index] = (candidate[index] + 1).min(BPS_BASE - 1);
            let full = eval_bps(&snap, &paths, &candidate, amount).unwrap();
            let suffix =
                eval_bps_from_checkpoint(&snap, &paths, &candidate, amount, index, &checkpoint)
                    .unwrap();
            assert_eq!(
                full.as_ref().map(|plan| plan.amount_out),
                suffix.as_ref().map(|plan| plan.amount_out)
            );
            assert_eq!(
                full.as_ref().map(|plan| {
                    plan.legs
                        .iter()
                        .map(|leg| {
                            (
                                leg.amount_in,
                                leg.amount_out,
                                leg.slice_bps,
                                leg.losses.clone(),
                            )
                        })
                        .collect::<Vec<_>>()
                }),
                suffix.as_ref().map(|plan| {
                    plan.legs
                        .iter()
                        .map(|leg| {
                            (
                                leg.amount_in,
                                leg.amount_out,
                                leg.slice_bps,
                                leg.losses.clone(),
                            )
                        })
                        .collect::<Vec<_>>()
                })
            );
        }
    }

    #[test]
    fn executable_three_hop_survives_a_shallow_baseline() {
        let token_in = Address::repeat_byte(0xa3);
        let token_out = Address::repeat_byte(0xb3);
        let shallow_direct = (
            V3Pool {
                protocol: V3Protocol::UNIV3,
                address: Address::repeat_byte(20),
                token0: token_in,
                token1: token_out,
                fee_ppm: 500,
                tick_spacing: 1,
                verify_pool_spacing: false,
                execution: Some(crate::pools::V3ExecutionMeta {
                    fork_id: FORK_UNIV3,
                    pool_id: 500,
                }),
                v4: None,
                algebra: None,
            },
            V3State {
                sqrt_price: U256::ONE << 96usize,
                tick: 0,
                liquidity: U256::from(1_000_000u64),
                ticks: Vec::new().into(),
                pos: 0,
                lo_cover: 0,
                hi_cover: 0,
            },
        );
        let snap = Snapshot {
            block: 1,
            settler: Some(Address::repeat_byte(0xfe)),
            v3: vec![shallow_direct],
            v2: vec![
                v2_pool(21, token_in, USDG, 1_000_000, 1_000_000),
                v2_pool(22, WETH, USDG, 1_000_000, 1_000_000),
                v2_pool(23, WETH, token_out, 1_000_000, 1_000_000),
            ],
            ekubo: vec![],
        };

        let amount = U256::from(1_000u64);
        assert!(
            best_split_plan(
                &snap,
                &enumerate_paths(&snap, token_in, token_out),
                amount,
                64,
                50,
            )
            .unwrap()
            .is_none()
        );
        let selected = best_plan(&snap, token_in, token_out, amount, 64, 50).unwrap();
        assert_eq!(selected.legs.len(), 1);
        assert_eq!(selected.legs[0].path.len(), 3);
        assert!(selected.amount_out > U256::ZERO);
    }

    #[test]
    fn three_hop_candidate_never_replaces_a_better_baseline() {
        let token_in = Address::repeat_byte(0xa2);
        let token_out = Address::repeat_byte(0xb2);
        let snap = Snapshot {
            block: 1,
            settler: Some(Address::repeat_byte(0xfe)),
            v3: vec![],
            v2: vec![
                v2_pool(4, token_in, token_out, 10_000_000, 20_000_000),
                v2_pool(5, token_in, WETH, 1_000_000, 1_000_000),
                v2_pool(6, WETH, USDG, 1_000_000, 1_000_000),
                v2_pool(7, USDG, token_out, 1_000_000, 1_000_000),
            ],
            ekubo: vec![],
        };
        let amount = U256::from(1_000);
        let baseline = best_split_plan(
            &snap,
            &enumerate_paths(&snap, token_in, token_out),
            amount,
            64,
            50,
        )
        .unwrap()
        .unwrap();
        let selected = best_plan(&snap, token_in, token_out, amount, 64, 50).unwrap();

        assert_eq!(selected.amount_out, baseline.amount_out);
        assert_eq!(selected.legs[0].path.len(), 1);
    }

    #[test]
    fn ordered_resim_rejects_a_second_sheriff_swap() {
        let token0 = Address::repeat_byte(0xa0);
        let token1 = Address::repeat_byte(0xb0);
        let snap = Snapshot {
            block: 1,
            settler: Some(Address::repeat_byte(0xfe)),
            v3: vec![(
                V3Pool {
                    protocol: V3Protocol::SHERIFF,
                    address: Address::repeat_byte(1),
                    token0,
                    token1,
                    fee_ppm: 400,
                    tick_spacing: 10,
                    verify_pool_spacing: false,
                    execution: Some(crate::pools::V3ExecutionMeta {
                        fork_id: FORK_SHERIFF,
                        pool_id: 0,
                    }),
                    v4: None,
                    algebra: Some(AlgebraMeta {
                        fee_0to1_ppm: 365,
                        fee_1to0_ppm: 434,
                    }),
                },
                V3State {
                    sqrt_price: U256::ONE << 96usize,
                    tick: 0,
                    liquidity: U256::from(1_000_000_000_000_000_000u128),
                    ticks: Vec::new().into(),
                    pos: 0,
                    lo_cover: MIN_TICK,
                    hi_cover: MAX_TICK,
                },
            )],
            v2: vec![],
            ekubo: vec![],
        };
        let path = vec![Hop {
            kind: HopKind::V3,
            index: 0,
            zero_for_one: true,
            token_in: token0,
            token_out: token1,
        }];
        let paths = [path.clone(), path];
        let amount = U256::from(1_000_000u64);

        assert!(
            resim_ordered(&snap, &paths, &[amount, U256::ZERO])
                .unwrap()
                .is_some()
        );
        assert!(
            resim_ordered(&snap, &paths, &[amount, amount])
                .unwrap()
                .is_none()
        );
    }

    /// `count` identical parallel pools between one pair, so a candidate set
    /// can be widened by pools that are incapable of making it worse.
    fn parallel_pool_snapshot(count: u16) -> (Snapshot, Address, Address) {
        let token_in = Address::repeat_byte(0xc1);
        let token_out = Address::repeat_byte(0xc2);
        let v2 = (0..count)
            .map(|i| {
                let mut raw = [0u8; 20];
                raw[18..].copy_from_slice(&i.to_be_bytes());
                (
                    V2Pool {
                        protocol: V2Protocol::UNIV2,
                        address: Address::from(raw),
                        token0: token_in,
                        token1: token_out,
                        fee_bps: 30,
                    },
                    V2State {
                        reserve0: U256::from(1_000_000_000_000u64),
                        reserve1: U256::from(1_000_000_000_000u64),
                    },
                )
            })
            .collect();
        (
            Snapshot {
                block: 1,
                settler: Some(Address::repeat_byte(0xfe)),
                v3: vec![],
                v2,
                ekubo: vec![],
            },
            token_in,
            token_out,
        )
    }

    fn single_hop_paths(snap: &Snapshot, tin: Address, tout: Address) -> Vec<Vec<Hop>> {
        hops_between(snap, tin, tout)
            .into_iter()
            .map(|hop| vec![hop])
            .collect()
    }

    #[test]
    #[ignore = "timing probe"]
    fn time_the_quantized_solve() {
        let amount = U256::from(10_000_000_000u64);
        for count in [8u16, 32, 64, 128, 186, 200, 255] {
            let (snap, tin, tout) = parallel_pool_snapshot(count);
            let routes = PreparedRoutes::new(&snap, tin, tout).unwrap();
            let start = std::time::Instant::now();
            let plan = routes
                .try_solve_quantized(amount, 256, 50)
                .unwrap()
                .unwrap();
            let ms = start.elapsed().as_secs_f64() * 1e3;
            println!(
                "{count} candidates -> {} legs, {} out, {ms:.1} ms",
                plan.legs.len(),
                plan.amount_out
            );
        }
    }

    /// Offering more candidates never lowers the plan.
    ///
    /// The regression this pins: a greedy split over `L` comparable candidates
    /// gives `C mod L` of them two chunks and the rest one, so under a floor of
    /// 50 bps of a 256-chunk input — 1.28 chunks — exactly `C − L` legs used to
    /// clear it and the rest were discarded. Each candidate above `C/2` cost
    /// the plan one leg, and at `L ≥ C` no leg cleared the floor at all and the
    /// split collapsed to a single path: widening 200 identical pools to 256
    /// cost **96 bps**, which is a coverage measurement's whole signal
    /// (`the maintainers' research notes` §4). Keeping whichever plan
    /// delivers more removes the dependence on the candidate count.
    #[test]
    fn widening_the_candidate_set_never_lowers_the_plan() {
        const CHUNKS: u32 = 256;
        const FLOOR_BPS: u32 = 50;
        let amount = U256::from(10_000_000_000u64);

        let mut previous: Option<U256> = None;
        for count in [128u16, 150, 200, 240, 255, 256, 300] {
            let (snap, tin, tout) = parallel_pool_snapshot(count);
            let paths = single_hop_paths(&snap, tin, tout);
            let plan = best_split_plan(&snap, &paths, amount, CHUNKS, FLOOR_BPS)
                .unwrap()
                .unwrap();
            assert!(
                plan.legs.len() > 1,
                "the cull collapsed {count} candidates to one path"
            );
            assert!(
                plan.legs.len() <= MAX_SPLIT_LEGS,
                "{count} candidates escaped the leg budget"
            );
            if let Some(previous) = previous {
                assert!(
                    plan.amount_out >= previous,
                    "widening to {count} candidates lowered the plan"
                );
            }
            previous = Some(plan.amount_out);
        }
    }

    /// Past the leg budget the plan stops growing, and stops changing.
    ///
    /// The budget keeps `min(K, live)` legs however many candidates are on the
    /// table, so 200 comparable pools and 255 of them produce the same plan the
    /// best 128 do. A share threshold answered that question with `C − L` and
    /// walked to one leg.
    #[test]
    fn the_leg_budget_bounds_the_plan_whatever_is_offered() {
        let amount = U256::from(10_000_000_000u64);
        let solve = |count: u16| {
            let (snap, tin, tout) = parallel_pool_snapshot(count);
            let paths = single_hop_paths(&snap, tin, tout);
            best_split_plan(&snap, &paths, amount, 256, 50)
                .unwrap()
                .unwrap()
        };
        let budgeted = solve(MAX_SPLIT_LEGS as u16);
        for count in [200u16, 255, 300] {
            let plan = solve(count);
            assert_eq!(plan.legs.len(), MAX_SPLIT_LEGS);
            assert_eq!(plan.amount_out, budgeted.amount_out);
        }
    }

    /// The floor still buys fewer legs wherever fewer legs are free, and stands
    /// aside where they are not.
    #[test]
    fn the_floor_yields_to_the_plan_that_delivers_more() {
        const CHUNKS: u32 = 256;
        let amount = U256::from(10_000_000_000u64);
        let (snap, tin, tout) = parallel_pool_snapshot(200);
        let paths = single_hop_paths(&snap, tin, tout);

        let floored = best_split_plan(&snap, &paths, amount, CHUNKS, 50)
            .unwrap()
            .unwrap();
        let free = best_split_plan(&snap, &paths, amount, CHUNKS, 0)
            .unwrap()
            .unwrap();
        // The cull's own answer here is 56 legs and 1.24 bps worse, so the
        // unculled plan wins and keeps every candidate that drew a chunk.
        assert_eq!(floored.amount_out, free.amount_out);
        assert_eq!(floored.legs.len(), free.legs.len());

        // Where the split gains nothing, the floor's answer ties and still wins,
        // because a tie goes to the shorter plan.
        let (shallow, tin, tout) = parallel_pool_snapshot(2);
        let paths = single_hop_paths(&shallow, tin, tout);
        let tiny = best_split_plan(&shallow, &paths, U256::from(2u64), CHUNKS, 10_000)
            .unwrap()
            .unwrap();
        assert_eq!(tiny.legs.len(), 1);
    }
}
