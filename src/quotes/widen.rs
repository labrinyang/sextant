//! A resident quote's widening: after each solve, the connectors whose
//! skeletons beat the served plan at the margin are admitted and the quote is
//! solved again on the wider graph, until none is or the rounds run out. A
//! quote that routes nothing without its thin pools takes them back.

use super::amm::{Round, solve_round};
use crate::budget::SolverBudget;
use crate::engine::Stamped;
use crate::route::{ALLOC_CHUNKS, MIN_SHARE_BPS};
use crate::settler::BPS_BASE;
use crate::universe::RouteUniverse;
use alloy_primitives::{Address, U256};
use std::time::Instant;

/// A resident candidate is admitted when its probes say it could add at least
/// this share of the quote (`resident::Widening::worth_admitting`): 0.1 bp, in
/// bp × 10⁴.
pub(super) const WIDEN_BPS_E4: u64 = 1_000;

/// Probing and re-solving rounds a resident quote may take after its first
/// solve.
pub(super) const WIDEN_ROUNDS: usize = 3;

/// What a resident quote admitted beyond the graph it started from.
#[derive(Clone, Debug)]
pub(super) struct WideningReport {
    /// Why it stopped: `settled` (no candidate's probes say it could add
    /// enough), `no_gain` (a wider solve found nothing more), `rounds` (the
    /// round limit came first, so this is not known), `stopped` (a probe or
    /// graph could not be built) or `none` (no candidates).
    pub(super) end: &'static str,
    /// Connectors beyond the static ones this pair's resident graph may use.
    pub(super) candidates: usize,
    /// Connectors admitted on their probes, in the order admitted.
    pub(super) admitted: Vec<Address>,
    /// Probing and re-solving rounds after the first solve.
    pub(super) rounds: usize,
    /// Wall time of the probes, in microseconds.
    pub(super) probe_us: u64,
    /// Admitted skeletons the pair ceiling left out of the served graph.
    pub(super) left_out: usize,
    /// Thin pools the served graph left out, and whether it kept them.
    pub(super) thin_left_out: usize,
    pub(super) thin_kept: bool,
}

impl Default for WideningReport {
    fn default() -> Self {
        Self {
            end: "none",
            candidates: 0,
            admitted: Vec::new(),
            rounds: 0,
            probe_us: 0,
            left_out: 0,
            thin_left_out: 0,
            thin_kept: false,
        }
    }
}

/// Widens `stamped`'s resident graph from the quote's first round. Leaves
/// `universe`, `round` and `solve_ms` those of the round that ships, and
/// returns what the widening did with the resident graph it shipped on, if
/// not the snapshot's own.
pub(super) fn widen(
    stamped: &Stamped,
    (a, b): (Address, Address),
    amount_in: U256,
    budget: &SolverBudget,
    universe: &mut RouteUniverse,
    round: &mut Round,
    solve_ms: &mut u64,
) -> anyhow::Result<(WideningReport, Option<crate::resident::Widened>)> {
    // A resident quote admits the connectors whose skeletons its probes
    // find better than its own best route at the margin, and is solved
    // again on the wider graph, until none is or the rounds run out.
    // Nothing is remembered between quotes.
    let mut widening = WideningReport::default();
    let mut graph: Option<crate::resident::Widened> = None;
    // Whether any graph this quote solved left thin pools out.
    let mut thin_tried = false;
    if let Some(candidates) = stamped.widening.as_deref() {
        widening.thin_left_out = candidates.thin_left_out();
        widening.thin_kept = candidates.thin_kept();
        thin_tried = widening.thin_left_out > 0;
    }
    if let Some(candidates) = stamped.widening.as_deref()
        && !candidates.connectors().is_empty()
    {
        widening.candidates = candidates.connectors().len();
        widening.left_out = candidates.left_out();
        widening.end = "rounds";
        let mut admitted = candidates.admitted().clone();
        let probe = (amount_in / U256::from(*ALLOC_CHUNKS))
            .max(amount_in * U256::from(*MIN_SHARE_BPS) / U256::from(BPS_BASE))
            .max(U256::ONE);
        while widening.rounds < WIDEN_ROUNDS {
            let t = Instant::now();
            let promote = match round.plan.as_ref() {
                // Nothing to probe against: everything is admitted, as
                // when the quote could not start narrow.
                None => candidates
                    .connectors()
                    .into_iter()
                    .filter(|connector| !admitted.contains(connector))
                    .collect(),
                Some(plan) => {
                    let served = graph
                        .as_ref()
                        .map_or(&stamped.snap, |graph| &graph.snapshot);
                    match crate::route::plan_states(served, plan) {
                        Ok(after) => candidates.worth_admitting(
                            &admitted,
                            served,
                            &after,
                            universe.token_paths(),
                            a,
                            probe,
                            plan.amount_out,
                            plan.amount_out * U256::from(WIDEN_BPS_E4) / U256::from(100_000_000u64),
                        ),
                        Err(error) => {
                            tracing::info!(
                                "widening stopped: {}",
                                crate::rpc::sanitized_error(&error)
                            );
                            widening.end = "stopped";
                            break;
                        }
                    }
                }
            };
            widening.probe_us = widening
                .probe_us
                .saturating_add(t.elapsed().as_micros() as u64);
            if promote.is_empty() {
                widening.end = "settled";
                break;
            }
            budget.checkpoint("widening")?;
            admitted.extend(promote.iter().copied());
            // A graph that cannot be built leaves the quote on the one it
            // has, which was already solved and certified.
            let next = match candidates
                .graph(&admitted)
                .and_then(|next| Ok((next.universe.orient(a, b)?, next)))
            {
                Ok(next) => next,
                Err(error) => {
                    tracing::info!("widening stopped: {}", crate::rpc::sanitized_error(&error));
                    widening.end = "stopped";
                    break;
                }
            };
            let (next_universe, next) = next;
            thin_tried |= next.thin_left_out > 0;
            // Its route set borrows `next`, which the graph takes below.
            let (next_round, _) = solve_round(&next.snapshot, &next_universe, amount_in, budget)?;
            *solve_ms = solve_ms.saturating_add(next_round.solve_ms);
            widening.rounds += 1;
            // The wider graph's optimum is no worse, but the allocator is
            // greedy and can find less there; the better plan ships, and a
            // round that does not improve the quote ends the widening.
            if next_round.amount_out() <= round.amount_out() {
                widening.end = "no_gain";
                break;
            }
            widening.admitted.extend(promote);
            widening.left_out = next.left_out;
            widening.thin_left_out = next.thin_left_out;
            widening.thin_kept = next.thin_kept;
            *universe = next_universe;
            *round = next_round;
            graph = Some(next);
        }
    }
    // A graph without its thin pools can route on paper and still fill
    // nothing; the quote then takes them back, with every connector,
    // rather than fail.
    if round.plan.is_none()
        && thin_tried
        && let Some(candidates) = stamped.widening.as_deref()
    {
        let everything: std::collections::BTreeSet<Address> =
            candidates.connectors().into_iter().collect();
        if let Ok(full) = candidates.graph_with_thin(&everything)
            && let Ok(full_universe) = full.universe.orient(a, b)
        {
            let (full_round, _) = solve_round(&full.snapshot, &full_universe, amount_in, budget)?;
            *solve_ms = solve_ms.saturating_add(full_round.solve_ms);
            if full_round.plan.is_some() {
                widening.admitted = everything
                    .into_iter()
                    .filter(|connector| !candidates.admitted().contains(connector))
                    .collect();
                widening.left_out = full.left_out;
                widening.thin_left_out = 0;
                widening.thin_kept = true;
                widening.end = "thin";
                *universe = full_universe;
                *round = full_round;
                graph = Some(full);
            }
        }
    }
    Ok((widening, graph))
}
