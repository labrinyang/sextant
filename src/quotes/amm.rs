use super::widen::{WideningReport, widen};
use super::wire::{CertificateJson, RouteUniverseJson, certificate_json};
use crate::budget::SolverBudget;
use crate::certificate;
use crate::certificate::{Certificate, certify_in_universe_with_budget};
use crate::chain::ChainProfile;
use crate::engine::Stamped;
use crate::route::{ALLOC_CHUNKS, MIN_SHARE_BPS, Plan, PreparedRoutes};
use crate::rpc::RpcUnavailable;
use crate::snapshot::Snapshot;
use crate::universe::{RouteUniverse, RouteUniverseDiagnostics};
use alloy_primitives::{Address, U256};
use anyhow::{Context, ensure};
use std::sync::{Arc, LazyLock};
use std::time::Instant;

/// Certificate-triggered allocator escalation threshold, in bps (fractional
/// allowed; ≤ 0 disables). A certified gap above this line is measured
/// missing output, not optimizer noise: the production-box attribution of
/// 2026-08-02 (`certificate_explain` at block 25227339) put the entire
/// surviving ladder tail on the allocator — WETH→CASHCAT 500 certified
/// 6.21 bps at the default 256-chunk/50 bp resolution and 0.31 bps at
/// 4096/0 with the bound unchanged, SLVR→USDG 0.3 went 8.40 → 0.46 the
/// same way. SOLVER_CERTIFICATE_ESCALATE_BPS.
///
/// **0.1 bp since 2026-08-06**, measured. The line was 1 bp, chosen as the
/// quality gate's own. Letting the minimum-share cull lose an argument
/// (unpublished allocator-monotonicity notes, §7 B) lowered the base solve's
/// certified gap under that line on exactly the deep cases escalation used to
/// win, so the re-solve stopped firing where it was paying: on the Robinhood
/// ladder at block 29298590, six cases lost output — USDG→CASHCAT 200k by
/// 0.95 bps with its plan going 79 legs to 33, CASHCAT→USDG 600k by 0.44 with
/// 103 to 35. At 0.1 bp the same ladder is **21 better and 0 worse** against
/// the pre-change build, the summed certified gap halves (8.14 → 4.03 bps) and
/// the whole ladder's solve time rises 14% (1,596 → 1,819 ms for 37 quotes).
pub(super) static ESCALATE_BPS_E4: LazyLock<u64> =
    LazyLock::new(|| read_escalate_threshold_e4().unwrap_or_else(|error| panic!("{error:#}")));

/// `SOLVER_CERTIFICATE_ESCALATE_BPS`, as a `Result` so startup can reject a
/// typo instead of the first quote that certifies tripping the `LazyLock`.
fn read_escalate_threshold_e4() -> anyhow::Result<u64> {
    match std::env::var("SOLVER_CERTIFICATE_ESCALATE_BPS") {
        Ok(value) => escalate_threshold_e4(&value),
        Err(std::env::VarError::NotPresent) => Ok(1_000),
        Err(error) => {
            anyhow::bail!("SOLVER_CERTIFICATE_ESCALATE_BPS is not valid Unicode: {error}")
        }
    }
}

/// Every `SOLVER_*` setting this module owns, parsed at startup.
pub(crate) fn validate_settings() -> anyhow::Result<()> {
    read_escalate_threshold_e4().map(|_| ())
}

/// Allocator for the escalated re-solve: 1024 chunks with a 10 bp floor.
///
/// Measured on a Morph fork at block 28073500 (15 Oct 2026; 11 tokens, 421
/// quotes from $10 to $10,000): the re-solve fired on 253 quotes and gained
/// over 0.1 bp on 14, all through one token's near-empty pools. 1024/10 kept
/// 13 of the 14 at 2.3 ms median and 11.8 ms p95 per re-solve, against 7.5
/// and 42.7 ms for 4096/0; 256/0 kept none, so chunk size, not the floor, is
/// what those quotes need. Elsewhere it gained at most 0.045 bp. On Robinhood
/// in August 4096/0 was the knee (4096/10 left 2.85 bps in sub-10 bp slivers,
/// 2048/0 left 0.78, 4096/0 left 0.31). The tier is per build, not per chain;
/// re-measure on each chain this serves before tuning it.
const ESCALATED_CHUNKS: u32 = 1024;
const ESCALATED_MIN_SHARE: u32 = 10;

pub(super) fn escalate_threshold_e4(raw: &str) -> anyhow::Result<u64> {
    let bps: f64 = raw.trim().parse().with_context(|| {
        format!("SOLVER_CERTIFICATE_ESCALATE_BPS must be a number of bps, got {raw:?}")
    })?;
    // A non-finite value (inf, NaN) has no meaning as a threshold and would
    // saturate the cast below.
    ensure!(
        bps.is_finite(),
        "SOLVER_CERTIFICATE_ESCALATE_BPS must be finite, got {raw:?}"
    );
    Ok(if bps <= 0.0 {
        0
    } else {
        (bps * 10_000.0).round() as u64
    })
}

/// Everything needed to compare the final AMM candidate with a firm RFQ.
/// Native quotes are intentionally fetched only after this work is complete:
/// their short validity window must not be consumed by allocator escalation or
/// coverage measurement.
pub(super) struct AmmEvaluation {
    pub(super) route_universe: RouteUniverseJson,
    pub(super) universe_diag: RouteUniverseDiagnostics,
    pub(super) plan: Option<Plan>,
    /// Best linear AMM prefix into the reviewed stable bridge. The public v1
    /// route shape cannot faithfully describe a split-then-join followed by a
    /// single RFQ call, so mixed routes deliberately use one AMM leg.
    pub(super) native_last_prefix: Option<Plan>,
    pub(super) fair: Option<Plan>,
    pub(super) fair_in: U256,
    pub(super) certificate: Option<CertificateJson>,
    pub(super) coverage: Option<crate::counterfactual::CoverageReading>,
    pub(super) solve_ms: u64,
    pub(super) certificate_us: u64,
    pub(super) coverage_us: u64,
    /// The resident graph the plan was solved on, when the quote widened past
    /// the one it was stamped with. Everything after the solve reads it.
    pub(super) widened: Option<Arc<Stamped>>,
    pub(super) widening: WideningReport,
}

/// One graph's solve and, when certificates are on, its certificate.
pub(super) struct Round {
    pub(super) plan: Option<Plan>,
    pub(super) certificate: Option<anyhow::Result<Certificate>>,
    pub(super) solve_ms: u64,
    pub(super) certificate_us: u64,
}

impl Round {
    pub(super) fn amount_out(&self) -> Option<U256> {
        self.plan.as_ref().map(|plan| plan.amount_out)
    }
}

/// Solve `universe` over `snap`, and keep the route set: the escalation and
/// the fair probe solve the same snapshot and universe again. Certification
/// waits for the plan that ships ([`certify_round`]).
pub(super) fn solve_round<'a>(
    snap: &'a Snapshot,
    universe: &RouteUniverse,
    amount_in: U256,
    budget: &SolverBudget,
) -> anyhow::Result<(Round, PreparedRoutes<'a>)> {
    let t = Instant::now();
    let routes = PreparedRoutes::for_universe_with_budget(snap, universe, budget.clone())?;
    let plan = routes.try_solve_quantized(amount_in, *ALLOC_CHUNKS, *MIN_SHARE_BPS)?;
    let round = Round {
        plan,
        certificate: None,
        solve_ms: t.elapsed().as_millis() as u64,
        certificate_us: 0,
    };
    Ok((round, routes))
}

/// Certify `round`'s plan with `screening` priced beside it. The certificate
/// window also holds the escalated re-solve: a loose bound names its own
/// cure. Only quotes the certificate has already proven loose pay for the
/// second solve, and the better plan wins on output — the recertification
/// keeps the reported bound honest for whichever plan ships.
#[allow(clippy::too_many_arguments)] // the round's own snapshot, graph and budget
pub(super) fn certify_round(
    round: &mut Round,
    routes: &PreparedRoutes<'_>,
    snap: &Snapshot,
    screening: &crate::snapshot::ScreeningPools,
    universe: &RouteUniverse,
    endpoints: (Address, Address),
    amount_in: U256,
    budget: &SolverBudget,
) -> anyhow::Result<()> {
    let t = Instant::now();
    let Some(plan) = round.plan.as_mut().filter(|_| *certificate::ENABLED) else {
        return Ok(());
    };
    let mut result = certify_in_universe_with_budget(
        universe, snap, screening, endpoints, amount_in, plan, budget,
    );
    budget.checkpoint("certificate evaluation")?;
    if let Ok(cert) = &result
        && *ESCALATE_BPS_E4 > 0
        && cert.gap_bps_e4 > *ESCALATE_BPS_E4
    {
        match routes.try_solve_quantized(amount_in, ESCALATED_CHUNKS, ESCALATED_MIN_SHARE) {
            Ok(Some(better)) if better.amount_out > plan.amount_out => {
                result = certify_in_universe_with_budget(
                    universe, snap, screening, endpoints, amount_in, &better, budget,
                );
                budget.checkpoint("escalated certificate evaluation")?;
                *plan = better;
            }
            Err(error)
                if error
                    .downcast_ref::<crate::budget::SolverBudgetExceeded>()
                    .is_some() =>
            {
                return Err(error);
            }
            _ => {}
        }
    }
    round.certificate = Some(result);
    round.certificate_us = t.elapsed().as_micros() as u64;
    Ok(())
}

pub(super) fn fresh_amm_snapshot(stamped: &Stamped) -> anyhow::Result<&Snapshot> {
    if stamped.is_fresh_to_finish() {
        Ok(&stamped.snap)
    } else {
        Err(
            anyhow::anyhow!("AMM snapshot became stale before quote finalization")
                .context(RpcUnavailable("snapshot freshness")),
        )
    }
}

/// The AMM stage of a quote: solve the pair, widen a resident graph, certify
/// the plan that ships, solve the 1% probe for the fair reference, and measure
/// coverage. CPU work only; the caller decides whether it runs in place or on
/// a blocking thread.
pub(super) fn evaluate_amm(
    stamped: &Stamped,
    profile: &'static ChainProfile,
    (a, b): (Address, Address),
    amount_in: U256,
    native_planning_enabled: bool,
    budget: &SolverBudget,
) -> anyhow::Result<AmmEvaluation> {
    budget.checkpoint("quote solve")?;
    let canonical_hash = stamped
        .block_id()
        .as_block_hash()
        .context("snapshot is not pinned to a canonical block hash")?;
    let mut universe = stamped.universe.orient(a, b)?;
    let (mut round, first_routes) = solve_round(&stamped.snap, &universe, amount_in, budget)?;
    let mut solve_ms = round.solve_ms;

    let (widening, graph) = widen(
        stamped,
        (a, b),
        amount_in,
        budget,
        &mut universe,
        &mut round,
        &mut solve_ms,
    )?;
    let snap = graph
        .as_ref()
        .map_or(&stamped.snap, |graph| &graph.snapshot);
    // The shipped round's route set, for the escalation and the fair probe:
    // the first round's when no wider graph shipped (the universe changes
    // only with the graph), else one build over the graph that did.
    let routes = match &graph {
        None => first_routes,
        Some(graph) => {
            PreparedRoutes::for_universe_with_budget(&graph.snapshot, &universe, budget.clone())?
        }
    };
    let screening = &stamped.screening;
    // Only the plan that ships is certified.
    certify_round(
        &mut round,
        &routes,
        snap,
        screening,
        &universe,
        (a, b),
        amount_in,
        budget,
    )?;
    let certificate_us = round.certificate_us;
    let universe_diag = universe.diagnostics();
    let route_universe = RouteUniverseJson::new(
        profile.chain_id,
        snap.block,
        canonical_hash,
        universe_diag,
        stamped.topology_fences,
    );

    let t = Instant::now();
    let native_last_prefix = if native_planning_enabled
        && a != profile.stable
        && b != profile.stable
    {
        PreparedRoutes::for_profile_with_budget(snap, profile, a, profile.stable, budget.clone())?
            .try_solve_single_quantized(amount_in, *ALLOC_CHUNKS)?
    } else {
        None
    };
    let fair_in = amount_in / U256::from(100);
    // one probe, two derived numbers: the size penalty this API has always
    // reported, and the fee-free baseline the UI prices every route against
    let fair = if round.plan.is_none() || fair_in.is_zero() {
        None
    } else {
        routes.try_solve_quantized(fair_in, *ALLOC_CHUNKS, *MIN_SHARE_BPS)?
    };
    solve_ms = solve_ms.saturating_add(t.elapsed().as_millis() as u64);
    let Round {
        plan, certificate, ..
    } = round;
    // Captured before `certificate_json` consumes the result: it is the
    // upper bound on what evicting an idle connector can cost (docs §22).
    let certified_gap_bps_e4: Option<U256> = certificate
        .as_ref()
        .and_then(|result| result.as_ref().ok())
        .map(|cert| cert.gap_bps_e4);
    let certificate = certificate.map(|result| certificate_json(result, *ESCALATE_BPS_E4 > 0));

    // Coverage, measured. `plan` is final here — after any escalation — so
    // both sides of `V(U ∪ screened) − V(U)` come from the same allocator
    // settings at the same block.
    //
    // Gated on screening having loaded state rather than on a flag of its
    // own: those reads are the expensive part and they are already paid for.
    // A failure here degrades to "unmeasured" and never touches the quote,
    // matching how the screening reads themselves degrade — the counterfactual
    // budget-checkpoints, so an exhausted budget stops it almost immediately
    // instead of spending past the deadline.
    //
    // `coverage` rather than `measure_coverage`: the measurement is amortized
    // over the topology lease, so most quotes read a verdict instead of
    // paying 112–721 ms to reproduce one.
    let t = Instant::now();
    // No certified gap means no bound on an eviction's cost, so admission
    // gets no evidence rather than an unbacked zero.
    let coverage = if let (Some(plan), Some(certified_gap_bps_e4)) =
        (plan.as_ref(), certified_gap_bps_e4)
        && !screening.is_empty()
    {
        match crate::counterfactual::coverage(
            snap,
            &universe,
            screening,
            plan,
            certified_gap_bps_e4,
            plan.amount_out,
            amount_in,
            *ALLOC_CHUNKS,
            *MIN_SHARE_BPS,
            budget,
        ) {
            // `Ok(None)` is the module declining to answer: nothing screened
            // it could reach, no reproducible route, or a non-monotone
            // solve. It stays absent rather than collapsing into a zero,
            // because a zero here is a proof that no connector helps.
            Ok(value) => value,
            Err(error) => {
                tracing::info!(
                    "coverage unmeasured: {}",
                    crate::rpc::sanitized_error(&error)
                );
                None
            }
        }
    } else {
        None
    };
    let coverage_us = t.elapsed().as_micros() as u64;
    Ok(AmmEvaluation {
        route_universe,
        universe_diag,
        plan,
        native_last_prefix,
        fair,
        fair_in,
        certificate,
        coverage,
        solve_ms,
        certificate_us,
        coverage_us,
        widened: graph.map(|graph| stamped.widened(graph)),
        widening,
    })
}
