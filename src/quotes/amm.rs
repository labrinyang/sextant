use super::wire::{CertificateJson, RouteUniverseJson};
use crate::budget::SolverBudget;
use crate::certificate;
use crate::certificate::{Certificate, certify_in_universe_with_budget};
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
