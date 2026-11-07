// Quote orchestration: snapshot → plan → (optional) transaction.
// Response field names are the HTTP contract (README, "HTTP"), byte-compatible
// with the Julia solver's output (amounts as decimal strings, lowercase hex addresses).

use crate::abi::{addrhex, tohex};
use crate::budget::SolverBudget;
#[cfg(test)]
use crate::certificate::certify;
use crate::certificate::{self, Certificate, certify_in_universe_with_budget, format_bps_e4};
use crate::chain::{ChainProfile, NATIVE};
use crate::config::Config;
use crate::engine::{Engine, SnapshotScope, Stamped};
use crate::rfq::{
    FirmQuoteRequest, NativePair, NativeRfqError, NativeRfqSource, ValidatedFirmQuote,
};
use crate::route::{ALLOC_CHUNKS, Hop, HopKind, Leg, MIN_SHARE_BPS, Plan, PreparedRoutes};
#[cfg(test)]
use crate::route::{best_plan, quantized_plan};
use crate::rpc::{CanonicalBlock, RpcUnavailable};
use crate::settler::{
    BPS_BASE, ComposedSwapStage, PositiveSlippage, build_composed_native_rfq_tx_for_profile,
    build_swap_tx_for_profile,
};
use crate::simulation::{self, Approval, Issues, Simulation};
use crate::snapshot::Snapshot;
use crate::topology::CatalogFences;
use crate::universe::{RouteUniverse, RouteUniverseDiagnostics};
use crate::v3math::muldiv;
use alloy_primitives::{
    Address, B256, U256,
    aliases::{U1024, U4096},
};
use anyhow::{Context, ensure};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;

pub fn net_after_fee(gross: U256, fee_bps: u32) -> anyhow::Result<U256> {
    Ok(gross - muldiv(gross, U256::from(fee_bps), U256::from(BPS_BASE))?)
}

fn price_impact_bps(amount_in: U256, amount_out: U256, fair_in: U256, fair_out: U256) -> u32 {
    let fair_rate = U1024::from(fair_out) * U1024::from(amount_in);
    let execution_rate = U1024::from(amount_out) * U1024::from(fair_in);
    if execution_rate >= fair_rate {
        return 0;
    }
    let impact =
        ((fair_rate - execution_rate) * U1024::from(BPS_BASE) + fair_rate - U1024::ONE) / fair_rate;
    u32::try_from(impact).expect("price impact is at most 10000 bps")
}

/// LP-fee denominator: v2's `fee_bps` × 100.
const PPM_BASE: u32 = 1_000_000;

fn v2_fee_ppm(snap: &Snapshot, hop: &Hop) -> u32 {
    snap.v2[hop.index].0.fee_bps * 100
}

/// Adds every hop's LP fee back onto a leg's output, then scales it to the
/// quote size. Keep the compounded ratio fractional until after scaling: one
/// widened division per leg matches the direct quote formula.
///
/// A fee at or above PPM_BASE would underflow, on the same snapshot invariant
/// `sim_v2` already leans on for `10_000 - fee_bps`.
fn fee_free_out(
    snap: &Snapshot,
    leg: &Leg,
    fair_in: U256,
    amount_in: U256,
) -> anyhow::Result<U256> {
    // Routes have at most three hops: 4096 bits hold both quote amounts and
    // three pool-fee ratios without overflow.
    let mut numerator = U4096::from(leg.amount_out) * U4096::from(amount_in);
    let mut denominator = U4096::from(fair_in);
    for hop in leg.path.iter().filter(|hop| hop.kind == HopKind::V2) {
        let fee_ppm = v2_fee_ppm(snap, hop);
        numerator *= U4096::from(PPM_BASE);
        denominator *= U4096::from(PPM_BASE - fee_ppm);
    }
    for loss in &leg.losses {
        numerator *= U4096::from(loss.gross);
        denominator *= U4096::from(loss.net);
    }
    let out = numerator / denominator;
    ensure!(out >> 256usize == U4096::ZERO, "midAmountOut overflow");
    Ok(U256::from_limbs(
        out.as_limbs()[..4].try_into().expect("four low limbs"),
    ))
}

/// The fee-free reference output for `amount_in`: the 1% probe plan's output
/// with every LP fee added back, scaled to full size.
/// It is what the trade would fetch if both size and fees were free, and
/// it is the ONE denominator every quote row on the frontend is scored against
/// — one route's cost can then never sit on a different scale from another's.
///
/// Derived from the probe PLAN rather than a pool's raw mid price on purpose:
/// the reference stays a price that was actually executable at probe size, so
/// a stale or illiquid pool advertising a great mid cannot poison it. The
/// residual error is the probe's own depth cost — it moves 1% of the trade, so
/// a sub-bp share of the full-size move.
fn mid_amount_out(
    snap: &Snapshot,
    fair: &Plan,
    fair_in: U256,
    amount_in: U256,
) -> anyhow::Result<U256> {
    let mut acc = U256::ZERO;
    for leg in &fair.legs {
        acc += fee_free_out(snap, leg, fair_in, amount_in)?;
    }
    Ok(acc)
}

fn reference_metrics(
    snap: &Snapshot,
    full: &Plan,
    fair: Option<&Plan>,
    fair_in: U256,
    amount_in: U256,
) -> anyhow::Result<(Option<u32>, Option<U256>)> {
    let Some(fair) = fair else {
        return Ok((None, None));
    };
    let mid = mid_amount_out(snap, fair, fair_in, amount_in)?;
    if mid < full.amount_out {
        return Ok((None, None));
    }
    Ok((
        Some(price_impact_bps(
            amount_in,
            full.amount_out,
            fair_in,
            fair.amount_out,
        )),
        Some(mid),
    ))
}

#[derive(Clone, Deserialize)]
#[serde(untagged)]
pub enum AmountIn {
    Num(u64),
    Str(String),
}

impl std::fmt::Display for AmountIn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AmountIn::Num(n) => write!(f, "{n}"),
            AmountIn::Str(s) => f.write_str(s),
        }
    }
}

fn default_slippage() -> i64 {
    50
}

fn default_deadline() -> i64 {
    600
}

/// Per-request `feeBps` ceiling — 1%, well above the terminal's own rates.
/// The public API takes a RATE override only; the receiver stays server config.
pub const MAX_FEE_OVERRIDE_BPS: u32 = 100;

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QuoteRequest {
    /// Required chain binding. It must match the single chain this process
    /// verified at startup; it is never a request-time chain selector.
    pub chain_id: u64,
    pub token_in: String,
    pub token_out: String,
    pub amount_in: AmountIn,
    #[serde(default = "default_slippage")]
    pub slippage_bps: i64,
    #[serde(default)]
    pub recipient: Option<String>,
    /// Account that owns the input and authorizes the returned transaction.
    /// Defaults to the recipient for backwards compatibility. This is the
    /// AllowanceHolder owner and Settler authorization taker, not EVM
    /// `tx.origin`.
    #[serde(default)]
    pub sender: Option<String>,
    /// Explicit EOA expected as EVM `tx.origin` by Native Router v6. This is
    /// intentionally not inferred from `sender`: smart-account and relayed
    /// transactions commonly have different values.
    #[serde(default)]
    pub tx_origin: Option<String>,
    #[serde(default = "default_deadline")]
    pub deadline_seconds: i64,
    /// terminal-fee override for this quote (zap charges 9 while swap rides
    /// the server default); absent = `SOLVER_FEE_BPS`
    #[serde(default)]
    pub fee_bps: Option<u32>,
}

/// The product name of a hop's venue, which the backend's calldata checks and
/// the app's route display share. An AMM venue is named by its protocol id.
fn venue(protocol: &'static str) -> &'static str {
    match protocol {
        "nativerfq" => "native",
        other => other,
    }
}

#[derive(Serialize)]
#[serde(untagged)]
pub enum HopJson {
    #[serde(rename_all = "camelCase")]
    NativeRfq {
        protocol: &'static str,
        venue: &'static str,
        router: String,
        pool: String,
        token_in: String,
        token_out: String,
        quote_deadline: u64,
    },
    #[serde(rename_all = "camelCase")]
    V3 {
        protocol: &'static str,
        venue: &'static str,
        pool: String,
        token_in: String,
        token_out: String,
        fee_ppm: u32,
        tick_spacing: i32,
    },
    #[serde(rename_all = "camelCase")]
    V2 {
        protocol: &'static str,
        venue: &'static str,
        pool: String,
        token_in: String,
        token_out: String,
        fee_bps: u32,
    },
    #[serde(rename_all = "camelCase")]
    Ekubo {
        protocol: &'static str,
        venue: &'static str,
        pool: String,
        token_in: String,
        token_out: String,
        extension: &'static str,
        pool_type: &'static str,
        fee_x64: String,
        fee_ppm: u32,
        tick_spacing: Option<u32>,
    },
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RouteLegJson {
    pub share_bps: u32,
    pub amount_in: String,
    pub amount_out: String,
    pub hops: Vec<HopJson>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TxJson {
    /// The account the quote was built for. Settler calldata cannot bind
    /// this address, so clients must enforce it.
    pub required_from: String,
    pub to: String,
    pub value: String,
    pub data: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PositiveSlippageJson {
    pub recipient: String,
    pub token: String,
    pub expected_amount: String,
    pub max_bps: u32,
}

/// Phase timings and snapshot provenance for the server log — never
/// serialized, not part of the /quote contract.
#[derive(Clone, Default)]
pub struct QuoteMeta {
    pub snapshot_ms: u64,
    /// Upstream JSON-RPC requests made by this quote's snapshot pull.
    /// A resident memory hit is always zero, including during refreshes.
    pub snapshot_rpc_calls: u64,
    pub solve_ms: u64,
    /// Wall time of the shadow certificate pass — microseconds, because at
    /// milliseconds it reads as zero.
    pub certificate_us: u64,
    pub encode_ms: u64,
    /// Head read, prerequisite reads, `eth_call`, gas and L1 fee of the built
    /// transaction. Zero when no transaction was built.
    pub simulate_ms: u64,
    /// The first transaction, priced on an earlier block, failed its check at
    /// the head, and this response was priced again from that block.
    pub repriced: bool,
    /// Native firm-quote request wall time. Zero also means the source was not
    /// configured or the request was display-only; the booleans disambiguate.
    pub rfq_ms: u64,
    pub rfq_attempted: bool,
    pub rfq_quoted: bool,
    pub rfq_selected: bool,
    /// "resident" (the resident pool state), "memory" (fresh per-pair hit)
    /// or "pull" (fetched by this quote)
    pub source: &'static str,
    pub universe_source: &'static str,
    pub universe_fallback_stage: Option<&'static str>,
    pub universe_fallback_reason: Option<&'static str>,
    pub universe_scope: &'static str,
    pub universe_selection_scope: &'static str,
    pub universe_selector: &'static str,
    pub universe_protocol_mask: u32,
    pub universe_eligible_count: usize,
    pub universe_connector_count: usize,
    /// Connectors priced but deliberately not routed. Zero means this quote's
    /// coverage question went unasked, which is a different statement from
    /// `graphGapBps` reading flat — that one means it was asked and answered.
    pub universe_screened_count: usize,
    /// `V(U ∪ screened) − V(U)` in output wei, and the allocator runs it cost.
    /// `None` means the measurement did not run or could not finish, which is a
    /// different statement from a measured zero — that one is a proof.
    pub coverage_gain: Option<U256>,
    pub coverage_used: usize,
    pub coverage_solves: usize,
    /// Age of the verdict served. `Some(0)` is a measurement this quote paid
    /// for; a larger value is one it reused off the topology lease. Reading
    /// `coverage_us` alone would confuse a reused verdict with a cheap one.
    pub coverage_age_ms: Option<u64>,
    pub coverage_us: u64,
    pub universe_shortlist_truncated: bool,
    pub universe_fingerprint: B256,
    pub adjacency_fences: Option<CatalogFences>,
    pub topology_fences: Option<CatalogFences>,
    /// Connectors beyond the static ones that this pair's resident graph may
    /// route through: the resident ones, where they have pools.
    pub widening_candidates: usize,
    /// Connectors a resident quote admitted beyond its starting graph because
    /// their skeletons' probes beat its best route, in that order.
    pub widened: Vec<Address>,
    /// Probing and re-solving rounds after the first solve.
    pub widening_rounds: usize,
    /// Why widening stopped: `settled`, `no_gain`, `rounds`, `stopped` or
    /// `none`; see `WideningReport::end`.
    pub widening_end: &'static str,
    /// Wall time of the probes, in microseconds.
    pub widening_probe_us: u64,
    /// Admitted skeletons the resident pair ceiling left out of the served
    /// graph.
    pub widening_left_out: usize,
    /// Pools the served graph left out for failing the liquidity test where
    /// they would only carry the trade to another token
    /// (`resident::Widening::graph`).
    pub widening_thin_left_out: usize,
    /// The served graph took back such pools, on the edges nothing else
    /// serves, or all of them when the graph without them filled nothing.
    pub widening_thin_kept: bool,
}

pub const ROUTE_UNIVERSE_SCHEMA_VERSION: u8 = 1;

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CanonicalBlockJson {
    pub number: u64,
    pub hash: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct V23FenceJson {
    /// Decimal strings retain exactness in JavaScript when the catalog runs
    /// beyond Number.MAX_SAFE_INTEGER.
    pub seq: String,
    pub generation: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct V4FenceJson {
    pub block: u64,
    pub generation: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CatalogFencesJson {
    pub v23: V23FenceJson,
    pub v4: Option<V4FenceJson>,
}

impl From<CatalogFences> for CatalogFencesJson {
    fn from(fences: CatalogFences) -> Self {
        Self {
            v23: V23FenceJson {
                seq: fences.v23.seq.to_string(),
                generation: fences.v23.generation.to_string(),
            },
            v4: fences.v4.map(|fence| V4FenceJson {
                block: fence.block,
                generation: format!("{:#x}", fence.generation),
            }),
        }
    }
}

/// Versioned proof boundary shared byte-for-byte by successful quotes and
/// structured no-route responses. A certificate covers only `scope` at this
/// canonical block; `selection_scope` records a wider shadow observation but
/// never widens that claim.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RouteUniverseJson {
    pub version: u8,
    pub chain_id: u64,
    pub canonical_block: CanonicalBlockJson,
    pub source: &'static str,
    pub fallback_stage: Option<&'static str>,
    pub fallback_reason: Option<&'static str>,
    pub scope: &'static str,
    pub selection_scope: &'static str,
    pub selector: &'static str,
    pub protocol_mask: u32,
    pub eligible_count: usize,
    pub connector_count: usize,
    pub shortlist_truncated: bool,
    pub fingerprint: String,
    pub adjacency_fences: Option<CatalogFencesJson>,
    pub topology_fences: Option<CatalogFencesJson>,
}

impl RouteUniverseJson {
    pub(crate) fn new(
        chain_id: u64,
        block: u64,
        block_hash: B256,
        universe: RouteUniverseDiagnostics,
        topology_fences: Option<CatalogFences>,
    ) -> Self {
        Self {
            version: ROUTE_UNIVERSE_SCHEMA_VERSION,
            chain_id,
            canonical_block: CanonicalBlockJson {
                number: block,
                hash: format!("{block_hash:#x}"),
            },
            source: universe.source,
            fallback_stage: universe.fallback_stage,
            fallback_reason: universe.fallback_reason,
            scope: universe.scope,
            selection_scope: universe.selection_scope,
            selector: universe.selector,
            protocol_mask: universe.protocol_mask,
            eligible_count: universe.eligible_count,
            connector_count: universe.connector_count,
            shortlist_truncated: universe.shortlist_truncated,
            fingerprint: format!("{:#x}", universe.fingerprint),
            adjacency_fences: universe.adjacency_fences.map(Into::into),
            topology_fences: topology_fences.map(Into::into),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct NoRouteError {
    pub route_universe: RouteUniverseJson,
}

impl fmt::Display for NoRouteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("no executable route within modeled depth")
    }
}

impl std::error::Error for NoRouteError {}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QuoteResponse {
    pub chain: &'static str,
    pub chain_id: u64,
    /// `amm`, `native_rfq`, or `mixed`. Mixed routes contain one linear AMM
    /// stage and one Native RFQ stage in the order shown by `route[].hops`.
    pub liquidity_source: &'static str,
    /// Echoed request semantics. Clients validate these before accepting route
    /// or transaction data so a stale/mis-keyed response cannot silently widen
    /// slippage, change the payer, or apply another fee override.
    pub slippage_bps: u32,
    pub deadline_seconds: u64,
    pub requested_fee_bps: Option<u32>,
    pub recipient: Option<String>,
    pub sender: Option<String>,
    pub tx_origin: Option<String>,
    /// AMM state remains pinned by `block` and `routeUniverse`. A selected
    /// Native v6 quote has its own later canonical observation because its
    /// signer/nonce checks and live pAMM reference do not belong to that AMM
    /// snapshot.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub native_observation: Option<CanonicalBlockJson>,
    pub block: u64,
    /// Hash and consensus timestamp of `block`, the AMM snapshot.
    pub block_hash: String,
    pub block_timestamp: u64,
    pub route_universe: RouteUniverseJson,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub settler: Option<String>,
    pub token_in: String,
    pub token_out: String,
    pub amount_in: String,
    pub amount_out_gross: String,
    pub price_impact_bps: Option<u32>,
    /// fee-free reference output for `amountIn` — see `mid_amount_out`.
    /// `null` under exactly the conditions `priceImpactBps` is.
    pub mid_amount_out: Option<String>,
    pub fee_bps: u32,
    pub amount_out_net: String,
    pub min_amount_out_net: String,
    pub deadline: u64,
    pub route: Vec<RouteLegJson>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx: Option<TxJson>,
    /// present iff a tx was built; JSON null for native input
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowance_target: Option<Option<String>>,
    /// The Settler profile's AllowanceHolder; present iff a tx was built.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowance_holder: Option<String>,
    /// `execute`, or `executeWithNativeAuthorization` when the route has a
    /// Native stage; present iff a tx was built.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entrypoint: Option<&'static str>,
    /// Present iff a tx was built; JSON null unless the entrypoint is
    /// `executeWithNativeAuthorization`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_deadline: Option<Option<u64>>,
    /// Present iff a tx was built; JSON null for native input. Approve exactly
    /// `amount` to `spender` when `current` is short, then quote again.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval: Option<Option<Approval>>,
    /// Present iff a tx was built. Only `simulated` is signable; `skipped`
    /// names the missing prerequisite in `reason` and `issues`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub simulation: Option<Simulation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issues: Option<Issues>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fee_receiver: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub positive_slippage: Option<PositiveSlippageJson>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate: Option<CertificateJson>,
    /// What the connectors the pair budget declined would actually have been
    /// worth, measured rather than bounded.
    ///
    /// Deliberately outside `certificate`. That artifact's contract is that
    /// every number in it is re-evaluatable from `prices` and the block's pool
    /// states; this one requires re-running the allocator, so folding it in
    /// would weaken the guarantee instead of extending it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub coverage: Option<CoverageJson>,
    #[serde(skip)]
    pub meta: QuoteMeta,
}

/// One connector's leave-one-out value, in output-token wei.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectorMarginalJson {
    pub token: String,
    /// This connector's share, in basis points of the achieved output — the
    /// same denominator as `gainBps`, so a connector and the total it belongs
    /// to are on one scale. Threshold against this rather than the wei amount,
    /// which is not comparable across pairs, bands, or a reusing quote.
    pub marginal_bps: String,
    /// What removing this connector from the widened universe costs. Measured
    /// against the widened universe, so two substitutable connectors cannot
    /// each claim the same gain.
    pub marginal_wei: String,
}

/// `V(U ∪ screened) − V(U)`: the coverage question, answered exactly.
///
/// `gainWei` of zero is the useful reading, and it is a proof rather than a
/// bound: `V` is monotone in the pool set, so the widened solve dominates every
/// subset, and zero means no subset of these connectors improves this quote at
/// this size.
///
/// The measurement is amortized over the topology lease, so the wei amounts here
/// can come from an earlier quote. `measuredInWei` and `ageMs` say which quote,
/// and every wei amount belongs to `measuredInWei` rather than to the amount
/// being served. Both are always present, so a fresh reading is stated as
/// `ageMs: 0` rather than left to be inferred from a missing field.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CoverageJson {
    /// The verdict, as basis points of the achieved output. **This is the field
    /// to compare and to threshold against.**
    ///
    /// It is the only one that survives reuse. The wei fields below are absolute
    /// amounts at `measuredInWei`, so a verdict reused for a larger quote in the
    /// same band publishes a `widenedWei` BELOW that quote's own `amountOutNet`
    /// — a band spans a factor of two and the served output scales with it, so
    /// this is the common case rather than a rare one. That reads as the widened
    /// universe losing to a subset of itself, which monotonicity forbids. The
    /// ratio is scale-free and does not express it.
    pub gain_bps: String,
    pub gain_wei: String,
    pub widened_wei: String,
    /// The certified ceiling on coverage regret: no plan over the widened
    /// universe beats this quote by more than this many basis points.
    ///
    /// This is the proof `gainBps`'s zero only approximates. `gainBps` compares
    /// two runs of a chunked heuristic, so its zero says the allocator found
    /// nothing over there; a `regretBoundBps` under the churn floor says
    /// nothing is there, from a dual that holds whatever the allocator did
    /// (unpublished allocator-monotonicity notes, §6).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub regret_bound_bps: Option<String>,
    /// The widened solve's own optimality gap, on the same denominator. A
    /// `gainBps` below this sits inside the measurement's own error.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub widened_gap_bps: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub widened_bound_wei: Option<String>,
    /// The input amount these wei amounts were measured at. Equal to the
    /// quote's own `amountIn` when `ageMs` is zero, within a factor of two of it
    /// otherwise — verdicts are banded by binary magnitude.
    pub measured_in_wei: String,
    /// Milliseconds since the measurement ran. Zero when this quote ran it.
    pub age_ms: u64,
    /// Connectors the widened plan routed through, richest marginal first.
    pub used: Vec<ConnectorMarginalJson>,
    /// What dropping each already-routable dynamic connector would cost,
    /// costliest first — `V(A) − V(A − a)`, on the same `achieved` denominator
    /// as `used` (docs §20).
    ///
    /// Read this beside `used` rather than on its own. A `used` entry says what
    /// ADDING that candidate is worth over a universe that already routes these
    /// incumbents; only an entry here says what losing one of these costs. A
    /// promotion is sound when a candidate's `marginalBps` exceeds an
    /// incumbent's, and unproven otherwise.
    ///
    /// An incumbent missing from this list has no reading — its leave-one-out
    /// lost monotonicity — and absent means unevictable. It never means zero.
    pub incumbents: Vec<ConnectorMarginalJson>,
    /// Admitted dynamic connectors this quote's own plan routed no flow
    /// through, and the certified ceiling on what evicting them costs (§22).
    ///
    /// These two decide admission, and both come free: `idle` reads the served
    /// plan, `lossBoundBps` is the certificate's own gap on the same `achieved`
    /// denominator as every marginal above. A candidate in `used` whose
    /// `marginalBps` exceeds `lossBoundBps` can take an `idle` connector's slot
    /// and leave the quote strictly better, with no comparison between the two
    /// connectors anywhere in the argument.
    pub idle: Vec<String>,
    pub loss_bound_bps: String,
    /// Allocator runs this measurement cost, so its price is observable. It
    /// stays at the measured cost on a reused verdict, which is the cost that
    /// was actually paid for it.
    pub solves: usize,
    /// The served plan beat the measurement's own solve over the served
    /// universe, and was used as the baseline instead. Prices the resolution
    /// difference between a quote that may have escalated and a measurement that
    /// never does.
    pub base_seeded: bool,
    /// **Read this before trusting a `gainBps` of zero.** True means the
    /// allocator did worse over the widened universe than over the served one
    /// and the served universe's plan carried the measurement — so the zero says
    /// the allocator found nothing, never that nothing is there. `regretBoundBps`
    /// is the reading that still holds, because it does not depend on the
    /// allocator.
    pub widened_seeded: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificatePriceJson {
    pub token: String,
    pub num: String,
    pub den: String,
}

/// One screened connector's value at the certificate's prices, in output wei.
/// Zero is the useful case: it says the token is provably worth nothing to
/// this quote, which is what retires a candidate rather than deferring it.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScreenedValueJson {
    pub token: String,
    pub arb_wei: String,
    /// The extended price this connector was valued at, in the same num/den
    /// shape as `prices`. It completes the checkable half for `graphBoundWei`,
    /// which `prices` alone cannot reconstruct because the relaxation prices
    /// tokens the certified dual point never names.
    pub price_num: String,
    pub price_den: String,
    /// The same sum at the price that MINIMISES it, rather than at the
    /// relaxation's upward-biased one. `arbWei − minArbWei` is §11's κ priced in
    /// output wei, and a `minArbWei` of zero is a proof that routing through this
    /// connector cannot beat the quote by more than `gapBps`
    /// (unpublished connector dual-price notes).
    ///
    /// `graphBoundWei` still uses `arbWei`. These two ship side by side so the
    /// difference is measurable before anything is decided on it.
    pub min_arb_wei: String,
    pub min_price_num: String,
    pub min_price_den: String,
}

/// The optimality certificate as a checkable artifact rather than a claim.
///
/// `prices` is the dual point; `boundWei` is what `certificate::bound_at`
/// evaluates to at that point. A holder can re-evaluate it against the same
/// block's pool states and confirm the bound without trusting — or
/// reproducing — the search that produced it. `gapBps` is what the quote
/// concedes against the best output inside the serialized materialized route
/// universe. Catalog edges that were not materialized are explicitly outside
/// this certificate.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificateJson {
    /// "active" allows a certified gap to trigger the bounded allocator
    /// escalation; "shadow" is reporting-only.
    pub mode: &'static str,
    /// Binds this artifact to `quote.routeUniverse`; clients must not display a
    /// proof claim when that versioned scope is absent or malformed.
    pub scope: &'static str,
    /// "certified", "unavailable" (with a reason), or "inconsistent" — the
    /// last meaning the bound came out below the achieved output, which weak
    /// duality forbids and which is therefore a defect signal.
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bound_wei: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gap_wei: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gap_bps: Option<String>,
    /// The same bound taken over every pool in the snapshot rather than only
    /// the ones this pair's skeletons can reach. Its optimum ranges over
    /// arbitrary flows, so it also prices triangular inconsistencies among
    /// pools the trade never touches: read it as a market-condition signal and
    /// as the coverage term `gapBps` deliberately excludes, never as a verdict
    /// on the allocator.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub catalog_gap_bps: Option<String>,
    /// The catalog bound widened to connector tokens the pair budget declined
    /// to make routable. Equal to `catalogGapBps` when screening is off, which
    /// is the one case where this quote's coverage went unmeasured rather than
    /// answered. Screened pools are priced and never routed: no plan can be
    /// built on them, and `gapBps` above is bit-identical either way.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub graph_gap_bps: Option<String>,
    /// Screened pools evaluated, and those skipped for want of a price.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub screened_pools: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub screened_unpriced: Option<usize>,
    /// What each screened connector was worth at these prices, richest first.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub screened_value: Vec<ScreenedValueJson>,
    /// Pools carrying arbitrage value at these prices that the plan never
    /// routed through.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unrouted_pools: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scanned_pools: Option<usize>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub prices: Vec<CertificatePriceJson>,
}

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
static ESCALATE_BPS_E4: LazyLock<u64> =
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

fn escalate_threshold_e4(raw: &str) -> anyhow::Result<u64> {
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

/// Certify a plan, or explain why it could not be certified. Never propagates:
/// a quote is a quote whether or not its bound could be evaluated.
fn certificate_json(
    result: anyhow::Result<certificate::Certificate>,
    allows_escalation: bool,
) -> CertificateJson {
    let mode = if allows_escalation {
        "active"
    } else {
        "shadow"
    };
    match result {
        Ok(cert) => CertificateJson {
            mode,
            scope: "materialized_route_universe",
            status: if cert.consistent {
                "certified"
            } else {
                "inconsistent"
            },
            reason: None,
            bound_wei: Some(cert.bound.to_string()),
            gap_wei: Some(cert.gap.to_string()),
            gap_bps: Some(format_bps_e4(cert.gap_bps_e4)),
            catalog_gap_bps: Some(format_bps_e4(cert.catalog_gap_bps_e4)),
            graph_gap_bps: Some(format_bps_e4(cert.graph_gap_bps_e4)),
            screened_pools: Some(cert.screened_pools),
            screened_unpriced: Some(cert.screened_unpriced),
            screened_value: cert
                .screened_value
                .iter()
                .map(|value| ScreenedValueJson {
                    token: addrhex(value.connector),
                    arb_wei: value.arb.to_string(),
                    price_num: value.price.num.to_string(),
                    price_den: value.price.den.to_string(),
                    min_arb_wei: value.min_arb.to_string(),
                    min_price_num: value.min_price.num.to_string(),
                    min_price_den: value.min_price.den.to_string(),
                })
                .collect(),
            unrouted_pools: Some(cert.unrouted_pools),
            scanned_pools: Some(cert.scanned_pools),
            prices: cert
                .prices
                .iter()
                .map(|(token, price)| CertificatePriceJson {
                    token: addrhex(*token),
                    num: price.num.to_string(),
                    den: price.den.to_string(),
                })
                .collect(),
        },
        Err(error) => CertificateJson {
            mode,
            scope: "materialized_route_universe",
            status: "unavailable",
            reason: Some(format!("{error:#}")),
            bound_wei: None,
            gap_wei: None,
            gap_bps: None,
            catalog_gap_bps: None,
            graph_gap_bps: None,
            screened_pools: None,
            screened_unpriced: None,
            screened_value: Vec::new(),
            unrouted_pools: None,
            scanned_pools: None,
            prices: Vec::new(),
        },
    }
}

fn parse_addr(s: &str) -> anyhow::Result<Address> {
    s.parse().map_err(|_| anyhow::anyhow!("bad address {s}"))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ExecutionIdentities {
    recipient: Option<Address>,
    /// Explicit request sender, preserved for response echoing.
    sender: Option<Address>,
    /// AllowanceHolder owner and Settler authorization taker.
    required_from: Option<Address>,
    /// Explicit EVM origin binding for Native Router v6.
    tx_origin: Option<Address>,
}

fn parse_execution_identities(req: &QuoteRequest) -> anyhow::Result<ExecutionIdentities> {
    let recipient = req.recipient.as_deref().map(parse_addr).transpose()?;
    let sender = req.sender.as_deref().map(parse_addr).transpose()?;
    let tx_origin = req.tx_origin.as_deref().map(parse_addr).transpose()?;
    ensure!(
        sender.is_none() || recipient.is_some(),
        "sender requires recipient"
    );
    ensure!(
        tx_origin.is_none() || recipient.is_some(),
        "txOrigin requires recipient"
    );
    ensure!(
        tx_origin != Some(Address::ZERO),
        "txOrigin must not be zero"
    );

    Ok(ExecutionIdentities {
        recipient,
        sender,
        required_from: sender.or(recipient),
        tx_origin,
    })
}

fn parse_amount(v: &AmountIn) -> anyhow::Result<U256> {
    match v {
        AmountIn::Num(n) => Ok(U256::from(*n)),
        AmountIn::Str(s) => {
            ensure!(
                !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()),
                "amountIn must be a decimal string"
            );
            U256::from_str_radix(s, 10).context("amountIn out of range")
        }
    }
}

fn routed_tokens(
    profile: &crate::chain::ChainProfile,
    token_in: Address,
    token_out: Address,
) -> (Address, Address) {
    (profile.erc20_of(token_in), profile.erc20_of(token_out))
}

fn hop_json(snap: &Snapshot, h: &Hop) -> anyhow::Result<HopJson> {
    Ok(match h.kind {
        HopKind::V3 => {
            let p = &snap.v3[h.index].0;
            let protocol = p.protocol.as_str();
            HopJson::V3 {
                protocol,
                venue: venue(protocol),
                // v4 pools have no address of their own — the PoolKey hash
                // is the canonical identity
                pool: match &p.v4 {
                    Some(v4) => format!("{:#x}", v4.pool_id),
                    None => addrhex(p.address),
                },
                token_in: addrhex(h.token_in),
                token_out: addrhex(h.token_out),
                fee_ppm: p.fee_ppm_for(h.zero_for_one)?,
                tick_spacing: p.tick_spacing,
            }
        }
        HopKind::V2 => {
            let p = &snap.v2[h.index].0;
            let protocol = p.protocol.as_str();
            HopJson::V2 {
                protocol,
                venue: venue(protocol),
                pool: addrhex(p.address),
                token_in: addrhex(h.token_in),
                token_out: addrhex(h.token_out),
                fee_bps: p.fee_bps,
            }
        }
        HopKind::Ekubo => {
            let p = &snap.ekubo[h.index].0;
            HopJson::Ekubo {
                protocol: "ekubov3",
                venue: venue("ekubov3"),
                pool: format!("{:#x}", p.pool_id),
                token_in: addrhex(h.token_in),
                token_out: addrhex(h.token_out),
                extension: p.extension.as_str(),
                pool_type: p.pool_type.as_str(),
                fee_x64: p.fee_x64.to_string(),
                fee_ppm: u32::try_from((u128::from(p.fee_x64) * u128::from(PPM_BASE)) >> 64usize)
                    .expect("Q64 fee fits ppm"),
                tick_spacing: p.pool_type.tick_spacing(),
            }
        }
    })
}

/// Quote (and, when `recipient` is given, build) a swap.
/// The selected chain's native gas token uses the API's 0xeeee…eeee sentinel.
/// Amounts are raw integer token units.
pub async fn quote_swap(
    cfg: &Config,
    engine: &Arc<Engine>,
    req: QuoteRequest,
) -> anyhow::Result<QuoteResponse> {
    Box::pin(quote_swap_checked(
        cfg,
        engine,
        req,
        SolverBudget::unlimited(),
        None,
        None,
    ))
    .await
}

/// Production quote path. CPU-heavy work runs in a bounded blocking region and
/// cooperatively observes the same deadline as the HTTP request.
pub(crate) async fn quote_swap_bounded(
    cfg: &Config,
    engine: &Arc<Engine>,
    req: QuoteRequest,
    budget: SolverBudget,
    compute_slots: Arc<Semaphore>,
    native_rfq: Option<&dyn NativeRfqSource>,
) -> anyhow::Result<QuoteResponse> {
    // Boxed: the quote's state machine is large enough to overflow a test
    // thread's stack in debug builds.
    Box::pin(quote_swap_checked(
        cfg,
        engine,
        req,
        budget,
        Some(compute_slots),
        native_rfq,
    ))
    .await
}

/// A transaction priced on one block failed its check at a later block. The
/// state it was priced on is gone, so the failure says nothing yet about the
/// route; the quote is priced once more from the block of the check.
#[derive(Debug)]
struct PricedBeforeCheck(u64);

impl std::fmt::Display for PricedBeforeCheck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "priced before block {}, where the transaction failed its check",
            self.0
        )
    }
}

/// One quote, priced again at most once when the chain moved between pricing
/// and the check. A second failure is the answer.
async fn quote_swap_checked(
    cfg: &Config,
    engine: &Arc<Engine>,
    req: QuoteRequest,
    budget: SolverBudget,
    compute_slots: Option<Arc<Semaphore>>,
    native_rfq: Option<&dyn NativeRfqSource>,
) -> anyhow::Result<QuoteResponse> {
    let first = Box::pin(quote_swap_routed(
        cfg,
        engine,
        req.clone(),
        budget.clone(),
        compute_slots.clone(),
        native_rfq,
        0,
    ))
    .await;
    let Some(&PricedBeforeCheck(block)) = first
        .as_ref()
        .err()
        .and_then(|error| error.downcast_ref::<PricedBeforeCheck>())
    else {
        return first;
    };
    let mut resp = Box::pin(quote_swap_routed(
        cfg,
        engine,
        req,
        budget,
        compute_slots,
        native_rfq,
        block,
    ))
    .await?;
    resp.meta.repriced = true;
    Ok(resp)
}

/// One quote from the resident pools when they cover the pair, and from the
/// pair's own pools otherwise. A pair the resident list covers but cannot
/// route may still have a route through a pool off the list, so the per-pair
/// path is asked before the answer is "no route".
async fn quote_swap_routed(
    cfg: &Config,
    engine: &Arc<Engine>,
    req: QuoteRequest,
    budget: SolverBudget,
    compute_slots: Option<Arc<Semaphore>>,
    native_rfq: Option<&dyn NativeRfqSource>,
    min_block: u64,
) -> anyhow::Result<QuoteResponse> {
    let first = Box::pin(quote_swap_inner(
        cfg,
        engine,
        req.clone(),
        budget.clone(),
        compute_slots.clone(),
        native_rfq,
        min_block,
        SnapshotScope::Any,
    ))
    .await;
    let resident_found_none = first
        .as_ref()
        .err()
        .and_then(|error| error.downcast_ref::<NoRouteError>())
        .is_some_and(|error| error.route_universe.source == "resident");
    if !resident_found_none {
        return first;
    }
    Box::pin(quote_swap_inner(
        cfg,
        engine,
        req,
        budget,
        compute_slots,
        native_rfq,
        min_block,
        SnapshotScope::PairOnly,
    ))
    .await
}

/// Everything needed to compare the final AMM candidate with a firm RFQ.
/// Native quotes are intentionally fetched only after this work is complete:
/// their short validity window must not be consumed by allocator escalation or
/// coverage measurement.
struct AmmEvaluation {
    route_universe: RouteUniverseJson,
    universe_diag: RouteUniverseDiagnostics,
    plan: Option<Plan>,
    /// Best linear AMM prefix into the reviewed stable bridge. The public v1
    /// route shape cannot faithfully describe a split-then-join followed by a
    /// single RFQ call, so mixed routes deliberately use one AMM leg.
    native_last_prefix: Option<Plan>,
    fair: Option<Plan>,
    fair_in: U256,
    certificate: Option<CertificateJson>,
    coverage: Option<crate::counterfactual::CoverageReading>,
    solve_ms: u64,
    certificate_us: u64,
    coverage_us: u64,
    /// The resident graph the plan was solved on, when the quote widened past
    /// the one it was stamped with. Everything after the solve reads it.
    widened: Option<Arc<Stamped>>,
    widening: WideningReport,
}

/// A resident candidate is admitted when its probes say it could add at least
/// this share of the quote (`resident::Widening::worth_admitting`): 0.1 bp, in
/// bp × 10⁴.
const WIDEN_BPS_E4: u64 = 1_000;

/// Probing and re-solving rounds a resident quote may take after its first
/// solve.
const WIDEN_ROUNDS: usize = 3;

/// What a resident quote admitted beyond the graph it started from.
#[derive(Clone, Debug)]
struct WideningReport {
    /// Why it stopped: `settled` (no candidate's probes say it could add
    /// enough), `no_gain` (a wider solve found nothing more), `rounds` (the
    /// round limit came first, so this is not known), `stopped` (a probe or
    /// graph could not be built) or `none` (no candidates).
    end: &'static str,
    /// Connectors beyond the static ones this pair's resident graph may use.
    candidates: usize,
    /// Connectors admitted on their probes, in the order admitted.
    admitted: Vec<Address>,
    /// Probing and re-solving rounds after the first solve.
    rounds: usize,
    /// Wall time of the probes, in microseconds.
    probe_us: u64,
    /// Admitted skeletons the pair ceiling left out of the served graph.
    left_out: usize,
    /// Thin pools the served graph left out, and whether it kept them.
    thin_left_out: usize,
    thin_kept: bool,
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
struct Round {
    plan: Option<Plan>,
    certificate: Option<anyhow::Result<Certificate>>,
    solve_ms: u64,
    certificate_us: u64,
}

impl Round {
    fn amount_out(&self) -> Option<U256> {
        self.plan.as_ref().map(|plan| plan.amount_out)
    }
}

/// Solve `universe` over `snap`, and keep the route set: the escalation and
/// the fair probe solve the same snapshot and universe again. Certification
/// waits for the plan that ships ([`certify_round`]).
fn solve_round<'a>(
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
fn certify_round(
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NativePlacement {
    Only,
    First,
    Last,
}

enum NativeDraft {
    Only {
        token_in: Address,
        token_out: Address,
        amount_in: U256,
    },
    First {
        token_in: Address,
        bridge: Address,
        amount_in: U256,
    },
    Last {
        bridge: Address,
        token_out: Address,
        prefix: Plan,
    },
}

impl NativeDraft {
    fn request_tokens_and_amount(&self) -> (Address, Address, U256) {
        match self {
            Self::Only {
                token_in,
                token_out,
                amount_in,
            } => (*token_in, *token_out, *amount_in),
            Self::First {
                token_in,
                bridge,
                amount_in,
            } => (*token_in, *bridge, *amount_in),
            Self::Last {
                bridge,
                token_out,
                prefix,
            } => (*bridge, *token_out, prefix.amount_out),
        }
    }
}

enum NativeRoute {
    Only {
        quote: ValidatedFirmQuote,
    },
    First {
        quote: ValidatedFirmQuote,
        suffix: Plan,
    },
    Last {
        prefix: Plan,
        quote: ValidatedFirmQuote,
    },
}

impl NativeRoute {
    fn placement(&self) -> NativePlacement {
        match self {
            Self::Only { .. } => NativePlacement::Only,
            Self::First { .. } => NativePlacement::First,
            Self::Last { .. } => NativePlacement::Last,
        }
    }

    fn quote(&self) -> &ValidatedFirmQuote {
        match self {
            Self::Only { quote } | Self::First { quote, .. } | Self::Last { quote, .. } => quote,
        }
    }

    fn amm_plan(&self) -> Option<&Plan> {
        match self {
            Self::Only { .. } => None,
            Self::First { suffix, .. } => Some(suffix),
            Self::Last { prefix, .. } => Some(prefix),
        }
    }

    fn amount_out(&self) -> U256 {
        match self {
            Self::Only { quote } | Self::Last { quote, .. } => quote.amount_out(),
            Self::First { suffix, .. } => suffix.amount_out,
        }
    }

    fn is_live_at(&self, now: u64) -> bool {
        self.quote().is_live_at(now)
    }

    fn liquidity_source(&self) -> &'static str {
        match self {
            Self::Only { .. } => "native_rfq",
            Self::First { .. } | Self::Last { .. } => "mixed",
        }
    }
}

fn native_route_beats_amm(route: &NativeRoute, amm: Option<&Plan>, now: u64) -> bool {
    route.is_live_at(now) && amm.is_none_or(|plan| route.amount_out() > plan.amount_out)
}

#[cfg(test)]
fn native_quote_beats_amm(quote: &ValidatedFirmQuote, amm: Option<&Plan>, now: u64) -> bool {
    quote.is_live_at(now) && amm.is_none_or(|plan| quote.amount_out() > plan.amount_out)
}

fn native_hop_json(quote: &ValidatedFirmQuote) -> HopJson {
    HopJson::NativeRfq {
        protocol: "nativerfq",
        venue: venue("nativerfq"),
        router: addrhex(quote.target()),
        pool: addrhex(quote.pool()),
        token_in: addrhex(quote.token_in()),
        token_out: addrhex(quote.token_out()),
        quote_deadline: quote.deadline(),
    }
}

fn linear_amm_hops(snap: &Snapshot, plan: &Plan) -> anyhow::Result<Vec<HopJson>> {
    ensure!(
        plan.legs.len() == 1,
        "mixed route AMM stage must contain exactly one leg"
    );
    plan.legs[0]
        .path
        .iter()
        .map(|hop| hop_json(snap, hop))
        .collect()
}

fn native_route_json(
    snap: &Snapshot,
    route: &NativeRoute,
    amount_in: U256,
) -> anyhow::Result<RouteLegJson> {
    let mut hops = Vec::new();
    match route {
        NativeRoute::Only { quote } => hops.push(native_hop_json(quote)),
        NativeRoute::First { quote, suffix } => {
            hops.push(native_hop_json(quote));
            hops.extend(linear_amm_hops(snap, suffix)?);
        }
        NativeRoute::Last { prefix, quote } => {
            hops.extend(linear_amm_hops(snap, prefix)?);
            hops.push(native_hop_json(quote));
        }
    }
    Ok(RouteLegJson {
        share_bps: BPS_BASE,
        amount_in: amount_in.to_string(),
        amount_out: route.amount_out().to_string(),
        hops,
    })
}

/// `Ok(None)` means the optional Native source failed in a way that permits an
/// independently fresh AMM fallback. Capacity errors remain retryable service
/// failures and never silently change an eligible request into AMM-only.
async fn optional_native_indicatives(
    source: &dyn NativeRfqSource,
    identity: crate::chain::NativeRfqProfile,
    requests: &[(NativePair, U256)],
    budget: &SolverBudget,
) -> Result<Option<Vec<(NativePair, U256, U256)>>, NativeRfqError> {
    let result = match budget.remaining() {
        None => source.indicative_quotes(identity, requests).await,
        Some(remaining) => {
            let wait = remaining.saturating_sub(OPTIONAL_RFQ_RESPONSE_RESERVE);
            if wait.is_zero() {
                return Err(NativeRfqError::QueueTimeout);
            }
            match tokio::time::timeout(wait, source.indicative_quotes(identity, requests)).await {
                Ok(result) => result,
                Err(_) => return Err(NativeRfqError::QueueTimeout),
            }
        }
    };
    match result {
        Ok(available) => Ok(Some(available)),
        Err(error) if error.is_retryable_capacity() => Err(error),
        Err(error) => {
            tracing::info!("native rfq unavailable: {error}");
            Ok(None)
        }
    }
}

/// Rank every feasible Native placement from one local orderbook observation,
/// then spend at most one request-specific firm quote on the winner. Draft
/// insertion order is the deterministic tie-break: direct, Native-last, then
/// Native-first.
#[allow(clippy::too_many_arguments)] // keeps routing, snapshot, admission and budget inputs explicit
async fn choose_native_draft(
    source: &dyn NativeRfqSource,
    identity: crate::chain::NativeRfqProfile,
    routed_tokens: (Address, Address),
    stable: Address,
    amount_in: U256,
    native_last_prefix: Option<Plan>,
    stamped: &Stamped,
    profile: &ChainProfile,
    compute_slots: Option<&Arc<Semaphore>>,
    budget: &SolverBudget,
) -> anyhow::Result<(Option<NativeDraft>, u64)> {
    let (routed_in, routed_out) = routed_tokens;
    // Keep the outbound boundary fail-closed as well as the request planner.
    // This prevents a future caller or connector-planning refactor from using
    // Native when neither final user endpoint is a reviewed stock token.
    if !identity.allows_endpoints(routed_in, routed_out) {
        return Ok((None, 0));
    }
    let mut drafts = vec![NativeDraft::Only {
        token_in: routed_in,
        token_out: routed_out,
        amount_in,
    }];
    if routed_in != stable
        && routed_out != stable
        && let Some(prefix) = native_last_prefix
    {
        drafts.push(NativeDraft::Last {
            bridge: stable,
            token_out: routed_out,
            prefix,
        });
    }
    if routed_in != stable && routed_out != stable {
        drafts.push(NativeDraft::First {
            token_in: routed_in,
            bridge: stable,
            amount_in,
        });
    }
    let requested: Vec<_> = drafts
        .iter()
        .map(|draft| {
            let (token_in, token_out, amount_in) = draft.request_tokens_and_amount();
            (NativePair::new(token_in, token_out), amount_in)
        })
        .collect();
    let Some(indicatives) =
        optional_native_indicatives(source, identity, &requested, budget).await?
    else {
        return Ok((None, 0));
    };
    let mut best: Option<(NativeDraft, U256)> = None;
    let mut solve_ms = 0u64;
    for (draft, (pair, request_amount)) in drafts.into_iter().zip(requested) {
        let Some((_, _, indicative_out)) = indicatives
            .iter()
            .find(|(candidate, amount, _)| *candidate == pair && *amount == request_amount)
        else {
            continue;
        };
        let final_out = match &draft {
            NativeDraft::First { bridge, .. } => {
                let (suffix, elapsed_ms) = solve_profile_stage_bounded(
                    stamped,
                    profile,
                    *bridge,
                    routed_out,
                    *indicative_out,
                    compute_slots,
                    budget,
                    "native indicative suffix compute admission",
                )
                .await?;
                solve_ms = solve_ms.saturating_add(elapsed_ms);
                let Some(suffix) = suffix else {
                    continue;
                };
                suffix.amount_out
            }
            NativeDraft::Only { .. } | NativeDraft::Last { .. } => *indicative_out,
        };
        if best
            .as_ref()
            .is_none_or(|(_, best_out)| final_out > *best_out)
        {
            best = Some((draft, final_out));
        }
    }
    Ok((best.map(|(draft, _)| draft), solve_ms))
}

fn fresh_amm_snapshot(stamped: &Stamped) -> anyhow::Result<&Snapshot> {
    if stamped.is_fresh_to_finish() {
        Ok(&stamped.snap)
    } else {
        Err(
            anyhow::anyhow!("AMM snapshot became stale before quote finalization")
                .context(RpcUnavailable("snapshot freshness")),
        )
    }
}

#[allow(clippy::too_many_arguments)] // mirrors the bounded top-level solve without hidden context
async fn solve_profile_stage_bounded(
    stamped: &Stamped,
    profile: &ChainProfile,
    token_in: Address,
    token_out: Address,
    amount_in: U256,
    compute_slots: Option<&Arc<Semaphore>>,
    budget: &SolverBudget,
    admission_checkpoint: &'static str,
) -> anyhow::Result<(Option<Plan>, u64)> {
    fresh_amm_snapshot(stamped)?;
    let permit = match compute_slots {
        Some(slots) => Some(
            Arc::clone(slots)
                .acquire_owned()
                .await
                .context("solver compute admission is closed")?,
        ),
        None => None,
    };
    budget.checkpoint(admission_checkpoint)?;
    fresh_amm_snapshot(stamped)?;
    let started = Instant::now();
    let solve = || -> anyhow::Result<Option<Plan>> {
        PreparedRoutes::for_profile_with_budget(
            &stamped.snap,
            profile,
            token_in,
            token_out,
            budget.clone(),
        )?
        .try_solve_single_quantized(amount_in, *ALLOC_CHUNKS)
    };
    let plan = if budget.is_bounded() {
        tokio::task::block_in_place(solve)?
    } else {
        solve()?
    };
    let solve_ms = started.elapsed().as_millis() as u64;
    drop(permit);
    Ok((plan, solve_ms))
}

fn selected_deadline(request_deadline: u64, native: Option<&ValidatedFirmQuote>) -> u64 {
    native.map_or(request_deadline, |quote| {
        request_deadline.min(quote.deadline())
    })
}

const OPTIONAL_RFQ_RESPONSE_RESERVE: Duration = Duration::from_millis(100);

fn native_result_or_fallback(
    result: Result<Option<ValidatedFirmQuote>, NativeRfqError>,
) -> Result<Option<ValidatedFirmQuote>, NativeRfqError> {
    match result {
        Ok(quote) => Ok(quote),
        Err(error) if error.is_retryable_capacity() => Err(error),
        Err(error) => {
            // Native is optional. Its failure must leave the independently
            // computed AMM candidate available for freshness-checked selection.
            tracing::info!("native rfq unavailable: {error}");
            Ok(None)
        }
    }
}

async fn request_optional_native_quote(
    source: &dyn NativeRfqSource,
    request: FirmQuoteRequest,
    budget: &SolverBudget,
) -> Result<Option<ValidatedFirmQuote>, NativeRfqError> {
    let Some(wait) = budget
        .remaining()
        .map(|remaining| remaining.saturating_sub(OPTIONAL_RFQ_RESPONSE_RESERVE))
    else {
        return native_result_or_fallback(source.firm_quote(request).await);
    };
    if wait.is_zero() {
        return Err(NativeRfqError::QueueTimeout);
    }

    match tokio::time::timeout(wait, source.firm_quote(request)).await {
        Ok(result) => native_result_or_fallback(result),
        Err(_) => Err(NativeRfqError::QueueTimeout),
    }
}

/// `min_block` is 0, or the block a retry must price from (see
/// `quote_swap_checked`).
#[allow(clippy::too_many_arguments)] // the snapshot scope joins the request's existing inputs
async fn quote_swap_inner(
    cfg: &Config,
    engine: &Arc<Engine>,
    req: QuoteRequest,
    budget: SolverBudget,
    compute_slots: Option<Arc<Semaphore>>,
    native_rfq: Option<&dyn NativeRfqSource>,
    min_block: u64,
    scope: SnapshotScope,
) -> anyhow::Result<QuoteResponse> {
    ensure!(
        engine.profile() == cfg.profile,
        "solver engine profile does not match server profile"
    );
    ensure!(
        req.chain_id == cfg.profile.chain_id,
        "chainId mismatch: solver is {}, request is {}",
        cfg.profile.chain_id,
        req.chain_id
    );
    ensure!(
        cfg.profile.capabilities.quote,
        "quotes are not enabled for {} ({})",
        cfg.profile.name,
        cfg.profile.chain_id
    );
    ensure!(
        req.recipient.is_none() || cfg.profile.execution_enabled(),
        "transaction building is not enabled for {} ({})",
        cfg.profile.name,
        cfg.profile.chain_id
    );
    let token_in = parse_addr(&req.token_in)?;
    let token_out = parse_addr(&req.token_out)?;
    let (a, b) = routed_tokens(cfg.profile, token_in, token_out);
    ensure!(a != b, "tokenIn and tokenOut are the same asset");
    let identities = parse_execution_identities(&req)?;
    let recipient = identities.recipient;
    let sender = identities.sender;
    let amount_in = parse_amount(&req.amount_in)?;
    ensure!(amount_in > U256::ZERO, "amountIn must be positive");
    ensure!(
        (0..BPS_BASE as i64).contains(&req.slippage_bps),
        "slippageBps out of range"
    );
    ensure!(req.deadline_seconds > 0, "deadlineSeconds must be positive");
    let slippage_bps = req.slippage_bps as u32;
    // The Native branch is a product policy over the user's final endpoints,
    // never over an intermediate draft leg or AMM connector. Keeping this gate
    // above all Native discovery also makes a future stock connector harmless
    // for crypto-to-crypto and stable-to-crypto requests.
    let native_identity = cfg.profile.native_rfq_for_endpoints(a, b);
    let native_planning_enabled = native_rfq.is_some()
        && native_identity.is_some()
        && recipient.is_some_and(|beneficiary| beneficiary != Address::ZERO)
        && slippage_bps > 0;
    if native_planning_enabled {
        ensure!(
            cfg.profile.connectors.contains(&cfg.profile.stable),
            "Native composition bridge is not a reviewed profile connector"
        );
    }
    let requested_fee_bps = req.fee_bps;
    let fee_bps = match requested_fee_bps {
        None => cfg.fee_bps,
        Some(bps) => {
            ensure!(
                bps <= MAX_FEE_OVERRIDE_BPS,
                "feeBps out of range (0..={MAX_FEE_OVERRIDE_BPS})"
            );
            ensure!(
                bps == 0
                    || cfg
                        .fee_receiver
                        .is_some_and(|receiver| receiver != Address::ZERO),
                "feeBps > 0 but no fee receiver is configured"
            );
            bps
        }
    };
    let t = Instant::now();
    let (mut stamped, mut source) = engine.snapshot_scoped(a, b, min_block, scope).await?;
    let mut snapshot_ms = t.elapsed().as_millis() as u64;
    budget.checkpoint("snapshot acquisition")?;
    if source == "pull" && !stamped.is_fresh() {
        return Err(
            anyhow::anyhow!("snapshot was stale when acquisition completed")
                .context(RpcUnavailable("snapshot freshness")),
        );
    }

    let _compute_permit = loop {
        let permit = match compute_slots.as_ref() {
            Some(slots) => Some(
                Arc::clone(slots)
                    .acquire_owned()
                    .await
                    .context("solver compute admission is closed")?,
            ),
            None => None,
        };
        budget.checkpoint("compute admission")?;
        if stamped.is_fresh() {
            break permit;
        }

        // Network refreshes must not occupy a scarce CPU slot. Rejoin the
        // fair compute queue after obtaining a fresh canonical snapshot.
        drop(permit);
        let t = Instant::now();
        (stamped, source) = engine.snapshot_scoped(a, b, min_block, scope).await?;
        snapshot_ms = snapshot_ms.saturating_add(t.elapsed().as_millis() as u64);
        budget.checkpoint("snapshot refresh after compute admission")?;
        if source == "pull" && !stamped.is_fresh() {
            return Err(anyhow::anyhow!("snapshot was stale when refresh completed")
                .context(RpcUnavailable("snapshot freshness")));
        }
    };

    let compute_amm = || -> anyhow::Result<AmmEvaluation> {
        budget.checkpoint("quote solve")?;
        let canonical_hash = stamped
            .block_id()
            .as_block_hash()
            .context("snapshot is not pinned to a canonical block hash")?;
        let mut universe = stamped.universe.orient(a, b)?;
        let (mut round, first_routes) = solve_round(&stamped.snap, &universe, amount_in, &budget)?;
        let mut solve_ms = round.solve_ms;

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
                                plan.amount_out * U256::from(WIDEN_BPS_E4)
                                    / U256::from(100_000_000u64),
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
                let (next_round, _) =
                    solve_round(&next.snapshot, &next_universe, amount_in, &budget)?;
                solve_ms = solve_ms.saturating_add(next_round.solve_ms);
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
                universe = next_universe;
                round = next_round;
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
                let (full_round, _) =
                    solve_round(&full.snapshot, &full_universe, amount_in, &budget)?;
                solve_ms = solve_ms.saturating_add(full_round.solve_ms);
                if full_round.plan.is_some() {
                    widening.admitted = everything
                        .into_iter()
                        .filter(|connector| !candidates.admitted().contains(connector))
                        .collect();
                    widening.left_out = full.left_out;
                    widening.thin_left_out = 0;
                    widening.thin_kept = true;
                    widening.end = "thin";
                    universe = full_universe;
                    round = full_round;
                    graph = Some(full);
                }
            }
        }
        let snap = graph
            .as_ref()
            .map_or(&stamped.snap, |graph| &graph.snapshot);
        // The shipped round's route set, for the escalation and the fair probe:
        // the first round's when no wider graph shipped (the universe changes
        // only with the graph), else one build over the graph that did.
        let routes = match &graph {
            None => first_routes,
            Some(graph) => PreparedRoutes::for_universe_with_budget(
                &graph.snapshot,
                &universe,
                budget.clone(),
            )?,
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
            &budget,
        )?;
        let certificate_us = round.certificate_us;
        let universe_diag = universe.diagnostics();
        let route_universe = RouteUniverseJson::new(
            cfg.profile.chain_id,
            snap.block,
            canonical_hash,
            universe_diag,
            stamped.topology_fences,
        );

        let t = Instant::now();
        let native_last_prefix =
            if native_planning_enabled && a != cfg.profile.stable && b != cfg.profile.stable {
                PreparedRoutes::for_profile_with_budget(
                    snap,
                    cfg.profile,
                    a,
                    cfg.profile.stable,
                    budget.clone(),
                )?
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
                &budget,
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
    };

    let mut amm = if budget.is_bounded() {
        tokio::task::block_in_place(compute_amm)?
    } else {
        compute_amm()?
    };
    // Network I/O must not occupy one of the scarce CPU admission slots.
    drop(_compute_permit);
    // Whatever follows reads the graph the plan was solved on.
    if let Some(widened) = amm.widened.take() {
        stamped = widened;
    }

    // One cached orderbook observation prices every feasible placement. Only
    // the best skeleton may consume a request-specific firm quote. The firm
    // quote remains the last network input acquired so its TTL is not spent on
    // the full AMM solve, certificate escalation, or coverage measurement.
    budget.checkpoint("native RFQ request")?;
    let native_context = match (native_rfq, recipient, native_identity, stamped.snap.settler) {
        (Some(source), Some(beneficiary), Some(identity), Some(settler))
            if beneficiary != Address::ZERO && slippage_bps > 0 =>
        {
            Some((source, beneficiary, identity, settler))
        }
        _ => None,
    };
    let rfq_attempted = native_context.is_some();
    let rfq_started = Instant::now();
    let (native_draft, native_indicative_solve_ms) = match native_context {
        Some((source, _, identity, _)) => {
            choose_native_draft(
                source,
                identity,
                (a, b),
                cfg.profile.stable,
                amount_in,
                amm.native_last_prefix.clone(),
                &stamped,
                cfg.profile,
                compute_slots.as_ref(),
                &budget,
            )
            .await?
        }
        None => (None, 0),
    };
    amm.solve_ms = amm.solve_ms.saturating_add(native_indicative_solve_ms);
    let native_quote = match (native_context, native_draft.as_ref()) {
        (Some((source, beneficiary, identity, settler)), Some(draft)) => {
            let (native_token_in, native_token_out, native_amount_in) =
                draft.request_tokens_and_amount();
            request_optional_native_quote(
                source,
                FirmQuoteRequest {
                    identity,
                    token_in: native_token_in,
                    token_out: native_token_out,
                    amount_in: native_amount_in,
                    settler,
                    beneficiary,
                    tx_origin: identities.tx_origin,
                    slippage_bps,
                    expiry_seconds: req.deadline_seconds as u64,
                    chain_timestamp: stamped.chain_now(),
                },
                &budget,
            )
            .await?
        }
        _ => None,
    };
    let rfq_ms = if rfq_attempted {
        rfq_started.elapsed().as_millis() as u64
    } else {
        0
    };
    budget.checkpoint("native RFQ response")?;

    let rfq_quoted = native_quote.is_some();
    let native_route = match (native_draft, native_quote) {
        (Some(NativeDraft::Only { .. }), Some(quote)) => Some(NativeRoute::Only { quote }),
        (Some(NativeDraft::Last { prefix, .. }), Some(quote)) => {
            Some(NativeRoute::Last { prefix, quote })
        }
        (Some(NativeDraft::First { bridge, .. }), Some(quote)) => {
            // A Native-first suffix must be solved from the firm output, not an
            // indicative orderbook amount. Re-enter the same bounded compute
            // queue and keep the network wait outside that scarce region.
            let (suffix, suffix_solve_ms) = solve_profile_stage_bounded(
                &stamped,
                cfg.profile,
                bridge,
                b,
                quote.amount_out(),
                compute_slots.as_ref(),
                &budget,
                "native suffix compute admission",
            )
            .await?;
            amm.solve_ms = amm.solve_ms.saturating_add(suffix_solve_ms);
            match suffix {
                Some(suffix) => Some(NativeRoute::First { quote, suffix }),
                None => {
                    tracing::info!(
                        "native rfq unavailable: firm output has no executable AMM suffix"
                    );
                    None
                }
            }
        }
        _ => None,
    };

    let selection_now = stamped.chain_now();
    if native_route
        .as_ref()
        .is_some_and(|route| !route.is_live_at(selection_now))
    {
        tracing::info!("native rfq unavailable: quote lost its minimum TTL before selection");
    }
    let native_wins_at_selection = native_route
        .as_ref()
        .is_some_and(|route| native_route_beats_amm(route, amm.plan.as_ref(), selection_now));
    if !native_wins_at_selection && amm.plan.is_none() {
        return Err(NoRouteError {
            route_universe: amm.route_universe,
        }
        .into());
    }

    budget.checkpoint("quote assembly")?;
    let AmmEvaluation {
        route_universe,
        universe_diag,
        plan,
        native_last_prefix: _,
        fair,
        fair_in,
        certificate,
        coverage,
        solve_ms,
        certificate_us,
        coverage_us,
        widened: _,
        widening,
    } = amm;
    let snap = &stamped.snap;
    let snapshot_hash = stamped
        .block_id()
        .as_block_hash()
        .context("snapshot is not pinned to a canonical block hash")?;
    // Re-evaluate immediately before transaction assembly. If Native's
    // minimum-TTL window elapsed after comparison, use the AMM candidate only
    // while its own snapshot remains fresh.
    let finalization_now = stamped.chain_now();
    let native_selected_at_comparison = native_route.as_ref().filter(|_| native_wins_at_selection);
    let selected_native =
        native_selected_at_comparison.filter(|route| route.is_live_at(finalization_now));
    if native_selected_at_comparison.is_some() && selected_native.is_none() {
        tracing::info!("native rfq unavailable: quote lost its minimum TTL before encoding");
    }
    let native_wins = selected_native.is_some();
    if !native_wins && plan.is_none() {
        return Err(NoRouteError { route_universe }.into());
    }
    // Even a Native-only firm quote is bound to the Settler identity read from
    // this snapshot. Never assemble it after that Registry observation becomes
    // stale; the caller can retry against a fresh identity and obtain a new
    // beneficiary-bound firm quote.
    fresh_amm_snapshot(&stamped)?;
    let selected_plan = if native_wins { None } else { plan.as_ref() };
    let response_certificate = if native_wins { None } else { certificate };
    let response_coverage = if native_wins { None } else { coverage.as_ref() };
    let coverage_json = response_coverage.map(|reading| CoverageJson {
        gain_bps: format_bps_e4(reading.value.gain_bps_e4),
        gain_wei: reading.value.total_gain.to_string(),
        widened_wei: reading.value.widened_out.to_string(),
        regret_bound_bps: reading.value.regret_bound_bps_e4.map(format_bps_e4),
        widened_gap_bps: reading.value.widened_gap_bps_e4.map(format_bps_e4),
        widened_bound_wei: reading.value.widened_bound.map(|bound| bound.to_string()),
        measured_in_wei: reading.measured_in.to_string(),
        age_ms: reading.age.as_millis() as u64,
        used: reading
            .value
            .marginals
            .iter()
            .map(|marginal| ConnectorMarginalJson {
                token: addrhex(marginal.connector),
                marginal_bps: format_bps_e4(marginal.marginal_bps_e4),
                marginal_wei: marginal.marginal_out.to_string(),
            })
            .collect(),
        incumbents: reading
            .value
            .incumbents
            .iter()
            .map(|loss| ConnectorMarginalJson {
                token: addrhex(loss.connector),
                marginal_bps: format_bps_e4(loss.marginal_bps_e4),
                marginal_wei: loss.marginal_out.to_string(),
            })
            .collect(),
        idle: reading.value.idle.iter().copied().map(addrhex).collect(),
        loss_bound_bps: format_bps_e4(reading.value.loss_bound_bps_e4),
        solves: reading.value.solves,
        base_seeded: reading.value.base_seeded,
        widened_seeded: reading.value.widened_seeded,
    });

    let (price_impact_bps, mid_amount_out) = if let Some(plan) = selected_plan {
        reference_metrics(snap, plan, fair.as_ref(), fair_in, amount_in)?
    } else {
        (None, None)
    };
    let gross = selected_native.map_or_else(
        || selected_plan.expect("AMM plan checked above").amount_out,
        NativeRoute::amount_out,
    );
    let gross_min = muldiv(
        gross,
        U256::from(BPS_BASE - slippage_bps),
        U256::from(BPS_BASE),
    )?;
    let request_deadline = finalization_now
        .checked_add(req.deadline_seconds as u64)
        .context("deadline overflow")?;
    let deadline = selected_deadline(request_deadline, selected_native.map(NativeRoute::quote));
    let amount_out_net = net_after_fee(gross, fee_bps)?;
    let min_amount_out_net = net_after_fee(gross_min, fee_bps)?;
    let positive_slippage = if cfg.positive_slippage_max_bps == 0 {
        None
    } else {
        ensure!(
            cfg.positive_slippage_max_bps <= BPS_BASE,
            "positive slippage max bps out of range"
        );
        Some(PositiveSlippage {
            recipient: cfg
                .positive_slippage_recipient
                .context("positive slippage recipient is not configured")?,
            expected_amount: amount_out_net,
            max_bps: cfg.positive_slippage_max_bps,
        })
    };

    let (prebuilt_native_tx, native_encode_ms) = if let Some(native_route) = selected_native {
        budget.checkpoint("transaction encoding")?;
        let recipient = recipient.expect("Native RFQ requests require a recipient");
        let sender = identities
            .required_from
            .expect("recipient supplies the default sender");
        ensure!(sender != Address::ZERO, "sender must not be zero");
        let t = Instant::now();
        let authorizer = cfg
            .native_rfq
            .as_ref()
            .context("Native RFQ selected without a beneficiary authorizer")?
            .authorizer();
        let quote = native_route.quote();
        let native_stage = ComposedSwapStage::NativeRfq {
            quote,
            token_in: quote.token_in(),
            token_out: quote.token_out(),
        };
        let amm_stage = native_route
            .amm_plan()
            .map(|plan| ComposedSwapStage::Amm { plan });
        let stages = match native_route.placement() {
            NativePlacement::Only => vec![native_stage],
            NativePlacement::First => {
                vec![native_stage, amm_stage.expect("Native-first AMM stage")]
            }
            NativePlacement::Last => {
                vec![amm_stage.expect("Native-last AMM stage"), native_stage]
            }
        };
        let tx = build_composed_native_rfq_tx_for_profile(
            cfg.profile,
            authorizer,
            sender,
            fee_bps,
            cfg.fee_receiver,
            positive_slippage,
            snap,
            &stages,
            token_in,
            token_out,
            amount_in,
            min_amount_out_net,
            recipient,
            finalization_now,
            deadline,
        )?;
        (Some(tx), t.elapsed().as_millis() as u64)
    } else {
        (None, 0)
    };

    let mut route = Vec::with_capacity(selected_native.map_or_else(
        || selected_plan.expect("AMM plan checked above").legs.len(),
        |_| 1,
    ));
    if let Some(native_route) = selected_native {
        route.push(native_route_json(snap, native_route, amount_in)?);
    } else {
        for leg in &selected_plan.expect("AMM plan checked above").legs {
            route.push(RouteLegJson {
                share_bps: u32::try_from(muldiv(leg.amount_in, U256::from(BPS_BASE), amount_in)?)
                    .context("share bps out of range")?,
                amount_in: leg.amount_in.to_string(),
                amount_out: leg.amount_out.to_string(),
                hops: leg
                    .path
                    .iter()
                    .map(|h| hop_json(snap, h))
                    .collect::<anyhow::Result<_>>()?,
            });
        }
    }

    let mut resp = QuoteResponse {
        chain: cfg.profile.key,
        chain_id: cfg.profile.chain_id,
        liquidity_source: selected_native.map_or("amm", NativeRoute::liquidity_source),
        slippage_bps,
        deadline_seconds: req.deadline_seconds as u64,
        requested_fee_bps,
        recipient: recipient.map(addrhex),
        sender: sender.map(addrhex),
        tx_origin: identities.tx_origin.map(addrhex),
        native_observation: selected_native
            .map(NativeRoute::quote)
            .map(|quote| {
                quote
                    .observation()
                    .context("selected Native RFQ quote has no canonical observation")
                    .map(|observation| CanonicalBlockJson {
                        number: observation.number,
                        hash: format!("{:#x}", observation.hash),
                    })
            })
            .transpose()?,
        block: snap.block,
        block_hash: format!("{snapshot_hash:#x}"),
        block_timestamp: stamped.block_timestamp(),
        route_universe,
        settler: snap.settler.map(addrhex),
        token_in: addrhex(token_in),
        token_out: addrhex(token_out),
        amount_in: amount_in.to_string(),
        amount_out_gross: gross.to_string(),
        price_impact_bps,
        mid_amount_out: mid_amount_out.map(|out| out.to_string()),
        fee_bps,
        amount_out_net: amount_out_net.to_string(),
        min_amount_out_net: min_amount_out_net.to_string(),
        deadline,
        route,
        tx: None,
        allowance_target: None,
        allowance_holder: None,
        entrypoint: None,
        authorization_deadline: None,
        approval: None,
        simulation: None,
        issues: None,
        fee_receiver: None,
        positive_slippage: None,
        certificate: response_certificate,
        coverage: coverage_json,
        meta: QuoteMeta {
            certificate_us,
            snapshot_ms,
            snapshot_rpc_calls: if source == "pull" {
                stamped.rpc_calls()
            } else {
                0
            },
            solve_ms,
            encode_ms: native_encode_ms,
            simulate_ms: 0,
            repriced: false,
            rfq_ms,
            rfq_attempted,
            rfq_quoted,
            rfq_selected: native_wins,
            source,
            universe_source: universe_diag.source,
            universe_fallback_stage: universe_diag.fallback_stage,
            universe_fallback_reason: universe_diag.fallback_reason,
            universe_scope: universe_diag.scope,
            universe_selection_scope: universe_diag.selection_scope,
            universe_selector: universe_diag.selector,
            universe_protocol_mask: universe_diag.protocol_mask,
            universe_eligible_count: universe_diag.eligible_count,
            universe_connector_count: universe_diag.connector_count,
            universe_screened_count: universe_diag.screened_count,
            coverage_gain: response_coverage.map(|r| r.value.total_gain),
            coverage_used: response_coverage.map_or(0, |r| r.value.used.len()),
            coverage_solves: response_coverage.map_or(0, |r| r.value.solves),
            coverage_age_ms: response_coverage.map(|r| r.age.as_millis() as u64),
            coverage_us,
            universe_shortlist_truncated: universe_diag.shortlist_truncated,
            universe_fingerprint: universe_diag.fingerprint,
            adjacency_fences: universe_diag.adjacency_fences,
            topology_fences: stamped.topology_fences,
            widening_candidates: widening.candidates,
            widened: widening.admitted,
            widening_rounds: widening.rounds,
            widening_end: widening.end,
            widening_probe_us: widening.probe_us,
            widening_left_out: widening.left_out,
            widening_thin_left_out: widening.thin_left_out,
            widening_thin_kept: widening.thin_kept,
        },
    };

    if let Some(recipient) = recipient {
        let sender = identities
            .required_from
            .expect("recipient supplies the default sender");
        ensure!(sender != Address::ZERO, "sender must not be zero");
        let native_entry = prebuilt_native_tx.is_some();
        let tx = match prebuilt_native_tx {
            Some(tx) => tx,
            None => {
                budget.checkpoint("transaction encoding")?;
                let fresh_snap = fresh_amm_snapshot(&stamped)?;
                let t = Instant::now();
                let tx = build_swap_tx_for_profile(
                    cfg.profile,
                    fee_bps,
                    cfg.fee_receiver,
                    positive_slippage,
                    fresh_snap,
                    selected_plan.expect("AMM plan checked above"),
                    token_in,
                    token_out,
                    amount_in,
                    min_amount_out_net,
                    recipient,
                    deadline,
                )?;
                resp.meta.encode_ms = t.elapsed().as_millis() as u64;
                tx
            }
        };
        budget.checkpoint("transaction simulation")?;
        let t = Instant::now();
        let rpc = engine.rpc();
        let simulation_block = simulation::simulation_block(
            rpc,
            CanonicalBlock {
                number: snap.block,
                hash: snapshot_hash,
                timestamp: stamped.block_timestamp(),
            },
        )
        .await?;
        let report = match Box::pin(simulation::verify(
            rpc,
            &tx,
            sender,
            token_in,
            amount_in,
            simulation_block,
        ))
        .await
        {
            // Only AMM routes are priced again: a second Native firm quote
            // would be spent on a market maker's price that did not move.
            Err(error)
                if min_block == 0
                    && !native_entry
                    && simulation_block.number > snap.block
                    && error
                        .downcast_ref::<simulation::SimulationFailed>()
                        .is_some() =>
            {
                return Err(error.context(PricedBeforeCheck(simulation_block.number)));
            }
            report => report?,
        };
        resp.meta.simulate_ms = t.elapsed().as_millis() as u64;
        budget.checkpoint("transaction simulation")?;
        resp.tx = Some(TxJson {
            required_from: addrhex(sender),
            to: addrhex(tx.to),
            value: tx.value.to_string(),
            data: tohex(&tx.data),
        });
        resp.allowance_target = Some(tx.allowance_target.map(addrhex));
        resp.allowance_holder = Some(addrhex(
            cfg.profile
                .settler
                .context("transaction built without a Settler profile")?
                .allowance_holder,
        ));
        resp.entrypoint = Some(if native_entry {
            "executeWithNativeAuthorization"
        } else {
            "execute"
        });
        resp.authorization_deadline = Some(native_entry.then_some(deadline));
        resp.approval = Some(report.approval);
        resp.simulation = Some(report.simulation);
        resp.issues = Some(report.issues);
        // "" when unset, matching the Julia responses byte-for-byte
        resp.fee_receiver = Some(cfg.fee_receiver.map(addrhex).unwrap_or_default());
        resp.positive_slippage = positive_slippage.map(|positive_slippage| PositiveSlippageJson {
            recipient: addrhex(positive_slippage.recipient),
            token: addrhex(if token_out == NATIVE {
                NATIVE
            } else {
                cfg.profile.erc20_of(token_out)
            }),
            expected_amount: positive_slippage.expected_amount.to_string(),
            max_bps: positive_slippage.max_bps,
        });
    }
    // A built transaction was encoded from a fresh snapshot and then checked
    // at the chain head, which supersedes the snapshot's age. A quote without
    // one rests on the snapshot alone, so it must still be fresh.
    if recipient.is_none() && !native_wins {
        fresh_amm_snapshot(&stamped)?;
    }
    Ok(resp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::{
        BSC_NATIVE_RFQ, BSC_PROFILE, BSC_USD1, BSC_USDT, ChainProfile, FIXTURE_NATIVE_RFQ,
        FIXTURE_PROFILE, FIXTURE_USDT0, FIXTURE_WETH, WBNB,
    };
    use crate::pools::{
        AlgebraMeta, V2Pool, V2Protocol, V2State, V3Pool, V3Protocol, V3State, sim_v2,
    };
    use crate::rfq::{NativeBeneficiaryAuthorizer, NativeRfqConfig};
    use crate::state::ObservedSnapshot;
    use alloy::eips::BlockId;
    use alloy_primitives::Bytes;
    use futures_util::future::BoxFuture;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const TEST_BENEFICIARY_KEY: &str =
        "0x59c6995e998f97a5a0044976f0945389dc9e86dae88c7a8412f4603b6b78690d";
    const MIXED_STOCK: Address = Address::repeat_byte(0xa5);
    const MIXED_SETTLER: Address = Address::repeat_byte(0x77);
    const MIXED_STOCK_TOKENS: [Address; 1] = [MIXED_STOCK];
    const MIXED_CONNECTORS: [Address; 4] = [WBNB, BSC_USDT, BSC_USD1, MIXED_STOCK];
    static MIXED_NATIVE_RFQ: std::sync::LazyLock<crate::chain::NativeRfqProfile> =
        std::sync::LazyLock::new(|| crate::chain::NativeRfqProfile {
            stock_tokens: &MIXED_STOCK_TOKENS,
            ..*BSC_NATIVE_RFQ
        });
    static MIXED_TEST_PROFILE: std::sync::LazyLock<ChainProfile> =
        std::sync::LazyLock::new(|| ChainProfile {
            connectors: &MIXED_CONNECTORS,
            native_rfq: Some(*MIXED_NATIVE_RFQ),
            settler: Some(crate::chain::with_native_entry(*crate::chain::BSC_SETTLER)),
            ..*BSC_PROFILE
        });

    fn put_word(calldata: &mut [u8], offset: usize, value: U256) {
        calldata[offset..offset + 32].copy_from_slice(&value.to_be_bytes::<32>());
    }

    fn put_quote_address(calldata: &mut [u8], index: usize, value: Address) {
        let offset = 4 + 96 + index * 32;
        calldata[offset + 12..offset + 32].copy_from_slice(value.as_slice());
    }

    fn mock_native_calldata(request: FirmQuoteRequest, amount_out: U256, deadline: u64) -> Bytes {
        let mut calldata = vec![0u8; 4 + 96 + 16 * 32];
        calldata[..4].copy_from_slice(&request.identity.trade_selector);
        put_word(&mut calldata, 4, U256::from(96u64));
        put_quote_address(&mut calldata, 0, request.identity.pool);
        put_quote_address(&mut calldata, 2, request.settler);
        put_quote_address(&mut calldata, 3, request.token_in);
        put_quote_address(&mut calldata, 4, request.token_out);
        put_word(&mut calldata, 4 + 96 + 5 * 32, request.amount_in);
        put_word(&mut calldata, 4 + 96 + 6 * 32, amount_out);
        put_word(&mut calldata, 4 + 96 + 8 * 32, U256::from(deadline));
        put_quote_address(&mut calldata, 14, request.settler);
        put_quote_address(
            &mut calldata,
            15,
            request.tx_origin.unwrap_or(Address::ZERO),
        );
        calldata.into()
    }

    fn mock_validated_quote(request: FirmQuoteRequest, amount_out: U256) -> ValidatedFirmQuote {
        let deadline = request.chain_timestamp + 60;
        ValidatedFirmQuote {
            target: request.identity.router,
            pool: request.identity.pool,
            calldata: mock_native_calldata(request, amount_out, deadline),
            token_in: request.token_in,
            token_out: request.token_out,
            settler: request.settler,
            expected_origin: request.tx_origin.unwrap_or(Address::ZERO),
            amount_in: request.amount_in,
            amount_out,
            signer: Address::repeat_byte(0x66),
            nonce: U256::from(7u64),
            beneficiary: request.beneficiary,
            deadline,
            min_ttl_seconds: 10,
            amount_in_offset: 36,
            amount_out_minimum_offset: 68,
            router_version: request.identity.router_version,
            observation: Some(crate::rfq::NativeQuoteObservation {
                number: 2,
                hash: B256::repeat_byte(0x44),
            }),
        }
    }

    struct PlannedNativeSource {
        indicatives: Vec<(NativePair, U256)>,
        amount_out: U256,
        delay: Duration,
        pair_calls: AtomicUsize,
        firm_calls: AtomicUsize,
        requests: Mutex<Vec<FirmQuoteRequest>>,
    }

    impl PlannedNativeSource {
        fn new(available: Vec<NativePair>, amount_out: U256) -> Self {
            Self {
                indicatives: available
                    .into_iter()
                    .map(|pair| (pair, amount_out))
                    .collect(),
                amount_out,
                delay: Duration::ZERO,
                pair_calls: AtomicUsize::new(0),
                firm_calls: AtomicUsize::new(0),
                requests: Mutex::new(Vec::new()),
            }
        }

        fn with_indicatives(indicatives: Vec<(NativePair, U256)>, firm_amount_out: U256) -> Self {
            Self {
                indicatives,
                amount_out: firm_amount_out,
                delay: Duration::ZERO,
                pair_calls: AtomicUsize::new(0),
                firm_calls: AtomicUsize::new(0),
                requests: Mutex::new(Vec::new()),
            }
        }

        fn with_delay(mut self, delay: Duration) -> Self {
            self.delay = delay;
            self
        }
    }

    impl NativeRfqSource for PlannedNativeSource {
        fn indicative_quotes<'a>(
            &'a self,
            _identity: crate::chain::NativeRfqProfile,
            requests: &'a [(NativePair, U256)],
        ) -> BoxFuture<'a, Result<Vec<(NativePair, U256, U256)>, NativeRfqError>> {
            Box::pin(async move {
                self.pair_calls.fetch_add(1, Ordering::SeqCst);
                Ok(requests
                    .iter()
                    .filter_map(|(pair, amount_in)| {
                        self.indicatives
                            .iter()
                            .find(|(candidate, _)| candidate == pair)
                            .map(|(_, amount_out)| (*pair, *amount_in, *amount_out))
                    })
                    .collect())
            })
        }

        fn available_pairs<'a>(
            &'a self,
            _identity: crate::chain::NativeRfqProfile,
            pairs: &'a [NativePair],
        ) -> BoxFuture<'a, Result<Vec<NativePair>, NativeRfqError>> {
            Box::pin(async move {
                self.pair_calls.fetch_add(1, Ordering::SeqCst);
                Ok(pairs
                    .iter()
                    .filter(|pair| {
                        self.indicatives
                            .iter()
                            .any(|(candidate, _)| candidate == *pair)
                    })
                    .copied()
                    .collect())
            })
        }

        fn firm_quote<'a>(
            &'a self,
            request: FirmQuoteRequest,
        ) -> BoxFuture<'a, Result<Option<ValidatedFirmQuote>, NativeRfqError>> {
            Box::pin(async move {
                self.firm_calls.fetch_add(1, Ordering::SeqCst);
                self.requests.lock().unwrap().push(request);
                tokio::time::sleep(self.delay).await;
                Ok(Some(mock_validated_quote(request, self.amount_out)))
            })
        }
    }

    fn mixed_config() -> Config {
        let authorizer = NativeBeneficiaryAuthorizer::from_secret(TEST_BENEFICIARY_KEY).unwrap();
        Config {
            profile: &MIXED_TEST_PROFILE,
            rpc_url: MIXED_TEST_PROFILE.public_rpc.to_string(),
            logs_rpc_url: MIXED_TEST_PROFILE.public_rpc.to_string(),
            indexer_url: None,
            native_rfq: Some(
                NativeRfqConfig::new(
                    "https://v2.api.native.org/swap-api-v2/",
                    "test-api-key",
                    Duration::from_millis(500),
                    60,
                    10,
                    authorizer,
                )
                .unwrap(),
            ),
            fee_bps: 0,
            fee_receiver: None,
            positive_slippage_max_bps: 0,
            positive_slippage_recipient: None,
            port: 0,
            quote_timeout: 5,
        }
    }

    fn mixed_observation(token_in: Address, token_out: Address) -> ObservedSnapshot {
        ObservedSnapshot {
            snapshot: Snapshot {
                block: 1,
                settler: Some(MIXED_SETTLER),
                v3: Vec::new(),
                v2: vec![(
                    V2Pool {
                        protocol: V2Protocol::PANCAKEV2,
                        address: Address::repeat_byte(0x88),
                        token0: WBNB,
                        token1: BSC_USDT,
                        fee_bps: 25,
                    },
                    V2State {
                        reserve0: U256::from(10u64).pow(U256::from(24u64)),
                        reserve1: U256::from(10u64).pow(U256::from(24u64)),
                    },
                )],
                ekubo: Vec::new(),
            },
            screening: Default::default(),
            universe: crate::universe::RouteUniverse::profile_only(
                &MIXED_TEST_PROFILE,
                token_in,
                token_out,
            )
            .unwrap(),
            topology_fences: None,
            block_id: BlockId::hash_canonical(B256::repeat_byte(0x33)),
            block_timestamp: 1_800_000_000,
            observed_at: Instant::now(),
        }
    }

    fn mixed_request(token_in: Address, token_out: Address, amount_in: U256) -> QuoteRequest {
        let taker = Address::repeat_byte(0x99);
        QuoteRequest {
            chain_id: MIXED_TEST_PROFILE.chain_id,
            token_in: format!("{token_in:#x}"),
            token_out: format!("{token_out:#x}"),
            amount_in: AmountIn::Str(amount_in.to_string()),
            slippage_bps: 50,
            recipient: Some(format!("{taker:#x}")),
            sender: Some(format!("{taker:#x}")),
            tx_origin: Some(format!("{taker:#x}")),
            deadline_seconds: 60,
            fee_bps: None,
        }
    }

    use crate::simulation::test_chain::{
        RevertFirst, SIMULATION_HEAD, SimulationChain, TOO_MUCH_SLIPPAGE, simulation_chain,
    };

    #[tokio::test(flavor = "multi_thread")]
    async fn solver_builds_amm_then_native_as_one_ordered_path() {
        let amount_in = U256::from(10u64).pow(U256::from(18u64));
        let observation = mixed_observation(WBNB, MIXED_STOCK);
        let expected_prefix =
            PreparedRoutes::for_profile(&observation.snapshot, &MIXED_TEST_PROFILE, WBNB, BSC_USDT)
                .unwrap()
                .try_solve_single_quantized(amount_in, *ALLOC_CHUNKS)
                .unwrap()
                .expect("WBNB/USDT prefix");
        let (rpc, server) = simulation_chain(SimulationChain::funded());
        let engine = Engine::for_profile(rpc, &MIXED_TEST_PROFILE);
        engine.cache_snapshot_for_test(WBNB, MIXED_STOCK, observation);
        let native_out = U256::from(2u64) * amount_in;
        let source = PlannedNativeSource::with_indicatives(
            vec![
                (
                    NativePair::new(WBNB, MIXED_STOCK),
                    amount_in * U256::from(2u64),
                ),
                (
                    NativePair::new(BSC_USDT, MIXED_STOCK),
                    amount_in * U256::from(3u64),
                ),
            ],
            native_out,
        );

        let response = quote_swap_bounded(
            &mixed_config(),
            &engine,
            mixed_request(WBNB, MIXED_STOCK, amount_in),
            SolverBudget::for_duration(Duration::from_secs(5)),
            Arc::new(Semaphore::new(1)),
            Some(&source),
        )
        .await
        .unwrap();

        assert_eq!(response.liquidity_source, "mixed");
        assert_eq!(response.amount_out_gross, native_out.to_string());
        assert!(response.certificate.is_none());
        assert!(response.coverage.is_none());
        assert!(response.tx.is_some());
        assert_eq!(response.entrypoint, Some("executeWithNativeAuthorization"));
        assert_eq!(
            response.authorization_deadline,
            Some(Some(response.deadline))
        );
        assert_eq!(response.simulation.as_ref().unwrap().status, "simulated");
        server.abort();
        assert_eq!(response.route.len(), 1);
        assert_eq!(response.route[0].hops.len(), 2);
        assert!(matches!(response.route[0].hops[0], HopJson::V2 { .. }));
        assert!(matches!(
            response.route[0].hops[1],
            HopJson::NativeRfq { .. }
        ));
        assert_eq!(source.pair_calls.load(Ordering::SeqCst), 1);
        assert_eq!(source.firm_calls.load(Ordering::SeqCst), 1);
        let requests = source.requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].token_in, BSC_USDT);
        assert_eq!(requests[0].token_out, MIXED_STOCK);
        assert_eq!(requests[0].amount_in, expected_prefix.amount_out);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn solver_reprices_amm_tail_from_native_firm_output() {
        let amount_in = U256::from(10u64).pow(U256::from(18u64));
        let native_out = U256::from(3u64) * amount_in;
        let observation = mixed_observation(MIXED_STOCK, WBNB);
        let expected_suffix =
            PreparedRoutes::for_profile(&observation.snapshot, &MIXED_TEST_PROFILE, BSC_USDT, WBNB)
                .unwrap()
                .try_solve_single_quantized(native_out, *ALLOC_CHUNKS)
                .unwrap()
                .expect("USDT/WBNB suffix");
        let (rpc, server) = simulation_chain(SimulationChain::funded());
        let engine = Engine::for_profile(rpc, &MIXED_TEST_PROFILE);
        engine.cache_snapshot_for_test(MIXED_STOCK, WBNB, observation);
        let source = PlannedNativeSource::with_indicatives(
            vec![
                (
                    NativePair::new(MIXED_STOCK, WBNB),
                    amount_in * U256::from(2u64),
                ),
                (
                    NativePair::new(MIXED_STOCK, BSC_USDT),
                    amount_in * U256::from(3u64),
                ),
            ],
            native_out,
        );

        let response = quote_swap_bounded(
            &mixed_config(),
            &engine,
            mixed_request(MIXED_STOCK, WBNB, amount_in),
            SolverBudget::for_duration(Duration::from_secs(5)),
            Arc::new(Semaphore::new(1)),
            Some(&source),
        )
        .await
        .unwrap();

        assert_eq!(response.liquidity_source, "mixed");
        assert_eq!(
            response.amount_out_gross,
            expected_suffix.amount_out.to_string()
        );
        assert!(response.tx.is_some());
        assert_eq!(response.simulation.as_ref().unwrap().status, "simulated");
        server.abort();
        assert_eq!(response.route.len(), 1);
        assert_eq!(response.route[0].hops.len(), 2);
        assert!(matches!(
            response.route[0].hops[0],
            HopJson::NativeRfq { .. }
        ));
        assert!(matches!(response.route[0].hops[1], HopJson::V2 { .. }));
        assert_eq!(source.pair_calls.load(Ordering::SeqCst), 1);
        assert_eq!(source.firm_calls.load(Ordering::SeqCst), 1);
        let requests = source.requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].token_in, MIXED_STOCK);
        assert_eq!(requests[0].token_out, BSC_USDT);
        assert_eq!(requests[0].amount_in, amount_in);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn non_stock_endpoints_never_query_native() {
        let amount_in = U256::from(10u64).pow(U256::from(18u64));
        assert!(MIXED_TEST_PROFILE.connectors.contains(&MIXED_STOCK));
        let observation = mixed_observation(WBNB, BSC_USDT);
        let chain = SimulationChain::funded();
        let (rpc, server) = simulation_chain(chain.clone());
        let engine = Engine::for_profile(rpc, &MIXED_TEST_PROFILE);
        engine.cache_snapshot_for_test(WBNB, BSC_USDT, observation);
        let source = PlannedNativeSource::with_indicatives(
            vec![(
                NativePair::new(WBNB, BSC_USDT),
                amount_in * U256::from(100u64),
            )],
            amount_in * U256::from(100u64),
        );

        let response = quote_swap_bounded(
            &mixed_config(),
            &engine,
            mixed_request(WBNB, BSC_USDT, amount_in),
            SolverBudget::for_duration(Duration::from_secs(5)),
            Arc::new(Semaphore::new(1)),
            Some(&source),
        )
        .await
        .unwrap();

        assert_eq!(response.liquidity_source, "amm");
        assert!(response.tx.is_some());
        let holder = MIXED_TEST_PROFILE.settler.unwrap().allowance_holder;
        assert_eq!(response.allowance_holder, Some(addrhex(holder)));
        assert_eq!(response.entrypoint, Some("execute"));
        assert_eq!(response.authorization_deadline, Some(None));
        let approval = response.approval.clone().unwrap().unwrap();
        assert_eq!(approval.spender, addrhex(holder));
        assert_eq!(approval.amount, amount_in.to_string());
        let simulation = response.simulation.clone().unwrap();
        assert_eq!(simulation.status, "simulated");
        assert_eq!(simulation.block, SIMULATION_HEAD);
        assert_eq!(
            simulation.block_hash,
            format!("{:#x}", B256::repeat_byte(0x44))
        );
        assert_eq!(simulation.gas_estimate.as_deref(), Some("200000"));
        assert_eq!(response.issues, Some(Issues::default()));
        let mut calls = chain.calls();
        calls.sort();
        assert_eq!(
            calls,
            [
                "eth_call",
                "eth_call",
                "eth_call",
                "eth_estimateGas",
                "eth_gasPrice",
                "eth_getBalance",
                "eth_getBlockByNumber",
            ]
        );
        assert!(response.route[0].hops.iter().all(|hop| matches!(
            hop,
            HopJson::V2 {
                venue: "pancakev2",
                ..
            }
        )));
        server.abort();
        assert!(!response.meta.rfq_attempted);
        assert!(!response.meta.rfq_quoted);
        assert!(!response.meta.rfq_selected);
        assert_eq!(response.meta.rfq_ms, 0);
        assert_eq!(source.pair_calls.load(Ordering::SeqCst), 0);
        assert_eq!(source.firm_calls.load(Ordering::SeqCst), 0);
        assert!(response.route.iter().all(|leg| {
            leg.hops
                .iter()
                .all(|hop| !matches!(hop, HopJson::NativeRfq { .. }))
        }));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn native_draft_ties_prefer_direct_and_still_use_one_firm_quote() {
        let amount_in = U256::from(10u64).pow(U256::from(18u64));
        let observation = mixed_observation(WBNB, MIXED_STOCK);
        let (rpc, server) = simulation_chain(SimulationChain::funded());
        let engine = Engine::for_profile(rpc, &MIXED_TEST_PROFILE);
        engine.cache_snapshot_for_test(WBNB, MIXED_STOCK, observation);
        let tied_out = amount_in * U256::from(3u64);
        let source = PlannedNativeSource::with_indicatives(
            vec![
                (NativePair::new(WBNB, MIXED_STOCK), tied_out),
                (NativePair::new(BSC_USDT, MIXED_STOCK), tied_out),
            ],
            tied_out,
        );

        let response = quote_swap_bounded(
            &mixed_config(),
            &engine,
            mixed_request(WBNB, MIXED_STOCK, amount_in),
            SolverBudget::for_duration(Duration::from_secs(5)),
            Arc::new(Semaphore::new(1)),
            Some(&source),
        )
        .await
        .unwrap();

        assert_eq!(response.liquidity_source, "native_rfq");
        assert_eq!(response.simulation.as_ref().unwrap().status, "simulated");
        assert!(matches!(
            response.route[0].hops[0],
            HopJson::NativeRfq {
                venue: "native",
                ..
            }
        ));
        server.abort();
        assert_eq!(response.route.len(), 1);
        assert_eq!(response.route[0].hops.len(), 1);
        assert!(matches!(
            response.route[0].hops[0],
            HopJson::NativeRfq { .. }
        ));
        assert_eq!(source.pair_calls.load(Ordering::SeqCst), 1);
        assert_eq!(source.firm_calls.load(Ordering::SeqCst), 1);
        let requests = source.requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].token_in, WBNB);
        assert_eq!(requests[0].token_out, MIXED_STOCK);
        assert_eq!(requests[0].amount_in, amount_in);
    }

    #[tokio::test]
    async fn native_draft_ties_prefer_last_over_first() {
        let amount_in = U256::from(10u64).pow(U256::from(18u64));
        let first_indicative_out = amount_in * U256::from(2u64);
        let mut observation = mixed_observation(WBNB, MIXED_STOCK);
        observation.snapshot.v2.push((
            V2Pool {
                protocol: V2Protocol::PANCAKEV2,
                address: Address::repeat_byte(0x89),
                token0: BSC_USDT,
                token1: MIXED_STOCK,
                fee_bps: 25,
            },
            V2State {
                reserve0: U256::from(10u64).pow(U256::from(24u64)),
                reserve1: U256::from(10u64).pow(U256::from(24u64)),
            },
        ));
        let prefix =
            PreparedRoutes::for_profile(&observation.snapshot, &MIXED_TEST_PROFILE, WBNB, BSC_USDT)
                .unwrap()
                .try_solve_single_quantized(amount_in, *ALLOC_CHUNKS)
                .unwrap()
                .expect("WBNB/USDT prefix");
        let first_final_out = PreparedRoutes::for_profile(
            &observation.snapshot,
            &MIXED_TEST_PROFILE,
            BSC_USDT,
            MIXED_STOCK,
        )
        .unwrap()
        .try_solve_single_quantized(first_indicative_out, *ALLOC_CHUNKS)
        .unwrap()
        .expect("USDT/stock suffix")
        .amount_out;
        let engine = Engine::for_profile(
            crate::rpc::Rpc::connect("http://127.0.0.1:1").unwrap(),
            &MIXED_TEST_PROFILE,
        );
        let stamped = engine.cache_snapshot_for_test(WBNB, MIXED_STOCK, observation);
        let source = PlannedNativeSource::with_indicatives(
            vec![
                (NativePair::new(BSC_USDT, MIXED_STOCK), first_final_out),
                (NativePair::new(WBNB, BSC_USDT), first_indicative_out),
            ],
            first_final_out,
        );

        let (draft, _) = choose_native_draft(
            &source,
            *MIXED_NATIVE_RFQ,
            (WBNB, MIXED_STOCK),
            BSC_USDT,
            amount_in,
            Some(prefix),
            &stamped,
            &MIXED_TEST_PROFILE,
            None,
            &SolverBudget::unlimited(),
        )
        .await
        .unwrap();

        assert!(matches!(draft, Some(NativeDraft::Last { .. })));
        assert_eq!(source.pair_calls.load(Ordering::SeqCst), 1);
        assert_eq!(source.firm_calls.load(Ordering::SeqCst), 0);
    }

    async fn amm_quote_against(chain: SimulationChain) -> anyhow::Result<QuoteResponse> {
        amm_quote_priced_at(chain, 1, Default::default()).await
    }

    /// The WBNB/USDT snapshot of `mixed_observation`, at `block`.
    fn amm_observation_at(block: u64) -> ObservedSnapshot {
        let mut observation = mixed_observation(WBNB, BSC_USDT);
        observation.snapshot.block = block;
        observation
    }

    /// An AMM quote priced on a snapshot of `block`, checked against `chain`
    /// at `SIMULATION_HEAD`. `engine` is filled in before the quote starts, so
    /// the chain's hooks can reach the engine.
    async fn amm_quote_priced_at(
        chain: SimulationChain,
        block: u64,
        engine: Arc<std::sync::OnceLock<Arc<Engine>>>,
    ) -> anyhow::Result<QuoteResponse> {
        let amount_in = U256::from(10u64).pow(U256::from(18u64));
        let (rpc, server) = simulation_chain(chain);
        let engine = engine
            .get_or_init(|| Engine::for_profile(rpc, &MIXED_TEST_PROFILE))
            .clone();
        engine.cache_snapshot_for_test(WBNB, BSC_USDT, amm_observation_at(block));
        let result = quote_swap_bounded(
            &mixed_config(),
            &engine,
            mixed_request(WBNB, BSC_USDT, amount_in),
            SolverBudget::for_duration(Duration::from_secs(5)),
            Arc::new(Semaphore::new(1)),
            None,
        )
        .await;
        server.abort();
        result
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn short_allowance_skips_simulation_and_names_the_approval() {
        let chain = SimulationChain {
            allowance: U256::from(7u64),
            ..SimulationChain::funded()
        };
        let response = amm_quote_against(chain.clone()).await.unwrap();

        let simulation = response.simulation.unwrap();
        assert_eq!(simulation.status, "skipped");
        assert_eq!(simulation.reason, Some("allowance"));
        assert_eq!(simulation.gas_estimate, None);
        let issues = response.issues.unwrap();
        let shortfall = issues.allowance.unwrap();
        assert_eq!(shortfall.available, "7");
        assert_eq!(issues.balance, None);
        let approval = response.approval.unwrap().unwrap();
        assert_eq!(approval.current, "7");
        assert_eq!(approval.amount, shortfall.required);
        assert!(response.tx.is_some());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_call_that_reverts_for_want_of_the_allowance_is_not_a_failure() {
        // The call goes out beside the allowance read and reverts in
        // transferFrom; the shortfall, not the revert, is the answer.
        let chain = SimulationChain {
            allowance: U256::from(7u64),
            revert: true,
            ..SimulationChain::funded()
        };
        let response = amm_quote_against(chain.clone()).await.unwrap();

        let simulation = response.simulation.unwrap();
        assert_eq!(simulation.status, "skipped");
        assert_eq!(simulation.reason, Some("allowance"));
        assert!(response.issues.unwrap().allowance.is_some());
        assert!(response.tx.is_some());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn short_balance_is_reported_before_the_allowance() {
        let chain = SimulationChain {
            balance: U256::ZERO,
            allowance: U256::ZERO,
            ..SimulationChain::funded()
        };
        let response = amm_quote_against(chain).await.unwrap();

        let simulation = response.simulation.unwrap();
        assert_eq!(simulation.status, "skipped");
        assert_eq!(simulation.reason, Some("balance"));
        let issues = response.issues.unwrap();
        assert!(issues.balance.is_some() && issues.allowance.is_some());
    }

    fn estimates(chain: &SimulationChain) -> usize {
        chain
            .calls()
            .iter()
            .filter(|call| *call == "eth_estimateGas")
            .count()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_reverting_transaction_is_not_offered() {
        let chain = SimulationChain {
            revert: true,
            ..SimulationChain::funded()
        };
        // Priced on the block it is checked at: the revert is the answer.
        let Err(error) =
            amm_quote_priced_at(chain.clone(), SIMULATION_HEAD, Default::default()).await
        else {
            panic!("a reverting transaction was offered");
        };

        let failed = error
            .downcast_ref::<simulation::SimulationFailed>()
            .expect("a revert is a failed simulation");
        assert_eq!(failed.block.number, SIMULATION_HEAD);
        assert_eq!(
            failed.revert.as_deref().map(|data| &data[..4]),
            Some(TOO_MUCH_SLIPPAGE.as_slice())
        );
        assert!(error.downcast_ref::<PricedBeforeCheck>().is_none());
        assert_eq!(estimates(&chain), 1);
    }

    /// A chain whose first check reverts because a trade landed after the
    /// quote was priced; the engine then holds a snapshot of the new head.
    fn chain_moving_on(
        engine: &Arc<std::sync::OnceLock<Arc<Engine>>>,
        revert: bool,
    ) -> SimulationChain {
        let engine = engine.clone();
        SimulationChain {
            revert,
            revert_first: Some(RevertFirst::new(move || {
                engine.get().expect("engine").cache_snapshot_for_test(
                    WBNB,
                    BSC_USDT,
                    amm_observation_at(SIMULATION_HEAD),
                );
            })),
            ..SimulationChain::funded()
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_check_failed_after_the_chain_moved_is_priced_again() {
        let engine = Arc::<std::sync::OnceLock<Arc<Engine>>>::default();
        let chain = chain_moving_on(&engine, false);

        let response = amm_quote_priced_at(chain.clone(), 1, engine)
            .await
            .expect("priced again from the block of the check");

        assert!(response.meta.repriced);
        assert_eq!(response.block, SIMULATION_HEAD);
        let simulation = response.simulation.unwrap();
        assert_eq!(simulation.status, "simulated");
        assert_eq!(simulation.block, SIMULATION_HEAD);
        assert_eq!(estimates(&chain), 2);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_route_is_priced_again_only_once() {
        let engine = Arc::<std::sync::OnceLock<Arc<Engine>>>::default();
        let chain = chain_moving_on(&engine, true);

        let Err(error) = amm_quote_priced_at(chain.clone(), 1, engine).await else {
            panic!("a reverting transaction was offered");
        };

        let failed = error
            .downcast_ref::<simulation::SimulationFailed>()
            .expect("the second revert is the answer");
        assert_eq!(failed.block.number, SIMULATION_HEAD);
        assert!(error.downcast_ref::<PricedBeforeCheck>().is_none());
        assert_eq!(estimates(&chain), 2);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_native_route_is_not_priced_again() {
        let amount_in = U256::from(10u64).pow(U256::from(18u64));
        let chain = SimulationChain {
            revert: true,
            ..SimulationChain::funded()
        };
        let (rpc, server) = simulation_chain(chain.clone());
        let engine = Engine::for_profile(rpc, &MIXED_TEST_PROFILE);
        // Priced a block before the check.
        engine.cache_snapshot_for_test(WBNB, MIXED_STOCK, mixed_observation(WBNB, MIXED_STOCK));
        let source = PlannedNativeSource::with_indicatives(
            vec![
                (
                    NativePair::new(WBNB, MIXED_STOCK),
                    amount_in * U256::from(2u64),
                ),
                (
                    NativePair::new(BSC_USDT, MIXED_STOCK),
                    amount_in * U256::from(3u64),
                ),
            ],
            U256::from(2u64) * amount_in,
        );

        let result = quote_swap_bounded(
            &mixed_config(),
            &engine,
            mixed_request(WBNB, MIXED_STOCK, amount_in),
            SolverBudget::for_duration(Duration::from_secs(5)),
            Arc::new(Semaphore::new(1)),
            Some(&source),
        )
        .await;
        server.abort();

        let Err(error) = result else {
            panic!("a reverting transaction was offered");
        };
        assert!(
            error
                .downcast_ref::<simulation::SimulationFailed>()
                .is_some()
        );
        assert!(error.downcast_ref::<PricedBeforeCheck>().is_none());
        // One firm quote, never a second one for the same request.
        assert_eq!(source.firm_calls.load(Ordering::SeqCst), 1);
        assert_eq!(estimates(&chain), 1);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn fixture_quotes_simulate_and_name_their_venue() {
        let amount_in = U256::from(10u64).pow(U256::from(18u64));
        let reserve = U256::from(10u64).pow(U256::from(24u64));
        let pair = alloy_primitives::address!("00bf5210b24d371e3df88179da61b2cd83ab44ee");
        let observation = ObservedSnapshot {
            snapshot: Snapshot {
                block: 1,
                settler: Some(Address::repeat_byte(0x5e)),
                v3: vec![],
                v2: vec![(
                    V2Pool {
                        protocol: V2Protocol::UNIV2,
                        address: pair,
                        token0: FIXTURE_WETH,
                        token1: FIXTURE_USDT0,
                        fee_bps: crate::chain::FIXTURE_V2_FEE_PPM / 100,
                    },
                    V2State {
                        reserve0: reserve,
                        reserve1: reserve,
                    },
                )],
                ekubo: vec![],
            },
            ..empty_fixture_observation(Instant::now())
        };
        let observation = ObservedSnapshot {
            block_id: BlockId::hash_canonical(B256::repeat_byte(0x33)),
            ..observation
        };
        let chain = SimulationChain::funded();
        let (rpc, server) = simulation_chain(chain.clone());
        let engine = Engine::for_profile(rpc, &FIXTURE_PROFILE);
        engine.cache_snapshot_for_test(FIXTURE_WETH, FIXTURE_USDT0, observation);
        let taker = Address::repeat_byte(0x99);
        let cfg = Config {
            profile: &FIXTURE_PROFILE,
            rpc_url: FIXTURE_PROFILE.public_rpc.to_string(),
            logs_rpc_url: FIXTURE_PROFILE.public_rpc.to_string(),
            indexer_url: None,
            native_rfq: None,
            fee_bps: 0,
            fee_receiver: None,
            positive_slippage_max_bps: 0,
            positive_slippage_recipient: None,
            port: 0,
            quote_timeout: 5,
        };

        let response = quote_swap_bounded(
            &cfg,
            &engine,
            QuoteRequest {
                chain_id: FIXTURE_PROFILE.chain_id,
                token_in: format!("{FIXTURE_WETH:#x}"),
                token_out: format!("{FIXTURE_USDT0:#x}"),
                amount_in: AmountIn::Str(amount_in.to_string()),
                slippage_bps: 50,
                recipient: Some(format!("{taker:#x}")),
                sender: None,
                tx_origin: None,
                deadline_seconds: 120,
                fee_bps: None,
            },
            SolverBudget::for_duration(Duration::from_secs(5)),
            Arc::new(Semaphore::new(1)),
            None,
        )
        .await
        .unwrap();
        server.abort();

        assert_eq!(
            response.block_hash,
            format!("{:#x}", B256::repeat_byte(0x33))
        );
        assert_eq!(response.block_timestamp, 1_000);
        assert_eq!(
            response.allowance_holder,
            Some(addrhex(crate::chain::FIXTURE_ALLOWANCE_HOLDER))
        );
        let simulation = response.simulation.unwrap();
        assert_eq!(simulation.status, "simulated");
        assert!(matches!(
            response.route[0].hops[0],
            HopJson::V2 {
                protocol: "univ2",
                venue: "univ2",
                ..
            }
        ));
        let value = serde_json::to_value(&response.route[0].hops[0]).unwrap();
        assert_eq!(value["venue"], "univ2");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn native_only_quote_rejects_a_stale_settler_observation() {
        let amount_in = U256::from(10u64).pow(U256::from(18u64));
        let token_out = Address::repeat_byte(0xa6);
        let mut observation = mixed_observation(MIXED_STOCK, token_out);
        observation.observed_at = Instant::now()
            .checked_sub(Duration::from_millis(1_500))
            .unwrap();
        let engine = Engine::for_profile(
            crate::rpc::Rpc::connect("http://127.0.0.1:1").unwrap(),
            &MIXED_TEST_PROFILE,
        );
        engine.cache_snapshot_for_test(MIXED_STOCK, token_out, observation);
        let source = PlannedNativeSource::new(
            vec![NativePair::new(MIXED_STOCK, token_out)],
            amount_in * U256::from(2u64),
        )
        // 2.4 s old after the wait: past the bound and its finishing grace.
        .with_delay(Duration::from_millis(900));

        let result = quote_swap_bounded(
            &mixed_config(),
            &engine,
            mixed_request(MIXED_STOCK, token_out, amount_in),
            SolverBudget::for_duration(Duration::from_secs(5)),
            Arc::new(Semaphore::new(1)),
            Some(&source),
        )
        .await;
        let error = match result {
            Ok(_) => panic!("stale Settler observation was accepted"),
            Err(error) => error,
        };

        assert_eq!(
            error
                .downcast_ref::<RpcUnavailable>()
                .map(|marker| marker.0),
            Some("snapshot freshness")
        );
        assert_eq!(source.firm_calls.load(Ordering::SeqCst), 1);
    }

    fn fixture_weth_usdt0_v2(reserve_weth: U256, reserve_usdt0: U256) -> (V2Pool, V2State) {
        (
            V2Pool {
                protocol: V2Protocol::UNIV2,
                address: alloy_primitives::address!("00bf5210b24d371e3df88179da61b2cd83ab44ee"),
                token0: FIXTURE_WETH,
                token1: FIXTURE_USDT0,
                fee_bps: crate::chain::FIXTURE_V2_FEE_PPM / 100,
            },
            V2State {
                reserve0: reserve_weth,
                reserve1: reserve_usdt0,
            },
        )
    }

    fn fixture_config() -> Config {
        Config {
            profile: &FIXTURE_PROFILE,
            rpc_url: FIXTURE_PROFILE.public_rpc.to_string(),
            logs_rpc_url: FIXTURE_PROFILE.public_rpc.to_string(),
            indexer_url: None,
            native_rfq: None,
            fee_bps: 0,
            fee_receiver: None,
            positive_slippage_max_bps: 0,
            positive_slippage_recipient: None,
            port: 0,
            quote_timeout: 5,
        }
    }

    fn fixture_request(amount_in: U256) -> QuoteRequest {
        QuoteRequest {
            chain_id: FIXTURE_PROFILE.chain_id,
            token_in: format!("{FIXTURE_WETH:#x}"),
            token_out: format!("{FIXTURE_USDT0:#x}"),
            amount_in: AmountIn::Str(amount_in.to_string()),
            slippage_bps: 50,
            recipient: Some(format!("{:#x}", Address::repeat_byte(0x99))),
            sender: None,
            tx_origin: None,
            deadline_seconds: 120,
            fee_bps: None,
        }
    }

    /// An engine whose resident state holds `pool` at block 2 and whose
    /// per-pair memory holds the deep WETH/USDT0 pair at block 1.
    fn fixture_engine_with_resident(rpc: crate::rpc::Rpc, pool: (V2Pool, V2State)) -> Arc<Engine> {
        fixture_engine_with_resident_pools(rpc, vec![pool], &[])
    }

    /// `fixture_engine_with_resident` with `pools`, `connectors` resident
    /// connectors.
    fn fixture_engine_with_resident_pools(
        rpc: crate::rpc::Rpc,
        pools: Vec<(V2Pool, V2State)>,
        connectors: &[Address],
    ) -> Arc<Engine> {
        fixture_engine_with_resident_connectors(rpc, pools, connectors, Vec::new())
    }

    /// `fixture_engine_with_resident_pools` whose resident state also admits
    /// `others` where they have pools.
    fn fixture_engine_with_resident_connectors(
        rpc: crate::rpc::Rpc,
        pools: Vec<(V2Pool, V2State)>,
        connectors: &[Address],
        others: Vec<Address>,
    ) -> Arc<Engine> {
        fixture_engine_with_resident_state(rpc, Vec::new(), pools, connectors, others)
    }

    /// `fixture_engine_with_resident_connectors` with V3 pools as well.
    fn fixture_engine_with_resident_state(
        rpc: crate::rpc::Rpc,
        v3: Vec<(crate::pools::V3Pool, crate::pools::V3State)>,
        pools: Vec<(V2Pool, V2State)>,
        connectors: &[Address],
        others: Vec<Address>,
    ) -> Arc<Engine> {
        let resident = crate::resident::Resident::with_connectors(
            &FIXTURE_PROFILE,
            rpc.clone(),
            crate::resident::Settings {
                list_url: "http://127.0.0.1:1/pools".to_string(),
                poll: Duration::from_secs(1),
                connectors: Vec::new(),
                full_read: None,
            },
            vec![FIXTURE_WETH, FIXTURE_USDT0],
            connectors.iter().copied().chain(others).collect(),
        )
        .unwrap();
        resident.publish_for_test(
            Snapshot {
                block: 2,
                settler: Some(Address::repeat_byte(0x5e)),
                v3,
                v2: pools,
                ekubo: vec![],
            },
            crate::rpc::CanonicalBlock {
                number: 2,
                hash: B256::repeat_byte(0x22),
                timestamp: 1_002,
            },
            Instant::now(),
        );
        let engine = Engine::for_profile_with_resident(rpc, &FIXTURE_PROFILE, None, Some(resident));
        let reserve = U256::from(10u64).pow(U256::from(24u64));
        let observation = ObservedSnapshot {
            snapshot: Snapshot {
                block: 1,
                settler: Some(Address::repeat_byte(0x5e)),
                v3: vec![],
                v2: vec![fixture_weth_usdt0_v2(reserve, reserve)],
                ekubo: vec![],
            },
            block_id: BlockId::hash_canonical(B256::repeat_byte(0x11)),
            ..empty_fixture_observation(Instant::now())
        };
        engine.cache_snapshot_for_test(FIXTURE_WETH, FIXTURE_USDT0, observation);
        engine
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_covered_pair_is_quoted_from_the_resident_state() {
        let amount_in = U256::from(10u64).pow(U256::from(18u64));
        let reserve = U256::from(10u64).pow(U256::from(24u64));
        let (rpc, server) = simulation_chain(SimulationChain::funded());
        let engine = fixture_engine_with_resident(rpc, fixture_weth_usdt0_v2(reserve, reserve));
        let response = quote_swap_bounded(
            &fixture_config(),
            &engine,
            fixture_request(amount_in),
            SolverBudget::for_duration(Duration::from_secs(5)),
            Arc::new(Semaphore::new(1)),
            None,
        )
        .await
        .unwrap();
        server.abort();
        assert_eq!(response.meta.source, "resident");
        assert_eq!(response.meta.universe_source, "resident");
        assert_eq!(response.meta.snapshot_rpc_calls, 0);
        assert_eq!(response.block, 2);
        assert_eq!(
            response.block_hash,
            format!("{:#x}", B256::repeat_byte(0x22))
        );
        assert_eq!(response.simulation.unwrap().status, "simulated");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_resident_connector_carries_a_route_the_resident_state_has_no_other_way_for() {
        let amount_in = U256::from(10u64).pow(U256::from(18u64));
        let reserve = U256::from(10u64).pow(U256::from(24u64));
        let connector = alloy_primitives::address!("f5634d07bfcd83152164629679076ec413a25688");
        let pool = |address: u8, a: Address, b: Address| {
            let (token0, token1) = if a < b { (a, b) } else { (b, a) };
            (
                V2Pool {
                    protocol: V2Protocol::UNIV2,
                    address: Address::repeat_byte(address),
                    token0,
                    token1,
                    fee_bps: crate::chain::FIXTURE_V2_FEE_PPM / 100,
                },
                V2State {
                    reserve0: reserve,
                    reserve1: reserve,
                },
            )
        };
        let pools = vec![
            pool(0xb1, FIXTURE_WETH, connector),
            pool(0xb2, connector, FIXTURE_USDT0),
        ];
        let (rpc, server) = simulation_chain(SimulationChain::funded());
        let engine = fixture_engine_with_resident_pools(rpc, pools, &[connector]);
        let response = quote_swap_bounded(
            &fixture_config(),
            &engine,
            fixture_request(amount_in),
            SolverBudget::for_duration(Duration::from_secs(5)),
            Arc::new(Semaphore::new(1)),
            None,
        )
        .await
        .unwrap();
        server.abort();
        assert_eq!(response.meta.source, "resident");
        assert_eq!(response.meta.snapshot_rpc_calls, 0);
        assert_eq!(response.meta.universe_connector_count, 1);
        assert_eq!(response.block, 2);
        let through: Vec<(String, String)> = response
            .route
            .iter()
            .flat_map(|leg| &leg.hops)
            .map(|hop| match hop {
                HopJson::V2 {
                    token_in,
                    token_out,
                    ..
                } => (token_in.clone(), token_out.clone()),
                _ => panic!("only V2 pools are resident"),
            })
            .collect();
        assert_eq!(
            through,
            vec![
                (format!("{FIXTURE_WETH:#x}"), format!("{connector:#x}")),
                (format!("{connector:#x}"), format!("{FIXTURE_USDT0:#x}")),
            ]
        );
        assert_eq!(response.simulation.unwrap().status, "simulated");
    }

    /// A resident WETH→USDT0 quote with a thin direct pool at one for one and
    /// a USDC route on deep pools paying `usdc_per_weth_bps` / 10⁴ per WETH.
    async fn quote_beside_a_usdc_route(usdc_per_weth_bps: u64) -> QuoteResponse {
        let amount_in = U256::from(10u64).pow(U256::from(18u64));
        let deep = U256::from(10u64).pow(U256::from(24u64));
        let pool = |address: u8, a: Address, b: Address, reserve_a: U256, reserve_b: U256| {
            let ((token0, reserve0), (token1, reserve1)) = if a < b {
                ((a, reserve_a), (b, reserve_b))
            } else {
                ((b, reserve_b), (a, reserve_a))
            };
            (
                V2Pool {
                    protocol: V2Protocol::UNIV2,
                    address: Address::repeat_byte(address),
                    token0,
                    token1,
                    fee_bps: crate::chain::FIXTURE_V2_FEE_PPM / 100,
                },
                V2State { reserve0, reserve1 },
            )
        };
        let thin = U256::from(10u64).pow(U256::from(20u64));
        let pools = vec![
            pool(0xb1, FIXTURE_WETH, FIXTURE_USDT0, thin, thin),
            pool(
                0xb2,
                FIXTURE_WETH,
                crate::chain::FIXTURE_USDC,
                deep,
                deep * U256::from(usdc_per_weth_bps) / U256::from(10_000),
            ),
            pool(0xb3, crate::chain::FIXTURE_USDC, FIXTURE_USDT0, deep, deep),
        ];
        let (rpc, server) = simulation_chain(SimulationChain::funded());
        let engine = fixture_engine_with_resident_connectors(
            rpc,
            pools,
            &[],
            vec![crate::chain::FIXTURE_USDC],
        );
        let quote = || async {
            quote_swap_bounded(
                &fixture_config(),
                &engine,
                fixture_request(amount_in),
                SolverBudget::for_duration(Duration::from_secs(5)),
                Arc::new(Semaphore::new(1)),
                None,
            )
            .await
            .unwrap()
        };
        let response = quote().await;
        // The same request at the same block widens the same way: nothing is
        // remembered between quotes.
        let again = quote().await;
        server.abort();
        assert_eq!(response.meta.source, "resident");
        assert_eq!(response.meta.widening_candidates, 1);
        assert_eq!(again.block, response.block);
        assert_eq!(again.amount_out_gross, response.amount_out_gross);
        assert_eq!(hops(&again), hops(&response));
        assert_eq!(again.meta.widened, response.meta.widened);
        assert_eq!(again.meta.widening_rounds, response.meta.widening_rounds);
        response
    }

    fn hops(response: &QuoteResponse) -> Vec<(String, String)> {
        response
            .route
            .iter()
            .flat_map(|leg| &leg.hops)
            .map(|hop| match hop {
                HopJson::V2 {
                    token_in,
                    token_out,
                    ..
                } => (token_in.clone(), token_out.clone()),
                _ => panic!("only V2 pools are resident"),
            })
            .collect()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_resident_quote_admits_a_connector_its_probe_finds_better() {
        let response = quote_beside_a_usdc_route(20_000).await;
        assert_eq!(response.meta.widened, vec![crate::chain::FIXTURE_USDC]);
        assert_eq!(response.meta.widening_rounds, 1);
        assert_eq!(response.meta.widening_end, "settled");
        assert_eq!(response.meta.widening_left_out, 0);
        assert_eq!(response.meta.universe_connector_count, 1);
        assert!(
            hops(&response).contains(&(
                format!("{FIXTURE_WETH:#x}"),
                format!("{:#x}", crate::chain::FIXTURE_USDC)
            )),
            "routed through USDC"
        );
        // Widened in place: the same block, and a transaction built and
        // checked from the wider graph.
        assert_eq!(response.block, 2);
        assert_eq!(response.simulation.unwrap().status, "simulated");
        assert!(
            U256::from_str_radix(&response.amount_out_gross, 10).unwrap()
                > U256::from(10u64).pow(U256::from(18u64)),
            "more than the thin pool's one for one"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_resident_quote_leaves_a_connector_probed_as_no_better_unrouted() {
        // Half a USDT0 per WETH through USDC cannot beat the direct pool at
        // one for one. Its probe says so without a second solve.
        let response = quote_beside_a_usdc_route(5_000).await;
        assert!(response.meta.widened.is_empty());
        assert_eq!(response.meta.widening_rounds, 0);
        assert_eq!(response.meta.widening_end, "settled");
        assert_eq!(response.meta.universe_connector_count, 0);
        assert_eq!(
            hops(&response),
            vec![(format!("{FIXTURE_WETH:#x}"), format!("{FIXTURE_USDT0:#x}"))]
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_skeleton_through_two_candidates_admits_both() {
        // WETH → R1 → R2 → USDT0 on deep pools at two for one, beside a thin
        // direct pool at one for one. R1 and R2 are resident connectors.
        let amount_in = U256::from(10u64).pow(U256::from(18u64));
        let deep = U256::from(10u64).pow(U256::from(24u64));
        let thin = U256::from(10u64).pow(U256::from(20u64));
        let (r1, r2) = (
            alloy_primitives::address!("f5634d07bfcd83152164629679076ec413a25688"),
            alloy_primitives::address!("444c8672b00fd1da2c135552a1ae06923424f5cc"),
        );
        let pool = |address: u8, a: Address, b: Address, reserve_a: U256, reserve_b: U256| {
            let ((token0, reserve0), (token1, reserve1)) = if a < b {
                ((a, reserve_a), (b, reserve_b))
            } else {
                ((b, reserve_b), (a, reserve_a))
            };
            (
                V2Pool {
                    protocol: V2Protocol::UNIV2,
                    address: Address::repeat_byte(address),
                    token0,
                    token1,
                    fee_bps: crate::chain::FIXTURE_V2_FEE_PPM / 100,
                },
                V2State { reserve0, reserve1 },
            )
        };
        let pools = vec![
            pool(0xb1, FIXTURE_WETH, FIXTURE_USDT0, thin, thin),
            pool(0xb2, FIXTURE_WETH, r1, deep, deep * U256::from(2)),
            pool(0xb3, r1, r2, deep, deep),
            pool(0xb4, r2, FIXTURE_USDT0, deep, deep),
        ];
        let (rpc, server) = simulation_chain(SimulationChain::funded());
        let engine = fixture_engine_with_resident_pools(rpc, pools, &[r1, r2]);
        let response = quote_swap_bounded(
            &fixture_config(),
            &engine,
            fixture_request(amount_in),
            SolverBudget::for_duration(Duration::from_secs(5)),
            Arc::new(Semaphore::new(1)),
            None,
        )
        .await
        .unwrap();
        server.abort();
        assert_eq!(response.meta.source, "resident");
        assert_eq!(response.meta.widening_candidates, 2);
        assert_eq!(response.meta.widened, vec![r1, r2]);
        assert_eq!(response.meta.widening_rounds, 1);
        assert_eq!(response.meta.widening_end, "settled");
        assert!(
            hops(&response).contains(&(format!("{r1:#x}"), format!("{r2:#x}"))),
            "routed through both"
        );
        assert_eq!(response.simulation.unwrap().status, "simulated");
    }

    /// A V2 pool holding `reserve_a` of `a` and `reserve_b` of `b`.
    fn v2_pool(
        address: u8,
        a: Address,
        b: Address,
        reserve_a: U256,
        reserve_b: U256,
    ) -> (V2Pool, V2State) {
        let ((token0, reserve0), (token1, reserve1)) = if a < b {
            ((a, reserve_a), (b, reserve_b))
        } else {
            ((b, reserve_b), (a, reserve_a))
        };
        (
            V2Pool {
                protocol: V2Protocol::UNIV2,
                address: Address::repeat_byte(address),
                token0,
                token1,
                fee_bps: crate::chain::FIXTURE_V2_FEE_PPM / 100,
            },
            V2State { reserve0, reserve1 },
        )
    }

    const DUST_CONNECTOR: Address =
        alloy_primitives::address!("f5634d07bfcd83152164629679076ec413a25688");

    /// WETH/USDT0 at 2,500 USDT0 a WETH with $25M a side, and a resident
    /// connector R whose two pools hold $250 and $500 a side at twice that price:
    /// at the margin a WETH fetches about 4,500 USDT0 through R.
    fn dust_connector_pools() -> Vec<(V2Pool, V2State)> {
        let e = |power: u64| U256::from(10u64).pow(U256::from(power));
        vec![
            v2_pool(
                0xd1,
                FIXTURE_WETH,
                FIXTURE_USDT0,
                e(22),
                U256::from(25u64) * e(12),
            ),
            v2_pool(0xd2, FIXTURE_WETH, DUST_CONNECTOR, e(17), e(20)),
            v2_pool(
                0xd3,
                DUST_CONNECTOR,
                FIXTURE_USDT0,
                e(20),
                U256::from(5u64) * e(8),
            ),
        ]
    }

    async fn dust_quote(
        pools: Vec<(V2Pool, V2State)>,
        connectors: &[Address],
        request: QuoteRequest,
    ) -> QuoteResponse {
        let (rpc, server) = simulation_chain(SimulationChain::funded());
        let engine = fixture_engine_with_resident_pools(rpc, pools, connectors);
        let response = quote_swap_bounded(
            &fixture_config(),
            &engine,
            request,
            SolverBudget::for_duration(Duration::from_secs(5)),
            Arc::new(Semaphore::new(1)),
            None,
        )
        .await
        .unwrap();
        server.abort();
        assert_eq!(response.meta.source, "resident");
        response
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_thin_pool_still_trades_its_own_token() {
        // The same thin pools are R's own market: buying R goes through them.
        let response = dust_quote(
            dust_connector_pools(),
            &[DUST_CONNECTOR],
            QuoteRequest {
                token_in: format!("{FIXTURE_USDT0:#x}"),
                token_out: format!("{DUST_CONNECTOR:#x}"),
                ..fixture_request(U256::from(100_000_000u64))
            },
        )
        .await;
        assert_eq!(response.meta.widening_thin_left_out, 0);
        assert!(!response.meta.widening_thin_kept);
        assert_eq!(
            hops(&response).last().unwrap().1,
            format!("{DUST_CONNECTOR:#x}")
        );
        assert_eq!(response.simulation.unwrap().status, "simulated");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_candidate_past_a_thin_shared_hop_is_admitted_on_its_edge() {
        // KAOLA → WETH through a pool a thousandth the size of the sale, then
        // WETH → USDC → USDT0 about 25 bp better than WETH → USDT0. The sale
        // leaves the shared pool paying about a millionth of a WETH per KAOLA
        // at the margin, so what one more probe of KAOLA fetches is dust, but
        // every WETH the sale already bought gets the 25 bp. Found on a Morph
        // fork at block 28073500, 15 Oct 2026: a thin token → USDT0 lost 3 bp this
        // way.
        let kaola = alloy_primitives::address!("bdef3827ab5b4ae52458f0a2b2348720504f3ef9");
        let thin = U256::from(10u64).pow(U256::from(18u64));
        let deep = U256::from(10u64).pow(U256::from(24u64));
        let amount_in = thin * U256::from(1_000u64);
        let pool = |address: u8, a: Address, b: Address, reserve_a: U256, reserve_b: U256| {
            let ((token0, reserve0), (token1, reserve1)) = if a < b {
                ((a, reserve_a), (b, reserve_b))
            } else {
                ((b, reserve_b), (a, reserve_a))
            };
            (
                V2Pool {
                    protocol: V2Protocol::UNIV2,
                    address: Address::repeat_byte(address),
                    token0,
                    token1,
                    fee_bps: crate::chain::FIXTURE_V2_FEE_PPM / 100,
                },
                V2State { reserve0, reserve1 },
            )
        };
        let usdc = crate::chain::FIXTURE_USDC;
        let pools = vec![
            pool(0xc1, kaola, FIXTURE_WETH, thin, thin),
            pool(0xc2, FIXTURE_WETH, FIXTURE_USDT0, deep, deep),
            pool(
                0xc3,
                FIXTURE_WETH,
                usdc,
                deep,
                deep * U256::from(10_060u64) / U256::from(10_000u64),
            ),
            pool(0xc4, usdc, FIXTURE_USDT0, deep, deep),
        ];
        let (rpc, server) = simulation_chain(SimulationChain::funded());
        let engine = fixture_engine_with_resident_connectors(rpc, pools, &[], vec![usdc]);
        let response = quote_swap_bounded(
            &fixture_config(),
            &engine,
            QuoteRequest {
                token_in: format!("{kaola:#x}"),
                ..fixture_request(amount_in)
            },
            SolverBudget::for_duration(Duration::from_secs(5)),
            Arc::new(Semaphore::new(1)),
            None,
        )
        .await
        .unwrap();
        server.abort();
        assert_eq!(response.meta.source, "resident");
        assert_eq!(response.meta.widening_candidates, 1);
        assert_eq!(response.meta.widened, vec![usdc]);
        assert_eq!(response.meta.widening_rounds, 1);
        assert!(
            hops(&response).contains(&(format!("{FIXTURE_WETH:#x}"), format!("{usdc:#x}"))),
            "routed through USDC"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_pair_the_resident_state_cannot_fill_is_asked_of_its_own_pools() {
        let amount_in = U256::from(10u64).pow(U256::from(18u64));
        let reserve = U256::from(10u64).pow(U256::from(24u64));
        let (rpc, server) = simulation_chain(SimulationChain::funded());
        // The listed pair holds one unit of USDT0: it covers the pair and has
        // a skeleton, but nothing fills.
        let engine =
            fixture_engine_with_resident(rpc, fixture_weth_usdt0_v2(reserve, U256::from(1u64)));
        let response = quote_swap_bounded(
            &fixture_config(),
            &engine,
            fixture_request(amount_in),
            SolverBudget::for_duration(Duration::from_secs(5)),
            Arc::new(Semaphore::new(1)),
            None,
        )
        .await
        .unwrap();
        server.abort();
        assert_eq!(response.meta.source, "memory");
        assert_eq!(response.meta.universe_source, "profile_only");
        assert_eq!(response.block, 1);
    }

    fn empty_fixture_observation(observed_at: Instant) -> ObservedSnapshot {
        ObservedSnapshot {
            snapshot: Snapshot {
                block: 1,
                settler: None,
                v3: vec![],
                v2: vec![],
                ekubo: vec![],
            },
            screening: Default::default(),
            universe: crate::universe::RouteUniverse::profile_only(
                &FIXTURE_PROFILE,
                FIXTURE_WETH,
                FIXTURE_USDT0,
            )
            .unwrap(),
            topology_fences: None,
            block_id: BlockId::number(1),
            block_timestamp: 1_000,
            observed_at,
        }
    }

    #[tokio::test]
    async fn compute_queue_refreshes_a_snapshot_that_expires_while_waiting() {
        let cfg = Config {
            profile: &FIXTURE_PROFILE,
            rpc_url: FIXTURE_PROFILE.public_rpc.to_string(),
            logs_rpc_url: FIXTURE_PROFILE.public_rpc.to_string(),
            indexer_url: None,
            native_rfq: None,
            fee_bps: 0,
            fee_receiver: None,
            positive_slippage_max_bps: 0,
            positive_slippage_recipient: None,
            port: 0,
            quote_timeout: 5,
        };
        let engine = Engine::for_profile(
            crate::rpc::Rpc::connect("http://127.0.0.1:1").unwrap(),
            &FIXTURE_PROFILE,
        );
        let seeded = engine.cache_snapshot_for_test(
            FIXTURE_WETH,
            FIXTURE_USDT0,
            empty_fixture_observation(Instant::now()),
        );
        let compute_slots = Arc::new(Semaphore::new(0));
        let task_slots = compute_slots.clone();
        let task_engine = engine.clone();
        let quote = tokio::spawn(async move {
            quote_swap_bounded(
                &cfg,
                &task_engine,
                QuoteRequest {
                    chain_id: FIXTURE_PROFILE.chain_id,
                    token_in: format!("{FIXTURE_WETH:#x}"),
                    token_out: format!("{FIXTURE_USDT0:#x}"),
                    amount_in: AmountIn::Str("1".to_string()),
                    slippage_bps: 50,
                    recipient: None,
                    sender: None,
                    tx_origin: None,
                    deadline_seconds: 60,
                    fee_bps: None,
                },
                SolverBudget::for_duration(Duration::from_secs(5)),
                task_slots,
                None,
            )
            .await
        });

        tokio::time::timeout(Duration::from_secs(1), async {
            while Arc::strong_count(&seeded) < 3 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("quote did not reach compute admission with the seeded snapshot");
        tokio::time::sleep(Duration::from_millis(2_050)).await;
        compute_slots.add_permits(1);

        let result = tokio::time::timeout(Duration::from_secs(1), quote)
            .await
            .expect("quote did not refresh after compute admission")
            .expect("quote task panicked");
        let error = match result {
            Ok(_) => panic!("quote used the snapshot after it became stale in the compute queue"),
            Err(error) => error,
        };
        // The refresh asks this test's dead RPC for the head block, the first
        // read of a new snapshot. Pricing the stale one would ask it nothing.
        assert!(
            error
                .downcast_ref::<crate::rpc::RpcUnavailable>()
                .is_some_and(|marker| marker.0 == "eth_getBlockByNumber"),
            "{error:#}"
        );
        assert_eq!(compute_slots.available_permits(), 1);
    }

    fn test_route_universe(block: u64) -> RouteUniverseJson {
        RouteUniverseJson::new(
            56,
            block,
            B256::repeat_byte(0x11),
            RouteUniverseDiagnostics {
                source: "profile_only",
                fallback_stage: None,
                fallback_reason: None,
                scope: "profile",
                selector: "none",
                selection_scope: "profile",
                protocol_mask: 0,
                eligible_count: 0,
                connector_count: 0,
                shortlist_truncated: false,
                screened_count: 0,
                adjacency_fences: None,
                fingerprint: B256::repeat_byte(0x22),
            },
            None,
        )
    }

    fn validated_native_quote(
        amount_out: u64,
        deadline: u64,
        min_ttl_seconds: u64,
    ) -> ValidatedFirmQuote {
        ValidatedFirmQuote {
            target: Address::repeat_byte(0x11),
            pool: Address::repeat_byte(0x22),
            calldata: Default::default(),
            token_in: Address::repeat_byte(0x11),
            token_out: Address::repeat_byte(0x22),
            settler: Address::repeat_byte(0x33),
            expected_origin: Address::repeat_byte(0x55),
            amount_in: U256::ONE,
            amount_out: U256::from(amount_out),
            signer: Address::repeat_byte(0x55),
            nonce: U256::from(7u64),
            beneficiary: Address::repeat_byte(0x33),
            deadline,
            min_ttl_seconds,
            amount_in_offset: 36,
            amount_out_minimum_offset: 68,
            router_version: 6,
            observation: Some(crate::rfq::NativeQuoteObservation {
                number: 123,
                hash: B256::repeat_byte(0x44),
            }),
        }
    }

    fn native_request() -> FirmQuoteRequest {
        FirmQuoteRequest {
            identity: FIXTURE_NATIVE_RFQ,
            token_in: Address::repeat_byte(0x11),
            token_out: Address::repeat_byte(0x22),
            amount_in: U256::ONE,
            settler: Address::repeat_byte(0x33),
            beneficiary: Address::repeat_byte(0x44),
            tx_origin: Some(Address::repeat_byte(0x55)),
            slippage_bps: 50,
            expiry_seconds: 60,
            chain_timestamp: 1_800_000_000,
        }
    }

    struct SlowNativeSource {
        delay: Duration,
        calls: AtomicUsize,
    }

    impl NativeRfqSource for SlowNativeSource {
        fn indicative_quotes<'a>(
            &'a self,
            _identity: crate::chain::NativeRfqProfile,
            _requests: &'a [(NativePair, U256)],
        ) -> BoxFuture<'a, Result<Vec<(NativePair, U256, U256)>, NativeRfqError>> {
            Box::pin(async { Ok(Vec::new()) })
        }

        fn firm_quote<'a>(
            &'a self,
            _request: FirmQuoteRequest,
        ) -> BoxFuture<'a, Result<Option<ValidatedFirmQuote>, NativeRfqError>> {
            Box::pin(async move {
                self.calls.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(self.delay).await;
                Ok(None)
            })
        }
    }

    fn amm_plan(amount_out: u64) -> Plan {
        Plan {
            legs: Vec::new(),
            amount_out: U256::from(amount_out),
            universe_id: None,
        }
    }

    #[test]
    fn native_selection_uses_the_final_amm_amount_and_rechecks_ttl() {
        let now = 1_000;
        let quote = validated_native_quote(101, now + 10, 10);

        assert!(native_quote_beats_amm(&quote, Some(&amm_plan(100)), now));
        assert!(!native_quote_beats_amm(&quote, Some(&amm_plan(101)), now));
        assert!(!native_quote_beats_amm(&quote, Some(&amm_plan(102)), now));
        assert!(native_quote_beats_amm(&quote, None, now));
        // A quote that won comparison must still lose to the retained AMM
        // plan if the final encoding check crosses the TTL boundary.
        assert!(!native_quote_beats_amm(
            &quote,
            Some(&amm_plan(100)),
            now + 1
        ));

        let stale = validated_native_quote(1_000, now + 9, 10);
        assert!(!native_quote_beats_amm(&stale, Some(&amm_plan(1)), now));
        assert!(!native_quote_beats_amm(&stale, None, now));
    }

    #[test]
    fn native_response_deadline_is_the_tighter_execution_deadline() {
        let quote = validated_native_quote(100, 1_050, 10);
        assert_eq!(selected_deadline(1_100, Some(&quote)), 1_050);
        assert_eq!(selected_deadline(1_025, Some(&quote)), 1_025);
        assert_eq!(selected_deadline(1_100, None), 1_100);
    }

    #[test]
    fn native_capacity_errors_never_become_amm_fallbacks() {
        for error in [
            NativeRfqError::Saturated,
            NativeRfqError::QueueTimeout,
            NativeRfqError::Api(201_005),
        ] {
            assert_eq!(
                native_result_or_fallback(Err(error.clone())).unwrap_err(),
                error
            );
        }
        assert!(
            native_result_or_fallback(Err(NativeRfqError::Transport))
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn optional_native_timeout_is_not_amm_fallback() {
        let source = SlowNativeSource {
            delay: Duration::from_secs(2),
            calls: AtomicUsize::new(0),
        };
        let budget = SolverBudget::for_duration(Duration::from_millis(250));
        let started = Instant::now();

        let error = request_optional_native_quote(&source, native_request(), &budget)
            .await
            .unwrap_err();

        assert_eq!(error, NativeRfqError::QueueTimeout);
        assert_eq!(source.calls.load(Ordering::SeqCst), 1);
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(
            budget
                .remaining()
                .is_some_and(|remaining| !remaining.is_zero())
        );
    }

    #[tokio::test]
    async fn missing_native_response_budget_is_not_amm_fallback() {
        let source = SlowNativeSource {
            delay: Duration::ZERO,
            calls: AtomicUsize::new(0),
        };
        let budget = SolverBudget::for_duration(OPTIONAL_RFQ_RESPONSE_RESERVE);

        let error = request_optional_native_quote(&source, native_request(), &budget)
            .await
            .unwrap_err();

        assert_eq!(error, NativeRfqError::QueueTimeout);
        assert_eq!(source.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn native_wait_that_expires_snapshot_rejects_amm_fallback() {
        let engine = Engine::for_profile(
            crate::rpc::Rpc::connect("http://127.0.0.1:1").unwrap(),
            &FIXTURE_PROFILE,
        );
        let observed_at = Instant::now()
            .checked_sub(Duration::from_millis(1_500))
            .unwrap();
        let stamped = engine.cache_snapshot_for_test(
            FIXTURE_WETH,
            FIXTURE_USDT0,
            empty_fixture_observation(observed_at),
        );
        assert!(stamped.is_fresh());
        // 2.4 s old after the wait: past the bound and its finishing grace.
        let source = SlowNativeSource {
            delay: Duration::from_millis(900),
            calls: AtomicUsize::new(0),
        };

        let quote = request_optional_native_quote(
            &source,
            native_request(),
            &SolverBudget::for_duration(Duration::from_secs(2)),
        )
        .await
        .unwrap();

        assert!(quote.is_none());
        let error = fresh_amm_snapshot(&stamped).unwrap_err();
        assert_eq!(
            error
                .downcast_ref::<RpcUnavailable>()
                .map(|marker| marker.0),
            Some("snapshot freshness")
        );
    }

    #[tokio::test]
    async fn fresh_native_miss_still_allows_amm_fallback() {
        let engine = Engine::for_profile(
            crate::rpc::Rpc::connect("http://127.0.0.1:1").unwrap(),
            &FIXTURE_PROFILE,
        );
        let stamped = engine.cache_snapshot_for_test(
            FIXTURE_WETH,
            FIXTURE_USDT0,
            empty_fixture_observation(Instant::now()),
        );
        let source = SlowNativeSource {
            delay: Duration::ZERO,
            calls: AtomicUsize::new(0),
        };

        let quote = request_optional_native_quote(
            &source,
            native_request(),
            &SolverBudget::for_duration(Duration::from_secs(1)),
        )
        .await
        .unwrap();

        assert!(quote.is_none());
        assert!(fresh_amm_snapshot(&stamped).is_ok());
    }

    #[test]
    fn quote_token_normalization_uses_the_selected_profile() {
        let token = Address::repeat_byte(0x44);
        let (input, output) = routed_tokens(&crate::chain::BSC_PROFILE, NATIVE, token);
        assert_eq!(input, crate::chain::BSC_PROFILE.wrapped_native);
        assert_ne!(input, crate::chain::ROBINHOOD_PROFILE.wrapped_native);
        assert_eq!(output, token);
    }

    #[test]
    fn escalation_threshold_parses_bps_and_disables_at_zero() {
        assert_eq!(escalate_threshold_e4("1").unwrap(), 10_000);
        assert_eq!(escalate_threshold_e4("0.5").unwrap(), 5_000);
        assert_eq!(escalate_threshold_e4(" 2.25 ").unwrap(), 22_500);
        assert_eq!(escalate_threshold_e4("0").unwrap(), 0);
        assert_eq!(escalate_threshold_e4("-3").unwrap(), 0);
        for bad in ["0.1bp", "inf", "NaN", ""] {
            assert!(
                escalate_threshold_e4(bad).is_err(),
                "{bad:?} must be refused at startup"
            );
        }
    }

    fn quote_request_with_identities(
        recipient: Option<Address>,
        sender: Option<Address>,
        tx_origin: Option<Address>,
    ) -> QuoteRequest {
        serde_json::from_value(serde_json::json!({
            "chainId": 2818,
            "tokenIn": format!("{:#x}", Address::repeat_byte(0x11)),
            "tokenOut": format!("{:#x}", Address::repeat_byte(0x22)),
            "amountIn": "1",
            "recipient": recipient.map(addrhex),
            "sender": sender.map(addrhex),
            "txOrigin": tx_origin.map(addrhex),
        }))
        .expect("valid quote request")
    }

    #[test]
    fn execution_identity_keeps_smart_account_sender_separate_from_evm_origin() {
        let recipient = Address::repeat_byte(0x33);
        let safe = Address::repeat_byte(0x44);
        let owner_eoa = Address::repeat_byte(0x55);
        let request = quote_request_with_identities(Some(recipient), Some(safe), Some(owner_eoa));

        let identities = parse_execution_identities(&request).unwrap();

        assert_eq!(identities.recipient, Some(recipient));
        assert_eq!(identities.sender, Some(safe));
        assert_eq!(identities.required_from, Some(safe));
        assert_eq!(identities.tx_origin, Some(owner_eoa));
    }

    #[test]
    fn sender_defaults_to_recipient_without_inventing_an_evm_origin() {
        let recipient = Address::repeat_byte(0x33);
        let request = quote_request_with_identities(Some(recipient), None, None);

        let identities = parse_execution_identities(&request).unwrap();

        assert_eq!(identities.required_from, Some(recipient));
        assert_eq!(identities.tx_origin, None);
    }

    #[test]
    fn tx_origin_requires_an_execution_request_and_must_be_nonzero() {
        let eoa = Address::repeat_byte(0x55);
        let without_recipient = quote_request_with_identities(None, None, Some(eoa));
        assert_eq!(
            parse_execution_identities(&without_recipient)
                .unwrap_err()
                .to_string(),
            "txOrigin requires recipient"
        );

        let zero_origin = quote_request_with_identities(
            Some(Address::repeat_byte(0x33)),
            None,
            Some(Address::ZERO),
        );
        assert_eq!(
            parse_execution_identities(&zero_origin)
                .unwrap_err()
                .to_string(),
            "txOrigin must not be zero"
        );
    }

    #[test]
    fn transaction_json_serializes_the_checked_sender_as_required_from() {
        let sender = Address::repeat_byte(0x11);
        let value = serde_json::to_value(TxJson {
            required_from: addrhex(sender),
            to: addrhex(Address::repeat_byte(0x22)),
            value: "0".to_string(),
            data: "0x".to_string(),
        })
        .expect("serializable");
        assert_eq!(value["requiredFrom"], addrhex(sender));
    }

    #[test]
    fn quote_json_omits_missing_settler_identity() {
        let mut response = QuoteResponse {
            chain: "bsc",
            chain_id: 56,
            liquidity_source: "amm",
            slippage_bps: 50,
            deadline_seconds: 600,
            requested_fee_bps: None,
            recipient: None,
            sender: None,
            tx_origin: None,
            native_observation: None,
            block: 1,
            block_hash: format!("{:#x}", B256::repeat_byte(0x12)),
            block_timestamp: 99,
            route_universe: test_route_universe(1),
            settler: None,
            token_in: addrhex(Address::repeat_byte(1)),
            token_out: addrhex(Address::repeat_byte(2)),
            amount_in: "1".to_string(),
            amount_out_gross: "1".to_string(),
            price_impact_bps: None,
            mid_amount_out: None,
            fee_bps: 0,
            amount_out_net: "1".to_string(),
            min_amount_out_net: "1".to_string(),
            deadline: 1,
            route: Vec::new(),
            tx: None,
            allowance_target: None,
            allowance_holder: None,
            entrypoint: None,
            authorization_deadline: None,
            approval: None,
            simulation: None,
            issues: None,
            fee_receiver: None,
            positive_slippage: None,
            certificate: None,
            coverage: None,
            meta: QuoteMeta::default(),
        };
        let value = serde_json::to_value(&response).expect("serializable");
        assert!(value.get("settler").is_none());
        // Quote-only responses carry none of the transaction fields.
        for field in [
            "tx",
            "allowanceTarget",
            "allowanceHolder",
            "entrypoint",
            "authorizationDeadline",
            "approval",
            "simulation",
            "issues",
        ] {
            assert!(value.get(field).is_none(), "{field}");
        }
        assert_eq!(
            value["blockHash"],
            format!("{:#x}", B256::repeat_byte(0x12))
        );
        assert_eq!(value["blockTimestamp"], 99);
        assert!(value.get("nativeObservation").is_none());
        assert!(value["txOrigin"].is_null());
        assert_eq!(value["routeUniverse"]["version"], 1);
        assert_eq!(value["routeUniverse"]["chainId"], 56);
        assert_eq!(value["routeUniverse"]["canonicalBlock"]["number"], 1);
        assert_eq!(value["routeUniverse"]["scope"], "profile");
        assert_eq!(value["routeUniverse"]["selectionScope"], "profile");

        response.settler = Some(addrhex(Address::repeat_byte(3)));
        response.tx_origin = Some(addrhex(Address::repeat_byte(4)));
        response.native_observation = Some(CanonicalBlockJson {
            number: 123,
            hash: format!("{:#x}", B256::repeat_byte(0x55)),
        });
        let value = serde_json::to_value(&response).expect("serializable");
        assert_eq!(value["settler"], addrhex(Address::repeat_byte(3)));
        assert_eq!(value["txOrigin"], addrhex(Address::repeat_byte(4)));
        assert_eq!(value["nativeObservation"]["number"], 123);
        assert_eq!(
            value["nativeObservation"]["hash"],
            format!("{:#x}", B256::repeat_byte(0x55))
        );
    }

    #[test]
    fn executable_fair_price_impact_is_ceil_bps_and_never_negative() {
        assert_eq!(
            price_impact_bps(U256::from(30), U256::from(29), U256::ONE, U256::ONE),
            334
        );
        assert_eq!(
            price_impact_bps(U256::from(100), U256::from(101), U256::ONE, U256::ONE),
            0
        );
        assert_eq!(
            price_impact_bps(U256::MAX, U256::ZERO, U256::MAX, U256::MAX),
            BPS_BASE
        );
    }

    /// v2 pools at the given fee tiers; these functions read only the fees, so
    /// the reserves are placeholders
    fn fee_snapshot(fee_bps: &[u32]) -> Snapshot {
        Snapshot {
            block: 1,
            settler: Some(Address::repeat_byte(0xfe)),
            v3: vec![],
            v2: fee_bps
                .iter()
                .enumerate()
                .map(|(i, &fee_bps)| {
                    let pool = V2Pool {
                        protocol: V2Protocol::UP33V2,
                        address: Address::repeat_byte(i as u8 + 1),
                        token0: Address::repeat_byte(0xa0),
                        token1: Address::repeat_byte(0xb0),
                        fee_bps,
                    };
                    (
                        pool,
                        V2State {
                            reserve0: U256::ONE,
                            reserve1: U256::ONE,
                        },
                    )
                })
                .collect(),
            ekubo: vec![],
        }
    }

    /// The emitted artifact has to be enough to re-derive the claim: take the
    /// serialized dual point, feed it back to `bound_at`, and get the same
    /// bound. That round trip is what makes `boundWei` checkable by someone
    /// who never runs our solver.
    #[test]
    fn the_serialized_certificate_reproduces_its_own_bound() {
        let token_in = Address::repeat_byte(0xa0);
        let token_out = Address::repeat_byte(0xb0);
        let amount_in = U256::from(10u64).pow(U256::from(20u64));
        let mut snap = fee_snapshot(&[30, 30]);
        snap.v2[0].1 = V2State {
            reserve0: U256::from(10u64).pow(U256::from(23u64)),
            reserve1: U256::from(12u64) * U256::from(10u64).pow(U256::from(22u64)),
        };
        snap.v2[1].1 = V2State {
            reserve0: U256::from(4u64) * U256::from(10u64).pow(U256::from(22u64)),
            reserve1: U256::from(5u64) * U256::from(10u64).pow(U256::from(22u64)),
        };
        let plan = best_plan(&snap, token_in, token_out, amount_in, 256, 50).expect("plan");
        let json = certificate_json(
            certify(
                &crate::chain::ROBINHOOD_PROFILE,
                &snap,
                token_in,
                token_out,
                amount_in,
                &plan,
            ),
            false,
        );
        assert_eq!(json.status, "certified");
        assert_eq!(json.mode, "shadow");
        assert_eq!(json.scope, "materialized_route_universe");

        let prices: std::collections::HashMap<Address, certificate::Price> = json
            .prices
            .iter()
            .map(|price| {
                (
                    price.token.parse().expect("address"),
                    certificate::Price {
                        num: price.num.parse().expect("numerator"),
                        den: price.den.parse().expect("denominator"),
                    },
                )
            })
            .collect();
        let (bound, _) = certificate::bound_at(
            &snap,
            token_in,
            amount_in,
            &prices,
            Some(&certificate::PoolSet::reachable(
                &crate::chain::ROBINHOOD_PROFILE,
                &snap,
                token_in,
                token_out,
            )),
            &certificate::PoolSet::of(&snap, &plan),
        )
        .expect("re-evaluated bound");
        assert_eq!(bound.to_string(), json.bound_wei.expect("bound"));
        assert!(bound >= plan.amount_out);
    }

    #[test]
    fn an_uncertifiable_plan_reports_a_reason_instead_of_failing_the_quote() {
        let token_in = Address::repeat_byte(0xa0);
        let token_out = Address::repeat_byte(0xb0);
        let snap = fee_snapshot(&[30]);
        let empty = Plan {
            legs: Vec::new(),
            amount_out: U256::ZERO,
            universe_id: None,
        };
        let json = certificate_json(
            certify(
                &crate::chain::ROBINHOOD_PROFILE,
                &snap,
                token_in,
                token_out,
                U256::ONE,
                &empty,
            ),
            true,
        );
        assert_eq!(json.mode, "active");
        assert_eq!(json.status, "unavailable");
        assert!(json.reason.is_some());
        assert!(json.bound_wei.is_none());
    }

    #[test]
    fn hop_json_uses_the_directional_v3_fee() {
        let token0 = Address::repeat_byte(0xa0);
        let token1 = Address::repeat_byte(0xb0);
        let mut snap = fee_snapshot(&[]);
        snap.v3.push((
            V3Pool {
                protocol: V3Protocol::SHERIFF,
                address: Address::repeat_byte(1),
                token0,
                token1,
                fee_ppm: 400,
                tick_spacing: 10,
                verify_pool_spacing: false,
                execution: Some(crate::pools::V3ExecutionMeta {
                    fork_id: 41,
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
                liquidity: U256::ONE,
                ticks: Vec::new().into(),
                pos: 0,
                lo_cover: 0,
                hi_cover: 0,
            },
        ));

        for (zero_for_one, expected) in [(true, 365), (false, 434)] {
            let HopJson::V3 { fee_ppm, .. } = hop_json(
                &snap,
                &Hop {
                    kind: HopKind::V3,
                    index: 0,
                    zero_for_one,
                    token_in: token0,
                    token_out: token1,
                },
            )
            .expect("valid Sheriff metadata") else {
                panic!("v3 hop")
            };
            assert_eq!(fee_ppm, expected);
        }
    }

    fn leg(pools: &[usize], amount_out: u64) -> Leg {
        Leg {
            path: pools
                .iter()
                .map(|&index| Hop {
                    kind: HopKind::V2,
                    index,
                    zero_for_one: true,
                    token_in: Address::repeat_byte(0xa0),
                    token_out: Address::repeat_byte(0xb0),
                })
                .collect(),
            amount_in: U256::ONE,
            amount_out: U256::from(amount_out),
            losses: vec![],
            slice_bps: BPS_BASE,
        }
    }

    #[test]
    fn fee_free_out_compounds_hop_fees_instead_of_adding_them() {
        let snap = fee_snapshot(&[30, 30, 60]);
        // 30 bps off a hop's input: 997_000 of 1_000_000 arrives
        assert_eq!(
            fee_free_out(&snap, &leg(&[0], 997_000), U256::ONE, U256::ONE).expect("fits"),
            U256::from(1_000_000)
        );
        // two 30 bps hops keep 0.997² = 0.994009, slightly MORE than the 0.994 a
        // summed 60 bps keeps — so summing overstates the fee and lifts the
        // baseline above the truth. Small (0.09 bps here), but the product is
        // free, and it is what the pools actually charge.
        assert_eq!(
            fee_free_out(&snap, &leg(&[0, 1], 994_009), U256::ONE, U256::ONE).expect("fits"),
            U256::from(1_000_000)
        );
        assert_eq!(
            fee_free_out(&snap, &leg(&[2], 994_009), U256::ONE, U256::ONE).expect("fits"),
            U256::from(1_000_009)
        );
        assert_eq!(
            fee_free_out(&snap, &leg(&[0, 1, 0], 991_026_973), U256::ONE, U256::ONE)
                .expect("three-hop fee product fits"),
            U256::from(1_000_000_000u64)
        );
    }

    #[test]
    fn mid_amount_out_undoes_each_leg_at_its_own_fee_then_scales_to_full_size() {
        let snap = fee_snapshot(&[30, 100]); // 0.30% and 1.00%
        let fair = Plan {
            legs: vec![leg(&[0], 997), leg(&[1], 990)],
            amount_out: U256::from(1_987),
            universe_id: None,
        };
        // each leg grosses up at the fee IT paid — 997/0.997 + 990/0.99 = 2000 —
        // and a share-weighted average of the two would land somewhere else
        let (fair_in, amount_in) = (U256::from(100), U256::from(10_000));
        let mid = mid_amount_out(&snap, &fair, fair_in, amount_in).expect("fits");
        assert_eq!(mid, U256::from(200_000));
        // the baseline must sit ABOVE the executable output it came from: that
        // gap IS the pool fee the old headline left out
        assert!(mid > fair.amount_out * U256::from(100));
    }

    #[test]
    fn mid_amount_out_matches_direct_fee_rounding_vectors() {
        let snap = fee_snapshot(&[100]);
        let fair = Plan {
            legs: vec![leg(&[0], 220)],
            amount_out: U256::from(220),
            universe_id: None,
        };
        assert_eq!(
            mid_amount_out(&snap, &fair, U256::from(100), U256::from(10_000)).expect("fits"),
            U256::from(22_222)
        );

        let snap = fee_snapshot(&[30]);
        let fair = Plan {
            legs: vec![leg(&[0], 332)],
            amount_out: U256::from(332),
            universe_id: None,
        };
        assert_eq!(
            mid_amount_out(&snap, &fair, U256::ONE, U256::from(100)).expect("fits"),
            U256::from(33_299)
        );
    }

    #[test]
    fn rounded_v2_probe_drops_both_reference_metrics_when_mid_is_below_full_output() {
        let mut snap = fee_snapshot(&[30]);
        snap.v2[0].1 = V2State {
            reserve0: U256::from(1_000_000_000_000u64),
            reserve1: U256::from(1_000_000_000_000u64),
        };
        let amount_in = U256::from(300);
        let fair_in = amount_in / U256::from(100);
        let (pool, state) = &snap.v2[0];
        let full_out = sim_v2(pool, state, true, amount_in)
            .expect("full sim")
            .amount_out;
        let fair_out = sim_v2(pool, state, true, fair_in)
            .expect("probe sim")
            .amount_out;
        assert_eq!((full_out, fair_out), (U256::from(299), U256::from(2)));

        let full = Plan {
            legs: vec![],
            amount_out: full_out,
            universe_id: None,
        };
        let fair = Plan {
            legs: vec![Leg {
                amount_in: fair_in,
                amount_out: fair_out,
                ..leg(&[0], 0)
            }],
            amount_out: fair_out,
            universe_id: None,
        };
        assert_eq!(
            mid_amount_out(&snap, &fair, fair_in, amount_in).expect("mid"),
            U256::from(200)
        );

        let (price_impact_bps, mid_amount_out) =
            reference_metrics(&snap, &full, Some(&fair), fair_in, amount_in).expect("metrics");
        assert_eq!((price_impact_bps, mid_amount_out), (None, None));
    }

    #[test]
    fn mid_amount_out_rounds_once_per_split_leg_after_all_hop_fees() {
        let snap = fee_snapshot(&[30, 100, 30]);
        let fair = Plan {
            legs: vec![leg(&[0, 1], 987), leg(&[2], 332)],
            amount_out: U256::from(1_319),
            universe_id: None,
        };

        assert_eq!(
            mid_amount_out(&snap, &fair, U256::from(100), U256::from(10_000)).expect("fits"),
            U256::from(133_295)
        );
    }

    #[test]
    fn mid_amount_out_uses_the_v3_fee_actually_charged() {
        let token0 = Address::repeat_byte(0xa0);
        let token1 = Address::repeat_byte(0xb0);
        let snap = Snapshot {
            block: 1,
            settler: Some(Address::repeat_byte(0xfe)),
            v3: vec![(
                V3Pool {
                    protocol: V3Protocol::UNIV3,
                    address: Address::repeat_byte(1),
                    token0,
                    token1,
                    fee_ppm: 3_000,
                    tick_spacing: 60,
                    verify_pool_spacing: false,
                    execution: Some(crate::pools::V3ExecutionMeta {
                        fork_id: 0,
                        pool_id: 3_000,
                    }),
                    v4: None,
                    algebra: None,
                },
                V3State {
                    sqrt_price: U256::ONE << 96usize,
                    tick: 0,
                    liquidity: U256::from(1_000_000_000_000u64),
                    ticks: Vec::new().into(),
                    pos: 0,
                    lo_cover: -180_000,
                    hi_cover: 180_000,
                },
            )],
            v2: vec![],
            ekubo: vec![],
        };
        let fair_in = U256::from(768);
        let amount_in = U256::from(76_800);
        let fair = quantized_plan(
            &snap,
            &best_plan(&snap, token0, token1, fair_in, 256, 50).expect("route"),
            fair_in,
        )
        .expect("quantized");

        assert_eq!(fair.amount_out, U256::from(764));
        let [fee] = fair.legs[0].losses.as_slice() else {
            panic!("one v3 fee")
        };
        assert_eq!((fee.gross, fee.net), (U256::from(768), U256::from(765)));
        assert_eq!(
            mid_amount_out(&snap, &fair, fair_in, amount_in).expect("fits"),
            U256::from(76_699)
        );
    }
}
