use super::fees::PPM_BASE;
use crate::abi::addrhex;
use crate::certificate;
use crate::certificate::format_bps_e4;
use crate::counterfactual::CoverageReading;
use crate::route::{Hop, HopKind, Leg};
use crate::settler::BPS_BASE;
use crate::simulation::{Approval, Issues, Simulation};
use crate::snapshot::Snapshot;
use crate::topology::CatalogFences;
use crate::universe::RouteUniverseDiagnostics;
use crate::v3math::muldiv;
use alloy_primitives::{Address, B256, U256};
use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::fmt;

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
pub(super) fn venue(protocol: &'static str) -> &'static str {
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

/// Certify a plan, or explain why it could not be certified. Never propagates:
/// a quote is a quote whether or not its bound could be evaluated.
pub(super) fn certificate_json(
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

pub(super) fn hop_json(snap: &Snapshot, h: &Hop) -> anyhow::Result<HopJson> {
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

impl CoverageJson {
    /// A coverage reading in wire form.
    pub(super) fn new(reading: &CoverageReading) -> Self {
        CoverageJson {
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
        }
    }
}

/// One AMM leg in wire form: its share of the input, its amounts and its hops.
pub(super) fn leg_json(
    snap: &Snapshot,
    leg: &Leg,
    amount_in: U256,
) -> anyhow::Result<RouteLegJson> {
    Ok(RouteLegJson {
        share_bps: u32::try_from(muldiv(leg.amount_in, U256::from(BPS_BASE), amount_in)?)
            .context("share bps out of range")?,
        amount_in: leg.amount_in.to_string(),
        amount_out: leg.amount_out.to_string(),
        hops: leg
            .path
            .iter()
            .map(|h| hop_json(snap, h))
            .collect::<anyhow::Result<_>>()?,
    })
}
