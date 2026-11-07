// Quote orchestration: snapshot → plan → (optional) transaction.
// Response field names are the HTTP contract (README, "HTTP"), byte-compatible
// with the Julia solver's output (amounts as decimal strings, lowercase hex addresses).

mod amm;
mod fees;
mod native;
mod request;
mod tx;
mod widen;
mod wire;

use crate::abi::addrhex;
use crate::budget::SolverBudget;
use crate::config::Config;
use crate::engine::{Engine, SnapshotScope};
use crate::rfq::NativeRfqSource;
use crate::rpc::RpcUnavailable;
use crate::settler::{
    BPS_BASE, ComposedSwapStage, PositiveSlippage, build_composed_native_rfq_tx_for_profile,
};
use crate::v3math::muldiv;
use alloy_primitives::{Address, U256};
pub(crate) use amm::*;
use anyhow::{Context, ensure};
pub use fees::*;
use native::{
    NativeOutcome, NativePlacement, NativeRoute, native_route_beats_amm, native_route_json,
    native_stage, selected_deadline,
};
use request::{QuoteTerms, validate};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Semaphore;
use tx::attach_transaction;
pub use wire::*;

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
    let terms = validate(cfg, engine, &req, native_rfq.is_some())?;
    let QuoteTerms {
        token_in,
        token_out,
        a,
        b,
        identities,
        amount_in,
        slippage_bps,
        deadline_seconds,
        native_identity: _,
        native_planning_enabled,
        requested_fee_bps,
        fee_bps,
    } = terms;
    let recipient = identities.recipient;
    let sender = identities.sender;
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

    let compute_amm = || {
        evaluate_amm(
            &stamped,
            cfg.profile,
            (a, b),
            amount_in,
            native_planning_enabled,
            engine.coverage_cache(),
            &budget,
        )
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

    let NativeOutcome {
        route: native_route,
        attempted: rfq_attempted,
        quoted: rfq_quoted,
        rfq_ms,
        solve_ms: native_solve_ms,
    } = native_stage(
        &terms,
        native_rfq,
        cfg.profile,
        amm.native_last_prefix.as_ref(),
        &stamped,
        compute_slots.as_ref(),
        &budget,
    )
    .await?;
    amm.solve_ms = amm.solve_ms.saturating_add(native_solve_ms);

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
    let coverage_json = response_coverage.map(CoverageJson::new);

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
        .checked_add(deadline_seconds)
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
            route.push(leg_json(snap, leg, amount_in)?);
        }
    }

    let mut resp = QuoteResponse {
        chain: cfg.profile.key,
        chain_id: cfg.profile.chain_id,
        liquidity_source: selected_native.map_or("amm", NativeRoute::liquidity_source),
        slippage_bps,
        deadline_seconds,
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
        attach_transaction(
            &mut resp,
            cfg,
            engine,
            &terms,
            recipient,
            prebuilt_native_tx,
            &stamped,
            snapshot_hash,
            positive_slippage,
            selected_plan,
            min_amount_out_net,
            deadline,
            &budget,
            min_block,
        )
        .await?;
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
mod tests;
