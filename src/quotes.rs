// Quote orchestration: snapshot → plan → (optional) transaction.
// Response field names are the HTTP contract (README, "HTTP"), byte-compatible
// with the Julia solver's output (amounts as decimal strings, lowercase hex addresses).

mod amm;
mod fees;
mod native;
mod request;
mod wire;

use crate::abi::{addrhex, tohex};
use crate::budget::SolverBudget;
use crate::certificate::format_bps_e4;
use crate::chain::NATIVE;
use crate::config::Config;
use crate::engine::{Engine, SnapshotScope};
use crate::rfq::{FirmQuoteRequest, NativeRfqSource};
use crate::route::{ALLOC_CHUNKS, MIN_SHARE_BPS, PreparedRoutes};
use crate::rpc::{CanonicalBlock, RpcUnavailable};
use crate::settler::{
    BPS_BASE, ComposedSwapStage, PositiveSlippage, build_composed_native_rfq_tx_for_profile,
    build_swap_tx_for_profile,
};
use crate::simulation;
use crate::v3math::muldiv;
use alloy_primitives::{Address, U256};
pub(crate) use amm::*;
use anyhow::{Context, ensure};
pub use fees::*;
use native::{
    NativeDraft, NativePlacement, NativeRoute, choose_native_draft, native_route_beats_amm,
    native_route_json, request_optional_native_quote, selected_deadline,
    solve_profile_stage_bounded,
};
use request::{parse_addr, parse_amount, parse_execution_identities, routed_tokens};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Semaphore;
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
mod tests;
