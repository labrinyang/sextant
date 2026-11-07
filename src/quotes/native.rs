use super::amm::fresh_amm_snapshot;
use super::wire::{HopJson, RouteLegJson, hop_json, venue};
use crate::abi::addrhex;
use crate::budget::SolverBudget;
use crate::chain::ChainProfile;
use crate::engine::Stamped;
use crate::rfq::{
    FirmQuoteRequest, NativePair, NativeRfqError, NativeRfqSource, ValidatedFirmQuote,
};
use crate::route::{ALLOC_CHUNKS, Plan, PreparedRoutes};
use crate::settler::BPS_BASE;
use crate::snapshot::Snapshot;
use alloy_primitives::{Address, U256};
use anyhow::{Context, ensure};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum NativePlacement {
    Only,
    First,
    Last,
}

pub(super) enum NativeDraft {
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
    pub(super) fn request_tokens_and_amount(&self) -> (Address, Address, U256) {
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

pub(super) enum NativeRoute {
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
    pub(super) fn placement(&self) -> NativePlacement {
        match self {
            Self::Only { .. } => NativePlacement::Only,
            Self::First { .. } => NativePlacement::First,
            Self::Last { .. } => NativePlacement::Last,
        }
    }

    pub(super) fn quote(&self) -> &ValidatedFirmQuote {
        match self {
            Self::Only { quote } | Self::First { quote, .. } | Self::Last { quote, .. } => quote,
        }
    }

    pub(super) fn amm_plan(&self) -> Option<&Plan> {
        match self {
            Self::Only { .. } => None,
            Self::First { suffix, .. } => Some(suffix),
            Self::Last { prefix, .. } => Some(prefix),
        }
    }

    pub(super) fn amount_out(&self) -> U256 {
        match self {
            Self::Only { quote } | Self::Last { quote, .. } => quote.amount_out(),
            Self::First { suffix, .. } => suffix.amount_out,
        }
    }

    pub(super) fn is_live_at(&self, now: u64) -> bool {
        self.quote().is_live_at(now)
    }

    pub(super) fn liquidity_source(&self) -> &'static str {
        match self {
            Self::Only { .. } => "native_rfq",
            Self::First { .. } | Self::Last { .. } => "mixed",
        }
    }
}

pub(super) fn native_route_beats_amm(route: &NativeRoute, amm: Option<&Plan>, now: u64) -> bool {
    route.is_live_at(now) && amm.is_none_or(|plan| route.amount_out() > plan.amount_out)
}

#[cfg(test)]
pub(super) fn native_quote_beats_amm(
    quote: &ValidatedFirmQuote,
    amm: Option<&Plan>,
    now: u64,
) -> bool {
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

pub(super) fn native_route_json(
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
pub(super) async fn choose_native_draft(
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

#[allow(clippy::too_many_arguments)] // mirrors the bounded top-level solve without hidden context
pub(super) async fn solve_profile_stage_bounded(
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

pub(super) fn selected_deadline(request_deadline: u64, native: Option<&ValidatedFirmQuote>) -> u64 {
    native.map_or(request_deadline, |quote| {
        request_deadline.min(quote.deadline())
    })
}

pub(super) const OPTIONAL_RFQ_RESPONSE_RESERVE: Duration = Duration::from_millis(100);

pub(super) fn native_result_or_fallback(
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

pub(super) async fn request_optional_native_quote(
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
