use super::wire::{AmountIn, MAX_FEE_OVERRIDE_BPS, QuoteRequest};
use crate::chain::NativeRfqProfile;
use crate::config::Config;
use crate::engine::Engine;
use crate::settler::BPS_BASE;
use alloy_primitives::{Address, U256};
use anyhow::{Context, ensure};

pub(super) fn parse_addr(s: &str) -> anyhow::Result<Address> {
    s.parse().map_err(|_| anyhow::anyhow!("bad address {s}"))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ExecutionIdentities {
    pub(super) recipient: Option<Address>,
    /// Explicit request sender, preserved for response echoing.
    pub(super) sender: Option<Address>,
    /// AllowanceHolder owner and Settler authorization taker.
    pub(super) required_from: Option<Address>,
    /// Explicit EVM origin binding for Native Router v6.
    pub(super) tx_origin: Option<Address>,
}

pub(super) fn parse_execution_identities(
    req: &QuoteRequest,
) -> anyhow::Result<ExecutionIdentities> {
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

pub(super) fn parse_amount(v: &AmountIn) -> anyhow::Result<U256> {
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

pub(super) fn routed_tokens(
    profile: &crate::chain::ChainProfile,
    token_in: Address,
    token_out: Address,
) -> (Address, Address) {
    (profile.erc20_of(token_in), profile.erc20_of(token_out))
}

/// A request's terms, checked: what the stages after the checks read from the
/// request, in the units they use.
#[derive(Clone, Copy, Debug)]
pub(super) struct QuoteTerms {
    pub(super) token_in: Address,
    pub(super) token_out: Address,
    /// The pair routed: the endpoints, the native sentinel wrapped.
    pub(super) a: Address,
    pub(super) b: Address,
    pub(super) identities: ExecutionIdentities,
    pub(super) amount_in: U256,
    pub(super) slippage_bps: u32,
    pub(super) deadline_seconds: u64,
    /// The Native identity the profile reviewed for these endpoints.
    pub(super) native_identity: Option<NativeRfqProfile>,
    /// Native may be drafted: a source, an identity, a beneficiary and room to
    /// slip.
    pub(super) native_planning_enabled: bool,
    pub(super) requested_fee_bps: Option<u32>,
    pub(super) fee_bps: u32,
}

/// The request's checks against the engine and the profile, in the order a
/// client meets their errors; `native_source` is whether a Native RFQ source
/// is configured.
pub(super) fn validate(
    cfg: &Config,
    engine: &Engine,
    req: &QuoteRequest,
    native_source: bool,
) -> anyhow::Result<QuoteTerms> {
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
    let identities = parse_execution_identities(req)?;
    let recipient = identities.recipient;
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
    let native_planning_enabled = native_source
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
    Ok(QuoteTerms {
        token_in,
        token_out,
        a,
        b,
        identities,
        amount_in,
        slippage_bps,
        deadline_seconds: req.deadline_seconds as u64,
        native_identity,
        native_planning_enabled,
        requested_fee_bps,
        fee_bps,
    })
}
