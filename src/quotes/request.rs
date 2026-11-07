use super::wire::{AmountIn, QuoteRequest};
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
