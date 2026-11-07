//! Ekubo V3 pool model and the small adapter between chain quote data and the
//! official Rust SDK. Ekubo has different price/fee arithmetic from Uniswap
//! V3, so it deliberately remains its own route pool family. Fetching pool
//! keys and quote data is the application's (`sextant::ekubo`).

use alloy_primitives::{Address, B256, U256, aliases::U96};
use anyhow::{Context, ensure};
use ekubo_sdk::{
    chain::evm::{
        EvmConcentratedPool, EvmConcentratedPoolState, EvmFullRangePool, EvmFullRangePoolState,
        EvmPoolConfig, EvmPoolKey, EvmPoolTypeConfig, EvmStableswapPool, EvmStableswapPoolState,
        EvmVe33ConcentratedPool, EvmVe33ConcentratedPoolState, EvmVe33FullRangePool,
        EvmVe33FullRangePoolState, EvmVe33StableswapPool, EvmVe33StableswapPoolState,
        float_sqrt_ratio_to_fixed,
    },
    quoting::{
        pools::{
            concentrated::ConcentratedPool, full_range::FullRangePool, stableswap::StableswapPool,
            ve33::Ve33Pool,
        },
        types::{Pool, PoolConfig, PoolKey, Quote, QuoteParams, Tick, TokenAmount},
    },
};

pub const VE33: Address = alloy_primitives::address!("d18685a514e59b06d59824e16db07e73345d9953");

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EkuboExtension {
    Extensionless,
    Ve33,
}

impl EkuboExtension {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Extensionless => "extensionless",
            Self::Ve33 => "ve33",
        }
    }

    pub const fn requires_forward(self) -> bool {
        matches!(self, Self::Ve33)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EkuboPoolType {
    Concentrated { tick_spacing: u32 },
    FullRange,
    Stableswap { amplification: u8, center_tick: i32 },
}

impl EkuboPoolType {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Concentrated { .. } => "concentrated",
            Self::FullRange => "full_range",
            Self::Stableswap { .. } => "stableswap",
        }
    }

    pub const fn tick_spacing(self) -> Option<u32> {
        match self {
            Self::Concentrated { tick_spacing } => Some(tick_spacing),
            Self::FullRange | Self::Stableswap { .. } => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EkuboPoolKey {
    pub pool_id: B256,
    pub token0: Address,
    pub token1: Address,
    pub config: B256,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EkuboTick {
    pub number: i32,
    pub liquidity_delta: i128,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EkuboQuoteState {
    pub tick: i32,
    pub sqrt_ratio: U96,
    pub liquidity: u128,
    pub min_tick: i32,
    pub max_tick: i32,
    pub ticks: Vec<EkuboTick>,
}

pub fn supported_key(key: EkuboPoolKey) -> anyhow::Result<Option<EkuboPoolKey>> {
    let config = EvmPoolConfig::try_from(key.config).context("invalid Ekubo topology config")?;
    if config.extension != Address::ZERO && config.extension != VE33 {
        return Ok(None);
    }
    ensure!(
        config.extension != VE33 || config.fee == 0,
        "Ve33 Core fee must be zero"
    );
    let sdk_key = EvmPoolKey {
        token0: key.token0,
        token1: key.token1,
        config,
    };
    ensure!(sdk_key.pool_id() == key.pool_id, "Ekubo pool id mismatch");
    Ok(Some(key))
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum EkuboModel {
    Concentrated(EvmConcentratedPool),
    FullRange(EvmFullRangePool),
    Stableswap(EvmStableswapPool),
    Ve33Concentrated(EvmVe33ConcentratedPool),
    Ve33FullRange(EvmVe33FullRangePool),
    Ve33Stableswap(EvmVe33StableswapPool),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EkuboPool {
    pub pool_id: B256,
    /// Tokens as the route graph sees them. Ekubo's native address is folded
    /// to the chain's wrapped native token here, just like Uniswap V4.
    pub token0: Address,
    pub token1: Address,
    /// Tokens in the Core PoolKey. Native remains address(0).
    pub core_token0: Address,
    pub core_token1: Address,
    pub config: B256,
    pub fee_x64: u64,
    pub extension: EkuboExtension,
    pub pool_type: EkuboPoolType,
    model: EkuboModel,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EkuboState {
    Concentrated(EvmConcentratedPoolState),
    FullRange(EvmFullRangePoolState),
    Stableswap(EvmStableswapPoolState),
    Ve33Concentrated(EvmVe33ConcentratedPoolState),
    Ve33FullRange(EvmVe33FullRangePoolState),
    Ve33Stableswap(EvmVe33StableswapPoolState),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EkuboSim {
    pub consumed: U256,
    pub amount_out: U256,
    pub state_after: EkuboState,
    /// Exact multiplicative fee loss in its native denomination. For Core
    /// pools this is input-side; Ve33 charges exact-input swaps on output.
    pub fee_loss: Option<(U256, U256)>,
}

fn sdk_quote<P>(
    pool: &P,
    state: P::State,
    token: Address,
    amount: i128,
) -> anyhow::Result<Quote<P::Resources, P::State>>
where
    P: Pool<Address = Address, Meta = ()>,
    P::QuoteError: std::fmt::Display,
{
    pool.quote(QuoteParams {
        token_amount: TokenAmount { token, amount },
        sqrt_ratio_limit: None,
        override_state: Some(state),
        meta: (),
    })
    .map_err(|error| anyhow::anyhow!("Ekubo quote failed: {error}"))
}

fn finish_sim(
    extension: EkuboExtension,
    consumed: i128,
    amount_out: u128,
    fees_paid: u128,
    state_after: EkuboState,
) -> anyhow::Result<EkuboSim> {
    let consumed = u128::try_from(consumed).context("Ekubo consumed a negative input")?;
    let amount_out = U256::from(amount_out);
    let fee = U256::from(fees_paid);
    let fee_loss = if fee.is_zero() {
        None
    } else {
        Some(match extension {
            EkuboExtension::Extensionless => {
                let gross = U256::from(consumed);
                (
                    gross,
                    gross.checked_sub(fee).context("Ekubo fee exceeds input")?,
                )
            }
            EkuboExtension::Ve33 => (
                amount_out.checked_add(fee).context("Ekubo fee overflow")?,
                amount_out,
            ),
        })
    };
    Ok(EkuboSim {
        consumed: U256::from(consumed),
        amount_out,
        state_after,
        fee_loss,
    })
}

pub fn sim_ekubo(
    pool: &EkuboPool,
    state: &EkuboState,
    zero_for_one: bool,
    amount_in: U256,
) -> anyhow::Result<EkuboSim> {
    let amount = i128::try_from(amount_in).context("Ekubo input exceeds int128")?;
    let token = if zero_for_one {
        pool.core_token0
    } else {
        pool.core_token1
    };
    match (&pool.model, state) {
        (EkuboModel::Concentrated(model), EkuboState::Concentrated(state)) => {
            let quote = sdk_quote(model, *state, token, amount)?;
            finish_sim(
                pool.extension,
                quote.consumed_amount,
                quote.calculated_amount,
                quote.fees_paid,
                EkuboState::Concentrated(quote.state_after),
            )
        }
        (EkuboModel::FullRange(model), EkuboState::FullRange(state)) => {
            let quote = sdk_quote(model, *state, token, amount)?;
            finish_sim(
                pool.extension,
                quote.consumed_amount,
                quote.calculated_amount,
                quote.fees_paid,
                EkuboState::FullRange(quote.state_after),
            )
        }
        (EkuboModel::Stableswap(model), EkuboState::Stableswap(state)) => {
            let quote = sdk_quote(model, *state, token, amount)?;
            finish_sim(
                pool.extension,
                quote.consumed_amount,
                quote.calculated_amount,
                quote.fees_paid,
                EkuboState::Stableswap(quote.state_after),
            )
        }
        (EkuboModel::Ve33Concentrated(model), EkuboState::Ve33Concentrated(state)) => {
            let quote = sdk_quote(model, *state, token, amount)?;
            finish_sim(
                pool.extension,
                quote.consumed_amount,
                quote.calculated_amount,
                quote.fees_paid,
                EkuboState::Ve33Concentrated(quote.state_after),
            )
        }
        (EkuboModel::Ve33FullRange(model), EkuboState::Ve33FullRange(state)) => {
            let quote = sdk_quote(model, *state, token, amount)?;
            finish_sim(
                pool.extension,
                quote.consumed_amount,
                quote.calculated_amount,
                quote.fees_paid,
                EkuboState::Ve33FullRange(quote.state_after),
            )
        }
        (EkuboModel::Ve33Stableswap(model), EkuboState::Ve33Stableswap(state)) => {
            let quote = sdk_quote(model, *state, token, amount)?;
            finish_sim(
                pool.extension,
                quote.consumed_amount,
                quote.calculated_amount,
                quote.fees_paid,
                EkuboState::Ve33Stableswap(quote.state_after),
            )
        }
        _ => anyhow::bail!("Ekubo pool/state variant mismatch"),
    }
}

pub fn commit_ekubo(state: &mut EkuboState, sim: &EkuboSim) {
    *state = sim.state_after;
}

pub fn build_pool(
    key: &EkuboPoolKey,
    quote: EkuboQuoteState,
    swap_fee: Option<u64>,
    wrapped_native: Address,
) -> anyhow::Result<(EkuboPool, EkuboState)> {
    let config = EvmPoolConfig::try_from(key.config).context("invalid Ekubo pool config")?;
    let generic_key = EvmPoolKey {
        token0: key.token0,
        token1: key.token1,
        config,
    };
    ensure!(
        generic_key.pool_id() == key.pool_id,
        "Ekubo pool id mismatch"
    );
    let extension = match config.extension {
        Address::ZERO if swap_fee.is_none() => EkuboExtension::Extensionless,
        VE33 if swap_fee.is_some() => {
            ensure!(config.fee == 0, "Ve33 Core fee must be zero");
            EkuboExtension::Ve33
        }
        _ => anyhow::bail!("unsupported Ekubo extension"),
    };
    let fixed_sqrt_ratio = float_sqrt_ratio_to_fixed(quote.sqrt_ratio);
    let sdk_ticks: Vec<Tick> = quote
        .ticks
        .into_iter()
        .map(|tick| Tick {
            index: tick.number,
            liquidity_delta: tick.liquidity_delta,
        })
        .collect();

    let (pool_type, model, state) = match config.pool_type_config {
        EvmPoolTypeConfig::Concentrated(pool_type_config) => {
            let sdk_key = PoolKey {
                token0: key.token0,
                token1: key.token1,
                config: PoolConfig {
                    extension: config.extension,
                    fee: config.fee,
                    pool_type_config,
                },
            };
            let base = ConcentratedPool::from_partial_data(
                sdk_key,
                fixed_sqrt_ratio,
                sdk_ticks,
                quote.min_tick,
                quote.max_tick,
                quote.liquidity,
                quote.tick,
            )
            .context("constructing Ekubo concentrated pool")?;
            let pool_type = EkuboPoolType::Concentrated {
                tick_spacing: pool_type_config.0,
            };
            match swap_fee {
                Some(fee) => {
                    let model = Ve33Pool::new(base, fee).context("constructing Ve33 pool")?;
                    let state = model.state();
                    (
                        pool_type,
                        EkuboModel::Ve33Concentrated(model),
                        EkuboState::Ve33Concentrated(state),
                    )
                }
                None => {
                    let state = base.state();
                    (
                        pool_type,
                        EkuboModel::Concentrated(base),
                        EkuboState::Concentrated(state),
                    )
                }
            }
        }
        EvmPoolTypeConfig::FullRange(pool_type_config) => {
            let sdk_key = PoolKey {
                token0: key.token0,
                token1: key.token1,
                config: PoolConfig {
                    extension: config.extension,
                    fee: config.fee,
                    pool_type_config,
                },
            };
            let base = FullRangePool::new(
                sdk_key,
                EvmFullRangePoolState {
                    sqrt_ratio: fixed_sqrt_ratio,
                    liquidity: quote.liquidity,
                },
            )
            .context("constructing Ekubo full-range pool")?;
            match swap_fee {
                Some(fee) => {
                    let model = Ve33Pool::new(base, fee).context("constructing Ve33 pool")?;
                    let state = model.state();
                    (
                        EkuboPoolType::FullRange,
                        EkuboModel::Ve33FullRange(model),
                        EkuboState::Ve33FullRange(state),
                    )
                }
                None => {
                    let state = base.state();
                    (
                        EkuboPoolType::FullRange,
                        EkuboModel::FullRange(base),
                        EkuboState::FullRange(state),
                    )
                }
            }
        }
        EvmPoolTypeConfig::Stableswap(pool_type_config) => {
            let sdk_key = PoolKey {
                token0: key.token0,
                token1: key.token1,
                config: PoolConfig {
                    extension: config.extension,
                    fee: config.fee,
                    pool_type_config,
                },
            };
            let base = StableswapPool::new(
                sdk_key,
                EvmStableswapPoolState {
                    sqrt_ratio: fixed_sqrt_ratio,
                    liquidity: quote.liquidity,
                },
            )
            .context("constructing Ekubo stableswap pool")?;
            let pool_type = EkuboPoolType::Stableswap {
                amplification: pool_type_config.amplification_factor,
                center_tick: pool_type_config.center_tick,
            };
            match swap_fee {
                Some(fee) => {
                    let model = Ve33Pool::new(base, fee).context("constructing Ve33 pool")?;
                    let state = model.state();
                    (
                        pool_type,
                        EkuboModel::Ve33Stableswap(model),
                        EkuboState::Ve33Stableswap(state),
                    )
                }
                None => {
                    let state = base.state();
                    (
                        pool_type,
                        EkuboModel::Stableswap(base),
                        EkuboState::Stableswap(state),
                    )
                }
            }
        }
    };

    let routed = |token| {
        if token == Address::ZERO {
            wrapped_native
        } else {
            token
        }
    };
    let token0 = routed(key.token0);
    let token1 = routed(key.token1);
    ensure!(
        token0 != token1,
        "Ekubo pool collapses after native wrapping"
    );
    Ok((
        EkuboPool {
            pool_id: key.pool_id,
            token0,
            token1,
            core_token0: key.token0,
            core_token1: key.token1,
            config: key.config,
            fee_x64: swap_fee.unwrap_or(config.fee),
            extension,
            pool_type,
            model,
        },
        state,
    ))
}
