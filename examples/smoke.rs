// Live validation (a port of the original solver's smoke script): the local simulators
// must reproduce the on-chain quoters EXACTLY (same math, same state, same
// block). Run:
//   cargo run --release --example smoke
// Env: SOLVER_RPC (defaults to the public RPC).

use alloy::eips::BlockId;
use alloy_primitives::{Address, U256, address, aliases::I24, aliases::U160};
use alloy_sol_types::{SolCall, sol};
use anyhow::{Context, ensure};
use sextant::chain::{
    GIGADEX_V3_QUOTER, NATIVE, PUBLIC_RPC, ROBINHOOD_PROFILE, ROBINSWAP_V3_QUOTER, SUSHI_V3_QUOTER,
    UNIV3_QUOTER, UP, UP33_CL_QUOTER, USDG, WETH,
};
use sextant::config::Config;
use sextant::engine::Engine;
use sextant::pools::{V2Protocol, V3Pool, V3Protocol, sim_v2, sim_v3};
use sextant::quotes::{AmountIn, QuoteRequest, quote_swap};
use sextant::rpc::Rpc;
use sextant::state::snapshot_at_for;

sol! {
    interface IQuoterV2 {
        struct Params { address tokenIn; address tokenOut; uint256 amountIn; uint24 fee; uint160 sqrtPriceLimitX96; }
        function quoteExactInputSingle(Params params) external returns (uint256 amountOut, uint160 sqrtPriceX96After, uint32 initializedTicksCrossed, uint256 gasEstimate);
    }
    interface IClQuoter {
        struct Params { address tokenIn; address tokenOut; uint256 amountIn; int24 tickSpacing; uint160 sqrtPriceLimitX96; }
        function quoteExactInputSingle(Params params) external returns (uint256 amountOut, uint160 sqrtPriceX96After, uint32 initializedTicksCrossed, uint256 gasEstimate);
    }
    interface IV2Router {
        function getAmountsOut(uint256 amountIn, address[] path) external view returns (uint256[] memory amounts);
    }
    interface ISolidlyPair {
        function getAmountOut(uint256 amountIn, address tokenIn) external view returns (uint256);
    }
}

const V2_ROUTER: Address = address!("89e5db8b5aa49aa85ac63f691524311aeb649eba");
const NEW_V3_PARITY_BLOCK: u64 = 15_724_416;

fn pow10(n: u64) -> U256 {
    U256::from(10).pow(U256::from(n))
}

async fn quoter_out(
    rpc: &Rpc,
    block: BlockId,
    pool: &V3Pool,
    token_in: Address,
    token_out: Address,
    amt: U256,
) -> anyhow::Result<(U256, u32)> {
    let (quoter, data) = match pool.protocol {
        V3Protocol::UNIV3 => {
            let call = IQuoterV2::quoteExactInputSingleCall {
                params: IQuoterV2::Params {
                    tokenIn: token_in,
                    tokenOut: token_out,
                    amountIn: amt,
                    fee: alloy_primitives::aliases::U24::from(pool.fee_ppm),
                    sqrtPriceLimitX96: U160::ZERO,
                },
            };
            (UNIV3_QUOTER, call.abi_encode())
        }
        V3Protocol::UP33CL => {
            let call = IClQuoter::quoteExactInputSingleCall {
                params: IClQuoter::Params {
                    tokenIn: token_in,
                    tokenOut: token_out,
                    amountIn: amt,
                    tickSpacing: I24::try_from(pool.tick_spacing).expect("fits int24"),
                    sqrtPriceLimitX96: U160::ZERO,
                },
            };
            (UP33_CL_QUOTER, call.abi_encode())
        }
        V3Protocol::GIGADEXV3 => {
            let call = IQuoterV2::quoteExactInputSingleCall {
                params: IQuoterV2::Params {
                    tokenIn: token_in,
                    tokenOut: token_out,
                    amountIn: amt,
                    fee: alloy_primitives::aliases::U24::from(pool.fee_ppm),
                    sqrtPriceLimitX96: U160::ZERO,
                },
            };
            (GIGADEX_V3_QUOTER, call.abi_encode())
        }
        V3Protocol::SUSHIV3 => {
            let call = IQuoterV2::quoteExactInputSingleCall {
                params: IQuoterV2::Params {
                    tokenIn: token_in,
                    tokenOut: token_out,
                    amountIn: amt,
                    fee: alloy_primitives::aliases::U24::from(pool.fee_ppm),
                    sqrtPriceLimitX96: U160::ZERO,
                },
            };
            (SUSHI_V3_QUOTER, call.abi_encode())
        }
        V3Protocol::ROBINSWAPV3 => {
            let call = IQuoterV2::quoteExactInputSingleCall {
                params: IQuoterV2::Params {
                    tokenIn: token_in,
                    tokenOut: token_out,
                    amountIn: amt,
                    fee: alloy_primitives::aliases::U24::from(pool.fee_ppm),
                    sqrtPriceLimitX96: U160::ZERO,
                },
            };
            (ROBINSWAP_V3_QUOTER, call.abi_encode())
        }
        // Callers filter these families because the reference quoters above do
        // not support their ABIs; their calldata parity is covered by E2E.
        // Sheriff is Algebra: its quoter takes a different ABI, and its
        // per-side sliding fee means a quoter reading fee() would disagree
        // anyway. Parity is pinned offline instead — tests/port.rs asserts the
        // simulator against the pool's own swap() at a fixed block.
        _ => {
            anyhow::bail!(
                "no compatible reference quoter for {}",
                pool.protocol.as_str()
            )
        }
    };
    let ret = rpc
        .eth_call(quoter, data, block)
        .await
        .context("reference V3 quoter eth_call")?;
    let dec = IQuoterV2::quoteExactInputSingleCall::abi_decode_returns(&ret)
        .context("decoding reference V3 quoter response")?;
    Ok((dec.amountOut, dec.initializedTicksCrossed))
}

async fn pinned_new_v3_parity(rpc: &Rpc) -> anyhow::Result<()> {
    let snap = snapshot_at_for(
        &ROBINHOOD_PROFILE,
        rpc,
        None,
        WETH,
        USDG,
        Some(NEW_V3_PARITY_BLOCK),
    )
    .await?;
    for (protocol, fee, weth_in, usdg_in, must_cross) in [
        (
            V3Protocol::GIGADEXV3,
            500,
            U256::from(10).pow(U256::from(18)),
            U256::from(1_000_000_000u64),
            true,
        ),
        (
            V3Protocol::SUSHIV3,
            3000,
            U256::from(10).pow(U256::from(18)),
            U256::from(1_000_000_000u64),
            false,
        ),
        (
            V3Protocol::ROBINSWAPV3,
            500,
            U256::from(2) * U256::from(10).pow(U256::from(18)),
            U256::from(1_000_000_000u64),
            true,
        ),
    ] {
        let (pool, state) = snap
            .v3
            .iter()
            .find(|(pool, _)| pool.protocol == protocol && pool.fee_ppm == fee)
            .with_context(|| {
                format!(
                    "pinned snapshot has no {} fee {fee} pool",
                    protocol.as_str()
                )
            })?;
        for (token_in, token_out, amount_in, expect_cross) in [
            (WETH, USDG, weth_in, must_cross),
            (USDG, WETH, usdg_in, false),
        ] {
            let zero_for_one = token_in == pool.token0;
            let sim = sim_v3(pool, state, zero_for_one, amount_in)?;
            ensure!(
                sim.consumed == amount_in,
                "{} pinned parity exhausted modeled depth",
                protocol.as_str()
            );
            let (quoted, crossed) = quoter_out(
                rpc,
                BlockId::number(NEW_V3_PARITY_BLOCK),
                pool,
                token_in,
                token_out,
                amount_in,
            )
            .await?;
            ensure!(
                sim.amount_out == quoted,
                "{} pinned parity mismatch: sim={} quoter={quoted}",
                protocol.as_str(),
                sim.amount_out
            );
            ensure!(
                !expect_cross || crossed > 0,
                "{} pinned case no longer crosses a tick",
                protocol.as_str()
            );
        }
        println!("pinned {} parity: both directions exact", protocol.as_str());
    }
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cfg = Config::from_env()?;
    let rpc = Rpc::connect(&std::env::var("SOLVER_RPC").unwrap_or_else(|_| PUBLIC_RPC.into()))?;
    rpc.verify_chain_id(ROBINHOOD_PROFILE.chain_id, "SOLVER_RPC")
        .await?;
    let engine = Engine::for_profile(rpc.clone(), &ROBINHOOD_PROFILE);
    pinned_new_v3_parity(&rpc).await?;
    let pairs = [(WETH, USDG), (WETH, UP), (USDG, UP)];
    let mut checked = 0u32;
    let mut checked_univ3 = 0u32;
    let mut checked_up33cl = 0u32;
    let mut checked_extended_v3 = 0u32;
    let mut checked_univ2 = 0u32;
    let mut checked_up33v2 = 0u32;
    let mut exact = 0u32;
    let mut mismatches: Vec<String> = Vec::new();

    for (a, b) in pairs {
        let snap = snapshot_at_for(&ROBINHOOD_PROFILE, &rpc, None, a, b, None).await?;
        let block = BlockId::number(snap.block);
        let settler = snap.settler.context("snapshot has no Settler identity")?;
        println!(
            "pair {a:#x} → {b:#x}   block {}   v3 pools {}   v2 pools {}   settler {:#x}",
            snap.block,
            snap.v3.len(),
            snap.v2.len(),
            settler
        );

        for (pool, st) in &snap.v3 {
            if !matches!(
                pool.protocol,
                V3Protocol::UNIV3
                    | V3Protocol::UP33CL
                    | V3Protocol::GIGADEXV3
                    | V3Protocol::SUSHIV3
                    | V3Protocol::ROBINSWAPV3
            ) {
                continue;
            }
            for zfo in [true, false] {
                for amt in [pow10(13), pow10(16), pow10(18), pow10(20)] {
                    let sim = sim_v3(pool, st, zfo, amt)?;
                    if sim.consumed != amt {
                        continue;
                    }
                    let (tin, tout) = if zfo {
                        (pool.token0, pool.token1)
                    } else {
                        (pool.token1, pool.token0)
                    };
                    let (q, _) = quoter_out(&rpc, block, pool, tin, tout, amt)
                        .await
                        .with_context(|| {
                            format!(
                                "{} reference quote failed for pool {:#x}, zfo={zfo}, amount={amt}",
                                pool.protocol.as_str(),
                                pool.address
                            )
                        })?;
                    checked += 1;
                    match pool.protocol {
                        V3Protocol::UNIV3 => checked_univ3 += 1,
                        V3Protocol::UP33CL => checked_up33cl += 1,
                        V3Protocol::GIGADEXV3 | V3Protocol::SUSHIV3 | V3Protocol::ROBINSWAPV3 => {
                            checked_extended_v3 += 1
                        }
                        _ => unreachable!("unsupported reference quoter"),
                    }
                    if q == sim.amount_out {
                        exact += 1;
                    } else {
                        mismatches.push(format!(
                            "{} {:#x} fee={} ts={} zfo={zfo} amt={amt} sim={} quoter={q}",
                            pool.protocol.as_str(),
                            pool.address,
                            pool.fee_ppm,
                            pool.tick_spacing,
                            sim.amount_out
                        ));
                    }
                }
            }
        }

        for (pool, st) in &snap.v2 {
            for zfo in [true, false] {
                for amt in [pow10(13), pow10(16), pow10(18)] {
                    let sim = sim_v2(pool, st, zfo, amt)?;
                    let (tin, tout) = if zfo {
                        (pool.token0, pool.token1)
                    } else {
                        (pool.token1, pool.token0)
                    };
                    // univ2 pairs are quoted through the router; up33v2
                    // (Solidly) pools must be asked THEMSELVES — the router
                    // would resolve the univ2 twin for the same tokens.
                    let q = if pool.protocol == V2Protocol::UP33V2 {
                        let call = ISolidlyPair::getAmountOutCall {
                            amountIn: amt,
                            tokenIn: tin,
                        };
                        let ret = rpc
                            .eth_call(pool.address, call.abi_encode(), block)
                            .await
                            .with_context(|| {
                                format!(
                                    "up33v2 reference quote failed for pool {:#x}, zfo={zfo}, amount={amt}",
                                    pool.address
                                )
                            })?;
                        ISolidlyPair::getAmountOutCall::abi_decode_returns(&ret)
                            .context("decoding up33v2 reference quote")?
                    } else {
                        let call = IV2Router::getAmountsOutCall {
                            amountIn: amt,
                            path: vec![tin, tout],
                        };
                        let ret = rpc
                            .eth_call(V2_ROUTER, call.abi_encode(), block)
                            .await
                            .with_context(|| {
                                format!(
                                    "univ2 reference quote failed for pool {:#x}, zfo={zfo}, amount={amt}",
                                    pool.address
                                )
                            })?;
                        let amounts = IV2Router::getAmountsOutCall::abi_decode_returns(&ret)
                            .context("decoding univ2 reference quote")?;
                        *amounts.last().expect("nonempty amounts")
                    };
                    checked += 1;
                    match pool.protocol {
                        V2Protocol::UP33V2 => checked_up33v2 += 1,
                        _ => checked_univ2 += 1,
                    }
                    if q == sim.amount_out {
                        exact += 1;
                    } else {
                        mismatches.push(format!(
                            "{} {:#x} zfo={zfo} amt={amt} sim={} chain={q}",
                            pool.protocol.as_str(),
                            pool.address,
                            sim.amount_out
                        ));
                    }
                }
            }
        }
    }

    println!(
        "\nquoter cross-check: {exact}/{checked} exact (univ3={checked_univ3}, up33cl={checked_up33cl}, extendedv3={checked_extended_v3}, univ2={checked_univ2}, up33v2={checked_up33v2})"
    );
    if checked_univ3 == 0 || checked_up33cl == 0 || checked_univ2 == 0 || checked_up33v2 == 0 {
        anyhow::bail!("quoter cross-check had no coverage for one or more reference protocols");
    }
    for m in &mismatches {
        println!("  MISMATCH  {m}");
    }
    if !mismatches.is_empty() {
        std::process::exit(1);
    }

    // end-to-end quote through the whole pipeline
    println!("\nfull quotes:");
    for (tin, tout, amt) in [
        (WETH, USDG, pow10(18)),
        (NATIVE, UP, pow10(17)),
        (USDG, WETH, U256::from(5) * pow10(20)),
    ] {
        let req = QuoteRequest {
            chain_id: cfg.profile.chain_id,
            token_in: format!("{tin:#x}"),
            token_out: format!("{tout:#x}"),
            amount_in: AmountIn::Str(amt.to_string()),
            slippage_bps: 50,
            recipient: None,
            sender: None,
            tx_origin: None,
            deadline_seconds: 600,
            fee_bps: None,
        };
        let q = quote_swap(&cfg, &engine, req).await?;
        let legs: Vec<String> = q
            .route
            .iter()
            .map(|l| format!("{}bps×{}hop", l.share_bps, l.hops.len()))
            .collect();
        println!(
            "  {}… → {}…  in={}  gross={}  net={}  route: {}",
            &q.token_in[..10],
            &q.token_out[..10],
            q.amount_in,
            q.amount_out_gross,
            q.amount_out_net,
            legs.join(" + ")
        );
    }
    Ok(())
}
