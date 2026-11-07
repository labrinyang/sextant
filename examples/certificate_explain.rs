//! Itemize one quote's certified bound: the dual point, and which pools carry
//! the arbitrage the bound is charging us for.
//!
//! Run with:
//!   SOLVER_RPC=… cargo run --release --example certificate_explain -- \
//!       <tokenIn> <tokenOut> <amountIn> [--block N]
//!
//! SOLVER_CHAIN picks the chain (robinhood when unset). A chain whose pools
//! come from an indexer is refused, because this tool configures none.
//!
//! Reads only.

use alloy_primitives::{Address, U256};
use anyhow::Context;
use sextant::certificate::{attribution, bound_at, certify_in_universe, dual_prices};
use sextant::chain::profile_by_key;
use sextant::engine::Engine;
use sextant::route::{ALLOC_CHUNKS, MIN_SHARE_BPS, PreparedRoutes, plan_states, quantized_plan};
use sextant::rpc::Rpc;

fn token(name: &str) -> anyhow::Result<Address> {
    Ok(match name.to_ascii_uppercase().as_str() {
        "WETH" => sextant::chain::WETH,
        "USDG" => sextant::chain::USDG,
        "UP" => sextant::chain::UP,
        "SLVR" => sextant::chain::SLVR,
        "ETH" | "NATIVE" => sextant::chain::NATIVE,
        _ => name.parse().context("token must be a name or address")?,
    })
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    anyhow::ensure!(args.len() >= 3, "usage: <tokenIn> <tokenOut> <amountIn>");
    let chain = std::env::var("SOLVER_CHAIN")
        .ok()
        .filter(|key| !key.trim().is_empty())
        .unwrap_or_else(|| "robinhood".to_string());
    let profile = profile_by_key(&chain)?;
    anyhow::ensure!(
        !profile.needs_indexer(),
        "SOLVER_CHAIN={}: {} finds its pools through an indexer, and this tool configures none",
        profile.key,
        profile.name
    );
    let token_in = profile.erc20_of(token(&args[0])?);
    let token_out = profile.erc20_of(token(&args[1])?);
    let amount_in = U256::from_str_radix(&args[2], 10).context("amountIn")?;
    let pinned = args
        .iter()
        .position(|a| a == "--block")
        .and_then(|i| args.get(i + 1))
        .map(|b| b.parse::<u64>())
        .transpose()
        .context("--block")?;

    let rpc_url = std::env::var("SOLVER_RPC").unwrap_or_else(|_| profile.public_rpc.to_string());
    let rpc = Rpc::connect(&rpc_url)?;
    rpc.verify_chain_id(profile.chain_id, "SOLVER_RPC").await?;
    let block = match pinned {
        Some(block) => block,
        None => rpc.block_number().await?,
    };
    let engine = Engine::for_profile_pinned(rpc, profile, None, block);
    let (stamped, _) = engine.snapshot(token_in, token_out).await?;
    let snap = &stamped.snap;
    let universe = stamped.universe.orient(token_in, token_out)?;
    // Solved in the same universe the certificate below is computed in.
    let plan = PreparedRoutes::for_universe(snap, &universe)?.solve(
        amount_in,
        *ALLOC_CHUNKS,
        *MIN_SHARE_BPS,
    )?;
    let plan = quantized_plan(snap, &plan, amount_in)?;

    let states = plan_states(snap, &plan)?;
    let routed = sextant::certificate::PoolSet::of(snap, &plan);
    let mut prices = dual_prices(snap, token_out, &states, &routed)?;
    let certificate = certify_in_universe(&universe, snap, token_in, token_out, amount_in, &plan)?;
    let reachable = sextant::certificate::PoolSet::reachable_in_universe(snap, &universe);
    let scope = Some(&reachable);
    let (raw, _) = bound_at(snap, token_in, amount_in, &prices, scope, &routed)?;
    let (catalog, _) = bound_at(snap, token_in, amount_in, &prices, None, &routed)?;

    let started = std::time::Instant::now();
    let bound = sextant::certificate::tighten(
        snap,
        token_in,
        token_out,
        amount_in,
        &mut prices,
        scope,
        &routed,
        std::env::var("TIGHTEN_BUDGET")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(512),
    )?;
    let tighten_us = started.elapsed().as_micros();

    let bps = |bound: U256| -> String {
        let gap = bound.saturating_sub(certificate.achieved);
        let scaled = gap * U256::from(100_000_000u64) / certificate.achieved;
        sextant::certificate::format_bps_e4(scaled)
    };
    println!("block {block}  pools {}", snap.v3.len() + snap.v2.len());
    println!("achieved  {}", certificate.achieved);
    println!("reachable {raw}  gap {}", bps(raw));
    println!("catalog   {catalog}  gap {}", bps(catalog));
    println!("tightened {bound}  gap {}  ({tighten_us}us)", bps(bound));
    // g is convex in ν. If the reported point is really its minimum, this
    // curve bottoms out at 1.0; if it does not, the search is at fault.
    println!("\nbound vs a scaling of the input token's price:");
    for (num, den) in [
        (50u64, 100u64),
        (75, 100),
        (90, 100),
        (95, 100),
        (99, 100),
        (100, 100),
        (101, 100),
        (110, 100),
        (150, 100),
    ] {
        let mut probe = prices.clone();
        let base = probe[&token_in];
        probe.insert(
            token_in,
            sextant::certificate::Price {
                num: base.num * U256::from(num),
                den: base.den * U256::from(den),
            },
        );
        let (value, _) = bound_at(snap, token_in, amount_in, &probe, scope, &routed)?;
        println!("  x{num:>4}/{den}  {value:>24}  gap {}", bps(value));
    }

    println!("\ndual point (out-wei per wei):");
    let mut priced: Vec<_> = prices.iter().collect();
    priced.sort_by_key(|(token, _)| **token);
    for (token, price) in priced {
        // Decimal magnitude is what matters when hunting a mispriced token.
        let approx = price.num.bit_len() as i64 - price.den.bit_len() as i64;
        println!("  {token:#x}  {}/{}  ~2^{approx}", price.num, price.den);
    }

    println!("\ntop arbitrage contributors:");
    let items = attribution(snap, &prices)?;
    let total: U256 = items
        .iter()
        .map(|item| item.3)
        .fold(U256::ZERO, |a, b| a + b);
    println!("  (pool arb total {total})");
    for (label, token0, token1, arb) in items.iter().take(12) {
        if arb.is_zero() {
            break;
        }
        println!("  {arb:>40}  {label}  {token0:#x}/{token1:#x}");
    }

    // The claim `arb_p` makes is "no trade with this pool is worth more than
    // this". Scanning the EXACT simulator is the independent way to check it
    // on a live pool, where tick spacing and a truncated window look nothing
    // like a unit-test fixture.
    println!("\nclosed form vs a scan of the simulator (top contributors):");
    for (label, _, _, arb) in items.iter().take(5) {
        if arb.is_zero() {
            break;
        }
        let address = label.split_whitespace().nth(1).unwrap_or_default();
        let mut scanned = U256::ZERO;
        for (pool, state) in &snap.v3 {
            if format!("{:#x}", pool.address) != address {
                continue;
            }
            for zero_for_one in [true, false] {
                let (token_in_side, token_out_side) = if zero_for_one {
                    (pool.token0, pool.token1)
                } else {
                    (pool.token1, pool.token0)
                };
                let price_in = prices[&token_in_side];
                let price_out = prices[&token_out_side];
                for step in 0..96u32 {
                    let delta = state.liquidity * U256::from(2u64).pow(U256::from(step))
                        / U256::from(1u64 << 30);
                    if delta.is_zero() {
                        continue;
                    }
                    let Ok(sim) = sextant::pools::sim_v3(pool, state, zero_for_one, delta) else {
                        continue;
                    };
                    if sim.consumed != delta {
                        continue;
                    }
                    let gain = price_out.num * sim.amount_out / price_out.den;
                    let cost = price_in.num * delta / price_in.den + U256::ONE;
                    scanned = scanned.max(gain.saturating_sub(cost));
                }
            }
        }
        println!("  {label}\n    closed {arb}\n    scan   {scanned}");
    }
    Ok(())
}
