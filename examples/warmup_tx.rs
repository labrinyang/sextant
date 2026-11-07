// Cross-language differential fixture: build the deterministic warmup tx and
// print its calldata + planned output. The original solver's script prints the
// same pair; byte-equality proved math → quantize → encode parity.

use alloy_primitives::{I256, U256, address};
use sextant::abi::tohex;
use sextant::chain::ROBINHOOD_PROFILE;
use sextant::pools::{TickInfo, V3ExecutionMeta, V3Pool, V3Protocol, V3State};
use sextant::route::{PreparedRoutes, quantized_plan};
use sextant::settler::build_swap_tx_for_profile;
use sextant::state::Snapshot;

fn main() -> anyhow::Result<()> {
    let l = U256::from(10).pow(U256::from(21));
    let pool = V3Pool {
        protocol: V3Protocol::UP33CL,
        address: address!("1000000000000000000000000000000000000001"),
        token0: address!("0a00000000000000000000000000000000000001"),
        token1: address!("0b00000000000000000000000000000000000001"),
        fee_ppm: 3000,
        tick_spacing: 200,
        verify_pool_spacing: false,
        execution: Some(V3ExecutionMeta {
            fork_id: 40,
            pool_id: 200,
        }),
        v4: None,
        algebra: None,
    };
    let ticks = vec![
        TickInfo {
            tick: -600,
            liquidity_net: I256::try_from(l)?,
        },
        TickInfo {
            tick: 600,
            liquidity_net: -I256::try_from(l)?,
        },
    ];
    let state = V3State {
        sqrt_price: U256::ONE << 96usize,
        tick: 0,
        liquidity: l,
        ticks: ticks.into(),
        pos: 1,
        lo_cover: -180_000,
        hi_cover: 180_000,
    };
    let snap = Snapshot {
        block: 1,
        settler: Some(address!("1d4b86491ec211257cbedd77a4380a7494624eff")),
        v3: vec![(pool.clone(), state)],
        v2: vec![],
        ekubo: vec![],
    };
    let amount = U256::from(10).pow(U256::from(18));
    let plan = quantized_plan(
        &snap,
        &PreparedRoutes::for_profile(&snap, &ROBINHOOD_PROFILE, pool.token0, pool.token1)?
            .solve(amount, 64, 200)?,
        amount,
    )?;
    let tx = build_swap_tx_for_profile(
        &ROBINHOOD_PROFILE,
        9,
        Some(address!("00000000000000000000000000000000000000fe")),
        None,
        &snap,
        &plan,
        pool.token0,
        pool.token1,
        amount,
        U256::ONE,
        address!("00000000000000000000000000000000000000aa"),
        1 << 31,
    )?;
    println!("{}", tohex(&tx.data));
    println!("{}", plan.amount_out);
    Ok(())
}
