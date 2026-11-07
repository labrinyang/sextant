//! End-to-end routing goldens across pool families and hop counts.
//!
//! Every exact-output check the published repository has today pins the
//! primitives (tests/port.rs) or the UniV3 benchmark. These pin the solver's
//! own output for a two-hop path that crosses pool families, so a speed or
//! refactor change cannot alter a quote without failing here.

use alloy_primitives::{Address, B256, I256, U256};
use sextant::chain::ROBINHOOD_PROFILE;
use sextant::pools::{
    AlgebraMeta, TickInfo, V2Pool, V2Protocol, V2State, V3ExecutionMeta, V3Pool, V3Protocol,
    V3State, V4Meta,
};
use sextant::route::{PreparedRoutes, quantized_plan};
use sextant::state::Snapshot;
use sextant::universe::RouteUniverse;

fn addr(tag: u8) -> Address {
    let mut bytes = [0u8; 20];
    bytes[19] = tag;
    Address::from(bytes)
}

fn pow10(n: u32) -> U256 {
    U256::from(10).pow(U256::from(n))
}

/// A concentrated-liquidity pool with a tick every 10 and flat liquidity, as
/// the benchmark fixture has: every boundary is initialized, so the walk only
/// uses the cached tick prices.
#[allow(clippy::too_many_arguments)] // the fixture spells each fact out
fn dense_v3(
    protocol: V3Protocol,
    address: Address,
    token0: Address,
    token1: Address,
    fee_ppm: u32,
    spacing: i32,
    liquidity: U256,
    algebra: Option<AlgebraMeta>,
    v4: Option<V4Meta>,
) -> (V3Pool, V3State) {
    let ticks: Vec<TickInfo> = (-2_048..2_048)
        .step_by(usize::try_from(spacing).unwrap())
        .map(|tick| TickInfo {
            tick,
            liquidity_net: I256::ZERO,
        })
        .collect();
    let pos = ticks.partition_point(|tick| tick.tick <= 0);
    (
        V3Pool {
            protocol,
            address,
            token0,
            token1,
            fee_ppm,
            tick_spacing: spacing,
            verify_pool_spacing: false,
            execution: Some(V3ExecutionMeta {
                fork_id: 0,
                pool_id: fee_ppm,
            }),
            v4,
            algebra,
        },
        V3State {
            sqrt_price: U256::ONE << 96usize,
            tick: 0,
            liquidity,
            ticks: ticks.into(),
            pos,
            lo_cover: -10_240,
            hi_cover: 10_240,
        },
    )
}

fn v2(pool: Address, token0: Address, token1: Address) -> (V2Pool, V2State) {
    (
        V2Pool {
            protocol: V2Protocol::UNIV2,
            address: pool,
            token0,
            token1,
            fee_bps: 30,
        },
        V2State {
            reserve0: pow10(24),
            reserve1: pow10(24),
        },
    )
}

/// Routes `a` to `c` through `b`: the two-hop skeleton is the only path with
/// pools on it, so the plan is exactly one leg per hop.
fn route_through(
    snapshot: &Snapshot,
    a: Address,
    b: Address,
    c: Address,
    amount_in: U256,
) -> anyhow::Result<U256> {
    let universe =
        RouteUniverse::profile_only(&ROBINHOOD_PROFILE, a, c)?.with_listed(&[vec![a, b, c]])?;
    let routes = PreparedRoutes::for_universe(snapshot, &universe)?;
    let plan = routes.solve(amount_in, 256, 0)?;
    let plan = quantized_plan(snapshot, &plan, amount_in)?;
    assert_eq!(plan.legs.len(), 1, "one path: {plan:?}");
    assert_eq!(plan.legs[0].path.len(), 2, "one hop per edge: {plan:?}");
    Ok(plan.amount_out)
}

fn snapshot(v3: Vec<(V3Pool, V3State)>, v2: Vec<(V2Pool, V2State)>) -> Snapshot {
    Snapshot {
        block: 1,
        settler: Some(addr(0xf0)),
        v3,
        v2,
        ekubo: vec![],
    }
}

#[test]
fn two_hop_v2_then_univ3_is_pinned() {
    let (a, b, c) = (addr(0x0a), addr(0x0b), addr(0x0c));
    let snap = snapshot(
        vec![dense_v3(
            V3Protocol::UNIV3,
            addr(0x21),
            b,
            c,
            3_000,
            10,
            pow10(22),
            None,
            None,
        )],
        vec![v2(addr(0x11), a, b)],
    );
    let amount_out = route_through(&snap, a, b, c, pow10(18)).unwrap();
    assert_eq!(amount_out, U256::from(993_909_213_602_163_689u128));
}

#[test]
fn two_hop_univ4_then_algebra_is_pinned() {
    let (a, b, c) = (addr(0x1a), addr(0x1b), addr(0x1c));
    let snap = snapshot(
        vec![
            dense_v3(
                V3Protocol::UNIV4,
                addr(0x31),
                a,
                b,
                0,
                10,
                pow10(22),
                None,
                Some(V4Meta {
                    pool_id: B256::repeat_byte(0x44),
                    state_slot: B256::repeat_byte(0x55),
                    native: false,
                    hooks: Address::ZERO,
                    swap_fee_0to1_ppm: 3_000,
                    swap_fee_1to0_ppm: 3_000,
                }),
            ),
            dense_v3(
                V3Protocol::SHERIFF,
                addr(0x32),
                b,
                c,
                3_000,
                10,
                pow10(22),
                Some(AlgebraMeta {
                    fee_0to1_ppm: 3_000,
                    fee_1to0_ppm: 3_000,
                }),
                None,
            ),
        ],
        vec![],
    );
    let amount_out = route_through(&snap, a, b, c, pow10(18)).unwrap();
    assert_eq!(amount_out, U256::from(993_811_131_309_326_293u128));
}
