//! Deterministic CPU profile for the routing hot path.
//!
//! Run with: cargo run --release --example route_profile

use alloy_primitives::{Address, I256, U256};
use sextant::certificate::certify_in_universe;
use sextant::chain::ROBINHOOD_PROFILE;
use sextant::pools::{TickInfo, V3ExecutionMeta, V3Pool, V3Protocol, V3State};
use sextant::route::{Plan, PreparedRoutes, quantized_plan};
use sextant::state::Snapshot;
use sextant::universe::RouteUniverse;
use std::hint::black_box;
use std::time::Instant;

const POOLS: usize = 8;
const TICKS_PER_POOL: i32 = 4_096;
const CLONE_RUNS: u32 = 200;
const ROUTE_RUNS: u32 = 5;
const CERT_RUNS: u32 = 50;
/// Fresh snapshots: nothing a walk memoizes on the tick lists carries over.
const COLD_RUNS: u32 = 5;

fn addr(tag: u8) -> Address {
    let mut bytes = [0u8; 20];
    bytes[19] = tag;
    Address::from(bytes)
}

fn fixture() -> (Snapshot, Address, Address, U256) {
    let token0 = addr(1);
    let token1 = addr(2);
    let mut v3 = Vec::with_capacity(POOLS);
    for i in 0..POOLS {
        let liquidity = U256::from(10).pow(U256::from(22)) * U256::from(i + 1);
        let ticks: Vec<TickInfo> = (-TICKS_PER_POOL / 2..TICKS_PER_POOL / 2)
            .map(|n| TickInfo {
                tick: n * 10,
                liquidity_net: I256::ZERO,
            })
            .collect();
        let pos = ticks.partition_point(|tick| tick.tick <= 0);
        v3.push((
            V3Pool {
                protocol: V3Protocol::UNIV3,
                address: addr(10 + i as u8),
                token0,
                token1,
                fee_ppm: 3_000,
                tick_spacing: 10,
                verify_pool_spacing: false,
                execution: Some(V3ExecutionMeta {
                    fork_id: 0,
                    pool_id: 3_000,
                }),
                v4: None,
                algebra: None,
            },
            V3State {
                sqrt_price: U256::ONE << 96usize,
                tick: 0,
                liquidity,
                ticks: ticks.into(),
                pos,
                lo_cover: -TICKS_PER_POOL * 5,
                hi_cover: TICKS_PER_POOL * 5,
            },
        ));
    }
    // Pools on pairs the trade never touches, as a quote's graph carries:
    // `ROUTE_PROFILE_IDLE_POOLS` of them (none by default).
    let idle: usize = std::env::var("ROUTE_PROFILE_IDLE_POOLS")
        .ok()
        .map_or(0, |count| count.parse().expect("ROUTE_PROFILE_IDLE_POOLS"));
    let template = v3[0].clone();
    for i in 0..idle {
        let (mut pool, state) = template.clone();
        let mut bytes = [0u8; 20];
        bytes[16..]
            .copy_from_slice(&(u32::try_from(i).expect("idle pool count") + 1).to_be_bytes());
        bytes[0] = 0xee;
        pool.address = Address::from(bytes);
        bytes[0] = 0xef;
        pool.token0 = Address::from(bytes);
        bytes[0] = 0xf0;
        pool.token1 = Address::from(bytes);
        v3.push((pool, state));
    }
    (
        Snapshot {
            block: 1,
            settler: Some(addr(3)),
            v3,
            v2: vec![],
            ekubo: vec![],
        },
        token0,
        token1,
        U256::from(10).pow(U256::from(21)),
    )
}

fn solve(
    snapshot: &Snapshot,
    token0: Address,
    token1: Address,
    amount: U256,
) -> anyhow::Result<Plan> {
    let plan = PreparedRoutes::for_profile(snapshot, &ROBINHOOD_PROFILE, token0, token1)?
        .solve(amount, 256, 0)?;
    quantized_plan(snapshot, &plan, amount)
}

fn main() -> anyhow::Result<()> {
    let (snapshot, token0, token1, amount) = fixture();
    let universe = RouteUniverse::profile_only(&ROBINHOOD_PROFILE, token0, token1)?;
    let expected = solve(&snapshot, token0, token1, amount)?;

    let started = Instant::now();
    for _ in 0..CLONE_RUNS {
        black_box(
            snapshot
                .v3
                .iter()
                .map(|(_, state)| state.clone())
                .collect::<Vec<_>>(),
        );
    }
    let clone_ns = started.elapsed().as_nanos() / u128::from(CLONE_RUNS);

    let started = Instant::now();
    for _ in 0..ROUTE_RUNS {
        let plan = solve(&snapshot, token0, token1, amount)?;
        assert_eq!(plan.amount_out, expected.amount_out);
        assert_eq!(plan.legs.len(), expected.legs.len());
        black_box(plan);
    }
    let route_ns = started.elapsed().as_nanos() / u128::from(ROUTE_RUNS);

    let certificate = certify_in_universe(&universe, &snapshot, token0, token1, amount, &expected)?;
    let started = Instant::now();
    for _ in 0..CERT_RUNS {
        black_box(certify_in_universe(
            &universe, &snapshot, token0, token1, amount, &expected,
        )?);
    }
    let cert_ns = started.elapsed().as_nanos() / u128::from(CERT_RUNS);

    // The same work on a snapshot no walk has seen: a per-pair pull's cost.
    // The warm figures above are a resident block's, where every quote at the
    // block shares the snapshot.
    let (mut route_cold_ns, mut cert_cold_ns) = (0u128, 0u128);
    for _ in 0..COLD_RUNS {
        let (fresh, ..) = fixture();
        let started = Instant::now();
        let plan = solve(&fresh, token0, token1, amount)?;
        route_cold_ns += started.elapsed().as_nanos();
        assert_eq!(plan.amount_out, expected.amount_out);
        let started = Instant::now();
        black_box(certify_in_universe(
            &universe, &fresh, token0, token1, amount, &plan,
        )?);
        cert_cold_ns += started.elapsed().as_nanos();
    }
    let route_cold_ns = route_cold_ns / u128::from(COLD_RUNS);
    let cert_cold_ns = cert_cold_ns / u128::from(COLD_RUNS);

    println!(
        "pools={POOLS} ticks_per_pool={TICKS_PER_POOL} clone_ns={clone_ns} route_ns={route_ns} legs={} amount_out={}",
        expected.legs.len(),
        expected.amount_out
    );
    println!(
        "cert_ns={cert_ns} cert_share={:.1}% gap_bps={} unrouted_pools={}/{} consistent={}",
        100.0 * cert_ns as f64 / route_ns as f64,
        sextant::certificate::format_bps_e4(certificate.gap_bps_e4),
        certificate.unrouted_pools,
        certificate.scanned_pools,
        certificate.consistent
    );
    println!("route_cold_ns={route_cold_ns} cert_cold_ns={cert_cold_ns}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The benchmark's own result, pinned. `gates.sh` checks the same amount
    /// from the outside; this test keeps it inside `cargo test --examples`,
    /// so a clone without the maintainers' tools still catches a change.
    #[test]
    fn the_benchmark_fixture_routes_to_the_pinned_output() {
        let (snapshot, token0, token1, amount) = fixture();
        let universe = RouteUniverse::profile_only(&ROBINHOOD_PROFILE, token0, token1).unwrap();
        let plan = solve(&snapshot, token0, token1, amount).unwrap();
        assert_eq!(plan.amount_out, U256::from(994_246_489_566_748_118_282u128));
        let certificate =
            certify_in_universe(&universe, &snapshot, token0, token1, amount, &plan).unwrap();
        assert!(certificate.consistent);
    }
}
