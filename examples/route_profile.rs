//! Deterministic CPU profile for the routing hot path.
//!
//! Two fixtures. The first, eight dense single-hop UniV3 pools, is the one the
//! rewrite was measured on; its keys (`route_ns`, `cert_ns`, …) and its
//! `amount_out` stay as they were, so two revisions compare like with like. The
//! second (`mh_*` keys) is shaped like a live multi-hop pair: see
//! [`multihop`]. Both print their outputs, which later speed work must leave
//! bit-identical.
//!
//! Run with: cargo run --release --example route_profile

use alloy_primitives::{Address, I256, U256};
use sextant::certificate::certify_in_universe;
use sextant::chain::ROBINHOOD_PROFILE;
use sextant::pools::{
    TickInfo, V2Pool, V2Protocol, V2State, V3ExecutionMeta, V3Pool, V3Protocol, V3State,
};
use sextant::route::{Plan, PreparedRoutes, quantized_plan};
use sextant::state::Snapshot;
use sextant::universe::RouteUniverse;
use std::collections::BTreeMap;
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
    // `ROUTE_PROFILE_MULTIHOP=0` skips the second fixture, which takes half a
    // minute in the dev profile; the example's own tests pin its outputs.
    if std::env::var("ROUTE_PROFILE_MULTIHOP").as_deref() != Ok("0") {
        println!("{}", multihop::profile()?);
    }
    Ok(())
}

/// A production-shaped quote (R2-10). The endpoints and the profile's three
/// connectors give ten skeletons — direct, three two-hop and six three-hop — so
/// every connector pair's pools are walked in both directions. Each edge
/// carries the four common fee/spacing pairs, sometimes one or two more pools
/// and a V2 pair. Every concentrated pool's ticks come from positions: sparse,
/// with `liquidity_net` that changes the active liquidity, so a walk ends
/// between ticks or at a bitmap-word edge as often as on an initialized tick,
/// as on a live pair. It times what a quote runs (`quotes.rs`): the served
/// solve at 256 chunks / 50 bps, the fair probe at 1/100 of the amount, the
/// escalated re-solve at 1024 / 10, and the certificate. Seeded, so the pools
/// are the same on every run and at every revision.
mod multihop {
    use super::*;

    const RUNS: u32 = 3;
    const COLD_RUNS: u32 = 2;
    /// `SOLVER_ALLOC_CHUNKS` and `SOLVER_MIN_SHARE_BPS` defaults.
    pub(super) const SERVED: (u32, u32) = (256, 50);
    /// `ESCALATED_CHUNKS` and `ESCALATED_MIN_SHARE`.
    pub(super) const ESCALATED: (u32, u32) = (1024, 10);
    /// Each edge's depth scale, in 10^21: direct, input–connector ×3,
    /// connector–output ×3, connector pairs ×3. Against `AMOUNT` this gives a
    /// live pair's shape: a 7 bp quote over 14 legs, three of them three-hop,
    /// served in about 70 ms.
    const DEPTH: [u64; 10] = [8, 512, 64, 32, 512, 256, 64, 768, 256, 128];
    /// The traded amount, in 10^18.
    const AMOUNT: u64 = 100;
    /// (fee in ppm, tick spacing): the pairs live V3 venues use.
    const TIERS: [(u32, i32); 4] = [(100, 1), (500, 10), (3_000, 60), (10_000, 200)];

    /// xorshift64: fixed seed, no dependency.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }

        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }

        /// Uniform in `lo..hi`.
        fn range(&mut self, lo: i32, hi: i32) -> i32 {
            let span = u64::try_from(hi - lo).expect("non-empty range");
            lo + i32::try_from(self.below(span)).expect("span fits i32")
        }
    }

    pub(super) fn tokens() -> (Address, Address, [Address; 3]) {
        let c = ROBINHOOD_PROFILE.connectors;
        (
            Address::repeat_byte(0xa1),
            Address::repeat_byte(0xb2),
            [c[0], c[1], c[2]],
        )
    }

    fn ordered(a: Address, b: Address) -> (Address, Address) {
        if a < b { (a, b) } else { (b, a) }
    }

    fn pool_address(index: u16) -> Address {
        let mut bytes = [0u8; 20];
        bytes[0] = 0x5e;
        bytes[18..].copy_from_slice(&index.to_be_bytes());
        Address::from(bytes)
    }

    fn e21(n: u64) -> U256 {
        U256::from(10).pow(U256::from(21)) * U256::from(n)
    }

    /// A concentrated pool at price 1 whose ticks are the boundaries of
    /// 16-31 random positions plus one spanning the whole read window, so the
    /// active liquidity is never zero inside it.
    fn concentrated(
        rng: &mut Rng,
        address: Address,
        (token0, token1): (Address, Address),
        (fee_ppm, spacing): (u32, i32),
        scale: U256,
    ) -> (V3Pool, V3State) {
        // Four bitmap words each side, capped: the window a Lens read covers.
        let reach = (spacing * 1_024).min(80_000) / spacing * spacing;
        let mut nets: BTreeMap<i32, I256> = BTreeMap::new();
        let mut active = U256::ZERO;
        let mut add = |lo: i32, hi: i32, liquidity: U256| {
            let net = I256::try_from(liquidity).expect("liquidity fits I256");
            *nets.entry(lo).or_insert(I256::ZERO) += net;
            *nets.entry(hi).or_insert(I256::ZERO) -= net;
            if lo <= 0 && 0 < hi {
                active += liquidity;
            }
        };
        add(-reach, reach, scale / U256::from(4));
        for _ in 0..16 + rng.below(16) {
            let center = rng.range(-reach / 2, reach / 2);
            let half = rng.range(spacing * 4, reach / 2 + spacing * 4);
            let lo = (center - half).div_euclid(spacing).max(-reach / spacing) * spacing;
            let hi = (-((-(center + half)).div_euclid(spacing))).min(reach / spacing) * spacing;
            let hi = if hi > lo { hi } else { lo + spacing };
            add(
                lo,
                hi,
                scale * U256::from(1 + rng.below(8)) / U256::from(16),
            );
        }
        let ticks: Vec<TickInfo> = nets
            .into_iter()
            .map(|(tick, liquidity_net)| TickInfo {
                tick,
                liquidity_net,
            })
            .collect();
        let pos = ticks.partition_point(|tick| tick.tick <= 0);
        (
            V3Pool {
                protocol: V3Protocol::UNIV3,
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
                v4: None,
                algebra: None,
            },
            V3State {
                sqrt_price: U256::ONE << 96usize,
                tick: 0,
                liquidity: active,
                ticks: ticks.into(),
                pos,
                lo_cover: -reach,
                hi_cover: reach,
            },
        )
    }

    pub(super) fn fixture() -> (Snapshot, Address, Address, U256) {
        let (tin, tout, [c0, c1, c2]) = tokens();
        // Shaped like a long-tail pair: the direct edge is thin, the input
        // trades mostly against one connector (a WETH), the connectors trade
        // deeply with each other and with the output (a stable), so the
        // served split takes two- and three-hop paths.
        let edges = [
            (tin, tout, e21(DEPTH[0])),
            (tin, c0, e21(DEPTH[1])),
            (tin, c1, e21(DEPTH[2])),
            (tin, c2, e21(DEPTH[3])),
            (c0, tout, e21(DEPTH[4])),
            (c1, tout, e21(DEPTH[5])),
            (c2, tout, e21(DEPTH[6])),
            (c0, c1, e21(DEPTH[7])),
            (c0, c2, e21(DEPTH[8])),
            (c1, c2, e21(DEPTH[9])),
        ];
        let mut rng = Rng(0x5eed_0f5e_7a47_0001);
        let mut next = 0u16;
        let mut address = || {
            next += 1;
            pool_address(next)
        };
        let (mut v3, mut v2) = (Vec::new(), Vec::new());
        for (a, b, scale) in edges {
            let pair = ordered(a, b);
            let mut tiers = TIERS.to_vec();
            for _ in 0..rng.below(3) {
                tiers.push(TIERS[usize::try_from(rng.below(4)).expect("tier index")]);
            }
            // Depth is uneven, as on a live pair: a few pools hold most of
            // an edge's liquidity.
            for tier in tiers {
                let depth = scale >> usize::try_from(rng.below(5)).expect("shift");
                v3.push(concentrated(&mut rng, address(), pair, tier, depth));
            }
            if rng.below(2) == 0 {
                let reserve =
                    (scale >> usize::try_from(rng.below(3)).expect("shift")) * U256::from(40);
                v2.push((
                    V2Pool {
                        protocol: V2Protocol::UNIV2,
                        address: address(),
                        token0: pair.0,
                        token1: pair.1,
                        fee_bps: 30,
                    },
                    V2State {
                        reserve0: reserve,
                        reserve1: reserve,
                    },
                ));
            }
        }
        (
            Snapshot {
                block: 1,
                settler: Some(addr(3)),
                v3,
                v2,
                ekubo: vec![],
            },
            tin,
            tout,
            U256::from(AMOUNT) * U256::from(10).pow(U256::from(18)),
        )
    }

    /// The served solve as `solve_round` runs it: a fresh route set, then the
    /// quantized split.
    pub(super) fn solve(
        snapshot: &Snapshot,
        universe: &RouteUniverse,
        amount: U256,
        (chunks, min_share_bps): (u32, u32),
    ) -> anyhow::Result<Plan> {
        PreparedRoutes::for_universe(snapshot, universe)?
            .try_solve_quantized(amount, chunks, min_share_bps)?
            .ok_or_else(|| anyhow::anyhow!("the multi-hop fixture has no route"))
    }

    fn timed<T>(runs: u32, mut work: impl FnMut() -> anyhow::Result<T>) -> anyhow::Result<u128> {
        let started = Instant::now();
        for _ in 0..runs {
            black_box(work()?);
        }
        Ok(started.elapsed().as_nanos() / u128::from(runs))
    }

    pub(super) fn profile() -> anyhow::Result<String> {
        let (snapshot, tin, tout, amount) = fixture();
        let universe = RouteUniverse::profile_only(&ROBINHOOD_PROFILE, tin, tout)?;
        let fair_in = amount / U256::from(100);
        let served = solve(&snapshot, &universe, amount, SERVED)?;
        let fair = solve(&snapshot, &universe, fair_in, SERVED)?;
        let escalated = solve(&snapshot, &universe, amount, ESCALATED)?;
        let certificate = certify_in_universe(&universe, &snapshot, tin, tout, amount, &served)?;

        let route_ns = timed(RUNS, || {
            let plan = solve(&snapshot, &universe, amount, SERVED)?;
            assert_eq!(plan, served);
            Ok(plan)
        })?;
        let fair_ns = timed(RUNS, || solve(&snapshot, &universe, fair_in, SERVED))?;
        let escalated_ns = timed(RUNS, || solve(&snapshot, &universe, amount, ESCALATED))?;
        let cert_ns = timed(RUNS, || {
            certify_in_universe(&universe, &snapshot, tin, tout, amount, &served)
        })?;
        let route_cold_ns = timed(COLD_RUNS, || {
            let (fresh, ..) = fixture();
            let plan = solve(&fresh, &universe, amount, SERVED)?;
            assert_eq!(plan, served);
            Ok(plan)
        })?;

        let mut hops = [0usize; 4];
        for leg in &served.legs {
            hops[leg.path.len().min(3)] += 1;
        }
        Ok(format!(
            "mh_pools={} mh_legs={} mh_legs_by_hops={}/{}/{} mh_route_ns={route_ns} \
             mh_route_cold_ns={route_cold_ns} mh_fair_ns={fair_ns} mh_esc_ns={escalated_ns} \
             mh_cert_ns={cert_ns} mh_amount_out={} mh_fair_out={} mh_esc_out={} \
             mh_gap_bps={} mh_consistent={}",
            snapshot.v3.len() + snapshot.v2.len(),
            served.legs.len(),
            hops[1],
            hops[2],
            hops[3],
            served.amount_out,
            fair.amount_out,
            escalated.amount_out,
            sextant::certificate::format_bps_e4(certificate.gap_bps_e4),
            certificate.consistent
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The benchmark's own result, pinned. CI checks the same amount from the
    /// outside, in its release run; this test keeps it inside
    /// `cargo test --examples`, so a plain test run catches a change too.
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

    /// The multi-hop fixture's three solves, pinned: the served split, the
    /// fair probe and the escalated re-solve. Speed work must leave all three
    /// bit-identical, and the served plan must keep taking three-hop paths, or
    /// the fixture has stopped measuring them.
    #[test]
    fn the_multihop_fixture_routes_to_the_pinned_outputs() {
        let (snapshot, tin, tout, amount) = multihop::fixture();
        let universe = RouteUniverse::profile_only(&ROBINHOOD_PROFILE, tin, tout).unwrap();
        let served = multihop::solve(&snapshot, &universe, amount, multihop::SERVED).unwrap();
        assert_eq!(
            served.amount_out,
            U256::from(99_928_706_092_062_156_233u128)
        );
        assert!(served.legs.iter().any(|leg| leg.path.len() == 3));
        let fair = multihop::solve(
            &snapshot,
            &universe,
            amount / U256::from(100),
            multihop::SERVED,
        )
        .unwrap();
        assert_eq!(fair.amount_out, U256::from(999_800_514_405_492_759u128));
        let escalated = multihop::solve(&snapshot, &universe, amount, multihop::ESCALATED).unwrap();
        assert_eq!(
            escalated.amount_out,
            U256::from(99_928_706_189_294_837_549u128)
        );
    }
}
