use super::graph::{ListedGraph, canonical, routable};
use super::liquidity::{LIQUIDITY_TEST_USD, dollar_amounts, fails_liquidity_test, testable_venues};
use super::reader::fetch_list;
use super::settings::Settings;
use super::widening::Widening;
use super::{PoolCounts, Resident, State};
use crate::catalog::CatalogProtocol;
use crate::chain::{FIXTURE_PROFILE, FIXTURE_USDC, FIXTURE_USDT0, FIXTURE_WETH};
use crate::freshness::STALE;
use crate::pools::{TickInfo, V2Protocol, V2State, V3ExecutionMeta, V3Protocol};
use crate::pools::{V2Pool, V3Pool, V3State};
use crate::rpc::{CanonicalBlock, Rpc};
use crate::snapshot::Snapshot;
use crate::universe::RouteUniverse;
use alloy_primitives::Address;
use alloy_primitives::{B256, U256, address};
use axum::{Router, routing::get};
use serde_json::{Value, json};
use std::collections::{BTreeSet, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

const T1: Address = address!("1000000000000000000000000000000000000001");
const T2: Address = address!("2000000000000000000000000000000000000002");

fn v3(address: Address, a: Address, b: Address, spacing: i32) -> (V3Pool, V3State) {
    let (token0, token1) = canonical(a, b);
    (
        V3Pool {
            protocol: V3Protocol::UNIV3,
            address,
            token0,
            token1,
            fee_ppm: 3_000,
            tick_spacing: spacing,
            verify_pool_spacing: false,
            execution: Some(V3ExecutionMeta {
                fork_id: 200,
                pool_id: 3_000,
            }),
            v4: None,
            algebra: None,
        },
        V3State {
            sqrt_price: U256::from(1u128 << 96),
            tick: 0,
            liquidity: U256::from(1_000_000u64),
            ticks: Vec::<TickInfo>::new().into(),
            pos: 0,
            lo_cover: -887_272,
            hi_cover: 887_272,
        },
    )
}

fn v2(address: Address, a: Address, b: Address) -> (V2Pool, V2State) {
    let (token0, token1) = canonical(a, b);
    (
        V2Pool {
            protocol: V2Protocol::UNIV2,
            address,
            token0,
            token1,
            fee_bps: 35,
        },
        V2State {
            reserve0: U256::from(10u64).pow(U256::from(21u64)),
            reserve1: U256::from(10u64).pow(U256::from(21u64)),
        },
    )
}

fn block(number: u64) -> CanonicalBlock {
    CanonicalBlock {
        number,
        hash: B256::repeat_byte(number as u8),
        timestamp: 1_000 + number,
    }
}

/// A V2 pool holding `reserve_a` of `a` and `reserve_b` of `b`.
fn v2_holding(
    address: Address,
    a: Address,
    b: Address,
    reserve_a: U256,
    reserve_b: U256,
) -> (V2Pool, V2State) {
    let (pool, _) = v2(address, a, b);
    let (reserve0, reserve1) = if pool.token0 == a {
        (reserve_a, reserve_b)
    } else {
        (reserve_b, reserve_a)
    };
    (pool, V2State { reserve0, reserve1 })
}

#[test]
fn the_liquidity_test_passes_pools_from_about_two_thousand_dollars_a_side() {
    let usd = |dollars: u64| U256::from(dollars) * U256::from(1_000_000u64);
    let tokens = U256::from(10u64).pow(U256::from(24u64));
    let weth = U256::from(10u64).pow(U256::from(22u64));
    let snapshot = Snapshot {
        block: 7,
        settler: None,
        v3: vec![],
        v2: vec![
            // 2,500 USDT0 a WETH, $25M a side.
            v2_holding(
                Address::repeat_byte(0xc0),
                FIXTURE_WETH,
                FIXTURE_USDT0,
                weth,
                usd(25_000_000),
            ),
            v2_holding(
                Address::repeat_byte(0xc1),
                T1,
                FIXTURE_USDT0,
                tokens,
                usd(1_000_000),
            ),
            // A $500 round trip loses about 32%, but a $1,000 buy's unit
            // price is only 18% above a $500 one's.
            v2_holding(
                Address::repeat_byte(0xc2),
                T1,
                FIXTURE_USDT0,
                tokens,
                usd(2_200),
            ),
            // About 40% lost and 25% dearer: thin.
            v2_holding(
                Address::repeat_byte(0xc3),
                T1,
                FIXTURE_USDT0,
                tokens,
                usd(1_500),
            ),
            // No side has a dollar price: not tested.
            v2_holding(Address::repeat_byte(0xc4), T1, T2, tokens, U256::from(1u8)),
            // USDC's one pool to a priced token is thin, so USDC has no
            // dollar price, and its thin pool with T2 is not tested.
            v2_holding(
                Address::repeat_byte(0xc6),
                FIXTURE_USDC,
                FIXTURE_USDT0,
                U256::from(1_500_000_000u64),
                usd(1_500),
            ),
            v2_holding(
                Address::repeat_byte(0xc7),
                FIXTURE_USDC,
                T2,
                U256::from(1_000_000_000u64),
                tokens,
            ),
        ],
        ekubo: vec![],
    };
    let connectors = [FIXTURE_WETH, FIXTURE_USDT0, FIXTURE_USDC];
    let dollars = dollar_amounts(&snapshot, &FIXTURE_PROFILE, &connectors, LIQUIDITY_TEST_USD);
    assert_eq!(dollars[0], (FIXTURE_USDT0, usd(500)));
    // $500 of WETH is about 0.2 WETH, through the deep pool.
    let fifth = U256::from(2u64) * U256::from(10u64).pow(U256::from(17u64));
    assert_eq!(dollars[1].0, FIXTURE_WETH);
    assert!(dollars[1].1 < fifth && dollars[1].1 > fifth * U256::from(99) / U256::from(100));
    assert_eq!(dollars.len(), 2, "USDC is priced only through a thin pool");
    let thin: Vec<bool> = testable_venues(&snapshot)
        .map(|venue| fails_liquidity_test(&venue, &dollars))
        .collect();
    assert_eq!(thin, [false, false, false, true, false, true, false]);

    let resident = resident(connectors.to_vec());
    resident.publish_for_test(snapshot.clone(), block(7), Instant::now());
    assert_eq!(resident.health()["thinPools"], 2);
    assert!(resident.health()["liquidityTestAgeMs"].is_u64());
    let mut metrics = String::new();
    resident.prometheus(&mut metrics);
    assert!(metrics.contains("solver_resident_thin_pools 2\n"));
    // Published, every pool is tested; asked again, none is.
    let judged = resident.thin_pools(&snapshot);
    assert_eq!(
        *judged,
        HashSet::from([Address::repeat_byte(0xc3), Address::repeat_byte(0xc6)])
    );
    // Within the retest interval only new pools are tested.
    let mut grown = snapshot.clone();
    grown.v2.push(v2_holding(
        Address::repeat_byte(0xc5),
        T2,
        FIXTURE_USDT0,
        tokens,
        usd(100),
    ));
    assert_eq!(
        *resident.thin_pools(&grown),
        HashSet::from([
            Address::repeat_byte(0xc3),
            Address::repeat_byte(0xc5),
            Address::repeat_byte(0xc6)
        ])
    );
    let refill = |snapshot: &Snapshot, byte: u8, dollars: u64| {
        let mut next = snapshot.clone();
        next.v2
            .retain(|(pool, _)| pool.address != Address::repeat_byte(byte));
        next.v2.push(v2_holding(
            Address::repeat_byte(byte),
            T1,
            FIXTURE_USDT0,
            tokens,
            usd(dollars),
        ));
        next
    };
    // A thin pool funded since is tested again at the next block, and
    // passes.
    let funded = refill(&grown, 0xc3, 1_000_000);
    assert_eq!(
        *resident.thin_pools(&funded),
        HashSet::from([Address::repeat_byte(0xc5), Address::repeat_byte(0xc6)])
    );
    // A pass stands until the retest, however the pool has been drained
    // since; the retest catches it.
    let drained = refill(&funded, 0xc1, 100);
    assert!(
        !resident
            .thin_pools(&drained)
            .contains(&Address::repeat_byte(0xc1))
    );
    resident.liquidity.lock().unwrap().tested_at = None;
    assert!(
        resident
            .thin_pools(&drained)
            .contains(&Address::repeat_byte(0xc1))
    );
}

#[test]
fn a_graph_that_needs_thin_pools_takes_back_only_those_on_bare_edges() {
    // L trades against WETH; R, a resident connector, against WETH through
    // a pool that passed and one that failed, and against USDT0 only
    // through one that failed. Without the failures nothing reaches USDT0,
    // so R's USDT0 pool comes back; the failed WETH pool, beside one that
    // passed, stays out.
    let resident_connector = Address::repeat_byte(0x4e);
    let token = Address::repeat_byte(0x4c);
    let at = Address::repeat_byte;
    let snapshot = Snapshot {
        block: 7,
        settler: Some(Address::repeat_byte(0x5e)),
        v3: vec![
            v3(at(0xe1), token, FIXTURE_WETH, 10),
            v3(at(0xe2), FIXTURE_WETH, resident_connector, 10),
            v3(at(0xe3), FIXTURE_WETH, resident_connector, 60),
            v3(at(0xe4), resident_connector, FIXTURE_USDT0, 10),
        ],
        v2: vec![],
        ekubo: vec![],
    };
    let statics = vec![FIXTURE_WETH, FIXTURE_USDT0];
    let mut state = State::new(
        snapshot,
        block(7),
        &[FIXTURE_WETH, FIXTURE_USDT0, resident_connector],
        Instant::now(),
    );
    state.thin = Arc::new(HashSet::from([at(0xe3), at(0xe4)]));
    let widening = Widening {
        state: Arc::new(state),
        profile: &FIXTURE_PROFILE,
        endpoints: (token, FIXTURE_USDT0),
        statics: statics.clone(),
        bases: statics,
        candidates: vec![vec![token, FIXTURE_WETH, resident_connector, FIXTURE_USDT0]],
        admitted: BTreeSet::new(),
        left_out: 0,
        thin_left_out: 0,
        thin_kept: false,
    };
    let admitted = BTreeSet::from([resident_connector]);
    let graph = widening.graph(&admitted).unwrap();
    let pools: HashSet<Address> = graph
        .snapshot
        .v3
        .iter()
        .map(|(pool, _)| pool.address)
        .collect();
    assert_eq!(pools, HashSet::from([at(0xe1), at(0xe2), at(0xe4)]));
    assert!(graph.thin_kept);
    assert_eq!(graph.thin_left_out, 1);
    // With every pool kept, the full graph is the same skeleton.
    let full = widening.graph_with_thin(&admitted).unwrap();
    assert_eq!(full.snapshot.v3.len(), 4);
    assert_eq!(full.universe.token_paths(), graph.universe.token_paths());
}

fn settings(connectors: Vec<Address>) -> Settings {
    Settings {
        list_url: "http://127.0.0.1:1/pools".to_string(),
        poll: Duration::from_millis(1_000),
        connectors,
        full_read: None,
    }
}

fn resident(statics: Vec<Address>) -> Arc<Resident> {
    resident_with(statics, Vec::new())
}

fn resident_with(statics: Vec<Address>, others: Vec<Address>) -> Arc<Resident> {
    let rpc = Rpc::connect("http://127.0.0.1:1").unwrap();
    Resident::with_connectors(&FIXTURE_PROFILE, rpc, settings(Vec::new()), statics, others).unwrap()
}

/// Sorted by pair and address, as the reader keeps its list.
fn sample() -> Snapshot {
    let mut v3_pools = vec![
        v3(Address::repeat_byte(0xa1), FIXTURE_WETH, FIXTURE_USDT0, 10),
        v3(Address::repeat_byte(0xa2), T1, FIXTURE_WETH, 60),
        v3(Address::repeat_byte(0xc1), FIXTURE_WETH, FIXTURE_USDT0, 200),
        v3(Address::repeat_byte(0xc3), T1, FIXTURE_WETH, 200),
    ];
    v3_pools.sort_by_key(|(pool, _)| (pool.token0, pool.token1, pool.address));
    Snapshot {
        block: 7,
        settler: Some(Address::repeat_byte(0x5e)),
        v3: v3_pools,
        v2: vec![v2(Address::repeat_byte(0xb1), T2, FIXTURE_USDT0)],
        ekubo: Vec::new(),
    }
}

#[test]
fn resident_state_is_off_unless_configured() {
    let parse = |mode, poll, url, connectors| {
        Settings::parse(&FIXTURE_PROFILE, mode, poll, url, connectors, "")
    };
    assert!(parse("", "", "", "").unwrap().is_none());
    assert!(
        parse("off", "", "http://127.0.0.1:9/pools", "")
            .unwrap()
            .is_none()
    );
    assert!(parse("on", "", "", "").is_err(), "on needs a list");
    assert!(parse("yes", "", "", "").is_err());
    assert!(parse("on", "100", "http://127.0.0.1:9/pools", "").is_err());
    assert!(parse("on", "", "ftp://list", "").is_err());
    assert!(parse("on", "", "http://127.0.0.1:9/pools", "0xnope").is_err());
    assert!(
        Settings::parse(
            &crate::chain::ROBINHOOD_PROFILE,
            "on",
            "",
            "http://127.0.0.1:9/pools",
            "",
            ""
        )
        .is_err(),
        "Robinhood's discovery has no venue table"
    );
    let tuned = parse(
        "on",
        "500",
        "http://127.0.0.1:9/pools",
        &format!(" {FIXTURE_USDC:#x} ,, "),
    )
    .unwrap()
    .unwrap();
    assert_eq!(tuned.poll, Duration::from_millis(500));
    assert_eq!(tuned.list_url, "http://127.0.0.1:9/pools");
    assert_eq!(tuned.connectors, vec![FIXTURE_USDC]);
    assert_eq!(tuned.full_read, Some(Duration::from_secs(60)));
}

#[test]
fn whole_reads_are_spaced_by_the_full_read_interval_or_every_block() {
    let full_read = |value| {
        Settings::parse(
            &FIXTURE_PROFILE,
            "on",
            "",
            "http://127.0.0.1:9/pools",
            "",
            value,
        )
        .map(|settings| settings.unwrap().full_read)
    };
    assert_eq!(full_read("").unwrap(), Some(Duration::from_secs(60)));
    assert_eq!(full_read("0").unwrap(), None, "every block read whole");
    assert_eq!(
        full_read(" 250 ").unwrap(),
        Some(Duration::from_millis(250))
    );
    assert!(full_read("3600001").is_err());
    assert!(full_read("soon").is_err());
}

#[test]
fn configured_connectors_join_the_profiles_own() {
    let rpc = Rpc::connect("http://127.0.0.1:1").unwrap();
    let resident = Resident::new(
        &FIXTURE_PROFILE,
        rpc,
        settings(vec![FIXTURE_USDC, FIXTURE_WETH]),
    )
    .unwrap();
    let mut expected = FIXTURE_PROFILE.connectors.to_vec();
    expected.push(FIXTURE_USDC);
    assert_eq!(
        resident.connectors(),
        expected.as_slice(),
        "a static one is not repeated"
    );
    let many = |count: u8| {
        Resident::with_connectors(
            &FIXTURE_PROFILE,
            Rpc::connect("http://127.0.0.1:1").unwrap(),
            settings(Vec::new()),
            (1..=count).map(Address::repeat_byte).collect(),
            vec![FIXTURE_USDC],
        )
    };
    assert!(many(7).is_ok(), "seven static connectors span 36 pairs");
    assert!(many(8).is_err(), "eight span 45");
}

#[test]
fn a_pair_gets_its_route_graph_in_the_lists_order() {
    let state = State::new(sample(), block(7), &[], Instant::now());
    let universe =
        RouteUniverse::resident(&FIXTURE_PROFILE, &[FIXTURE_WETH], &[], T1, FIXTURE_USDT0).unwrap();
    let subset = state.subset(&universe);
    let addresses: Vec<Address> = subset.v3.iter().map(|(pool, _)| pool.address).collect();
    let expected: Vec<Address> = sample().v3.iter().map(|(pool, _)| pool.address).collect();
    assert_eq!(
        addresses, expected,
        "every V3 pool is on the graph, in list order"
    );
    assert!(subset.v2.is_empty(), "T2/USDT0 is off this graph");
    assert_eq!(subset.settler, Some(Address::repeat_byte(0x5e)));
    assert!(routable(&subset, &universe));
}

#[tokio::test]
async fn a_quote_reads_the_resident_state_only_when_it_covers_and_routes_the_pair() {
    let resident = resident(vec![FIXTURE_WETH, FIXTURE_USDT0]);
    assert!(
        resident.stamped_for(T1, FIXTURE_USDT0, 0).await.is_none(),
        "nothing published"
    );
    resident.publish_for_test(sample(), block(7), Instant::now());

    let stamped = resident
        .stamped_for(FIXTURE_USDT0, T1, 0)
        .await
        .expect("covered");
    assert_eq!(stamped.snap.block, 7);
    assert_eq!(stamped.rpc_calls(), 0);
    assert!(stamped.universe.is_resident());
    assert_eq!(stamped.universe.endpoints(), canonical(T1, FIXTURE_USDT0));
    assert_eq!(stamped.block_id().as_block_hash(), Some(block(7).hash));

    // T2 trades only against USDT0; T1 only against WETH. Through WETH
    // and USDT0 they connect.
    assert!(resident.stamped_for(T1, T2, 0).await.is_some());
    // A token no listed pool trades goes to the per-pair path.
    let unknown = Address::repeat_byte(0x77);
    assert!(
        resident
            .stamped_for(unknown, FIXTURE_WETH, 0)
            .await
            .is_none()
    );
}

#[tokio::test]
async fn a_covered_pair_without_a_complete_skeleton_goes_to_the_per_pair_path() {
    // No connectors: T1 and T2 have no direct pool.
    let resident = resident(Vec::new());
    resident.publish_for_test(sample(), block(7), Instant::now());
    assert!(resident.stamped_for(T1, T2, 0).await.is_none());
    assert!(resident.stamped_for(T1, FIXTURE_WETH, 0).await.is_some());
}

#[tokio::test]
async fn a_resident_connector_waits_beside_the_static_graph_until_admitted() {
    // USDC trades against WETH and USDT0.
    let mut snapshot = sample();
    for (pool, token) in [(0xa4, FIXTURE_WETH), (0xa5, FIXTURE_USDT0)] {
        snapshot
            .v3
            .push(v3(Address::repeat_byte(pool), token, FIXTURE_USDC, 10));
    }
    let rpc = Rpc::connect("http://127.0.0.1:1").unwrap();
    let resident = Resident::new(&FIXTURE_PROFILE, rpc, settings(vec![FIXTURE_USDC])).unwrap();
    resident.publish_for_test(snapshot, block(7), Instant::now());
    let stamped = resident
        .stamped_for(FIXTURE_WETH, FIXTURE_USDT0, 0)
        .await
        .expect("served from here");
    assert_eq!(
        canonical(FIXTURE_WETH, FIXTURE_USDT0),
        (FIXTURE_WETH, FIXTURE_USDT0)
    );
    let pools = |snapshot: &Snapshot| -> HashSet<Address> {
        snapshot.v3.iter().map(|(pool, _)| pool.address).collect()
    };
    // The quote starts from the static graph; USDC is a candidate.
    let through_usdc = vec![FIXTURE_WETH, FIXTURE_USDC, FIXTURE_USDT0];
    assert!(!stamped.universe.token_paths().contains(&through_usdc));
    assert!(stamped.universe.listed_connectors().is_empty());
    assert!(!pools(&stamped.snap).contains(&Address::repeat_byte(0xa4)));
    let widening = stamped.widening.as_deref().expect("a resident stamp");
    assert_eq!(widening.connectors(), vec![FIXTURE_USDC]);
    assert!(widening.admitted().is_empty());
    // Admitted, it is routed.
    let wide = widening
        .graph(&BTreeSet::from([FIXTURE_USDC]))
        .expect("the wider graph");
    assert!(wide.universe.token_paths().contains(&through_usdc));
    assert_eq!(wide.universe.listed_connectors(), vec![FIXTURE_USDC]);
    for pool in [0xa4, 0xa5] {
        assert!(pools(&wide.snapshot).contains(&Address::repeat_byte(pool)));
    }
    assert_eq!(wide.left_out, 0);
    // Its fingerprint is not the narrow graph's: a plan solved on one is
    // never certified against the other.
    assert_ne!(wide.universe.fingerprint(), stamped.universe.fingerprint());
    // The per-pair path, with only the profile's connectors, takes USDC
    // where the list has its pools.
    assert_eq!(
        resident.listed_paths(FIXTURE_PROFILE.connectors, FIXTURE_WETH, FIXTURE_USDT0),
        vec![through_usdc]
    );
}

#[tokio::test]
async fn a_skeleton_through_two_candidates_is_routed_once_both_are_admitted() {
    // R1 trades against WETH and R2; R2 against R1 and USDT0.
    let (r1, r2) = (Address::repeat_byte(0x41), Address::repeat_byte(0x42));
    let mut snapshot = sample();
    for (pool, a, b) in [
        (0xa6, FIXTURE_WETH, r1),
        (0xa7, r1, r2),
        (0xa8, r2, FIXTURE_USDT0),
    ] {
        snapshot.v3.push(v3(Address::repeat_byte(pool), a, b, 10));
    }
    let resident = resident_with(vec![FIXTURE_WETH, FIXTURE_USDT0], vec![r1, r2]);
    resident.publish_for_test(snapshot, block(7), Instant::now());
    let stamped = resident
        .stamped_for(FIXTURE_WETH, FIXTURE_USDT0, 0)
        .await
        .expect("served from here");
    let widening = stamped.widening.as_deref().expect("a resident stamp");
    assert_eq!(widening.connectors(), vec![r1, r2]);
    let through = vec![FIXTURE_WETH, r1, r2, FIXTURE_USDT0];
    let alone = widening.graph(&BTreeSet::from([r1])).unwrap();
    assert!(!alone.universe.token_paths().contains(&through));
    let both = widening.graph(&BTreeSet::from([r1, r2])).unwrap();
    assert!(both.universe.token_paths().contains(&through));
}

#[tokio::test]
async fn state_older_than_the_freshness_bound_is_not_served() {
    let resident = resident(vec![FIXTURE_WETH]);
    resident.publish_for_test(
        sample(),
        block(7),
        Instant::now() - STALE - Duration::from_millis(1),
    );
    assert!(resident.stamped_for(T1, FIXTURE_WETH, 0).await.is_none());
    // A head check that finds the block still the head makes it fresh.
    let state = resident.current.load_full().unwrap();
    state.confirm(Instant::now() - STALE * 3);
    assert!(
        resident.stamped_for(T1, FIXTURE_WETH, 0).await.is_none(),
        "never moves back"
    );
    state.confirm(Instant::now());
    assert!(resident.stamped_for(T1, FIXTURE_WETH, 0).await.is_some());
}

#[tokio::test]
async fn chain_time_runs_from_the_first_read_of_the_block() {
    let resident = resident(vec![FIXTURE_WETH]);
    // Read 30 s ago and confirmed at every head check since: the chain is
    // 30 s past the block's timestamp, however recent the confirmation.
    resident.publish_for_test(sample(), block(7), Instant::now() - Duration::from_secs(30));
    resident
        .current
        .load_full()
        .unwrap()
        .confirm(Instant::now());
    let stamped = resident.stamped_for(T1, FIXTURE_WETH, 0).await.unwrap();
    assert!(stamped.is_fresh());
    assert_eq!(stamped.chain_now(), 1_007 + 30);
}

#[tokio::test(start_paused = true)]
async fn a_later_block_is_waited_for_then_left_to_the_per_pair_path() {
    let resident = resident(vec![FIXTURE_WETH]);
    resident.publish_for_test(sample(), block(7), Instant::now());
    let waiter = {
        let resident = resident.clone();
        tokio::spawn(async move {
            resident
                .stamped_for(T1, FIXTURE_WETH, 8)
                .await
                .map(|s| s.snap.block)
        })
    };
    tokio::task::yield_now().await;
    let mut next = sample();
    next.block = 8;
    resident.publish_for_test(next, block(8), Instant::now());
    assert_eq!(waiter.await.unwrap(), Some(8));
    let late = resident.stamped_for(T1, FIXTURE_WETH, 9);
    assert!(late.await.is_none(), "no block 9 within the wait");
}

#[test]
fn counts_split_the_published_pools_by_family() {
    assert_eq!(PoolCounts::of(&sample()), PoolCounts { v3: 4, v2: 1 });
}

#[test]
fn listed_skeletons_run_through_resident_connectors_only() {
    let (r, token, other) = (
        Address::repeat_byte(0x4e),
        Address::repeat_byte(0xaa),
        Address::repeat_byte(0xbb),
    );
    let statics = [FIXTURE_WETH, FIXTURE_USDT0];
    let graph = ListedGraph::new(
        [
            (FIXTURE_WETH, r),
            (FIXTURE_USDT0, r),
            (token, r),
            (FIXTURE_WETH, FIXTURE_USDT0),
            (other, FIXTURE_WETH),
        ],
        &[FIXTURE_WETH, FIXTURE_USDT0, r],
    );
    assert_eq!(
        graph.paths(&statics, FIXTURE_WETH, FIXTURE_USDT0),
        vec![vec![FIXTURE_WETH, r, FIXTURE_USDT0]]
    );
    let mut through_r = graph.paths(&statics, token, other);
    through_r.sort();
    let mut expected = vec![
        vec![token, r, FIXTURE_USDT0, other],
        vec![token, r, FIXTURE_WETH, other],
    ];
    expected.sort();
    assert_eq!(
        through_r, expected,
        "the static connector's pool with the far endpoint is left to the snapshot"
    );
    assert!(
        graph.paths(&statics, r, FIXTURE_USDT0).is_empty(),
        "an endpoint is not its own connector"
    );
    for (a, b) in [
        (token, FIXTURE_USDT0),
        (token, other),
        (FIXTURE_WETH, FIXTURE_USDT0),
    ] {
        let forward = graph.paths(&statics, a, b);
        let backward: Vec<Vec<Address>> = graph
            .paths(&statics, b, a)
            .into_iter()
            .map(|mut path| {
                path.reverse();
                path
            })
            .collect();
        assert_eq!(
            forward, backward,
            "a pair and its reverse get the same skeletons"
        );
    }
}

async fn serve_list(body: Value) -> (String, tokio::task::JoinHandle<()>) {
    let app = Router::new().route(
        "/pools",
        get(move || {
            let body = body.clone();
            async move { axum::Json(body) }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{address}/pools"), server)
}

fn row(address: Address, protocol: &str, fee: u64, token0: Address, token1: Address) -> Value {
    json!({
        "protocol": protocol,
        "address": format!("{address:#x}"),
        "token0": format!("{token0:#x}"),
        "token1": format!("{token1:#x}"),
        "feePpm": fee,
    })
}

#[tokio::test]
async fn the_list_is_read_whole() {
    let (a, b) = (Address::repeat_byte(0x0a), Address::repeat_byte(0x0b));
    let (url, server) = serve_list(json!([
        row(Address::repeat_byte(0x31), "univ3", 500, a, b),
        row(Address::repeat_byte(0x32), "pancakev2", 2_500, a, b),
    ]))
    .await;
    let rows = fetch_list(reqwest::Client::new(), url).await.unwrap();
    server.abort();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].protocol, CatalogProtocol::UNIV3);
    assert_eq!(rows[0].fee_ppm, 500);
    assert_eq!(rows[1].protocol, CatalogProtocol::PANCAKEV2);
    assert_eq!((rows[1].token0, rows[1].token1), (a, b));
}

#[tokio::test]
async fn a_bad_list_is_refused_whole() {
    let (a, b) = (Address::repeat_byte(0x0a), Address::repeat_byte(0x0b));
    let good = row(Address::repeat_byte(0x31), "univ3", 500, a, b);
    for (body, expected) in [
        (json!({"pools": []}), "not a JSON array"),
        (json!([]), "is empty"),
        (json!([good.clone(), good.clone()]), "twice"),
        (
            json!([
                good.clone(),
                row(Address::repeat_byte(0x33), "univ4", 500, a, b)
            ]),
            "not an address-pool protocol",
        ),
        (
            json!([
                good.clone(),
                row(Address::repeat_byte(0x34), "univ3", 1_000_000, a, b)
            ]),
            "feePpm",
        ),
        (json!([{"protocol": "univ3", "address": "nope"}]), "row 0"),
    ] {
        let (url, server) = serve_list(body).await;
        let error = fetch_list(reqwest::Client::new(), url).await.unwrap_err();
        server.abort();
        assert!(format!("{error:#}").contains(expected), "{error:#}");
    }
}
