/// Pools per leg needed to make one connector's `left x right` work exceed
/// the cap. Derived, so moving `BASELINE_PATH_CANDIDATE_CAP` cannot leave
/// these fixtures asserting against an old number.
fn legs_over_cap() -> u32 {
    let mut n = 1u32;
    while (n as usize) * (n as usize) <= BASELINE_PATH_CANDIDATE_CAP {
        n += 1;
    }
    n
}

use super::algebra::{
    SHERIFF_PLUGIN_CONFIG, SHERIFF_SLIDING_FEE_PLUGIN, SHERIFF_SLIDING_FEE_PLUGIN_CODEHASH,
    attach_algebra_fees, before_swap_call, decode_before_swap_fee, validate_sheriff_binding,
};
use super::cache::{
    TOPO_CACHE, Topology, TopologyStatus, cache_topology, topology_cached, topology_key,
};
use super::connectors::{
    admit_dynamic_work, admit_indexed_topology_work, augmented_availability_fallback,
    indexed_topology_pool_counts, retain_allowlisted,
};
use super::execution::settler_registry_call;
use super::factories::{FactoryDiscoveryPlan, finish_factory_discovery, plan_factory_discovery};
use super::indexed_validation::{
    finish_indexed_validation, indexed_probe_spacing, indexed_route_pairs,
    indexed_topology_query_pairs, plan_indexed_validation,
};
use super::lens_parse::{ParsedLens, SheriffBinding, parse_indexed_lens, parse_lens};
use super::pool_ids::{
    algebra_pool_addr, clone_pool_addr, extsload, v4_hook_flags, v4_meta, v4_pool_id, v4_swap_fee,
};
use super::robinhood::{
    ensure_complete_probes, finish_robinhood_discovery, plan_robinhood_probes,
    requires_verified_settler, settler_supports_protocol_for,
};
use super::settings::{
    BITMAP_WORDS, CONNECTOR_SCREENING, DYNAMIC_CONNECTORS, DynamicConnectorMode, RANKED_CONNECTORS,
    admission_setting_admitted, bitmap_words, connector_mode_admitted, parse_connector_screening,
    ranked_setting_admitted, read_connector_min_bps_e4, screening_has_a_reader,
    screening_setting_admitted,
};
use super::v4_keys::{
    V4_KEYS_PER_PAIR_CAP, V4_REORG_OVERLAP, V4_UNKNOWN_KEY_FEE_PPM, V4KeyDiscovery, V4ScanContext,
    V4ScanSource, ensure_v4_key_capacity, v4_currency_pair_for, v4_event_keys, v4_key_gate,
    v4_parse_key, v4_refresh_from, v4_scan_covers_primary, v4_tokens_from_currencies_for,
};
use super::{
    Probe, UpstreamIntegrityError, beforeSwapCall, globalStateCall, snapshot_at_for,
    snapshot_at_observed_for, sorted_pair,
};
use crate::abi::{
    IArbSys, IPoolState, ISettlerRegistry, IUniV2Factory, IUniV3Factory, IUp33ClFactory,
    IUp33V2Factory,
};
use crate::catalog::CandidateSource;
use crate::chain::{
    ARBSYS, DiscoveryProfile, FORK_GIGADEX, FORK_PANCAKE, FORK_ROBINSWAP, FORK_SHERIFF, FORK_SUSHI,
    FORK_SWAPHOOD, FORK_UNIV3, FORK_UP33, GIGADEX_V3_DEPLOYER, GIGADEX_V3_INIT, NATIVE,
    PANCAKE_V3_DEPLOYER, PANCAKE_V3_INIT, ROBINHOOD_PROFILE, ROBINSWAP_V3_DEPLOYER,
    ROBINSWAP_V3_INIT, SHERIFF_DEPLOYER, SHERIFF_INIT, SUSHI_V3_DEPLOYER, SUSHI_V3_INIT,
    SWAPHOOD_V3_DEPLOYER, SWAPHOOD_V3_INIT, SettlerRuntimePolicy, UNIV2_FACTORY, UNIV3_FACTORY,
    UP33_CL_FACTORY, UP33_V2_FACTORY, V4_DYNAMIC_FEE_FLAG, V4_MAX_FEE_PPM, V4_POOL_MANAGER, WETH,
};
use crate::indexer::IndexerClient;
use crate::pools::{TickInfo, V2Pool, V2Protocol, V3ExecutionMeta, V3Pool, V3Protocol, V3State};
use crate::route::BASELINE_PATH_CANDIDATE_CAP;
use crate::rpc::{Rpc, RpcUnavailable};
use crate::topology::{
    AddressPoolTopology, CatalogFences, ConnectorSelection, PoolTopology as IndexedPoolTopology,
    Protocol as IndexedProtocol, TokenPair, Topology as IndexedTopology, V4PoolTopology,
};
use crate::universe::{FallbackKind, RouteUniverse, RouteUniverseSource};
use crate::v3math::{MAX_TICK, MIN_TICK};
use alloy::eips::BlockId;
use alloy_primitives::aliases::U24;
use alloy_primitives::{Address, B256, I256, U256, address};
use alloy_sol_types::SolCall;
use axum::{Json, Router, extract::State, routing::post};
use serde_json::{Value, json};
use sextant_amm::snapshot::Snapshot;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;
use tokio::sync::OnceCell;

fn signed_word(v: i64) -> U256 {
    I256::try_from(v).expect("fits I256").into_raw()
}

fn abi_address_word(address: Address) -> Vec<u8> {
    let mut word = vec![0u8; 12];
    word.extend_from_slice(address.as_slice());
    word
}

fn abi_signed_word(value: i64) -> Vec<u8> {
    signed_word(value).to_be_bytes::<32>().to_vec()
}

fn indexed_address_pool(
    protocol: IndexedProtocol,
    address: Address,
    fee_ppm: u32,
    tick_spacing: Option<i32>,
    created_block: Option<u64>,
) -> IndexedPoolTopology {
    IndexedPoolTopology::Address(AddressPoolTopology {
        protocol,
        address,
        token0: Address::repeat_byte(0x11),
        token1: Address::repeat_byte(0x22),
        fee_ppm,
        tick_spacing,
        created_block,
    })
}

fn indexed_v4_pool(
    currency0: Address,
    currency1: Address,
    pool_key_fee: u32,
    key_fee_ppm: Option<u32>,
    tick_spacing: i32,
    hooks: Address,
    created_block: Option<u64>,
) -> IndexedPoolTopology {
    IndexedPoolTopology::Univ4(V4PoolTopology {
        pool_manager: crate::chain::BSC_UNIV4_POOL_MANAGER,
        pool_id: v4_pool_id(currency0, currency1, pool_key_fee, tick_spacing, hooks),
        currency0,
        currency1,
        key_fee_ppm,
        tick_spacing,
        hooks,
        created_block,
    })
}

fn bsc_test_topology(pools: Vec<IndexedPoolTopology>) -> IndexedTopology {
    IndexedTopology {
        pairs: vec![
            TokenPair::new(Address::repeat_byte(0x11), Address::repeat_byte(0x22)).unwrap(),
        ],
        protocols: crate::chain::BSC_INDEXED_DISCOVERY.quote_protocols(),
        fences: crate::topology::CatalogFences {
            v23: crate::topology::V23Fence {
                seq: 1,
                generation: 1,
            },
            v4: Some(crate::topology::V4Fence {
                block: 1,
                generation: B256::repeat_byte(0x77),
            }),
        },
        pools,
    }
}

fn five_protocol_bsc_topology() -> IndexedTopology {
    let univ3 = crate::chain::BSC_PROFILE
        .indexed_v3_execution(crate::catalog::CatalogProtocol::UNIV3)
        .unwrap();
    let pancakev3 = crate::chain::BSC_PROFILE
        .indexed_v3_execution(crate::catalog::CatalogProtocol::PANCAKEV3)
        .unwrap();
    let token0 = Address::repeat_byte(0x11);
    let token1 = Address::repeat_byte(0x22);
    bsc_test_topology(vec![
        indexed_address_pool(
            IndexedProtocol::UNIV2,
            Address::repeat_byte(0x31),
            3_000,
            None,
            Some(10),
        ),
        indexed_address_pool(
            IndexedProtocol::UNIV3,
            clone_pool_addr(univ3.deployer, univ3.init_hash, token0, token1, 500),
            500,
            Some(10),
            Some(11),
        ),
        indexed_address_pool(
            IndexedProtocol::PANCAKEV2,
            Address::repeat_byte(0x33),
            2_500,
            None,
            Some(12),
        ),
        indexed_address_pool(
            IndexedProtocol::PANCAKEV3,
            clone_pool_addr(
                pancakev3.deployer,
                pancakev3.init_hash,
                token0,
                token1,
                2_500,
            ),
            2_500,
            Some(50),
            Some(13),
        ),
        indexed_v4_pool(token0, token1, 500, Some(500), 10, Address::ZERO, Some(14)),
    ])
}

fn five_protocol_bsc_results() -> Vec<Option<Vec<u8>>> {
    let topology = five_protocol_bsc_topology();
    let pools = topology
        .pools
        .iter()
        .filter_map(|pool| match pool {
            IndexedPoolTopology::Address(pool) => Some(pool.address),
            IndexedPoolTopology::Univ4(_) => None,
        })
        .collect::<Vec<_>>();
    vec![
        Some(abi_address_word(pools[0])),
        Some(abi_address_word(pools[1])),
        Some(abi_signed_word(10)),
        Some(abi_address_word(pools[2])),
        Some(abi_address_word(pools[3])),
        Some(abi_signed_word(50)),
    ]
}

#[test]
fn bsc_route_graph_becomes_one_bounded_canonical_batch() {
    let universe = RouteUniverse::profile_only(
        &crate::chain::BSC_PROFILE,
        Address::repeat_byte(0x11),
        Address::repeat_byte(0x99),
    )
    .unwrap();
    let pairs = indexed_route_pairs(&universe).unwrap();
    assert!(!pairs.is_empty() && pairs.len() <= crate::topology::MAX_PAIRS);
    assert!(pairs.iter().all(|pair| pair.token0 < pair.token1));
    let unique: std::collections::HashSet<_> = pairs.iter().copied().collect();
    assert_eq!(unique.len(), pairs.len());
    assert!(pairs.contains(
        &TokenPair::new(Address::repeat_byte(0x11), Address::repeat_byte(0x99)).unwrap()
    ));
}

#[test]
fn bsc_native_v4_alias_is_queried_and_admitted_as_wbnb() {
    let profile = &crate::chain::BSC_PROFILE;
    let token = Address::repeat_byte(0x99);
    let universe = RouteUniverse::profile_only(profile, profile.wrapped_native, token).unwrap();
    let protocols = crate::chain::BSC_INDEXED_DISCOVERY.quote_protocols();
    let pairs = indexed_topology_query_pairs(profile, &universe, &protocols).unwrap();

    let (wrapped0, wrapped1) = sorted_pair(profile.wrapped_native, token);
    assert!(pairs.contains(&TokenPair::new(wrapped0, wrapped1).unwrap()));
    assert!(pairs.contains(&TokenPair::new(Address::ZERO, token).unwrap()));

    let mut topology = bsc_test_topology(vec![indexed_v4_pool(
        Address::ZERO,
        token,
        500,
        Some(500),
        10,
        Address::ZERO,
        Some(10),
    )]);
    let admitted = admit_indexed_topology_work(profile, &universe, &mut topology).unwrap();

    assert_eq!(admitted.pairs(), universe.pairs());
    assert_eq!(topology.pools.len(), 1);
    assert_eq!(
        indexed_topology_pool_counts(profile, &topology)
            .get(&sorted_pair(profile.wrapped_native, token)),
        Some(&1)
    );
}

fn numbered_address(value: u16) -> Address {
    let mut bytes = [0u8; 20];
    bytes[0] = 0x7f;
    bytes[18..].copy_from_slice(&value.to_be_bytes());
    Address::from(bytes)
}

fn candidate_v2_pool(address: Address, a: Address, b: Address) -> V2Pool {
    let (token0, token1) = sorted_pair(a, b);
    V2Pool {
        protocol: V2Protocol::UNIV2,
        address,
        token0,
        token1,
        fee_bps: 30,
    }
}

fn indexed_v2_pool(address: Address, a: Address, b: Address) -> IndexedPoolTopology {
    let (token0, token1) = sorted_pair(a, b);
    IndexedPoolTopology::Address(AddressPoolTopology {
        protocol: IndexedProtocol::UNIV2,
        address,
        token0,
        token1,
        fee_ppm: 3_000,
        tick_spacing: None,
        created_block: Some(1),
    })
}

fn test_catalog_fences() -> CatalogFences {
    CatalogFences {
        v23: crate::topology::V23Fence {
            seq: 10,
            generation: 20,
        },
        v4: None,
    }
}

#[test]
fn connector_screening_setting_is_validated_and_needs_a_ranking() {
    assert!(!parse_connector_screening(None).unwrap());
    assert!(!parse_connector_screening(Some("0")).unwrap());
    assert!(parse_connector_screening(Some("1")).unwrap());
    for rejected in ["true", "yes", "", "2"] {
        assert!(parse_connector_screening(Some(rejected)).is_err());
    }

    // Screening off is compatible with every mode; screening on needs a
    // mode that actually ranks candidates.
    for mode in [
        DynamicConnectorMode::ProfileOnly,
        DynamicConnectorMode::Shadow,
        DynamicConnectorMode::Adjacency,
    ] {
        assert!(screening_setting_admitted(false, mode));
    }
    assert!(!screening_setting_admitted(
        true,
        DynamicConnectorMode::ProfileOnly
    ));
    assert!(screening_setting_admitted(
        true,
        DynamicConnectorMode::Shadow
    ));
    assert!(screening_setting_admitted(
        true,
        DynamicConnectorMode::Adjacency
    ));

    // And it needs the dual pass, which is what reads the state it buys.
    assert!(screening_has_a_reader(false, false));
    assert!(screening_has_a_reader(false, true));
    assert!(screening_has_a_reader(true, true));
    assert!(!screening_has_a_reader(true, false));
}

#[test]
fn ranked_connectors_needs_a_mode_that_asks_for_one() {
    // profile_only never asks for a connector, so a ranked selector there
    // would report nothing and read as "the ranking found none".
    assert!(!ranked_setting_admitted(
        true,
        DynamicConnectorMode::ProfileOnly
    ));
    for mode in [
        DynamicConnectorMode::Shadow,
        DynamicConnectorMode::Adjacency,
    ] {
        assert!(ranked_setting_admitted(true, mode));
    }
    for mode in [
        DynamicConnectorMode::ProfileOnly,
        DynamicConnectorMode::Shadow,
        DynamicConnectorMode::Adjacency,
    ] {
        assert!(ranked_setting_admitted(false, mode));
    }
}

/// Admission needs its reordering to reach a quote. `shadow` is the trap:
/// it ranks and screens like `adjacency`, so the shortlist looks admissible
/// — but shadow's connectors are deliberately never routable, so reordering
/// them changes nothing a caller can observe while reading as though
/// measurement were steering the pair budget.
#[test]
fn connector_admission_needs_a_mode_whose_connectors_route() {
    for mode in [
        DynamicConnectorMode::ProfileOnly,
        DynamicConnectorMode::Shadow,
    ] {
        assert!(!admission_setting_admitted(true, mode));
    }
    assert!(admission_setting_admitted(
        true,
        DynamicConnectorMode::Adjacency
    ));
    for mode in [
        DynamicConnectorMode::ProfileOnly,
        DynamicConnectorMode::Shadow,
        DynamicConnectorMode::Adjacency,
    ] {
        assert!(admission_setting_admitted(false, mode));
    }
}

/// One basis point, expressed in the ×10⁴ unit every ratio in the API uses.
/// A default that silently meant 1/10000 bp would admit everything §16
/// measured and read as a working threshold.
#[test]
fn the_default_admission_threshold_is_one_basis_point() {
    if std::env::var_os("SOLVER_CONNECTOR_MIN_BPS_E4").is_some() {
        return;
    }
    assert_eq!(read_connector_min_bps_e4().expect("default parses"), 10_000);
    assert_eq!(
        crate::certificate::format_bps_e4(U256::from(
            read_connector_min_bps_e4().expect("default parses")
        )),
        "1.0000"
    );
}

#[test]
fn the_two_selectors_never_share_a_cached_topology() {
    // The flag is process-wide, so it cannot be flipped mid-test. Rebuild
    // the encoding instead and require the live key to EQUAL it: an
    // inequality assertion would pass just as happily against a key that
    // omits the flag entirely, which is the regression worth catching.
    let profile = &crate::chain::BSC_PROFILE;
    let encode = |ranked: bool| {
        let mut scope = Vec::with_capacity(96);
        scope.push(3);
        scope.extend_from_slice(&profile.chain_id.to_be_bytes());
        scope.extend_from_slice(&(profile.key.len() as u16).to_be_bytes());
        scope.extend_from_slice(profile.key.as_bytes());
        scope.push(profile.connectors.len() as u8);
        for connector in profile.connectors {
            scope.extend_from_slice(connector.as_slice());
        }
        scope.push(1);
        scope.push(match *DYNAMIC_CONNECTORS {
            DynamicConnectorMode::ProfileOnly => 0,
            DynamicConnectorMode::Shadow => 1,
            DynamicConnectorMode::Adjacency => 2,
        });
        scope.push(1);
        scope.push(u8::from(*CONNECTOR_SCREENING));
        scope.push(u8::from(ranked));
        let DiscoveryProfile::IndexedEvm(discovery) = profile.discovery else {
            unreachable!("BSC is indexer-backed");
        };
        let protocols = discovery.quote_protocols();
        scope.push(protocols.len() as u8);
        for protocol in protocols {
            scope.push(protocol.rank());
        }
        scope.push(0); // BSC's indexer names its pools
        alloy_primitives::keccak256(&scope)
    };

    let live = topology_key(
        profile,
        Address::repeat_byte(0x11),
        Address::repeat_byte(0x99),
    )
    .1;
    assert_eq!(
        live,
        encode(*RANKED_CONNECTORS),
        "the topology cache scope must encode the ranked-connector flag"
    );
    assert_ne!(
        encode(false),
        encode(true),
        "flipping the flag must change the scope"
    );
}

fn test_connector_selection(
    connectors: Vec<Address>,
    eligible_count: usize,
    shortlist_truncated: bool,
) -> ConnectorSelection {
    ConnectorSelection {
        fences: test_catalog_fences(),
        protocols: vec![IndexedProtocol::UNIV2],
        screened: connectors.clone(),
        connectors,
        eligible_count,
        shortlist_truncated,
        selector: crate::topology::ConnectorSelector::AdjacencyWalk,
    }
}

/// A candidate the chain does not permit leaves by both doors.
///
/// Screening matters as much as routing here: a token left in `screened`
/// gets priced, lands in a coverage verdict, and becomes something
/// admission can promote into a route later.
#[test]
fn the_allowlist_removes_a_candidate_from_routing_and_from_screening() {
    let permitted = crate::chain::BSC_PROFILE.dynamic_connector_allowlist[0];
    let refused = Address::repeat_byte(0x9e);
    let mut selection = test_connector_selection(vec![permitted, refused], 2, false);

    retain_allowlisted(&crate::chain::BSC_PROFILE, &mut selection);

    assert_eq!(selection.connectors, vec![permitted]);
    assert_eq!(selection.screened, vec![permitted]);
    // The ranking's own count survives: it reports what the indexer found.
    assert_eq!(selection.eligible_count, 2);
}

/// An empty allowlist admits nothing, which is what makes it the safe
/// default for a chain that has never been reviewed.
#[test]
fn an_empty_allowlist_refuses_every_candidate() {
    let mut selection = test_connector_selection(vec![Address::repeat_byte(0x9f), WETH], 2, false);

    retain_allowlisted(&crate::chain::ROBINHOOD_PROFILE, &mut selection);

    assert!(selection.connectors.is_empty());
    assert!(selection.screened.is_empty());
}

#[test]
fn topology_cache_returns_universe_and_fences_from_the_same_entry() {
    let token_in = Address::repeat_byte(0x31);
    let token_out = Address::repeat_byte(0x32);
    let connector = Address::repeat_byte(0x33);
    let fences = test_catalog_fences();
    let universe = RouteUniverse::adjacency_complete(
        &crate::chain::BSC_PROFILE,
        token_in,
        token_out,
        test_connector_selection(vec![connector], 1, false),
    )
    .unwrap();
    let key = topology_key(&crate::chain::BSC_PROFILE, token_in, token_out);
    cache_topology(
        key,
        Topology {
            at: Instant::now(),
            status: TopologyStatus::Complete,
            screen_v3: Vec::new(),
            screen_v2: Vec::new(),
            universe: universe.clone(),
            topology_fences: Some(fences),
            v3: Vec::new(),
            v2: Vec::new(),
        },
    );

    let cached = topology_cached(key).unwrap();
    assert_eq!(cached.universe.fingerprint(), universe.fingerprint());
    assert_eq!(cached.topology_fences, Some(fences));
    TOPO_CACHE.lock().expect("topo cache lock").remove(&key);
}

#[test]
fn oversized_static_baseline_remains_a_hard_error() {
    let token_in = Address::repeat_byte(0x41);
    let token_out = Address::repeat_byte(0x42);
    let dynamic_connector = Address::repeat_byte(0x43);
    let proposed = RouteUniverse::adjacency_complete(
        &crate::chain::BSC_PROFILE,
        token_in,
        token_out,
        test_connector_selection(vec![dynamic_connector], 1, false),
    )
    .unwrap();
    let mut v3 = Vec::new();
    let mut v2 = Vec::new();
    for index in 0..u16::try_from(legs_over_cap()).unwrap() {
        v2.push(candidate_v2_pool(
            numbered_address(300 + index),
            token_in,
            crate::chain::WBNB,
        ));
        v2.push(candidate_v2_pool(
            numbered_address(500 + index),
            crate::chain::WBNB,
            token_out,
        ));
    }

    let error =
        admit_dynamic_work(&crate::chain::BSC_PROFILE, &proposed, &mut v3, &mut v2).unwrap_err();
    assert!(error.to_string().contains("baseline route candidate limit"));
}

/// A connector with no pool on one leg is dropped, and says so.
///
/// This is the ordinary case rather than an exotic one: the ranked selector
/// sees V2/V3 only, so a candidate whose second leg exists solely in V4
/// arrives here every time. Reporting it as an untruncated shortlist would
/// mean a coverage run reads "the selector's whole list is routable" on a
/// universe that quietly routes less than it was handed.
#[test]
fn a_connector_the_topology_cannot_route_marks_the_shortlist_truncated() {
    let token_in = Address::repeat_byte(0x11);
    let token_out = Address::repeat_byte(0x99);
    let routable = Address::repeat_byte(0x44);
    let one_legged = Address::repeat_byte(0x55);
    let proposed = RouteUniverse::adjacency_complete(
        &crate::chain::BSC_PROFILE,
        token_in,
        token_out,
        test_connector_selection(vec![routable, one_legged], 2, false),
    )
    .unwrap();
    let mut v3 = Vec::new();
    let mut v2 = vec![
        candidate_v2_pool(numbered_address(1), token_in, token_out),
        candidate_v2_pool(numbered_address(2), token_in, routable),
        candidate_v2_pool(numbered_address(3), routable, token_out),
        // Reachable from `token_in` and nowhere onward.
        candidate_v2_pool(numbered_address(4), token_in, one_legged),
    ];

    let universe =
        admit_dynamic_work(&crate::chain::BSC_PROFILE, &proposed, &mut v3, &mut v2).unwrap();

    let RouteUniverseSource::AdjacencyComplete {
        connectors,
        eligible_count,
        shortlist_truncated,
        ..
    } = universe.source()
    else {
        panic!("dynamic work gate lost adjacency provenance");
    };
    assert_eq!(connectors, &vec![routable]);
    assert_eq!(*eligible_count, 2);
    assert!(
        *shortlist_truncated,
        "a candidate the selector counted never became routable"
    );
}

#[test]
fn dynamic_candidate_work_cannot_turn_a_valid_static_quote_into_an_error() {
    let token_in = Address::repeat_byte(0x11);
    let token_out = Address::repeat_byte(0x99);
    let connector = Address::repeat_byte(0x44);
    let proposed = RouteUniverse::adjacency_complete(
        &crate::chain::BSC_PROFILE,
        token_in,
        token_out,
        test_connector_selection(vec![connector], 1, false),
    )
    .unwrap();
    let mut v3 = Vec::new();
    let mut v2 = vec![candidate_v2_pool(numbered_address(1), token_in, token_out)];
    for index in 0..u16::try_from(legs_over_cap()).unwrap() {
        v2.push(candidate_v2_pool(
            numbered_address(2 + index),
            token_in,
            connector,
        ));
        v2.push(candidate_v2_pool(
            numbered_address(130 + index),
            connector,
            token_out,
        ));
    }

    let universe =
        admit_dynamic_work(&crate::chain::BSC_PROFILE, &proposed, &mut v3, &mut v2).unwrap();
    let RouteUniverseSource::AdjacencyComplete {
        connectors,
        eligible_count,
        shortlist_truncated,
        ..
    } = universe.source()
    else {
        panic!("dynamic work gate lost adjacency provenance");
    };
    assert!(connectors.is_empty());
    assert_eq!(*eligible_count, 1);
    assert!(*shortlist_truncated);
    assert_eq!(v2.len(), 1, "rejected dynamic pools reached Lens");
}

#[test]
fn dynamic_work_is_admitted_before_factory_proof() {
    let token_in = Address::repeat_byte(0x11);
    let token_out = Address::repeat_byte(0x99);
    let connector = Address::repeat_byte(0x44);
    let proposed = RouteUniverse::adjacency_complete(
        &crate::chain::BSC_PROFILE,
        token_in,
        token_out,
        test_connector_selection(vec![connector], 1, false),
    )
    .unwrap();
    let mut pools = vec![indexed_v2_pool(numbered_address(1), token_in, token_out)];
    for index in 0..u16::try_from(legs_over_cap()).unwrap() {
        pools.push(indexed_v2_pool(
            numbered_address(2 + index),
            token_in,
            connector,
        ));
        pools.push(indexed_v2_pool(
            numbered_address(130 + index),
            connector,
            token_out,
        ));
    }
    let mut topology = IndexedTopology {
        pairs: indexed_route_pairs(&proposed).unwrap(),
        protocols: crate::chain::BSC_INDEXED_DISCOVERY.quote_protocols(),
        fences: test_catalog_fences(),
        pools,
    };

    let universe =
        admit_indexed_topology_work(&crate::chain::BSC_PROFILE, &proposed, &mut topology).unwrap();

    let RouteUniverseSource::AdjacencyComplete {
        connectors,
        shortlist_truncated,
        ..
    } = universe.source()
    else {
        panic!("dynamic work gate lost adjacency provenance");
    };
    assert!(connectors.is_empty());
    assert!(*shortlist_truncated);
    assert_eq!(topology.pools.len(), 1);
    assert_eq!(
        plan_indexed_validation(&crate::chain::BSC_INDEXED_DISCOVERY, &topology, 100, false,)
            .unwrap()
            .calls
            .len(),
        1,
        "rejected dynamic pools reached factory proof"
    );
}

#[test]
fn immutable_v4_spam_does_not_consume_route_candidate_work() {
    let profile = &crate::chain::BSC_PROFILE;
    let token_in = Address::repeat_byte(0x11);
    let token_out = Address::repeat_byte(0x99);
    let dynamic_connector = Address::repeat_byte(0x44);
    let proposed = RouteUniverse::adjacency_complete(
        profile,
        token_in,
        token_out,
        test_connector_selection(vec![dynamic_connector], 1, false),
    )
    .unwrap();
    let mut pools = vec![indexed_v2_pool(numbered_address(1), token_in, token_out)];
    let (left0, left1) = sorted_pair(token_in, profile.wrapped_native);
    let (right0, right1) = sorted_pair(profile.wrapped_native, token_out);
    for index in 0..legs_over_cap() {
        let fee = V4_MAX_FEE_PPM + 1 + index;
        pools.push(indexed_v4_pool(
            left0,
            left1,
            fee,
            Some(fee),
            10,
            Address::ZERO,
            Some(1),
        ));
        pools.push(indexed_v4_pool(
            right0,
            right1,
            fee,
            Some(fee),
            10,
            Address::ZERO,
            Some(1),
        ));
    }
    let mut topology = IndexedTopology {
        pairs: indexed_route_pairs(&proposed).unwrap(),
        protocols: crate::chain::BSC_INDEXED_DISCOVERY.quote_protocols(),
        fences: test_catalog_fences(),
        pools,
    };

    admit_indexed_topology_work(profile, &proposed, &mut topology).unwrap();
    let plan = plan_indexed_validation(&crate::chain::BSC_INDEXED_DISCOVERY, &topology, 100, false)
        .unwrap();
    assert_eq!(plan.probes.len(), 1);
    assert_eq!(plan.calls.len(), 1, "V4 spam reached factory proof");
}

#[test]
fn augmented_rpc_unavailability_retries_a_clean_static_universe() {
    let token_in = Address::repeat_byte(0x11);
    let token_out = Address::repeat_byte(0x99);
    let connector = Address::repeat_byte(0x44);
    let proposed = RouteUniverse::adjacency_complete(
        &crate::chain::BSC_PROFILE,
        token_in,
        token_out,
        test_connector_selection(vec![connector], 1, false),
    )
    .unwrap();
    // RpcUnavailable covers both transport failures and node/request
    // timeouts; contextual wrapping must not hide that typed cause.
    let unavailable = anyhow::anyhow!("transport details")
        .context(RpcUnavailable("eth_call"))
        .context("proving augmented topology through its factories");

    let fallback =
        augmented_availability_fallback(&crate::chain::BSC_PROFILE, &proposed, &unavailable)
            .unwrap()
            .expect("augmented availability failure must retry statically");
    let static_universe =
        RouteUniverse::profile_only(&crate::chain::BSC_PROFILE, token_in, token_out).unwrap();

    assert_eq!(fallback.token_paths(), static_universe.token_paths());
    assert_eq!(fallback.pairs(), static_universe.pairs());
    assert!(
        !fallback
            .token_paths()
            .iter()
            .flatten()
            .any(|token| *token == connector)
    );
    assert_eq!(fallback.fallback_kind(), Some(FallbackKind::Transport));

    let indexer_timeout = anyhow::Error::new(crate::topology::IndexerError::new(
        crate::topology::IndexerErrorKind::Transport,
        "topology request timed out",
    ));
    assert!(
        augmented_availability_fallback(&crate::chain::BSC_PROFILE, &proposed, &indexer_timeout,)
            .unwrap()
            .is_some(),
        "indexer transport timeouts must retry the static universe"
    );
    assert!(
        augmented_availability_fallback(
            &crate::chain::BSC_PROFILE,
            &static_universe,
            &unavailable,
        )
        .unwrap()
        .is_none(),
        "the clean static retry must not recurse"
    );
}

#[test]
fn malformed_augmented_topology_never_falls_back() {
    let proposed = RouteUniverse::adjacency_complete(
        &crate::chain::BSC_PROFILE,
        Address::repeat_byte(0x11),
        Address::repeat_byte(0x99),
        test_connector_selection(vec![Address::repeat_byte(0x44)], 1, false),
    )
    .unwrap();
    let malformed = anyhow::Error::new(crate::topology::IndexerError::new(
        crate::topology::IndexerErrorKind::InvalidResponse,
        "malformed topology",
    ))
    .context("pool indexer topology is unavailable");

    assert!(
        augmented_availability_fallback(&crate::chain::BSC_PROFILE, &proposed, &malformed,)
            .unwrap()
            .is_none()
    );
}

#[test]
fn augmented_topology_capacity_retries_a_clean_static_universe() {
    let token_in = Address::repeat_byte(0x11);
    let token_out = Address::repeat_byte(0x99);
    let proposed = RouteUniverse::adjacency_complete(
        &crate::chain::BSC_PROFILE,
        token_in,
        token_out,
        test_connector_selection(vec![Address::repeat_byte(0x44)], 1, false),
    )
    .unwrap();

    for kind in [
        crate::topology::IndexerErrorKind::Capacity,
        crate::topology::IndexerErrorKind::BodyTooLarge,
    ] {
        let error = anyhow::Error::new(crate::topology::IndexerError::new(
            kind,
            "augmented topology exceeded its strict capacity",
        ));
        let fallback =
            augmented_availability_fallback(&crate::chain::BSC_PROFILE, &proposed, &error)
                .unwrap()
                .expect("augmented capacity failure must retry statically");
        let static_universe =
            RouteUniverse::profile_only(&crate::chain::BSC_PROFILE, token_in, token_out).unwrap();

        assert_eq!(fallback.token_paths(), static_universe.token_paths());
        assert_eq!(fallback.pairs(), static_universe.pairs());
        assert_eq!(fallback.fallback_kind(), Some(FallbackKind::Capacity));
    }
}

#[test]
fn dynamic_candidate_inside_the_work_cap_is_retained() {
    let token_in = Address::repeat_byte(0x11);
    let token_out = Address::repeat_byte(0x99);
    let connector = Address::repeat_byte(0x44);
    let proposed = RouteUniverse::adjacency_complete(
        &crate::chain::BSC_PROFILE,
        token_in,
        token_out,
        test_connector_selection(vec![connector], 1, false),
    )
    .unwrap();
    let mut v3 = Vec::new();
    let mut v2 = vec![candidate_v2_pool(numbered_address(1), token_in, token_out)];
    for index in 0..2u16 {
        v2.push(candidate_v2_pool(
            numbered_address(2 + index),
            token_in,
            connector,
        ));
    }
    for index in 0..3u16 {
        v2.push(candidate_v2_pool(
            numbered_address(10 + index),
            connector,
            token_out,
        ));
    }

    let universe =
        admit_dynamic_work(&crate::chain::BSC_PROFILE, &proposed, &mut v3, &mut v2).unwrap();
    let RouteUniverseSource::AdjacencyComplete {
        connectors,
        shortlist_truncated,
        ..
    } = universe.source()
    else {
        panic!("dynamic work gate lost adjacency provenance");
    };
    assert_eq!(connectors, &[connector]);
    assert!(!shortlist_truncated);
    assert_eq!(v2.len(), 6);
}

#[test]
fn bsc_indexed_validation_admits_all_five_protocols_without_extra_v4_rpc() {
    let plan = plan_indexed_validation(
        &crate::chain::BSC_INDEXED_DISCOVERY,
        &five_protocol_bsc_topology(),
        100,
        false,
    )
    .unwrap();
    assert_eq!(plan.probes.len(), 5);
    assert_eq!(plan.calls.len(), 6, "V4 must not add a factory RPC");
    assert_eq!(
        plan.calls
            .iter()
            .map(|(target, _)| *target)
            .collect::<Vec<_>>(),
        vec![
            crate::chain::BSC_UNIV2_FACTORY,
            crate::chain::BSC_UNIV3_FACTORY,
            crate::chain::BSC_UNIV3_FACTORY,
            crate::chain::BSC_PANCAKE_V2_FACTORY,
            crate::chain::BSC_PANCAKE_V3_FACTORY,
            crate::chain::BSC_PANCAKE_V3_FACTORY,
        ]
    );
    let (v3, v2) = finish_indexed_validation(
        &crate::chain::BSC_PROFILE,
        plan,
        &five_protocol_bsc_results(),
    )
    .unwrap();

    assert_eq!(
        v2.iter()
            .map(|pool| (pool.protocol.as_str(), pool.fee_bps))
            .collect::<Vec<_>>(),
        vec![("univ2", 30), ("pancakev2", 25)]
    );
    assert_eq!(
        v3.iter()
            .map(|pool| {
                (
                    pool.protocol.as_str(),
                    pool.fee_ppm,
                    pool.tick_spacing,
                    pool.verify_pool_spacing,
                    pool.execution,
                )
            })
            .collect::<Vec<_>>(),
        vec![
            (
                "univ3",
                500,
                10,
                false,
                Some(V3ExecutionMeta {
                    fork_id: 0,
                    pool_id: 500,
                }),
            ),
            (
                "pancakev3",
                2_500,
                50,
                true,
                Some(V3ExecutionMeta {
                    fork_id: 1,
                    pool_id: 2_500,
                }),
            ),
            ("univ4", 500, 10, false, None),
        ]
    );
    let v4 = v3.iter().find(|pool| pool.v4.is_some()).unwrap();
    assert_eq!(v4.address, crate::chain::BSC_UNIV4_POOL_MANAGER);
    assert_eq!(
        v4.v4.as_ref().unwrap().pool_id,
        v4_pool_id(
            Address::repeat_byte(0x11),
            Address::repeat_byte(0x22),
            500,
            10,
            Address::ZERO,
        )
    );
    assert!(v3.iter().all(|pool| pool.algebra.is_none()));
}

#[test]
fn bsc_indexed_v4_known_pool_key_must_reproduce_pool_id() {
    let mut topology = bsc_test_topology(vec![indexed_v4_pool(
        Address::repeat_byte(0x11),
        Address::repeat_byte(0x22),
        500,
        Some(500),
        10,
        Address::ZERO,
        Some(14),
    )]);
    let valid =
        plan_indexed_validation(&crate::chain::BSC_INDEXED_DISCOVERY, &topology, 100, false)
            .unwrap();
    assert!(valid.calls.is_empty());
    assert_eq!(valid.probes.len(), 1);

    let IndexedPoolTopology::Univ4(pool) = &mut topology.pools[0] else {
        unreachable!()
    };
    pool.pool_id = B256::repeat_byte(0xee);
    let error =
        plan_indexed_validation(&crate::chain::BSC_INDEXED_DISCOVERY, &topology, 100, false)
            .unwrap_err();
    assert!(error.to_string().contains("PoolKey"));
    assert!(error.downcast_ref::<UpstreamIntegrityError>().is_some());
}

#[test]
fn bsc_indexed_v4_missing_key_fee_is_recovered_from_pinned_slot0() {
    let profile = &crate::chain::BSC_PROFILE;
    let topology = bsc_test_topology(vec![indexed_v4_pool(
        Address::ZERO,
        profile.stable,
        500,
        None,
        10,
        Address::ZERO,
        Some(14),
    )]);
    let plan = plan_indexed_validation(&crate::chain::BSC_INDEXED_DISCOVERY, &topology, 100, false)
        .unwrap();
    assert!(plan.calls.is_empty());
    let (candidates, v2) = finish_indexed_validation(profile, plan, &[]).unwrap();
    assert!(v2.is_empty());
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].fee_ppm, V4_UNKNOWN_KEY_FEE_PPM);

    let lp_fee = 500u32;
    let protocol_fee = (125u32 << 12) | 125;
    let slot0 = (U256::from(lp_fee) << 208usize)
        | (U256::from(protocol_fee) << 184usize)
        | (U256::ONE << 96usize);
    let mut words = vec![slot0, U256::from(1_000_000u64), U256::ONE];
    words.extend(std::iter::repeat_n(
        U256::ZERO,
        usize::try_from(*BITMAP_WORDS * 2 + 1).unwrap(),
    ));
    let result = crate::lens::PeekResult {
        words,
        window_words: bitmap_words().unwrap(),
        block_number: 100,
        block_timestamp: 1_800_000_000,
        block_id: BlockId::number(100),
        observed_at: Instant::now(),
    };

    let parsed = parse_lens(&candidates, &[], &result).unwrap();
    assert_eq!(parsed.snapshot.v3.len(), 1);
    let (pool, state) = &parsed.snapshot.v3[0];
    assert_eq!(pool.fee_ppm, lp_fee);
    assert_eq!(pool.token0, profile.wrapped_native);
    assert_eq!(pool.token1, profile.stable);
    assert_eq!(state.sqrt_price, U256::ONE << 96usize);
    let meta = pool.v4.as_ref().unwrap();
    assert!(meta.native);
    assert_eq!(
        (meta.swap_fee_0to1_ppm, meta.swap_fee_1to0_ppm),
        (
            v4_swap_fee(125, lp_fee).unwrap(),
            v4_swap_fee(125, lp_fee).unwrap(),
        )
    );
}

#[test]
fn invalid_live_v4_frame_does_not_misalign_the_next_pool() {
    let profile = &crate::chain::BSC_PROFILE;
    let topology = bsc_test_topology(vec![indexed_v4_pool(
        Address::ZERO,
        profile.stable,
        500,
        None,
        10,
        Address::ZERO,
        Some(14),
    )]);
    let plan = plan_indexed_validation(&crate::chain::BSC_INDEXED_DISCOVERY, &topology, 100, false)
        .unwrap();
    let (candidates, v2) = finish_indexed_validation(profile, plan, &[]).unwrap();
    assert!(v2.is_empty());
    let valid = candidates.into_iter().next().unwrap();
    let valid_pool_id = valid.v4.as_ref().unwrap().pool_id;
    let mut invalid = valid.clone();
    invalid.v4.as_mut().unwrap().pool_id = B256::repeat_byte(0xee);

    let lp_fee = 500u32;
    let slot0 = (U256::from(lp_fee) << 208usize) | (U256::ONE << 96usize);
    let bitmap_word_count = usize::try_from(*BITMAP_WORDS * 2 + 1).unwrap();
    let mut words = Vec::new();
    for liquidity_net in [7u64, 9] {
        words.extend([slot0, U256::from(1_000_000u64), U256::ONE]);
        let mut bitmap = vec![U256::ZERO; bitmap_word_count];
        bitmap[usize::try_from(*BITMAP_WORDS).unwrap()] = U256::ONE;
        words.extend(bitmap);
        words.push(U256::from(liquidity_net) << 128usize);
    }
    let result = crate::lens::PeekResult {
        words,
        window_words: bitmap_words().unwrap(),
        block_number: 100,
        block_timestamp: 1_800_000_000,
        block_id: BlockId::number(100),
        observed_at: Instant::now(),
    };

    let parsed = parse_lens(&[invalid, valid], &[], &result).unwrap();
    assert_eq!(parsed.snapshot.v3.len(), 1);
    assert_eq!(
        parsed.snapshot.v3[0].0.v4.as_ref().unwrap().pool_id,
        valid_pool_id
    );
    let state = &parsed.snapshot.v3[0].1;
    assert_eq!(state.sqrt_price, U256::ONE << 96usize);
    assert_eq!(state.liquidity, U256::from(1_000_000u64));
    assert_eq!(state.tick, 0);
    assert_eq!(state.ticks.len(), 1);
    assert_eq!(state.ticks[0].tick, 0);
    assert_eq!(state.ticks[0].liquidity_net, I256::try_from(9).unwrap());
}

#[test]
fn bsc_factory_address_mismatch_fails_the_complete_topology() {
    let proposed = RouteUniverse::adjacency_complete(
        &crate::chain::BSC_PROFILE,
        Address::repeat_byte(0x11),
        Address::repeat_byte(0x22),
        test_connector_selection(vec![Address::repeat_byte(0x44)], 1, false),
    )
    .unwrap();
    let plan = plan_indexed_validation(
        &crate::chain::BSC_INDEXED_DISCOVERY,
        &five_protocol_bsc_topology(),
        100,
        false,
    )
    .unwrap();
    let mut results = five_protocol_bsc_results();
    results[0] = Some(abi_address_word(Address::repeat_byte(0xee)));

    let error = finish_indexed_validation(&crate::chain::BSC_PROFILE, plan, &results).unwrap_err();
    assert!(error.to_string().contains("factory identity"));
    assert!(error.downcast_ref::<UpstreamIntegrityError>().is_some());
    assert!(
        augmented_availability_fallback(&crate::chain::BSC_PROFILE, &proposed, &error)
            .unwrap()
            .is_none(),
        "factory identity mismatch must fail closed"
    );
}

#[test]
fn bsc_v3_spoofed_factory_identity_fails_the_settler_create2_proof() {
    let spoofed = Address::repeat_byte(0xee);
    let topology = bsc_test_topology(vec![indexed_address_pool(
        IndexedProtocol::UNIV3,
        spoofed,
        500,
        Some(10),
        Some(11),
    )]);
    let plan = plan_indexed_validation(&crate::chain::BSC_INDEXED_DISCOVERY, &topology, 100, false)
        .unwrap();

    // The compromised topology and factory agree on the same spoofed
    // address. Only the Settler's reviewed CREATE2 identity can reject it.
    let results = [Some(abi_address_word(spoofed)), Some(abi_signed_word(10))];
    let error = finish_indexed_validation(&crate::chain::BSC_PROFILE, plan, &results).unwrap_err();

    assert!(error.to_string().contains("Settler CREATE2 identity"));
    assert!(error.downcast_ref::<UpstreamIntegrityError>().is_some());
}

#[test]
fn bsc_factory_spacing_mismatch_fails_the_complete_topology() {
    let plan = plan_indexed_validation(
        &crate::chain::BSC_INDEXED_DISCOVERY,
        &five_protocol_bsc_topology(),
        100,
        false,
    )
    .unwrap();
    let mut results = five_protocol_bsc_results();
    results[2] = Some(abi_signed_word(60));

    let error = finish_indexed_validation(&crate::chain::BSC_PROFILE, plan, &results).unwrap_err();
    assert!(error.to_string().contains("tick spacing"));
    assert!(error.downcast_ref::<UpstreamIntegrityError>().is_some());
}

#[test]
fn bsc_factory_spacing_requires_canonical_int24_sign_extension() {
    let mut malformed_negative_one = vec![0u8; 32];
    malformed_negative_one[29..].fill(0xff);
    let error = indexed_probe_spacing(&[Some(malformed_negative_one)], 0).unwrap_err();
    assert!(error.to_string().contains("canonical int24"));

    let canonical_negative_one = abi_signed_word(-1);
    assert_eq!(
        indexed_probe_spacing(&[Some(canonical_negative_one)], 0).unwrap(),
        -1
    );
}

#[test]
fn indexed_lens_decode_failures_are_upstream_integrity_errors() {
    let pool = V2Pool {
        protocol: V2Protocol::PANCAKEV2,
        address: Address::repeat_byte(0x41),
        token0: Address::repeat_byte(0x42),
        token1: Address::repeat_byte(0x43),
        fee_bps: 25,
    };
    let result = crate::lens::PeekResult {
        words: Vec::new(),
        window_words: bitmap_words().unwrap(),
        block_number: 1,
        block_timestamp: 1_800_000_000,
        block_id: BlockId::number(1),
        observed_at: Instant::now(),
    };

    let error = parse_indexed_lens(&[], &[pool], &result)
        .err()
        .expect("truncated Lens output must fail");
    assert!(error.downcast_ref::<UpstreamIntegrityError>().is_some());
    assert!(
        error
            .to_string()
            .contains("Lens response failed validation")
    );
}

#[test]
fn bsc_pancake_pool_rechecks_its_live_spacing() {
    let pool = V3Pool {
        protocol: V3Protocol::PANCAKEV3,
        address: Address::repeat_byte(0x31),
        token0: Address::repeat_byte(0x11),
        token1: Address::repeat_byte(0x22),
        fee_ppm: 500,
        tick_spacing: 10,
        verify_pool_spacing: true,
        execution: None,
        v4: None,
        algebra: None,
    };
    let result = |spacing| crate::lens::PeekResult {
        // ok, sqrtPrice, tick, liquidity, pool tickSpacing, live
        words: vec![
            U256::ONE,
            U256::ZERO,
            U256::ZERO,
            U256::ZERO,
            signed_word(spacing),
            U256::ZERO,
        ],
        window_words: bitmap_words().unwrap(),
        block_number: 100,
        block_timestamp: 1_800_000_000,
        block_id: BlockId::number(100),
        observed_at: Instant::now(),
    };

    parse_lens(std::slice::from_ref(&pool), &[], &result(10)).unwrap();
    let error = parse_lens(&[pool], &[], &result(60))
        .err()
        .expect("mismatched live spacing must fail closed");
    assert!(
        error
            .to_string()
            .contains("changed after factory validation")
    );
}

#[test]
fn bsc_pinned_replay_skips_only_candidates_created_after_the_pin() {
    let topology = bsc_test_topology(vec![indexed_address_pool(
        IndexedProtocol::UNIV2,
        Address::repeat_byte(0x31),
        3_000,
        None,
        Some(101),
    )]);

    let replay =
        plan_indexed_validation(&crate::chain::BSC_INDEXED_DISCOVERY, &topology, 100, true)
            .unwrap();
    assert!(replay.calls.is_empty() && replay.probes.is_empty());
    let error =
        plan_indexed_validation(&crate::chain::BSC_INDEXED_DISCOVERY, &topology, 100, false)
            .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("ahead of the canonical RPC block")
    );
    assert!(error.downcast_ref::<UpstreamIntegrityError>().is_some());
}

#[tokio::test]
async fn bsc_snapshot_without_an_indexer_fails_before_rpc_and_redacts_its_url() {
    let secret = "should-never-appear";
    let rpc = Rpc::connect(&format!("http://user:{secret}@127.0.0.1:1")).unwrap();
    let error = snapshot_at_observed_for(
        &crate::chain::BSC_PROFILE,
        &rpc,
        None,
        crate::chain::WBNB,
        crate::chain::BSC_USDT,
        None,
        None,
        None,
    )
    .await
    .err()
    .expect("missing indexer must reject the snapshot");
    let rendered = format!("{error:#}");
    assert!(rendered.contains("pool indexer is not configured"));
    assert!(!rendered.contains(secret));
}

#[test]
fn v4_topology_requires_fresh_scans_covering_the_primary_head() {
    let fresh = V4KeyDiscovery::Fresh(vec![(500, 10, Address::ZERO)]);
    assert_eq!(TopologyStatus::from_v4(&[fresh]), TopologyStatus::Complete);

    let discoveries = [
        V4KeyDiscovery::Fresh(vec![(500, 10, Address::ZERO)]),
        V4KeyDiscovery::Stale(vec![(3_000, 60, Address::ZERO)]),
    ];
    assert_eq!(
        TopologyStatus::from_v4(&discoveries),
        TopologyStatus::RetryV4
    );
    assert_eq!(
        TopologyStatus::from_v4(&[V4KeyDiscovery::BootstrapIncomplete]),
        TopologyStatus::RetryV4
    );
    assert!(v4_scan_covers_primary(Some(100), 100));
    assert!(v4_scan_covers_primary(Some(100), 101));
    assert!(!v4_scan_covers_primary(Some(100), 99));
    assert!(!v4_scan_covers_primary(None, 100));
}

#[test]
fn v4_incremental_scan_rechecks_the_recent_canonical_window() {
    assert_eq!(v4_refresh_from(0), 0);
    assert_eq!(v4_refresh_from(V4_REORG_OVERLAP - 1), 0);
    assert_eq!(v4_refresh_from(V4_REORG_OVERLAP), 1);
    assert_eq!(v4_refresh_from(100), 37);
}

#[test]
fn malformed_v4_initialize_log_is_not_silently_skipped() {
    assert!(v4_parse_key(&json!({})).is_err());
    assert!(v4_parse_key(&json!({"data": "0x00"})).is_err());
}

fn initialize_log_with(fee: u32, spacing: u8, hooks: Address) -> Value {
    let mut data = [0u8; 160];
    data[28..32].copy_from_slice(&fee.to_be_bytes());
    data[63] = spacing;
    data[76..96].copy_from_slice(hooks.as_slice());
    json!({"data": format!("0x{}", alloy_primitives::hex::encode(data))})
}

/// A hook address whose LOW 14 BITS are exactly `flags` (Hooks.sol
/// dispatch bits); the high bytes are arbitrary nonzero identity.
fn hook_with_flags(flags: u16) -> Address {
    let mut b = [0x11u8; 20];
    b[18] = (flags >> 8) as u8 & 0x3f;
    b[19] = flags as u8;
    Address::from(b)
}

#[test]
fn v4_admission_is_by_swap_capability_not_by_hook_identity() {
    let parse = |fee, hooks| v4_parse_key(&initialize_log_with(fee, 1, hooks)).unwrap();

    // hookless static tier — routable, as before
    assert_eq!(parse(500, Address::ZERO), Some((500, 1, Address::ZERO)));
    // liquidity-only hook (beforeAddLiquidity | beforeRemoveLiquidity):
    // never consulted during a swap — routable, identity preserved
    let liq_hook = hook_with_flags(1 << 11 | 1 << 9);
    assert_eq!(parse(500, liq_hook), Some((500, 1, liq_hook)));
    // dynamic-fee key under the same transparent hook — routable
    assert_eq!(
        parse(V4_DYNAMIC_FEE_FLAG, liq_hook),
        Some((V4_DYNAMIC_FEE_FLAG, 1, liq_hook))
    );
    // any swap-time permission bit excludes the pool
    for flags in [1u16 << 7, 1 << 6, 1 << 3, 1 << 2] {
        assert_eq!(parse(500, hook_with_flags(flags)), None);
    }
    // the live USDG/NVDA dynamic pool's hook (…8a80: beforeAddLiquidity |
    // beforeRemoveLiquidity | beforeSwap) — can override its fee per swap
    let robinhood = address!("a0ce1df0191a66434fb04391161776c7814f8a80");
    assert_eq!(parse(V4_DYNAMIC_FEE_FLAG, robinhood), None);
    // spam static fee above the cap still excluded
    assert_eq!(parse(V4_MAX_FEE_PPM + 1, Address::ZERO), None);
}

#[test]
fn v4_swap_fee_matches_pool_sol_fee_folding() {
    // Pool.sol:307 / ProtocolFeeLibrary.calculateSwapFee:
    // pf + lpFee - floor(pf * lpFee / 1e6)
    assert_eq!(v4_swap_fee(0, 500).unwrap(), 500);
    assert_eq!(v4_swap_fee(1000, 3000).unwrap(), 3997);
    assert_eq!(v4_swap_fee(125, 100).unwrap(), 225); // floor drops 0.0125
    assert_eq!(v4_swap_fee(1000, 1_000_000).unwrap(), 1_000_000); // 100% cap edge
    // the packed word observed live on NVDA pools: 1000 pips each way
    let packed = 4_097_000u32;
    assert_eq!((packed & 0xfff, packed >> 12), (1000, 1000));
}

#[test]
fn v4_hook_flags_read_the_low_14_bits() {
    assert_eq!(v4_hook_flags(Address::ZERO), 0);
    assert_eq!(
        v4_hook_flags(address!("a0ce1df0191a66434fb04391161776c7814f8a80")),
        0x0a80
    );
    assert_eq!(v4_hook_flags(hook_with_flags(0x3fff)), 0x3fff);
}

#[test]
fn v4_key_cache_rejects_an_oversized_single_pair_without_truncation() {
    let c0 = Address::repeat_byte(0xd1);
    let c1 = Address::repeat_byte(0xd2);
    ensure_v4_key_capacity(c0, c1, V4_KEYS_PER_PAIR_CAP).unwrap();
    let error = ensure_v4_key_capacity(c0, c1, V4_KEYS_PER_PAIR_CAP + 1).unwrap_err();
    assert!(error.to_string().contains("capacity"));
}

#[tokio::test]
async fn v4_bootstrap_gate_is_shared_per_currency_pair() {
    let key = (Address::repeat_byte(0xa1), Address::repeat_byte(0xb2));
    let (first, first_generation) = v4_key_gate(key).unwrap();
    let (second, second_generation) = v4_key_gate(key).unwrap();
    assert!(Arc::ptr_eq(&first, &second));
    assert_eq!(first_generation, second_generation);

    let guard = first.lock().await;
    assert!(second.try_lock().is_err());
    drop(guard);
    assert!(second.try_lock().is_ok());
}

#[derive(Clone)]
struct ScanRpcState {
    get_logs: Arc<AtomicUsize>,
    logs: Arc<Vec<Value>>,
}

async fn scan_rpc(State(state): State<ScanRpcState>, Json(request): Json<Value>) -> Json<Value> {
    let result = match request["method"].as_str() {
        Some("eth_blockNumber") => json!("0x64"),
        Some("eth_getLogs") => {
            state.get_logs.fetch_add(1, Ordering::Relaxed);
            Value::Array(state.logs.as_ref().clone())
        }
        method => panic!("unexpected rpc method {method:?}"),
    };
    Json(json!({
        "jsonrpc": "2.0",
        "id": request["id"],
        "result": result,
    }))
}

async fn rpc_with_logs(logs: Vec<Value>) -> (Rpc, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
    let get_logs = Arc::new(AtomicUsize::new(0));
    let app = Router::new()
        .route("/", post(scan_rpc))
        .with_state(ScanRpcState {
            get_logs: get_logs.clone(),
            logs: Arc::new(logs),
        });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (
        Rpc::connect(&format!("http://{address}")).unwrap(),
        get_logs,
        server,
    )
}

fn initialize_log(fee: u32) -> Value {
    let mut data = [0u8; 160];
    data[28..32].copy_from_slice(&fee.to_be_bytes());
    data[63] = 1; // positive int24 tickSpacing = 1
    json!({"data": format!("0x{}", alloy_primitives::hex::encode(data))})
}

#[tokio::test]
async fn concurrent_v4_bootstrap_miss_shares_one_log_scan() {
    let (rpc, get_logs, server) = rpc_with_logs(vec![]).await;
    let head = OnceCell::new();
    let source = V4ScanSource {
        rpc: &rpc,
        head: &head,
    };
    let scans = V4ScanContext {
        logs: Some(source),
        primary: source,
    };
    let c0 = Address::repeat_byte(0xc1);
    let c1 = Address::repeat_byte(0xc2);

    let (first, second) =
        tokio::join!(v4_event_keys(&scans, c0, c1), v4_event_keys(&scans, c0, c1));

    assert_eq!(first.unwrap(), V4KeyDiscovery::Fresh(vec![]));
    assert_eq!(second.unwrap(), V4KeyDiscovery::Fresh(vec![]));
    assert_eq!(get_logs.load(Ordering::Relaxed), 1);
    server.abort();
}

#[tokio::test]
async fn concurrent_v4_capacity_failure_shares_one_log_scan() {
    let logs = (1..=u32::try_from(V4_KEYS_PER_PAIR_CAP + 1).unwrap())
        .map(initialize_log)
        .collect();
    let (rpc, get_logs, server) = rpc_with_logs(logs).await;
    let head = OnceCell::new();
    let source = V4ScanSource {
        rpc: &rpc,
        head: &head,
    };
    let scans = V4ScanContext {
        logs: Some(source),
        primary: source,
    };
    let c0 = Address::repeat_byte(0xe1);
    let c1 = Address::repeat_byte(0xe2);

    let (first, second) =
        tokio::join!(v4_event_keys(&scans, c0, c1), v4_event_keys(&scans, c0, c1));

    let first = first.unwrap_err().to_string();
    let second = second.unwrap_err().to_string();
    assert!(first.contains("capacity"));
    assert_eq!(first, second);
    assert_eq!(get_logs.load(Ordering::Relaxed), 1);
    server.abort();
}

#[tokio::test]
async fn separate_logs_endpoint_needs_primary_canonical_tail() {
    let (logs_rpc, logs_calls, logs_server) = rpc_with_logs(vec![]).await;
    let (primary_rpc, primary_calls, primary_server) =
        rpc_with_logs(vec![initialize_log(500)]).await;
    let logs_head = OnceCell::new();
    let primary_head = OnceCell::new();
    let scans = V4ScanContext {
        logs: Some(V4ScanSource {
            rpc: &logs_rpc,
            head: &logs_head,
        }),
        primary: V4ScanSource {
            rpc: &primary_rpc,
            head: &primary_head,
        },
    };
    let c0 = Address::repeat_byte(0xf1);
    let c1 = Address::repeat_byte(0xf2);

    let discovery = v4_event_keys(&scans, c0, c1).await.unwrap();

    assert_eq!(
        discovery,
        V4KeyDiscovery::Fresh(vec![(500, 1, Address::ZERO)])
    );
    assert_eq!(logs_calls.load(Ordering::Relaxed), 1);
    assert_eq!(primary_calls.load(Ordering::Relaxed), 1);
    logs_server.abort();
    primary_server.abort();
}

#[test]
fn topology_probe_failures_are_never_cacheable_as_complete() {
    let complete = vec![None, Some(vec![]), Some(vec![1])];
    ensure_complete_probes(2, &complete).unwrap();

    let partial = vec![Some(vec![]), Some(vec![]), None];
    assert_eq!(
        ensure_complete_probes(2, &partial).unwrap_err().to_string(),
        "1 topology probes reverted"
    );
}

fn parsed_sheriff(binding: SheriffBinding) -> ParsedLens {
    let pool = V3Pool {
        protocol: V3Protocol::SHERIFF,
        address: Address::repeat_byte(0x31),
        token0: Address::repeat_byte(0x41),
        token1: Address::repeat_byte(0x42),
        fee_ppm: 0,
        tick_spacing: 10,
        verify_pool_spacing: false,
        execution: Some(V3ExecutionMeta {
            fork_id: FORK_SHERIFF,
            pool_id: 0,
        }),
        v4: None,
        algebra: None,
    };
    let state = V3State {
        sqrt_price: U256::ONE,
        tick: 0,
        liquidity: U256::ONE,
        ticks: Vec::<TickInfo>::new().into(),
        pos: 0,
        lo_cover: MIN_TICK,
        hi_cover: MAX_TICK,
    };
    ParsedLens {
        snapshot: Snapshot {
            block: 1,
            settler: Some(Address::repeat_byte(0x51)),
            v3: vec![(pool, state)],
            v2: vec![],
            ekubo: vec![],
        },
        sheriff_plugins: vec![binding],
    }
}

async fn failed_fee_rpc(State(code): State<i64>, Json(request): Json<Value>) -> Json<Value> {
    Json(json!({
        "jsonrpc": "2.0",
        "id": request["id"],
        "error": {"code": code, "message": "forced fee failure"}
    }))
}

#[tokio::test]
async fn sheriff_transport_failure_aborts_the_snapshot() {
    let app = Router::new()
        .route("/", post(failed_fee_rpc))
        .with_state(429);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let rpc = Rpc::connect(&format!("http://{address}")).unwrap();
    let parsed = parsed_sheriff(SheriffBinding {
        index: 0,
        plugin: SHERIFF_SLIDING_FEE_PLUGIN,
        codehash: SHERIFF_SLIDING_FEE_PLUGIN_CODEHASH,
        last_fee: 500,
        config: SHERIFF_PLUGIN_CONFIG,
    });

    let error = attach_algebra_fees(&rpc, parsed, BlockId::latest())
        .await
        .unwrap_err();
    assert!(error.downcast_ref::<crate::rpc::RpcUnavailable>().is_some());
    server.abort();
}

#[tokio::test]
async fn unsupported_sheriff_binding_is_explicitly_dropped_without_rpc() {
    let rpc = Rpc::connect("http://127.0.0.1:1").unwrap();
    let parsed = parsed_sheriff(SheriffBinding {
        index: 0,
        plugin: Address::ZERO,
        codehash: SHERIFF_SLIDING_FEE_PLUGIN_CODEHASH,
        last_fee: 500,
        config: SHERIFF_PLUGIN_CONFIG,
    });

    let snapshot = attach_algebra_fees(&rpc, parsed, BlockId::latest())
        .await
        .unwrap();
    assert!(snapshot.v3.is_empty());
}

#[test]
fn sheriff_pool_uses_the_settler_two_word_salt() {
    assert_eq!(
        algebra_pool_addr(SHERIFF_DEPLOYER, SHERIFF_INIT, WETH, crate::chain::USDG),
        address!("536a7b19abb933bf6319e0b8817e733bba166674")
    );
}

#[test]
fn extended_v3_forks_fail_closed_on_unknown_settler_builds() {
    // The reviewed build, pinned exactly or as the compatible extension.
    let extended_v3_hash = match crate::chain::ROBINHOOD_SETTLER.runtime {
        SettlerRuntimePolicy::Exact(hash)
        | SettlerRuntimePolicy::Compatible {
            extended_v3_hash: hash,
        } => hash,
        SettlerRuntimePolicy::SignerMasked { .. } => {
            panic!("Robinhood must pin the build its extended forks run on")
        }
    };
    for protocol in [
        V3Protocol::GIGADEXV3,
        V3Protocol::SUSHIV3,
        V3Protocol::ROBINSWAPV3,
    ] {
        assert!(settler_supports_protocol_for(
            &ROBINHOOD_PROFILE,
            protocol,
            extended_v3_hash
        ));
        assert!(!settler_supports_protocol_for(
            &ROBINHOOD_PROFILE,
            protocol,
            B256::ZERO
        ));

        assert!(!settler_supports_protocol_for(
            &crate::chain::BSC_PROFILE,
            protocol,
            extended_v3_hash
        ));
    }
    for protocol in [
        V3Protocol::UNIV3,
        V3Protocol::UP33CL,
        V3Protocol::PANCAKEV3,
        V3Protocol::SWAPHOODV3,
        V3Protocol::UNIV4,
        V3Protocol::SHERIFF,
    ] {
        assert!(!requires_verified_settler(protocol));
        assert!(settler_supports_protocol_for(
            &ROBINHOOD_PROFILE,
            protocol,
            B256::ZERO
        ));
    }
}

#[test]
fn algebra_lens_layout_rebuilds_the_linked_tick_window() {
    let pool_addr = address!("536a7b19abb933bf6319e0b8817e733bba166674");
    let plugin = address!("3a04e527a7aef9cb4c953d59ae8988134e2fa9f9");
    let plugin_codehash =
        alloy_primitives::b256!("1e392f56e5af82ce2c54ef72175494590d8211bd33ca0449b1a6679e09b18138");
    let pool = V3Pool {
        protocol: V3Protocol::SHERIFF,
        address: pool_addr,
        token0: WETH,
        token1: crate::chain::USDG,
        fee_ppm: 0,
        tick_spacing: 0,
        verify_pool_spacing: false,
        execution: Some(V3ExecutionMeta {
            fork_id: FORK_SHERIFF,
            pool_id: 0,
        }),
        v4: None,
        algebra: None,
    };
    let result = crate::lens::PeekResult {
        words: vec![
            U256::ONE,       // ok
            U256::from(999), // sqrt
            signed_word(-5),
            U256::from(777), // liquidity
            U256::from(400), // base fee
            U256::from(500), // last fee
            U256::from(SHERIFF_PLUGIN_CONFIG),
            U256::from(10), // spacing
            U256::from_be_slice(plugin.as_slice()),
            U256::from_be_slice(plugin_codehash.as_slice()),
            U256::ONE, // live
            U256::from(2),
            signed_word(-100),
            signed_word(10),
            signed_word(-10),
            signed_word(-3),
            U256::from(2),
            signed_word(20),
            signed_word(-7),
            signed_word(100),
            U256::ZERO,
        ],
        window_words: bitmap_words().unwrap(),
        block_number: 123,
        block_timestamp: 1_800_000_000,
        block_id: BlockId::number(123),
        observed_at: Instant::now(),
    };

    let parsed = parse_lens(&[pool], &[], &result).unwrap();
    assert_eq!(
        parsed.sheriff_plugins,
        vec![SheriffBinding {
            index: 0,
            plugin,
            codehash: plugin_codehash,
            last_fee: 500,
            config: SHERIFF_PLUGIN_CONFIG,
        }]
    );
    let (pool, state) = &parsed.snapshot.v3[0];
    assert_eq!((pool.fee_ppm, pool.tick_spacing), (400, 10));
    assert_eq!(state.pos, 2);
    assert_eq!((state.lo_cover, state.hi_cover), (-100, 100));
    assert_eq!(
        state.ticks.iter().map(|t| t.tick).collect::<Vec<_>>(),
        vec![-100, -10, 20, 100]
    );
}

#[test]
fn before_swap_fee_decoder_fails_closed() {
    let response = |override_fee: u32, plugin_fee: u32| {
        let mut ret = vec![0u8; 96];
        ret[..4].copy_from_slice(&beforeSwapCall::SELECTOR);
        ret[60..64].copy_from_slice(&override_fee.to_be_bytes());
        ret[92..96].copy_from_slice(&plugin_fee.to_be_bytes());
        ret
    };
    assert_eq!(decode_before_swap_fee(&response(367, 0), 500).unwrap(), 367);
    assert_eq!(decode_before_swap_fee(&response(367, 1), 500).unwrap(), 368);
    assert_eq!(decode_before_swap_fee(&response(0, 2), 500).unwrap(), 502);
    assert!(decode_before_swap_fee(&response(999_999, 1), 500).is_err());
    let mut wrong_selector = response(367, 0);
    wrong_selector[0] ^= 1;
    assert!(decode_before_swap_fee(&wrong_selector, 500).is_err());
    assert!(decode_before_swap_fee(&response(367, 0)[..95], 500).is_err());

    let binding = SheriffBinding {
        index: 0,
        plugin: SHERIFF_SLIDING_FEE_PLUGIN,
        codehash: SHERIFF_SLIDING_FEE_PLUGIN_CODEHASH,
        last_fee: 500,
        config: SHERIFF_PLUGIN_CONFIG,
    };
    validate_sheriff_binding(binding).unwrap();
    assert!(
        validate_sheriff_binding(SheriffBinding {
            plugin: Address::ZERO,
            ..binding
        })
        .is_err()
    );
    assert!(
        validate_sheriff_binding(SheriffBinding {
            config: 0,
            ..binding
        })
        .is_err()
    );
    assert!(
        validate_sheriff_binding(SheriffBinding {
            codehash: B256::ZERO,
            ..binding
        })
        .is_err()
    );
    assert!(
        validate_sheriff_binding(SheriffBinding {
            last_fee: 1_000_000,
            ..binding
        })
        .is_err()
    );

    let settler = address!("1d4b86491ec211257cbedd77a4380a7494624eff");
    let call = beforeSwapCall::abi_decode(&before_swap_call(settler, true)).unwrap();
    assert_eq!(
        (call.sender, call.recipient, call.zeroToOne),
        (settler, settler, true)
    );
}

#[test]
fn native_v4_pair_mapping_does_not_depend_on_weth_sort_order() {
    let cashcat = address!("020bfc650a365f8bb26819deaabf3e21291018b4");

    assert!(cashcat < WETH);
    assert_eq!(
        v4_currency_pair_for(WETH, cashcat, WETH, true),
        Some((Address::ZERO, cashcat))
    );
    assert_eq!(
        v4_currency_pair_for(WETH, WETH, cashcat, true),
        Some((Address::ZERO, cashcat))
    );
    assert_eq!(
        v4_tokens_from_currencies_for(WETH, Address::ZERO, cashcat),
        (WETH, cashcat)
    );
}

#[test]
fn bsc_profile_uses_only_its_own_native_and_registry_facts() {
    let bsc = &crate::chain::BSC_PROFILE;
    let token = Address::repeat_byte(0x72);

    assert_eq!(bsc.erc20_of(NATIVE), bsc.wrapped_native);
    assert_ne!(bsc.erc20_of(NATIVE), WETH);
    assert_eq!(
        v4_currency_pair_for(bsc.wrapped_native, bsc.wrapped_native, token, true),
        Some((Address::ZERO, token))
    );
    assert_eq!(
        v4_tokens_from_currencies_for(bsc.wrapped_native, Address::ZERO, token),
        (bsc.wrapped_native, token)
    );

    let bsc_execution = bsc.settler.unwrap();
    let (target, data) = settler_registry_call(bsc).unwrap();
    let call = ISettlerRegistry::ownerOfCall::abi_decode(&data).unwrap();
    assert_eq!(target, bsc_execution.registry);
    assert_eq!(call.id, U256::from(bsc_execution.registry_token_id));

    // A synthetic future adapter proves registry query construction reads
    // only the selected profile and never Robinhood compatibility globals.
    let mut future_bsc = **bsc;
    let mut execution = ROBINHOOD_PROFILE.settler.unwrap();
    execution.registry = Address::repeat_byte(0x73);
    execution.registry_token_id = 73;
    future_bsc.settler = Some(execution);
    let (target, data) = settler_registry_call(&future_bsc).unwrap();
    let call = ISettlerRegistry::ownerOfCall::abi_decode(&data).unwrap();
    assert_eq!(target, execution.registry);
    assert_eq!(call.id, U256::from(execution.registry_token_id));
    assert_ne!(target, ROBINHOOD_PROFILE.settler.unwrap().registry);
}

/// What the fixture's factories answer to `plan`: each tier's spacing as on
/// chain (100:1, 500:10, 3000:60, 10000:200), `named` at the given calls,
/// and the zero address, no pool, everywhere else.
fn fixture_factory_answers(
    plan: &FactoryDiscoveryPlan,
    named: &[(usize, Address)],
) -> Vec<Option<Vec<u8>>> {
    let spacing = |fee: u32| match fee {
        100 => 1,
        500 => 10,
        3_000 => 60,
        10_000 => 200,
        _ => 0,
    };
    let mut results = vec![Some(abi_address_word(Address::ZERO)); plan.calls.len()];
    for &(_, fee, call) in &plan.tiers {
        results[call] = Some(abi_signed_word(spacing(fee)));
    }
    for &(call, address) in named {
        results[call] = Some(abi_address_word(address));
    }
    results
}

/// The call asking about `pair` at `fee`, or for its V2 pair.
fn ask_call(plan: &FactoryDiscoveryPlan, pair: (Address, Address), fee: Option<u32>) -> usize {
    plan.asks
        .iter()
        .find(|ask| (ask.token0, ask.token1) == pair && ask.tier.map(|(fee, _)| fee) == fee)
        .expect("the plan asks about this pool")
        .call
}

/// The fixture's WETH/USDT0 0.05% pool: where the Settler's CREATE2 puts
/// it, and where it is on chain.
fn fixture_weth_usdt0_500() -> ((Address, Address), Address) {
    let pair = sorted_pair(crate::chain::FIXTURE_WETH, crate::chain::FIXTURE_USDT0);
    let pool = clone_pool_addr(
        crate::chain::FIXTURE_V3_FACTORY,
        crate::chain::FIXTURE_V3_INIT_HASH,
        pair.0,
        pair.1,
        500,
    );
    assert_eq!(pool, address!("24a691c2c8afab7049b6ab6847e3d06b5cbe5a11"));
    (pair, pool)
}

#[test]
fn factories_are_asked_about_each_pair_once_at_every_tier() {
    let discovery = &crate::chain::FIXTURE_DISCOVERY;
    let (x, y, z) = (
        Address::repeat_byte(0x11),
        Address::repeat_byte(0x22),
        Address::repeat_byte(0x33),
    );
    let plan = plan_factory_discovery(discovery, &[(y, x), (x, y), (z, x)]).unwrap();
    // The four tiers' spacings, then per pair its V2 pair and its V3 pool
    // at each tier; the reversed repeat of (x, y) is not asked again.
    assert_eq!(
        plan.tiers
            .iter()
            .map(|&(_, fee, call)| (fee, call))
            .collect::<Vec<_>>(),
        vec![(100, 0), (500, 1), (3_000, 2), (10_000, 3)]
    );
    assert_eq!(plan.calls.len(), 4 + 2 * 5);
    assert_eq!(plan.asks.len(), 2 * 5);
    assert!(plan.asks.iter().all(|ask| ask.token0 < ask.token1));
    let targets: Vec<Address> = plan.calls.iter().map(|(target, _)| *target).collect();
    let v3 = crate::chain::FIXTURE_V3_FACTORY;
    let v2 = crate::chain::FIXTURE_V2_FACTORY;
    assert_eq!(
        targets,
        [v3, v3, v3, v3, v2, v3, v3, v3, v3, v2, v3, v3, v3, v3]
    );
    let pair = IUniV2Factory::getPairCall::abi_decode(&plan.calls[4].1).unwrap();
    assert_eq!((pair.a, pair.b), (x, y));
    let pool = IUniV3Factory::getPoolCall::abi_decode(&plan.calls[6].1).unwrap();
    assert_eq!((pool.a, pool.b, pool.fee), (x, y, U24::from(500)));
    let pair = IUniV2Factory::getPairCall::abi_decode(&plan.calls[9].1).unwrap();
    assert_eq!((pair.a, pair.b), (x, z));

    assert!(plan_factory_discovery(&crate::chain::BSC_INDEXED_DISCOVERY, &[(x, y)]).is_err());
}

#[test]
fn the_pools_the_factories_name_are_proved_like_indexer_candidates() {
    let (pair, v3_pool) = fixture_weth_usdt0_500();
    let v2_pair = Address::repeat_byte(0x2a);
    let plan =
        plan_factory_discovery(&crate::chain::FIXTURE_DISCOVERY, &[(pair.1, pair.0)]).unwrap();
    let results = fixture_factory_answers(
        &plan,
        &[
            (ask_call(&plan, pair, None), v2_pair),
            (ask_call(&plan, pair, Some(500)), v3_pool),
        ],
    );
    let (v3, v2) =
        finish_factory_discovery(&crate::chain::FIXTURE_PROFILE, plan, &results).unwrap();

    assert_eq!(
        v2.iter()
            .map(|pool| (
                pool.protocol,
                pool.address,
                pool.token0,
                pool.token1,
                pool.fee_bps
            ))
            .collect::<Vec<_>>(),
        vec![(V2Protocol::UNIV2, v2_pair, pair.0, pair.1, 35)]
    );
    assert_eq!(
        v3.iter()
            .map(|pool| (
                pool.protocol,
                pool.address,
                pool.token0,
                pool.token1,
                pool.fee_ppm,
                pool.tick_spacing,
                pool.verify_pool_spacing,
                pool.execution,
            ))
            .collect::<Vec<_>>(),
        vec![(
            V3Protocol::UNIV3,
            v3_pool,
            pair.0,
            pair.1,
            500,
            10,
            false,
            Some(V3ExecutionMeta {
                fork_id: crate::chain::FIXTURE_V3_FORK_ID,
                pool_id: 500,
            }),
        )]
    );
}

#[test]
fn a_factory_answer_that_cannot_be_trusted_fails_the_round() {
    let (pair, v3_pool) = fixture_weth_usdt0_500();
    let profile = &crate::chain::FIXTURE_PROFILE;
    let discovery = &crate::chain::FIXTURE_DISCOVERY;
    let fails = |results: &dyn Fn(&FactoryDiscoveryPlan) -> Vec<Option<Vec<u8>>>,
                 expected: &str| {
        let plan = plan_factory_discovery(discovery, &[pair]).unwrap();
        let results = results(&plan);
        let error = finish_factory_discovery(profile, plan, &results).unwrap_err();
        assert!(
            error.downcast_ref::<UpstreamIntegrityError>().is_some(),
            "{error:#}"
        );
        assert!(format!("{error:#}").contains(expected), "{error:#}");
    };

    // A pool the Settler's CREATE2 does not reach.
    fails(
        &|plan| {
            fixture_factory_answers(
                plan,
                &[(ask_call(plan, pair, Some(500)), Address::repeat_byte(0x77))],
            )
        },
        "Settler CREATE2 identity",
    );
    // A factory with no code answers with no word: an RPC on another chain.
    fails(
        &|plan| {
            let mut results = fixture_factory_answers(plan, &[]);
            results[ask_call(plan, pair, None)] = Some(Vec::new());
            results
        },
        "non-word result",
    );
    // A factory call that reverted.
    fails(
        &|plan| {
            let mut results = fixture_factory_answers(plan, &[]);
            results[ask_call(plan, pair, Some(3_000))] = None;
            results
        },
        "reverted",
    );
    // A pool at a tier the factory says it has not enabled.
    fails(
        &|plan| {
            let mut results =
                fixture_factory_answers(plan, &[(ask_call(plan, pair, Some(500)), v3_pool)]);
            let spacing = plan.tiers.iter().find(|tier| tier.1 == 500).unwrap().2;
            results[spacing] = Some(abi_signed_word(0));
            results
        },
        "has not enabled",
    );
    // An answer short of the plan.
    fails(
        &|plan| {
            let mut results = fixture_factory_answers(plan, &[]);
            results.pop();
            results
        },
        "wrong result count",
    );
}

#[test]
fn named_pools_come_out_in_the_order_an_indexer_lists_them() {
    let late = (Address::repeat_byte(0x41), Address::repeat_byte(0x42));
    let early = (Address::repeat_byte(0x05), Address::repeat_byte(0x06));
    let plan = plan_factory_discovery(&crate::chain::FIXTURE_DISCOVERY, &[late, early]).unwrap();
    let results = fixture_factory_answers(
        &plan,
        &[
            (ask_call(&plan, late, None), Address::repeat_byte(0x91)),
            (ask_call(&plan, early, None), Address::repeat_byte(0x92)),
        ],
    );
    let (v3, v2) =
        finish_factory_discovery(&crate::chain::FIXTURE_PROFILE, plan, &results).unwrap();
    assert!(v3.is_empty());
    assert_eq!(
        v2.iter()
            .map(|pool| (pool.token0, pool.address))
            .collect::<Vec<_>>(),
        vec![
            (early.0, Address::repeat_byte(0x92)),
            (late.0, Address::repeat_byte(0x91)),
        ]
    );
}

#[test]
fn factory_named_pools_route_through_the_profiles_connectors_only() {
    use DynamicConnectorMode::{Adjacency, ProfileOnly, Shadow};
    let factories = Some(CandidateSource::Factories);
    assert!(connector_mode_admitted(factories, ProfileOnly));
    assert!(!connector_mode_admitted(factories, Shadow));
    assert!(!connector_mode_admitted(factories, Adjacency));
    for mode in [ProfileOnly, Shadow, Adjacency] {
        assert!(connector_mode_admitted(
            Some(CandidateSource::Indexer),
            mode
        ));
        assert!(connector_mode_admitted(None, mode));
    }
}

#[tokio::test]
async fn a_profile_whose_factories_name_its_pools_refuses_an_indexer() {
    let rpc = Rpc::connect("http://127.0.0.1:1").unwrap();
    let client = IndexerClient::builder("http://127.0.0.1:1", &crate::chain::BSC_PROFILE)
        .unwrap()
        .build()
        .unwrap();
    let outcome = snapshot_at_observed_for(
        &crate::chain::FIXTURE_PROFILE,
        &rpc,
        Some(&client),
        Address::repeat_byte(0x11),
        Address::repeat_byte(0x22),
        None,
        None,
        None,
    )
    .await;
    let Err(error) = outcome else {
        panic!("a factory-discovery snapshot took an indexer");
    };
    assert!(error.to_string().contains("takes no indexer"), "{error:#}");
    assert!(error.downcast_ref::<RpcUnavailable>().is_none());
}

#[tokio::test]
async fn snapshot_at_for_a_profile_without_discovery_errs_as_the_dispatcher_does() {
    let rpc = Rpc::connect("http://127.0.0.1:1").unwrap();
    let mut disabled = *crate::chain::BSC_PROFILE;
    disabled.discovery = DiscoveryProfile::Disabled;
    let (token_a, token_b) = (crate::chain::WBNB, crate::chain::BSC_USDT);
    let public = snapshot_at_for(&disabled, &rpc, None, token_a, token_b, None)
        .await
        .expect_err("a profile without discovery must refuse the snapshot");
    let dispatched =
        snapshot_at_observed_for(&disabled, &rpc, None, token_a, token_b, None, None, None)
            .await
            .err()
            .expect("the dispatcher refuses a profile without discovery");
    assert_eq!(format!("{public:#}"), format!("{dispatched:#}"));
    assert_eq!(
        public.to_string(),
        format!(
            "pool discovery is not enabled for {} ({})",
            disabled.name, disabled.chain_id
        )
    );
}

/// A Robinhood probe as the goldens compare and print it.
#[derive(Debug, PartialEq)]
enum ProbeRow {
    V2(V2Protocol, (Address, Address)),
    V3Univ3((Address, Address), u32),
    V3Up33((Address, Address), i32),
    V3Clone(V3Protocol, u8, Address, (Address, Address), u32),
    V3Sheriff(Address, (Address, Address)),
    V4((Address, Address), u32, i32, bool),
}

fn probe_row(probe: &Probe) -> ProbeRow {
    match *probe {
        Probe::V2 { proto, pair } => ProbeRow::V2(proto, pair),
        Probe::V3Univ3 { pair, fee } => ProbeRow::V3Univ3(pair, fee),
        Probe::V3Up33 { pair, spacing } => ProbeRow::V3Up33(pair, spacing),
        Probe::V3Clone {
            proto,
            fork_id,
            addr,
            pair,
            fee,
        } => ProbeRow::V3Clone(proto, fork_id, addr, pair, fee),
        Probe::V3Sheriff { addr, pair } => ProbeRow::V3Sheriff(addr, pair),
        Probe::V4 {
            pair,
            fee,
            spacing,
            native,
        } => ProbeRow::V4(pair, fee, spacing, native),
    }
}

#[test]
fn robinhood_asks_every_venue_about_a_pair_in_one_fixed_order() {
    // A two-token universe has one pair, here in the direction a quote from
    // USDG sees it: the reverse of the sorted pair, which only the CREATE2
    // derivations and the V4 currencies use.
    let usdg = crate::chain::USDG;
    let (x, y) = (usdg, WETH);
    let pair = (x, y);
    let (t0, t1) = (WETH, usdg);
    assert_eq!(sorted_pair(x, y), (t0, t1));
    let spacings = [1, 50, 100, 200];
    let head = (ARBSYS, IArbSys::arbBlockNumberCall {}.abi_encode());
    // No V4 keys: the scans of the pair's ERC-20 side and of its native side
    // were both unavailable, so both sides are probed on the key grid.
    let unavailable = [
        V4KeyDiscovery::BootstrapIncomplete,
        V4KeyDiscovery::BootstrapIncomplete,
    ];
    let plan = plan_robinhood_probes(
        &ROBINHOOD_PROFILE,
        vec![head.clone()],
        &[pair],
        &spacings,
        &unavailable,
    )
    .unwrap();

    let mut expected = vec![
        (
            (
                UNIV2_FACTORY,
                IUniV2Factory::getPairCall { a: x, b: y }.abi_encode(),
            ),
            ProbeRow::V2(V2Protocol::UNIV2, pair),
        ),
        (
            (
                UP33_V2_FACTORY,
                IUp33V2Factory::getPoolCall {
                    a: x,
                    b: y,
                    stable: false,
                }
                .abi_encode(),
            ),
            ProbeRow::V2(V2Protocol::UP33V2, pair),
        ),
    ];
    for fee in [100, 500, 3_000, 10_000] {
        let call = IUniV3Factory::getPoolCall {
            a: x,
            b: y,
            fee: U24::from(fee),
        };
        expected.push((
            (UNIV3_FACTORY, call.abi_encode()),
            ProbeRow::V3Univ3(pair, fee),
        ));
    }
    for spacing in spacings {
        let call = IUp33ClFactory::getPoolCall {
            a: x,
            b: y,
            tickSpacing: crate::lens::i24(spacing).unwrap(),
        };
        expected.push((
            (UP33_CL_FACTORY, call.abi_encode()),
            ProbeRow::V3Up33(pair, spacing),
        ));
    }
    // A clone is probed at its own CREATE2 address, by slot0.
    let mut clone_probe = |protocol, fork_id, deployer, init, fee| {
        let pool = clone_pool_addr(deployer, init, t0, t1, fee);
        expected.push((
            (pool, IPoolState::slot0Call {}.abi_encode()),
            ProbeRow::V3Clone(protocol, fork_id, pool, pair, fee),
        ));
    };
    // Pancake and SwapHood take turns within each tier.
    for fee in [100, 500, 2_500, 10_000] {
        clone_probe(
            V3Protocol::PANCAKEV3,
            FORK_PANCAKE,
            PANCAKE_V3_DEPLOYER,
            PANCAKE_V3_INIT,
            fee,
        );
        clone_probe(
            V3Protocol::SWAPHOODV3,
            FORK_SWAPHOOD,
            SWAPHOOD_V3_DEPLOYER,
            SWAPHOOD_V3_INIT,
            fee,
        );
    }
    for fee in [100, 200, 500, 1_000, 2_000, 3_000, 10_000, 20_000] {
        clone_probe(
            V3Protocol::GIGADEXV3,
            FORK_GIGADEX,
            GIGADEX_V3_DEPLOYER,
            GIGADEX_V3_INIT,
            fee,
        );
    }
    for fee in [500, 3_000, 10_000] {
        clone_probe(
            V3Protocol::SUSHIV3,
            FORK_SUSHI,
            SUSHI_V3_DEPLOYER,
            SUSHI_V3_INIT,
            fee,
        );
    }
    for fee in [100, 500, 2_500, 3_000, 10_000] {
        clone_probe(
            V3Protocol::ROBINSWAPV3,
            FORK_ROBINSWAP,
            ROBINSWAP_V3_DEPLOYER,
            ROBINSWAP_V3_INIT,
            fee,
        );
    }
    // The pair's one Sheriff pool (sheriff_pool_uses_the_settler_two_word_salt).
    let sheriff = address!("536a7b19abb933bf6319e0b8817e733bba166674");
    expected.push((
        (sheriff, globalStateCall {}.abi_encode()),
        ProbeRow::V3Sheriff(sheriff, pair),
    ));
    // The key grid on the ERC-20 side's currencies, the sorted pair, then on
    // the native side's, ETH and USDG.
    for (native, (c0, c1)) in [(false, (t0, t1)), (true, (Address::ZERO, usdg))] {
        for (fee, spacing) in [(100, 1), (500, 10), (3_000, 60), (10_000, 200)] {
            let slot = v4_meta(c0, c1, fee, spacing, Address::ZERO).state_slot;
            expected.push((
                (V4_POOL_MANAGER, extsload(slot)),
                ProbeRow::V4(pair, fee, spacing, native),
            ));
        }
    }
    let (calls, rows): (Vec<_>, Vec<_>) = expected.into_iter().unzip();

    // 43 probes: 2 V2 venues, 4 univ3 tiers, 4 spacings, 24 clone pools,
    // Sheriff and 4 grid keys on each V4 side. The calls are the head
    // rider's, then one per probe.
    assert_eq!(plan.probes.len(), 43);
    assert_eq!(plan.calls[0], head);
    assert_eq!(plan.calls[1..], calls);
    assert_eq!(plan.probes.iter().map(probe_row).collect::<Vec<_>>(), rows);
    assert!(plan.v4direct.is_empty());

    // Scans that found no keys leave V4 nothing to probe.
    let found_none = [
        V4KeyDiscovery::Fresh(Vec::new()),
        V4KeyDiscovery::Fresh(Vec::new()),
    ];
    let plan = plan_robinhood_probes(
        &ROBINHOOD_PROFILE,
        vec![head],
        &[pair],
        &spacings,
        &found_none,
    )
    .unwrap();
    assert_eq!(plan.calls[1..], calls[..35]);
    assert_eq!(
        plan.probes.iter().map(probe_row).collect::<Vec<_>>(),
        rows[..35]
    );
    assert!(plan.v4direct.is_empty());
}

#[test]
fn robinhood_discovery_drops_absent_pools_and_refuses_short_answers() {
    let usdg = crate::chain::USDG;
    let (x, y) = (usdg, WETH);
    let spacings = [1, 50, 100, 200];
    let head = vec![(ARBSYS, IArbSys::arbBlockNumberCall {}.abi_encode())];
    let found_none = [
        V4KeyDiscovery::Fresh(Vec::new()),
        V4KeyDiscovery::Fresh(Vec::new()),
    ];
    let plan = plan_robinhood_probes(
        &ROBINHOOD_PROFILE,
        head.clone(),
        &[(x, y)],
        &spacings,
        &found_none,
    )
    .unwrap();
    assert_eq!(plan.probes.len(), 35);

    // Every probe answers "absent" (the zero address, a zero word or empty
    // data). One UniV3 tier names a pool and one clone answers a nonzero
    // word; another clone answers empty data (a codeless address) and a
    // third 31 bytes, both skipped by the length check.
    let mut res = vec![Some(abi_signed_word(1_000))];
    res.extend((0..plan.probes.len()).map(|_| Some(abi_address_word(Address::ZERO))));
    res[3] = Some(abi_address_word(numbered_address(100))); // univ3, 100 ppm
    res[11] = Some(abi_signed_word(1)); // the clone's pool exists
    res[12] = Some(Vec::new());
    res[13] = Some(vec![0u8; 31]);

    // A factory answer too short to be a word fails the round.
    let mut short = res.clone();
    short[1] = Some(vec![0u8; 31]); // the up33v2 factory
    let error = finish_robinhood_discovery(
        &ROBINHOOD_PROFILE,
        &plan.probes,
        &short,
        plan.v4direct.clone(),
    )
    .unwrap_err();
    assert!(
        format!("{error:#}").contains("return data shorter than expected"),
        "{error:#}"
    );

    ensure_complete_probes(plan.probes.len(), &res).unwrap();
    let (v3, v2) =
        finish_robinhood_discovery(&ROBINHOOD_PROFILE, &plan.probes, &res, plan.v4direct).unwrap();
    assert!(v2.is_empty());
    assert_eq!(v3.len(), 2, "only the named pools: {v3:?}");
    assert_eq!(
        (v3[0].protocol, v3[0].address, v3[0].fee_ppm),
        (V3Protocol::UNIV3, numbered_address(100), 100)
    );
    assert!(v3[1].verify_pool_spacing);
    assert_eq!(v3[1].execution.unwrap().pool_id, v3[1].fee_ppm);

    // A negative up33 spacing cannot become a Settler pool id.
    let plan =
        plan_robinhood_probes(&ROBINHOOD_PROFILE, head, &[(x, y)], &[-1], &found_none).unwrap();
    let mut res = vec![Some(abi_signed_word(1_000))];
    res.extend((0..plan.probes.len()).map(|_| Some(abi_address_word(Address::ZERO))));
    res[7] = Some(abi_address_word(numbered_address(7))); // the one up33cl probe
    let error = finish_robinhood_discovery(&ROBINHOOD_PROFILE, &plan.probes, &res, plan.v4direct)
        .unwrap_err();
    assert!(
        format!("{error:#}").contains("negative tickSpacing"),
        "{error:#}"
    );
}

#[test]
fn the_lens_window_comes_from_the_read_not_a_global() {
    let profile = &crate::chain::BSC_PROFILE;
    let mut candidates = Vec::new();
    for address in [Address::repeat_byte(0x71), Address::repeat_byte(0x72)] {
        candidates.push(V3Pool {
            protocol: V3Protocol::UNIV3,
            address,
            token0: profile.wrapped_native,
            token1: profile.stable,
            fee_ppm: 3_000,
            tick_spacing: 10,
            verify_pool_spacing: false,
            execution: None,
            v4: None,
            algebra: None,
        });
    }
    // Per pool: the call-succeeded word, sqrtPrice, tick, liquidity, the
    // initialized flag, then one bitmap word per side of a one-word window.
    let mut words = Vec::new();
    for _ in 0..2 {
        words.extend([
            U256::ONE,
            U256::ONE << 96usize,
            U256::ZERO,
            U256::from(1_000u64),
            U256::ONE,
        ]);
        words.extend([U256::ZERO; 3]);
    }
    let result = crate::lens::PeekResult {
        words,
        window_words: 1,
        block_number: 100,
        block_timestamp: 1_800_000_000,
        block_id: BlockId::number(100),
        observed_at: Instant::now(),
    };
    let parsed = parse_lens(&candidates, &[], &result).unwrap();
    assert_eq!(parsed.snapshot.v3.len(), 2, "both pools parse in order");
    let (_, first) = &parsed.snapshot.v3[0];
    assert_eq!((first.lo_cover, first.hi_cover), (-2_560, 5_110));
}

#[test]
fn robinhood_pools_come_out_in_probe_order_with_event_pools_last() {
    let usdg = crate::chain::USDG;
    let (x, y) = (usdg, WETH);
    let (t0, t1) = (WETH, usdg);
    let spacings = [1, 50, 100, 200];
    let head = vec![(ARBSYS, IArbSys::arbBlockNumberCall {}.abi_encode())];
    // The ERC-20 side's Initialize events name two keys, one under a
    // liquidity-only hook, so that side needs no probe; the native side's scan
    // was unavailable, so it is probed on the key grid.
    let hook = hook_with_flags(1 << 11 | 1 << 9);
    let keys = vec![(500, 10, Address::ZERO), (V4_DYNAMIC_FEE_FLAG, 60, hook)];
    let v4keys = [
        V4KeyDiscovery::Fresh(keys.clone()),
        V4KeyDiscovery::BootstrapIncomplete,
    ];
    let plan =
        plan_robinhood_probes(&ROBINHOOD_PROFILE, head, &[(x, y)], &spacings, &v4keys).unwrap();
    // The 35 probes before V4, then the native side's 4 grid keys.
    assert_eq!(plan.probes.len(), 39);
    // The head rider answers a block number. Then probe i answers the word of
    // numbered_address(i): the pool a factory names, and for the slot0,
    // globalState and extsload probes a nonzero word, so every probe finds
    // its pool.
    let mut res = vec![Some(abi_signed_word(1_000))];
    res.extend((0..plan.probes.len()).map(|i| Some(abi_address_word(numbered_address(i as u16)))));
    ensure_complete_probes(plan.probes.len(), &res).unwrap();
    let (v3, v2) =
        finish_robinhood_discovery(&ROBINHOOD_PROFILE, &plan.probes, &res, plan.v4direct).unwrap();

    // Probes 0 and 1 ask the two V2 factories; every V2 pool takes UNIV2_FEE_BPS.
    assert_eq!(
        v2.iter()
            .map(|pool| (
                pool.protocol,
                pool.address,
                pool.token0,
                pool.token1,
                pool.fee_bps
            ))
            .collect::<Vec<_>>(),
        vec![
            (V2Protocol::UNIV2, numbered_address(0), t0, t1, 30),
            (V2Protocol::UP33V2, numbered_address(1), t0, t1, 30),
        ]
    );

    let execution = |fork_id, pool_id| Some(V3ExecutionMeta { fork_id, pool_id });
    let mut expected = Vec::new();
    // Probes 2-5: univ3 at each tier, which fixes its spacing.
    for (i, (fee, spacing)) in [(100, 1), (500, 10), (3_000, 60), (10_000, 200)]
        .into_iter()
        .enumerate()
    {
        let pool = numbered_address(2 + i as u16);
        expected.push((
            V3Protocol::UNIV3,
            pool,
            (t0, t1),
            fee,
            spacing,
            false,
            execution(FORK_UNIV3, fee),
            None,
        ));
    }
    // Probes 6-9: up33cl at each spacing, which is also its Settler pool id.
    for (i, spacing) in spacings.into_iter().enumerate() {
        let pool = numbered_address(6 + i as u16);
        let pool_id = u32::try_from(spacing).unwrap();
        expected.push((
            V3Protocol::UP33CL,
            pool,
            (t0, t1),
            0,
            spacing,
            false,
            execution(FORK_UP33, pool_id),
            None,
        ));
    }
    // Probes 10-33: the clones at their CREATE2 addresses; each re-reads its
    // own spacing, and its fee is its Settler pool id.
    let mut clone_pool = |protocol, fork_id, deployer, init, fee| {
        let pool = clone_pool_addr(deployer, init, t0, t1, fee);
        expected.push((
            protocol,
            pool,
            (t0, t1),
            fee,
            0,
            true,
            execution(fork_id, fee),
            None,
        ));
    };
    for fee in [100, 500, 2_500, 10_000] {
        clone_pool(
            V3Protocol::PANCAKEV3,
            FORK_PANCAKE,
            PANCAKE_V3_DEPLOYER,
            PANCAKE_V3_INIT,
            fee,
        );
        clone_pool(
            V3Protocol::SWAPHOODV3,
            FORK_SWAPHOOD,
            SWAPHOOD_V3_DEPLOYER,
            SWAPHOOD_V3_INIT,
            fee,
        );
    }
    for fee in [100, 200, 500, 1_000, 2_000, 3_000, 10_000, 20_000] {
        clone_pool(
            V3Protocol::GIGADEXV3,
            FORK_GIGADEX,
            GIGADEX_V3_DEPLOYER,
            GIGADEX_V3_INIT,
            fee,
        );
    }
    for fee in [500, 3_000, 10_000] {
        clone_pool(
            V3Protocol::SUSHIV3,
            FORK_SUSHI,
            SUSHI_V3_DEPLOYER,
            SUSHI_V3_INIT,
            fee,
        );
    }
    for fee in [100, 500, 2_500, 3_000, 10_000] {
        clone_pool(
            V3Protocol::ROBINSWAPV3,
            FORK_ROBINSWAP,
            ROBINSWAP_V3_DEPLOYER,
            ROBINSWAP_V3_INIT,
            fee,
        );
    }
    // Probe 34: Sheriff, whose fee and spacing the Lens reads.
    let sheriff = address!("536a7b19abb933bf6319e0b8817e733bba166674");
    expected.push((
        V3Protocol::SHERIFF,
        sheriff,
        (t0, t1),
        0,
        0,
        false,
        execution(FORK_SHERIFF, 0),
        None,
    ));
    // Probes 35-38: the native side's grid, ETH/USDG pools routed as WETH/USDG.
    for (fee, spacing) in [(100, 1), (500, 10), (3_000, 60), (10_000, 200)] {
        let id = v4_pool_id(Address::ZERO, usdg, fee, spacing, Address::ZERO);
        expected.push((
            V3Protocol::UNIV4,
            V4_POOL_MANAGER,
            (t0, t1),
            fee,
            spacing,
            false,
            None,
            Some((id, true, Address::ZERO)),
        ));
    }
    // Last, the ERC-20 side's pools its events prove, in key order.
    for (fee, spacing, hooks) in keys {
        let id = v4_pool_id(t0, t1, fee, spacing, hooks);
        expected.push((
            V3Protocol::UNIV4,
            V4_POOL_MANAGER,
            (t0, t1),
            fee,
            spacing,
            false,
            None,
            Some((id, false, hooks)),
        ));
    }
    assert_eq!(
        v3.iter()
            .map(|pool| (
                pool.protocol,
                pool.address,
                (pool.token0, pool.token1),
                pool.fee_ppm,
                pool.tick_spacing,
                pool.verify_pool_spacing,
                pool.execution,
                pool.v4
                    .as_ref()
                    .map(|meta| (meta.pool_id, meta.native, meta.hooks)),
            ))
            .collect::<Vec<_>>(),
        expected
    );
    assert!(v3.iter().all(|pool| pool.algebra.is_none()));
}
