use super::ObservedSnapshot;
use super::cache::{
    Topology, TopologyStatus, cache_topology, listed_topology_key, topology_cached, topology_key,
};
use super::connectors::{discover_indexed, indexed_route_universe};
use super::execution::{SettlerUnavailable, verify_execution_adapter_at};
use super::factories::discover_by_factories;
use super::indexed_validation::{
    finish_indexed_validation, indexed_probe_spacing, indexed_query_pairs_of,
    plan_indexed_validation,
};
use super::lens_parse::parse_indexed_lens;
use super::settings::{TOPO_TTL, bitmap_words};
use crate::abi::IUniV3Factory;
use crate::catalog::{CatalogVenue, IndexedEvmDiscovery};
use crate::chain::ChainProfile;
use crate::counterfactual::CoverageCache;
use crate::indexer::IndexerClient;
use crate::pools::{V2Pool, V3Pool};
use crate::rpc::{CanonicalBlock, Rpc, sanitized_error};
use crate::topology::{
    AddressPoolTopology, CatalogFences, PoolTopology as IndexedPoolTopology,
    Protocol as IndexedProtocol, Topology as IndexedTopology,
};
use crate::universe::RouteUniverse;
use alloy::eips::BlockId;
use alloy_primitives::Address;
use alloy_primitives::aliases::U24;
use alloy_sol_types::SolCall;
use anyhow::ensure;
use sextant_amm::snapshot::ScreeningPools;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// What optional graph expansion may add to a snapshot pull.
///
/// A snapshot pull is FOREGROUND work: cold and stale quotes await the shared
/// pull future, so anything slow inside it is latency a caller pays. The
/// indexer client already draws this line for `connector_selection`, whose own
/// 2 s budget exists "so optional graph expansion cannot consume the quote
/// budget" — screening is the same kind of work and gets the same treatment.
/// Without it screening would inherit the client's 10 s default and could hold
/// a quote for the difference.
///
/// The budget covers a whole best-effort attempt end to end, not a single
/// call, because it is the total added latency that matters. Exceeding it
/// yields the same empty result as any other failure.
const SCREENING_BUDGET: Duration = Duration::from_secs(2);

/// Identity-proved pool identities for the screened connectors, or nothing.
///
/// Best effort by construction. Screening is measurement, and a measurement
/// that can fail or stall a quote is a liability, so every error path here
/// returns an empty set inside `SCREENING_BUDGET`: the quote then reports
/// `screened_connectors=0`, which reads as "the coverage question went
/// unasked" rather than as a broken quote. The proof itself is not relaxed —
/// these addresses go through the same factory re-derivation at the same
/// canonical block as any routable pool, because a bound computed over
/// unproven state would be a bound over fiction.
async fn screening_identities(
    profile: &ChainProfile,
    discovery: &IndexedEvmDiscovery,
    rpc: &Rpc,
    indexer: &IndexerClient,
    universe: &RouteUniverse,
    canonical: CanonicalBlock,
    pin_block: Option<u64>,
) -> (Vec<V3Pool>, Vec<V2Pool>) {
    let screening_pairs = universe.screening_pairs();
    if screening_pairs.is_empty() {
        return (Vec::new(), Vec::new());
    }
    let protocols = discovery.quote_protocols();
    let attempt = async {
        let pairs = indexed_query_pairs_of(profile, screening_pairs, &protocols)?;
        let topology = indexer.topology(&pairs, &protocols).await?;
        let plan =
            plan_indexed_validation(discovery, &topology, canonical.number, pin_block.is_some())?;
        let results = rpc
            .multicall(plan.calls.clone(), BlockId::hash_canonical(canonical.hash))
            .await?;
        finish_indexed_validation(profile, plan, &results)
    };
    match tokio::time::timeout(SCREENING_BUDGET, attempt).await {
        Ok(Ok((v3, v2))) => (v3, v2),
        Ok(Err(error)) => {
            tracing::info!(
                "screening identities unavailable: {}",
                sanitized_error(&error)
            );
            (Vec::new(), Vec::new())
        }
        Err(_) => {
            tracing::info!("screening identities unavailable: budget exceeded");
            (Vec::new(), Vec::new())
        }
    }
}

/// Who names a pair's candidate pools for `snapshot_at_observed_indexed`: the
/// venue table's `CandidateSource`, with the indexer client it needs.
#[derive(Clone, Copy)]
pub(super) enum PoolNamer<'a> {
    Indexer(&'a IndexerClient),
    Factories,
}

/// Where `snapshot_at_observed_indexed` finds a pair's listed skeletons: from
/// `a` to `b` beside `statics`, through the connectors a pool list kept outside
/// state (the resident's) has pools for.
pub trait ListedPaths: Send + Sync {
    fn listed_paths(&self, statics: &[Address], a: Address, b: Address) -> Vec<Vec<Address>>;
}

#[allow(clippy::too_many_arguments)] // the pair, its pin, and what the engine already knows
pub(super) async fn snapshot_at_observed_indexed(
    profile: &ChainProfile,
    discovery: &IndexedEvmDiscovery,
    rpc: &Rpc,
    namer: PoolNamer<'_>,
    token_a: Address,
    token_b: Address,
    pin_block: Option<u64>,
    listed: Option<&dyn ListedPaths>,
    coverage: Option<&CoverageCache>,
) -> anyhow::Result<ObservedSnapshot> {
    let (a, b) = (profile.erc20_of(token_a), profile.erc20_of(token_b));
    ensure!(a != b, "identical tokens");
    let listed = listed
        .map(|listed| listed.listed_paths(profile.connectors, a, b))
        .unwrap_or_default();
    let selected = pin_block.map_or_else(BlockId::latest, BlockId::number);
    // Freshness starts at the earliest instant this block could have been
    // observed, which is before the call that resolves it.
    let observed_at = Instant::now();
    let canonical = rpc.canonical_block(selected).await?;
    let block_id = BlockId::hash_canonical(canonical.hash);
    let cache_ok = pin_block.is_none() && *TOPO_TTL > 0;
    let key = listed_topology_key(topology_key(profile, a, b), &listed);
    let cached = if cache_ok { topology_cached(key) } else { None };
    let (v3pools, v2pools, screen_v3, screen_v2, universe, topology_fences) = match cached {
        Some(topology) => (
            topology.v3,
            topology.v2,
            topology.screen_v3,
            topology.screen_v2,
            topology.universe,
            topology.topology_fences,
        ),
        None => {
            let (v3, v2, screen_v3, screen_v2, universe, topology_fences) = match namer {
                PoolNamer::Indexer(indexer) => {
                    let proposed = indexed_route_universe(
                        profile, discovery, indexer, a, b, pin_block, &listed, coverage,
                    )
                    .await?;
                    let (v3, v2, universe, topology_fences) = discover_indexed(
                        profile, discovery, rpc, indexer, &proposed, canonical, pin_block,
                    )
                    .await?;
                    let (screen_v3, screen_v2) = screening_identities(
                        profile, discovery, rpc, indexer, &universe, canonical, pin_block,
                    )
                    .await;
                    (
                        v3,
                        v2,
                        screen_v3,
                        screen_v2,
                        universe,
                        Some(topology_fences),
                    )
                }
                PoolNamer::Factories => {
                    // The profile's connectors and the listed skeletons only:
                    // ranking others needs a catalog (`validate_settings`).
                    // There is none to fence, and nothing to screen.
                    let universe =
                        RouteUniverse::profile_only(profile, a, b)?.with_listed(&listed)?;
                    let (v3, v2) =
                        discover_by_factories(profile, discovery, rpc, &universe, canonical)
                            .await?;
                    (v3, v2, Vec::new(), Vec::new(), universe, None)
                }
            };
            if cache_ok {
                let status = if universe.fallback_kind().is_some() {
                    TopologyStatus::AdjacencyFallback
                } else {
                    TopologyStatus::Complete
                };
                cache_topology(
                    key,
                    Topology {
                        at: Instant::now(),
                        status,
                        universe: universe.clone(),
                        topology_fences,
                        v3: v3.clone(),
                        v2: v2.clone(),
                        screen_v3: screen_v3.clone(),
                        screen_v2: screen_v2.clone(),
                    },
                );
            }
            (v3, v2, screen_v3, screen_v2, universe, topology_fences)
        }
    };
    let words = bitmap_words()?;
    // Both reads are pinned to the same canonical hash, so the execution
    // identity resolves alongside pool state instead of a round trip after it.
    // A registry with no current Settler (never deployed, or paused through
    // its module) leaves this snapshot quote-only rather than failing it.
    let execution = async {
        if !profile.execution_enabled() {
            return Ok(None);
        }
        match verify_execution_adapter_at(profile, rpc, block_id).await {
            Ok(identity) => Ok(Some(identity)),
            Err(error) if error.downcast_ref::<SettlerUnavailable>().is_some() => {
                tracing::info!("snapshot: no current Settler; quotes stay indicative");
                Ok(None)
            }
            Err(error) => Err(error),
        }
    };
    // Screened state rides the same canonical block as everything else, in its
    // own Lens read so a failure there cannot cost the quote its snapshot.
    //
    // Bounded for the same reason the identity fetch is: `join!` below is a
    // barrier, not a race, so an unbounded read here would hold the snapshot
    // for as long as it hung even though the routable read had already landed.
    let screening_state = async {
        if screen_v3.is_empty() && screen_v2.is_empty() {
            return ScreeningPools::default();
        }
        let read = async {
            crate::lens::peek_pinned(rpc, words, &screen_v3, &screen_v2, canonical, observed_at)
                .await
                .and_then(|ret| parse_indexed_lens(&screen_v3, &screen_v2, &ret))
        };
        match tokio::time::timeout(SCREENING_BUDGET, read).await {
            Ok(Ok(parsed)) => ScreeningPools {
                v3: parsed.snapshot.v3,
                v2: parsed.snapshot.v2,
            },
            Ok(Err(error)) => {
                tracing::info!("screening state unavailable: {}", sanitized_error(&error));
                ScreeningPools::default()
            }
            Err(_) => {
                tracing::info!("screening state unavailable: budget exceeded");
                ScreeningPools::default()
            }
        }
    };
    let (ret, execution, screening) = tokio::join!(
        crate::lens::peek_pinned(rpc, words, &v3pools, &v2pools, canonical, observed_at),
        execution,
        screening_state,
    );
    let (ret, execution) = (ret?, execution?);
    ensure_integrity!(
        ret.block_number == canonical.number && ret.block_id == block_id,
        "indexed EVM Lens did not preserve the canonical state block"
    );
    let mut parsed = parse_indexed_lens(&v3pools, &v2pools, &ret)?;
    ensure_integrity!(
        parsed.sheriff_plugins.is_empty(),
        "indexed snapshot unexpectedly contains Algebra state"
    );
    match execution {
        Some(identity) => parsed.snapshot.settler = Some(identity.settler),
        None => ensure_integrity!(
            parsed.snapshot.settler.is_none(),
            "quote-only indexed snapshot unexpectedly contains execution identity"
        ),
    }
    Ok(ObservedSnapshot {
        screening,
        snapshot: parsed.snapshot,
        universe,
        topology_fences,
        block_id,
        block_timestamp: ret.block_timestamp,
        observed_at: ret.observed_at,
    })
}

/// Pools named by an outside list (the resident's), proved one by one with the same
/// factory and Settler identity rules as an indexer candidate. One that fails
/// is returned with the reason instead of failing the others: a list is a
/// suggestion, and one wrong row must not cost every listed pool its quotes.
/// A V3 row's tick spacing is the factory's for its fee.
pub async fn prove_listed_pools(
    profile: &ChainProfile,
    discovery: &IndexedEvmDiscovery,
    rpc: &Rpc,
    pools: &[AddressPoolTopology],
    canonical: CanonicalBlock,
) -> anyhow::Result<(Vec<V3Pool>, Vec<V2Pool>, Vec<(Address, String)>)> {
    let block = BlockId::hash_canonical(canonical.hash);
    let mut fees: Vec<(IndexedProtocol, u32)> = pools
        .iter()
        .filter(|pool| {
            matches!(
                discovery.venue(pool.protocol),
                Some(CatalogVenue::V3 { .. })
            )
        })
        .map(|pool| (pool.protocol, pool.fee_ppm))
        .collect();
    fees.sort_unstable_by_key(|(protocol, fee)| (protocol.rank(), *fee));
    fees.dedup();
    let mut calls = Vec::with_capacity(fees.len());
    for &(protocol, fee) in &fees {
        let CatalogVenue::V3 { factory, .. } = discovery.require_venue(protocol)? else {
            anyhow::bail!("{} is not configured as V3", protocol.as_str());
        };
        calls.push((
            factory,
            IUniV3Factory::feeAmountTickSpacingCall {
                fee: U24::from(fee),
            }
            .abi_encode(),
        ));
    }
    let results = rpc.multicall(calls, block).await?;
    ensure!(
        results.len() == fees.len(),
        "fee tier spacing response length mismatch"
    );
    let mut spacing_of = HashMap::new();
    for (index, key) in fees.iter().enumerate() {
        if let Ok(spacing) = indexed_probe_spacing(&results, index)
            && spacing > 0
        {
            spacing_of.insert(*key, spacing);
        }
    }

    let mut rejected = Vec::new();
    let mut plans = Vec::new();
    let mut calls = Vec::new();
    for pool in pools {
        if pool.token0 >= pool.token1 {
            rejected.push((
                pool.address,
                "tokens are not in token0 < token1 order".to_string(),
            ));
            continue;
        }
        let mut pool = pool.clone();
        // Every V3 venue of the table, whatever its name: the factory's
        // spacing for the row's fee.
        if matches!(
            discovery.venue(pool.protocol),
            Some(CatalogVenue::V3 { .. })
        ) {
            match spacing_of.get(&(pool.protocol, pool.fee_ppm)) {
                Some(&spacing) => pool.tick_spacing = Some(spacing),
                None => {
                    rejected.push((
                        pool.address,
                        format!("fee {} is not a factory tier", pool.fee_ppm),
                    ));
                    continue;
                }
            }
        }
        let address = pool.address;
        let topology = IndexedTopology {
            pairs: Vec::new(),
            protocols: Vec::new(),
            fences: CatalogFences {
                v23: crate::topology::V23Fence {
                    seq: 0,
                    generation: 0,
                },
                v4: None,
            },
            pools: vec![IndexedPoolTopology::Address(pool)],
        };
        match plan_indexed_validation(discovery, &topology, canonical.number, false) {
            Ok(plan) => {
                let start = calls.len();
                calls.extend(plan.calls.iter().cloned());
                plans.push((address, plan, start..calls.len()));
            }
            Err(error) => rejected.push((address, format!("{error:#}"))),
        }
    }
    let results = rpc.multicall(calls, block).await?;
    let mut v3 = Vec::new();
    let mut v2 = Vec::new();
    for (address, plan, range) in plans {
        let Some(slice) = results.get(range) else {
            anyhow::bail!("listed pool validation returned the wrong result count");
        };
        match finish_indexed_validation(profile, plan, slice) {
            Ok((proved_v3, proved_v2)) => {
                v3.extend(proved_v3);
                v2.extend(proved_v2);
            }
            Err(error) => rejected.push((address, sanitized_error(&error))),
        }
    }
    Ok((v3, v2, rejected))
}
