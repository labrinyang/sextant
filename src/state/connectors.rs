use super::*;

async fn prepare_indexed_topology(
    profile: &ChainProfile,
    discovery: &IndexedEvmDiscovery,
    indexer: &IndexerClient,
    proposed: &RouteUniverse,
) -> anyhow::Result<(IndexedTopology, RouteUniverse)> {
    let quote_protocols = discovery.quote_protocols();
    let pairs = indexed_topology_query_pairs(profile, proposed, &quote_protocols)?;
    let mut topology = indexer
        .topology(&pairs, &quote_protocols)
        .await
        .context("pool indexer topology is unavailable")?;
    let universe = admit_indexed_topology_work(profile, proposed, &mut topology)?;
    Ok((topology, universe))
}

async fn prove_indexed_topology(
    profile: &ChainProfile,
    discovery: &IndexedEvmDiscovery,
    rpc: &Rpc,
    topology: IndexedTopology,
    canonical: CanonicalBlock,
    pin_block: Option<u64>,
) -> anyhow::Result<(Vec<V3Pool>, Vec<V2Pool>, CatalogFences)> {
    let pinned_replay = pin_block.is_some();
    let topology_fences = topology.fences;
    let plan = plan_indexed_validation(discovery, &topology, canonical.number, pinned_replay)?;
    let block_id = BlockId::hash_canonical(canonical.hash);
    let results = rpc.multicall(plan.calls.clone(), block_id).await?;
    let (v3, v2) = finish_indexed_validation(profile, plan, &results)?;
    Ok((v3, v2, topology_fences))
}

fn adjacency_fallback_kind(error: &crate::topology::IndexerError) -> FallbackKind {
    match error.kind() {
        crate::topology::IndexerErrorKind::Transport
        | crate::topology::IndexerErrorKind::HttpStatus => FallbackKind::Transport,
        crate::topology::IndexerErrorKind::Conflict => FallbackKind::Conflict,
        crate::topology::IndexerErrorKind::Capacity
        | crate::topology::IndexerErrorKind::BodyTooLarge => FallbackKind::Capacity,
        crate::topology::IndexerErrorKind::InvalidConfiguration
        | crate::topology::IndexerErrorKind::InvalidRequest
        | crate::topology::IndexerErrorKind::InvalidResponse => FallbackKind::InvalidResponse,
    }
}

fn optional_augmented_topology_failure(error: &anyhow::Error) -> Option<FallbackKind> {
    if error.downcast_ref::<RpcUnavailable>().is_some() {
        return Some(FallbackKind::Transport);
    }
    match error
        .downcast_ref::<crate::topology::IndexerError>()?
        .kind()
    {
        crate::topology::IndexerErrorKind::Transport => Some(FallbackKind::Transport),
        crate::topology::IndexerErrorKind::Capacity
        | crate::topology::IndexerErrorKind::BodyTooLarge => Some(FallbackKind::Capacity),
        crate::topology::IndexerErrorKind::InvalidConfiguration
        | crate::topology::IndexerErrorKind::InvalidRequest
        | crate::topology::IndexerErrorKind::Conflict
        | crate::topology::IndexerErrorKind::HttpStatus
        | crate::topology::IndexerErrorKind::InvalidResponse => None,
    }
}

fn is_augmented_universe(universe: &RouteUniverse) -> bool {
    matches!(
        universe.source(),
        RouteUniverseSource::AdjacencyComplete { connectors, .. } if !connectors.is_empty()
    )
}

pub(super) fn augmented_availability_fallback(
    profile: &ChainProfile,
    universe: &RouteUniverse,
    error: &anyhow::Error,
) -> anyhow::Result<Option<RouteUniverse>> {
    if !is_augmented_universe(universe) {
        return Ok(None);
    }
    let Some(reason) = optional_augmented_topology_failure(error) else {
        return Ok(None);
    };
    let (token_in, token_out) = universe.endpoints();
    RouteUniverse::adjacency_fallback(profile, token_in, token_out, reason).map(Some)
}

/// `listed` are skeletons from the resident list, through the resident's
/// connectors beyond the profile's, where the list has their pools. They join
/// the profile-only universe; the adjacency modes never see them.
pub(super) async fn indexed_route_universe(
    profile: &ChainProfile,
    discovery: &IndexedEvmDiscovery,
    indexer: &IndexerClient,
    token_in: Address,
    token_out: Address,
    pin_block: Option<u64>,
    listed: &[Vec<Address>],
) -> anyhow::Result<RouteUniverse> {
    let mode = *DYNAMIC_CONNECTORS;
    if pin_block.is_some() || mode == DynamicConnectorMode::ProfileOnly {
        return RouteUniverse::profile_only(profile, token_in, token_out)?.with_listed(listed);
    }
    let protocols = discovery.quote_protocols();
    let selection = indexer
        .connector_selection(token_in, token_out, &protocols)
        .await
        // With screening off the ranking is dropped entirely, so no screening
        // pair is derived in ANY mode and every universe fingerprint is
        // exactly what it was before screening existed.
        //
        // Truncating to `connectors` instead would be wrong for shadow mode,
        // whose whole premise is that admitted connectors are NOT routable:
        // their pairs would read as uncovered and get screened, buying an
        // indexer request, a Multicall3 round and a Lens read that nobody
        // asked for.
        .map(|mut selection| {
            if !*CONNECTOR_SCREENING {
                selection.screened.clear();
            }
            retain_allowlisted(profile, &mut selection);
            selection
        });
    if mode == DynamicConnectorMode::Shadow {
        return match selection {
            Ok(selection) => {
                RouteUniverse::profile_only_shadow_complete(profile, token_in, token_out, selection)
                    .or_else(|_| {
                        RouteUniverse::profile_only_shadow_fallback(
                            profile,
                            token_in,
                            token_out,
                            FallbackKind::InvalidResponse,
                        )
                    })
            }
            Err(error) => RouteUniverse::profile_only_shadow_fallback(
                profile,
                token_in,
                token_out,
                adjacency_fallback_kind(&error),
            ),
        };
    }
    match selection {
        Ok(selection) => {
            let selection = admit_by_certified_value(profile, token_in, token_out, selection);
            RouteUniverse::adjacency_complete(profile, token_in, token_out, selection).or_else(
                |error| {
                    // `invalid_response` names the indexer, and this arm reaches
                    // it after the indexer answered correctly -- the selection
                    // was rejected here. Print the reason or the next reader
                    // debugs the wrong process, as one did.
                    tracing::info!("route universe rejected the selection: {error:#}");
                    RouteUniverse::adjacency_fallback(
                        profile,
                        token_in,
                        token_out,
                        FallbackKind::InvalidResponse,
                    )
                },
            )
        }
        Err(error) => RouteUniverse::adjacency_fallback(
            profile,
            token_in,
            token_out,
            adjacency_fallback_kind(&error),
        ),
    }
}

/// The boundary that no selector can bypass: nothing this chain refuses may
/// reach a route universe, routable or screened.
///
/// The rule is enforced where the shortlist is built, because that is where
/// the budget is spent (`indexer::permitted_connector`). This is the belt: it
/// covers `ConnectorSelection` as a type rather than the two functions that
/// build one today, so a third selector cannot quietly arrive without it.
/// Screening is covered as well as routing — a token left in `screened` gets
/// priced, lands in a coverage verdict, and becomes something admission can
/// promote later.
///
/// The ranking is trusted for ORDER and never for eligibility. It sorts by
/// measured bottleneck depth, and depth is rentable — sampled against the live
/// BSC ranking on 2026-08-06, the candidates it offered included one carrying
/// $206k of measured depth that no registry lists at all
/// (`chain::BSC_DYNAMIC_CONNECTOR_ALLOWLIST`).
///
/// A drop here means a selector let a refused token through and its slot went
/// with it, so the message names that rather than the allowlist working. In
/// normal operation this is silent.
///
/// `eligible_count` keeps the ranking's own number. It reports what the
/// indexer found, and rewriting it here would hide the difference between a
/// thin pair and a filtered one; the admitted lengths say the rest.
pub(super) fn retain_allowlisted(profile: &ChainProfile, selection: &mut ConnectorSelection) {
    let permitted = |token: &Address| profile.dynamic_connector_allowlist.contains(token);
    let before = selection.connectors.len() + selection.screened.len();
    selection.connectors.retain(permitted);
    selection.screened.retain(permitted);
    let dropped = before - selection.connectors.len() - selection.screened.len();
    if dropped > 0 {
        tracing::info!(
            "connector selector returned {dropped} of {before} refused candidates on chain {} \
             -- the shortlist was built without the allowlist and lost those slots",
            profile.chain_id
        );
    }
}

/// Give a slot held by a proven-idle connector to a candidate that beats the
/// certified cost of taking it (docs §22).
///
/// A no-op without evidence, which is the common case: nothing has measured
/// this pair until connector screening has run for it inside the coverage
/// lease, and with no proven-idle incumbent there is no slot this rule is
/// allowed to touch.
///
/// `token_in` and `token_out` arrive already canonicalized by the engine's
/// `canon`, so they name the pair rather than the traffic's direction. Verdicts
/// are filed under the direction quoted, which is why the lookup reads both.
fn admit_by_certified_value(
    profile: &ChainProfile,
    token_in: Address,
    token_out: Address,
    mut selection: ConnectorSelection,
) -> ConnectorSelection {
    if !*CONNECTOR_ADMISSION || selection.screened.is_empty() {
        return selection;
    }
    let evidence =
        crate::counterfactual::certified_admission(profile.chain_id, token_in, token_out);
    if evidence.idle.is_empty() {
        return selection;
    }
    // Soundness comes from the certified bound; the configured floor only
    // suppresses churn. §21 measured gaps as low as 0.0043 bp, and a candidate
    // clearing that by a hair would be a provably profitable swap that rewrites
    // the route for nothing. The floor is handed over rather than folded into
    // the bound, because the rule multiplies the bound by the live band count
    // and a churn policy has no business scaling with how many sizes are in
    // retention (§33).
    let admitted = selection.connectors.len();
    selection.screened = crate::counterfactual::admit_by_certified_value(
        &selection.screened,
        admitted,
        &evidence,
        *CONNECTOR_MIN_BPS_E4,
    );
    selection.connectors = selection
        .screened
        .iter()
        .take(admitted)
        .copied()
        .collect::<Vec<_>>();
    selection
}

fn pool_counts(
    pairs: impl IntoIterator<Item = (Address, Address)>,
) -> HashMap<(Address, Address), usize> {
    let mut counts = HashMap::new();
    for (token0, token1) in pairs {
        *counts.entry(sorted_pair(token0, token1)).or_default() += 1;
    }
    counts
}

#[cfg(test)]
fn indexed_pool_counts(v3: &[V3Pool], v2: &[V2Pool]) -> HashMap<(Address, Address), usize> {
    pool_counts(
        v3.iter()
            .map(|pool| (pool.token0, pool.token1))
            .chain(v2.iter().map(|pool| (pool.token0, pool.token1))),
    )
}

pub(super) fn indexed_topology_pool_counts(
    profile: &ChainProfile,
    topology: &IndexedTopology,
) -> HashMap<(Address, Address), usize> {
    pool_counts(topology.pools.iter().filter_map(|pool| match pool {
        IndexedPoolTopology::Address(pool) => Some((pool.token0, pool.token1)),
        IndexedPoolTopology::Univ4(pool) => indexed_v4_quote_candidate(pool).then(|| {
            v4_tokens_from_currencies_for(profile.wrapped_native, pool.currency0, pool.currency1)
        }),
    }))
}

fn baseline_candidate_work(
    universe: &RouteUniverse,
    counts: &HashMap<(Address, Address), usize>,
) -> Option<usize> {
    let mut total = 0usize;
    for path in universe.token_paths().iter().filter(|path| path.len() <= 3) {
        let mut work = 1usize;
        for edge in path.windows(2) {
            work = work.checked_mul(
                counts
                    .get(&sorted_pair(edge[0], edge[1]))
                    .copied()
                    .unwrap_or(0),
            )?;
        }
        total = total.checked_add(work)?;
    }
    Some(total)
}

#[cfg(test)]
fn retain_universe_pools(universe: &RouteUniverse, v3: &mut Vec<V3Pool>, v2: &mut Vec<V2Pool>) {
    let pairs: HashSet<(Address, Address)> = universe
        .pairs()
        .iter()
        .map(|&(a, b)| sorted_pair(a, b))
        .collect();
    v3.retain(|pool| pairs.contains(&sorted_pair(pool.token0, pool.token1)));
    v2.retain(|pool| pairs.contains(&sorted_pair(pool.token0, pool.token1)));
}

fn admit_dynamic_work_for_counts(
    profile: &ChainProfile,
    proposed: &RouteUniverse,
    counts: &HashMap<(Address, Address), usize>,
) -> anyhow::Result<RouteUniverse> {
    let RouteUniverseSource::AdjacencyComplete {
        fences,
        protocols,
        connectors,
        eligible_count,
        shortlist_truncated,
        selector,
        ..
    } = proposed.source().clone()
    else {
        return Ok(proposed.clone());
    };
    let (token_in, token_out) = proposed.endpoints();
    let static_universe = RouteUniverse::profile_only(profile, token_in, token_out)?;
    let mut work = baseline_candidate_work(&static_universe, counts)
        .context("baseline route candidate count overflow")?;
    ensure!(
        work <= BASELINE_PATH_CANDIDATE_CAP,
        "baseline route candidate limit exceeded: {work} > {BASELINE_PATH_CANDIDATE_CAP}"
    );

    let work_before = work;
    let connector_count = connectors.len();
    let mut decisions: Vec<String> = Vec::with_capacity(connector_count);
    let mut admitted = Vec::new();
    let mut truncated = shortlist_truncated;
    for connector in connectors {
        let left = counts
            .get(&sorted_pair(token_in, connector))
            .copied()
            .unwrap_or(0);
        let right = counts
            .get(&sorted_pair(connector, token_out))
            .copied()
            .unwrap_or(0);
        let mut note = |verdict: &str| {
            decisions.push(format!("{connector:#x}={left}x{right}:{verdict}"));
        };
        let Some(dynamic_work) = left.checked_mul(right) else {
            note("overflow");
            truncated = true;
            continue;
        };
        if dynamic_work == 0 {
            // The selector offered this connector and the topology came back
            // with no pool on one of its legs, so it routes nothing and is
            // dropped like the three paths around it. It reports the same way
            // too: `shortlist_truncated` says a candidate the selector counted
            // never became routable, and this is a candidate the selector
            // counted. The ranked selector covers V2/V3 only, so a connector
            // reachable through V4 alone arrives here as a matter of course
            // rather than as an edge case.
            note("no-pool");
            truncated = true;
            continue;
        }
        let Some(next_work) = work.checked_add(dynamic_work) else {
            note("overflow");
            truncated = true;
            continue;
        };
        if next_work > BASELINE_PATH_CANDIDATE_CAP {
            note("over-cap");
            truncated = true;
            continue;
        }
        work = next_work;
        note("admitted");
        admitted.push(connector);
    }

    // Say which connectors the work gate refused and what it refused them for.
    // The selector's count and the served count disagree routinely — WBNB→USDC
    // offers four and serves one — and until this line the difference was
    // visible as a number with no cause attached. Silent in the common case,
    // because it only prints when the gate actually dropped something.
    if admitted.len() < connector_count {
        tracing::info!(
            "connector work gate: {}/{} admitted, baseline {work_before}, cap \
             {BASELINE_PATH_CANDIDATE_CAP}, {}",
            admitted.len(),
            connector_count,
            decisions.join(" ")
        );
    }

    let universe = RouteUniverse::adjacency_complete(
        profile,
        token_in,
        token_out,
        ConnectorSelection {
            fences,
            protocols,
            connectors: admitted,
            // The work gate decides what is routable. What was priced is a
            // property of the proposal and survives it unchanged, so a
            // connector dropped here keeps being measured.
            screened: proposed.screened().to_vec(),
            eligible_count,
            shortlist_truncated: truncated,
            // The gate narrows what is routable; it never re-answers which
            // selector found the candidates.
            selector,
        },
    )?;
    Ok(universe)
}

#[cfg(test)]
pub(super) fn admit_dynamic_work(
    profile: &ChainProfile,
    proposed: &RouteUniverse,
    v3: &mut Vec<V3Pool>,
    v2: &mut Vec<V2Pool>,
) -> anyhow::Result<RouteUniverse> {
    let universe = admit_dynamic_work_for_counts(profile, proposed, &indexed_pool_counts(v3, v2))?;
    retain_universe_pools(&universe, v3, v2);
    Ok(universe)
}

pub(super) fn admit_indexed_topology_work(
    profile: &ChainProfile,
    proposed: &RouteUniverse,
    topology: &mut IndexedTopology,
) -> anyhow::Result<RouteUniverse> {
    let universe = admit_dynamic_work_for_counts(
        profile,
        proposed,
        &indexed_topology_pool_counts(profile, topology),
    )?;
    let admitted_pairs: HashSet<(Address, Address)> = universe
        .pairs()
        .iter()
        .map(|&(a, b)| sorted_pair(a, b))
        .collect();
    topology.pools.retain(|pool| {
        let (token0, token1) = match pool {
            IndexedPoolTopology::Address(pool) => (pool.token0, pool.token1),
            IndexedPoolTopology::Univ4(pool) => v4_tokens_from_currencies_for(
                profile.wrapped_native,
                pool.currency0,
                pool.currency1,
            ),
        };
        admitted_pairs.contains(&sorted_pair(token0, token1))
    });
    topology.pairs = indexed_route_pairs(&universe)?;
    Ok(universe)
}

async fn prove_prepared_indexed_topology(
    profile: &ChainProfile,
    discovery: &IndexedEvmDiscovery,
    rpc: &Rpc,
    prepared: (IndexedTopology, RouteUniverse),
    canonical: CanonicalBlock,
    pin_block: Option<u64>,
) -> anyhow::Result<(Vec<V3Pool>, Vec<V2Pool>, RouteUniverse, CatalogFences)> {
    let (topology, universe) = prepared;
    let (v3, v2, fences) =
        prove_indexed_topology(profile, discovery, rpc, topology, canonical, pin_block).await?;
    Ok((v3, v2, universe, fences))
}

async fn discover_indexed_fallback(
    profile: &ChainProfile,
    discovery: &IndexedEvmDiscovery,
    rpc: &Rpc,
    indexer: &IndexerClient,
    fallback: RouteUniverse,
    canonical: CanonicalBlock,
    pin_block: Option<u64>,
) -> anyhow::Result<(Vec<V3Pool>, Vec<V2Pool>, RouteUniverse, CatalogFences)> {
    let prepared = prepare_indexed_topology(profile, discovery, indexer, &fallback).await?;
    prove_prepared_indexed_topology(profile, discovery, rpc, prepared, canonical, pin_block).await
}

pub(super) async fn discover_indexed(
    profile: &ChainProfile,
    discovery: &IndexedEvmDiscovery,
    rpc: &Rpc,
    indexer: &IndexerClient,
    proposed: &RouteUniverse,
    canonical: CanonicalBlock,
    pin_block: Option<u64>,
) -> anyhow::Result<(Vec<V3Pool>, Vec<V2Pool>, RouteUniverse, CatalogFences)> {
    let prepared = match prepare_indexed_topology(profile, discovery, indexer, proposed).await {
        Ok(prepared) => prepared,
        Err(error) => {
            let Some(fallback) = augmented_availability_fallback(profile, proposed, &error)? else {
                return Err(error);
            };
            return discover_indexed_fallback(
                profile, discovery, rpc, indexer, fallback, canonical, pin_block,
            )
            .await;
        }
    };
    let admitted = prepared.1.clone();
    match prove_prepared_indexed_topology(profile, discovery, rpc, prepared, canonical, pin_block)
        .await
    {
        Ok(discovered) => Ok(discovered),
        Err(error) => {
            let Some(fallback) = augmented_availability_fallback(profile, &admitted, &error)?
            else {
                return Err(error);
            };
            discover_indexed_fallback(
                profile, discovery, rpc, indexer, fallback, canonical, pin_block,
            )
            .await
        }
    }
}
