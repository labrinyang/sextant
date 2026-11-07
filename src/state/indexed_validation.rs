use super::*;

#[derive(Clone, Debug)]
pub(super) enum IndexedTopologyProbe {
    V2 {
        pool: AddressPoolTopology,
        factory_result: usize,
    },
    V3 {
        pool: AddressPoolTopology,
        factory_result: usize,
        spacing_result: usize,
        verify_pool_spacing: bool,
    },
    V4 {
        pool: V4PoolTopology,
        pools_slot: u64,
    },
}

#[derive(Debug)]
pub(super) struct IndexedValidationPlan {
    pub(super) calls: Vec<(Address, Vec<u8>)>,
    pub(super) probes: Vec<IndexedTopologyProbe>,
}

pub(super) fn indexed_route_pairs(universe: &RouteUniverse) -> anyhow::Result<Vec<TokenPair>> {
    indexed_pairs_of(universe.pairs())
}

fn indexed_pairs_of(pairs: &[(Address, Address)]) -> anyhow::Result<Vec<TokenPair>> {
    pairs
        .iter()
        .copied()
        .map(|(x, y)| {
            let (token0, token1) = sorted_pair(x, y);
            TokenPair::new(token0, token1).map_err(anyhow::Error::from)
        })
        .collect()
}

/// V2/V3 use wrapped-native addresses, while a V4 native pool is keyed by
/// currency address(0). Ask the indexer for both identities on every route
/// edge touching wrapped native; later admission folds the native currency
/// back onto the route model's wrapped token.
pub(super) fn indexed_topology_query_pairs(
    profile: &ChainProfile,
    universe: &RouteUniverse,
    protocols: &[IndexedProtocol],
) -> anyhow::Result<Vec<TokenPair>> {
    indexed_query_pairs_of(profile, universe.pairs(), protocols)
}

pub(super) fn indexed_query_pairs_of(
    profile: &ChainProfile,
    route_pairs: &[(Address, Address)],
    protocols: &[IndexedProtocol],
) -> anyhow::Result<Vec<TokenPair>> {
    let mut pairs = indexed_pairs_of(route_pairs)?;
    if protocols.contains(&IndexedProtocol::UNIV4) {
        for &(token0, token1) in route_pairs {
            let other = if token0 == profile.wrapped_native {
                Some(token1)
            } else if token1 == profile.wrapped_native {
                Some(token0)
            } else {
                None
            };
            if let Some(other) = other.filter(|token| *token != Address::ZERO) {
                pairs.push(TokenPair::new(Address::ZERO, other).map_err(anyhow::Error::from)?);
            }
        }
        pairs.sort_unstable();
        pairs.dedup();
    }
    ensure!(
        pairs.len() <= crate::topology::MAX_PAIRS,
        "native V4 aliases need {} topology pairs but the indexer allows {}",
        pairs.len(),
        crate::topology::MAX_PAIRS
    );
    Ok(pairs)
}

pub(super) fn indexed_v4_quote_candidate(pool: &V4PoolTopology) -> bool {
    v4_hook_flags(pool.hooks) & V4_SWAP_HOOK_FLAGS == 0
        && pool
            .key_fee_ppm
            .is_none_or(|fee| fee == V4_DYNAMIC_FEE_FLAG || fee <= V4_MAX_FEE_PPM)
}

/// Build one immutable-identity verification round from the already strict
/// indexer response. The catalog is a candidate source only: every address is
/// re-proved through its official factory at the exact state block. Historical
/// replays may omit pools created later; a current-head response ahead of the
/// selected RPC block is an integrity failure instead of a silent omission.
pub(super) fn plan_indexed_validation(
    discovery: &IndexedEvmDiscovery,
    topology: &IndexedTopology,
    block_number: u64,
    pinned_replay: bool,
) -> anyhow::Result<IndexedValidationPlan> {
    let mut calls = Vec::new();
    let mut probes = Vec::new();
    for indexed in &topology.pools {
        let created_block = match indexed {
            IndexedPoolTopology::Address(pool) => pool.created_block,
            IndexedPoolTopology::Univ4(pool) => pool.created_block,
        };
        if created_block.is_some_and(|created| created > block_number) {
            if pinned_replay {
                continue;
            }
            return Err(UpstreamIntegrityError::new(
                "indexer catalog is ahead of the canonical RPC block",
            )
            .into());
        }
        match indexed {
            IndexedPoolTopology::Address(pool) => {
                let venue = discovery.require_venue(pool.protocol)?;
                match venue {
                    CatalogVenue::V2 { factory, .. } => {
                        let factory_result = calls.len();
                        calls.push((
                            factory,
                            IUniV2Factory::getPairCall {
                                a: pool.token0,
                                b: pool.token1,
                            }
                            .abi_encode(),
                        ));
                        probes.push(IndexedTopologyProbe::V2 {
                            pool: pool.clone(),
                            factory_result,
                        });
                    }
                    CatalogVenue::V3 {
                        factory,
                        verify_pool_spacing,
                        ..
                    } => {
                        let fee = U24::from(pool.fee_ppm);
                        let factory_result = calls.len();
                        calls.push((
                            factory,
                            IUniV3Factory::getPoolCall {
                                a: pool.token0,
                                b: pool.token1,
                                fee,
                            }
                            .abi_encode(),
                        ));
                        let spacing_result = calls.len();
                        calls.push((
                            factory,
                            IUniV3Factory::feeAmountTickSpacingCall { fee }.abi_encode(),
                        ));
                        probes.push(IndexedTopologyProbe::V3 {
                            pool: pool.clone(),
                            factory_result,
                            spacing_result,
                            verify_pool_spacing,
                        });
                    }
                    CatalogVenue::V4 { .. } => {
                        anyhow::bail!(
                            "address-keyed topology names {}, a V4 venue",
                            pool.protocol.as_str()
                        )
                    }
                }
            }
            IndexedPoolTopology::Univ4(pool) => {
                let CatalogVenue::V4 {
                    pool_manager,
                    pools_slot,
                    ..
                } = discovery.require_venue(IndexedProtocol::UNIV4)?
                else {
                    anyhow::bail!("Uniswap V4 is not configured as a V4 venue");
                };
                ensure_integrity!(
                    pool.pool_manager == pool_manager,
                    "indexed V4 PoolManager does not match the reviewed venue"
                );
                if !indexed_v4_quote_candidate(pool) {
                    continue;
                }
                if let Some(fee) = pool.key_fee_ppm {
                    ensure_integrity!(
                        v4_pool_id(
                            pool.currency0,
                            pool.currency1,
                            fee,
                            pool.tick_spacing,
                            pool.hooks,
                        ) == pool.pool_id,
                        "indexed V4 PoolKey does not reproduce its PoolId"
                    );
                }
                probes.push(IndexedTopologyProbe::V4 {
                    pool: pool.clone(),
                    pools_slot,
                });
            }
        }
    }
    Ok(IndexedValidationPlan { calls, probes })
}

fn indexed_probe_word(results: &[Option<Vec<u8>>], index: usize) -> anyhow::Result<&[u8]> {
    let result = results.get(index).ok_or_else(|| {
        UpstreamIntegrityError::new("indexed topology validation result is missing")
    })?;
    let result = result
        .as_deref()
        .ok_or_else(|| UpstreamIntegrityError::new("indexed topology validation probe reverted"))?;
    ensure_integrity!(
        result.len() == 32,
        "indexed topology validation returned a non-word result"
    );
    Ok(result)
}

pub(super) fn indexed_probe_address(
    results: &[Option<Vec<u8>>],
    index: usize,
) -> anyhow::Result<Address> {
    let word = indexed_probe_word(results, index)?;
    ensure_integrity!(
        word[..12].iter().all(|byte| *byte == 0),
        "indexed factory returned a non-canonical address word"
    );
    Ok(Address::from_slice(&word[12..]))
}

pub(super) fn indexed_probe_spacing(
    results: &[Option<Vec<u8>>],
    index: usize,
) -> anyhow::Result<i32> {
    let word = indexed_probe_word(results, index)?;
    let extension = if word[29] & 0x80 == 0 { 0x00 } else { 0xff };
    ensure_integrity!(
        word[..29].iter().all(|byte| *byte == extension),
        "indexed factory tick spacing is not canonical int24"
    );
    let spacing = IUniV3Factory::feeAmountTickSpacingCall::abi_decode_returns(word)
        .map_err(|_| UpstreamIntegrityError::new("decoding indexed factory tick spacing"))?;
    Ok(spacing.as_i32())
}

pub(super) fn finish_indexed_validation(
    profile: &ChainProfile,
    plan: IndexedValidationPlan,
    results: &[Option<Vec<u8>>],
) -> anyhow::Result<(Vec<V3Pool>, Vec<V2Pool>)> {
    ensure_integrity!(
        results.len() == plan.calls.len(),
        "indexed topology validation returned the wrong result count"
    );
    let mut v3 = Vec::new();
    let mut v2 = Vec::new();
    for probe in plan.probes {
        match probe {
            IndexedTopologyProbe::V2 {
                pool,
                factory_result,
            } => {
                ensure_integrity!(
                    indexed_probe_address(results, factory_result)? == pool.address,
                    "indexed V2 factory identity does not match the indexer candidate"
                );
                ensure_integrity!(
                    pool.fee_ppm % 100 == 0,
                    "indexed V2 fee cannot be represented in basis points"
                );
                // Probed as V2 because the venue table lists it as V2.
                let protocol = pool.protocol;
                v2.push(V2Pool {
                    protocol,
                    address: pool.address,
                    token0: pool.token0,
                    token1: pool.token1,
                    fee_bps: pool.fee_ppm / 100,
                });
            }
            IndexedTopologyProbe::V3 {
                pool,
                factory_result,
                spacing_result,
                verify_pool_spacing,
            } => {
                ensure_integrity!(
                    indexed_probe_address(results, factory_result)? == pool.address,
                    "indexed V3 factory identity does not match the indexer candidate"
                );
                let expected_spacing = pool.tick_spacing.ok_or_else(|| {
                    UpstreamIntegrityError::new("indexed V3 candidate is missing tick spacing")
                })?;
                ensure_integrity!(
                    indexed_probe_spacing(results, spacing_result)? == expected_spacing,
                    "indexed V3 factory tick spacing does not match the indexer candidate"
                );
                // Probed as V3 because the venue table lists it as V3.
                let (protocol, catalog_protocol) = (pool.protocol, pool.protocol);
                let execution = profile.indexed_v3_execution(catalog_protocol);
                ensure_integrity!(
                    !profile.execution_enabled() || execution.is_some(),
                    "{} has no reviewed Settler binding",
                    catalog_protocol.as_str()
                );
                let execution = execution.map(|execution| {
                    let derived = clone_pool_addr(
                        execution.deployer,
                        execution.init_hash,
                        pool.token0,
                        pool.token1,
                        pool.fee_ppm,
                    );
                    (execution, derived)
                });
                if let Some((_, derived)) = execution {
                    ensure_integrity!(
                        derived == pool.address,
                        "{} candidate does not match the Settler CREATE2 identity",
                        catalog_protocol.as_str()
                    );
                }
                v3.push(V3Pool {
                    protocol,
                    address: pool.address,
                    token0: pool.token0,
                    token1: pool.token1,
                    fee_ppm: pool.fee_ppm,
                    tick_spacing: expected_spacing,
                    verify_pool_spacing,
                    execution: execution.map(|(execution, _)| V3ExecutionMeta {
                        fork_id: execution.fork_id,
                        pool_id: pool.fee_ppm,
                    }),
                    v4: None,
                    algebra: None,
                });
            }
            IndexedTopologyProbe::V4 { pool, pools_slot } => {
                if profile.execution_enabled() {
                    ensure_integrity!(
                        profile
                            .settler
                            .and_then(|settler| settler.univ4_pool_manager)
                            == Some(pool.pool_manager),
                        "univ4 has no reviewed Settler PoolManager binding"
                    );
                }
                let (token0, token1) = v4_tokens_from_currencies_for(
                    profile.wrapped_native,
                    pool.currency0,
                    pool.currency1,
                );
                if token0 == token1 {
                    continue;
                }
                let fee_ppm = pool.key_fee_ppm.unwrap_or(V4_UNKNOWN_KEY_FEE_PPM);
                let meta = v4_meta_from_pool_id(
                    pool.pool_id,
                    pools_slot,
                    pool.currency0 == Address::ZERO,
                    pool.hooks,
                );
                v3.push(V3Pool {
                    protocol: V3Protocol::UNIV4,
                    address: pool.pool_manager,
                    token0,
                    token1,
                    fee_ppm,
                    tick_spacing: pool.tick_spacing,
                    verify_pool_spacing: false,
                    execution: None,
                    v4: Some(meta),
                    algebra: None,
                });
            }
        }
    }
    Ok((v3, v2))
}
