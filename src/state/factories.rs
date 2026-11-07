use super::*;

/// One factory question: a V2 venue's `getPair`, or a V3 venue's `getPool`
/// at one of its fee tiers, for one pair.
#[derive(Debug)]
pub(super) struct FactoryAsk {
    venue: CatalogVenue,
    pub(super) token0: Address,
    pub(super) token1: Address,
    /// Where the factory's answer lands.
    pub(super) call: usize,
    /// The V3 fee asked at, and where its tier's `feeAmountTickSpacing` lands.
    pub(super) tier: Option<(u32, usize)>,
}

/// One Multicall3 round in which the venues' factories name a universe's
/// pools (`CandidateSource::Factories`).
#[derive(Debug)]
pub(super) struct FactoryDiscoveryPlan {
    pub(super) calls: Vec<(Address, Vec<u8>)>,
    /// Each V3 tier asked at: its protocol, fee and spacing call.
    pub(super) tiers: Vec<(IndexedProtocol, u32, usize)>,
    pub(super) asks: Vec<FactoryAsk>,
}

/// Ask every quoted venue about every pair of the universe: `getPair` once
/// per V2 venue, `getPool` once per V3 venue and fee tier, and each tier's
/// `feeAmountTickSpacing` once.
pub(super) fn plan_factory_discovery(
    discovery: &IndexedEvmDiscovery,
    pairs: &[(Address, Address)],
) -> anyhow::Result<FactoryDiscoveryPlan> {
    ensure!(
        discovery.candidates == CandidateSource::Factories,
        "this venue table's pools are named by an indexer, not by their factories"
    );
    let venues: Vec<CatalogVenue> = discovery
        .venues
        .iter()
        .copied()
        .filter(|venue| venue.quote_enabled())
        .collect();
    let mut calls = Vec::new();
    let mut tiers = Vec::new();
    for venue in &venues {
        if let CatalogVenue::V3 {
            protocol,
            factory,
            fee_tiers,
            ..
        } = *venue
        {
            for &fee in fee_tiers {
                tiers.push((protocol, fee, calls.len()));
                calls.push((
                    factory,
                    IUniV3Factory::feeAmountTickSpacingCall {
                        fee: U24::from(fee),
                    }
                    .abi_encode(),
                ));
            }
        }
    }
    let mut asked = HashSet::new();
    let mut asks = Vec::new();
    for &(x, y) in pairs {
        let (token0, token1) = sorted_pair(x, y);
        ensure!(token0 != token1, "a route pair joins a token to itself");
        if !asked.insert((token0, token1)) {
            continue;
        }
        for venue in &venues {
            match *venue {
                CatalogVenue::V2 { factory, .. } => {
                    asks.push(FactoryAsk {
                        venue: *venue,
                        token0,
                        token1,
                        call: calls.len(),
                        tier: None,
                    });
                    calls.push((
                        factory,
                        IUniV2Factory::getPairCall {
                            a: token0,
                            b: token1,
                        }
                        .abi_encode(),
                    ));
                }
                CatalogVenue::V3 {
                    protocol,
                    factory,
                    fee_tiers,
                    ..
                } => {
                    for &fee in fee_tiers {
                        let spacing_call = tiers
                            .iter()
                            .find(|&&(tier_protocol, tier_fee, _)| {
                                tier_protocol == protocol && tier_fee == fee
                            })
                            .map(|&(_, _, call)| call)
                            .context("a fee tier was asked at without its spacing")?;
                        asks.push(FactoryAsk {
                            venue: *venue,
                            token0,
                            token1,
                            call: calls.len(),
                            tier: Some((fee, spacing_call)),
                        });
                        calls.push((
                            factory,
                            IUniV3Factory::getPoolCall {
                                a: token0,
                                b: token1,
                                fee: U24::from(fee),
                            }
                            .abi_encode(),
                        ));
                    }
                }
                CatalogVenue::V4 { .. } => {
                    anyhow::bail!("a V4 singleton's pools cannot be named by a factory")
                }
            }
        }
    }
    Ok(FactoryDiscoveryPlan { calls, tiers, asks })
}

/// The pools the factories named, proved exactly as an indexer candidate is
/// (`finish_indexed_validation`, Settler CREATE2 identity included) against
/// the same round's answers: a factory's answer is the identity proof, so no
/// second round re-asks it. A zero address is no pool. An answer that is not
/// one address word, which is what a factory with no code returns, fails the
/// round rather than reading as no pool, because an RPC on the wrong chain
/// answers exactly that way. Pools come out in the order an indexer lists
/// them: by pair, then protocol, then address.
pub(super) fn finish_factory_discovery(
    profile: &ChainProfile,
    plan: FactoryDiscoveryPlan,
    results: &[Option<Vec<u8>>],
) -> anyhow::Result<(Vec<V3Pool>, Vec<V2Pool>)> {
    ensure_integrity!(
        results.len() == plan.calls.len(),
        "factory discovery returned the wrong result count"
    );
    let mut named = Vec::new();
    for ask in plan.asks {
        let address = indexed_probe_address(results, ask.call)?;
        if address == Address::ZERO {
            continue;
        }
        let probe = match (ask.venue, ask.tier) {
            (
                CatalogVenue::V2 {
                    protocol, fee_ppm, ..
                },
                None,
            ) => IndexedTopologyProbe::V2 {
                pool: AddressPoolTopology {
                    protocol,
                    address,
                    token0: ask.token0,
                    token1: ask.token1,
                    fee_ppm,
                    tick_spacing: None,
                    created_block: None,
                },
                factory_result: ask.call,
            },
            (
                CatalogVenue::V3 {
                    protocol,
                    verify_pool_spacing,
                    ..
                },
                Some((fee, spacing_call)),
            ) => {
                let spacing = indexed_probe_spacing(results, spacing_call)?;
                ensure_integrity!(
                    spacing > 0,
                    "{} factory names a pool at fee {fee}, a tier it has not enabled",
                    protocol.as_str()
                );
                IndexedTopologyProbe::V3 {
                    pool: AddressPoolTopology {
                        protocol,
                        address,
                        token0: ask.token0,
                        token1: ask.token1,
                        fee_ppm: fee,
                        tick_spacing: Some(spacing),
                        created_block: None,
                    },
                    factory_result: ask.call,
                    spacing_result: spacing_call,
                    verify_pool_spacing,
                }
            }
            _ => anyhow::bail!("factory discovery asked a venue a question it cannot answer"),
        };
        named.push(probe);
    }
    named.sort_by_key(|probe| match probe {
        IndexedTopologyProbe::V2 { pool, .. } | IndexedTopologyProbe::V3 { pool, .. } => {
            (pool.token0, pool.token1, pool.protocol.rank(), pool.address)
        }
        IndexedTopologyProbe::V4 { pool, .. } => (
            pool.currency0,
            pool.currency1,
            IndexedProtocol::UNIV4.rank(),
            pool.pool_manager,
        ),
    });
    finish_indexed_validation(
        profile,
        IndexedValidationPlan {
            calls: plan.calls,
            probes: named,
        },
        results,
    )
}

/// The universe's pools as the venues' factories name them, at the quote's
/// canonical block, in one Multicall3 round.
pub(super) async fn discover_by_factories(
    profile: &ChainProfile,
    discovery: &IndexedEvmDiscovery,
    rpc: &Rpc,
    universe: &RouteUniverse,
    canonical: CanonicalBlock,
) -> anyhow::Result<(Vec<V3Pool>, Vec<V2Pool>)> {
    let plan = plan_factory_discovery(discovery, universe.pairs())?;
    let results = rpc
        .multicall(plan.calls.clone(), BlockId::hash_canonical(canonical.hash))
        .await?;
    finish_factory_discovery(profile, plan, &results).context("naming pools by factory")
}

/// The startup check of a profile whose factories name its pools: every fee
/// tier it lists is enabled at its factory, and its own pair (wrapped native
/// and the stable) has a pool, named and proved as a quote names and proves
/// one. An RPC on another chain fails here, because a factory with no code
/// answers with no address word.
pub(crate) async fn verify_factory_discovery(
    profile: &ChainProfile,
    rpc: &Rpc,
) -> anyhow::Result<()> {
    let discovery = profile
        .indexed_discovery()
        .filter(|discovery| discovery.candidates == CandidateSource::Factories)
        .context("this profile's pools are not named by their factories")?;
    let canonical = rpc.canonical_block(BlockId::latest()).await?;
    let plan = plan_factory_discovery(discovery, &[(profile.wrapped_native, profile.stable)])?;
    let results = rpc
        .multicall(plan.calls.clone(), BlockId::hash_canonical(canonical.hash))
        .await?;
    for &(protocol, fee, call) in &plan.tiers {
        ensure!(
            indexed_probe_spacing(&results, call).context("reading a fee tier's spacing")? > 0,
            "{} fee tier {fee} is not enabled at its factory",
            protocol.as_str()
        );
    }
    let (v3, v2) =
        finish_factory_discovery(profile, plan, &results).context("naming pools by factory")?;
    ensure!(
        !v3.is_empty() || !v2.is_empty(),
        "the factories name no pool for {}'s own pair",
        profile.name
    );
    Ok(())
}
