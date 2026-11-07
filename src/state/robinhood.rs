//! Pool discovery + consistent on-chain state snapshot.
//!
//! STATE is always fetched fresh and pinned to one block; the pool TOPOLOGY
//! (factory probe results — append-only on chain) is cached per quoted
//! direction for SOLVER_TOPO_TTL seconds (default 600, 0 disables). Rounds:
//!   R1 (once per process)    up33 factory tickSpacings()
//!   R2 (topology miss only)  per-pair v4 Initialize getLogs (concurrent),
//!                            then head rider + factory getPool/getPair probes
//!                            for every edge in the direct/connector route graph
//!   lens (every snapshot)    one state-override eth_call per <=128 pool queries,
//!                            all pinned to one block; each fetches scalar state,
//!                            the ±SOLVER_BITMAP_WORDS tickBitmap window, and
//!                            every initialized tick's liquidityNet in-EVM
//!   Sheriff fee (if present) two parallel beforeSwap eth_calls, pinned to the
//!                            lens block and sent from the pool
//! A topology hit with <=128 pools is one round trip. Larger universes are split
//! to stay below public-node gas caps. Sheriff adds one dependent fee round,
//! pinned to the same block. The head rider is answered inside the lens; the
//! profile's Settler registry is read separately at that same canonical block.
//! On a miss the probe round pins the block and the lens runs pinned to it. (ArbSys, NOT
//! Multicall3.getBlockNumber: block.number on this chain is the parent
//! chain's height.) Pinned replays (differential testing) bypass the topology
//! cache: a head-discovered pool set may not exist at an old block.

use super::*;

pub(super) fn requires_verified_settler(protocol: V3Protocol) -> bool {
    matches!(
        protocol,
        V3Protocol::GIGADEXV3 | V3Protocol::SUSHIV3 | V3Protocol::ROBINSWAPV3
    )
}

pub(super) fn settler_supports_protocol_for(
    profile: &ChainProfile,
    protocol: V3Protocol,
    codehash: B256,
) -> bool {
    if !requires_verified_settler(protocol) {
        return true;
    }
    profile
        .settler
        .is_some_and(|settler| match settler.runtime {
            SettlerRuntimePolicy::Exact(expected)
            | SettlerRuntimePolicy::Compatible {
                extended_v3_hash: expected,
            } => codehash == expected,
            SettlerRuntimePolicy::SignerMasked { .. } => false,
        })
}

fn gate_v3_by_settler(profile: &ChainProfile, snapshot: &mut Snapshot, codehash: B256) {
    if !snapshot
        .v3
        .iter()
        .any(|(pool, _)| requires_verified_settler(pool.protocol))
    {
        return;
    }
    let before = snapshot.v3.len();
    snapshot
        .v3
        .retain(|(pool, _)| settler_supports_protocol_for(profile, pool.protocol, codehash));
    if snapshot.v3.len() != before {
        tracing::info!(
            "snapshot: Settler runtime {codehash:#x} is not verified for GigaDex/Sushi/RobinSwap; dropped {} pools",
            before - snapshot.v3.len()
        );
    }
}

fn gate_ekubo_by_settler(profile: &ChainProfile, snapshot: &mut Snapshot, codehash: B256) {
    if snapshot.ekubo.is_empty() {
        return;
    }
    let supported = profile
        .settler
        .is_some_and(|settler| settler.ekubo_v3_runtimes.contains(&codehash));
    if !supported {
        tracing::info!(
            "snapshot: Settler runtime {codehash:#x} is not verified for Ekubo V3; dropped {} pools",
            snapshot.ekubo.len()
        );
        snapshot.ekubo.clear();
    }
}

static UP33_SPACINGS: OnceCell<Vec<i32>> = OnceCell::const_new();

async fn up33_spacings(rpc: &Rpc) -> anyhow::Result<&'static Vec<i32>> {
    UP33_SPACINGS
        .get_or_try_init(|| async {
            let ret = rpc
                .eth_call(
                    UP33_CL_FACTORY,
                    IUp33ClFactory::tickSpacingsCall {}.abi_encode(),
                    BlockId::latest(),
                )
                .await?;
            let vals = IUp33ClFactory::tickSpacingsCall::abi_decode_returns(&ret)
                .context("decoding tickSpacings()")?;
            vals.iter()
                .map(|v| Ok(v.as_i32()))
                .collect::<anyhow::Result<Vec<i32>>>()
        })
        .await
}

fn head_block(res: &[Option<Vec<u8>>]) -> anyhow::Result<u64> {
    let w = read_word(
        res.first()
            .context("snapshot round returned no head result")?
            .as_ref()
            .context("arbBlockNumber reverted")?,
        0,
    )?;
    u64::try_from(w).map_err(|_| anyhow::anyhow!("block number out of range"))
}

pub(super) fn ensure_complete_probes(
    probe_count: usize,
    results: &[Option<Vec<u8>>],
) -> anyhow::Result<()> {
    ensure!(
        results.len() == probe_count + 1,
        "topology round returned {} results for {} probes",
        results.len().saturating_sub(1),
        probe_count
    );
    let failed = results[1..]
        .iter()
        .filter(|result| result.is_none())
        .count();
    ensure!(failed == 0, "{failed} topology probes reverted");
    Ok(())
}

/// Run the first snapshot round. The ArbSys rider answers on the real chain;
/// on a vanilla-EVM fork (anvil) the precompile address holds only the 0xfe
/// stub and reverts — then pin via eth_blockNumber and re-run the same calls
/// there (such forks are frozen, so the two-step read stays consistent).
/// Running at `latest` is only sound while the round fits ONE aggregate3
/// batch (atomic in one block); a larger set resolves the selected height to
/// a canonical hash before launching any batch.
async fn first_round(
    rpc: &Rpc,
    calls: Vec<(Address, Vec<u8>)>,
    pin_block: Option<u64>,
) -> anyhow::Result<(u64, Vec<Option<Vec<u8>>>)> {
    if pin_block.is_none() && calls.len() <= rpc.chunk() {
        let res = rpc.multicall(calls.clone(), BlockId::latest()).await?;
        if let Ok(blk) = head_block(&res) {
            return Ok((blk, res));
        }
    }
    let blk = match pin_block {
        Some(n) => n,
        None => rpc.block_number().await?,
    };
    let hash = rpc.block_hash(BlockId::number(blk)).await?;
    let res = rpc.multicall(calls, BlockId::hash_canonical(hash)).await?;
    Ok((blk, res))
}

pub(super) async fn snapshot_at_observed_profile(
    profile: &ChainProfile,
    rpc: &Rpc,
    token_a: Address,
    token_b: Address,
    pin_block: Option<u64>,
) -> anyhow::Result<ObservedSnapshot> {
    let (a, b) = (profile.erc20_of(token_a), profile.erc20_of(token_b));
    ensure!(a != b, "identical tokens");
    let requested_universe = RouteUniverse::profile_only(profile, a, b)?;
    let cache_ok = pin_block.is_none() && *TOPO_TTL > 0;
    let cached = if cache_ok {
        topology_cached(topology_key(profile, a, b))
    } else {
        None
    };
    let (v3pools, v2pools, universe, topology_fences, at) = match cached {
        // Topology known: the Lens chunk(s) are the snapshot and all pin to
        // the block returned by the first call.
        Some(topology) => (
            topology.v3,
            topology.v2,
            topology.universe,
            topology.topology_fences,
            BlockId::latest(),
        ),
        None => {
            let (blk, v3p, v2p) =
                discover_for(profile, rpc, &requested_universe, pin_block, cache_ok).await?;
            let at = if pin_block.is_some() {
                BlockId::number(blk)
            } else {
                // Topology is append-only. Reading state at the new head after
                // a slow discovery avoids publishing discovery's old block.
                BlockId::latest()
            };
            (v3p, v2p, requested_universe, None, at)
        }
    };
    let ekubo_keys = if matches!(profile.discovery, DiscoveryProfile::Robinhood) {
        crate::ekubo::topology_for_pairs(
            profile.chain_id,
            universe.pairs(),
            profile.wrapped_native,
            *TOPO_TTL,
        )
        .await?
    } else {
        Vec::new()
    };
    let words = bitmap_words()?;
    let ret = crate::lens::peek(rpc, words, &v3pools, &v2pools, at).await?;
    let block_id = ret.block_id;
    let observed_at = ret.observed_at;
    let mut parsed = parse_lens(&v3pools, &v2pools, &ret)?;
    let (execution, ekubo) = tokio::try_join!(
        verify_execution_adapter_at(profile, rpc, block_id),
        crate::ekubo::fetch_state(
            rpc,
            &ekubo_keys,
            u32::from(words),
            block_id,
            profile.wrapped_native,
        ),
    )?;
    parsed.snapshot.settler = Some(execution.settler);
    parsed.snapshot.ekubo = ekubo;
    let mut snapshot = attach_algebra_fees(rpc, parsed, block_id).await?;
    gate_v3_by_settler(profile, &mut snapshot, execution.runtime_hash);
    gate_ekubo_by_settler(profile, &mut snapshot, execution.runtime_hash);
    Ok(ObservedSnapshot {
        screening: Default::default(),
        snapshot,
        universe,
        topology_fences,
        block_id,
        block_timestamp: ret.block_timestamp,
        observed_at,
    })
}

/// R2: ArbSys head rider + factory/event pool discovery for every edge needed
/// by the direct, two-hop, and three-hop route skeletons. Returns the block the
/// lens call must pin to.
async fn discover_for(
    profile: &ChainProfile,
    rpc: &Rpc,
    universe: &RouteUniverse,
    pin_block: Option<u64>,
    cache_ok: bool,
) -> anyhow::Result<(u64, Vec<V3Pool>, Vec<V2Pool>)> {
    match profile.discovery {
        DiscoveryProfile::Robinhood => {
            discover_robinhood(profile, rpc, universe, pin_block, cache_ok).await
        }
        DiscoveryProfile::IndexedEvm(_) => {
            anyhow::bail!("indexed EVM discovery uses the canonical quote-only snapshot path")
        }
        DiscoveryProfile::Disabled => anyhow::bail!(
            "pool discovery is not enabled for {} ({})",
            profile.name,
            profile.chain_id
        ),
    }
}

/// One R2 round as `plan_robinhood_probes` lays it out.
pub(super) struct RobinhoodProbePlan {
    /// The head rider, then one call per probe.
    pub(super) calls: Vec<(Address, Vec<u8>)>,
    pub(super) probes: Vec<Probe>,
    /// V4 pools their Initialize events already prove; no call asks for them.
    pub(super) v4direct: Vec<V3Pool>,
}

/// The R2 probes for `pairs`, each one's call appended to `head`, the round's
/// ArbSys rider. Per pair, in order: univ2, up33v2, univ3 at each tier, up33cl
/// at each of `spacings`, the CREATE2 clones, Sheriff, and V4 on the pair's
/// ERC-20 side, then on its native side if it holds the wrapped native.
/// `v4keys` has one Initialize scan per V4 side, in that order: a scan's keys
/// are pools already, and a side whose scan was unavailable is probed on the
/// static key grid.
pub(super) fn plan_robinhood_probes(
    profile: &ChainProfile,
    head: Vec<(Address, Vec<u8>)>,
    pairs: &[(Address, Address)],
    spacings: &[i32],
    v4keys: &[V4KeyDiscovery],
) -> anyhow::Result<RobinhoodProbePlan> {
    let mut v4cur = 0usize;
    let mut v4direct: Vec<V3Pool> = Vec::new();
    let mut calls = head;
    let mut probes: Vec<Probe> = Vec::new();
    for &(x, y) in pairs {
        calls.push((
            UNIV2_FACTORY,
            IUniV2Factory::getPairCall { a: x, b: y }.abi_encode(),
        ));
        probes.push(Probe::V2 {
            proto: V2Protocol::UNIV2,
            pair: (x, y),
        });
        // volatile only — stable pools would need the VELODROME action's curve
        calls.push((
            UP33_V2_FACTORY,
            IUp33V2Factory::getPoolCall {
                a: x,
                b: y,
                stable: false,
            }
            .abi_encode(),
        ));
        probes.push(Probe::V2 {
            proto: V2Protocol::UP33V2,
            pair: (x, y),
        });
        for f in UNIV3_FEE_TIERS {
            calls.push((
                UNIV3_FACTORY,
                IUniV3Factory::getPoolCall {
                    a: x,
                    b: y,
                    fee: U24::from(f),
                }
                .abi_encode(),
            ));
            probes.push(Probe::V3Univ3 {
                pair: (x, y),
                fee: f,
            });
        }
        for &ts in spacings {
            calls.push((
                UP33_CL_FACTORY,
                IUp33ClFactory::getPoolCall {
                    a: x,
                    b: y,
                    tickSpacing: crate::lens::i24(ts)?,
                }
                .abi_encode(),
            ));
            probes.push(Probe::V3Up33 {
                pair: (x, y),
                spacing: ts,
            });
        }
        let (t0, t1) = sorted_pair(x, y);
        for f in CLONE_FEE_TIERS {
            for (proto, fork_id, deployer, init) in [
                (
                    V3Protocol::PANCAKEV3,
                    FORK_PANCAKE,
                    PANCAKE_V3_DEPLOYER,
                    PANCAKE_V3_INIT,
                ),
                (
                    V3Protocol::SWAPHOODV3,
                    FORK_SWAPHOOD,
                    SWAPHOOD_V3_DEPLOYER,
                    SWAPHOOD_V3_INIT,
                ),
            ] {
                let addr = clone_pool_addr(deployer, init, t0, t1, f);
                calls.push((addr, IPoolState::slot0Call {}.abi_encode()));
                probes.push(Probe::V3Clone {
                    proto,
                    fork_id,
                    addr,
                    pair: (x, y),
                    fee: f,
                });
            }
        }
        for (proto, fork_id, deployer, init, fees) in [
            (
                V3Protocol::GIGADEXV3,
                FORK_GIGADEX,
                GIGADEX_V3_DEPLOYER,
                GIGADEX_V3_INIT,
                &GIGADEX_V3_FEE_TIERS[..],
            ),
            (
                V3Protocol::SUSHIV3,
                FORK_SUSHI,
                SUSHI_V3_DEPLOYER,
                SUSHI_V3_INIT,
                &SUSHI_V3_FEE_TIERS[..],
            ),
            (
                V3Protocol::ROBINSWAPV3,
                FORK_ROBINSWAP,
                ROBINSWAP_V3_DEPLOYER,
                ROBINSWAP_V3_INIT,
                &ROBINSWAP_V3_FEE_TIERS[..],
            ),
        ] {
            for &f in fees {
                let addr = clone_pool_addr(deployer, init, t0, t1, f);
                calls.push((addr, IPoolState::slot0Call {}.abi_encode()));
                probes.push(Probe::V3Clone {
                    proto,
                    fork_id,
                    addr,
                    pair: (x, y),
                    fee: f,
                });
            }
        }
        let sheriff = algebra_pool_addr(SHERIFF_DEPLOYER, SHERIFF_INIT, t0, t1);
        calls.push((sheriff, globalStateCall {}.abi_encode()));
        probes.push(Probe::V3Sheriff {
            addr: sheriff,
            pair: (x, y),
        });
        // Native-currency v4 pools bridge the profile's wrapped-native
        // side of the pair (the encoder unwraps/wraps around the action).
        for native in [false, true] {
            let Some((c0, c1)) = v4_currency_pair_for(profile.wrapped_native, x, y, native) else {
                continue;
            };
            let (token0, token1) = v4_tokens_from_currencies_for(profile.wrapped_native, c0, c1);
            match v4keys[v4cur].keys() {
                Some(keys) => {
                    // the Initialize event is the existence proof — no probe
                    for &(f, ts, hooks) in keys {
                        v4direct.push(V3Pool {
                            protocol: V3Protocol::UNIV4,
                            address: V4_POOL_MANAGER,
                            token0,
                            token1,
                            fee_ppm: f, // the PoolKey fee — sims price via fee_ppm_for
                            tick_spacing: ts,
                            verify_pool_spacing: false,
                            execution: None, // v4 is its own Settler action
                            v4: Some(v4_meta(c0, c1, f, ts, hooks)),
                            algebra: None,
                        });
                    }
                }
                None => {
                    tracing::info!(
                        "snapshot: v4 Initialize scan unavailable for {}/{} — falling back to the key grid",
                        addrhex(c0),
                        addrhex(c1)
                    );
                    for (f, ts) in V4_KEYS {
                        calls.push((
                            V4_POOL_MANAGER,
                            extsload(v4_meta(c0, c1, f, ts, Address::ZERO).state_slot),
                        ));
                        probes.push(Probe::V4 {
                            pair: (x, y),
                            fee: f,
                            spacing: ts,
                            native,
                        });
                    }
                }
            }
            v4cur += 1;
        }
    }
    Ok(RobinhoodProbePlan {
        calls,
        probes,
        v4direct,
    })
}

/// The pools a round's answers name. `res` holds the answers as
/// `ensure_complete_probes` accepted them: the head rider's, then one per
/// probe. Pools come out in probe order, with `v4direct` after them.
pub(super) fn finish_robinhood_discovery(
    profile: &ChainProfile,
    probes: &[Probe],
    res: &[Option<Vec<u8>>],
    v4direct: Vec<V3Pool>,
) -> anyhow::Result<(Vec<V3Pool>, Vec<V2Pool>)> {
    let mut v3found: Vec<V3Pool> = Vec::new();
    let mut v2found: Vec<V2Pool> = Vec::new();
    for (probe, ret) in probes.iter().zip(res[1..].iter()) {
        let ret = ret.as_ref().expect("probe completeness checked");
        // Clone probes hit the derived pool itself: an eth_call to a
        // codeless address "succeeds" with empty return data, so length
        // is the existence check; zero sqrtPrice means uninitialized.
        if let Probe::V3Clone {
            proto,
            fork_id,
            addr,
            pair: (x, y),
            fee,
        } = *probe
        {
            if ret.len() >= 32 && !read_word(ret, 0)?.is_zero() {
                let (t0, t1) = sorted_pair(x, y);
                v3found.push(V3Pool {
                    protocol: proto,
                    address: addr,
                    token0: t0,
                    token1: t1,
                    fee_ppm: fee,
                    tick_spacing: 0, // read from the pool in R3
                    verify_pool_spacing: true,
                    execution: Some(V3ExecutionMeta {
                        fork_id,
                        pool_id: fee,
                    }),
                    v4: None,
                    algebra: None,
                });
            }
            continue;
        }
        if let Probe::V3Sheriff { addr, pair: (x, y) } = *probe {
            if ret.len() >= 32 && !read_word(ret, 0)?.is_zero() {
                let (t0, t1) = sorted_pair(x, y);
                v3found.push(V3Pool {
                    protocol: V3Protocol::SHERIFF,
                    address: addr,
                    token0: t0,
                    token1: t1,
                    fee_ppm: 0,      // read atomically by the lens
                    tick_spacing: 0, // read atomically by the lens
                    verify_pool_spacing: false,
                    execution: Some(V3ExecutionMeta {
                        fork_id: FORK_SHERIFF,
                        pool_id: 0,
                    }),
                    v4: None,
                    algebra: None, // filled from pinned beforeSwap calls
                });
            }
            continue;
        }
        if let Probe::V4 {
            pair: (x, y),
            fee,
            spacing,
            native,
        } = *probe
        {
            if ret.len() >= 32 && !read_word(ret, 0)?.is_zero() {
                let Some((c0, c1)) = v4_currency_pair_for(profile.wrapped_native, x, y, native)
                else {
                    continue;
                };
                let (token0, token1) =
                    v4_tokens_from_currencies_for(profile.wrapped_native, c0, c1);
                v3found.push(V3Pool {
                    protocol: V3Protocol::UNIV4,
                    address: V4_POOL_MANAGER,
                    token0,
                    token1,
                    fee_ppm: fee, // grid keys are hookless static tiers
                    tick_spacing: spacing,
                    verify_pool_spacing: false,
                    execution: None, // v4 is its own Settler action
                    v4: Some(v4_meta(c0, c1, fee, spacing, Address::ZERO)),
                    algebra: None,
                });
            }
            continue;
        }
        let addr = word_address(ret, 0)?;
        if addr == Address::ZERO {
            continue;
        }
        match *probe {
            Probe::V2 {
                proto,
                pair: (x, y),
            } => {
                let (t0, t1) = sorted_pair(x, y);
                v2found.push(V2Pool {
                    protocol: proto,
                    address: addr,
                    token0: t0,
                    token1: t1,
                    fee_bps: UNIV2_FEE_BPS,
                });
            }
            Probe::V3Univ3 { pair: (x, y), fee } => {
                let (t0, t1) = sorted_pair(x, y);
                v3found.push(V3Pool {
                    protocol: V3Protocol::UNIV3,
                    address: addr,
                    token0: t0,
                    token1: t1,
                    fee_ppm: fee,
                    tick_spacing: univ3_tier_spacing(fee),
                    verify_pool_spacing: false,
                    execution: Some(V3ExecutionMeta {
                        fork_id: FORK_UNIV3,
                        pool_id: fee,
                    }),
                    v4: None,
                    algebra: None,
                });
            }
            Probe::V3Up33 {
                pair: (x, y),
                spacing,
            } => {
                let (t0, t1) = sorted_pair(x, y);
                v3found.push(V3Pool {
                    protocol: V3Protocol::UP33CL,
                    address: addr,
                    token0: t0,
                    token1: t1,
                    fee_ppm: 0,
                    tick_spacing: spacing,
                    verify_pool_spacing: false,
                    execution: Some(V3ExecutionMeta {
                        fork_id: FORK_UP33,
                        pool_id: u32::try_from(spacing).context("negative tickSpacing")?,
                    }),
                    v4: None,
                    algebra: None,
                });
            }
            Probe::V3Clone { .. } | Probe::V3Sheriff { .. } | Probe::V4 { .. } => {
                unreachable!("handled above")
            }
        }
    }
    // Event-derived v4 pools join after the probed set: deterministic
    // (pairs order × sorted keys), and R3 still validates their state.
    v3found.extend(v4direct);
    Ok((v3found, v2found))
}

/// Robinhood's audited venue catalog. Common chain identity (wrapped native,
/// connector graph, registry and runtime hash) still comes from `profile`;
/// the factory/fork constants in `plan_robinhood_probes` and
/// `finish_robinhood_discovery` are intentionally owned by this branch.
async fn discover_robinhood(
    profile: &ChainProfile,
    rpc: &Rpc,
    universe: &RouteUniverse,
    pin_block: Option<u64>,
    cache_ok: bool,
) -> anyhow::Result<(u64, Vec<V3Pool>, Vec<V2Pool>)> {
    let (a, b) = universe.endpoints();
    let head = vec![(ARBSYS, IArbSys::arbBlockNumberCall {}.abi_encode())];
    {
        // R2 — head rider + pool probes
        let spacings = up33_spacings(rpc).await?;
        let pairs = universe.pairs();
        // V4 key sets per (pair, native) from Initialize events, fetched
        // concurrently. Order matches `plan_robinhood_probes`'s loop:
        // (erc20, native?) per pair, native only when it contains the
        // profile's wrapped token.
        let v4queries: Vec<(Address, Address, bool)> = pairs
            .iter()
            .flat_map(|&(x, y)| {
                let (t0, t1) = sorted_pair(x, y);
                let mut q = vec![(t0, t1, false)];
                if let Some((c0, c1)) = v4_currency_pair_for(profile.wrapped_native, x, y, true) {
                    q.push((c0, c1, true));
                }
                q
            })
            .collect();
        let logs_head = OnceCell::new();
        let primary_head = OnceCell::new();
        let primary = V4ScanSource {
            rpc,
            head: &primary_head,
        };
        let logs_rpc = logs_rpc().with_probe_from(rpc);
        let logs = Some(V4ScanSource {
            rpc: &logs_rpc,
            head: if logs_rpc.url == rpc.url {
                &primary_head
            } else {
                &logs_head
            },
        });
        let scans = V4ScanContext { logs, primary };
        let v4keys: Vec<V4KeyDiscovery> = stream::iter(
            v4queries
                .into_iter()
                .map(|(c0, c1, _)| v4_event_keys(&scans, c0, c1)),
        )
        .buffered(rpc.concurrency())
        .try_collect()
        .await?;
        let topology_status = TopologyStatus::from_v4(&v4keys);
        let RobinhoodProbePlan {
            calls,
            probes,
            v4direct,
        } = plan_robinhood_probes(profile, head, pairs, spacings, &v4keys)?;
        let (blk, res) = first_round(rpc, calls, pin_block).await?;
        ensure_complete_probes(probes.len(), &res)?;

        let (v3found, v2found) = finish_robinhood_discovery(profile, &probes, &res, v4direct)?;
        // A stale event-key set or fallback key grid can serve quotes, but it
        // gets only the short retry TTL so a logs outage neither triggers R2
        // on every snapshot nor hides newly initialized pools for 10 minutes.
        if cache_ok && topology_status.ttl() > 0 {
            cache_topology(
                topology_key(profile, a, b),
                Topology {
                    at: Instant::now(),
                    status: topology_status,
                    universe: universe.clone(),
                    topology_fences: None,
                    v3: v3found.clone(),
                    v2: v2found.clone(),
                    // Robinhood discovery is profile-only; nothing to screen.
                    screen_v3: Vec::new(),
                    screen_v2: Vec::new(),
                },
            );
        }

        Ok((blk, v3found, v2found))
    }
}
