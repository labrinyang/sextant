//! Ekubo V3 pool discovery and quote-data reads. The pool model and its
//! exact simulation are `sextant_amm::ekubo`, re-exported here.

pub use sextant_amm::ekubo::*;

use crate::rpc::{Rpc, RpcUnavailable};
use alloy::eips::BlockId;
use alloy_primitives::{Address, B256, aliases::U96};
use alloy_sol_types::{SolCall, sol};
use anyhow::{Context, ensure};
use serde::Deserialize;
use std::{
    collections::{HashMap, HashSet},
    sync::{LazyLock, Mutex},
    time::{Duration, Instant},
};

pub const CORE: Address = alloy_primitives::address!("00000000000014aa86c5d3c41765bb24e11bd701");

pub const QUOTE_DATA_FETCHER: Address =
    alloy_primitives::address!("5a3f0f1da4ac0c4b937d5685f330704c8e8303f1");

pub const VE33_DATA_FETCHER: Address =
    alloy_primitives::address!("61f03754b1c7a7f0e584fd8869c00ba898ab888d");

const POOL_KEYS_API: &str = "https://prod-api.ekubo.org/poolKeys";

const FETCH_CHUNK: usize = 8;

const MAX_TOPOLOGY_POOLS: usize = 4_096;

sol! {
    struct FetchPoolKey {
        address token0;
        address token1;
        bytes32 config;
    }

    struct FetchTickDelta {
        int32 number;
        int128 liquidityDelta;
    }

    struct FetchQuoteData {
        int32 tick;
        uint96 sqrtRatio;
        uint128 liquidity;
        int32 minTick;
        int32 maxTick;
        FetchTickDelta[] ticks;
    }

    struct FetchVe33QuoteData {
        FetchQuoteData quoteData;
        uint64 swapFee;
    }

    function getQuoteData(FetchPoolKey[] poolKeys, uint32 minBitmapsSearched)
        external view returns (FetchQuoteData[] results);
    function getVe33QuoteData(FetchPoolKey[] poolKeys, uint32 minBitmapsSearched)
        external view returns (FetchVe33QuoteData[] results);
}

#[derive(Deserialize)]
struct ApiPoolKey {
    token0: String,
    token1: String,
    config: String,
}

#[derive(Deserialize)]
struct ApiPool {
    pool_id: String,
    pool_key: ApiPoolKey,
}

#[derive(Deserialize)]
struct ApiPoolPage {
    pools: Vec<ApiPool>,
    has_more: bool,
    next_cursor: Option<String>,
}

struct TopologyCache {
    at: Instant,
    chain_id: u64,
    keys: Vec<EkuboPoolKey>,
}

static TOPOLOGY: LazyLock<Mutex<Option<TopologyCache>>> = LazyLock::new(|| Mutex::new(None));

async fn fetch_topology(chain_id: u64) -> anyhow::Result<Vec<EkuboPoolKey>> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .context("building Ekubo API client")?;
    let mut cursor: Option<String> = None;
    let mut keys = Vec::new();
    loop {
        let mut url = reqwest::Url::parse(&format!("{POOL_KEYS_API}/{chain_id}/{CORE:#x}"))?;
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("limit", "200");
            if let Some(cursor) = &cursor {
                query.append_pair("cursor", cursor);
            }
        }
        let page: ApiPoolPage = client
            .get(url)
            .send()
            .await
            .context("requesting Ekubo pool topology")?
            .error_for_status()
            .context("Ekubo pool topology HTTP status")?
            .json()
            .await
            .context("decoding Ekubo pool topology")?;
        for pool in page.pools {
            let key = EkuboPoolKey {
                pool_id: pool.pool_id.parse().context("invalid Ekubo pool id")?,
                token0: api_address(&pool.pool_key.token0).context("invalid Ekubo token0")?,
                token1: api_address(&pool.pool_key.token1).context("invalid Ekubo token1")?,
                config: pool
                    .pool_key
                    .config
                    .parse()
                    .context("invalid Ekubo pool config")?,
            };
            if let Some(key) = supported_key(key)? {
                keys.push(key);
            }
        }
        ensure!(
            keys.len() <= MAX_TOPOLOGY_POOLS,
            "Ekubo topology exceeds pool limit"
        );
        if !page.has_more {
            break;
        }
        cursor = page.next_cursor;
        ensure!(cursor.is_some(), "Ekubo topology page omitted its cursor");
    }
    keys.sort_by_key(|key| key.pool_id);
    keys.dedup_by_key(|key| key.pool_id);
    Ok(keys)
}

fn api_address(value: &str) -> anyhow::Result<Address> {
    let hex = value.strip_prefix("0x").unwrap_or(value);
    ensure!(hex.len() <= 40, "address exceeds 20 bytes");
    format!("0x{hex:0>40}").parse().context("invalid address")
}

/// Return supported Ekubo keys on the route universe's existing token pairs.
/// Mutable pool state never comes from the API; it is read at the canonical
/// RPC block by `fetch_state` below.
pub async fn topology_for_pairs(
    chain_id: u64,
    pairs: &[(Address, Address)],
    wrapped_native: Address,
    ttl_seconds: u64,
) -> anyhow::Result<Vec<EkuboPoolKey>> {
    let cached = TOPOLOGY
        .lock()
        .expect("Ekubo topology cache")
        .as_ref()
        .filter(|cache| cache.chain_id == chain_id && cache.at.elapsed().as_secs() < ttl_seconds)
        .map(|cache| cache.keys.clone());
    let keys = match cached {
        Some(keys) => keys,
        None => {
            let keys = fetch_topology(chain_id).await?;
            *TOPOLOGY.lock().expect("Ekubo topology cache") = Some(TopologyCache {
                at: Instant::now(),
                chain_id,
                keys: keys.clone(),
            });
            keys
        }
    };
    let canonical = |a: Address, b: Address| if a < b { (a, b) } else { (b, a) };
    let pairs: HashSet<_> = pairs.iter().map(|&(a, b)| canonical(a, b)).collect();
    Ok(keys
        .into_iter()
        .filter(|key| {
            let routed = |token| {
                if token == Address::ZERO {
                    wrapped_native
                } else {
                    token
                }
            };
            pairs.contains(&canonical(routed(key.token0), routed(key.token1)))
        })
        .collect())
}

fn fetch_key(key: &EkuboPoolKey) -> FetchPoolKey {
    FetchPoolKey {
        token0: key.token0,
        token1: key.token1,
        config: key.config,
    }
}

fn quote_state(data: FetchQuoteData) -> EkuboQuoteState {
    EkuboQuoteState {
        tick: data.tick,
        sqrt_ratio: data.sqrtRatio,
        liquidity: data.liquidity,
        min_tick: data.minTick,
        max_tick: data.maxTick,
        ticks: data
            .ticks
            .into_iter()
            .map(|tick| EkuboTick {
                number: tick.number,
                liquidity_delta: tick.liquidityDelta,
            })
            .collect(),
    }
}

async fn fetch_quote_chunks(
    rpc: &Rpc,
    keys: &[EkuboPoolKey],
    min_bitmaps: u32,
    block: BlockId,
    ve33: bool,
) -> anyhow::Result<HashMap<B256, (EkuboQuoteState, Option<u64>)>> {
    if keys.is_empty() {
        return Ok(HashMap::new());
    }
    let calls: Vec<_> = keys
        .chunks(FETCH_CHUNK)
        .map(|chunk| {
            let keys = chunk.iter().map(fetch_key).collect();
            if ve33 {
                (
                    VE33_DATA_FETCHER,
                    getVe33QuoteDataCall {
                        poolKeys: keys,
                        minBitmapsSearched: min_bitmaps,
                    }
                    .abi_encode(),
                )
            } else {
                (
                    QUOTE_DATA_FETCHER,
                    getQuoteDataCall {
                        poolKeys: keys,
                        minBitmapsSearched: min_bitmaps,
                    }
                    .abi_encode(),
                )
            }
        })
        .collect();
    let returns = rpc.multicall(calls, block).await?;
    let mut out = HashMap::new();
    for (chunk, ret) in keys.chunks(FETCH_CHUNK).zip(returns) {
        let ret = ret.context(RpcUnavailable("Ekubo quote-data call"))?;
        if ve33 {
            let values = getVe33QuoteDataCall::abi_decode_returns(&ret)
                .context(RpcUnavailable("decoding Ekubo Ve33 quote data"))?;
            ensure!(
                values.len() == chunk.len(),
                "Ekubo quote-data length mismatch"
            );
            for (key, value) in chunk.iter().zip(values) {
                out.insert(
                    key.pool_id,
                    (quote_state(value.quoteData), Some(value.swapFee)),
                );
            }
        } else {
            let values = getQuoteDataCall::abi_decode_returns(&ret)
                .context(RpcUnavailable("decoding Ekubo quote data"))?;
            ensure!(
                values.len() == chunk.len(),
                "Ekubo quote-data length mismatch"
            );
            for (key, value) in chunk.iter().zip(values) {
                out.insert(key.pool_id, (quote_state(value), None));
            }
        }
    }
    Ok(out)
}

pub async fn fetch_state(
    rpc: &Rpc,
    keys: &[EkuboPoolKey],
    min_bitmaps: u32,
    block: BlockId,
    wrapped_native: Address,
) -> anyhow::Result<Vec<(EkuboPool, EkuboState)>> {
    if keys.is_empty() {
        return Ok(Vec::new());
    }
    let (extensionless, ve33): (Vec<_>, Vec<_>) = keys
        .iter()
        .cloned()
        .partition(|key| Address::from_slice(&key.config.as_slice()[..20]) == Address::ZERO);
    let (extensionless, ve33) = tokio::try_join!(
        fetch_quote_chunks(rpc, &extensionless, min_bitmaps, block, false),
        fetch_quote_chunks(rpc, &ve33, min_bitmaps, block, true),
    )?;
    let mut quotes = extensionless;
    quotes.extend(ve33);
    let mut pools = Vec::with_capacity(keys.len());
    for key in keys {
        let (quote, fee) = quotes
            .remove(&key.pool_id)
            .context("Ekubo quote data omitted a pool")?;
        if quote.sqrt_ratio == U96::ZERO {
            continue;
        }
        let built = build_pool(key, quote, fee, wrapped_native)?;
        pools.push(built);
    }
    Ok(pools)
}

#[cfg(test)]
#[test]
fn api_addresses_are_left_padded_like_evm_words() {
    assert_eq!(api_address("0x0").unwrap(), Address::ZERO);
    assert_eq!(
        api_address("0xbd7d308f8e1639fab988df18a8011f41eacad73").unwrap(),
        alloy_primitives::address!("0bd7d308f8e1639fab988df18a8011f41eacad73")
    );
}
