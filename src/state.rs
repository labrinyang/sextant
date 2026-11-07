// Pool discovery and consistent on-chain state snapshots. snapshot_at_observed_for
// runs the profile's pipeline from a child: robinhood (Robinhood's discovery rounds
// and snapshot) or indexed (the indexed-EVM snapshot, with connectors,
// indexed_validation and factories). The shared parts are in lens_parse, algebra,
// cache, v4_keys, pool_ids, execution and settings; the unit tests are in tests.

use crate::abi::{IArbSys, IExtsload, ISettlerRegistry};
use crate::abi::{
    IPoolState, IUniV2Factory, IUniV3Factory, IUp33ClFactory, IUp33V2Factory, addrhex, hexbytes,
    read_word, untwos, word_address, word_i64,
};
use crate::catalog::{CandidateSource, CatalogVenue, IndexedEvmDiscovery};
use crate::chain::{
    ARBSYS, CLONE_FEE_TIERS, ChainProfile, DiscoveryProfile, FORK_GIGADEX, FORK_PANCAKE,
    FORK_ROBINSWAP, FORK_SHERIFF, FORK_SUSHI, FORK_SWAPHOOD, FORK_UNIV3, FORK_UP33,
    GIGADEX_V3_DEPLOYER, GIGADEX_V3_FEE_TIERS, GIGADEX_V3_INIT, PANCAKE_V3_DEPLOYER,
    PANCAKE_V3_INIT, ROBINSWAP_V3_DEPLOYER, ROBINSWAP_V3_FEE_TIERS, ROBINSWAP_V3_INIT,
    SHERIFF_DEPLOYER, SHERIFF_INIT, SUSHI_V3_DEPLOYER, SUSHI_V3_FEE_TIERS, SUSHI_V3_INIT,
    SWAPHOOD_V3_DEPLOYER, SWAPHOOD_V3_INIT, SettlerRuntimePolicy, UNIV2_FACTORY, UNIV2_FEE_BPS,
    UNIV3_FACTORY, UNIV3_FEE_TIERS, UP33_CL_FACTORY, UP33_V2_FACTORY, V4_DYNAMIC_FEE_FLAG,
    V4_INIT_TOPIC, V4_KEYS, V4_MAX_FEE_PPM, V4_POOL_MANAGER, V4_POOLS_SLOT, V4_SWAP_HOOK_FLAGS,
    univ3_tier_spacing,
};
#[cfg(test)]
use crate::chain::{NATIVE, ROBINHOOD_PROFILE, WETH};
use crate::indexer::IndexerClient;
use crate::pools::{
    AlgebraMeta, TickInfo, V2Pool, V2Protocol, V2State, V3ExecutionMeta, V3Pool, V3Protocol,
    V3State, V4Meta,
};
use crate::route::BASELINE_PATH_CANDIDATE_CAP;
use crate::rpc::{CanonicalBlock, Rpc, RpcUnavailable, sanitized_error};
use crate::topology::{
    AddressPoolTopology, CatalogFences, ConnectorSelection, PoolTopology as IndexedPoolTopology,
    Protocol as IndexedProtocol, TokenPair, Topology as IndexedTopology, V4PoolTopology,
};
use crate::universe::{FallbackKind, RouteUniverse, RouteUniverseSource};
use crate::v3math::{MAX_TICK, MIN_TICK, sqrt_limit};
use alloy::eips::BlockId;
use alloy_primitives::{
    Address, B256, Bytes, I256, U256,
    aliases::{U24, U160},
    keccak256,
};
use alloy_sol_types::{SolCall, sol};
use anyhow::{Context, ensure};
use futures_util::{StreamExt, TryStreamExt, stream};
pub use sextant_amm::snapshot::{ScreeningPools, Snapshot};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::{Arc, LazyLock, Mutex, OnceLock};
use std::time::{Duration, Instant};
use tokio::sync::{Mutex as AsyncMutex, OnceCell};

/// The upstream catalog and canonical RPC disagree about immutable identity or
/// block binding. This is an operator/upstream failure (HTTP 502), never a bad
/// user quote request. The payload contains no endpoint URL.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpstreamIntegrityError(Arc<str>);

impl UpstreamIntegrityError {
    fn new(detail: impl Into<Arc<str>>) -> Self {
        Self(detail.into())
    }

    #[cfg(test)]
    pub(crate) fn test_only(detail: impl Into<Arc<str>>) -> Self {
        Self::new(detail)
    }
}

impl fmt::Display for UpstreamIntegrityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "upstream topology integrity failure: {}", self.0)
    }
}

impl std::error::Error for UpstreamIntegrityError {}

macro_rules! ensure_integrity {
    ($condition:expr, $($arg:tt)*) => {
        if !$condition {
            return Err(UpstreamIntegrityError::new(format!($($arg)*)).into());
        }
    };
}

mod algebra;
mod cache;
mod connectors;
mod execution;
mod factories;
mod indexed;
mod indexed_validation;
mod lens_parse;
mod pool_ids;
mod robinhood;
mod settings;
mod v4_keys;
use algebra::*;
use cache::*;
use connectors::*;
pub use execution::*;
pub(crate) use factories::*;
pub(crate) use indexed::*;
use indexed_validation::*;
pub(crate) use lens_parse::*;
pub use pool_ids::*;
use robinhood::*;
pub(crate) use settings::*;
pub(crate) use v4_keys::*;

sol! {
    function globalState() external view;
    function beforeSwap(
        address sender,
        address recipient,
        bool zeroToOne,
        int256 amountRequired,
        uint160 limitSqrtPrice,
        bool withPaymentInAdvance,
        bytes data
    ) external returns (bytes4 selector, uint24 overrideFee, uint24 pluginFee);
}

pub(crate) struct ObservedSnapshot {
    pub snapshot: Snapshot,
    /// Empty unless connector screening is on; see `ScreeningPools`.
    pub screening: ScreeningPools,
    pub universe: RouteUniverse,
    pub topology_fences: Option<CatalogFences>,
    pub block_id: BlockId,
    /// Consensus timestamp paired with `block_id`.
    pub block_timestamp: u64,
    pub observed_at: Instant,
}

fn sorted_pair(a: Address, b: Address) -> (Address, Address) {
    if a < b { (a, b) } else { (b, a) }
}

enum Probe {
    V2 {
        proto: V2Protocol,
        pair: (Address, Address),
    },
    V3Univ3 {
        pair: (Address, Address),
        fee: u32,
    },
    V3Up33 {
        pair: (Address, Address),
        spacing: i32,
    },
    // the call target IS the derived pool (slot0 probe), not a factory
    V3Clone {
        proto: V3Protocol,
        fork_id: u8,
        addr: Address,
        pair: (Address, Address),
        fee: u32,
    },
    // Algebra has one pool per pair; globalState() is its existence probe.
    V3Sheriff {
        addr: Address,
        pair: (Address, Address),
    },
    // extsload(state_slot) against the PoolManager: nonzero word = pool exists
    V4 {
        pair: (Address, Address),
        fee: u32,
        spacing: i32,
        native: bool,
    },
}

/// Profile-bound entrypoint used by the resident engine and, through
/// `snapshot_at_for`, by tools. Every caller passes the profile of the chain it
/// reads, so an enabled endpoint can never fall through to the
/// Robinhood-specific QuoteLens/address graph on another chain.
pub(crate) async fn snapshot_at_observed_for(
    profile: &ChainProfile,
    rpc: &Rpc,
    indexer: Option<&IndexerClient>,
    token_a: Address,
    token_b: Address,
    pin_block: Option<u64>,
    listed: Option<&dyn ListedPaths>,
) -> anyhow::Result<ObservedSnapshot> {
    match profile.discovery {
        DiscoveryProfile::Robinhood => {
            snapshot_at_observed_profile(profile, rpc, token_a, token_b, pin_block).await
        }
        DiscoveryProfile::IndexedEvm(discovery) => {
            let namer = match discovery.candidates {
                CandidateSource::Indexer => {
                    PoolNamer::Indexer(indexer.context("pool indexer is not configured")?)
                }
                CandidateSource::Factories => {
                    ensure!(
                        indexer.is_none(),
                        "{} names its pools by factory and takes no indexer",
                        profile.name
                    );
                    PoolNamer::Factories
                }
            };
            snapshot_at_observed_indexed(
                profile, discovery, rpc, namer, token_a, token_b, pin_block, listed,
            )
            .await
        }
        DiscoveryProfile::Disabled => anyhow::bail!(
            "pool discovery is not enabled for {} ({})",
            profile.name,
            profile.chain_id
        ),
    }
}

/// Snapshot of one token pair on `profile`'s chain, pinned to `pin_block`
/// (None = the current head). This is the public entry for tools: it runs
/// `snapshot_at_observed_for` without resident listed paths. `indexer` is the
/// client `server::configured_indexer` builds, None where the profile needs none.
pub async fn snapshot_at_for(
    profile: &ChainProfile,
    rpc: &Rpc,
    indexer: Option<&IndexerClient>,
    token_a: Address,
    token_b: Address,
    pin_block: Option<u64>,
) -> anyhow::Result<Snapshot> {
    Ok(
        snapshot_at_observed_for(profile, rpc, indexer, token_a, token_b, pin_block, None)
            .await?
            .snapshot,
    )
}

#[cfg(test)]
mod tests;
