// Closed-set chain profiles + solver configuration.
//
// The process is deliberately single-chain: one profile is selected at boot,
// both RPCs are verified against it before the listener opens, and every quote
// request is bound to that identity.  Protocol/address tables remain audited
// compile-time data rather than user-supplied ABI plugins.

use crate::catalog::{CandidateSource, CatalogProtocol, IndexedEvmDiscovery};
use alloy_primitives::{Address, B256, address, b256};
use anyhow::Context;
use std::sync::LazyLock;

/// Backwards-compatible Robinhood constants used by the existing port tests
/// and diagnostics. Runtime code must read identity from `Config::profile`.
/// `CHAIN_ID` also binds manifests: one whose `discovery.kind` is `robinhood`
/// must name this chain, because that discovery probes the compiled Robinhood
/// factories, deployers and init hashes.
pub const CHAIN_ID: u64 = 4663;
pub const PUBLIC_RPC: &str = "https://rpc.mainnet.chain.robinhood.com";

// Same sentinel the Settler uses for native ETH (`ETH_ADDRESS`).
pub const NATIVE: Address = address!("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee");

pub const WETH: Address = address!("0bd7d308f8e1639fab988df18a8011f41eacad73");
pub const USDG: Address = address!("5fc5360d0400a0fd4f2af552add042d716f1d168");
pub const UP: Address = address!("57c0e45cb534413d1c20a4240955d6bb250bb4f1");
pub const VIRTUAL: Address = address!("c6911796042b15d7fa4f6cde69e245ddcd3d9c31");
pub const CASHCAT: Address = address!("020bfc650a365f8bb26819deaabf3e21291018b4");
pub const SLVR: Address = address!("791229e3ebd6cfdc3d8157f48722684173c29ad9");

// Multi-hop intermediates worth probing. Routes may use two distinct
// connectors, so the maximum physical path length is three hops.
pub const CONNECTORS: [Address; 3] = [WETH, USDG, VIRTUAL];
pub const MAX_ROUTE_HOPS: usize = 3;

// BNB Smart Chain facts already verified by the terminal's chain-check. They
// are present now so the next protocol slices do not grow another parallel
// address table. The BSC indexer supplies immutable candidate topology; the
// solver still re-proves it against these factories at one canonical RPC block.
pub const BSC_CHAIN_ID: u64 = 56;
pub const WBNB: Address = address!("bb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c");
pub const BSC_USDT: Address = address!("55d398326f99059ff775485246999027b3197955");
pub const BSC_USD1: Address = address!("8d0d000ee44948fc98c9b98a4fa4921476f08b0d");

// Official BSC catalog identities. The indexer is only a candidate directory;
// an enabled BSC snapshot re-proves every returned pool through these exact
// factories at its canonical RPC block before reading state.
pub const BSC_UNIV2_FACTORY: Address = address!("8909dc15e40173ff4699343b6eb8132c65e18ec6");
pub const BSC_UNIV3_FACTORY: Address = address!("db1d10011ad0ff90774d0c6bb92e5c5c8b4461f7");
pub const BSC_PANCAKE_V2_FACTORY: Address = address!("ca143ce32fe78f1f7019d7d551a6402fc5350c73");
pub const BSC_PANCAKE_V3_FACTORY: Address = address!("0bfbcf9fa4f9c56b0f40a671ad40e0805a091865");
pub const BSC_UNIV4_POOL_MANAGER: Address = address!("28e2ea090877bf75740558f6bfb36a5ffee9e9df");
pub const BSC_UNIV2_FEE_PPM: u32 = 3_000;
pub const BSC_PANCAKE_V2_FEE_PPM: u32 = 2_500;

// Native.org Relay RFQ v6 calldata identity, shared by every chain it is on.
pub const NATIVE_RFQ_V6_CONTRACT_REVISION: u64 = 60_000;
pub const NATIVE_RFQ_V6_TRADE_SELECTOR: [u8; 4] = [0x70, 0x83, 0x52, 0x7c];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiscoveryProfile {
    /// The current QuoteLens and discovery graph are verified for this table.
    Robinhood,
    /// Reviewed venue table shared by ordinary EVM deployments. Candidate
    /// pools come from an indexer or the venues' factories (the table's
    /// `CandidateSource`), are re-proved on chain, and mutable state comes
    /// from the RPC.
    IndexedEvm(&'static IndexedEvmDiscovery),
    /// Profile identity is supported, but pool discovery must reject requests.
    Disabled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SolverCapabilities {
    pub quote: bool,
    pub unavailable_reason: Option<&'static str>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IndexedV3Execution {
    pub protocol: CatalogProtocol,
    /// 0x Settler's chain-local Uniswap-v3-fork discriminator.
    pub fork_id: u8,
    /// CREATE2 identity used by that fork inside the Settler. This can differ
    /// from the catalog factory (Pancake V3 is deployed by a separate deployer).
    pub deployer: Address,
    pub init_hash: B256,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SettlerRuntimePolicy {
    /// Every emitted action is bound to one reviewed chain-specific runtime.
    Exact(B256),
    /// Core actions are stable across Settler rotations, while selected newer
    /// Robinhood forks are admitted only on this reviewed runtime.
    Compatible { extended_v3_hash: B256 },
    /// One reviewed build whose only immutable is the Native authorization
    /// signer. The runtime must have `length` bytes, carry the same nonzero
    /// address word at every offset, and hash to `masked_hash` with those
    /// words zeroed. Rotating the signer deploys the same build again, so a
    /// rotation needs no solver release.
    SignerMasked {
        masked_hash: B256,
        length: usize,
        signer_offsets: &'static [usize],
    },
}

impl SettlerRuntimePolicy {
    /// Check a Settler runtime against this policy and return the Native
    /// authorization signer it carries, when the build has one.
    pub fn verify(&self, code: &[u8]) -> anyhow::Result<Option<Address>> {
        match *self {
            Self::Exact(hash) => {
                anyhow::ensure!(
                    alloy_primitives::keccak256(code) == hash,
                    "Settler runtime is not the reviewed build"
                );
                Ok(None)
            }
            Self::Compatible { .. } => Ok(None),
            Self::SignerMasked {
                masked_hash,
                length,
                signer_offsets,
            } => {
                anyhow::ensure!(
                    code.len() == length,
                    "Settler runtime has {} bytes; the reviewed build has {length}",
                    code.len()
                );
                let mut masked = code.to_vec();
                let mut signer = None;
                for &offset in signer_offsets {
                    let word = code
                        .get(offset..offset + 32)
                        .context("Settler signer offset is outside the runtime")?;
                    anyhow::ensure!(
                        word[..12].iter().all(|byte| *byte == 0),
                        "Settler signer word is not an address"
                    );
                    let address = Address::from_slice(&word[12..]);
                    anyhow::ensure!(
                        signer.is_none_or(|seen| seen == address),
                        "Settler signer words disagree"
                    );
                    signer = Some(address);
                    masked[offset..offset + 32].fill(0);
                }
                anyhow::ensure!(
                    alloy_primitives::keccak256(&masked) == masked_hash,
                    "Settler runtime is not the reviewed build"
                );
                let signer = signer.context("Settler build has no signer offset")?;
                anyhow::ensure!(
                    signer != Address::ZERO,
                    "Settler has no Native authorization signer"
                );
                Ok(Some(signer))
            }
        }
    }

    /// A nonzero reviewed hash exists for this policy.
    pub fn is_complete(&self) -> bool {
        match *self {
            Self::Exact(hash)
            | Self::Compatible {
                extended_v3_hash: hash,
            } => hash != B256::ZERO,
            Self::SignerMasked {
                masked_hash,
                length,
                signer_offsets,
            } => {
                masked_hash != B256::ZERO
                    && length > 0
                    && !signer_offsets.is_empty()
                    && signer_offsets.iter().all(|offset| offset + 32 <= length)
            }
        }
    }
}

/// Calldata semantics of the reviewed Settler runtime. Action selectors and
/// ABI word layouts stayed stable across the proportional-unit migration, so
/// the runtime binding must also say how those words and VIP V3 paths are read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SettlerEncoding {
    LegacyBpsVipPathWithSellToken,
    PpmVipPathFromPermit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SettlerProfile {
    pub registry: Address,
    pub registry_token_id: u64,
    pub allowance_holder: Address,
    pub allowance_holder_runtime_hash: B256,
    pub runtime: SettlerRuntimePolicy,
    pub encoding: SettlerEncoding,
    /// Reviewed runtimes that dispatch EKUBOV3 on this chain. Registry
    /// rotations not listed here remain usable for older actions, but Ekubo
    /// pools are withheld from executable snapshots.
    pub ekubo_v3_runtimes: &'static [B256],
    /// Indexed V3 deployments whose CREATE2 identity and fork id are reviewed
    /// for this exact chain adapter. V2 uses the pool address directly.
    pub indexed_v3: &'static [IndexedV3Execution],
    /// PoolManager compiled into this reviewed chain-specific Settler runtime.
    pub univ4_pool_manager: Option<Address>,
    /// The fork id this build's `UNISWAPV4` action takes for Uniswap V4.
    /// Builds released since November 2026 name the V4 fork in the action
    /// (`UNISWAPV4(…, uint8 forkId, …)`, a new selector); older ones take
    /// no fork id. `None` means an older build.
    pub univ4_fork_id: Option<u8>,
    /// The authorization type this build's `executeWithNativeAuthorization`
    /// recovers, when it has that entry. Upstream builds do not: Native RFQ
    /// executes only through a build that does.
    pub native_authorization_typehash: Option<B256>,
}

/// Reviewed Native.org contracts, calldata identity, and endpoint policy for
/// one chain.
///
/// This is deliberately separate from `SettlerProfile`: Native is an external
/// liquidity source called by the Settler, not 0x Settler's Permit2 RFQ action.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeRfqProfile {
    pub api_chain: &'static str,
    pub router_version: u8,
    pub contract_revision: u64,
    pub router: Address,
    pub router_runtime_hash: B256,
    pub pool: Address,
    pub pool_runtime_hash: B256,
    pub credit_vault: Address,
    pub credit_vault_runtime_hash: B256,
    pub trade_selector: [u8; 4],
    /// EIP-5267 domain advertised by the reviewed RFQ pool. Native maker
    /// signatures are chain- and pool-bound through this exact domain.
    pub domain_fields: u8,
    pub domain_name: &'static str,
    pub domain_version: &'static str,
    pub domain_chain_id: u64,
    /// Final user-request endpoints that are reviewed stock tokens. Native is
    /// considered only when at least one normalized endpoint is in this set.
    /// Draft legs and AMM connectors must never influence this decision.
    pub stock_tokens: &'static [Address],
}

impl NativeRfqProfile {
    pub fn allows_endpoints(&self, token_in: Address, token_out: Address) -> bool {
        self.stock_tokens.contains(&token_in) || self.stock_tokens.contains(&token_out)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChainProfile {
    pub key: &'static str,
    pub name: &'static str,
    pub chain_id: u64,
    pub public_rpc: &'static str,
    pub wrapped_native: Address,
    pub stable: Address,
    /// `stable`'s decimals: what one dollar of it is in its smallest unit.
    pub stable_decimals: u8,
    pub connectors: &'static [Address],
    /// Pairs one topology request may name. It is a contract with *this*
    /// chain's indexer, which enforces the same ceiling on its own side, so it
    /// belongs to the profile rather than to the client: two chains run two
    /// indexers and may sit at two budgets while one release train serves both.
    /// Must not exceed `indexer::MAX_PAIRS`, which a test asserts.
    ///
    /// Measured 2026-08-06 against the BSC catalog: a topology request's
    /// latency is flat from 2 to 16 pairs (103-138ms median, no slope) and 16
    /// pairs return 189 pools against a 2,048 cap. The budget rations nothing
    /// it is priced to ration, which is why BSC's is above the original 16.
    pub topology_pair_budget: usize,
    /// Dynamic connectors one pair may route through, over and above the
    /// static skeletons. Each costs two topology pairs, or three when an
    /// endpoint is wrapped native and V4 is on, so this and the budget above
    /// bind together: whichever runs out first sets the admitted count.
    pub dynamic_connector_cap: usize,
    /// How far this chain carries the connector ranking past what the routable
    /// cap above can admit, for screening to price.
    ///
    /// Screening depth decides how much of the ranking gets measured, so it is
    /// the resolution of every coverage number this chain can report — a
    /// candidate below this rank is not declined, it is unexamined. That makes
    /// it a per-chain quantity for the same reason the two budgets above are:
    /// what one screening request can hold depends on that chain's pair shapes
    /// and on how long its indexer takes to answer, and one release train
    /// serves two chains sitting at two different answers.
    ///
    /// A profile whose pair budget cannot afford this many clamps itself down
    /// through the same arithmetic that bounds the routable set, and never
    /// below that set: screening the ranking less deeply than the router routes
    /// it would leave admitted connectors unpriced.
    pub screen_connector_cap: usize,
    /// Tokens this chain permits a dynamic connector to be.
    ///
    /// The ranking orders candidates by measured depth, which is a statement
    /// about liquidity and never about who wrote the token. That is the right
    /// order and the wrong gate: depth is rentable, and a connector is a token
    /// the ROUTER picks on the user's behalf and moves their funds through
    /// mid-trade, so its contract runs while the Settler holds the balance.
    /// The user never named it.
    ///
    /// This list does not classify request endpoints: any token may still
    /// receive an AMM quote, taxed or not, and slippage prices the tax. Native's
    /// separate stock table gates only that optional liquidity source. This
    /// allowlist constrains only what the AMM router may choose for itself.
    ///
    /// Empty admits none, which is the safe default: a chain earns dynamic
    /// connectors by having a reviewed list, rather than by having a ranking.
    pub dynamic_connector_allowlist: &'static [Address],
    pub discovery: DiscoveryProfile,
    /// Transaction adapter. Quote-only chains carry no placeholder execution
    /// identity; `None` is the capability boundary at every entrypoint.
    pub settler: Option<SettlerProfile>,
    /// Optional external Native.org RFQ identity. Runtime enablement still
    /// requires credentials and a deployed Settler in process configuration.
    pub native_rfq: Option<NativeRfqProfile>,
    pub capabilities: SolverCapabilities,
}

impl ChainProfile {
    pub const fn execution_enabled(&self) -> bool {
        self.settler.is_some()
    }

    /// The Native RFQ adapter this profile executes with, or why it cannot:
    /// a deployed Settler, a reviewed Native identity with stock endpoints,
    /// and a Settler build carrying the Native authorization entry. One gate
    /// for `/health`, startup and the RFQ client.
    pub fn native_adapter(&self) -> anyhow::Result<(NativeRfqProfile, SettlerProfile)> {
        anyhow::ensure!(
            self.execution_enabled(),
            "Native RFQ requires Settler execution for {}",
            self.name
        );
        let native = self
            .native_rfq
            .context("chain profile has no reviewed Native RFQ adapter")?;
        anyhow::ensure!(
            !native.stock_tokens.is_empty(),
            "{} has no reviewed Native RFQ stock endpoints",
            self.name
        );
        let settler = self
            .settler
            .context("chain profile has no Settler execution adapter")?;
        anyhow::ensure!(
            settler.native_authorization_typehash.is_some(),
            "{}'s Settler build has no Native authorization entry",
            self.name
        );
        Ok((native, settler))
    }

    /// Whether Native RFQ can execute here, by the same gate startup uses.
    pub fn native_supported(&self) -> bool {
        self.native_adapter().is_ok()
    }

    /// Return the Native adapter only when the user's normalized input/output
    /// pair has a reviewed stock endpoint. Connector membership is irrelevant.
    pub fn native_rfq_for_endpoints(
        &self,
        token_in: Address,
        token_out: Address,
    ) -> Option<NativeRfqProfile> {
        self.native_rfq
            .filter(|native| native.allows_endpoints(token_in, token_out))
    }

    pub const fn indexed_discovery(&self) -> Option<&'static IndexedEvmDiscovery> {
        match self.discovery {
            DiscoveryProfile::IndexedEvm(discovery) => Some(discovery),
            DiscoveryProfile::Robinhood | DiscoveryProfile::Disabled => None,
        }
    }

    /// Whether a pair's candidate pools come from a topology indexer, which
    /// then is a process dependency (`SOLVER_INDEXER_URL`).
    pub const fn needs_indexer(&self) -> bool {
        matches!(
            self.discovery,
            DiscoveryProfile::IndexedEvm(IndexedEvmDiscovery {
                candidates: CandidateSource::Indexer,
                ..
            })
        )
    }

    /// Where a pair's pools come from, as `/health` reports it.
    pub const fn pool_discovery(&self) -> &'static str {
        match self.discovery {
            DiscoveryProfile::Robinhood => "robinhood",
            DiscoveryProfile::IndexedEvm(discovery) => match discovery.candidates {
                CandidateSource::Indexer => "indexer",
                CandidateSource::Factories => "factories",
            },
            DiscoveryProfile::Disabled => "disabled",
        }
    }

    pub fn indexed_v3_execution(&self, protocol: CatalogProtocol) -> Option<IndexedV3Execution> {
        self.settler?
            .indexed_v3
            .iter()
            .copied()
            .find(|execution| execution.protocol == protocol)
    }

    /// Stable protocol ids exposed by `/health`, derived from the selected
    /// discovery adapter so indexed profiles have no second allow-list to keep
    /// synchronized with their venue table.
    pub fn quote_protocols(&self) -> Vec<&'static str> {
        let protocols: Vec<_> = match self.discovery {
            DiscoveryProfile::Robinhood => ROBINHOOD_PROTOCOLS.to_vec(),
            DiscoveryProfile::IndexedEvm(discovery) => discovery
                .quote_protocols()
                .into_iter()
                .map(CatalogProtocol::as_str)
                .collect(),
            DiscoveryProfile::Disabled => Vec::new(),
        };
        protocols
    }

    /// The ERC-20 a token trades as on this chain: the `NATIVE` sentinel is
    /// the wrapped native token, and every other address is itself.
    pub fn erc20_of(&self, token: Address) -> Address {
        if token == NATIVE {
            self.wrapped_native
        } else {
            token
        }
    }
}

const ROBINHOOD_PROTOCOLS: &[&str] = &[
    "univ2",
    "univ3",
    "univ4",
    "up33v2",
    "up33cl",
    "pancakev3",
    "swaphoodv3",
    "gigadexv3",
    "sushiv3",
    "robinswapv3",
    "sheriff",
    "ekubov3",
];

fn load(key: &str) -> ChainProfile {
    crate::manifest::embedded(key).unwrap_or_else(|error| panic!("{error:#}"))
}

/// Every chain this build serves, in manifest order, built from its
/// manifest at first use. One process serves one of them, chosen by
/// `SOLVER_CHAIN` at boot.
pub static CHAIN_PROFILES: LazyLock<Vec<&'static ChainProfile>> = LazyLock::new(|| {
    crate::manifest::SOURCES
        .iter()
        .map(|(key, _)| &*Box::leak(Box::new(load(key))))
        .collect()
});

fn chain(key: &str) -> ChainProfile {
    **CHAIN_PROFILES
        .iter()
        .find(|profile| profile.key == key)
        .unwrap_or_else(|| panic!("no {key} manifest"))
}

/// Named copies of the served profiles, for tests and tools.
pub static ROBINHOOD_PROFILE: LazyLock<ChainProfile> = LazyLock::new(|| chain("robinhood"));
pub static BSC_PROFILE: LazyLock<ChainProfile> = LazyLock::new(|| chain("bsc"));
pub static ETHEREUM_PROFILE: LazyLock<ChainProfile> = LazyLock::new(|| chain("ethereum"));
pub static ROBINHOOD_SETTLER: LazyLock<SettlerProfile> =
    LazyLock::new(|| ROBINHOOD_PROFILE.settler.expect("Robinhood has a Settler"));
pub static BSC_SETTLER: LazyLock<SettlerProfile> =
    LazyLock::new(|| BSC_PROFILE.settler.expect("BSC has a Settler"));
/// BSC's reviewed Native identity. Its upstream Settler has no Native
/// authorization entry, so Native does not execute there.
pub static BSC_NATIVE_RFQ: LazyLock<NativeRfqProfile> =
    LazyLock::new(|| BSC_PROFILE.native_rfq.expect("BSC has a Native identity"));
pub static BSC_INDEXED_DISCOVERY: LazyLock<IndexedEvmDiscovery> = LazyLock::new(|| {
    *BSC_PROFILE
        .indexed_discovery()
        .expect("BSC has a venue table")
});

/// Whether `profile` is exactly one this build reviewed: a compiled profile,
/// or in tests the fixture one.
pub fn is_reviewed_profile(profile: &ChainProfile) -> bool {
    #[cfg(any(test, feature = "fixtures"))]
    if *profile == fixture::FIXTURE_PROFILE {
        return true;
    }
    CHAIN_PROFILES.iter().any(|reviewed| **reviewed == *profile)
}

pub fn profile_by_key(key: &str) -> anyhow::Result<&'static ChainProfile> {
    let value = key.trim();
    CHAIN_PROFILES
        .iter()
        .copied()
        .find(|profile| profile.key == value)
        .with_context(|| {
            format!(
                "SOLVER_CHAIN={value:?} is invalid; expected one of: {}",
                CHAIN_PROFILES
                    .iter()
                    .map(|profile| profile.key)
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })
}

/// Token-level route skeletons in deterministic preference order: direct,
/// one connector, then every ordered pair of distinct connectors.
pub fn route_token_paths(token_in: Address, token_out: Address) -> Vec<Vec<Address>> {
    route_token_paths_for(&CONNECTORS, token_in, token_out)
}

pub fn route_token_paths_for(
    connectors: &[Address],
    token_in: Address,
    token_out: Address,
) -> Vec<Vec<Address>> {
    let mut paths = vec![vec![token_in, token_out]];
    for &connector in connectors {
        if connector != token_in && connector != token_out {
            paths.push(vec![token_in, connector, token_out]);
        }
    }
    for &first in connectors {
        if first == token_in || first == token_out {
            continue;
        }
        for &second in connectors {
            if second != token_in && second != token_out && second != first {
                paths.push(vec![token_in, first, second, token_out]);
            }
        }
    }
    paths
}

/// Unique discovery edges required by all route skeletons. First-seen
/// direction is retained so pool discovery and route tie-breaking stay stable.
#[allow(dead_code)] // Robinhood compatibility helper for diagnostics/tests.
pub fn route_pairs(token_in: Address, token_out: Address) -> Vec<(Address, Address)> {
    route_pairs_for(&CONNECTORS, token_in, token_out)
}

/// Profile-bound discovery edges. Discovery and route construction must use
/// the same connector table or a route can be considered by the solver even
/// though its constituent pools were never probed.
pub fn route_pairs_for(
    connectors: &[Address],
    token_in: Address,
    token_out: Address,
) -> Vec<(Address, Address)> {
    let mut pairs = Vec::new();
    for path in route_token_paths_for(connectors, token_in, token_out) {
        for edge in path.windows(2) {
            let pair = (edge[0], edge[1]);
            let canonical = if pair.0 < pair.1 {
                pair
            } else {
                (pair.1, pair.0)
            };
            if !pairs.iter().any(|&(a, b)| {
                let existing = if a < b { (a, b) } else { (b, a) };
                existing == canonical
            }) {
                pairs.push(pair);
            }
        }
    }
    pairs
}

// Official Uniswap deployments on 4663.
pub const UNIV3_FACTORY: Address = address!("1f7d7550b1b028f7571e69a784071f0205fd2efa");
pub const UNIV2_FACTORY: Address = address!("8bceaa40b9acdfaedf85adf4ff01f5ad6517937f");
pub const UNIV3_QUOTER: Address = address!("33e885ed0ec9bf04ecfb19341582aadcb4c8a9e7"); // QuoterV2, validation only

// UP33 (ve(3,3), Slipstream-style CL).
pub const UP33_CL_FACTORY: Address = address!("1ac9db4a2608ba45d6127b1737949b51bb54b7f3");
pub const UP33_CL_QUOTER: Address = address!("03983ab2c057a2eac211ff01738a1e49ff325b49"); // validation only

// UP33 v2 (Solidly-style). Only volatile pools are routed: they settle through
// the plain UNISWAPV2 action, whereas stable pools need VELODROME (none exist
// on this factory today). Fees are per-pool, read via getFee(pool, stable).
pub const UP33_V2_FACTORY: Address = address!("fa5429aeba338bea2bfcc1b9a889862ee395bc28");

pub const UNIV3_FEE_TIERS: [u32; 4] = [100, 500, 3000, 10000];

// Settler-supported V3 forks — univ3 pools with
// identical swap math, settled through the same UNISWAPV3 actions under their
// own fork ids. Pool addresses are derived locally from the DEPLOYER + init
// hash (exactly the CREATE2 inputs the Settler verifies against) and probed
// directly — no factory round trip. poolId slot carries the fee tier.
// Constants from 0x-settler at commit f5744a9; pool derivations are pinned by
// chain-verified test vectors.
pub const PANCAKE_V3_DEPLOYER: Address = address!("41ff9aa7e16b8b1a8a8dc4f0efacd93d02d071c9");
pub const PANCAKE_V3_INIT: B256 =
    b256!("6ce8eb472fa82df5469c6ab6d485f17c3ad13c8cd7af59b3d4a8026c5ce0f7e2");
pub const FORK_PANCAKE: u8 = 1;
pub const SWAPHOOD_V3_DEPLOYER: Address = address!("cb42a120795ca98f762fdccf43cc4ab6d62bf1b2");
pub const SWAPHOOD_V3_INIT: B256 =
    b256!("9fca60359d787088d07f1c02f8be93ad13a3d45923e6d60b9032f18b5ac973aa");
pub const FORK_SWAPHOOD: u8 = 42;
// Existing Pancake/SwapHood tier set (tick spacing is read from each pool).
pub const CLONE_FEE_TIERS: [u32; 4] = [100, 500, 2500, 10000];

pub const SUSHI_V3_DEPLOYER: Address = address!("e51960f1b45f1c9fb6d166e6a884f866fc70433b");
pub const SUSHI_V3_INIT: B256 =
    b256!("e34f199b19b2b4f47f68442619d555527d244f78a3297ea89325f843f87b8b54");
pub const FORK_SUSHI: u8 = 2;
pub const SUSHI_V3_FEE_TIERS: [u32; 3] = [500, 3000, 10000];

pub const ROBINSWAP_V3_DEPLOYER: Address = address!("ea561e058313b96011e5070ca7d0f027a44e3748");
pub const ROBINSWAP_V3_INIT: B256 =
    b256!("7ef2b01a451cbf890790278981756372e549443802ece149dc0b592cbc114ee9");
pub const FORK_ROBINSWAP: u8 = 43;
pub const ROBINSWAP_V3_FEE_TIERS: [u32; 5] = [100, 500, 2500, 3000, 10000];

pub const GIGADEX_V3_DEPLOYER: Address = address!("5952f5d501a130da00fa8fe2257d8b35ddc0a57b");
pub const GIGADEX_V3_INIT: B256 =
    b256!("fd3b64c598013443d9bb6db0da30281063a1a31138e23b55395d600154969b68");
pub const FORK_GIGADEX: u8 = 45;
pub const GIGADEX_V3_FEE_TIERS: [u32; 8] = [100, 200, 500, 1000, 2000, 3000, 10000, 20000];

// Validation-only QuoterV2 deployments; production reads pool state directly.
pub const GIGADEX_V3_QUOTER: Address = address!("78cd9561bd33e5a3bdb6d4a92ce67cb535289655");
pub const SUSHI_V3_QUOTER: Address = address!("3e290e5e01818002a0b672148bdc7514d861c7b3");
pub const ROBINSWAP_V3_QUOTER: Address = address!("3c83ef839884118a3acf29fd18cb393ef9d429f9");

// Sheriff — Algebra Integral, wired into the LIVE Settler as univ3-fork 41
// (chain-verified: the deployer's factory constant is present in bytecode).
//
// SHERIFF_DEPLOYER is what the Settler CREATE2s against. It is NOT the pool's
// own `factory()` — Algebra splits the two, and the pool reports the factory
// while the deployer creates it. Derivation is chain-verified against the live
// WETH/USDG pool.
//
// Algebra has ONE pool per pair (no fee tier in the salt). The Settler models
// that with poolId 0: `_toPool` shortens the salt to 2 words when poolId is
// zero, giving keccak(abi.encode(token0, token1)).
pub const SHERIFF_DEPLOYER: Address = address!("9ac30d72168a4498ae5c80226f4d3c86278e8f80");
pub const SHERIFF_INIT: B256 =
    b256!("62441ebe4e4315cf3d49d5957f94d66b253dbabe7006f34ad7f70947e60bf15c");
pub const FORK_SHERIFF: u8 = 41;

// Uniswap V4 singleton. Pools are PoolKey hashes, state is read straight out
// of PoolManager storage via extsload (StateLibrary layout, pools mapping at
// slot 6 — chain-verified). Routable pools are those whose swap amounts the
// CL math fully determines: any hook without swap-time permissions (see
// V4_SWAP_HOOK_FLAGS), protocol fees folded in per direction (see
// `v4_swap_fee`). Hooks WITH swap-time permissions can reprice arbitrarily or
// revert per-sender and stay excluded.
pub const V4_POOL_MANAGER: Address = address!("8366a39cc670b4001a1121b8f6a443a643e40951");
pub const V4_POOLS_SLOT: u64 = 6;
// Initialize(bytes32 id, address currency0, address currency1, uint24 fee,
// int24 tickSpacing, address hooks, uint160 sqrtPriceX96, int24 tick) —
// currencies are indexed, so per-pair getLogs enumerates the full key set.
pub const V4_INIT_TOPIC: B256 =
    b256!("dd466e674ea557f56295e2d0218a125ea4b4f0f6f3307b95f85e6110838d6438");
/// Event-derived keys above this fee are spam (WETH/USDG alone has pools at
/// 39% and 95% fees); nothing above 10% can ever win a marginal chunk.
pub const V4_MAX_FEE_PPM: u32 = 100_000;
// A hook address carries its permission set in its LOW 14 BITS (Hooks.sol);
// the PoolManager consults ONLY these bits to decide whether the hook takes
// part in a swap. A hook with none of the four swap bits is never called
// during a swap — it cannot reprice, take a delta, or revert the swap — so
// the CL math stays wei-exact and the pool is routable. beforeSwap 1<<7 |
// afterSwap 1<<6 | beforeSwapReturnsDelta 1<<3 | afterSwapReturnsDelta 1<<2.
// (isValidHookAddress makes the delta bits imply the callback bits; both are
// checked anyway.)
pub const V4_SWAP_HOOK_FLAGS: u32 = (1 << 7) | (1 << 6) | (1 << 3) | (1 << 2);
/// LPFeeLibrary.DYNAMIC_FEE_FLAG: a PoolKey fee of exactly this value marks a
/// dynamic-fee pool whose live lpFee lives in slot0. Only a beforeSwap hook
/// can override that fee per swap, and those pools are excluded by
/// V4_SWAP_HOOK_FLAGS — so slot0's lpFee is exact at the snapshot block.
pub const V4_DYNAMIC_FEE_FLAG: u32 = 0x80_0000;
// (fee, tickSpacing) fallback grid — only used when the RPC cannot serve the
// filtered Initialize query (hookless keys only; hooked pools are reachable
// solely through event discovery). The live ladder is much richer than this
// (0x routed 20% of a 500-WETH trade through a 450ppm/9 pool).
pub const V4_KEYS: [(u32, i32); 4] = [(100, 1), (500, 10), (3000, 60), (10000, 200)];

pub fn univ3_tier_spacing(fee: u32) -> i32 {
    match fee {
        100 => 1,
        500 => 10,
        3000 => 60,
        10000 => 200,
        _ => unreachable!("unknown univ3 fee tier {fee}"),
    }
}

pub const UNIV2_FEE_BPS: u32 = 30;

// ArbSys precompile (Arbitrum lineage): the only in-EVM source of the L2
// block number — `block.number` here means the parent chain.
pub const ARBSYS: Address = address!("0000000000000000000000000000000000000064");

// 0x Settler (RobinHood build). The Settler address rotates — always resolved
// live from the registry (`ownerOf(2)`), never hardcoded.
pub const SETTLER_REGISTRY: Address = address!("00000000000004533fe15556b1e086bb1a72ceae");
pub const ALLOWANCE_HOLDER: Address = address!("0000000000001ff3684f28c67538d4d072c22734");
#[allow(dead_code)]
pub const PERMIT2: Address = address!("000000000022d473030f116ddee9f6b43ac78ba3");

// univ3-fork ids wired in src/chains/RobinHood/Common.sol.
pub const FORK_UNIV3: u8 = 0; // poolId slot carries the fee tier
pub const FORK_UP33: u8 = 40; // poolId slot carries the tickSpacing (ERC1167 pools)

// A fee above this is a fat-fingered SOLVER_FEE_BPS, not a fee.
pub const MAX_FEE_BPS: u32 = 1000;
pub const MAX_POSITIVE_SLIPPAGE_BPS: u32 = 10_000;

pub fn env_or(key: &str, default: &str) -> anyhow::Result<String> {
    match std::env::var(key) {
        Ok(value) => Ok(value),
        Err(std::env::VarError::NotPresent) => Ok(default.to_string()),
        Err(error) => Err(anyhow::anyhow!("reading {key}: {error}")),
    }
}

/// Test-only identities: one chain profile combining what no shipped profile
/// combines — pools named by factories, a Settler build carrying the Native
/// authorization entry (`SettlerRuntimePolicy::SignerMasked`), and a Native
/// RFQ adapter. The values are a retired deployment's, kept so recorded
/// vectors (`crates/rfq/fixtures/native_authorization.json`) still verify; no
/// runtime path can select this profile.
#[cfg(any(test, feature = "fixtures"))]
pub use fixture::*;

#[cfg(any(test, feature = "fixtures"))]
#[allow(dead_code)]
pub mod fixture {
    use super::*;
    use crate::catalog::{CatalogVenue, ReadinessPolicy};

    pub const FIXTURE_CHAIN_ID: u64 = 2_818;
    pub const FIXTURE_PUBLIC_RPC: &str = "https://rpc.fixture.invalid";
    pub const FIXTURE_WETH: Address = address!("5300000000000000000000000000000000000011");
    pub const FIXTURE_USDT0: Address = address!("e7cd86e13ac4309349f30b3435a9d337750fc82d");
    pub const FIXTURE_CONNECTORS: [Address; 2] = [FIXTURE_WETH, FIXTURE_USDT0];

    pub const FIXTURE_USDC: Address = address!("cfb1186f4e93d60e60a8bdd997427d1f33bc372b");
    pub const FIXTURE_USDT_BRIDGED: Address = address!("c7d67a9cbb121b3b0b9c053dd9f469523243379a");
    pub const FIXTURE_BGB: Address = address!("389c08bc23a7317000a1fd76c7c5b0cb0b4640b5");

    pub const FIXTURE_RESIDENT_CONNECTORS: [Address; 3] =
        [FIXTURE_USDC, FIXTURE_USDT_BRIDGED, FIXTURE_BGB];

    pub const FIXTURE_V2_FACTORY: Address = address!("8d2a8b8f7d200d75bf5f9e84e01f9272f90efb8b");
    pub const FIXTURE_V2_FEE_PPM: u32 = 3_500;

    pub const FIXTURE_V3_FACTORY: Address = address!("ff8578c2949148a6f19b7958ae86caab2779cddd");

    pub const FIXTURE_V3_FORK_ID: u8 = 200;
    pub const FIXTURE_V3_INIT_HASH: B256 =
        b256!("e34f199b19b2b4f47f68442619d555527d244f78a3297ea89325f843f87b8b54");

    pub const FIXTURE_SETTLER_REGISTRY: Address =
        address!("4aadb21103d76c0165acc50680c499be7a11f65e");
    pub const FIXTURE_SETTLER_TOKEN_ID: u64 = 2;
    pub const FIXTURE_ALLOWANCE_HOLDER: Address =
        address!("d6b6a3ca0cd07cc894ba4edbda05eaf0f8f8c609");
    pub const FIXTURE_ALLOWANCE_HOLDER_RUNTIME_HASH: B256 =
        b256!("99f5e8edaceacfdd183eb5f1da8a7757b322495b80cf7928db289a1b1a09f799");

    pub const FIXTURE_SETTLER_RUNTIME: SettlerRuntimePolicy = SettlerRuntimePolicy::SignerMasked {
        masked_hash: b256!("5b9963b813565d930dd66d019372bcf11d7e7d6e9a08dc5c60e33e3acba5974c"),
        length: 11_300,
        signer_offsets: &[625, 1_002],
    };

    pub const FIXTURE_NATIVE_RFQ_ROUTER_V6: Address =
        address!("dbb3f5f906fda25784a8ed1dd208cf3772efe6cb");
    pub const FIXTURE_NATIVE_RFQ_POOL_V6: Address =
        address!("80096680894326faba21e298806a84826dca3a83");
    pub const FIXTURE_NATIVE_CREDIT_VAULT: Address =
        address!("4df7557734b382eb542bea6c74786d398df4cc19");
    pub const FIXTURE_NATIVE_RFQ_ROUTER_V6_RUNTIME_HASH: B256 =
        b256!("67db470cfe480dc53775815aac228d13b0d2945ccc5e3e4b5d75b6570fe76be2");
    pub const FIXTURE_NATIVE_RFQ_POOL_V6_RUNTIME_HASH: B256 =
        b256!("63a2456bd948ba0793c4e684282e59ba0f164f67f7af7082f92961dad0b5be8d");
    pub const FIXTURE_NATIVE_CREDIT_VAULT_RUNTIME_HASH: B256 =
        b256!("1c09f4c17ea8a1dd11eb2bfa2640ca16c98f6f50b3aa7fcb74109edc8df374ae");

    pub const FIXTURE_NATIVE_STOCK_TOKENS: [Address; 0] = [];

    pub const FIXTURE_V3_FEE_TIERS: [u32; 4] = [100, 500, 3_000, 10_000];

    pub const FIXTURE_VENUES: [CatalogVenue; 2] = [
        CatalogVenue::V2 {
            protocol: CatalogProtocol::UNIV2,
            factory: FIXTURE_V2_FACTORY,
            fee_ppm: FIXTURE_V2_FEE_PPM,
            quote: true,
        },
        CatalogVenue::V3 {
            protocol: CatalogProtocol::UNIV3,
            factory: FIXTURE_V3_FACTORY,
            verify_pool_spacing: false,
            fee_tiers: &FIXTURE_V3_FEE_TIERS,
            quote: true,
        },
    ];

    pub const FIXTURE_DISCOVERY: IndexedEvmDiscovery = IndexedEvmDiscovery {
        schema_version: 2,
        readiness: ReadinessPolicy::RequestedVenues,
        venues: &FIXTURE_VENUES,
        candidates: CandidateSource::Factories,
    };

    pub const FIXTURE_V3_EXECUTION: [IndexedV3Execution; 1] = [IndexedV3Execution {
        protocol: CatalogProtocol::UNIV3,
        fork_id: FIXTURE_V3_FORK_ID,
        deployer: FIXTURE_V3_FACTORY,
        init_hash: FIXTURE_V3_INIT_HASH,
    }];

    /// keccak256("MorphNativeAuthorizationV1(uint256 chainId,address settler,
    /// address taker,address beneficiary,bytes32 executionHash,uint256 deadline)"),
    /// the type the recorded vectors were signed under.
    pub const FIXTURE_NATIVE_AUTHORIZATION_TYPEHASH: B256 =
        b256!("f1b70c5105f2c900fc2d52a933c7664d9bc4d771651a135b9b4f922e32d0dbd5");

    /// `settler` as a build with the Native authorization entry, for tests
    /// that encode Native on a chain whose reviewed build lacks it.
    pub const fn with_native_entry(settler: SettlerProfile) -> SettlerProfile {
        SettlerProfile {
            native_authorization_typehash: Some(FIXTURE_NATIVE_AUTHORIZATION_TYPEHASH),
            ..settler
        }
    }

    pub const FIXTURE_SETTLER: SettlerProfile = SettlerProfile {
        registry: FIXTURE_SETTLER_REGISTRY,
        registry_token_id: FIXTURE_SETTLER_TOKEN_ID,
        allowance_holder: FIXTURE_ALLOWANCE_HOLDER,
        allowance_holder_runtime_hash: FIXTURE_ALLOWANCE_HOLDER_RUNTIME_HASH,
        runtime: FIXTURE_SETTLER_RUNTIME,
        encoding: SettlerEncoding::PpmVipPathFromPermit,
        ekubo_v3_runtimes: &[],
        indexed_v3: &FIXTURE_V3_EXECUTION,
        univ4_pool_manager: None,
        univ4_fork_id: None,
        native_authorization_typehash: Some(FIXTURE_NATIVE_AUTHORIZATION_TYPEHASH),
    };

    pub const FIXTURE_NATIVE_RFQ: NativeRfqProfile = NativeRfqProfile {
        api_chain: "fixture",
        router_version: 6,
        contract_revision: NATIVE_RFQ_V6_CONTRACT_REVISION,
        router: FIXTURE_NATIVE_RFQ_ROUTER_V6,
        router_runtime_hash: FIXTURE_NATIVE_RFQ_ROUTER_V6_RUNTIME_HASH,
        pool: FIXTURE_NATIVE_RFQ_POOL_V6,
        pool_runtime_hash: FIXTURE_NATIVE_RFQ_POOL_V6_RUNTIME_HASH,
        credit_vault: FIXTURE_NATIVE_CREDIT_VAULT,
        credit_vault_runtime_hash: FIXTURE_NATIVE_CREDIT_VAULT_RUNTIME_HASH,
        trade_selector: NATIVE_RFQ_V6_TRADE_SELECTOR,
        domain_fields: 0x0f,
        domain_name: "Native RFQ Pool",
        domain_version: "1",
        domain_chain_id: FIXTURE_CHAIN_ID,
        stock_tokens: &FIXTURE_NATIVE_STOCK_TOKENS,
    };

    pub const FIXTURE_PROFILE: ChainProfile = ChainProfile {
        key: "fixture",
        name: "Fixture Chain",
        chain_id: FIXTURE_CHAIN_ID,
        public_rpc: FIXTURE_PUBLIC_RPC,
        wrapped_native: FIXTURE_WETH,
        stable: FIXTURE_USDT0,
        stable_decimals: 6,
        connectors: &FIXTURE_CONNECTORS,
        topology_pair_budget: 8,
        dynamic_connector_cap: 1,
        screen_connector_cap: 1,
        dynamic_connector_allowlist: &[],
        discovery: DiscoveryProfile::IndexedEvm(&FIXTURE_DISCOVERY),
        settler: Some(FIXTURE_SETTLER),
        native_rfq: Some(FIXTURE_NATIVE_RFQ),
        capabilities: SolverCapabilities {
            quote: true,
            unavailable_reason: None,
        },
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connector_set_replaces_up_with_virtual() {
        assert_eq!(CONNECTORS, [WETH, USDG, VIRTUAL]);
        assert!(!CONNECTORS.contains(&UP));
    }

    #[test]
    fn profiles_are_closed_to_the_compiled_runtime_set() {
        // The served profiles are exactly the embedded manifests, in order.
        let expected: Vec<&ChainProfile> = crate::manifest::SOURCES
            .iter()
            .map(|(key, _)| profile_by_key(key).unwrap())
            .collect();
        assert_eq!(CHAIN_PROFILES.as_slice(), expected.as_slice());
        assert_eq!(profile_by_key(" bsc ").unwrap(), &*BSC_PROFILE);
        assert_eq!(profile_by_key("ethereum").unwrap(), &*ETHEREUM_PROFILE);
        assert_eq!(profile_by_key("robinhood").unwrap(), &*ROBINHOOD_PROFILE);
        for refused in ["", "morph", "56", "BSC", "mainnet", "1"] {
            assert!(profile_by_key(refused).is_err(), "{refused:?} was accepted");
        }
        for profile in CHAIN_PROFILES.iter() {
            assert!(profile.capabilities.quote);
            assert!(profile.execution_enabled());
        }
        BSC_INDEXED_DISCOVERY.validate().unwrap();
        assert!(BSC_PROFILE.needs_indexer());
        assert_eq!(BSC_PROFILE.pool_discovery(), "indexer");
        assert!(!ROBINHOOD_PROFILE.needs_indexer());
        assert_eq!(ROBINHOOD_PROFILE.pool_discovery(), "robinhood");
        assert!(!ETHEREUM_PROFILE.needs_indexer());
        assert_eq!(ETHEREUM_PROFILE.pool_discovery(), "factories");
    }

    /// The Ethereum facts crates/chain/manifest/ethereum.md records as read from the
    /// chain: the Settler build is a ppm one, and its V3 fork table routes
    /// fork 0, 1 and 2 to Uniswap, PancakeSwap and Sushi.
    #[test]
    fn the_ethereum_profile_is_the_one_read_from_the_chain() {
        let profile = &*ETHEREUM_PROFILE;
        assert_eq!(profile.chain_id, 1);
        assert!(!profile.native_supported());
        let settler = profile.settler.expect("Ethereum executes through Settler");
        assert_eq!(settler.encoding, SettlerEncoding::PpmVipPathFromPermit);
        assert_eq!(
            settler.runtime,
            SettlerRuntimePolicy::Exact(alloy_primitives::b256!(
                "ffdce6016c0efe4a2503f44f26cefdca5b0a563455b4712081078d933623ff34"
            ))
        );
        let forks: Vec<(&str, u8)> = settler
            .indexed_v3
            .iter()
            .map(|fork| (fork.protocol.as_str(), fork.fork_id))
            .collect();
        assert_eq!(forks, [("univ3", 0), ("pancakev3", 1), ("sushiv3", 2)]);
        let DiscoveryProfile::IndexedEvm(discovery) = profile.discovery else {
            panic!("Ethereum's factories name its pools");
        };
        assert_eq!(discovery.candidates, CandidateSource::Factories);
        let venues: Vec<&str> = discovery
            .venues
            .iter()
            .map(|venue| venue.protocol().as_str())
            .collect();
        assert_eq!(
            venues,
            ["univ2", "sushiv2", "univ3", "sushiv3", "pancakev3"]
        );
    }

    #[test]
    fn manifests_build_the_reviewed_profiles() {
        assert_eq!(
            crate::manifest::embedded("robinhood").unwrap(),
            *ROBINHOOD_PROFILE
        );
        assert_eq!(crate::manifest::embedded("bsc").unwrap(), *BSC_PROFILE);
        // The values the tests and tools name directly.
        assert_eq!(BSC_PROFILE.chain_id, BSC_CHAIN_ID);
        assert_eq!(BSC_PROFILE.wrapped_native, WBNB);
        assert_eq!(BSC_PROFILE.stable, BSC_USDT);
        assert_eq!(BSC_PROFILE.connectors, [WBNB, BSC_USDT, BSC_USD1]);
        assert_eq!(ROBINHOOD_PROFILE.chain_id, CHAIN_ID);
        assert_eq!(ROBINHOOD_PROFILE.public_rpc, PUBLIC_RPC);
        assert_eq!(ROBINHOOD_PROFILE.wrapped_native, WETH);
        assert_eq!(ROBINHOOD_PROFILE.stable, USDG);
        assert_eq!(ROBINHOOD_PROFILE.connectors, CONNECTORS);
        assert_eq!(ROBINHOOD_SETTLER.registry, SETTLER_REGISTRY);
        assert_eq!(ROBINHOOD_SETTLER.allowance_holder, ALLOWANCE_HOLDER);
        assert_eq!(BSC_SETTLER.univ4_pool_manager, Some(BSC_UNIV4_POOL_MANAGER));
        let venue = |id| BSC_INDEXED_DISCOVERY.venue(id).unwrap();
        assert_eq!(venue(CatalogProtocol::UNIV2).identity(), BSC_UNIV2_FACTORY);
        assert_eq!(venue(CatalogProtocol::UNIV3).identity(), BSC_UNIV3_FACTORY);
        assert_eq!(
            venue(CatalogProtocol::PANCAKEV2).identity(),
            BSC_PANCAKE_V2_FACTORY
        );
        assert_eq!(
            venue(CatalogProtocol::PANCAKEV3).identity(),
            BSC_PANCAKE_V3_FACTORY
        );
        assert_eq!(
            venue(CatalogProtocol::UNIV2).v2_fee_ppm(),
            Some(BSC_UNIV2_FEE_PPM)
        );
        assert_eq!(
            venue(CatalogProtocol::PANCAKEV2).v2_fee_ppm(),
            Some(BSC_PANCAKE_V2_FEE_PPM)
        );
    }

    #[test]
    fn native_endpoint_policy_is_stock_only_and_connector_independent() {
        let future_connectors = [WBNB, BSC_USDT, BSC_USD1, BSC_NATIVE_RFQ.stock_tokens[0]];
        let profile = ChainProfile {
            connectors: Box::leak(Box::new(future_connectors)),
            native_rfq: Some(*BSC_NATIVE_RFQ),
            ..*BSC_PROFILE
        };
        let stock = BSC_NATIVE_RFQ.stock_tokens[0];

        assert!(profile.connectors.contains(&stock));
        assert!(
            profile.native_rfq_for_endpoints(WBNB, BSC_USDT).is_none(),
            "a stock connector must not enable Native for non-stock endpoints"
        );
        assert!(profile.native_rfq_for_endpoints(WBNB, stock).is_some());
        assert!(profile.native_rfq_for_endpoints(stock, BSC_USDT).is_some());
        let empty = ChainProfile {
            native_rfq: Some(NativeRfqProfile {
                stock_tokens: &[],
                ..*BSC_NATIVE_RFQ
            }),
            ..*BSC_PROFILE
        };
        assert!(
            empty.native_rfq_for_endpoints(WBNB, stock).is_none(),
            "an empty reviewed stock list must fail closed"
        );
    }

    #[test]
    fn native_stock_token_lists_are_canonical_sets() {
        for native in [*BSC_NATIVE_RFQ] {
            let mut seen = Vec::new();
            for token in native.stock_tokens {
                assert_ne!(*token, Address::ZERO);
                assert_ne!(*token, NATIVE);
                assert!(seen.iter().all(|seen_token| seen_token != token));
                seen.push(*token);
            }
        }
    }

    /// The per-profile budget is a contract with that chain's indexer, and
    /// A dynamic connector can only ever be a token the chain permits, and the
    /// static skeleton's own connectors have to be in that set — a chain whose
    /// profile routes a token the allowlist would refuse is contradicting
    /// itself about what it trusts.
    #[test]
    fn every_static_connector_is_permitted_as_a_dynamic_one() {
        for profile in CHAIN_PROFILES.iter() {
            if profile.dynamic_connector_allowlist.is_empty() {
                continue; // admits none; nothing to be consistent with
            }
            for connector in profile.connectors {
                assert!(
                    profile.dynamic_connector_allowlist.contains(connector),
                    "{} routes {connector:#x} statically but would refuse it dynamically",
                    profile.key,
                );
            }
        }
    }

    /// The list is a set, and a duplicate would read as two reviews of one
    /// token.
    #[test]
    fn the_connector_allowlist_carries_no_duplicates() {
        for profile in CHAIN_PROFILES.iter() {
            let mut seen = profile.dynamic_connector_allowlist.to_vec();
            seen.sort_unstable();
            let total = seen.len();
            seen.dedup();
            assert_eq!(seen.len(), total, "{} lists a connector twice", profile.key);
        }
    }

    /// The arithmetic that decides how many connectors a shape can afford,
    /// pinned against the four BSC shapes section 25 measured in production.
    /// Reading them here is what makes a budget change reviewable.
    ///
    /// With the cap at eight it binds on none of them, and every entry is the
    /// pair budget's own answer. The invariant that matters is the one asserted
    /// second: whatever the shape, the request the selection forces stays inside
    /// the budget, which is what `indexer::MAX_PAIRS` refuses at the wire.
    #[test]
    fn bsc_budget_decides_the_shortlist_on_every_measured_shape() {
        let cost_wrapped = 3usize; // an endpoint is WBNB and V4 is on
        let cost_plain = 2usize;
        for (name, base, cost, want) in [
            ("WBNB->USDT", 5usize, cost_wrapped, 6usize),
            ("WBNB->XRP", 9, cost_wrapped, 5),
            ("BTCB->USDT", 9, cost_plain, 7),
            ("USDC->BTCB", 14, cost_plain, 5),
        ] {
            let admitted = BSC_PROFILE
                .dynamic_connector_cap
                .min(BSC_PROFILE.topology_pair_budget.saturating_sub(base) / cost);
            assert_eq!(admitted, want, "{name} admits {admitted}, wanted {want}");
            assert!(
                admitted < BSC_PROFILE.dynamic_connector_cap,
                "{name} is capped rather than budgeted, so the cap is doing the sizing"
            );
            assert!(
                base + admitted * cost <= BSC_PROFILE.topology_pair_budget,
                "{name} would force {} pairs against a {} budget",
                base + admitted * cost,
                BSC_PROFILE.topology_pair_budget
            );
        }
    }

    #[test]
    fn route_skeletons_use_the_selected_profile_connectors() {
        let token_in = Address::repeat_byte(0x11);
        let token_out = Address::repeat_byte(0x22);
        let paths = route_token_paths_for(BSC_PROFILE.connectors, token_in, token_out);
        assert_eq!(paths.iter().filter(|path| path.len() == 3).count(), 3);
        assert!(
            paths
                .iter()
                .any(|path| path == &vec![token_in, WBNB, token_out])
        );
        assert!(!paths.iter().any(|path| path.contains(&WETH)));

        let pairs = route_pairs_for(BSC_PROFILE.connectors, token_in, token_out);
        let contains = |pair: &(Address, Address), token| pair.0 == token || pair.1 == token;
        assert!(pairs.iter().any(|pair| contains(pair, WBNB)));
        assert!(pairs.iter().any(|pair| contains(pair, BSC_USDT)));
        assert!(pairs.iter().any(|pair| contains(pair, BSC_USD1)));
        assert!(!pairs.iter().any(|pair| contains(pair, WETH)));
        assert!(!pairs.iter().any(|pair| contains(pair, USDG)));
        assert!(!pairs.iter().any(|pair| contains(pair, VIRTUAL)));
    }

    #[test]
    fn route_skeletons_cover_simple_paths_through_three_hops() {
        let token_in = Address::repeat_byte(0x11);
        let token_out = Address::repeat_byte(0x22);
        let paths = route_token_paths(token_in, token_out);

        assert_eq!(paths.iter().filter(|path| path.len() == 2).count(), 1);
        assert_eq!(paths.iter().filter(|path| path.len() == 3).count(), 3);
        assert_eq!(paths.iter().filter(|path| path.len() == 4).count(), 6);
        assert!(paths.iter().all(|path| path.len() - 1 <= MAX_ROUTE_HOPS));
        assert!(paths.iter().all(|path| {
            let mut unique = path.clone();
            unique.sort_unstable();
            unique.dedup();
            unique.len() == path.len()
        }));

        let pairs = route_pairs(token_in, token_out);
        assert_eq!(pairs.len(), 10);
        for (i, &(a, b)) in pairs.iter().enumerate() {
            let canonical = if a < b { (a, b) } else { (b, a) };
            assert!(
                !pairs[..i]
                    .iter()
                    .any(|&(x, y)| { (if x < y { (x, y) } else { (y, x) }) == canonical })
            );
        }
        assert_eq!(route_pairs(WETH, token_out).len(), 6);
    }

    /// The one native-to-wrapped mapping: on every profile `NATIVE` is that
    /// chain's wrapped native token, and any other address, zero included,
    /// is itself.
    #[test]
    fn erc20_of_maps_only_native_to_the_wrapped_token() {
        for profile in CHAIN_PROFILES.iter() {
            assert_eq!(
                profile.erc20_of(NATIVE),
                profile.wrapped_native,
                "{}",
                profile.key
            );
            for token in [
                profile.wrapped_native,
                profile.stable,
                Address::ZERO,
                Address::repeat_byte(0x11),
            ] {
                assert_eq!(profile.erc20_of(token), token, "{}", profile.key);
            }
        }
        assert_eq!(BSC_PROFILE.erc20_of(NATIVE), WBNB);
        assert_eq!(ROBINHOOD_PROFILE.erc20_of(NATIVE), WETH);
    }
}
