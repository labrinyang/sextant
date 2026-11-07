use crate::abi;
use crate::catalog::{CatalogProtocol, CatalogVenue};
use crate::chain::{ChainProfile, DiscoveryProfile, MAX_POSITIVE_SLIPPAGE_BPS};
use crate::config::Config;
use crate::indexer::IndexerClient;
use crate::pools::{TickInfo, V3ExecutionMeta, V3Pool, V3Protocol, V3State, V4Meta};
use crate::route::{ALLOC_CHUNKS, MIN_SHARE_BPS, PreparedRoutes};
use crate::rpc::{Rpc, sanitized_error};
use crate::settler::build_swap_tx_for_profile;
use crate::snapshot::Snapshot;
use crate::state::{SettlerUnavailable, verify_execution_adapter_at};
use crate::topology::TokenPair;
use alloy_primitives::{Address, B256, I256, U256, address, keccak256};
use alloy_sol_types::SolCall;
use anyhow::Context;
use std::sync::Arc;

pub(super) const MAX_QUOTE_TIMEOUT_SECS: u64 = 600;

pub(super) async fn verify_rpc_chain(
    rpc: &Rpc,
    expected: u64,
    role: &'static str,
) -> anyhow::Result<()> {
    rpc.verify_chain_id(expected, role)
        .await
        .map(|_| ())
        // Build a fresh error from the public-safe message. Keeping the original
        // source here would let anyhow's alternate display reveal the RPC URL.
        .map_err(|error| {
            anyhow::anyhow!(
                "{role} RPC verification failed: {}",
                sanitized_error(&error)
            )
        })
}

/// Prove the endpoint capabilities used by every snapshot before advertising
/// readiness: correct chain identity, canonical EIP-1898 block hashes,
/// state-override execution for QuoteLens, and canonical Multicall3 support.
pub(super) async fn verify_quote_rpc(rpc: &Rpc, profile: &ChainProfile) -> anyhow::Result<()> {
    verify_rpc_chain(rpc, profile.chain_id, "primary").await?;
    let peek = crate::lens::peek(rpc, 0, &[], &[], alloy::eips::BlockId::latest())
        .await
        .map_err(|error| {
            anyhow::anyhow!(
                "primary RPC QuoteLens capability check failed: {}",
                sanitized_error(&error)
            )
        })?;
    anyhow::ensure!(
        peek.words.is_empty(),
        "primary RPC QuoteLens capability check returned unexpected state"
    );
    let multicall = rpc
        .multicall(vec![(profile.wrapped_native, Vec::new())], peek.block_id)
        .await
        .map_err(|error| {
            anyhow::anyhow!(
                "primary RPC Multicall3 capability check failed: {}",
                sanitized_error(&error)
            )
        })?;
    anyhow::ensure!(
        multicall.len() == 1,
        "primary RPC Multicall3 capability check returned the wrong result count"
    );
    if profile.execution_enabled() {
        // No current Settler leaves the solver quote-only until one is
        // deployed or restored; a Settler that fails its review stops startup.
        match verify_execution_adapter_at(profile, rpc, peek.block_id).await {
            Err(error) if error.downcast_ref::<SettlerUnavailable>().is_some() => {
                tracing::info!(
                    "startup: the Settler registry has no current Settler; quotes stay indicative"
                );
                return Ok(());
            }
            result => result,
        }
        .map_err(|error| {
            anyhow::anyhow!(
                "primary RPC execution adapter check failed: {}",
                sanitized_error(&error)
            )
        })?;
    }
    Ok(())
}

pub(super) fn native_rfq_adapter_error(error: anyhow::Error) -> anyhow::Error {
    // Drop the original source chain after rendering only its public-safe form.
    // RPC provider errors may retain a paid endpoint URL that alternate anyhow
    // formatting would otherwise expose.
    anyhow::anyhow!(
        "Native RFQ adapter verification failed: {}",
        sanitized_error(&error)
    )
}

#[derive(Clone, Copy)]
pub(super) enum NativeSettlerTarget {
    Registry { address: Address, token_id: u64 },
}

#[derive(Clone, Copy)]
pub(super) struct NativeAdapter {
    pub(super) native: crate::chain::NativeRfqProfile,
    pub(super) settler: NativeSettlerTarget,
}

pub(super) fn configured_native_adapter(profile: &ChainProfile) -> anyhow::Result<NativeAdapter> {
    let (native, settler) = profile.native_adapter()?;
    Ok(NativeAdapter {
        native,
        settler: NativeSettlerTarget::Registry {
            address: settler.registry,
            token_id: settler.registry_token_id,
        },
    })
}

pub(super) async fn verify_native_rfq_adapter(
    rpc: &Rpc,
    profile: &ChainProfile,
    adapter: NativeAdapter,
    expected_authorization_signer: Address,
) -> anyhow::Result<()> {
    verify_native_rfq_adapter_inner(rpc, profile, adapter, expected_authorization_signer)
        .await
        .map_err(native_rfq_adapter_error)
}

async fn verify_native_rfq_adapter_inner(
    rpc: &Rpc,
    profile: &ChainProfile,
    adapter: NativeAdapter,
    expected_authorization_signer: Address,
) -> anyhow::Result<()> {
    let native = adapter.native;
    let canonical = rpc.canonical_block(alloy::eips::BlockId::latest()).await?;
    let at = alloy::eips::BlockId::hash_canonical(canonical.hash);
    let settler = match adapter.settler {
        NativeSettlerTarget::Registry { address, token_id } => {
            let result = rpc
                .eth_call(
                    address,
                    abi::ISettlerRegistry::ownerOfCall {
                        id: U256::from(token_id),
                    }
                    .abi_encode(),
                    at,
                )
                .await?;
            abi::ISettlerRegistry::ownerOfCall::abi_decode_returns(&result)
                .context("decoding Settler registry ownerOf")?
        }
    };
    anyhow::ensure!(settler != Address::ZERO, "Settler registry returned zero");
    let revision_call = abi::contractRevisionCall {}.abi_encode();
    let is_pool_call = abi::isNativePoolsCall { pool: native.pool }.abi_encode();
    let router_call = abi::routerCall {}.abi_encode();
    let vault_call = abi::vaultCall {}.abi_encode();
    let treasury_call = abi::treasuryCall {}.abi_encode();
    let weth_call = abi::WETH9Call {}.abi_encode();
    let domain_call = abi::eip712DomainCall {}.abi_encode();
    let authorization_signer_call = abi::nativeAuthorizationSignerCall {}.abi_encode();
    let (
        router_code,
        pool_code,
        credit_vault_code,
        router_revision_result,
        pool_revision_result,
        is_pool_result,
        pool_router_result,
        router_vault_result,
        pool_treasury_result,
        router_weth_result,
        pool_weth_result,
        pool_domain_result,
        authorization_signer_result,
    ) = tokio::try_join!(
        rpc.code_at(native.router, at),
        rpc.code_at(native.pool, at),
        rpc.code_at(native.credit_vault, at),
        rpc.eth_call(native.router, revision_call.clone(), at),
        rpc.eth_call(native.pool, revision_call, at),
        rpc.eth_call(native.router, is_pool_call, at),
        rpc.eth_call(native.pool, router_call, at),
        rpc.eth_call(native.router, vault_call, at),
        rpc.eth_call(native.pool, treasury_call, at),
        rpc.eth_call(native.router, weth_call.clone(), at),
        rpc.eth_call(native.pool, weth_call, at),
        rpc.eth_call(native.pool, domain_call, at),
        rpc.eth_call(settler, authorization_signer_call, at),
    )?;
    anyhow::ensure!(!router_code.is_empty(), "Native RFQ Router has no code");
    anyhow::ensure!(!pool_code.is_empty(), "Native RFQ pool has no code");
    anyhow::ensure!(
        !credit_vault_code.is_empty(),
        "Native RFQ CreditVault has no code"
    );
    anyhow::ensure!(
        keccak256(&router_code) == native.router_runtime_hash,
        "Native RFQ Router runtime is not reviewed for {}",
        profile.name
    );
    anyhow::ensure!(
        keccak256(&pool_code) == native.pool_runtime_hash,
        "Native RFQ pool runtime is not reviewed for {}",
        profile.name
    );
    anyhow::ensure!(
        keccak256(&credit_vault_code) == native.credit_vault_runtime_hash,
        "Native RFQ CreditVault runtime is not reviewed for {}",
        profile.name
    );
    let router_revision = abi::contractRevisionCall::abi_decode_returns(&router_revision_result)
        .context("decoding Native Router contractRevision")?;
    anyhow::ensure!(
        router_revision == U256::from(native.contract_revision),
        "Native RFQ Router revision is not reviewed for {}",
        profile.name
    );
    let pool_revision = abi::contractRevisionCall::abi_decode_returns(&pool_revision_result)
        .context("decoding Native RFQ pool contractRevision")?;
    anyhow::ensure!(
        pool_revision == U256::from(native.contract_revision),
        "Native RFQ pool revision is not reviewed for {}",
        profile.name
    );
    let is_pool = abi::isNativePoolsCall::abi_decode_returns(&is_pool_result)
        .context("decoding Native Router isNativePools")?;
    anyhow::ensure!(
        is_pool,
        "Native Router does not recognize the reviewed RFQ pool for {}",
        profile.name
    );
    let pool_router = abi::routerCall::abi_decode_returns(&pool_router_result)
        .context("decoding Native RFQ pool router")?;
    anyhow::ensure!(
        pool_router == native.router,
        "Native RFQ pool is wired to a different Router for {}",
        profile.name
    );
    let router_vault = abi::vaultCall::abi_decode_returns(&router_vault_result)
        .context("decoding Native Router vault")?;
    let pool_treasury = abi::treasuryCall::abi_decode_returns(&pool_treasury_result)
        .context("decoding Native RFQ pool treasury")?;
    anyhow::ensure!(
        router_vault == native.credit_vault && pool_treasury == native.credit_vault,
        "Native Router/pool CreditVault wiring is not reviewed for {}",
        profile.name
    );
    let router_weth = abi::WETH9Call::abi_decode_returns(&router_weth_result)
        .context("decoding Native Router WETH9")?;
    let pool_weth = abi::WETH9Call::abi_decode_returns(&pool_weth_result)
        .context("decoding Native RFQ pool WETH9")?;
    anyhow::ensure!(
        router_weth == profile.wrapped_native && pool_weth == profile.wrapped_native,
        "Native Router/pool wrapped-native wiring is not reviewed for {}",
        profile.name
    );
    let pool_domain = abi::eip712DomainCall::abi_decode_returns(&pool_domain_result)
        .context("decoding Native RFQ pool EIP-5267 domain")?;
    verify_native_pool_domain(
        profile,
        &native,
        pool_domain.fields[0],
        &pool_domain.name,
        &pool_domain.version,
        pool_domain.chainId,
        pool_domain.verifyingContract,
        pool_domain.salt,
        &pool_domain.extensions,
    )?;
    let authorization_signer =
        abi::nativeAuthorizationSignerCall::abi_decode_returns(&authorization_signer_result)
            .context("decoding Settler nativeAuthorizationSigner")?;
    verify_native_authorization_signer(authorization_signer, expected_authorization_signer)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn verify_native_pool_domain(
    profile: &ChainProfile,
    native: &crate::chain::NativeRfqProfile,
    fields: u8,
    name: &str,
    version: &str,
    chain_id: U256,
    verifying_contract: Address,
    salt: B256,
    extensions: &[U256],
) -> anyhow::Result<()> {
    anyhow::ensure!(
        fields == native.domain_fields,
        "Native RFQ pool EIP-712 fields are not reviewed for {}",
        profile.name
    );
    anyhow::ensure!(
        name == native.domain_name,
        "Native RFQ pool EIP-712 name is not reviewed for {}",
        profile.name
    );
    anyhow::ensure!(
        version == native.domain_version,
        "Native RFQ pool EIP-712 version is not reviewed for {}",
        profile.name
    );
    anyhow::ensure!(
        native.domain_chain_id == profile.chain_id
            && chain_id == U256::from(native.domain_chain_id),
        "Native RFQ pool EIP-712 chain id is not reviewed for {}",
        profile.name
    );
    anyhow::ensure!(
        verifying_contract == native.pool,
        "Native RFQ pool EIP-712 verifying contract is not reviewed for {}",
        profile.name
    );
    anyhow::ensure!(
        salt == B256::ZERO,
        "Native RFQ pool EIP-712 salt is not reviewed for {}",
        profile.name
    );
    anyhow::ensure!(
        extensions.is_empty(),
        "Native RFQ pool EIP-712 extensions are not reviewed for {}",
        profile.name
    );
    Ok(())
}

pub(super) fn verify_native_authorization_signer(
    actual: Address,
    expected: Address,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        actual == expected,
        "Settler Native authorization signer does not match the configured signing key"
    );
    Ok(())
}

/// Exercise the full hot path (solver + encoder) on synthetic pools. With no
/// JIT there is nothing to warm — this is a boot-time self-check that the
/// math, planner and Settler encoding agree before the port serves traffic.
pub(super) fn warmup_for_profile(profile: &ChainProfile) -> anyhow::Result<()> {
    let l = U256::from(10).pow(U256::from(21));
    let executable = profile.execution_enabled();
    let mut cases: Vec<(V3Protocol, Option<V3ExecutionMeta>, Option<Address>)> =
        match profile.discovery {
            DiscoveryProfile::IndexedEvm(_) if executable => profile
                .settler
                .expect("executable profile")
                .indexed_v3
                .iter()
                .map(|binding| {
                    (
                        binding.protocol,
                        Some(V3ExecutionMeta {
                            fork_id: binding.fork_id,
                            pool_id: 3000,
                        }),
                        None,
                    )
                })
                .collect(),
            _ if executable => vec![(
                V3Protocol::UP33CL,
                Some(V3ExecutionMeta {
                    fork_id: 40,
                    pool_id: 200,
                }),
                None,
            )],
            _ => vec![(V3Protocol::UNIV3, None, None)],
        };
    if profile.quote_protocols().contains(&"univ4") {
        let discovery_manager = match profile.discovery {
            DiscoveryProfile::IndexedEvm(discovery) => {
                match discovery.venue(CatalogProtocol::UNIV4) {
                    Some(CatalogVenue::V4 {
                        pool_manager,
                        quote: true,
                        ..
                    }) => Some(pool_manager),
                    _ => None,
                }
            }
            DiscoveryProfile::Robinhood => Some(crate::chain::V4_POOL_MANAGER),
            DiscoveryProfile::Disabled => None,
        };
        let manager = if executable {
            profile
                .settler
                .and_then(|settler| settler.univ4_pool_manager)
                .context("quote-enabled V4 has no executable Settler binding")?
        } else {
            discovery_manager.context("quote-enabled V4 has no discovery PoolManager")?
        };
        cases.push((V3Protocol::UNIV4, None, Some(manager)));
    }
    let ticks: std::sync::Arc<[TickInfo]> = vec![
        TickInfo {
            tick: -600,
            liquidity_net: I256::try_from(l).expect("fits"),
        },
        TickInfo {
            tick: 600,
            liquidity_net: -I256::try_from(l).expect("fits"),
        },
    ]
    .into();
    for (protocol, execution, v4_manager) in cases {
        let pool = V3Pool {
            protocol,
            address: v4_manager.unwrap_or(address!("1000000000000000000000000000000000000001")),
            token0: address!("0a00000000000000000000000000000000000001"),
            token1: address!("0b00000000000000000000000000000000000001"),
            fee_ppm: 3000,
            tick_spacing: 200,
            verify_pool_spacing: false,
            execution,
            v4: v4_manager.map(|_| V4Meta {
                pool_id: B256::repeat_byte(0x44),
                state_slot: B256::repeat_byte(0x55),
                native: false,
                hooks: Address::ZERO,
                swap_fee_0to1_ppm: 3_000,
                swap_fee_1to0_ppm: 3_000,
            }),
            algebra: None,
        };
        let state = V3State {
            sqrt_price: U256::ONE << 96usize,
            tick: 0,
            liquidity: l,
            ticks: ticks.clone().into(),
            pos: 1,
            lo_cover: -180_000,
            hi_cover: 180_000,
        };
        let snap = Snapshot {
            block: 1,
            settler: executable.then_some(address!("1d4b86491ec211257cbedd77a4380a7494624eff")),
            v3: vec![(pool.clone(), state)],
            v2: vec![],
            ekubo: vec![],
        };
        let amount = U256::from(10).pow(U256::from(18));
        let plan = PreparedRoutes::for_profile(&snap, profile, pool.token0, pool.token1)?
            .try_solve_quantized(amount, *ALLOC_CHUNKS, *MIN_SHARE_BPS)?
            .context("warmup route is not executable")?;
        if executable {
            build_swap_tx_for_profile(
                profile,
                9,
                Some(address!("00000000000000000000000000000000000000fe")),
                None,
                &snap,
                &plan,
                pool.token0,
                pool.token1,
                amount,
                U256::ONE,
                address!("00000000000000000000000000000000000000aa"),
                1 << 31,
            )?;
        }
    }
    Ok(())
}

/// Self-check of every compiled chain profile, used by the port tests.
pub fn warmup() -> anyhow::Result<()> {
    crate::chain::CHAIN_PROFILES
        .iter()
        .try_for_each(|profile| warmup_for_profile(profile))
}

pub(super) fn validate_profile(profile: &ChainProfile) -> anyhow::Result<()> {
    anyhow::ensure!(
        !profile.execution_enabled() || profile.capabilities.quote,
        "{} enables execution without quote capability",
        profile.name
    );
    anyhow::ensure!(
        !profile.capabilities.quote || profile.discovery != DiscoveryProfile::Disabled,
        "{} enables quote capability without pool discovery",
        profile.name
    );
    if let Some(settler) = profile.settler {
        anyhow::ensure!(
            settler.registry != Address::ZERO
                && settler.registry_token_id > 0
                && settler.allowance_holder != Address::ZERO
                && settler.allowance_holder_runtime_hash != B256::ZERO
                && settler.runtime.is_complete(),
            "{} has an incomplete Settler adapter",
            profile.name
        );
    }
    if let Some(native) = profile.native_rfq {
        anyhow::ensure!(
            native.router_version > 0
                && native.contract_revision > 0
                && native.router != Address::ZERO
                && native.router_runtime_hash != B256::ZERO
                && native.pool != Address::ZERO
                && native.pool_runtime_hash != B256::ZERO
                && native.credit_vault != Address::ZERO
                && native.credit_vault_runtime_hash != B256::ZERO
                && native.trade_selector != [0; 4]
                && !native.api_chain.is_empty()
                && native.domain_fields == 0x0f
                && !native.domain_name.is_empty()
                && !native.domain_version.is_empty()
                && native.domain_chain_id == profile.chain_id,
            "{} has an incomplete Native RFQ adapter",
            profile.name
        );
        for (index, token) in native.stock_tokens.iter().enumerate() {
            anyhow::ensure!(
                *token != Address::ZERO && *token != crate::chain::NATIVE,
                "{} has an invalid Native RFQ stock token",
                profile.name
            );
            anyhow::ensure!(
                !native.stock_tokens[..index].contains(token),
                "{} has a duplicate Native RFQ stock token {token:#x}",
                profile.name
            );
        }
    }
    anyhow::ensure!(
        crate::chain::is_reviewed_profile(profile),
        "{} is not an exact reviewed solver profile",
        profile.name
    );
    if let DiscoveryProfile::IndexedEvm(discovery) = profile.discovery {
        discovery.validate()?;
        if profile.execution_enabled() {
            let bindings = profile.settler.expect("checked above").indexed_v3;
            for venue in discovery.venues.iter().copied() {
                match venue {
                    CatalogVenue::V3 {
                        protocol,
                        quote: true,
                        ..
                    } => anyhow::ensure!(
                        bindings
                            .iter()
                            .filter(|binding| binding.protocol == protocol)
                            .count()
                            == 1,
                        "{} enables execution without a reviewed {} adapter",
                        profile.name,
                        protocol.as_str()
                    ),
                    CatalogVenue::V4 {
                        pool_manager,
                        quote: true,
                        ..
                    } => anyhow::ensure!(
                        profile
                            .settler
                            .and_then(|settler| settler.univ4_pool_manager)
                            == Some(pool_manager),
                        "{} enables execution without a reviewed univ4 PoolManager binding",
                        profile.name
                    ),
                    _ => {}
                }
            }
            for (index, binding) in bindings.iter().enumerate() {
                anyhow::ensure!(
                    binding.deployer != Address::ZERO && binding.init_hash != B256::ZERO,
                    "{} has an incomplete {} execution adapter",
                    profile.name,
                    binding.protocol.as_str()
                );
                anyhow::ensure!(
                    discovery.venues.iter().copied().any(|venue| matches!(
                        venue,
                        CatalogVenue::V3 { protocol, quote: true, .. }
                            if protocol == binding.protocol
                    )),
                    "{} execution adapter includes unquoted {}",
                    profile.name,
                    binding.protocol.as_str()
                );
                anyhow::ensure!(
                    bindings[..index].iter().all(|previous| {
                        previous.protocol != binding.protocol && previous.fork_id != binding.fork_id
                    }),
                    "{} has duplicate indexed V3 execution identity",
                    profile.name
                );
            }
        }
        let route_pairs = crate::chain::route_pairs_for(
            profile.connectors,
            Address::repeat_byte(1),
            Address::repeat_byte(2),
        );
        let native_aliases = usize::from(
            discovery
                .quote_protocols()
                .contains(&CatalogProtocol::UNIV4),
        ) * route_pairs
            .iter()
            .filter(|(token0, token1)| {
                *token0 == profile.wrapped_native || *token1 == profile.wrapped_native
            })
            .count();
        let pair_count = route_pairs.len() + native_aliases;
        anyhow::ensure!(
            pair_count <= crate::topology::MAX_PAIRS,
            "{} connector graph needs {pair_count} pairs but the indexer contract allows {}",
            profile.name,
            crate::topology::MAX_PAIRS
        );
    }
    Ok(())
}

pub(super) fn validate_config(cfg: &Config) -> anyhow::Result<()> {
    validate_profile(cfg.profile)?;
    anyhow::ensure!(
        (1..=MAX_QUOTE_TIMEOUT_SECS).contains(&cfg.quote_timeout),
        "SOLVER_QUOTE_TIMEOUT must be in 1..={MAX_QUOTE_TIMEOUT_SECS} seconds"
    );
    check_indexer_url(cfg.profile, cfg.indexer_url.as_deref())?;
    if cfg.native_rfq.is_some() {
        configured_native_adapter(cfg.profile)?;
    }
    validate_execution_settings(cfg)
}

/// `SOLVER_INDEXER_URL` exactly where a topology indexer names the profile's
/// candidate pools: required there, refused everywhere else rather than
/// silently ignored.
pub(super) fn check_indexer_url(profile: &ChainProfile, url: Option<&str>) -> anyhow::Result<()> {
    if profile.needs_indexer() {
        anyhow::ensure!(
            url.is_some_and(|url| !url.trim().is_empty()),
            "SOLVER_INDEXER_URL is required for indexer-backed pool discovery"
        );
    } else if profile.indexed_discovery().is_some() {
        anyhow::ensure!(
            url.is_none(),
            "SOLVER_INDEXER_URL is not used: {} names its pools by factory",
            profile.name
        );
    } else {
        anyhow::ensure!(
            url.is_none(),
            "SOLVER_INDEXER_URL is only valid for an indexer-backed chain profile"
        );
    }
    Ok(())
}

/// Fee and positive-slippage settings. Fail at boot, not on the first
/// tx-building request.
pub(super) fn validate_execution_settings(cfg: &Config) -> anyhow::Result<()> {
    anyhow::ensure!(
        cfg.fee_receiver != Some(Address::ZERO),
        "SOLVER_FEE_RECEIVER must not be zero"
    );
    anyhow::ensure!(
        cfg.fee_bps == 0 || cfg.fee_receiver.is_some(),
        "SOLVER_FEE_BPS is {} but SOLVER_FEE_RECEIVER is not set",
        cfg.fee_bps
    );
    anyhow::ensure!(
        cfg.positive_slippage_max_bps <= MAX_POSITIVE_SLIPPAGE_BPS,
        "SOLVER_POSITIVE_SLIPPAGE_MAX_BPS {} exceeds {}",
        cfg.positive_slippage_max_bps,
        MAX_POSITIVE_SLIPPAGE_BPS
    );
    anyhow::ensure!(
        cfg.positive_slippage_recipient != Some(Address::ZERO),
        "SOLVER_POSITIVE_SLIPPAGE_RECIPIENT must not be zero"
    );
    anyhow::ensure!(
        cfg.positive_slippage_max_bps == 0 || cfg.positive_slippage_recipient.is_some(),
        "SOLVER_POSITIVE_SLIPPAGE_MAX_BPS is {} but SOLVER_POSITIVE_SLIPPAGE_RECIPIENT is not set",
        cfg.positive_slippage_max_bps
    );
    if !cfg.profile.execution_enabled() {
        anyhow::ensure!(
            cfg.fee_bps == 0 && cfg.fee_receiver.is_none(),
            "quote-only profile {} cannot configure execution fees",
            cfg.profile.name
        );
        anyhow::ensure!(
            cfg.positive_slippage_max_bps == 0 && cfg.positive_slippage_recipient.is_none(),
            "quote-only profile {} cannot configure positive-slippage capture",
            cfg.profile.name
        );
    }
    Ok(())
}

/// Builds the pool indexer client production uses: None when the profile needs
/// no indexer, otherwise a client for the configured indexer URL with this
/// process's SOLVER_RANKED_CONNECTORS setting. It is public for tools, so they
/// discover pools through exactly the client the server builds.
pub fn configured_indexer(cfg: &Config) -> anyhow::Result<Option<Arc<IndexerClient>>> {
    if !cfg.profile.needs_indexer() {
        return Ok(None);
    }
    let url = cfg
        .indexer_url
        .as_deref()
        .context("SOLVER_INDEXER_URL is required for indexer-backed pool discovery")?;
    Ok(Some(Arc::new(
        IndexerClient::builder(url, cfg.profile)?
            .ranked_connectors(crate::state::ranked_connectors())
            .build()?,
    )))
}

pub(super) async fn verify_indexer_startup(
    profile: &ChainProfile,
    indexer: &IndexerClient,
) -> anyhow::Result<()> {
    let (token0, token1) = if profile.stable < profile.wrapped_native {
        (profile.stable, profile.wrapped_native)
    } else {
        (profile.wrapped_native, profile.stable)
    };
    let protocols = profile
        .indexed_discovery()
        .context("profile is not indexer-backed")?
        .quote_protocols();
    let mut pairs = vec![TokenPair::new(token0, token1)?];
    if protocols.contains(&CatalogProtocol::UNIV4) {
        pairs.push(TokenPair::new(Address::ZERO, profile.stable)?);
        pairs.sort_unstable();
        pairs.dedup();
    }
    indexer.topology(&pairs, &protocols).await?;
    Ok(())
}
