// HTTP surface: POST /quote, GET /health, and the operator-only
// POST /rpc-recovery when SOLVER_RPC_RECOVERY_TOKEN is set.

use crate::abi::{self, addrhex, tohex};
use crate::budget::{SolverBudget, SolverBudgetExceeded};
use crate::catalog::{CatalogProtocol, CatalogVenue};
#[cfg(test)]
use crate::chain::FIXTURE_PROFILE;
use crate::chain::{ChainProfile, DiscoveryProfile, MAX_POSITIVE_SLIPPAGE_BPS};
use crate::config::Config;
use crate::engine::Engine;
use crate::indexer::IndexerClient;
use crate::pools::{TickInfo, V3ExecutionMeta, V3Pool, V3Protocol, V3State, V4Meta};
use crate::quote_metrics::{QuoteMetrics, QuoteOutcome};
use crate::quotes::{NoRouteError, QuoteRequest, quote_swap_bounded};
use crate::rfq::{NativeRfqClient, NativeRfqError, NativeRfqSource};
use crate::route::{ALLOC_CHUNKS, MIN_SHARE_BPS, PreparedRoutes};
use crate::rpc::{Rpc, RpcRejected, RpcUnavailable, sanitized_error};
use crate::rpc_dispatch::RpcCapacity;
use crate::settler::build_swap_tx_for_profile;
use crate::simulation::SimulationFailed;
use crate::snapshot::Snapshot;
use crate::state::{SettlerUnavailable, UpstreamIntegrityError, verify_execution_adapter_at};
#[cfg(test)]
use crate::topology::CatalogFences;
use crate::topology::{IndexerError, TokenPair};
use alloy_primitives::{Address, B256, I256, U256, address, keccak256};
use alloy_sol_types::SolCall;
use anyhow::Context;
use axum::Router;
use axum::body::Body;
#[cfg(test)]
use axum::body::Bytes;
use axum::extract::{Request, State};
use axum::http::HeaderValue;
use axum::http::StatusCode;
#[cfg(test)]
use axum::http::header::ACCESS_CONTROL_EXPOSE_HEADERS;
use axum::http::header::RETRY_AFTER;
use axum::response::Response;
use axum::routing::{get, post};
use serde::Serialize;
use serde_json::json;
use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex as AsyncMutex, OwnedSemaphorePermit, Semaphore};

const CORS_HEADERS: [(&str, &str); 4] = [
    ("Access-Control-Allow-Origin", "*"),
    ("Access-Control-Allow-Methods", "POST, GET, OPTIONS"),
    ("Access-Control-Allow-Headers", "Content-Type"),
    ("Access-Control-Expose-Headers", "Retry-After"),
];
/// How often a background task re-runs the readiness probes. Quotes and health
/// checks read its last result and never wait on a probe: until 16 Oct 2026 the
/// first request after the result aged 10 s ran the probes itself while every
/// other request queued behind it, about 0.4 s at a 130 ms round trip.
const READINESS_REFRESH: Duration = Duration::from_secs(10);
/// A result older than this (the refresher stopped, or none was started) is
/// probed again by the request that finds it, with the others waiting on that
/// one probe.
const READINESS_TTL: Duration = Duration::from_secs(30);
// Health probes must fail faster than the load balancer's liveness window.
// Quote traffic retains the RPC client's longer timeout and is unaffected.
const READINESS_PROBE_TIMEOUT: Duration = Duration::from_secs(5);
const NO_ROUTE_SCHEMA_VERSION: u8 = 1;
const MAX_QUOTE_TIMEOUT_SECS: u64 = 600;
const DEFAULT_COMPUTE_CONCURRENCY: usize = 2;
const MAX_COMPUTE_CONCURRENCY: usize = 64;
const INFLIGHT_QUOTES_PER_COMPUTE_SLOT: usize = 4;
const MAX_INFLIGHT_QUOTES: usize = 256;
/// Quotes that may wait for a slot, per slot; beyond that a quote is refused at once.
const QUEUED_QUOTES_PER_SLOT: usize = 2;
const DEFAULT_QUOTE_ADMISSION_WAIT_MS: u64 = 1_000;
const MAX_QUOTE_ADMISSION_WAIT_MS: u64 = 10_000;
const MAX_QUOTE_REQUEST_BYTES: usize = 16 * 1024;
const QUOTE_BODY_READ_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_QUOTE_LOG_FIELD_BYTES: usize = 256;

fn quote_log_field(value: &str) -> String {
    let mut escaped = value.chars().flat_map(char::escape_default);
    let mut rendered: String = escaped.by_ref().take(MAX_QUOTE_LOG_FIELD_BYTES).collect();
    if escaped.next().is_some() {
        rendered.truncate(MAX_QUOTE_LOG_FIELD_BYTES - 3);
        rendered.push_str("...");
    }
    rendered
}

fn parse_compute_concurrency(value: Option<&str>) -> anyhow::Result<usize> {
    let concurrency = value
        .unwrap_or("2")
        .parse::<usize>()
        .context("SOLVER_COMPUTE_CONCURRENCY must be a positive integer")?;
    anyhow::ensure!(
        (1..=MAX_COMPUTE_CONCURRENCY).contains(&concurrency),
        "SOLVER_COMPUTE_CONCURRENCY must be in 1..={MAX_COMPUTE_CONCURRENCY}"
    );
    Ok(concurrency)
}

fn compute_concurrency_from_env() -> anyhow::Result<usize> {
    match std::env::var("SOLVER_COMPUTE_CONCURRENCY") {
        Ok(value) => parse_compute_concurrency(Some(&value)),
        Err(std::env::VarError::NotPresent) => Ok(DEFAULT_COMPUTE_CONCURRENCY),
        Err(error) => Err(anyhow::anyhow!(
            "reading SOLVER_COMPUTE_CONCURRENCY: {error}"
        )),
    }
}

fn parse_max_inflight_quotes(
    value: Option<&str>,
    compute_concurrency: usize,
) -> anyhow::Result<usize> {
    let default = compute_concurrency
        .checked_mul(INFLIGHT_QUOTES_PER_COMPUTE_SLOT)
        .context("default quote concurrency overflow")?;
    let max_inflight = value
        .map_or_else(|| Ok(default), str::parse::<usize>)
        .context("SOLVER_MAX_INFLIGHT_QUOTES must be a positive integer")?;
    anyhow::ensure!(
        (compute_concurrency..=MAX_INFLIGHT_QUOTES).contains(&max_inflight),
        "SOLVER_MAX_INFLIGHT_QUOTES must be in {compute_concurrency}..={MAX_INFLIGHT_QUOTES}"
    );
    Ok(max_inflight)
}

fn parse_quote_admission_wait(value: &str) -> anyhow::Result<Duration> {
    let ms = value
        .trim()
        .parse::<u64>()
        .context("SOLVER_QUOTE_ADMISSION_WAIT_MS must be a whole number of milliseconds")?;
    anyhow::ensure!(
        ms <= MAX_QUOTE_ADMISSION_WAIT_MS,
        "SOLVER_QUOTE_ADMISSION_WAIT_MS must be at most {MAX_QUOTE_ADMISSION_WAIT_MS}"
    );
    Ok(Duration::from_millis(ms))
}

fn quote_admission_wait_from_env() -> anyhow::Result<Duration> {
    parse_quote_admission_wait(&crate::chain::env_or(
        "SOLVER_QUOTE_ADMISSION_WAIT_MS",
        &DEFAULT_QUOTE_ADMISSION_WAIT_MS.to_string(),
    )?)
}

/// How long one quote may take: `SOLVER_QUOTE_TIMEOUT`, or less when the
/// caller says it stops waiting sooner (`x-quote-timeout-ms`), so the solver
/// neither queues nor works for an answer nobody will read.
fn quote_time_limit(configured_secs: u64, header: Option<&str>) -> Duration {
    let configured = Duration::from_secs(configured_secs);
    header
        .and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|ms| *ms > 0)
        .map_or(configured, |ms| configured.min(Duration::from_millis(ms)))
}

fn max_inflight_quotes_from_env(compute_concurrency: usize) -> anyhow::Result<usize> {
    match std::env::var("SOLVER_MAX_INFLIGHT_QUOTES") {
        Ok(value) => parse_max_inflight_quotes(Some(&value), compute_concurrency),
        Err(std::env::VarError::NotPresent) => parse_max_inflight_quotes(None, compute_concurrency),
        Err(error) => Err(anyhow::anyhow!(
            "reading SOLVER_MAX_INFLIGHT_QUOTES: {error}"
        )),
    }
}

fn json_response<T: Serialize>(status: StatusCode, obj: &T) -> Response {
    let mut builder = Response::builder()
        .status(status)
        .header("Content-Type", "application/json");
    for (k, v) in CORS_HEADERS {
        builder = builder.header(k, v);
    }
    builder
        .body(Body::from(
            serde_json::to_vec(obj).expect("serializable response"),
        ))
        .expect("valid response")
}

fn error_response(status: StatusCode, msg: String) -> Response {
    json_response(status, &json!({ "error": msg }))
}

fn quote_error_response(
    status: StatusCode,
    profile: &ChainProfile,
    code: &'static str,
    msg: String,
    requested_chain_id: Option<u64>,
) -> Response {
    json_response(
        status,
        &json!({
            "error": msg,
            "code": code,
            "chain": profile.key,
            "chainId": profile.chain_id,
            "requestedChainId": requested_chain_id,
        }),
    )
}

fn overloaded_response(profile: &ChainProfile) -> Response {
    let mut response = quote_error_response(
        StatusCode::SERVICE_UNAVAILABLE,
        profile,
        "overloaded",
        "solver is at capacity; retry shortly".to_string(),
        None,
    );
    response
        .headers_mut()
        .insert(RETRY_AFTER, HeaderValue::from_static("1"));
    response
}

fn native_busy_response(profile: &ChainProfile, requested_chain_id: Option<u64>) -> Response {
    let mut response = quote_error_response(
        StatusCode::SERVICE_UNAVAILABLE,
        profile,
        "native_busy",
        "Native RFQ is at capacity; retry shortly".to_string(),
        requested_chain_id,
    );
    response
        .headers_mut()
        .insert(RETRY_AFTER, HeaderValue::from_static("1"));
    response
}

/// The built transaction reverted at the simulation block. Quote again; the
/// route, its state or the taker's funds changed.
fn simulation_failed_response(
    profile: &ChainProfile,
    error: &SimulationFailed,
    requested_chain_id: Option<u64>,
) -> Response {
    json_response(
        StatusCode::UNPROCESSABLE_ENTITY,
        &json!({
            "error": error.to_string(),
            "code": "simulation_failed",
            "chain": profile.key,
            "chainId": profile.chain_id,
            "requestedChainId": requested_chain_id,
            "block": error.block.number,
            "blockHash": format!("{:#x}", error.block.hash),
            "revertSelector": error
                .revert
                .as_ref()
                .filter(|data| data.len() >= 4)
                .map(|data| tohex(&data[..4])),
        }),
    )
}

fn no_route_response(
    profile: &ChainProfile,
    error: &NoRouteError,
    requested_chain_id: Option<u64>,
) -> Response {
    json_response(
        StatusCode::UNPROCESSABLE_ENTITY,
        &json!({
            "schemaVersion": NO_ROUTE_SCHEMA_VERSION,
            "error": error.to_string(),
            "code": "no_route",
            "chain": profile.key,
            "chainId": profile.chain_id,
            "requestedChainId": requested_chain_id,
            "routeUniverse": &error.route_universe,
        }),
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum QuoteGate {
    ChainMismatch(u64),
    QuotesUnavailable,
    ExecutionUnavailable,
}

fn gate_quote_request(profile: &ChainProfile, req: &QuoteRequest) -> Result<(), QuoteGate> {
    if req.chain_id != profile.chain_id {
        return Err(QuoteGate::ChainMismatch(req.chain_id));
    }
    if !profile.capabilities.quote {
        return Err(QuoteGate::QuotesUnavailable);
    }
    if !profile.execution_enabled()
        && (req.recipient.is_some() || req.fee_bps.is_some_and(|fee_bps| fee_bps > 0))
    {
        return Err(QuoteGate::ExecutionUnavailable);
    }
    Ok(())
}

fn quote_error_status(error: &anyhow::Error) -> StatusCode {
    if error.downcast_ref::<SolverBudgetExceeded>().is_some() {
        StatusCode::GATEWAY_TIMEOUT
    } else if error.downcast_ref::<NoRouteError>().is_some()
        || error.downcast_ref::<SimulationFailed>().is_some()
    {
        StatusCode::UNPROCESSABLE_ENTITY
    } else if error
        .downcast_ref::<NativeRfqError>()
        .is_some_and(NativeRfqError::is_retryable_capacity)
        || error.is::<RpcCapacity>()
    {
        StatusCode::SERVICE_UNAVAILABLE
    } else if error.downcast_ref::<RpcUnavailable>().is_some()
        || error.downcast_ref::<RpcRejected>().is_some()
        || error.downcast_ref::<IndexerError>().is_some()
        || error.downcast_ref::<UpstreamIntegrityError>().is_some()
    {
        StatusCode::BAD_GATEWAY
    } else {
        StatusCode::BAD_REQUEST
    }
}

async fn verify_rpc_chain(rpc: &Rpc, expected: u64, role: &'static str) -> anyhow::Result<()> {
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
async fn verify_quote_rpc(rpc: &Rpc, profile: &ChainProfile) -> anyhow::Result<()> {
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

fn native_rfq_adapter_error(error: anyhow::Error) -> anyhow::Error {
    // Drop the original source chain after rendering only its public-safe form.
    // RPC provider errors may retain a paid endpoint URL that alternate anyhow
    // formatting would otherwise expose.
    anyhow::anyhow!(
        "Native RFQ adapter verification failed: {}",
        sanitized_error(&error)
    )
}

#[derive(Clone, Copy)]
enum NativeSettlerTarget {
    Registry { address: Address, token_id: u64 },
}

#[derive(Clone, Copy)]
struct NativeAdapter {
    native: crate::chain::NativeRfqProfile,
    settler: NativeSettlerTarget,
}

fn configured_native_adapter(profile: &ChainProfile) -> anyhow::Result<NativeAdapter> {
    let (native, settler) = profile.native_adapter()?;
    Ok(NativeAdapter {
        native,
        settler: NativeSettlerTarget::Registry {
            address: settler.registry,
            token_id: settler.registry_token_id,
        },
    })
}

async fn verify_native_rfq_adapter(
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
fn verify_native_pool_domain(
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

fn verify_native_authorization_signer(actual: Address, expected: Address) -> anyhow::Result<()> {
    anyhow::ensure!(
        actual == expected,
        "Settler Native authorization signer does not match the configured signing key"
    );
    Ok(())
}

#[derive(Clone, Copy)]
struct ReadinessState {
    checked_at: Instant,
    rpc_ready: bool,
    indexer_ready: bool,
}

impl ReadinessState {
    fn new(rpc_ready: bool, indexer_ready: bool) -> Self {
        Self {
            checked_at: Instant::now(),
            rpc_ready,
            indexer_ready,
        }
    }
}

struct App {
    cfg: Config,
    rpc: Rpc,
    engine: Arc<Engine>,
    indexer: Option<Arc<IndexerClient>>,
    native_rfq: Option<Arc<dyn NativeRfqSource>>,
    native_adapter: Option<NativeAdapter>,
    quote_slots: Arc<Semaphore>,
    compute_slots: Arc<Semaphore>,
    memory: Arc<crate::process_memory::ProcessMemory>,
    chain_verified: bool,
    readiness: AsyncMutex<ReadinessState>,
    metrics: QuoteMetrics,
    /// Places for quotes waiting on `quote_slots`.
    quote_queue: Arc<Semaphore>,
    quote_admission_wait: Duration,
}

fn app_is_ready(app: &App, readiness: ReadinessState) -> bool {
    app.chain_verified
        && readiness.rpc_ready
        && readiness.indexer_ready
        && app.cfg.profile.capabilities.quote
}

async fn readiness(app: &App) -> ReadinessState {
    // Boxed: the probes' state machines are large, and every quote and health
    // request awaits this one.
    cached_readiness(
        &app.readiness,
        READINESS_PROBE_TIMEOUT,
        Box::pin(readiness_probe(app)),
    )
    .await
}

/// Re-run the readiness probes every `period` while the app is alive, so no
/// request waits on them.
fn spawn_readiness_refresher(app: &Arc<App>, period: Duration) {
    let app = Arc::downgrade(app);
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(period).await;
            let Some(app) = app.upgrade() else {
                return;
            };
            let (rpc_ready, indexer_ready) =
                tokio::time::timeout(READINESS_PROBE_TIMEOUT, Box::pin(readiness_probe(&app)))
                    .await
                    .unwrap_or_default();
            *app.readiness.lock().await = ReadinessState::new(rpc_ready, indexer_ready);
        }
    });
}

async fn readiness_probe(app: &App) -> (bool, bool) {
    {
        let rpc_probe = async {
            verify_quote_rpc(&app.rpc, app.cfg.profile).await?;
            if let Some(config) = app.cfg.native_rfq.as_ref() {
                verify_native_rfq_adapter(
                    &app.rpc,
                    app.cfg.profile,
                    app.native_adapter
                        .context("Native RFQ startup adapter unavailable")?,
                    config.authorizer().address(),
                )
                .await?;
            }
            Ok::<(), anyhow::Error>(())
        };
        let indexer_probe = async {
            match app.indexer.as_deref() {
                Some(indexer) => verify_indexer_startup(app.cfg.profile, indexer)
                    .await
                    .is_ok(),
                // Factory discovery rides the quote RPC, which `rpc_probe`
                // already checks.
                None => !app.cfg.profile.needs_indexer(),
            }
        };
        let (rpc_result, indexer_ready) = tokio::join!(rpc_probe, indexer_probe);
        (rpc_result.is_ok(), indexer_ready)
    }
}

async fn cached_readiness<F>(
    state: &AsyncMutex<ReadinessState>,
    probe_timeout: Duration,
    probe: F,
) -> ReadinessState
where
    F: Future<Output = (bool, bool)>,
{
    // The mutex is intentionally held through both probes: concurrent health
    // requests share one upstream check instead of amplifying it.
    let mut cached = state.lock().await;
    if cached.checked_at.elapsed() < READINESS_TTL {
        return *cached;
    }
    let (rpc_ready, indexer_ready) = tokio::time::timeout(probe_timeout, probe)
        .await
        .unwrap_or_default();
    *cached = ReadinessState::new(rpc_ready, indexer_ready);
    *cached
}

/// A slot to quote in. With every slot busy the quote waits in arrival order,
/// for at most `SOLVER_QUOTE_ADMISSION_WAIT_MS` and never past its deadline;
/// once `QUEUED_QUOTES_PER_SLOT` quotes per slot are already waiting it is
/// refused at once. A refusal is a 503 with Retry-After.
async fn admit_quote(app: &App, deadline: Instant) -> Option<OwnedSemaphorePermit> {
    if let Ok(permit) = app.quote_slots.clone().try_acquire_owned() {
        return Some(permit);
    }
    let wait = app
        .quote_admission_wait
        .min(deadline.saturating_duration_since(Instant::now()));
    if wait.is_zero() {
        return None;
    }
    let _place = app.quote_queue.clone().try_acquire_owned().ok()?;
    let _waiting = app.metrics.waiting();
    tokio::time::timeout(wait, app.quote_slots.clone().acquire_owned())
        .await
        .ok()?
        .ok()
}

async fn handle_quote(State(app): State<Arc<App>>, request: Request) -> Response {
    let started = Instant::now();
    let rid = crate::quote_metrics::request_id(
        request
            .headers()
            .get("x-request-id")
            .and_then(|value| value.to_str().ok()),
    );
    let limit = quote_time_limit(
        app.cfg.quote_timeout,
        request
            .headers()
            .get("x-quote-timeout-ms")
            .and_then(|value| value.to_str().ok()),
    );
    let (mut response, outcome) = quote_response(&app, request, &rid, started, limit).await;
    app.metrics.record(
        outcome,
        started.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
    );
    if let Ok(value) = HeaderValue::from_str(&rid) {
        response.headers_mut().insert("x-request-id", value);
    }
    response
}

async fn quote_response(
    app: &Arc<App>,
    request: Request,
    rid: &str,
    started: Instant,
    limit: Duration,
) -> (Response, QuoteOutcome) {
    let deadline = started + limit;
    let body = match tokio::time::timeout(
        QUOTE_BODY_READ_TIMEOUT,
        axum::body::to_bytes(request.into_body(), MAX_QUOTE_REQUEST_BYTES),
    )
    .await
    {
        Ok(Ok(body)) => body,
        Ok(Err(_)) => {
            tracing::info!(
                "quote err request_id={rid} status=413 ms=0 error=request body too large"
            );
            return (
                quote_error_response(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    app.cfg.profile,
                    "bad_request",
                    format!("quote request body exceeds {MAX_QUOTE_REQUEST_BYTES} bytes"),
                    None,
                ),
                QuoteOutcome::BadRequest,
            );
        }
        Err(_) => {
            tracing::info!(
                "quote err request_id={rid} status=408 ms={} error=request body timed out",
                started.elapsed().as_millis()
            );
            return (
                quote_error_response(
                    StatusCode::REQUEST_TIMEOUT,
                    app.cfg.profile,
                    "bad_request",
                    "quote request body timed out".to_string(),
                    None,
                ),
                QuoteOutcome::BadRequest,
            );
        }
    };
    let req: QuoteRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            let error = quote_log_field(&e.to_string());
            tracing::info!(
                "quote err request_id={rid} status=400 ms=0 error=bad request body: {error}"
            );
            return (
                quote_error_response(
                    StatusCode::BAD_REQUEST,
                    app.cfg.profile,
                    "bad_request",
                    e.to_string(),
                    None,
                ),
                QuoteOutcome::BadRequest,
            );
        }
    };
    // Slow or malformed ingress must not reserve scarce quote-work capacity.
    // The per-request body bounds above protect parsing; this permit covers
    // every subsequent exit path, including readiness and upstream work.
    let _memory = match app.memory.admit() {
        Ok(permit) => permit,
        Err(_) => {
            return (
                overloaded_response(app.cfg.profile),
                QuoteOutcome::Overloaded,
            );
        }
    };
    let _quote_permit = match admit_quote(app, deadline).await {
        Some(permit) => permit,
        None => {
            tracing::info!(
                "quote rejected request_id={rid} status={} code=overloaded chain={} waited_ms={}",
                StatusCode::SERVICE_UNAVAILABLE.as_u16(),
                app.cfg.profile.chain_id,
                started.elapsed().as_millis()
            );
            return (
                overloaded_response(app.cfg.profile),
                QuoteOutcome::Overloaded,
            );
        }
    };
    if let Err(gate) = gate_quote_request(app.cfg.profile, &req) {
        let (status, code, message, requested) = match gate {
            QuoteGate::ChainMismatch(requested) => (
                StatusCode::CONFLICT,
                "chain_mismatch",
                format!(
                    "chainId mismatch: solver is {}, request is {requested}",
                    app.cfg.profile.chain_id
                ),
                Some(requested),
            ),
            QuoteGate::QuotesUnavailable => (
                StatusCode::NOT_IMPLEMENTED,
                "quotes_unavailable",
                app.cfg
                    .profile
                    .capabilities
                    .unavailable_reason
                    .unwrap_or("quotes are not enabled")
                    .to_string(),
                Some(req.chain_id),
            ),
            QuoteGate::ExecutionUnavailable => (
                StatusCode::NOT_IMPLEMENTED,
                "execution_unavailable",
                format!(
                    "transaction building is not enabled for {}",
                    app.cfg.profile.name
                ),
                Some(req.chain_id),
            ),
        };
        tracing::info!(
            "quote rejected request_id={rid} status={} code={code} chain={} requested={}",
            status.as_u16(),
            app.cfg.profile.chain_id,
            requested.map_or_else(|| "legacy".to_string(), |id| id.to_string())
        );
        return (
            quote_error_response(status, app.cfg.profile, code, message, requested),
            QuoteOutcome::Rejected,
        );
    }
    let current_readiness = readiness(app).await;
    if !app_is_ready(app, current_readiness) {
        tracing::info!(
            "quote rejected request_id={rid} status={} code=not_ready chain={}",
            StatusCode::SERVICE_UNAVAILABLE.as_u16(),
            app.cfg.profile.chain_id
        );
        return (
            quote_error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                app.cfg.profile,
                "not_ready",
                "solver readiness checks are failing".to_string(),
                Some(req.chain_id),
            ),
            QuoteOutcome::NotReady,
        );
    }
    let (tin, tout, amt) = (
        quote_log_field(&req.token_in),
        quote_log_field(&req.token_out),
        quote_log_field(&req.amount_in.to_string()),
    );
    let requested_chain_id = Some(req.chain_id);
    // The time spent reading, queueing and checking readiness counts.
    let quote_timeout = deadline.saturating_duration_since(Instant::now());
    let budget = SolverBudget::for_duration(quote_timeout);
    let timeout_cancellation = budget.clone();
    match tokio::time::timeout(
        quote_timeout,
        quote_swap_bounded(
            &app.cfg,
            &app.engine,
            req,
            budget,
            app.compute_slots.clone(),
            app.native_rfq.as_deref(),
        ),
    )
    .await
    {
        Ok(Ok(resp)) => {
            tracing::info!(
                "quote ok request_id={rid} {tin}->{tout} amount={amt} block={} legs={} gross={} ms={} snapshot_ms={} snapshot_rpc_calls={} source={} solve_ms={} encode_ms={} simulate_ms={} simulation={} repriced={} cert={} gap_bps={} catalog_gap_bps={} graph_gap_bps={} screened_connectors={} screened_pools={} coverage_gain={} coverage_used={} coverage_solves={} coverage_age_ms={} coverage_us={} cert_us={} universe_source={} fallback_stage={} fallback_reason={} universe_scope={} selection_scope={} selector={} protocol_mask={:#x} eligible={} connectors={} truncated={} widening_candidates={} widened={} widening_rounds={} widening_end={} widening_probe_us={} widening_left_out={} widening_thin_left_out={} widening_thin_kept={} universe_id={:#x} adjacency_fences={:?} topology_fences={:?}",
                resp.block,
                resp.route.len(),
                resp.amount_out_gross,
                started.elapsed().as_millis(),
                resp.meta.snapshot_ms,
                resp.meta.snapshot_rpc_calls,
                resp.meta.source,
                resp.meta.solve_ms,
                resp.meta.encode_ms,
                resp.meta.simulate_ms,
                resp.simulation
                    .as_ref()
                    .map_or("-", |simulation| simulation.status),
                resp.meta.repriced,
                resp.certificate.as_ref().map_or("off", |c| c.status),
                resp.certificate
                    .as_ref()
                    .and_then(|c| c.gap_bps.as_deref())
                    .unwrap_or("-"),
                resp.certificate
                    .as_ref()
                    .and_then(|c| c.catalog_gap_bps.as_deref())
                    .unwrap_or("-"),
                resp.certificate
                    .as_ref()
                    .and_then(|c| c.graph_gap_bps.as_deref())
                    .unwrap_or("-"),
                resp.meta.universe_screened_count,
                resp.certificate
                    .as_ref()
                    .and_then(|c| c.screened_pools)
                    .unwrap_or(0),
                // `-` means the coverage question went unasked or unfinished; a
                // measured `0` is a proof that no declined connector helps at
                // this size, so the two must not print alike.
                resp.meta
                    .coverage_gain
                    .map_or_else(|| "-".to_string(), |gain| gain.to_string()),
                resp.meta.coverage_used,
                resp.meta.coverage_solves,
                // Separates a verdict this quote measured from one it reused off
                // the topology lease. `coverage_us` cannot: a reused verdict and
                // a fast measurement both read as a small number.
                resp.meta
                    .coverage_age_ms
                    .map_or_else(|| "-".to_string(), |age| age.to_string()),
                resp.meta.coverage_us,
                resp.meta.certificate_us,
                resp.meta.universe_source,
                resp.meta.universe_fallback_stage.unwrap_or("-"),
                resp.meta.universe_fallback_reason.unwrap_or("-"),
                resp.meta.universe_scope,
                resp.meta.universe_selection_scope,
                resp.meta.universe_selector,
                resp.meta.universe_protocol_mask,
                resp.meta.universe_eligible_count,
                resp.meta.universe_connector_count,
                resp.meta.universe_shortlist_truncated,
                resp.meta.widening_candidates,
                if resp.meta.widened.is_empty() {
                    "-".to_string()
                } else {
                    resp.meta
                        .widened
                        .iter()
                        .map(|token| format!("{token:#x}"))
                        .collect::<Vec<_>>()
                        .join(",")
                },
                resp.meta.widening_rounds,
                resp.meta.widening_end,
                resp.meta.widening_probe_us,
                resp.meta.widening_left_out,
                resp.meta.widening_thin_left_out,
                resp.meta.widening_thin_kept,
                resp.meta.universe_fingerprint,
                resp.meta.adjacency_fences,
                resp.meta.topology_fences,
            );
            app.metrics
                .record_stages(resp.meta.snapshot_ms, resp.meta.simulate_ms);
            (json_response(StatusCode::OK, &resp), QuoteOutcome::Ok)
        }
        Ok(Err(e)) => {
            if e.downcast_ref::<SolverBudgetExceeded>().is_some() {
                tracing::info!(
                    "quote err request_id={rid} {tin}->{tout} amount={amt} status=504 ms={} error=compute deadline exceeded",
                    started.elapsed().as_millis()
                );
                return (
                    quote_error_response(
                        StatusCode::GATEWAY_TIMEOUT,
                        app.cfg.profile,
                        "quote_timeout",
                        format!("quote timed out after {} ms", limit.as_millis()),
                        requested_chain_id,
                    ),
                    QuoteOutcome::Timeout,
                );
            }
            if let Some(no_route) = e.downcast_ref::<NoRouteError>() {
                let universe = &no_route.route_universe;
                tracing::info!(
                    "quote no_route request_id={rid} {tin}->{tout} amount={amt} status=422 ms={} block={} universe_source={} fallback_stage={} fallback_reason={} universe_scope={} selection_scope={} selector={} protocol_mask={:#x} eligible={} connectors={} truncated={} universe_id={} adjacency_fences={:?} topology_fences={:?}",
                    started.elapsed().as_millis(),
                    universe.canonical_block.number,
                    universe.source,
                    universe.fallback_stage.unwrap_or("-"),
                    universe.fallback_reason.unwrap_or("-"),
                    universe.scope,
                    universe.selection_scope,
                    universe.selector,
                    universe.protocol_mask,
                    universe.eligible_count,
                    universe.connector_count,
                    universe.shortlist_truncated,
                    universe.fingerprint,
                    universe.adjacency_fences,
                    universe.topology_fences,
                );
                return (
                    no_route_response(app.cfg.profile, no_route, requested_chain_id),
                    QuoteOutcome::NoRoute,
                );
            }
            if let Some(failed) = e.downcast_ref::<SimulationFailed>() {
                tracing::info!(
                    "quote simulation_failed request_id={rid} {tin}->{tout} amount={amt} status=422 ms={} error={}",
                    started.elapsed().as_millis(),
                    quote_log_field(&failed.to_string())
                );
                return (
                    simulation_failed_response(app.cfg.profile, failed, requested_chain_id),
                    QuoteOutcome::SimulationFailed,
                );
            }
            if e.downcast_ref::<NativeRfqError>()
                .is_some_and(NativeRfqError::is_retryable_capacity)
            {
                tracing::info!(
                    "quote err request_id={rid} {tin}->{tout} amount={amt} status=503 ms={} error=native capacity",
                    started.elapsed().as_millis()
                );
                return (
                    native_busy_response(app.cfg.profile, requested_chain_id),
                    QuoteOutcome::NativeBusy,
                );
            }
            if e.is::<RpcCapacity>() {
                tracing::info!(
                    "quote err request_id={rid} {tin}->{tout} amount={amt} status=503 ms={} error=rpc capacity",
                    started.elapsed().as_millis()
                );
                return (
                    overloaded_response(app.cfg.profile),
                    QuoteOutcome::RpcCapacity,
                );
            }
            // 502 when the failure came from the RPC, whether the transport
            // failed or the node returned a non-retryable JSON-RPC rejection;
            // 400 is reserved for request and solver-domain errors.
            // Never expose the transport error chain for upstream failures:
            // provider errors may contain the paid endpoint URL.
            let status = quote_error_status(&e);
            let message = sanitized_error(&e);
            let log_message = quote_log_field(&message);
            tracing::info!(
                "quote err request_id={rid} {tin}->{tout} amount={amt} status={} ms={} error={log_message}",
                status.as_u16(),
                started.elapsed().as_millis()
            );
            (
                quote_error_response(
                    status,
                    app.cfg.profile,
                    "quote_failed",
                    message,
                    requested_chain_id,
                ),
                QuoteOutcome::Error,
            )
        }
        Err(_) => {
            timeout_cancellation.cancel();
            tracing::info!(
                "quote err request_id={rid} {tin}->{tout} amount={amt} status=504 ms={} error=timed out",
                started.elapsed().as_millis()
            );
            (
                quote_error_response(
                    StatusCode::GATEWAY_TIMEOUT,
                    app.cfg.profile,
                    "quote_timeout",
                    format!("quote timed out after {} ms", limit.as_millis()),
                    requested_chain_id,
                ),
                QuoteOutcome::Timeout,
            )
        }
    }
}

async fn handle_health(State(app): State<Arc<App>>) -> Response {
    let readiness = readiness(&app).await;
    let ready = app_is_ready(&app, readiness);
    let pairs: Vec<_> = app
        .engine
        .status()
        .iter()
        .map(|p| {
            json!({
                "pair": format!("{}/{}", addrhex(p.tokens.0), addrhex(p.tokens.1)),
                "block": p.block,
                "ageMs": p.age.as_millis() as u64,
                "hot": p.hot,
            })
        })
        .collect();
    let mut protocols = app.cfg.profile.quote_protocols();
    if app.native_rfq.is_some() {
        protocols.push("nativerfq");
    }
    let native_config = app.cfg.native_rfq.as_ref();
    json_response(
        if ready {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        },
        &json!({
            "ok": true,
            "ready": ready,
            "chainVerified": app.chain_verified,
            "rpcReady": readiness.rpc_ready,
            "indexerReady": readiness.indexer_ready,
            "chain": app.cfg.profile.key,
            "chainId": app.cfg.profile.chain_id,
            "processMemory": app.memory.sample(),
            "capabilities": {
                "quote": app.cfg.profile.capabilities.quote,
                "execution": app.cfg.profile.execution_enabled(),
                "protocols": protocols,
                "nativeRfq": {
                    "supported": app.cfg.profile.native_supported(),
                    "configured": app.native_rfq.is_some(),
                    "mode": "single_native_stage",
                    "qps": native_config.map(|config| config.qps()),
                    "queueWaitMs": native_config
                        .map(|config| config.queue_wait().as_millis() as u64),
                    "maxInflight": native_config.map(|config| config.max_inflight()),
                    "quotaScope": native_config.map(|config| config.quota_mode()),
                },
                "poolDiscovery": app.cfg.profile.pool_discovery(),
                "routeUniverseMode": crate::state::dynamic_connector_mode(),
                "connectorScreening": crate::state::connector_screening(),
                "rankedConnectors": crate::state::ranked_connectors(),
                "connectorAdmission": crate::state::connector_admission(),
                "connectorMinBps": crate::state::connector_min_bps_e4(),
            },
            "rpc": {
                "unknownDispatches": app.rpc.unknown_dispatches(),
                "unknownEpoch": app.rpc.unknown_dispatch_epoch(),
            },
            "quotes": app.metrics.json(),
            "resident": app
                .engine
                .resident()
                .map_or_else(|| json!({"enabled": false}), |resident| resident.health()),
            "pairs": pairs,
        }),
    )
}

/// The quote counters and timings, and the capacity they ran against, in
/// Prometheus text. The listener is private to the backend's network, as
/// `/health` is.
async fn handle_metrics(State(app): State<Arc<App>>) -> Response {
    let mut text = String::new();
    app.metrics.prometheus(&mut text);
    text.push_str("# HELP solver_quote_slots_available Quote slots free now.\n# TYPE solver_quote_slots_available gauge\n");
    text.push_str(&format!(
        "solver_quote_slots_available {}\n",
        app.quote_slots.available_permits()
    ));
    text.push_str("# HELP solver_rpc_unknown_dispatches RPC requests whose outcome is unknown, each holding its slot.\n# TYPE solver_rpc_unknown_dispatches gauge\n");
    text.push_str(&format!(
        "solver_rpc_unknown_dispatches {}\n",
        app.rpc.unknown_dispatches()
    ));
    if let Some(resident) = app.engine.resident() {
        resident.prometheus(&mut text);
    }
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/plain; version=0.0.4")
        .body(Body::from(text))
        .expect("valid response")
}

async fn preflight() -> Response {
    let mut builder = Response::builder().status(StatusCode::NO_CONTENT);
    for (k, v) in CORS_HEADERS {
        builder = builder.header(k, v);
    }
    builder.body(Body::empty()).expect("valid response")
}

async fn fallback() -> Response {
    error_response(StatusCode::NOT_FOUND, "not found".to_string())
}

fn router(app: Arc<App>) -> Router {
    Router::new()
        .route("/quote", post(handle_quote).options(preflight))
        .route("/health", get(handle_health).options(preflight))
        .route("/metrics", get(handle_metrics))
        .fallback(fallback)
        .with_state(app)
}

struct RpcRecovery {
    rpc: Rpc,
    token: Vec<u8>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RpcRecoveryRequest {
    expected_unknown_epoch: u64,
    provider_termination_confirmed: bool,
    evidence_reference: String,
}

/// An RPC request whose outcome is unknown keeps its dispatch slot, because
/// the provider may still be running it. Only an operator holding the
/// provider's confirmation that every unresolved request has ended releases
/// that debt, for the epoch /health reported. Without a token there is no route.
fn rpc_recovery_router(rpc: Rpc) -> anyhow::Result<Router> {
    let token = crate::chain::env_or("SOLVER_RPC_RECOVERY_TOKEN", "")?;
    if token.is_empty() {
        return Ok(Router::new());
    }
    let service_token = crate::chain::env_or("SOLVER_SERVICE_TOKEN", "")?;
    anyhow::ensure!(
        token.len() >= 32 && token != service_token,
        "SOLVER_RPC_RECOVERY_TOKEN must have at least 32 bytes and differ from SOLVER_SERVICE_TOKEN"
    );
    Ok(Router::new()
        .route("/rpc-recovery", post(handle_rpc_recovery))
        .with_state(Arc::new(RpcRecovery {
            rpc,
            token: token.into_bytes(),
        })))
}

fn token_matches(expected: &[u8], actual: &[u8]) -> bool {
    let mut difference = expected.len() ^ actual.len();
    for (index, byte) in expected.iter().enumerate() {
        difference |= usize::from(*byte ^ actual.get(index).copied().unwrap_or(0));
    }
    difference == 0 && !expected.is_empty()
}

async fn handle_rpc_recovery(
    State(recovery): State<Arc<RpcRecovery>>,
    request: Request,
) -> Response {
    let bearer = request
        .headers()
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .unwrap_or("");
    if !token_matches(&recovery.token, bearer.as_bytes()) {
        return json_response(
            StatusCode::UNAUTHORIZED,
            &json!({"code": "unauthorized_rpc_recovery"}),
        );
    }
    let invalid = || {
        json_response(
            StatusCode::BAD_REQUEST,
            &json!({"code": "invalid_recovery_evidence"}),
        )
    };
    let body = match tokio::time::timeout(
        Duration::from_secs(2),
        axum::body::to_bytes(request.into_body(), 4096),
    )
    .await
    {
        Ok(Ok(body)) => body,
        _ => return invalid(),
    };
    let Ok(receipt) = serde_json::from_slice::<RpcRecoveryRequest>(&body) else {
        return invalid();
    };
    if !receipt.provider_termination_confirmed
        || receipt.evidence_reference.trim().is_empty()
        || receipt.evidence_reference.len() > 512
    {
        return invalid();
    }
    match recovery
        .rpc
        .reconcile_unknown_dispatches(receipt.expected_unknown_epoch)
    {
        Ok(released) => {
            // The log keeps only a digest of the operator's evidence.
            let evidence = keccak256(receipt.evidence_reference.as_bytes());
            tracing::warn!(
                "RPC operator recovery epoch={} released={released} evidence={evidence:#x}",
                receipt.expected_unknown_epoch
            );
            json_response(
                StatusCode::OK,
                &json!({
                    "releasedUnknownDispatches": released,
                    "unknownEpoch": recovery.rpc.unknown_dispatch_epoch(),
                    "evidenceHash": format!("{evidence:#x}"),
                }),
            )
        }
        Err(_) => json_response(
            StatusCode::CONFLICT,
            &json!({"code": "rpc_recovery_epoch_conflict"}),
        ),
    }
}

/// Exercise the full hot path (solver + encoder) on synthetic pools. With no
/// JIT there is nothing to warm — this is a boot-time self-check that the
/// math, planner and Settler encoding agree before the port serves traffic.
fn warmup_for_profile(profile: &ChainProfile) -> anyhow::Result<()> {
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

async fn shutdown_signal() {
    let ctrl_c = async { tokio::signal::ctrl_c().await.expect("ctrl_c handler") };
    #[cfg(unix)]
    let term = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("sigterm handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {},
        _ = term => {},
    }
}

fn validate_profile(profile: &ChainProfile) -> anyhow::Result<()> {
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

fn validate_config(cfg: &Config) -> anyhow::Result<()> {
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
fn check_indexer_url(profile: &ChainProfile, url: Option<&str>) -> anyhow::Result<()> {
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
fn validate_execution_settings(cfg: &Config) -> anyhow::Result<()> {
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

async fn verify_indexer_startup(
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

pub async fn serve(cfg: Config) -> anyhow::Result<()> {
    validate_config(&cfg)?;
    let native_adapter = cfg
        .native_rfq
        .as_ref()
        .map(|_| configured_native_adapter(cfg.profile))
        .transpose()?;
    let compute_concurrency = compute_concurrency_from_env()?;
    let max_inflight_quotes = max_inflight_quotes_from_env(compute_concurrency)?;
    let quote_admission_wait = quote_admission_wait_from_env()?;
    crate::state::validate_settings(
        cfg.profile,
        (cfg.profile.discovery == DiscoveryProfile::Robinhood).then_some(cfg.logs_rpc_url.as_str()),
    )?;
    sextant_route::validate_settings()?;
    crate::quotes::validate_settings()?;
    if cfg.profile.capabilities.quote {
        warmup_for_profile(cfg.profile)?;
    }
    let rpc = Rpc::connect(&cfg.rpc_url)?;
    verify_quote_rpc(&rpc, cfg.profile).await?;
    if let Some(config) = cfg.native_rfq.as_ref() {
        verify_native_rfq_adapter(
            &rpc,
            cfg.profile,
            native_adapter.context("Native RFQ startup adapter unavailable")?,
            config.authorizer().address(),
        )
        .await
        .context("Native RFQ startup identity check failed")?;
    }
    let native_rfq = cfg
        .native_rfq
        .clone()
        .map(|config| NativeRfqClient::new(config, rpc.clone()))
        .transpose()?
        .map(|client| Arc::new(client) as Arc<dyn NativeRfqSource>);
    let indexer = configured_indexer(&cfg)?;
    if let Some(indexer) = indexer.as_deref() {
        verify_indexer_startup(cfg.profile, indexer)
            .await
            .context("pool indexer startup check failed")?;
    } else if cfg.profile.pool_discovery() == "factories" {
        crate::state::verify_factory_discovery(cfg.profile, &rpc)
            .await
            .context("factory pool discovery startup check failed")?;
    }
    if cfg.profile.discovery == DiscoveryProfile::Robinhood {
        let logs_rpc = Rpc::connect(&cfg.logs_rpc_url)?;
        verify_rpc_chain(&logs_rpc, cfg.profile.chain_id, "logs").await?;
        crate::state::configure_logs_rpc(logs_rpc)?;
    }
    // Resident pool state starts reading in the background; until its first
    // block is published every quote takes the per-pair path.
    let resident = match crate::resident::Settings::from_env(cfg.profile)? {
        Some(settings) => {
            let resident = crate::resident::Resident::new(cfg.profile, rpc.clone(), settings)?;
            resident.spawn();
            Some(resident)
        }
        None => None,
    };
    let resident_mode = if resident.is_some() { "on" } else { "off" };
    let engine =
        Engine::for_profile_with_resident(rpc.clone(), cfg.profile, indexer.clone(), resident);
    tracing::info!(
        "sextant listening port={} chain={} chain_id={} rpc={} resident={} route_universe_mode={} compute_concurrency={} max_inflight_quotes={} quote_admission_wait_ms={}",
        cfg.port,
        cfg.profile.key,
        cfg.profile.chain_id,
        if cfg.rpc_url == cfg.profile.public_rpc {
            "public"
        } else {
            "private"
        },
        resident_mode,
        crate::state::dynamic_connector_mode(),
        compute_concurrency,
        max_inflight_quotes,
        quote_admission_wait.as_millis(),
    );
    let compute_slots = Arc::new(Semaphore::new(compute_concurrency));
    let memory = crate::process_memory::ProcessMemory::from_env()?;
    memory.start();
    let quota_router = crate::native_coordinator::NativeQuotaAuthority::configured_router(
        cfg.native_rfq.as_ref(),
    )?;
    let recovery_router = rpc_recovery_router(rpc.clone())?;
    let app = Arc::new(App {
        metrics: QuoteMetrics::default(),
        cfg: cfg.clone(),
        rpc,
        engine,
        indexer,
        native_rfq,
        native_adapter,
        quote_slots: Arc::new(Semaphore::new(max_inflight_quotes)),
        quote_queue: Arc::new(Semaphore::new(max_inflight_quotes * QUEUED_QUOTES_PER_SLOT)),
        quote_admission_wait,
        compute_slots,
        memory,
        chain_verified: true,
        readiness: AsyncMutex::new(ReadinessState::new(true, true)),
    });
    spawn_readiness_refresher(&app, READINESS_REFRESH);
    let listener = tokio::net::TcpListener::bind(("0.0.0.0", cfg.port)).await?;
    axum::serve(
        listener,
        router(app).merge(quota_router).merge(recovery_router),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pools::{V2Pool, V2State};
    use futures_util::{StreamExt, future::BoxFuture, stream};
    use std::convert::Infallible;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use tokio::sync::Barrier;

    // Native is enabled only inside these request-path tests so this exact
    // fork can exercise its BSC migration profile. No transaction is emitted:
    // the synthetic Native source below always returns a capacity error.
    static BURST_TEST_PROFILE: std::sync::LazyLock<ChainProfile> =
        std::sync::LazyLock::new(|| ChainProfile {
            native_rfq: Some(*crate::chain::BSC_NATIVE_RFQ),
            settler: Some(crate::chain::with_native_entry(*crate::chain::BSC_SETTLER)),
            ..*crate::chain::BSC_PROFILE
        });

    const BURST_USDC: Address = address!("8ac76a51cc950d9822d68b83fe1ad97b32cd580d");
    const BURST_ETH: Address = address!("2170ed0880ac9a755fd29b2688956bd959f933f8");
    const BURST_BTCB: Address = address!("7130d2a12b9bcbfae4f2634d864a1ee1ce3ead9c");
    const BURST_TSLAON: Address = address!("2494b603319d4d9f9715c9f4496d9e0364b59d93");
    const BURST_NVDAON: Address = address!("a9ee28c80f960b889dfbd1902055218cba016f75");
    const BURST_GOOGLON: Address = address!("091fc7778e6932d4009b087b191d1ee3bac5729a");
    const BURST_QQQON: Address = address!("0cde6936d305d5b34667fc46425e852efd73559a");

    #[derive(Clone, Copy)]
    struct BurstMarket {
        name: &'static str,
        class: &'static str,
        route_shape: &'static str,
        token_in: Address,
        token_out: Address,
        amount_in: &'static str,
    }

    const BURST_MARKETS: [BurstMarket; 12] = [
        BurstMarket {
            name: "TSLAon->USDT",
            class: "stock",
            route_shape: "direct",
            token_in: BURST_TSLAON,
            token_out: crate::chain::BSC_USDT,
            amount_in: "1000000000000000",
        },
        BurstMarket {
            name: "WBNB->USDT",
            class: "crypto",
            route_shape: "direct",
            token_in: crate::chain::WBNB,
            token_out: crate::chain::BSC_USDT,
            amount_in: "10000000000000000",
        },
        BurstMarket {
            name: "USDC->USDT",
            class: "stable",
            route_shape: "direct",
            token_in: BURST_USDC,
            token_out: crate::chain::BSC_USDT,
            amount_in: "50000000000000000000000",
        },
        BurstMarket {
            name: "USDT->NVDAon",
            class: "stock",
            route_shape: "reverse",
            token_in: crate::chain::BSC_USDT,
            token_out: BURST_NVDAON,
            amount_in: "50000000000000000000000",
        },
        BurstMarket {
            name: "USDT->WBNB",
            class: "crypto",
            route_shape: "reverse",
            token_in: crate::chain::BSC_USDT,
            token_out: crate::chain::WBNB,
            amount_in: "100000000000000000000",
        },
        BurstMarket {
            name: "USDT->USDC",
            class: "stable",
            route_shape: "reverse",
            token_in: crate::chain::BSC_USDT,
            token_out: BURST_USDC,
            amount_in: "1000000000000000000000",
        },
        BurstMarket {
            name: "GOOGLon->USDT",
            class: "stock",
            route_shape: "direct",
            token_in: BURST_GOOGLON,
            token_out: crate::chain::BSC_USDT,
            amount_in: "20000000000000000",
        },
        BurstMarket {
            name: "QQQon->USDT",
            class: "stock",
            route_shape: "direct",
            token_in: BURST_QQQON,
            token_out: crate::chain::BSC_USDT,
            amount_in: "50000000000000000",
        },
        BurstMarket {
            name: "ETH->USDT",
            class: "crypto",
            route_shape: "two-hop",
            token_in: BURST_ETH,
            token_out: crate::chain::BSC_USDT,
            amount_in: "100000000000000000",
        },
        BurstMarket {
            name: "BTCB->USDT",
            class: "crypto",
            route_shape: "two-hop",
            token_in: BURST_BTCB,
            token_out: crate::chain::BSC_USDT,
            amount_in: "1000000000000000",
        },
        BurstMarket {
            name: "TSLAon->WBNB",
            class: "stock",
            route_shape: "two-hop",
            token_in: BURST_TSLAON,
            token_out: crate::chain::WBNB,
            amount_in: "250000000000000000",
        },
        BurstMarket {
            name: "WBNB->NVDAon",
            class: "stock",
            route_shape: "two-hop-reverse",
            token_in: crate::chain::WBNB,
            token_out: BURST_NVDAON,
            amount_in: "500000000000000000",
        },
    ];

    // Only requests with a stock endpoint are Native-eligible. Crypto/stable
    // directions remain AMM controls even if Native happens to advertise them.
    const NATIVE_MARKET_INDICES: [usize; 6] = [0, 3, 6, 7, 10, 11];
    const AMM_ONLY_MARKET_INDICES: [usize; 6] = [1, 2, 4, 5, 8, 9];

    #[derive(Clone, Copy)]
    struct BurstAttempt {
        market: BurstMarket,
        native_eligible: bool,
        execution_requested: bool,
    }

    fn diverse_burst_wave(size: usize, wave: usize, mix_native: bool) -> Vec<BurstAttempt> {
        (0..size)
            .map(|index| {
                if mix_native && index.is_multiple_of(2) {
                    BurstAttempt {
                        market: BURST_MARKETS[NATIVE_MARKET_INDICES
                            [(index / 2 + wave * 3) % NATIVE_MARKET_INDICES.len()]],
                        native_eligible: true,
                        execution_requested: true,
                    }
                } else if mix_native {
                    BurstAttempt {
                        market: BURST_MARKETS[AMM_ONLY_MARKET_INDICES
                            [(index / 2 + wave * 3) % AMM_ONLY_MARKET_INDICES.len()]],
                        native_eligible: false,
                        // Supplying all execution identities proves these
                        // requests skip Native because of their endpoints, not
                        // because they are display-only quotes.
                        execution_requested: true,
                    }
                } else {
                    BurstAttempt {
                        market: BURST_MARKETS[(index + wave * 5) % BURST_MARKETS.len()],
                        native_eligible: false,
                        execution_requested: false,
                    }
                }
            })
            .collect()
    }

    fn burst_v2_pools() -> Vec<(V2Pool, V2State)> {
        let reserve = U256::from(10u64).pow(U256::from(30u64));
        [
            (crate::chain::WBNB, crate::chain::BSC_USDT),
            (BURST_USDC, crate::chain::BSC_USDT),
            (BURST_TSLAON, crate::chain::BSC_USDT),
            (BURST_NVDAON, crate::chain::BSC_USDT),
            (BURST_GOOGLON, crate::chain::BSC_USDT),
            (BURST_QQQON, crate::chain::BSC_USDT),
            (BURST_ETH, crate::chain::WBNB),
            (BURST_BTCB, crate::chain::WBNB),
        ]
        .into_iter()
        .enumerate()
        .map(|(index, (token0, token1))| {
            (
                V2Pool {
                    protocol: crate::pools::V2Protocol::PANCAKEV2,
                    address: Address::repeat_byte(0x70 + index as u8),
                    token0,
                    token1,
                    fee_bps: 25,
                },
                V2State {
                    reserve0: reserve,
                    reserve1: reserve,
                },
            )
        })
        .collect()
    }

    struct CapacityLimitedNative {
        slots: Semaphore,
        calls: AtomicUsize,
        active: AtomicUsize,
        max_active: AtomicUsize,
    }

    impl CapacityLimitedNative {
        fn new(limit: usize) -> Self {
            Self {
                slots: Semaphore::new(limit),
                calls: AtomicUsize::new(0),
                active: AtomicUsize::new(0),
                max_active: AtomicUsize::new(0),
            }
        }
    }

    impl NativeRfqSource for CapacityLimitedNative {
        fn indicative_quotes<'a>(
            &'a self,
            _identity: crate::chain::NativeRfqProfile,
            requests: &'a [(crate::rfq::NativePair, U256)],
        ) -> BoxFuture<'a, Result<Vec<(crate::rfq::NativePair, U256, U256)>, NativeRfqError>>
        {
            Box::pin(async move {
                Ok(requests
                    .iter()
                    .map(|(pair, amount)| (*pair, *amount, *amount))
                    .collect())
            })
        }

        fn firm_quote<'a>(
            &'a self,
            _request: crate::rfq::FirmQuoteRequest,
        ) -> BoxFuture<'a, Result<Option<crate::rfq::ValidatedFirmQuote>, NativeRfqError>> {
            Box::pin(async move {
                self.calls.fetch_add(1, Ordering::SeqCst);
                let _permit = self
                    .slots
                    .try_acquire()
                    .map_err(|_| NativeRfqError::Saturated)?;
                let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
                self.max_active.fetch_max(active, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(25)).await;
                self.active.fetch_sub(1, Ordering::SeqCst);
                Err(NativeRfqError::QueueTimeout)
            })
        }
    }

    fn burst_test_app(
        max_inflight: usize,
        compute_concurrency: usize,
        native_rfq: Option<Arc<dyn NativeRfqSource>>,
    ) -> Arc<App> {
        // Execution requests check their transaction against this chain.
        let (rpc, _server) = crate::simulation::test_chain::simulation_chain(
            crate::simulation::test_chain::SimulationChain::funded(),
        );
        let engine = Engine::for_profile(rpc.clone(), &BURST_TEST_PROFILE);
        seed_burst_snapshots(&engine);
        Arc::new(App {
            metrics: QuoteMetrics::default(),
            quote_queue: Arc::new(Semaphore::new(16)),
            quote_admission_wait: Duration::ZERO,
            cfg: Config {
                profile: &BURST_TEST_PROFILE,
                rpc_url: BURST_TEST_PROFILE.public_rpc.to_string(),
                logs_rpc_url: BURST_TEST_PROFILE.public_rpc.to_string(),
                indexer_url: None,
                native_rfq: None,
                fee_bps: 0,
                fee_receiver: None,
                positive_slippage_max_bps: 0,
                positive_slippage_recipient: None,
                port: 0,
                quote_timeout: 5,
            },
            rpc,
            engine,
            indexer: None,
            native_rfq,
            native_adapter: None,
            quote_slots: Arc::new(Semaphore::new(max_inflight)),
            compute_slots: Arc::new(Semaphore::new(compute_concurrency)),
            memory: crate::process_memory::ProcessMemory::new(None, 0).unwrap(),
            chain_verified: true,
            readiness: AsyncMutex::new(ReadinessState::new(true, true)),
        })
    }

    /// Publish a fresh snapshot for every burst market. Waves re-seed, so each
    /// one measures admission rather than the age of the previous wave's state.
    fn seed_burst_snapshots(engine: &Engine) {
        let mut seeded_pairs = Vec::new();
        for market in BURST_MARKETS {
            let pair = if market.token_in <= market.token_out {
                (market.token_in, market.token_out)
            } else {
                (market.token_out, market.token_in)
            };
            if seeded_pairs.contains(&pair) {
                continue;
            }
            seeded_pairs.push(pair);
            engine.cache_snapshot_for_test(
                market.token_in,
                market.token_out,
                crate::state::ObservedSnapshot {
                    snapshot: Snapshot {
                        block: 1,
                        settler: Some(Address::repeat_byte(0x66)),
                        v3: vec![],
                        v2: burst_v2_pools(),
                        ekubo: vec![],
                    },
                    screening: Default::default(),
                    universe: crate::universe::RouteUniverse::profile_only(
                        &BURST_TEST_PROFILE,
                        market.token_in,
                        market.token_out,
                    )
                    .unwrap(),
                    topology_fences: None,
                    block_id: alloy::eips::BlockId::hash_canonical(B256::repeat_byte(0x88)),
                    block_timestamp: 1_800_000_000,
                    observed_at: Instant::now(),
                },
            );
        }
    }

    fn burst_quote_body(attempt: BurstAttempt) -> Vec<u8> {
        let mut body = json!({
            "chainId": BURST_TEST_PROFILE.chain_id,
            "tokenIn": format!("{:#x}", attempt.market.token_in),
            "tokenOut": format!("{:#x}", attempt.market.token_out),
            "amountIn": attempt.market.amount_in,
            "slippageBps": 50,
            "deadlineSeconds": 60,
        });
        if attempt.execution_requested {
            let taker = format!("{:#x}", Address::repeat_byte(0x44));
            body["recipient"] = json!(taker);
            body["sender"] = json!(taker);
            body["txOrigin"] = json!(taker);
        }
        serde_json::to_vec(&body).unwrap()
    }
    #[tokio::test]
    async fn process_rss_threshold_rejects_multi_request_work_without_spending_quote_or_compute_slots()
     {
        let mut app = burst_test_app(2, 1, None);
        let memory = crate::process_memory::ProcessMemory::new(Some(1), 1).unwrap();
        assert!(memory.sample().rss_bytes.unwrap() > 1);
        Arc::get_mut(&mut app).unwrap().memory = memory.clone();
        let body = burst_quote_body(BurstAttempt {
            market: BURST_MARKETS[0],
            native_eligible: true,
            execution_requested: false,
        });
        let responses = futures_util::future::join_all(
            (0..32)
                .map(|_| handle_quote(State(app.clone()), Request::new(Body::from(body.clone())))),
        )
        .await;
        assert!(
            responses
                .iter()
                .all(|response| response.status() == StatusCode::SERVICE_UNAVAILABLE)
        );
        assert_eq!(app.quote_slots.available_permits(), 2);
        assert_eq!(app.compute_slots.available_permits(), 1);
        assert_eq!(memory.sample().rejected, 32);
        assert_eq!(memory.sample().reserved_new_work_bytes, 0);
    }

    fn fixture_display_quote_body() -> Vec<u8> {
        serde_json::to_vec(&json!({
            "chainId": FIXTURE_PROFILE.chain_id,
            "tokenIn": format!("{:#x}", Address::repeat_byte(0x11)),
            "tokenOut": format!("{:#x}", Address::repeat_byte(0x22)),
            "amountIn": "1",
            "slippageBps": 50,
            "deadlineSeconds": 60,
        }))
        .unwrap()
    }

    async fn run_burst_wave(
        app: Arc<App>,
        traffic: Vec<BurstAttempt>,
    ) -> Vec<(BurstAttempt, Response, Duration)> {
        let barrier = Arc::new(Barrier::new(traffic.len() + 1));
        let tasks = traffic.into_iter().map(|attempt| {
            let app = app.clone();
            let barrier = barrier.clone();
            tokio::spawn(async move {
                barrier.wait().await;
                let started = Instant::now();
                let response = handle_quote(
                    State(app),
                    Request::new(Body::from(burst_quote_body(attempt))),
                )
                .await;
                (attempt, response, started.elapsed())
            })
        });
        let tasks: Vec<_> = tasks.collect();
        barrier.wait().await;
        tokio::time::timeout(Duration::from_secs(10), async {
            futures_util::future::join_all(tasks)
                .await
                .into_iter()
                .map(|result| result.expect("burst quote task panicked"))
                .collect()
        })
        .await
        .expect("burst wave did not drain")
    }

    fn latency_percentiles(
        responses: &[(BurstAttempt, Response, Duration)],
    ) -> (u128, u128, u128, u128) {
        let mut micros: Vec<_> = responses
            .iter()
            .map(|(_, _, latency)| latency.as_micros())
            .collect();
        micros.sort_unstable();
        let at = |percent: usize| {
            let index = (micros.len() * percent).div_ceil(100).saturating_sub(1);
            micros[index.min(micros.len() - 1)]
        };
        (at(50), at(95), at(99), *micros.last().unwrap())
    }

    fn assert_burst_workload_is_diverse(responses: &[(BurstAttempt, Response, Duration)]) {
        let classes: std::collections::BTreeSet<_> = responses
            .iter()
            .map(|(attempt, _, _)| attempt.market.class)
            .collect();
        let shapes: std::collections::BTreeSet<_> = responses
            .iter()
            .map(|(attempt, _, _)| attempt.market.route_shape)
            .collect();
        let markets: std::collections::BTreeSet<_> = responses
            .iter()
            .map(|(attempt, _, _)| attempt.market.name)
            .collect();
        let amounts: std::collections::BTreeSet<_> = responses
            .iter()
            .map(|(attempt, _, _)| attempt.market.amount_in)
            .collect();
        assert_eq!(classes, ["crypto", "stable", "stock"].into_iter().collect());
        assert!(shapes.contains("direct"));
        assert!(shapes.contains("reverse"));
        assert!(shapes.contains("two-hop"));
        assert_eq!(markets.len(), BURST_MARKETS.len());
        assert!(amounts.len() >= 8);
    }

    async fn assert_amm_response_shape(attempt: BurstAttempt, response: Response) {
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["liquiditySource"], "amm");
        let expected_hops = if attempt.market.route_shape.starts_with("two-hop") {
            2
        } else {
            1
        };
        let legs = body["route"]
            .as_array()
            .expect("quote route must be an array");
        assert!(!legs.is_empty());
        assert!(legs.iter().all(|leg| {
            leg["hops"]
                .as_array()
                .is_some_and(|hops| hops.len() == expected_hops)
        }));
    }

    fn config() -> Config {
        Config {
            profile: &FIXTURE_PROFILE,
            rpc_url: FIXTURE_PROFILE.public_rpc.to_string(),
            logs_rpc_url: FIXTURE_PROFILE.public_rpc.to_string(),
            indexer_url: None,
            native_rfq: None,
            fee_bps: 0,
            fee_receiver: None,
            positive_slippage_max_bps: 0,
            positive_slippage_recipient: None,
            port: 0,
            quote_timeout: 1,
        }
    }

    fn native_test_config() -> crate::rfq::NativeRfqConfig {
        crate::rfq::NativeRfqConfig::new(
            "https://v2.api.native.org/swap-api-v2/",
            "test-api-key",
            Duration::from_millis(1_500),
            60,
            10,
            crate::rfq::NativeBeneficiaryAuthorizer::from_secret(
                "0x59c6995e998f97a5a0044976f0945389dc9e86dae88c7a8412f4603b6b78690d",
            )
            .unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn fixture_native_rfq_uses_the_registry_settler_and_stays_closed_without_stock_endpoints() {
        let cfg = Config {
            native_rfq: Some(native_test_config()),
            ..config()
        };
        assert!(cfg.profile.execution_enabled());
        assert!(crate::chain::FIXTURE_NATIVE_RFQ.stock_tokens.is_empty());
        // The fixture lists no reviewed stock endpoint, so enabling Native refuses to start.
        assert!(validate_config(&cfg).is_err());
        assert!(configured_native_adapter(&FIXTURE_PROFILE).is_err());
        assert!(matches!(
            configured_native_adapter(&BURST_TEST_PROFILE)
                .unwrap()
                .settler,
            NativeSettlerTarget::Registry { .. }
        ));
    }

    #[derive(Clone)]
    struct NativeStartupFixture {
        adapter: NativeAdapter,
        signer: Address,
        requests: Arc<std::sync::Mutex<Vec<serde_json::Value>>>,
    }

    async fn native_startup_rpc(
        State(state): State<NativeStartupFixture>,
        axum::Json(request): axum::Json<serde_json::Value>,
    ) -> axum::Json<serde_json::Value> {
        use alloy_sol_types::SolValue;
        state.requests.lock().unwrap().push(request.clone());
        let native = state.adapter.native;
        let result = match request["method"].as_str().unwrap() {
            "eth_getBlockByNumber" => json!({
                "hash": B256::repeat_byte(0x80), "parentHash": B256::repeat_byte(0x81),
                "sha3Uncles": B256::ZERO, "miner": Address::ZERO, "stateRoot": B256::ZERO,
                "transactionsRoot": B256::ZERO, "receiptsRoot": B256::ZERO,
                "logsBloom": format!("0x{}", "00".repeat(256)), "difficulty":"0x0", "number":"0x1",
                "gasLimit":"0x7a1200", "gasUsed":"0x0", "timestamp":"0x64", "extraData":"0x",
                "mixHash": B256::ZERO, "nonce":"0x0000000000000000", "transactions":[], "uncles":[],
            }),
            "eth_getCode" => {
                let to: Address = request["params"][0].as_str().unwrap().parse().unwrap();
                let code = if to == native.router {
                    "0x6001"
                } else if to == native.pool {
                    "0x6002"
                } else if to == native.credit_vault {
                    "0x6003"
                } else {
                    "0x6004"
                };
                json!(code)
            }
            "eth_call" => {
                let input = request["params"][0]
                    .get("input")
                    .or_else(|| request["params"][0].get("data"))
                    .unwrap()
                    .as_str()
                    .unwrap();
                let data = crate::abi::hexbytes(input).unwrap();
                let selector = &data[..4];
                let output = if selector == abi::contractRevisionCall::SELECTOR {
                    U256::from(native.contract_revision).abi_encode()
                } else if selector == abi::isNativePoolsCall::SELECTOR {
                    true.abi_encode()
                } else if selector == abi::routerCall::SELECTOR {
                    native.router.abi_encode()
                } else if selector == abi::vaultCall::SELECTOR
                    || selector == abi::treasuryCall::SELECTOR
                {
                    native.credit_vault.abi_encode()
                } else if selector == abi::WETH9Call::SELECTOR {
                    FIXTURE_PROFILE.wrapped_native.abi_encode()
                } else if selector == abi::nativeAuthorizationSignerCall::SELECTOR {
                    state.signer.abi_encode()
                } else if selector == abi::ISettlerRegistry::ownerOfCall::SELECTOR {
                    Address::repeat_byte(0x61).abi_encode()
                } else if selector == abi::eip712DomainCall::SELECTOR {
                    (
                        alloy_primitives::FixedBytes::<1>::from([native.domain_fields]),
                        native.domain_name.to_string(),
                        native.domain_version.to_string(),
                        U256::from(native.domain_chain_id),
                        native.pool,
                        B256::ZERO,
                        Vec::<U256>::new(),
                    )
                        .abi_encode_params()
                } else {
                    panic!("unexpected startup RPC selector")
                };
                json!(crate::abi::tohex(&output))
            }
            _ => panic!("unexpected startup RPC method"),
        };
        axum::Json(json!({"jsonrpc":"2.0", "id":request["id"], "result":result}))
    }

    #[tokio::test]
    async fn native_startup_checks_the_registry_settler_and_its_authorization_signer() {
        let expected = Address::repeat_byte(0x71);
        let executor = Address::repeat_byte(0x61);
        let adapter = NativeAdapter {
            native: crate::chain::NativeRfqProfile {
                router_runtime_hash: keccak256([0x60, 0x01]),
                pool_runtime_hash: keccak256([0x60, 0x02]),
                credit_vault_runtime_hash: keccak256([0x60, 0x03]),
                ..crate::chain::FIXTURE_NATIVE_RFQ
            },
            settler: NativeSettlerTarget::Registry {
                address: crate::chain::FIXTURE_SETTLER_REGISTRY,
                token_id: crate::chain::FIXTURE_SETTLER_TOKEN_ID,
            },
        };
        let requests = Arc::new(std::sync::Mutex::new(Vec::new()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = Router::new()
            .route("/", post(native_startup_rpc))
            .with_state(NativeStartupFixture {
                adapter,
                signer: expected,
                requests: requests.clone(),
            });
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let rpc = Rpc::connect(&format!("http://{address}")).unwrap();
        verify_native_rfq_adapter(&rpc, &FIXTURE_PROFILE, adapter, expected)
            .await
            .unwrap();
        let error =
            verify_native_rfq_adapter(&rpc, &FIXTURE_PROFILE, adapter, Address::repeat_byte(0x72))
                .await
                .unwrap_err();
        assert!(error.to_string().contains("does not match"));
        let recorded = requests.lock().unwrap();
        let auth_calls: Vec<_> = recorded
            .iter()
            .filter(|request| request["method"] == "eth_call")
            .filter(|request| {
                request["params"][0]
                    .get("input")
                    .or_else(|| request["params"][0].get("data"))
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|data| {
                        data.starts_with(&crate::abi::tohex(
                            &abi::nativeAuthorizationSignerCall::SELECTOR,
                        ))
                    })
            })
            .collect();
        assert_eq!(auth_calls.len(), 2);
        assert!(auth_calls.iter().all(|request| {
            request["params"][0]["to"]
                .as_str()
                .unwrap()
                .parse::<Address>()
                .unwrap()
                == executor
        }));
        assert!(recorded.iter().any(|request| {
            request["method"] == "eth_call"
                && request["params"][0]
                    .get("input")
                    .or_else(|| request["params"][0].get("data"))
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|data| {
                        data.starts_with(&crate::abi::tohex(
                            &abi::ISettlerRegistry::ownerOfCall::SELECTOR,
                        ))
                    })
        }));
        task.abort();
    }

    #[test]
    fn bsc_warmup_covers_its_v4_execution_binding() {
        warmup_for_profile(&crate::chain::BSC_PROFILE).unwrap();
    }

    #[test]
    fn quote_only_v4_warmup_uses_the_catalog_manager() {
        let mut profile = *crate::chain::BSC_PROFILE;
        profile.settler = None;
        assert!(!profile.execution_enabled());
        warmup_for_profile(&profile).unwrap();
    }

    #[test]
    fn startup_rejects_zero_fee_receiver_even_when_the_fee_is_disabled() {
        let cfg = Config {
            fee_receiver: Some(Address::ZERO),
            ..config()
        };
        let error = validate_config(&cfg).unwrap_err();
        assert!(error.to_string().contains("FEE_RECEIVER must not be zero"));
    }

    #[test]
    fn compute_concurrency_is_bounded_and_explicitly_validated() {
        assert_eq!(parse_compute_concurrency(None).unwrap(), 2);
        assert_eq!(parse_compute_concurrency(Some("1")).unwrap(), 1);
        assert_eq!(parse_compute_concurrency(Some("64")).unwrap(), 64);
        assert!(parse_compute_concurrency(Some("0")).is_err());
        assert!(parse_compute_concurrency(Some("65")).is_err());
        assert!(parse_compute_concurrency(Some("many")).is_err());
    }

    #[test]
    fn max_inflight_quotes_is_bounded_and_never_below_compute() {
        assert_eq!(parse_max_inflight_quotes(None, 2).unwrap(), 8);
        assert_eq!(parse_max_inflight_quotes(Some("2"), 2).unwrap(), 2);
        assert_eq!(parse_max_inflight_quotes(Some("256"), 64).unwrap(), 256);
        assert!(parse_max_inflight_quotes(Some("1"), 2).is_err());
        assert!(parse_max_inflight_quotes(Some("257"), 2).is_err());
        assert!(parse_max_inflight_quotes(Some("many"), 2).is_err());
    }

    #[test]
    fn quote_log_field_is_single_line_ascii_and_bounded() {
        let rendered = quote_log_field("token\nnext\r\t\0\u{1b}\\é");

        assert!(rendered.chars().all(|character| !character.is_control()));
        assert!(rendered.is_ascii());
        assert!(rendered.contains("\\n"));
        assert!(rendered.contains("\\r"));
        assert!(rendered.contains("\\u{1b}"));
        assert!(rendered.contains("\\\\"));

        let oversized = "é".repeat(MAX_QUOTE_LOG_FIELD_BYTES);
        let rendered = quote_log_field(&oversized);
        assert_eq!(rendered.len(), MAX_QUOTE_LOG_FIELD_BYTES);
        assert!(rendered.ends_with("..."));
    }

    #[test]
    fn quote_log_field_preserves_canonical_values() {
        let address = format!("{:#x}", Address::repeat_byte(0xab));
        let amount = U256::MAX.to_string();

        assert_eq!(quote_log_field(&address), address);
        assert_eq!(quote_log_field(&amount), amount);
    }

    #[tokio::test]
    async fn log_rendering_does_not_change_http_error_body() {
        let message = "bad address 0x1\nforged status=200".to_string();
        let rendered = quote_log_field(&message);
        assert!(!rendered.contains('\n'));
        assert!(rendered.contains("\\n"));

        let response = quote_error_response(
            StatusCode::BAD_REQUEST,
            &FIXTURE_PROFILE,
            "quote_failed",
            message.clone(),
            Some(FIXTURE_PROFILE.chain_id),
        );
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["error"], message);
    }

    #[test]
    fn native_authorization_signer_mismatch_fails_closed() {
        let configured = Address::repeat_byte(0x11);
        assert!(verify_native_authorization_signer(configured, configured).is_ok());
        let error =
            verify_native_authorization_signer(Address::repeat_byte(0x22), configured).unwrap_err();
        assert!(error.to_string().contains("does not match"));
    }

    #[test]
    fn native_pool_domain_matches_only_the_reviewed_identity() {
        let profile = &FIXTURE_PROFILE;
        let native = crate::chain::FIXTURE_NATIVE_RFQ;
        let valid = || {
            verify_native_pool_domain(
                profile,
                &native,
                native.domain_fields,
                native.domain_name,
                native.domain_version,
                U256::from(profile.chain_id),
                native.pool,
                B256::ZERO,
                &[],
            )
        };
        assert!(valid().is_ok());

        assert!(
            verify_native_pool_domain(
                profile,
                &native,
                native.domain_fields ^ 1,
                native.domain_name,
                native.domain_version,
                U256::from(profile.chain_id),
                native.pool,
                B256::ZERO,
                &[],
            )
            .is_err()
        );
        assert!(
            verify_native_pool_domain(
                profile,
                &native,
                native.domain_fields,
                "Native RFQ Pool lookalike",
                native.domain_version,
                U256::from(profile.chain_id),
                native.pool,
                B256::ZERO,
                &[],
            )
            .is_err()
        );
        assert!(
            verify_native_pool_domain(
                profile,
                &native,
                native.domain_fields,
                native.domain_name,
                "6",
                U256::from(profile.chain_id),
                native.pool,
                B256::ZERO,
                &[],
            )
            .is_err()
        );
        assert!(
            verify_native_pool_domain(
                profile,
                &native,
                native.domain_fields,
                native.domain_name,
                native.domain_version,
                U256::from(profile.chain_id + 1),
                native.pool,
                B256::ZERO,
                &[],
            )
            .is_err()
        );
        assert!(
            verify_native_pool_domain(
                profile,
                &native,
                native.domain_fields,
                native.domain_name,
                native.domain_version,
                U256::from(profile.chain_id),
                Address::repeat_byte(0x11),
                B256::ZERO,
                &[],
            )
            .is_err()
        );
        assert!(
            verify_native_pool_domain(
                profile,
                &native,
                native.domain_fields,
                native.domain_name,
                native.domain_version,
                U256::from(profile.chain_id),
                native.pool,
                B256::repeat_byte(0x22),
                &[],
            )
            .is_err()
        );
        assert!(
            verify_native_pool_domain(
                profile,
                &native,
                native.domain_fields,
                native.domain_name,
                native.domain_version,
                U256::from(profile.chain_id),
                native.pool,
                B256::ZERO,
                &[U256::from(1)],
            )
            .is_err()
        );
    }

    #[test]
    fn native_adapter_rpc_error_drops_secret_source_chain() {
        let secret = "https://paid-rpc.example/super-secret-native-startup-key";
        let error = anyhow::anyhow!("transport failed at {secret}")
            .context(crate::rpc::RpcUnavailable("eth_call"));
        let rendered = format!("{:#}", native_rfq_adapter_error(error));

        assert!(rendered.contains("upstream rpc failed: eth_call"));
        assert!(!rendered.contains(secret));
        assert!(!rendered.contains("super-secret-native-startup-key"));
    }

    #[test]
    fn quote_timeout_is_positive_and_bounded() {
        let zero = Config {
            quote_timeout: 0,
            ..config()
        };
        assert!(validate_config(&zero).is_err());
        let too_large = Config {
            quote_timeout: MAX_QUOTE_TIMEOUT_SECS + 1,
            ..config()
        };
        assert!(validate_config(&too_large).is_err());
        let boundary = Config {
            quote_timeout: MAX_QUOTE_TIMEOUT_SECS,
            ..config()
        };
        assert!(validate_config(&boundary).is_ok());
    }

    #[test]
    fn startup_requires_nonzero_enabled_recipients() {
        let missing_fee = Config {
            fee_bps: 9,
            ..config()
        };
        assert!(validate_config(&missing_fee).is_err());

        let missing_positive = Config {
            positive_slippage_max_bps: 1,
            ..config()
        };
        assert!(validate_config(&missing_positive).is_err());

        let zero_positive = Config {
            positive_slippage_recipient: Some(Address::ZERO),
            ..config()
        };
        assert!(validate_config(&zero_positive).is_err());
    }

    #[test]
    fn startup_takes_an_indexer_only_where_one_names_the_pools() {
        // The fixture's factories name its pools: an indexer URL is refused, not
        // silently ignored.
        assert!(validate_config(&config()).is_ok());
        let fixture_with_indexer = Config {
            indexer_url: Some("http://fixture-indexer:8787".to_string()),
            ..config()
        };
        let error = validate_config(&fixture_with_indexer).unwrap_err();
        assert!(
            error.to_string().contains("names its pools by factory"),
            "{error:#}"
        );
        assert!(configured_indexer(&config()).unwrap().is_none());

        // An indexer-backed table still requires one.
        let bsc = &crate::chain::BSC_PROFILE;
        let error = check_indexer_url(bsc, None).unwrap_err();
        assert!(error.to_string().contains("SOLVER_INDEXER_URL is required"));
        assert!(check_indexer_url(bsc, Some(" ")).is_err());
        assert!(check_indexer_url(bsc, Some("http://bsc-indexer:8787")).is_ok());

        let robinhood = &crate::chain::ROBINHOOD_PROFILE;
        assert!(check_indexer_url(robinhood, None).is_ok());
        assert!(check_indexer_url(robinhood, Some("http://indexer:8787")).is_err());
    }

    /// The fixture without its Settler, as a chain whose Settler is not deployed.
    fn fixture_quote_only() -> &'static ChainProfile {
        Box::leak(Box::new(ChainProfile {
            settler: None,
            native_rfq: None,
            ..FIXTURE_PROFILE
        }))
    }

    #[test]
    fn quote_only_profile_rejects_execution_configuration() {
        let quote_only = || Config {
            profile: fixture_quote_only(),
            ..config()
        };
        assert!(validate_execution_settings(&quote_only()).is_ok());
        let fee = Config {
            fee_bps: 9,
            fee_receiver: Some(Address::repeat_byte(0x11)),
            ..quote_only()
        };
        assert!(validate_execution_settings(&fee).is_err());
        let dormant_receiver = Config {
            fee_receiver: Some(Address::repeat_byte(0x11)),
            ..quote_only()
        };
        assert!(validate_execution_settings(&dormant_receiver).is_err());
        let positive_slippage = Config {
            positive_slippage_max_bps: 100,
            positive_slippage_recipient: Some(Address::repeat_byte(0x22)),
            ..quote_only()
        };
        assert!(validate_execution_settings(&positive_slippage).is_err());

        // With its Settler, the fixture accepts the same settings; the launch
        // configuration keeps both at zero.
        let executable_fee = Config {
            fee_bps: 9,
            fee_receiver: Some(Address::repeat_byte(0x11)),
            ..config()
        };
        assert!(validate_config(&executable_fee).is_ok());
    }

    #[test]
    fn startup_rejects_incoherent_profile_capabilities() {
        let mut execution_without_quotes = *crate::chain::BSC_PROFILE;
        execution_without_quotes.capabilities.quote = false;
        execution_without_quotes.settler = crate::chain::ROBINHOOD_PROFILE.settler;
        let error = validate_profile(&execution_without_quotes).unwrap_err();
        assert!(error.to_string().contains("execution without quote"));

        let mut quotes_without_discovery = *crate::chain::BSC_PROFILE;
        quotes_without_discovery.discovery = DiscoveryProfile::Disabled;
        let error = validate_profile(&quotes_without_discovery).unwrap_err();
        assert!(error.to_string().contains("without pool discovery"));

        let mut indexed_with_foreign_execution_adapter = *crate::chain::BSC_PROFILE;
        indexed_with_foreign_execution_adapter.settler = crate::chain::ROBINHOOD_PROFILE.settler;
        let error = validate_profile(&indexed_with_foreign_execution_adapter).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("not an exact reviewed solver profile")
        );

        let mut bsc_with_robinhood_discovery = *crate::chain::BSC_PROFILE;
        bsc_with_robinhood_discovery.discovery = DiscoveryProfile::Robinhood;
        bsc_with_robinhood_discovery.capabilities.quote = true;
        let error = validate_profile(&bsc_with_robinhood_discovery).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("not an exact reviewed solver profile")
        );
    }

    #[test]
    fn upstream_rpc_markers_never_map_to_bad_request() {
        let unavailable =
            anyhow::anyhow!("details").context(RpcUnavailable("eth_getBlockByNumber"));
        assert_eq!(quote_error_status(&unavailable), StatusCode::BAD_GATEWAY);

        let rejected = anyhow::anyhow!("details").context(RpcRejected("eth_call"));
        assert_eq!(quote_error_status(&rejected), StatusCode::BAD_GATEWAY);

        let indexer = IndexerClient::builder("://secret-indexer-key", &crate::chain::BSC_PROFILE)
            .unwrap_err();
        assert_eq!(
            quote_error_status(&anyhow::Error::new(indexer)),
            StatusCode::BAD_GATEWAY
        );
        let integrity = anyhow::Error::new(UpstreamIntegrityError::test_only(
            "factory identity mismatch",
        ));
        assert_eq!(quote_error_status(&integrity), StatusCode::BAD_GATEWAY);
        assert_eq!(
            quote_error_status(&anyhow::anyhow!("no route")),
            StatusCode::BAD_REQUEST
        );
    }

    #[tokio::test]
    async fn native_capacity_is_retryable_service_unavailable() {
        for error in [
            NativeRfqError::Saturated,
            NativeRfqError::QueueTimeout,
            NativeRfqError::Api(201_005),
        ] {
            assert_eq!(
                quote_error_status(&anyhow::Error::new(error)),
                StatusCode::SERVICE_UNAVAILABLE
            );
        }

        let response = native_busy_response(&FIXTURE_PROFILE, Some(FIXTURE_PROFILE.chain_id));
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.headers()[RETRY_AFTER], "1");
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["code"], "native_busy");
        assert_eq!(body["requestedChainId"], FIXTURE_PROFILE.chain_id);
    }

    #[test]
    fn cooperative_compute_deadline_maps_to_gateway_timeout() {
        let error: anyhow::Error = SolverBudgetExceeded {
            stage: "route allocation",
        }
        .into();
        assert_eq!(quote_error_status(&error), StatusCode::GATEWAY_TIMEOUT);
    }

    #[tokio::test]
    async fn typed_no_route_is_422_and_preserves_universe_provenance() {
        let fences = CatalogFences {
            v23: crate::topology::V23Fence {
                seq: 17,
                generation: 3,
            },
            v4: None,
        };
        let diagnostics =
            |source: &'static str, fallback_reason: Option<&'static str>, truncated: bool| {
                let scope = if source == "adjacency_complete" {
                    "common_neighbor_two_hop"
                } else {
                    "profile"
                };
                crate::universe::RouteUniverseDiagnostics {
                    source,
                    fallback_stage: fallback_reason.map(|_| "adjacency"),
                    fallback_reason,
                    scope,
                    selector: "none",
                    selection_scope: scope,
                    protocol_mask: 0b1111,
                    eligible_count: 0,
                    connector_count: 0,
                    shortlist_truncated: truncated,
                    screened_count: 0,
                    adjacency_fences: (fallback_reason.is_none()).then_some(fences),
                    fingerprint: alloy_primitives::B256::repeat_byte(0x44),
                }
            };
        let complete = NoRouteError {
            route_universe: crate::quotes::RouteUniverseJson::new(
                56,
                123,
                alloy_primitives::B256::repeat_byte(0x55),
                diagnostics("adjacency_complete", None, false),
                Some(fences),
            ),
        };
        assert_eq!(
            quote_error_status(&anyhow::Error::new(complete.clone())),
            StatusCode::UNPROCESSABLE_ENTITY
        );
        let response = no_route_response(&crate::chain::BSC_PROFILE, &complete, Some(56));
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["schemaVersion"], 1);
        assert_eq!(body["code"], "no_route");
        assert_eq!(body["chain"], "bsc");
        assert_eq!(body["chainId"], 56);
        assert_eq!(body["requestedChainId"], 56);
        assert_eq!(body["routeUniverse"]["version"], 1);
        assert_eq!(body["routeUniverse"]["chainId"], 56);
        assert_eq!(body["routeUniverse"]["canonicalBlock"]["number"], 123);
        assert_eq!(
            body["routeUniverse"]["canonicalBlock"]["hash"],
            format!("{:#x}", alloy_primitives::B256::repeat_byte(0x55))
        );
        assert_eq!(body["routeUniverse"]["source"], "adjacency_complete");
        assert_eq!(body["routeUniverse"]["shortlistTruncated"], false);
        assert_eq!(body["routeUniverse"]["adjacencyFences"]["v23"]["seq"], "17");
        assert_eq!(
            body["routeUniverse"]["topologyFences"]["v23"]["generation"],
            "3"
        );

        let fallback = NoRouteError {
            route_universe: crate::quotes::RouteUniverseJson::new(
                56,
                124,
                alloy_primitives::B256::repeat_byte(0x66),
                diagnostics("adjacency_fallback", Some("transport"), true),
                Some(fences),
            ),
        };
        let response = no_route_response(&crate::chain::BSC_PROFILE, &fallback, Some(56));
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["routeUniverse"]["source"], "adjacency_fallback");
        assert_eq!(body["routeUniverse"]["fallbackReason"], "transport");
        assert_eq!(body["routeUniverse"]["shortlistTruncated"], true);
        assert!(body["routeUniverse"]["adjacencyFences"].is_null());
    }

    #[tokio::test]
    async fn startup_chain_probe_drops_rpc_error_source() {
        let secret = "super-secret-rpc-key";
        let rpc = Rpc::connect(&format!("http://127.0.0.1:1/{secret}")).unwrap();
        let error = verify_rpc_chain(&rpc, 4663, "primary").await.unwrap_err();
        let rendered = format!("{error:#}");

        assert_eq!(
            rendered,
            "primary RPC verification failed: upstream rpc failed: eth_chainId"
        );
        assert!(!rendered.contains(secret));
        assert!(!rendered.contains("127.0.0.1"));
    }

    #[test]
    fn request_chain_gate_rejects_mismatch_and_execution_on_quote_only_profiles() {
        let request = |chain_id, recipient| QuoteRequest {
            chain_id,
            token_in: format!("{:#x}", Address::repeat_byte(0x11)),
            token_out: format!("{:#x}", Address::repeat_byte(0x22)),
            amount_in: crate::quotes::AmountIn::Str("1".to_string()),
            slippage_bps: 50,
            recipient,
            sender: None,
            tx_origin: None,
            deadline_seconds: 600,
            fee_bps: None,
        };
        assert_eq!(
            gate_quote_request(&FIXTURE_PROFILE, &request(56, None)),
            Err(QuoteGate::ChainMismatch(56))
        );
        assert!(gate_quote_request(&FIXTURE_PROFILE, &request(2_818, None)).is_ok());
        let with_recipient = request(2_818, Some(format!("{:#x}", Address::repeat_byte(0x33))));
        assert!(gate_quote_request(&FIXTURE_PROFILE, &with_recipient).is_ok());
        let quote_only = fixture_quote_only();
        assert_eq!(
            gate_quote_request(quote_only, &with_recipient),
            Err(QuoteGate::ExecutionUnavailable)
        );
        let mut unexecutable_fee = request(2_818, None);
        unexecutable_fee.fee_bps = Some(9);
        assert_eq!(
            gate_quote_request(quote_only, &unexecutable_fee),
            Err(QuoteGate::ExecutionUnavailable)
        );
    }

    #[tokio::test]
    async fn body_validation_precedes_saturated_quote_admission() {
        let quote_slots = Arc::new(Semaphore::new(1));
        let held = quote_slots.clone().acquire_owned().await.unwrap();
        let app = Arc::new(App {
            metrics: QuoteMetrics::default(),
            quote_queue: Arc::new(Semaphore::new(16)),
            quote_admission_wait: Duration::ZERO,
            cfg: config(),
            rpc: Rpc::connect("http://127.0.0.1:1").unwrap(),
            engine: Engine::new(Rpc::connect("http://127.0.0.1:1").unwrap()),
            indexer: None,
            native_rfq: None,
            native_adapter: None,
            quote_slots: quote_slots.clone(),
            compute_slots: Arc::new(Semaphore::new(1)),
            memory: crate::process_memory::ProcessMemory::new(None, 0).unwrap(),
            chain_verified: false,
            readiness: AsyncMutex::new(ReadinessState::new(false, true)),
        });

        let mut sampled_response = None;
        for _ in 0..3 {
            let responses = tokio::time::timeout(
                Duration::from_millis(500),
                futures_util::future::join_all((0..128).map(|_| {
                    handle_quote(State(app.clone()), Request::new(Body::from("not json")))
                })),
            )
            .await
            .expect("bounded malformed-body burst did not drain");
            assert_eq!(responses.len(), 128);
            for response in &responses {
                assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            }
            sampled_response = responses.into_iter().next();
        }

        let response = sampled_response.expect("burst produced no response");
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["code"], "bad_request");
        assert_eq!(body["chainId"], 2_818);
        assert_eq!(body["requestedChainId"], serde_json::Value::Null);

        let response = handle_quote(
            State(app.clone()),
            Request::new(Body::from(vec![0; MAX_QUOTE_REQUEST_BYTES + 1])),
        )
        .await;
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(quote_slots.available_permits(), 0);

        let response = handle_quote(
            State(app.clone()),
            Request::new(Body::from(fixture_display_quote_body())),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.headers()[RETRY_AFTER], "1");
        assert_eq!(
            response.headers()[ACCESS_CONTROL_EXPOSE_HEADERS],
            "Retry-After"
        );
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["code"], "overloaded");

        drop(held);

        let response = handle_quote(State(app.clone()), Request::new(Body::from("not json"))).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(quote_slots.available_permits(), 1);
        // Three bursts of malformed bodies, the oversized one and the last.
        assert_eq!(app.metrics.count(QuoteOutcome::BadRequest), 3 * 128 + 2);
        assert_eq!(app.metrics.count(QuoteOutcome::Overloaded), 1);
    }

    #[test]
    fn a_callers_time_limit_only_shortens_the_quote() {
        assert_eq!(quote_time_limit(120, None), Duration::from_secs(120));
        assert_eq!(quote_time_limit(120, Some("5000")), Duration::from_secs(5));
        assert_eq!(quote_time_limit(5, Some("60000")), Duration::from_secs(5));
        for ignored in ["0", "-1", "soon", ""] {
            assert_eq!(quote_time_limit(5, Some(ignored)), Duration::from_secs(5));
        }
        assert_eq!(parse_quote_admission_wait("0").unwrap(), Duration::ZERO);
        assert_eq!(
            parse_quote_admission_wait("1000").unwrap(),
            Duration::from_secs(1)
        );
        assert!(parse_quote_admission_wait("10001").is_err());
        assert!(parse_quote_admission_wait("1s").is_err());
    }

    #[tokio::test]
    async fn a_busy_solver_queues_quotes_in_order_until_their_deadline() {
        let quote_slots = Arc::new(Semaphore::new(1));
        let app = Arc::new(App {
            metrics: QuoteMetrics::default(),
            quote_queue: Arc::new(Semaphore::new(1)),
            quote_admission_wait: Duration::from_secs(5),
            cfg: config(),
            rpc: Rpc::connect("http://127.0.0.1:1").unwrap(),
            engine: Engine::new(Rpc::connect("http://127.0.0.1:1").unwrap()),
            indexer: None,
            native_rfq: None,
            native_adapter: None,
            quote_slots: quote_slots.clone(),
            compute_slots: Arc::new(Semaphore::new(1)),
            memory: crate::process_memory::ProcessMemory::new(None, 0).unwrap(),
            chain_verified: false,
            readiness: AsyncMutex::new(ReadinessState::new(false, true)),
        });
        let quote = |limit_ms: Option<&'static str>| {
            let mut request = Request::new(Body::from(fixture_display_quote_body()));
            if let Some(ms) = limit_ms {
                request
                    .headers_mut()
                    .insert("x-quote-timeout-ms", HeaderValue::from_static(ms));
            }
            handle_quote(State(app.clone()), request)
        };

        // With the one slot busy, a quote takes the queue's one place.
        let held = quote_slots.clone().acquire_owned().await.unwrap();
        let waiting = tokio::spawn(quote(None));
        tokio::time::timeout(Duration::from_secs(2), async {
            while app.metrics.json()["waiting"] != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the quote never queued");
        // The next finds the queue full and is refused at once.
        let started = Instant::now();
        assert_eq!(quote(None).await.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(app.metrics.count(QuoteOutcome::Overloaded), 1);
        // The released slot goes to the waiting quote, which runs on (and finds
        // the solver not ready).
        drop(held);
        waiting.await.unwrap();
        assert_eq!(app.metrics.count(QuoteOutcome::NotReady), 1);
        assert_eq!(app.metrics.count(QuoteOutcome::Overloaded), 1);

        // A caller that stops waiting after 50 ms is refused then, not after
        // the solver's five-second wait.
        let held = quote_slots.clone().acquire_owned().await.unwrap();
        let started = Instant::now();
        assert_eq!(
            quote(Some("50")).await.status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        let waited = started.elapsed();
        assert!(
            waited >= Duration::from_millis(50) && waited < Duration::from_secs(2),
            "{waited:?}"
        );
        assert_eq!(app.metrics.count(QuoteOutcome::Overloaded), 2);
        let metrics = app.metrics.json();
        assert_eq!(
            (metrics["waiting"].clone(), metrics["queued"].clone()),
            (json!(0), json!(2))
        );
        drop(held);
    }

    #[tokio::test]
    async fn a_quote_answers_with_its_request_id_and_is_counted() {
        let app = Arc::new(App {
            metrics: QuoteMetrics::default(),
            quote_queue: Arc::new(Semaphore::new(16)),
            quote_admission_wait: Duration::ZERO,
            cfg: config(),
            rpc: Rpc::connect("http://127.0.0.1:1").unwrap(),
            engine: Engine::new(Rpc::connect("http://127.0.0.1:1").unwrap()),
            indexer: None,
            native_rfq: None,
            native_adapter: None,
            quote_slots: Arc::new(Semaphore::new(1)),
            compute_slots: Arc::new(Semaphore::new(1)),
            memory: crate::process_memory::ProcessMemory::new(None, 0).unwrap(),
            chain_verified: false,
            readiness: AsyncMutex::new(ReadinessState::new(false, true)),
        });
        let id = "6f2c7a1e-0b4d-4f6a-9a3e-2b1c0d9e8f7a";
        let mut request = Request::new(Body::from("not json"));
        request
            .headers_mut()
            .insert("x-request-id", HeaderValue::from_static(id));
        let response = handle_quote(State(app.clone()), request).await;
        assert_eq!(response.headers()["x-request-id"], id);
        let unnamed = handle_quote(State(app.clone()), Request::new(Body::from("not json"))).await;
        assert!(
            unnamed.headers()["x-request-id"]
                .to_str()
                .unwrap()
                .starts_with("solver-")
        );

        let metrics = handle_metrics(State(app.clone())).await;
        assert_eq!(metrics.status(), StatusCode::OK);
        let text = String::from_utf8(
            axum::body::to_bytes(metrics.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(text.contains("solver_quotes_total{outcome=\"bad_request\"} 2\n"));
        assert!(text.contains("solver_quote_duration_ms_count 2\n"));
        assert!(text.contains("solver_quote_slots_available 1\n"));
        assert!(text.contains("solver_rpc_unknown_dispatches 0\n"));
    }

    #[tokio::test]
    async fn slow_body_does_not_consume_quote_admission_capacity() {
        let quote_slots = Arc::new(Semaphore::new(1));
        let app = Arc::new(App {
            metrics: QuoteMetrics::default(),
            quote_queue: Arc::new(Semaphore::new(16)),
            quote_admission_wait: Duration::ZERO,
            cfg: config(),
            rpc: Rpc::connect("http://127.0.0.1:1").unwrap(),
            engine: Engine::new(Rpc::connect("http://127.0.0.1:1").unwrap()),
            indexer: None,
            native_rfq: None,
            native_adapter: None,
            quote_slots: quote_slots.clone(),
            compute_slots: Arc::new(Semaphore::new(1)),
            memory: crate::process_memory::ProcessMemory::new(None, 0).unwrap(),
            chain_verified: false,
            readiness: AsyncMutex::new(ReadinessState::new(false, true)),
        });
        let first_chunk_polled = Arc::new(AtomicBool::new(false));
        let polled = first_chunk_polled.clone();
        let slow_stream = stream::once(async move {
            polled.store(true, Ordering::SeqCst);
            Ok::<Bytes, Infallible>(Bytes::from_static(b"{"))
        })
        .chain(stream::pending::<Result<Bytes, Infallible>>());
        let slow_request = tokio::spawn(handle_quote(
            State(app.clone()),
            Request::new(Body::from_stream(slow_stream)),
        ));

        tokio::time::timeout(Duration::from_secs(1), async {
            while !first_chunk_polled.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("slow body was never polled");
        assert_eq!(quote_slots.available_permits(), 1);

        let response = handle_quote(
            State(app),
            Request::new(Body::from(fixture_display_quote_body())),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["code"], "not_ready");
        assert_eq!(quote_slots.available_permits(), 1);

        slow_request.abort();
        let _ = slow_request.await;
        assert_eq!(quote_slots.available_permits(), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn three_full_128_request_waves_drain_without_leaking_capacity() {
        const WAVE_SIZE: usize = 128;
        const WAVES: usize = 3;
        const COMPUTE_CONCURRENCY: usize = 4;
        let app = burst_test_app(WAVE_SIZE, COMPUTE_CONCURRENCY, None);

        for wave in 1..=WAVES {
            let responses =
                run_burst_wave(app.clone(), diverse_burst_wave(WAVE_SIZE, wave - 1, false)).await;
            assert_eq!(responses.len(), WAVE_SIZE);
            assert_burst_workload_is_diverse(&responses);
            assert!(
                responses
                    .iter()
                    .all(|(_, response, _)| { response.status() == StatusCode::OK })
            );
            let (p50_us, p95_us, p99_us, max_us) = latency_percentiles(&responses);
            eprintln!(
                "solver burst wave={wave} attempts={WAVE_SIZE} ok={WAVE_SIZE} p50_us={p50_us} p95_us={p95_us} p99_us={p99_us} max_us={max_us}",
            );
            for (attempt, response, _) in responses {
                assert_amm_response_shape(attempt, response).await;
            }
            assert_eq!(app.quote_slots.available_permits(), WAVE_SIZE);
            assert_eq!(app.compute_slots.available_permits(), COMPUTE_CONCURRENCY);
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn overlapping_128_request_waves_shed_load_and_fully_recover() {
        const WAVE_SIZE: usize = 128;
        const WAVES: usize = 3;
        const COMPUTE_CONCURRENCY: usize = 4;
        let app = burst_test_app(WAVE_SIZE, COMPUTE_CONCURRENCY, None);
        let waves = (0..WAVES).map(|wave| {
            let app = app.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis((wave * 10) as u64)).await;
                run_burst_wave(app, diverse_burst_wave(WAVE_SIZE, wave, false)).await
            })
        });
        let waves = futures_util::future::join_all(waves).await;
        let mut ok = 0usize;
        let mut overloaded = 0usize;
        for wave in waves {
            for (_, response, _) in wave.expect("overlapping wave task panicked") {
                match response.status() {
                    StatusCode::OK => ok += 1,
                    StatusCode::SERVICE_UNAVAILABLE => {
                        assert_eq!(response.headers()[RETRY_AFTER], "1");
                        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                            .await
                            .unwrap();
                        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
                        assert_eq!(body["code"], "overloaded");
                        overloaded += 1;
                    }
                    status => panic!("unexpected overlapping-burst status {status}"),
                }
            }
        }
        eprintln!(
            "solver overlapping bursts waves={WAVES} attempts={} ok={ok} overloaded={overloaded}",
            WAVES * WAVE_SIZE
        );
        assert_eq!(ok + overloaded, WAVES * WAVE_SIZE);
        assert!(ok >= WAVE_SIZE);
        assert!(overloaded > 0);
        assert_eq!(app.quote_slots.available_permits(), WAVE_SIZE);
        assert_eq!(app.compute_slots.available_permits(), COMPUTE_CONCURRENCY);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn native_capacity_waves_do_not_block_or_disguise_amm_quotes() {
        const WAVE_SIZE: usize = 128;
        const WAVES: usize = 3;
        const NATIVE_CONCURRENCY: usize = 8;
        const COMPUTE_CONCURRENCY: usize = 4;
        let native = Arc::new(CapacityLimitedNative::new(NATIVE_CONCURRENCY));
        let app = burst_test_app(
            WAVE_SIZE,
            COMPUTE_CONCURRENCY,
            Some(native.clone() as Arc<dyn NativeRfqSource>),
        );

        for wave in 1..=WAVES {
            // Native-eligible stock requests hit a separate capacity boundary
            // while diverse AMM-only crypto and stablecoin routes keep using
            // the same bounded solver compute pool.
            let traffic = diverse_burst_wave(WAVE_SIZE, wave - 1, true);
            seed_burst_snapshots(&app.engine);
            let responses = run_burst_wave(app.clone(), traffic).await;
            assert_burst_workload_is_diverse(&responses);
            let mut amm_ok = 0usize;
            let mut native_busy = 0usize;
            let mut max_latency = Duration::ZERO;
            let mut class_outcomes =
                std::collections::BTreeMap::<&'static str, (usize, usize)>::new();
            for (attempt, response, latency) in responses {
                max_latency = max_latency.max(latency);
                let outcomes = class_outcomes.entry(attempt.market.class).or_default();
                if attempt.native_eligible {
                    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
                    assert_eq!(response.headers()[RETRY_AFTER], "1");
                    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                        .await
                        .unwrap();
                    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
                    assert_eq!(body["code"], "native_busy");
                    native_busy += 1;
                    outcomes.1 += 1;
                } else {
                    assert_amm_response_shape(attempt, response).await;
                    amm_ok += 1;
                    outcomes.0 += 1;
                }
            }
            eprintln!(
                "solver mixed burst wave={wave} attempts={WAVE_SIZE} amm_ok={amm_ok} native_busy={native_busy} max_latency_ms={}",
                max_latency.as_millis()
            );
            assert_eq!(amm_ok, WAVE_SIZE / 2);
            assert_eq!(native_busy, WAVE_SIZE / 2);
            let (stock_amm_ok, stock_native_busy) = class_outcomes["stock"];
            assert_eq!(stock_amm_ok, 0);
            assert!(
                stock_native_busy > 0,
                "stock Native traffic was not exercised"
            );
            for class in ["crypto", "stable"] {
                let (class_amm_ok, class_native_busy) = class_outcomes[class];
                assert!(class_amm_ok > 0, "{class} AMM traffic was not exercised");
                assert_eq!(
                    class_native_busy, 0,
                    "{class} endpoints must never enter Native capacity"
                );
            }
            assert_eq!(app.quote_slots.available_permits(), WAVE_SIZE);
            assert_eq!(app.compute_slots.available_permits(), COMPUTE_CONCURRENCY);
            assert_eq!(native.slots.available_permits(), NATIVE_CONCURRENCY);
            assert_eq!(native.active.load(Ordering::SeqCst), 0);
        }

        assert_eq!(native.calls.load(Ordering::SeqCst), WAVES * WAVE_SIZE / 2);
        assert_eq!(native.max_active.load(Ordering::SeqCst), NATIVE_CONCURRENCY);
    }

    #[tokio::test]
    async fn mismatched_request_is_rejected_before_any_snapshot_rpc() {
        let app = Arc::new(App {
            metrics: QuoteMetrics::default(),
            quote_queue: Arc::new(Semaphore::new(16)),
            quote_admission_wait: Duration::ZERO,
            cfg: config(),
            rpc: Rpc::connect("http://127.0.0.1:1").unwrap(),
            engine: Engine::new(Rpc::connect("http://127.0.0.1:1").unwrap()),
            indexer: None,
            native_rfq: None,
            native_adapter: None,
            quote_slots: Arc::new(Semaphore::new(1)),
            compute_slots: Arc::new(Semaphore::new(1)),
            memory: crate::process_memory::ProcessMemory::new(None, 0).unwrap(),
            chain_verified: false,
            readiness: AsyncMutex::new(ReadinessState::new(false, true)),
        });
        let body = Bytes::from(
            serde_json::to_vec(&json!({
                "chainId": 56,
                "tokenIn": format!("{:#x}", Address::repeat_byte(0x11)),
                "tokenOut": format!("{:#x}", Address::repeat_byte(0x22)),
                "amountIn": "1"
            }))
            .unwrap(),
        );
        let response = handle_quote(State(app), Request::new(Body::from(body))).await;
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["code"], "chain_mismatch");
        assert_eq!(body["chainId"], 2_818);
        assert_eq!(body["requestedChainId"], 56);
    }

    #[tokio::test]
    async fn missing_request_chain_id_is_rejected_as_a_bad_request() {
        let app = Arc::new(App {
            metrics: QuoteMetrics::default(),
            quote_queue: Arc::new(Semaphore::new(16)),
            quote_admission_wait: Duration::ZERO,
            cfg: config(),
            rpc: Rpc::connect("http://127.0.0.1:1").unwrap(),
            engine: Engine::new(Rpc::connect("http://127.0.0.1:1").unwrap()),
            indexer: None,
            native_rfq: None,
            native_adapter: None,
            quote_slots: Arc::new(Semaphore::new(1)),
            compute_slots: Arc::new(Semaphore::new(1)),
            memory: crate::process_memory::ProcessMemory::new(None, 0).unwrap(),
            chain_verified: false,
            readiness: AsyncMutex::new(ReadinessState::new(false, true)),
        });
        let body = Bytes::from(
            serde_json::to_vec(&json!({
                "tokenIn": format!("{:#x}", Address::repeat_byte(0x11)),
                "tokenOut": format!("{:#x}", Address::repeat_byte(0x22)),
                "amountIn": "1"
            }))
            .unwrap(),
        );
        let response = handle_quote(State(app), Request::new(Body::from(body))).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["code"], "bad_request");
        assert_eq!(body["chainId"], 2_818);
    }

    #[tokio::test]
    async fn valid_quote_is_rejected_while_cached_readiness_is_failed() {
        let app = Arc::new(App {
            metrics: QuoteMetrics::default(),
            quote_queue: Arc::new(Semaphore::new(16)),
            quote_admission_wait: Duration::ZERO,
            cfg: config(),
            rpc: Rpc::connect("http://127.0.0.1:1").unwrap(),
            engine: Engine::for_profile(
                Rpc::connect("http://127.0.0.1:1").unwrap(),
                &FIXTURE_PROFILE,
            ),
            indexer: None,
            native_rfq: None,
            native_adapter: None,
            quote_slots: Arc::new(Semaphore::new(1)),
            compute_slots: Arc::new(Semaphore::new(1)),
            memory: crate::process_memory::ProcessMemory::new(None, 0).unwrap(),
            chain_verified: true,
            readiness: AsyncMutex::new(ReadinessState::new(false, true)),
        });
        let body = Bytes::from(
            serde_json::to_vec(&json!({
                "chainId": 2_818,
                "tokenIn": format!("{:#x}", Address::repeat_byte(0x11)),
                "tokenOut": format!("{:#x}", Address::repeat_byte(0x22)),
                "amountIn": "1"
            }))
            .unwrap(),
        );

        let response = handle_quote(State(app), Request::new(Body::from(body))).await;

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["code"], "not_ready");
        assert_eq!(body["chainId"], 2_818);
        assert_eq!(body["requestedChainId"], 2_818);
    }

    #[tokio::test]
    async fn health_exposes_verified_instance_identity_and_capabilities() {
        let app = Arc::new(App {
            metrics: QuoteMetrics::default(),
            quote_queue: Arc::new(Semaphore::new(16)),
            quote_admission_wait: Duration::ZERO,
            cfg: config(),
            rpc: Rpc::connect("http://127.0.0.1:1").unwrap(),
            engine: Engine::for_profile(
                Rpc::connect("http://127.0.0.1:1").unwrap(),
                &FIXTURE_PROFILE,
            ),
            indexer: None,
            native_rfq: None,
            native_adapter: None,
            quote_slots: Arc::new(Semaphore::new(1)),
            compute_slots: Arc::new(Semaphore::new(1)),
            memory: crate::process_memory::ProcessMemory::new(None, 0).unwrap(),
            chain_verified: true,
            readiness: AsyncMutex::new(ReadinessState::new(false, false)),
        });
        let response = handle_health(State(app)).await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["ok"], true);
        assert_eq!(body["ready"], false);
        assert_eq!(body["chainVerified"], true);
        assert_eq!(body["rpcReady"], false);
        assert_eq!(body["indexerReady"], false);
        assert_eq!(body["chain"], "fixture");
        assert_eq!(body["chainId"], 2_818);
        assert_eq!(body["capabilities"]["quote"], true);
        assert_eq!(body["capabilities"]["execution"], true);
        assert_eq!(body["capabilities"]["poolDiscovery"], "factories");
        assert_eq!(body["rpc"]["unknownDispatches"], 0);
        assert_eq!(body["rpc"]["unknownEpoch"], 0);
        assert_eq!(body["capabilities"]["protocols"], json!(["univ2", "univ3"]));
        assert_eq!(body["capabilities"]["nativeRfq"]["configured"], false);
        assert!(body["capabilities"]["nativeRfq"]["qps"].is_null());
        assert!(body["capabilities"]["nativeRfq"]["queueWaitMs"].is_null());
        assert!(body["capabilities"]["nativeRfq"]["maxInflight"].is_null());
        assert_eq!(body["capabilities"]["routeUniverseMode"], "profile_only");
        // A flat graphGapBps looks the same whether screening ran and found
        // nothing or never ran at all, so the setting has to be reportable.
        assert_eq!(body["capabilities"]["connectorScreening"], false);
    }

    #[tokio::test]
    async fn health_exposes_native_rfq_capacity_and_queue_deadline() {
        let authorizer = crate::rfq::NativeBeneficiaryAuthorizer::from_secret(
            "0x59c6995e998f97a5a0044976f0945389dc9e86dae88c7a8412f4603b6b78690d",
        )
        .unwrap();
        let native_config = crate::rfq::NativeRfqConfig::new(
            "https://v2.api.native.org/swap-api-v2/",
            "test-api-key",
            Duration::from_millis(1_500),
            60,
            10,
            authorizer,
        )
        .unwrap();
        let rpc = Rpc::connect("http://127.0.0.1:1").unwrap();
        let native_client = NativeRfqClient::new(native_config.clone(), rpc.clone()).unwrap();
        let mut cfg = config();
        cfg.native_rfq = Some(native_config);
        let app = Arc::new(App {
            metrics: QuoteMetrics::default(),
            quote_queue: Arc::new(Semaphore::new(16)),
            quote_admission_wait: Duration::ZERO,
            cfg,
            rpc: rpc.clone(),
            engine: Engine::for_profile(rpc, &FIXTURE_PROFILE),
            indexer: None,
            native_rfq: Some(Arc::new(native_client)),
            native_adapter: Some(NativeAdapter {
                native: crate::chain::FIXTURE_NATIVE_RFQ,
                settler: NativeSettlerTarget::Registry {
                    address: crate::chain::FIXTURE_SETTLER_REGISTRY,
                    token_id: crate::chain::FIXTURE_SETTLER_TOKEN_ID,
                },
            }),
            quote_slots: Arc::new(Semaphore::new(1)),
            compute_slots: Arc::new(Semaphore::new(1)),
            memory: crate::process_memory::ProcessMemory::new(None, 0).unwrap(),
            chain_verified: true,
            readiness: AsyncMutex::new(ReadinessState::new(false, false)),
        });

        let response = handle_health(State(app)).await;
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(body["capabilities"]["nativeRfq"]["configured"], true);
        assert_eq!(body["capabilities"]["nativeRfq"]["qps"], 4);
        assert_eq!(body["capabilities"]["nativeRfq"]["queueWaitMs"], 1_000);
        assert_eq!(body["capabilities"]["nativeRfq"]["maxInflight"], 8);
        assert_eq!(
            body["capabilities"]["protocols"],
            json!(["univ2", "univ3", "nativerfq"])
        );
    }

    #[tokio::test]
    async fn readiness_timeout_is_failed_cached_and_singleflight() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let state = Arc::new(AsyncMutex::new(ReadinessState {
            checked_at: Instant::now() - READINESS_TTL,
            rpc_ready: true,
            indexer_ready: true,
        }));
        let calls = Arc::new(AtomicUsize::new(0));
        let call = |state: Arc<AsyncMutex<ReadinessState>>, calls: Arc<AtomicUsize>| async move {
            cached_readiness(&state, Duration::from_millis(20), async move {
                calls.fetch_add(1, Ordering::SeqCst);
                std::future::pending::<(bool, bool)>().await
            })
            .await
        };

        let started = Instant::now();
        let (first, second) = tokio::join!(
            call(state.clone(), calls.clone()),
            call(state.clone(), calls.clone())
        );
        assert!(started.elapsed() < Duration::from_millis(500));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(!first.rpc_ready && !first.indexer_ready);
        assert_eq!(first.rpc_ready, second.rpc_ready);
        assert_eq!(first.indexer_ready, second.indexer_ready);

        let cached = cached_readiness(&state, Duration::from_millis(20), async {
            panic!("a fresh failed readiness result must be served from cache")
        })
        .await;
        assert!(!cached.rpc_ready && !cached.indexer_ready);
    }

    #[tokio::test]
    async fn a_result_younger_than_the_ttl_is_served_without_a_probe() {
        let state = AsyncMutex::new(ReadinessState {
            checked_at: Instant::now() - READINESS_REFRESH * 2,
            rpc_ready: true,
            indexer_ready: true,
        });
        let cached = cached_readiness(&state, Duration::from_millis(20), async {
            panic!("a result the refresher keeps younger than the TTL is never probed inline")
        })
        .await;
        assert!(cached.rpc_ready && cached.indexer_ready);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_refresher_records_a_failing_rpc_without_a_request() {
        // Nothing listens on port 1, so every probe fails at once.
        let rpc = Rpc::connect("http://127.0.0.1:1").unwrap();
        let app = Arc::new(App {
            metrics: QuoteMetrics::default(),
            quote_queue: Arc::new(Semaphore::new(1)),
            quote_admission_wait: Duration::ZERO,
            cfg: config(),
            rpc: rpc.clone(),
            engine: Engine::for_profile(rpc, &FIXTURE_PROFILE),
            indexer: None,
            native_rfq: None,
            native_adapter: None,
            quote_slots: Arc::new(Semaphore::new(1)),
            compute_slots: Arc::new(Semaphore::new(1)),
            memory: crate::process_memory::ProcessMemory::new(None, 0).unwrap(),
            chain_verified: true,
            readiness: AsyncMutex::new(ReadinessState::new(true, true)),
        });
        spawn_readiness_refresher(&app, Duration::from_millis(10));
        let deadline = Instant::now() + READINESS_PROBE_TIMEOUT + Duration::from_secs(2);
        while app.readiness.lock().await.rpc_ready {
            assert!(Instant::now() < deadline, "the refresher never ran");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(app.readiness.lock().await.checked_at.elapsed() < READINESS_TTL);
    }
}
