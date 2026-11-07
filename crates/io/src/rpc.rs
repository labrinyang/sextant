// JSON-RPC + Multicall3 batching, on the alloy provider stack.

use crate::abi::IMulticall3;
use alloy::eips::BlockId;
use alloy::network::{BlockResponse, primitives::HeaderResponse};
use alloy::providers::{DynProvider, Provider, ProviderBuilder};
use alloy::rpc::types::TransactionRequest;
use alloy::transports::TransportResult;
use alloy_primitives::{Address, B256, Bytes, TxKind, address};
use alloy_sol_types::SolCall;
use anyhow::Context;
use futures_util::{StreamExt, TryStreamExt, stream};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CanonicalBlock {
    pub number: u64,
    pub hash: B256,
    /// Consensus timestamp of the same canonical header. Quote-expiry checks
    /// use this chain clock instead of trusting the host wall clock.
    pub timestamp: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CanonicalHeader {
    pub block: CanonicalBlock,
    pub parent_hash: B256,
    pub logs_bloom: alloy_primitives::Bloom,
}

pub const MULTICALL3: Address = address!("ca11bde05977b3631167028862be2a173976ca11");

/// Context marker attached to every upstream-RPC failure (transport errors,
/// node-side timeouts, undecodable responses). The HTTP layer maps errors
/// carrying it to 502 — the request was fine, the node was not.
#[derive(Debug)]
pub struct RpcUnavailable(pub &'static str);

impl std::fmt::Display for RpcUnavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "upstream rpc failed: {}", self.0)
    }
}

/// The endpoint returned a valid, non-retryable JSON-RPC error response.
///
/// In particular, deterministic `eth_call` execution reverts belong here,
/// not under `RpcUnavailable`: the transport worked and retrying the same
/// call against the same block cannot repair the request.
#[derive(Debug)]
pub struct RpcRejected(pub &'static str);

/// A transport terminated without a provider response. The dispatch may still
/// be executing upstream and therefore cannot release its physical quota slot.
#[derive(Debug)]
pub struct RpcUncertain(pub &'static str);

impl std::fmt::Display for RpcUncertain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RPC dispatch outcome unknown: {}", self.0)
    }
}
impl std::error::Error for RpcUncertain {}

impl std::fmt::Display for RpcRejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "rpc call rejected: {}", self.0)
    }
}

/// Revert payload of a rejected `eth_call`, carried alongside `RpcRejected` so
/// a caller can read what the contract said instead of searching for it. The
/// Display form deliberately states only the size: the bytes are chain data,
/// but a rendered error must stay small enough to log.
#[derive(Debug)]
pub struct RevertData(pub Bytes);

impl std::fmt::Display for RevertData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "call reverted with {} bytes of data", self.0.len())
    }
}

#[derive(Default)]
struct ResponseByteCounter(usize);

impl std::io::Write for ResponseByteCounter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0 = self
            .0
            .checked_add(bytes.len())
            .ok_or_else(|| std::io::Error::other("RPC response byte count overflow"))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn response_bytes<T: serde::Serialize>(value: &T) -> anyhow::Result<usize> {
    let mut count = ResponseByteCounter::default();
    serde_json::to_writer(&mut count, value)?;
    Ok(count.0)
}

fn rpc_result<T: serde::Serialize>(
    result: TransportResult<T>,
    method: &'static str,
    work: Option<crate::work_budget::WorkBudget>,
) -> anyhow::Result<T> {
    if let Some(work) = work {
        let decoded_bytes = match &result {
            Ok(value) => Some(response_bytes(value)?),
            Err(error) => error.as_error_resp().map(response_bytes).transpose()?,
        };
        if let Some(decoded_bytes) = decoded_bytes {
            work.record_rpc_response_bytes(decoded_bytes, "RPC decoded response")?;
        }
    }
    match result {
        Ok(value) => Ok(value),
        Err(error)
            if error
                .as_error_resp()
                .is_some_and(|response| !response.is_retry_err()) =>
        {
            let revert = error
                .as_error_resp()
                .and_then(|response| response.as_revert_data());
            let rejected = Err(anyhow::Error::new(error));
            match revert {
                Some(data) => rejected
                    .context(RevertData(data))
                    .context(RpcRejected(method)),
                None => rejected.context(RpcRejected(method)),
            }
        }
        Err(error) => {
            let known = outcome_known(&error);
            let result = Err(anyhow::Error::new(error)).context(RpcUnavailable(method));
            if known {
                result
            } else {
                result.context(RpcUncertain(method))
            }
        }
    }
}

/// Whether the provider is done with a failed request: it answered with any
/// HTTP status or body, or the request never left this process. Only a
/// request lost after it was sent may still be running upstream.
fn outcome_known(error: &alloy::transports::TransportError) -> bool {
    use alloy::transports::{RpcError, TransportErrorKind};
    match error {
        RpcError::ErrorResp(_)
        | RpcError::NullResp
        | RpcError::DeserError { .. }
        | RpcError::SerError(_)
        | RpcError::UnsupportedFeature(_)
        | RpcError::LocalUsageError(_)
        | RpcError::Transport(TransportErrorKind::HttpError(_)) => true,
        _ => transport_definitely_unsent(error),
    }
}

/// Connection establishment and request construction fail before an HTTP
/// request reaches the provider. Timeouts after dispatch remain uncertain.
fn transport_definitely_unsent(error: &(dyn std::error::Error + 'static)) -> bool {
    let mut current = Some(error);
    while let Some(error) = current {
        if error
            .downcast_ref::<reqwest::Error>()
            .is_some_and(|error| error.is_connect() || error.is_builder())
        {
            return true;
        }
        current = error.source();
    }
    false
}

/// Render errors for logs and HTTP responses without exposing an upstream
/// transport's source chain, which may contain a paid RPC URL. Request and
/// solver errors retain their full context because they carry no RPC marker.
pub fn sanitized_error(error: &anyhow::Error) -> String {
    if let Some(marker) = error.downcast_ref::<RpcUnavailable>() {
        marker.to_string()
    } else if let Some(marker) = error.downcast_ref::<RpcRejected>() {
        marker.to_string()
    } else {
        format!("{error:#}")
    }
}

fn env_num<T>(key: &str, default: T) -> anyhow::Result<T>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    match std::env::var(key) {
        Ok(value) => value
            .parse()
            .map_err(|error| anyhow::anyhow!("{key}={value:?} is invalid: {error}")),
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(error) => Err(anyhow::anyhow!("reading {key}: {error}")),
    }
}

#[derive(Default)]
struct RpcProbe {
    calls: AtomicU64,
}

#[derive(Clone)]
pub struct Rpc {
    pub url: String,
    provider: DynProvider,
    chunk: usize,
    concurrency: usize,
    snapshot_concurrency: usize,
    probe: Option<Arc<RpcProbe>>,
    dispatch: crate::rpc_dispatch::RpcDispatch,
    request_work: Option<crate::work_budget::WorkBudget>,
}

impl Rpc {
    /// Connect over HTTP with the SOLVER_RPC_TIMEOUT (seconds, default 120)
    /// request deadline; SOLVER_MC_CHUNK caps calls per aggregate3 (anvil
    /// needs a lower one than the public RPC); SOLVER_MC_CONCURRENCY caps how
    /// many aggregate3 batches are in flight at once (1 = sequential).
    pub fn connect(url: &str) -> anyhow::Result<Self> {
        let timeout = env_num("SOLVER_RPC_TIMEOUT", 120u64)?;
        let chunk = env_num("SOLVER_MC_CHUNK", 300usize)?;
        let concurrency = env_num("SOLVER_MC_CONCURRENCY", 4usize)?;
        let snapshot_concurrency = env_num("SOLVER_SNAPSHOT_CONCURRENCY", 2usize)?;
        anyhow::ensure!(timeout > 0, "SOLVER_RPC_TIMEOUT must be positive");
        anyhow::ensure!(chunk > 0, "SOLVER_MC_CHUNK must be positive");
        anyhow::ensure!(concurrency > 0, "SOLVER_MC_CONCURRENCY must be positive");
        anyhow::ensure!(
            snapshot_concurrency > 0,
            "SOLVER_SNAPSHOT_CONCURRENCY must be positive"
        );
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(timeout))
            .build()
            .context("building http client")?;
        let parsed: reqwest::Url = url.parse().context("bad rpc url")?;
        let scope: String = env_num("SOLVER_RPC_QUOTA_GROUP", String::new())?;
        let scope = alloy_primitives::keccak256(if scope.is_empty() {
            url.as_bytes()
        } else {
            scope.as_bytes()
        });
        let dispatch = crate::rpc_dispatch::RpcDispatch::with_limits(
            scope,
            crate::rpc_dispatch::DispatchLimits {
                maximum_active: env_num("SOLVER_RPC_MAX_DISPATCHES", 32usize)?,
                maximum_per_second: env_num("SOLVER_RPC_DISPATCH_RPS", 256usize)?,
                admission_wait: Duration::from_millis(env_num(
                    "SOLVER_RPC_ADMISSION_WAIT_MS",
                    2_000u64,
                )?),
                uncertain_release: Duration::from_secs(env_num(
                    "SOLVER_RPC_UNCERTAIN_RELEASE_SECS",
                    crate::rpc_dispatch::DEFAULT_UNCERTAIN_RELEASE.as_secs(),
                )?),
            },
        )?;
        let transport = alloy::transports::http::Http::with_client(client, parsed);
        let rpc_client = alloy::rpc::client::RpcClient::new(transport, false);
        let provider = ProviderBuilder::new()
            .disable_recommended_fillers()
            .connect_client(rpc_client)
            .erased();
        Ok(Rpc {
            url: url.to_string(),
            provider,
            chunk,
            concurrency,
            snapshot_concurrency,
            probe: None,
            dispatch,
            request_work: None,
        })
    }

    /// Clone this client into a new request-counting scope. Clones of the
    /// returned client share the scope; later scopes remain independent.
    pub fn scoped_probe(&self) -> Self {
        let mut rpc = self.clone();
        rpc.probe = Some(Arc::new(RpcProbe::default()));
        rpc
    }

    /// Clone this endpoint while inheriting another client's counting scope.
    /// Discovery uses it to include the dedicated logs endpoint in the same
    /// snapshot-pull measurement.
    pub fn with_probe_from(&self, scope: &Self) -> Self {
        let mut rpc = self.clone();
        rpc.probe = scope.probe.clone();
        rpc
    }

    pub fn probed_calls(&self) -> u64 {
        self.probe
            .as_ref()
            .map_or(0, |probe| probe.calls.load(Ordering::Relaxed))
    }

    pub fn with_work_budget(&self, work: crate::work_budget::WorkBudget) -> Self {
        let mut scoped = self.clone();
        scoped.request_work = Some(work);
        scoped
    }

    pub fn unknown_dispatches(&self) -> usize {
        self.dispatch.unknown_dispatches()
    }
    pub fn dispatch_usage(&self) -> crate::rpc_dispatch::RpcDispatchUsage {
        self.dispatch.usage()
    }
    pub fn unknown_dispatch_epoch(&self) -> u64 {
        self.dispatch.unknown_epoch()
    }
    pub fn reconcile_unknown_dispatches(&self, epoch: u64) -> anyhow::Result<usize> {
        self.dispatch.reconcile_unknown(epoch)
    }

    async fn dispatch<T, F>(&self, operation: F) -> anyhow::Result<T>
    where
        T: Send + 'static,
        F: std::future::Future<Output = anyhow::Result<T>> + Send + 'static,
    {
        let work = self.request_work.clone();
        let probe = self.probe.clone();
        self.dispatch
            .run_with_admission(
                move || {
                    if let Some(work) = work {
                        work.charge(
                            crate::work_budget::WorkCharge {
                                rpc_calls: 1,
                                ..Default::default()
                            },
                            "request RPC dispatch",
                        )?;
                    }
                    if let Some(probe) = probe {
                        probe.calls.fetch_add(1, Ordering::Relaxed);
                    }
                    Ok(())
                },
                operation,
            )
            .await
    }

    /// Calls per aggregate3 batch — a single batch executes atomically in one
    /// block even at `latest`; larger call sets split and lose that guarantee.
    pub fn chunk(&self) -> usize {
        self.chunk
    }

    /// Maximum ordered fan-out inside one Multicall, Lens, or discovery stage.
    /// Complete snapshots have a separate process-wide limit in `Engine`.
    pub fn concurrency(&self) -> usize {
        self.concurrency
    }

    /// Maximum number of complete pair snapshots that may run concurrently.
    pub fn snapshot_concurrency(&self) -> usize {
        self.snapshot_concurrency
    }

    pub async fn block_number(&self) -> anyhow::Result<u64> {
        let provider = self.provider.clone();
        let work = self.request_work.clone();
        self.dispatch(async move {
            rpc_result(provider.get_block_number().await, "eth_blockNumber", work)
        })
        .await
    }

    /// Read the endpoint's chain id through the provider's raw `eth_chainId`
    /// call. Provider decoding failures are upstream failures too: callers must
    /// never continue when an endpoint returns a malformed JSON-RPC quantity.
    pub async fn chain_id(&self) -> anyhow::Result<u64> {
        let provider = self.provider.clone();
        let work = self.request_work.clone();
        self.dispatch(async move { rpc_result(provider.get_chain_id().await, "eth_chainId", work) })
            .await
    }

    /// Fail closed when an endpoint is connected to a different chain. The
    /// diagnostic deliberately identifies only the endpoint's role, never its
    /// URL, so it is safe to surface through startup logs.
    pub async fn verify_chain_id(&self, expected: u64, role: &'static str) -> anyhow::Result<u64> {
        let actual = self.chain_id().await?;
        anyhow::ensure!(
            actual == expected,
            "{role} RPC chain mismatch: expected chain id {expected}, got {actual}"
        );
        Ok(actual)
    }

    /// Resolve a number/tag to its canonical block hash for EIP-1898 calls.
    /// Hash inputs need no round trip; callers still re-wrap them with
    /// `BlockId::hash_canonical` to require canonical state.
    pub async fn block_hash(&self, block: BlockId) -> anyhow::Result<B256> {
        if let Some(hash) = block.as_block_hash() {
            return Ok(hash);
        }
        Ok(self.canonical_block(block).await?.hash)
    }

    /// Resolve any block tag/number/hash to one canonical number+hash pair.
    /// Snapshot callers pin every dependent request to the returned hash; the
    /// number is response metadata and never comes from injected chain code.
    pub async fn canonical_block(&self, block: BlockId) -> anyhow::Result<CanonicalBlock> {
        let provider = self.provider.clone();
        let work = self.request_work.clone();
        self.dispatch(async move {
            let block = rpc_result(
                provider.get_block(block).await,
                "eth_getBlockByNumber",
                work,
            )?
            .context(RpcRejected("eth_getBlockByNumber"))?;
            Ok(CanonicalBlock {
                number: block.header().number,
                hash: block.header().hash(),
                timestamp: block.header().timestamp,
            })
        })
        .await
    }

    /// `canonical_block` plus the two header fields a log follower needs: the
    /// parent hash, to tell the next block from a jump or a reorg, and the logs
    /// bloom, to skip a block that cannot hold the logs it follows.
    pub async fn canonical_header(&self, block: BlockId) -> anyhow::Result<CanonicalHeader> {
        let provider = self.provider.clone();
        let work = self.request_work.clone();
        self.dispatch(async move {
            let block = rpc_result(
                provider.get_block(block).await,
                "eth_getBlockByNumber",
                work,
            )?
            .context(RpcRejected("eth_getBlockByNumber"))?;
            let header = block.header();
            Ok(CanonicalHeader {
                block: CanonicalBlock {
                    number: header.number,
                    hash: header.hash(),
                    timestamp: header.timestamp,
                },
                parent_hash: header.parent_hash,
                logs_bloom: header.logs_bloom,
            })
        })
        .await
    }

    /// `eth_getLogs` over `filter`, asked in one JSON-RPC batch with
    /// `eth_blockNumber` so both answers come from the same node. A node whose
    /// head is below `to_block` answers `[]` for the blocks it lacks instead of
    /// an error (some public nodes do), so its answer is refused
    /// rather than read as "no logs".
    pub async fn logs_through(
        &self,
        filter: serde_json::Value,
        to_block: u64,
    ) -> anyhow::Result<Vec<serde_json::Value>> {
        let provider = self.provider.clone();
        let work = self.request_work.clone();
        self.dispatch(async move {
            let client = provider.client();
            let mut batch = alloy::rpc::client::BatchRequest::new(client);
            let head = batch
                .add_call::<_, alloy_primitives::U64>("eth_blockNumber", &())
                .context(RpcUnavailable("eth_blockNumber"))?;
            let logs = batch
                .add_call::<_, Vec<serde_json::Value>>("eth_getLogs", &(filter,))
                .context(RpcUnavailable("eth_getLogs"))?;
            rpc_result(batch.send().await, "eth_getLogs", None)?;
            let head = rpc_result(head.await, "eth_blockNumber", work.clone())?.to::<u64>();
            let logs = rpc_result(logs.await, "eth_getLogs", work)?;
            if head < to_block {
                return Err(
                    anyhow::anyhow!("node head {head} is below block {to_block}")
                        .context(RpcUnavailable("eth_getLogs")),
                );
            }
            Ok(logs)
        })
        .await
    }

    /// `eth_getLogs` for each of `filters`, all in one JSON-RPC batch with
    /// `eth_blockNumber`, refused whole when the node's head is below
    /// `to_block` (see `logs_through`). Answers come back in `filters`' order.
    pub async fn logs_batch(
        &self,
        filters: Vec<serde_json::Value>,
        to_block: u64,
    ) -> anyhow::Result<Vec<Vec<serde_json::Value>>> {
        if filters.is_empty() {
            return Ok(Vec::new());
        }
        let provider = self.provider.clone();
        let work = self.request_work.clone();
        self.dispatch(async move {
            let client = provider.client();
            let mut batch = alloy::rpc::client::BatchRequest::new(client);
            let head = batch
                .add_call::<_, alloy_primitives::U64>("eth_blockNumber", &())
                .context(RpcUnavailable("eth_blockNumber"))?;
            let waiters = filters
                .iter()
                .map(|filter| {
                    batch
                        .add_call::<_, Vec<serde_json::Value>>("eth_getLogs", &(filter,))
                        .context(RpcUnavailable("eth_getLogs"))
                })
                .collect::<anyhow::Result<Vec<_>>>()?;
            rpc_result(batch.send().await, "eth_getLogs", None)?;
            let head = rpc_result(head.await, "eth_blockNumber", work.clone())?.to::<u64>();
            let mut answers = Vec::with_capacity(waiters.len());
            for waiter in waiters {
                answers.push(rpc_result(waiter.await, "eth_getLogs", work.clone())?);
            }
            if head < to_block {
                return Err(
                    anyhow::anyhow!("node head {head} is below block {to_block}")
                        .context(RpcUnavailable("eth_getLogs")),
                );
            }
            Ok(answers)
        })
        .await
    }

    /// `canonical_header` for each of `numbers`, in one JSON-RPC batch, in
    /// order. A block the node does not have refuses the whole answer.
    pub async fn canonical_headers(
        &self,
        numbers: std::ops::Range<u64>,
    ) -> anyhow::Result<Vec<CanonicalHeader>> {
        if numbers.is_empty() {
            return Ok(Vec::new());
        }
        let provider = self.provider.clone();
        let work = self.request_work.clone();
        self.dispatch(async move {
            let client = provider.client();
            let mut batch = alloy::rpc::client::BatchRequest::new(client);
            let waiters = numbers
                .map(|number| {
                    batch
                        .add_call::<_, Option<alloy::rpc::types::Block>>(
                            "eth_getBlockByNumber",
                            &(alloy::eips::BlockNumberOrTag::Number(number), false),
                        )
                        .context(RpcUnavailable("eth_getBlockByNumber"))
                })
                .collect::<anyhow::Result<Vec<_>>>()?;
            rpc_result(batch.send().await, "eth_getBlockByNumber", None)?;
            let mut headers = Vec::with_capacity(waiters.len());
            for waiter in waiters {
                let block = rpc_result(waiter.await, "eth_getBlockByNumber", work.clone())?
                    .context(RpcRejected("eth_getBlockByNumber"))?;
                let header = &block.header;
                headers.push(CanonicalHeader {
                    block: CanonicalBlock {
                        number: header.number,
                        hash: header.hash,
                        timestamp: header.timestamp,
                    },
                    parent_hash: header.parent_hash,
                    logs_bloom: header.logs_bloom,
                });
            }
            Ok(headers)
        })
        .await
    }

    pub async fn code_at(&self, address: Address, block: BlockId) -> anyhow::Result<Bytes> {
        let provider = self.provider.clone();
        let work = self.request_work.clone();
        self.dispatch(async move {
            rpc_result(
                provider.get_code_at(address).block_id(block).await,
                "eth_getCode",
                work,
            )
        })
        .await
    }

    /// An account's nonce at `block`: for a contract, one more than the
    /// contracts it has created.
    pub async fn nonce_at(&self, address: Address, block: BlockId) -> anyhow::Result<u64> {
        let provider = self.provider.clone();
        let work = self.request_work.clone();
        self.dispatch(async move {
            rpc_result(
                provider
                    .get_transaction_count(address)
                    .block_id(block)
                    .await,
                "eth_getTransactionCount",
                work,
            )
        })
        .await
    }

    /// Raw JSON-RPC passthrough: eth_getLogs (v4 topology discovery) and
    /// harness use (anvil_* methods, impersonated transactions).
    pub async fn request(
        &self,
        method: &'static str,
        params: serde_json::Value,
    ) -> anyhow::Result<serde_json::Value> {
        let provider = self.provider.clone();
        let work = self.request_work.clone();
        self.dispatch(async move {
            rpc_result(
                provider
                    .raw_request::<_, serde_json::Value>(std::borrow::Cow::Borrowed(method), params)
                    .await,
                method,
                work,
            )
        })
        .await
    }

    pub async fn eth_call(
        &self,
        to: Address,
        data: Vec<u8>,
        block: BlockId,
    ) -> anyhow::Result<Vec<u8>> {
        let tx = TransactionRequest {
            to: Some(TxKind::Call(to)),
            input: Bytes::from(data).into(),
            gas: Some(16_000_000),
            ..Default::default()
        };
        let provider = self.provider.clone();
        let work = self.request_work.clone();
        let ret = self
            .dispatch(
                async move { rpc_result(provider.call(tx).block(block).await, "eth_call", work) },
            )
            .await?;
        Ok(ret.to_vec())
    }

    /// `eth_call` as a specific caller. Algebra plugins only expose their
    /// next-swap fee to the pool itself, so Sheriff snapshots use this without
    /// impersonating or mutating chain state.
    pub async fn eth_call_from(
        &self,
        from: Address,
        to: Address,
        data: Vec<u8>,
        block: BlockId,
    ) -> anyhow::Result<Vec<u8>> {
        let tx = TransactionRequest {
            from: Some(from),
            to: Some(TxKind::Call(to)),
            input: Bytes::from(data).into(),
            gas: Some(16_000_000),
            ..Default::default()
        };
        let provider = self.provider.clone();
        let work = self.request_work.clone();
        let ret = self
            .dispatch(
                async move { rpc_result(provider.call(tx).block(block).await, "eth_call", work) },
            )
            .await?;
        Ok(ret.to_vec())
    }

    /// eth_call with `code` installed at `to` via the state-override param —
    /// how the snapshot lens runs without ever being deployed. Supported by
    /// both chain endpoints and by anvil (verified live).
    ///
    /// `gas` is the call's limit; a node whose `eth_call` cap is lower
    /// clamps it to that cap.
    pub async fn eth_call_overridden(
        &self,
        to: Address,
        data: Vec<u8>,
        code: Bytes,
        block: BlockId,
        gas: u64,
    ) -> anyhow::Result<Vec<u8>> {
        use alloy::rpc::types::state::{AccountOverride, StateOverride};
        let tx = TransactionRequest {
            to: Some(TxKind::Call(to)),
            input: Bytes::from(data).into(),
            gas: Some(gas),
            ..Default::default()
        };
        let mut overrides = StateOverride::default();
        overrides.insert(
            to,
            AccountOverride {
                code: Some(code),
                ..Default::default()
            },
        );
        let provider = self.provider.clone();
        let work = self.request_work.clone();
        let ret = self
            .dispatch(async move {
                rpc_result(
                    provider.call(tx).block(block).overrides(overrides).await,
                    "eth_call",
                    work,
                )
            })
            .await?;
        Ok(ret.to_vec())
    }

    /// Batched eth_call via Multicall3 `aggregate3` (allowFailure = true),
    /// pinnable to a block for a consistent snapshot. Batches beyond the chunk
    /// size run concurrently (up to `concurrency` in flight), order preserved.
    /// Returns one entry per call: return bytes, or `None` if that call reverted.
    pub async fn multicall(
        &self,
        calls: Vec<(Address, Vec<u8>)>,
        block: BlockId,
    ) -> anyhow::Result<Vec<Option<Vec<u8>>>> {
        let batches: Vec<Vec<(Address, Vec<u8>)>> =
            calls.chunks(self.chunk).map(<[_]>::to_vec).collect();
        let results: Vec<Vec<Option<Vec<u8>>>> = stream::iter(
            batches
                .into_iter()
                .map(|batch| self.aggregate3(batch, block)),
        )
        .buffered(self.concurrency)
        .try_collect()
        .await?;
        Ok(results.into_iter().flatten().collect())
    }

    async fn aggregate3(
        &self,
        batch: Vec<(Address, Vec<u8>)>,
        block: BlockId,
    ) -> anyhow::Result<Vec<Option<Vec<u8>>>> {
        let call = IMulticall3::aggregate3Call {
            calls: batch
                .iter()
                .map(|(to, data)| IMulticall3::Call3 {
                    target: *to,
                    allowFailure: true,
                    callData: Bytes::from(data.clone()),
                })
                .collect(),
        };
        let ret = self.eth_call(MULTICALL3, call.abi_encode(), block).await?;
        let results = IMulticall3::aggregate3Call::abi_decode_returns(&ret)
            .context(RpcUnavailable("decoding aggregate3 return"))?;
        Ok(results
            .into_iter()
            .map(|r| r.success.then(|| r.returnData.to_vec()))
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::{Rpc, RpcRejected, RpcUnavailable, sanitized_error};
    use alloy::eips::BlockId;
    use alloy_primitives::{Address, B256, Bytes};
    use axum::{Json, Router, extract::State, routing::post};
    use serde_json::{Value, json};
    use std::sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    };

    #[test]
    fn malformed_rpc_url_is_not_echoed() {
        let secret = "://super-secret-rpc-key";
        let err = match Rpc::connect(secret) {
            Ok(_) => panic!("malformed URL unexpectedly connected"),
            Err(err) => err,
        };
        let rendered = format!("{err:#}");
        assert!(rendered.contains("bad rpc url"));
        assert!(!rendered.contains(secret));
    }

    #[test]
    fn rpc_source_chain_is_redacted_from_public_errors() {
        let secret = "https://paid-rpc.example/super-secret-key";
        let error = anyhow::anyhow!("transport failed at {secret}")
            .context(RpcUnavailable("eth_call"))
            .context("refreshing pair snapshot");
        let rendered = sanitized_error(&error);
        assert_eq!(rendered, "upstream rpc failed: eth_call");
        assert!(!rendered.contains(secret));
    }

    #[test]
    fn rejected_rpc_source_chain_is_redacted_from_public_errors() {
        let secret = "https://paid-rpc.example/super-secret-key";
        let error = anyhow::anyhow!("node rejected request at {secret}")
            .context(RpcRejected("eth_call"))
            .context("refreshing pair snapshot");
        let rendered = sanitized_error(&error);
        assert_eq!(rendered, "rpc call rejected: eth_call");
        assert!(!rendered.contains(secret));
    }

    async fn error_rpc(State(code): State<i64>, Json(request): Json<Value>) -> Json<Value> {
        Json(json!({
            "jsonrpc": "2.0",
            "id": request["id"],
            "error": {"code": code, "message": "forced failure"}
        }))
    }

    async fn rpc_returning(code: i64) -> (Rpc, tokio::task::JoinHandle<()>) {
        let app = Router::new().route("/", post(error_rpc)).with_state(code);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (Rpc::connect(&format!("http://{address}")).unwrap(), server)
    }

    async fn result_rpc(State(result): State<Value>, Json(request): Json<Value>) -> Json<Value> {
        Json(json!({
            "jsonrpc": "2.0",
            "id": request["id"],
            "result": result
        }))
    }

    async fn rpc_with_result(result: Value) -> (Rpc, tokio::task::JoinHandle<()>) {
        let app = Router::new()
            .route("/", post(result_rpc))
            .with_state(result);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (Rpc::connect(&format!("http://{address}")).unwrap(), server)
    }

    #[tokio::test]
    async fn chain_id_decodes_json_rpc_hex_quantity() {
        let (rpc, server) = rpc_with_result(json!("0x38")).await;

        assert_eq!(rpc.chain_id().await.unwrap(), 56);
        assert_eq!(rpc.verify_chain_id(56, "primary").await.unwrap(), 56);
        server.abort();
    }

    #[tokio::test]
    async fn direct_raw_and_typed_rpc_responses_are_metered_once() {
        let (rpc, server) = rpc_with_result(json!("0x2a")).await;
        let work =
            crate::work_budget::WorkBudget::bounded(crate::budget::SolverBudget::unlimited());
        let rpc = rpc.with_work_budget(work.clone());
        assert_eq!(
            rpc.request("eth_estimateGas", json!([])).await.unwrap(),
            json!("0x2a")
        );
        assert_eq!(work.used().rpc_calls, 1);
        assert_eq!(
            work.used().rpc_bytes,
            serde_json::to_vec(&json!("0x2a")).unwrap().len() as u64
        );
        assert_eq!(rpc.chain_id().await.unwrap(), 42);
        assert_eq!(work.used().rpc_calls, 2);
        assert_eq!(
            work.used().rpc_bytes,
            6 + serde_json::to_vec(&42u64).unwrap().len() as u64
        );
        assert_eq!(work.used().fact_reads, 0);
        assert_eq!(work.used().fact_bytes, 0);
        server.abort();
    }

    fn admitted_fixture(scope: u8, active: usize, rate: usize) -> Rpc {
        let mut rpc = Rpc::connect("http://127.0.0.1:1").unwrap().scoped_probe();
        rpc.dispatch =
            crate::rpc_dispatch::RpcDispatch::for_scope(B256::repeat_byte(scope), active, rate)
                .unwrap();
        rpc
    }

    #[tokio::test]
    async fn local_slot_rejection_does_not_meter_or_poll_a_provider() {
        let work =
            crate::work_budget::WorkBudget::bounded(crate::budget::SolverBudget::unlimited());
        let rpc = admitted_fixture(211, 1, 100).with_work_budget(work.clone());
        let gate = rpc.dispatch.clone();
        let (entered, started) = tokio::sync::oneshot::channel();
        let (release, wait) = tokio::sync::oneshot::channel();
        let owner = tokio::spawn(async move {
            gate.run(async move {
                entered.send(()).unwrap();
                wait.await.unwrap();
                Ok(())
            })
            .await
        });
        started.await.unwrap();
        let polls = Arc::new(AtomicU64::new(0));
        let operation_polls = polls.clone();
        let error = rpc
            .dispatch(async move {
                operation_polls.fetch_add(1, Ordering::Relaxed);
                Ok(())
            })
            .await
            .unwrap_err();
        assert!(error.is::<crate::rpc_dispatch::RpcCapacity>());
        assert_eq!(work.used(), crate::work_budget::WorkCharge::default());
        assert_eq!(rpc.probed_calls(), 0);
        assert_eq!(polls.load(Ordering::Relaxed), 0);
        release.send(()).unwrap();
        owner.await.unwrap().unwrap();

        let operation_polls = polls.clone();
        rpc.dispatch(async move {
            operation_polls.fetch_add(1, Ordering::Relaxed);
            Ok(())
        })
        .await
        .unwrap();
        assert_eq!(work.used().rpc_calls, 1);
        assert_eq!(rpc.probed_calls(), 1);
        assert_eq!(polls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn local_rate_rejection_preserves_actual_dispatch_counters() {
        let work =
            crate::work_budget::WorkBudget::bounded(crate::budget::SolverBudget::unlimited());
        let rpc = admitted_fixture(212, 2, 1).with_work_budget(work.clone());
        let polls = Arc::new(AtomicU64::new(0));
        let operation_polls = polls.clone();
        rpc.dispatch(async move {
            operation_polls.fetch_add(1, Ordering::Relaxed);
            Ok(())
        })
        .await
        .unwrap();
        let before = work.used();
        let operation_polls = polls.clone();
        let error = rpc
            .dispatch(async move {
                operation_polls.fetch_add(1, Ordering::Relaxed);
                Ok(())
            })
            .await
            .unwrap_err();
        assert!(error.is::<crate::rpc_dispatch::RpcCapacity>());
        assert_eq!(work.used(), before);
        assert_eq!(work.used().rpc_calls, 1);
        assert_eq!(rpc.probed_calls(), 1);
        assert_eq!(polls.load(Ordering::Relaxed), 1);
        assert_eq!(rpc.unknown_dispatches(), 0);
    }

    #[tokio::test]
    async fn budget_rejection_releases_unstarted_slot_and_rate_reservations() {
        let limits = crate::work_budget::WorkLimits {
            rpc_calls: 0,
            ..crate::work_budget::WorkLimits::bounded_default()
        };
        let work =
            crate::work_budget::WorkBudget::new(crate::budget::SolverBudget::unlimited(), limits);
        let rpc = admitted_fixture(213, 1, 1).with_work_budget(work.clone());
        let polls = Arc::new(AtomicU64::new(0));
        let operation_polls = polls.clone();
        let error = rpc
            .dispatch(async move {
                operation_polls.fetch_add(1, Ordering::Relaxed);
                Ok(())
            })
            .await
            .unwrap_err();
        assert!(error.is::<crate::work_budget::WorkLimitExceeded>());
        assert_eq!(work.used(), crate::work_budget::WorkCharge::default());
        assert_eq!(rpc.probed_calls(), 0);
        assert_eq!(polls.load(Ordering::Relaxed), 0);
        assert_eq!(rpc.unknown_dispatches(), 0);
        assert_eq!(rpc.unknown_dispatch_epoch(), 0);
        let usage = rpc.dispatch_usage();
        assert_eq!(usage.slots_used, 0);
        assert_eq!(usage.admitting, 0);
        assert_eq!(usage.recent_rate_used, 0);
        assert_eq!(usage.dispatched, 0);
        assert_eq!(usage.rejected_rate, 0);
        assert_eq!(usage.rejected_active, 0);

        // Same quota scope: rejected pre-dispatch work spent neither slot nor
        // its one allowed request per second. No time advancement is needed.
        let work =
            crate::work_budget::WorkBudget::bounded(crate::budget::SolverBudget::unlimited());
        let rpc = rpc.with_work_budget(work.clone());
        let operation_polls = polls.clone();
        rpc.dispatch(async move {
            operation_polls.fetch_add(1, Ordering::Relaxed);
            Ok(())
        })
        .await
        .unwrap();
        let usage = rpc.dispatch_usage();
        assert_eq!(usage.slots_used, 0);
        assert_eq!(usage.dispatched, 1);
        assert_eq!(usage.recent_rate_used, 1);
        assert_eq!(work.used().rpc_calls, 1);
        assert_eq!(rpc.probed_calls(), 1);
        assert_eq!(polls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn rejected_rpc_response_payload_stays_metered() {
        let (rpc, server) = rpc_returning(-32601).await;
        let work =
            crate::work_budget::WorkBudget::bounded(crate::budget::SolverBudget::unlimited());
        let error = rpc
            .with_work_budget(work.clone())
            .request("eth_call", json!([]))
            .await
            .unwrap_err();
        assert!(error.downcast_ref::<RpcRejected>().is_some());
        assert_eq!(work.used().rpc_calls, 1);
        assert!(work.used().rpc_bytes > 0);
        server.abort();
    }

    #[tokio::test]
    async fn wrong_chain_error_does_not_expose_rpc_url() {
        let (rpc, server) = rpc_with_result(json!("0x38")).await;
        let url = rpc.url.clone();

        let error = rpc.verify_chain_id(4663, "snapshot").await.unwrap_err();
        let rendered = sanitized_error(&error);
        assert_eq!(
            rendered,
            "snapshot RPC chain mismatch: expected chain id 4663, got 56"
        );
        assert!(!rendered.contains(&url));
        server.abort();
    }

    #[tokio::test]
    async fn malformed_chain_id_is_sanitized_as_rpc_unavailability() {
        let (rpc, server) = rpc_with_result(json!("not-a-hex-quantity")).await;
        let url = rpc.url.clone();

        let error = rpc.chain_id().await.unwrap_err();
        assert!(error.downcast_ref::<RpcUnavailable>().is_some());
        let rendered = sanitized_error(&error);
        assert_eq!(rendered, "upstream rpc failed: eth_chainId");
        assert!(!rendered.contains(&url));
        server.abort();
    }

    #[tokio::test]
    async fn rejected_chain_id_call_uses_sanitized_rpc_semantics() {
        let (rpc, server) = rpc_returning(3).await;
        let url = rpc.url.clone();

        let error = rpc.chain_id().await.unwrap_err();
        assert!(error.downcast_ref::<RpcRejected>().is_some());
        assert!(error.downcast_ref::<RpcUnavailable>().is_none());
        let rendered = sanitized_error(&error);
        assert_eq!(rendered, "rpc call rejected: eth_chainId");
        assert!(!rendered.contains(&url));
        server.abort();
    }

    #[tokio::test]
    async fn non_retryable_rpc_response_is_not_transport_unavailability() {
        let (rpc, server) = rpc_returning(3).await;
        let error = rpc
            .eth_call(Address::ZERO, Vec::new(), BlockId::latest())
            .await
            .unwrap_err();

        assert!(error.downcast_ref::<RpcRejected>().is_some());
        assert!(error.downcast_ref::<RpcUnavailable>().is_none());
        server.abort();
    }

    #[tokio::test]
    async fn retryable_rpc_response_remains_transport_unavailability() {
        let (rpc, server) = rpc_returning(429).await;
        let error = rpc
            .eth_call(Address::ZERO, Vec::new(), BlockId::latest())
            .await
            .unwrap_err();

        assert!(error.downcast_ref::<RpcUnavailable>().is_some());
        assert!(error.downcast_ref::<RpcRejected>().is_none());
        server.abort();
    }

    #[tokio::test]
    async fn scoped_probe_counts_each_upstream_request_once() {
        let (base, server) = rpc_returning(3).await;
        let rpc = base.scoped_probe();

        assert_eq!(
            rpc.block_hash(BlockId::hash_canonical(B256::ZERO))
                .await
                .unwrap(),
            B256::ZERO
        );
        assert_eq!(rpc.probed_calls(), 0);

        assert!(rpc.block_number().await.is_err());
        assert!(rpc.block_hash(BlockId::number(1)).await.is_err());
        assert!(rpc.canonical_block(BlockId::latest()).await.is_err());
        assert!(rpc.code_at(Address::ZERO, BlockId::latest()).await.is_err());
        assert!(rpc.request("eth_getLogs", json!([])).await.is_err());
        assert!(
            rpc.eth_call(Address::ZERO, Vec::new(), BlockId::latest())
                .await
                .is_err()
        );
        assert!(
            rpc.eth_call_from(Address::ZERO, Address::ZERO, Vec::new(), BlockId::latest(),)
                .await
                .is_err()
        );
        assert!(
            rpc.eth_call_overridden(
                Address::ZERO,
                Vec::new(),
                Bytes::new(),
                BlockId::latest(),
                16_000_000,
            )
            .await
            .is_err()
        );
        assert!(
            rpc.multicall(vec![(Address::ZERO, Vec::new())], BlockId::latest(),)
                .await
                .is_err()
        );

        assert_eq!(rpc.probed_calls(), 9);
        server.abort();
    }

    #[tokio::test]
    async fn probe_scopes_are_shared_only_when_explicitly_inherited() {
        let (base, server) = rpc_returning(3).await;
        let first = base.scoped_probe();
        let inherited = base.with_probe_from(&first);
        let second = base.scoped_probe();

        assert!(inherited.block_number().await.is_err());
        assert_eq!(first.probed_calls(), 1);
        assert_eq!(inherited.probed_calls(), 1);
        assert_eq!(second.probed_calls(), 0);
        assert_eq!(base.probed_calls(), 0);

        assert!(second.block_number().await.is_err());
        assert_eq!(first.probed_calls(), 1);
        assert_eq!(second.probed_calls(), 1);
        server.abort();
    }
    #[tokio::test]
    async fn an_html_error_page_is_an_answer_not_an_unknown_outcome() {
        use axum::http::StatusCode;
        let app = axum::Router::new().route(
            "/",
            axum::routing::post(|| async {
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    [("content-type", "text/html")],
                    "<html>upstream unavailable</html>",
                )
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let rpc = Rpc::connect(&format!("http://{address}")).unwrap();
        for _ in 0..3 {
            let error = rpc.chain_id().await.unwrap_err();
            assert!(error.downcast_ref::<RpcUnavailable>().is_some());
            assert!(error.downcast_ref::<super::RpcUncertain>().is_none());
        }
        assert_eq!(rpc.unknown_dispatches(), 0);
        assert_eq!(rpc.dispatch_usage().slots_used, 0);
        server.abort();
    }

    #[tokio::test]
    async fn refused_connection_has_no_unknown_debt_and_same_rpc_recovers() {
        use alloy_primitives::keccak256;
        use serde_json::{Value, json};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let mut rpc = Rpc::connect(&format!("http://{address}")).unwrap();
        // This isolated quota reproduces the old two-refusal capacity lockout.
        rpc.dispatch = crate::rpc_dispatch::RpcDispatch::for_scope(
            keccak256(format!("refusal-fixture-{address}")),
            2,
            100,
        )
        .unwrap();
        for _ in 0..2 {
            let error = rpc.chain_id().await.unwrap_err();
            assert!(error.downcast_ref::<RpcUnavailable>().is_some());
            assert!(error.downcast_ref::<super::RpcUncertain>().is_none());
            assert_eq!(rpc.unknown_dispatches(), 0);
        }
        let listener = tokio::net::TcpListener::bind(address).await.unwrap();
        let app = axum::Router::new().route(
            "/",
            axum::routing::post(|axum::Json(request): axum::Json<Value>| async move {
                axum::Json(json!({"jsonrpc":"2.0","id":request["id"],"result":"0xb02"}))
            }),
        );
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        assert_eq!(rpc.chain_id().await.unwrap(), 2818);
        server.abort();
    }

    /// Answers a batch of `eth_blockNumber` and `eth_getLogs` as one node
    /// would, with its head at `head`.
    async fn batch_node(head: u64) -> (Rpc, tokio::task::JoinHandle<()>) {
        let app = Router::new().route(
            "/",
            post(move |Json(request): Json<Value>| async move {
                let calls = request.as_array().expect("a batch").clone();
                Json(Value::Array(
                    calls
                        .iter()
                        .map(|call| {
                            let result = match call["method"].as_str() {
                                Some("eth_blockNumber") => json!(format!("{head:#x}")),
                                Some("eth_getLogs") => json!([{"topics": ["0x01"], "data": "0x"}]),
                                other => panic!("unexpected {other:?}"),
                            };
                            json!({"jsonrpc": "2.0", "id": call["id"], "result": result})
                        })
                        .collect(),
                ))
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (Rpc::connect(&format!("http://{address}")).unwrap(), server)
    }

    #[tokio::test]
    async fn logs_are_read_only_from_a_node_that_has_the_range() {
        let (rpc, server) = batch_node(100).await;
        let logs = rpc
            .logs_through(json!({"fromBlock": "0x1"}), 100)
            .await
            .unwrap();
        assert_eq!(logs.len(), 1);
        // The same node, asked past its head, answers [] for the blocks it
        // lacks; that answer is refused rather than read as "no logs".
        let error = rpc
            .logs_through(json!({"fromBlock": "0x1"}), 101)
            .await
            .unwrap_err();
        assert!(error.downcast_ref::<RpcUnavailable>().is_some());
        assert!(format!("{error:#}").contains("below block 101"));
        server.abort();
    }

    /// Answers batches of `eth_blockNumber`, `eth_getLogs` (one log naming
    /// the block hash it was asked for) and `eth_getBlockByNumber` (block `n`
    /// has hash `n` and parent `n - 1`), in reverse order as a node may.
    async fn chain_node(head: u64) -> (Rpc, tokio::task::JoinHandle<()>) {
        let app = Router::new().route(
            "/",
            post(move |Json(request): Json<Value>| async move {
                let calls = request.as_array().expect("a batch").clone();
                let mut answers: Vec<Value> = calls
                    .iter()
                    .map(|call| {
                        let result = match call["method"].as_str() {
                            Some("eth_blockNumber") => json!(format!("{head:#x}")),
                            Some("eth_getLogs") => {
                                json!([{"blockHash": call["params"][0]["blockHash"]}])
                            }
                            Some("eth_getBlockByNumber") => {
                                let number = u64::from_str_radix(
                                    call["params"][0].as_str().unwrap().trim_start_matches("0x"),
                                    16,
                                )
                                .unwrap();
                                if number > head {
                                    Value::Null
                                } else {
                                    let hash = |n: u64| format!("{:#066x}", n);
                                    json!({
                                        "hash": hash(number),
                                        "parentHash": hash(number - 1),
                                        "number": format!("{number:#x}"),
                                        "timestamp": "0x1",
                                        "sha3Uncles": format!("{:#066x}", 0),
                                        "miner": format!("{:#042x}", 0),
                                        "stateRoot": format!("{:#066x}", 0),
                                        "transactionsRoot": format!("{:#066x}", 0),
                                        "receiptsRoot": format!("{:#066x}", 0),
                                        "logsBloom": format!("0x{}", "00".repeat(256)),
                                        "difficulty": "0x0",
                                        "gasLimit": "0x1",
                                        "gasUsed": "0x0",
                                        "extraData": "0x",
                                        "mixHash": format!("{:#066x}", 0),
                                        "nonce": "0x0000000000000000",
                                        "transactions": [],
                                        "uncles": []
                                    })
                                }
                            }
                            other => panic!("unexpected {other:?}"),
                        };
                        json!({"jsonrpc": "2.0", "id": call["id"], "result": result})
                    })
                    .collect();
                answers.reverse();
                Json(Value::Array(answers))
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (Rpc::connect(&format!("http://{address}")).unwrap(), server)
    }

    #[tokio::test]
    async fn batched_headers_and_logs_come_back_in_the_order_asked() {
        let (rpc, server) = chain_node(20).await;
        let headers = rpc.canonical_headers(11..15).await.unwrap();
        assert_eq!(
            headers.iter().map(|h| h.block.number).collect::<Vec<_>>(),
            [11, 12, 13, 14]
        );
        for pair in headers.windows(2) {
            assert_eq!(pair[1].parent_hash, pair[0].block.hash);
        }
        assert!(
            rpc.canonical_headers(19..22).await.is_err(),
            "21 is past the head"
        );
        assert!(rpc.canonical_headers(5..5).await.unwrap().is_empty());

        let hashes = ["0x0b", "0x0c", "0x0d"];
        let answers = rpc
            .logs_batch(
                hashes
                    .iter()
                    .map(|hash| json!({"blockHash": hash}))
                    .collect(),
                13,
            )
            .await
            .unwrap();
        let asked: Vec<&str> = answers
            .iter()
            .map(|logs| logs[0]["blockHash"].as_str().unwrap())
            .collect();
        assert_eq!(asked, hashes);
        assert!(rpc.logs_batch(vec![json!({})], 21).await.is_err());
        server.abort();
    }
}
