use super::*;

const V4_KEY_CACHE_CAP: usize = 4_096;
/// Internal placeholder carried only from indexed topology into the Lens.
/// The Lens does not consume Query.fee for V4; the pinned slot0 LP fee then
/// proves either the static PoolKey fee or the dynamic-fee flag by PoolId.
pub(super) const V4_UNKNOWN_KEY_FEE_PPM: u32 = 0xff_ffff;
// Bounds both cached metadata and the number of Lens queries one adversarial
// currency pair can add. Exceeding it fails discovery; keys are never cut.
pub(super) const V4_KEYS_PER_PAIR_CAP: usize = 1_024;
pub(super) const V4_REORG_OVERLAP: u64 = 64;

pub(super) fn v4_currency_pair_for(
    wrapped_native: Address,
    a: Address,
    b: Address,
    native: bool,
) -> Option<(Address, Address)> {
    if !native {
        return Some(sorted_pair(a, b));
    }
    if a == wrapped_native {
        Some((Address::ZERO, b))
    } else if b == wrapped_native {
        Some((Address::ZERO, a))
    } else {
        None
    }
}

// The simulator represents a chain's native currency as its wrapped token,
// but token order must still follow V4 currency order rather than ERC-20
// address sorting.
pub(super) fn v4_tokens_from_currencies_for(
    wrapped_native: Address,
    currency0: Address,
    currency1: Address,
) -> (Address, Address) {
    (
        if currency0 == Address::ZERO {
            wrapped_native
        } else {
            currency0
        },
        currency1,
    )
}

/// Dedicated endpoint for the v4 Initialize scans. The public chain RPC
/// serves genesis-to-head filtered getLogs in one call, while typical paid
/// endpoints cap the range at 10k blocks (observed live) — useless for the
/// one-time full-history bootstrap. SOLVER_LOGS_RPC overrides.
static DEFAULT_LOGS_RPC: LazyLock<Rpc> = LazyLock::new(|| {
    let url = match std::env::var("SOLVER_LOGS_RPC") {
        Ok(url) => url,
        Err(std::env::VarError::NotPresent) => crate::chain::PUBLIC_RPC.to_string(),
        Err(error) => panic!("reading SOLVER_LOGS_RPC: {error}"),
    };
    Rpc::connect(&url).unwrap_or_else(|error| panic!("SOLVER_LOGS_RPC is invalid: {error:#}"))
});
static CONFIGURED_LOGS_RPC: OnceLock<Rpc> = OnceLock::new();

/// Install the already chain-verified logs endpoint. A second, different
/// endpoint is rejected: global topology caches intentionally belong to one
/// profile and one logs source for the process lifetime.
pub(crate) fn configure_logs_rpc(rpc: Rpc) -> anyhow::Result<()> {
    if let Some(current) = CONFIGURED_LOGS_RPC.get() {
        ensure!(
            current.url == rpc.url,
            "logs RPC is already configured for this process"
        );
        return Ok(());
    }
    CONFIGURED_LOGS_RPC
        .set(rpc)
        .map_err(|_| anyhow::anyhow!("logs RPC configuration raced"))
}

pub(super) fn logs_rpc() -> &'static Rpc {
    CONFIGURED_LOGS_RPC
        .get()
        .unwrap_or_else(|| &DEFAULT_LOGS_RPC)
}

/// One admissible v4 pool key: (PoolKey fee — V4_DYNAMIC_FEE_FLAG for
/// dynamic pools, tickSpacing, hooks). The hooks address is identity, not
/// annotation: it is hashed into the pool id and encoded into the fill.
type V4Key = (u32, i32, Address);

/// Append-only per-(c0, c1) key sets: Initialize events can only ADD keys, so
/// the full-history scan runs once per currency pair and later refreshes
/// re-read a short overlap below `scanned_to` before advancing to head. The
/// overlap catches replacement Initialize events after shallow reorgs; stale
/// and orphaned keys are harmless because the canonical state Lens validates
/// every candidate pool.
struct V4KeyCache {
    gate: Arc<AsyncMutex<()>>,
    generation: u64,
    last_outcome: Option<V4DiscoveryOutcome>,
    initialized: bool,
    scanned_to: u64,
    keys: std::collections::BTreeSet<V4Key>,
    last_used: Instant,
}
static V4_KEY_CACHE: LazyLock<Mutex<HashMap<(Address, Address), V4KeyCache>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

pub(super) fn v4_key_gate(key: (Address, Address)) -> anyhow::Result<(Arc<AsyncMutex<()>>, u64)> {
    let mut cache = V4_KEY_CACHE.lock().expect("v4 key cache lock");
    if !cache.contains_key(&key) && cache.len() >= V4_KEY_CACHE_CAP {
        let oldest = cache
            .iter()
            .filter(|(_, entry)| Arc::strong_count(&entry.gate) == 1)
            .min_by_key(|(key, entry)| (entry.last_used, **key))
            .map(|(key, _)| *key)
            .context("v4 key cache capacity exhausted")?;
        cache.remove(&oldest);
    }
    let entry = cache.entry(key).or_insert_with(|| V4KeyCache {
        gate: Arc::new(AsyncMutex::new(())),
        generation: 0,
        last_outcome: None,
        initialized: false,
        scanned_to: 0,
        keys: std::collections::BTreeSet::new(),
        last_used: Instant::now(),
    });
    entry.last_used = Instant::now();
    Ok((entry.gate.clone(), entry.generation))
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum V4DiscoveryOutcome {
    Fresh,
    Stale,
    BootstrapIncomplete,
    Failed(Arc<str>),
}

#[derive(Debug, Eq, PartialEq)]
pub(super) enum V4KeyDiscovery {
    Fresh(Vec<V4Key>),
    Stale(Vec<V4Key>),
    BootstrapIncomplete,
}

impl V4KeyDiscovery {
    pub(super) fn keys(&self) -> Option<&[V4Key]> {
        match self {
            Self::Fresh(keys) | Self::Stale(keys) => Some(keys),
            Self::BootstrapIncomplete => None,
        }
    }

    pub(super) fn is_fresh(&self) -> bool {
        matches!(self, Self::Fresh(_))
    }
}

impl V4KeyCache {
    fn last_result(&self) -> Option<anyhow::Result<V4KeyDiscovery>> {
        let outcome = self.last_outcome.as_ref()?;
        Some(match outcome {
            V4DiscoveryOutcome::Fresh => {
                Ok(V4KeyDiscovery::Fresh(self.keys.iter().copied().collect()))
            }
            V4DiscoveryOutcome::Stale => {
                Ok(V4KeyDiscovery::Stale(self.keys.iter().copied().collect()))
            }
            V4DiscoveryOutcome::BootstrapIncomplete => Ok(V4KeyDiscovery::BootstrapIncomplete),
            V4DiscoveryOutcome::Failed(message) => Err(anyhow::anyhow!("{}", message.as_ref())),
        })
    }
}

fn commit_v4_bootstrap_incomplete(key: (Address, Address)) -> V4KeyDiscovery {
    let mut cache = V4_KEY_CACHE.lock().expect("v4 key cache lock");
    let entry = cache.get_mut(&key).expect("v4 key gate entry");
    entry.generation += 1;
    entry.last_outcome = Some(V4DiscoveryOutcome::BootstrapIncomplete);
    entry.last_used = Instant::now();
    V4KeyDiscovery::BootstrapIncomplete
}

fn commit_v4_failure(key: (Address, Address), error: anyhow::Error) -> anyhow::Error {
    let message: Arc<str> = format!("{error:#}").into();
    let mut cache = V4_KEY_CACHE.lock().expect("v4 key cache lock");
    let entry = cache.get_mut(&key).expect("v4 key gate entry");
    entry.generation += 1;
    entry.last_outcome = Some(V4DiscoveryOutcome::Failed(message.clone()));
    entry.last_used = Instant::now();
    anyhow::anyhow!("{}", message.as_ref())
}

pub(super) fn ensure_v4_key_capacity(c0: Address, c1: Address, count: usize) -> anyhow::Result<()> {
    ensure!(
        count <= V4_KEYS_PER_PAIR_CAP,
        "v4 key capacity ({V4_KEYS_PER_PAIR_CAP}) exceeded for {}/{}",
        addrhex(c0),
        addrhex(c1)
    );
    Ok(())
}

pub(super) fn v4_scan_covers_primary(primary_head: Option<u64>, scanned_to: u64) -> bool {
    primary_head.is_some_and(|head| scanned_to >= head)
}

pub(super) fn v4_refresh_from(scanned_to: u64) -> u64 {
    scanned_to.saturating_sub(V4_REORG_OVERLAP - 1)
}

/// One discovery-scoped view of an endpoint. Concurrent pair scans share the
/// first head read, while every getLogs query keeps an explicit toBlock from
/// the same endpoint.
#[derive(Clone, Copy)]
pub(super) struct V4ScanSource<'a> {
    pub(super) rpc: &'a Rpc,
    pub(super) head: &'a OnceCell<Option<u64>>,
}

impl V4ScanSource<'_> {
    async fn head(self) -> Option<u64> {
        *self
            .head
            .get_or_init(|| async { self.rpc.block_number().await.ok() })
            .await
    }
}

pub(super) struct V4ScanContext<'a> {
    pub(super) logs: Option<V4ScanSource<'a>>,
    pub(super) primary: V4ScanSource<'a>,
}

/// One filtered Initialize query against one endpoint, `from ..= head`.
async fn v4_scan(
    source: V4ScanSource<'_>,
    c0: Address,
    c1: Address,
    from: u64,
) -> Option<(u64, Vec<V4Key>)> {
    let head = source.head().await?;
    if from > head {
        return Some((head, Vec::new()));
    }
    let pad = |t: Address| format!("0x000000000000000000000000{}", &addrhex(t)[2..]);
    let params = serde_json::json!([{
        "address": addrhex(V4_POOL_MANAGER),
        "topics": [format!("{V4_INIT_TOPIC:#x}"), serde_json::Value::Null, pad(c0), pad(c1)],
        "fromBlock": format!("{from:#x}"),
        "toBlock": format!("{head:#x}"),
    }]);
    match source.rpc.request("eth_getLogs", params).await {
        Ok(serde_json::Value::Array(logs)) => {
            let keys = logs
                .iter()
                .map(v4_parse_key)
                .collect::<anyhow::Result<Vec<_>>>();
            match keys {
                Ok(keys) => Some((head, keys.into_iter().flatten().collect())),
                Err(error) => {
                    tracing::info!(
                        "snapshot: malformed v4 Initialize logs for {}/{} ({error})",
                        addrhex(c0),
                        addrhex(c1)
                    );
                    None
                }
            }
        }
        Ok(_) => {
            tracing::info!(
                "snapshot: malformed eth_getLogs response for {}/{}",
                addrhex(c0),
                addrhex(c1)
            );
            None
        }
        Err(error) => {
            tracing::info!(
                "snapshot: v4 Initialize scan failed for {}/{} ({})",
                addrhex(c0),
                addrhex(c1),
                sanitized_error(&error)
            );
            None
        }
    }
}

/// Routable key from one Initialize log. Unroutable keys are valid-but-
/// skipped; malformed upstream data invalidates this scan.
///
/// Admission is by CAPABILITY, not by identity: a hook whose address carries
/// no swap-time permission bits (V4_SWAP_HOOK_FLAGS) is never called during a
/// swap — the PoolManager dispatches on those bits alone — so the pool prices
/// exactly like a hookless one. Hooks that CAN touch swaps (reprice, take a
/// delta, or revert per-sender) stay out. Dynamic-fee keys are admitted under
/// the same gate: without beforeSwap nothing can override the fee mid-swap,
/// and slot0's live lpFee is validated per snapshot.
pub(super) fn v4_parse_key(log: &serde_json::Value) -> anyhow::Result<Option<(u32, i32, Address)>> {
    let encoded = log["data"]
        .as_str()
        .context("Initialize log is missing data")?;
    let data = hexbytes(encoded).context("Initialize log data is not hex")?;
    ensure!(data.len() >= 160, "Initialize log data is truncated");
    let fee = u32::try_from(read_word(&data, 0)?).context("Initialize fee out of range")?;
    let spacing = i32::try_from(word_i64(read_word(&data, 32)?)?)
        .context("Initialize tick spacing out of range")?;
    let hooks = word_address(&data, 64)?;
    let hook_ok = v4_hook_flags(hooks) & V4_SWAP_HOOK_FLAGS == 0;
    let fee_ok = fee <= V4_MAX_FEE_PPM || fee == V4_DYNAMIC_FEE_FLAG;
    Ok((hook_ok && fee_ok && (1..=32767).contains(&spacing)).then_some((fee, spacing, hooks)))
}

/// Every hookless (fee, tickSpacing) ever initialized for (c0, c1), from the
/// PoolManager's Initialize events (currencies are indexed topics, so the
/// filtered query stays tiny even though the chain holds >10k v4 pools — and
/// it catches the nonstandard ladders 0x routes, e.g. 450ppm/9 carrying 20%
/// of a 500-WETH split). Bootstrap (cache miss) needs the full-range-capable
/// public endpoint; refreshes are small ranges served public-first with the
/// primary RPC as fallback (they fit its 10k-block cap), and when both fail
/// the cached keys are served stale. `BootstrapIncomplete` means the initial
/// event history is unavailable, so the caller uses the V4_KEYS grid and
/// caches that usable-but-incomplete topology only until the retry deadline.
/// Initialization is proof of existence, so event keys skip the extsload
/// existence probe; R3 still validates state, which also makes cross-endpoint
/// scans safe (a pool the logs endpoint knows but the state endpoint doesn't
/// reads sqrt == 0 and drops).
pub(super) async fn v4_event_keys(
    scans: &V4ScanContext<'_>,
    c0: Address,
    c1: Address,
) -> anyhow::Result<V4KeyDiscovery> {
    let key = (c0, c1);
    let (gate, generation) = v4_key_gate(key)?;
    let _guard = gate.lock().await;
    let cached: Option<(u64, std::collections::BTreeSet<V4Key>)> = {
        let mut cache = V4_KEY_CACHE.lock().expect("v4 key cache lock");
        let entry = cache.get_mut(&key).expect("v4 key gate entry");
        entry.last_used = Instant::now();
        if entry.generation != generation {
            return entry
                .last_result()
                .context("completed v4 scan has no outcome")?;
        }
        entry
            .initialized
            .then(|| (entry.scanned_to, entry.keys.clone()))
    };
    let (mut scanned_to, mut keys, was_cached) = match cached {
        None => {
            let Some(logs) = scans.logs else {
                return Ok(commit_v4_bootstrap_incomplete(key));
            };
            let Some((head, entries)) = v4_scan(logs, c0, c1, 0).await else {
                return Ok(commit_v4_bootstrap_incomplete(key));
            };
            let keys: std::collections::BTreeSet<V4Key> = entries.into_iter().collect();
            ensure_v4_key_capacity(c0, c1, keys.len())
                .map_err(|error| commit_v4_failure(key, error))?;
            (head, keys, false)
        }
        Some((scanned_to, keys)) => (scanned_to, keys, true),
    };

    // "Fresh" is relative to the state endpoint, not merely to whichever
    // logs endpoint answered. A lagging public logs node must not earn the
    // full topology TTL while missing pools already visible to state reads.
    let primary_head = scans.primary.head().await;
    let logs_is_primary = scans
        .logs
        .is_some_and(|logs| logs.rpc.url == scans.primary.rpc.url);
    let mut refreshed_to = (!was_cached).then_some(scanned_to);
    if was_cached {
        let from = v4_refresh_from(scanned_to);
        if let Some(logs) = scans.logs
            && let Some((head, entries)) = v4_scan(logs, c0, c1, from).await
        {
            keys.extend(entries);
            ensure_v4_key_capacity(c0, c1, keys.len())
                .map_err(|error| commit_v4_failure(key, error))?;
            scanned_to = scanned_to.max(head);
            refreshed_to = Some(head);
        }
    }
    let mut primary_refreshed_to = logs_is_primary.then_some(refreshed_to).flatten();
    if !logs_is_primary && let Some(primary_head) = primary_head {
        // A separate logs endpoint can be at the same height on a different
        // short fork. Always re-read the canonical state endpoint's overlap;
        // comparing block numbers alone cannot establish tail completeness.
        let from = v4_refresh_from(primary_head).min(scanned_to.saturating_add(1));
        if let Some((head, entries)) = v4_scan(scans.primary, c0, c1, from).await {
            keys.extend(entries);
            ensure_v4_key_capacity(c0, c1, keys.len())
                .map_err(|error| commit_v4_failure(key, error))?;
            scanned_to = scanned_to.max(head);
            primary_refreshed_to = Some(head);
        }
    }

    ensure_v4_key_capacity(c0, c1, keys.len()).map_err(|error| commit_v4_failure(key, error))?;
    let fresh = v4_scan_covers_primary(primary_head, primary_refreshed_to.unwrap_or(0));
    let mut cache = V4_KEY_CACHE.lock().expect("v4 key cache lock");
    let entry = cache.get_mut(&key).expect("v4 key gate entry");
    entry.keys.extend(keys);
    entry.scanned_to = entry.scanned_to.max(scanned_to);
    entry.initialized = true;
    entry.generation += 1;
    entry.last_outcome = Some(if fresh {
        V4DiscoveryOutcome::Fresh
    } else {
        V4DiscoveryOutcome::Stale
    });
    entry.last_used = Instant::now();
    let keys: Vec<V4Key> = entry.keys.iter().copied().collect();
    let covered_to = entry.scanned_to;
    drop(cache);

    if fresh {
        Ok(V4KeyDiscovery::Fresh(keys))
    } else {
        match primary_head {
            Some(head) => tracing::info!(
                "snapshot: v4 key refresh incomplete for {}/{} — scanned to block {covered_to}, state head {head}",
                addrhex(c0),
                addrhex(c1)
            ),
            None => tracing::info!(
                "snapshot: v4 state head unavailable for {}/{} — serving keys scanned to block {covered_to}",
                addrhex(c0),
                addrhex(c1)
            ),
        }
        Ok(V4KeyDiscovery::Stale(keys))
    }
}
