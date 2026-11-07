use super::{Resident, State, carry};
use crate::catalog::CatalogProtocol;
use crate::pools::{V2Pool, V3Pool};
use crate::rpc::{CanonicalBlock, CanonicalHeader, Rpc, sanitized_error};
use crate::snapshot::Snapshot;
use crate::topology::AddressPoolTopology;
use alloy::eips::BlockId;
use alloy_primitives::Address;
use anyhow::{Context, ensure};
use serde_json::{Value, json};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::task::JoinHandle;

const LIST_REFRESH: Duration = Duration::from_secs(600);

/// Pause after a failed list build before the next attempt.
const RETRY: Duration = Duration::from_secs(30);

/// The most blocks one step carries state across; a longer gap is read whole.
/// A step asks for their headers in one batch and their logs in another, so
/// the bound is on the size of those answers, not on round trips.
const MAX_STEP_BLOCKS: u64 = 32;

pub(super) async fn run(resident: Arc<Resident>) {
    let mut list: Option<List> = None;
    let mut fetch: Option<JoinHandle<anyhow::Result<Vec<AddressPoolTopology>>>> = None;
    let mut next_fetch = Instant::now() + LIST_REFRESH;
    loop {
        let started = Instant::now();
        let Some(current) = list.as_mut() else {
            match List::build(&resident).await {
                Ok(built) => {
                    tracing::info!(
                        "resident: list built: {} V3 and {} V2 pools proved, {} rejected",
                        built.v3.len(),
                        built.v2.len(),
                        built.rejected.len(),
                    );
                    list = Some(built);
                    next_fetch = Instant::now() + LIST_REFRESH;
                }
                Err(error) => {
                    resident.note_error(&error.context("building the pool list"));
                    tokio::time::sleep(RETRY).await;
                }
            }
            continue;
        };
        if fetch.as_ref().is_some_and(JoinHandle::is_finished) {
            match fetch.take().expect("checked").await {
                Ok(Ok(rows)) => current.pending_rows = Some(rows),
                Ok(Err(error)) => resident
                    .note_error(&error.context("fetching the pool list; keeping the last one")),
                Err(error) => resident.note_error(&anyhow::anyhow!(
                    "pool list fetch stopped: {error}; keeping the last one"
                )),
            }
        }
        if fetch.is_none() && Instant::now() >= next_fetch {
            fetch = Some(tokio::spawn(fetch_list(
                resident.http.clone(),
                resident.settings.list_url.clone(),
            )));
            next_fetch = Instant::now() + LIST_REFRESH;
        }
        if let Err(error) = resident.step(current).await {
            resident.note_error(&error);
        }
        tokio::time::sleep(resident.settings.poll.saturating_sub(started.elapsed())).await;
    }
}

/// The pools to read, with their identities. Owned by the reader.
pub(super) struct List {
    /// Sorted by (token0, token1, address), the per-pair path's order.
    v3: Vec<V3Pool>,
    v2: Vec<V2Pool>,
    rejected: HashSet<Address>,
    pub(super) pending_rows: Option<Vec<AddressPoolTopology>>,
    /// The last read, for the next to carry from.
    last: Option<carry::LastRead>,
}

impl List {
    async fn build(resident: &Resident) -> anyhow::Result<Self> {
        let header = resident.rpc.canonical_header(BlockId::latest()).await?;
        let mut list = Self {
            v3: Vec::new(),
            v2: Vec::new(),
            rejected: HashSet::new(),
            pending_rows: None,
            last: None,
        };
        let rows = fetch_list(resident.http.clone(), resident.settings.list_url.clone()).await?;
        list.apply_rows(resident, rows, header.block).await?;
        ensure!(
            !list.v3.is_empty() || !list.v2.is_empty(),
            "no pool on the list passed its identity check"
        );
        Ok(list)
    }

    /// Take a fresh list: prove the pools it adds, drop the ones it no longer
    /// lists.
    pub(super) async fn apply_rows(
        &mut self,
        resident: &Resident,
        rows: Vec<AddressPoolTopology>,
        block: CanonicalBlock,
    ) -> anyhow::Result<()> {
        let listed: HashSet<Address> = rows.iter().map(|row| row.address).collect();
        let known: HashSet<Address> = self
            .v3
            .iter()
            .map(|pool| pool.address)
            .chain(self.v2.iter().map(|pool| pool.address))
            .collect();
        let fresh: Vec<AddressPoolTopology> = rows
            .into_iter()
            .filter(|row| !known.contains(&row.address) && !self.rejected.contains(&row.address))
            .collect();
        let (v3, v2, rejected) = crate::state::prove_listed_pools(
            resident.profile,
            resident.discovery,
            &resident.rpc,
            &fresh,
            block,
        )
        .await?;
        for (address, reason) in rejected {
            tracing::info!("resident: the list names {address:#x}; left out: {reason}");
            self.rejected.insert(address);
        }
        self.v3.retain(|pool| listed.contains(&pool.address));
        self.v3.extend(v3);
        self.v3
            .sort_by_key(|pool| (pool.token0, pool.token1, pool.address));
        self.v2.retain(|pool| listed.contains(&pool.address));
        self.v2.extend(v2);
        self.v2
            .sort_by_key(|pool| (pool.token0, pool.token1, pool.address));
        let mut health = resident.health.lock().expect("resident health");
        health.list_at = Some(Instant::now());
        health.list_pools = self.v3.len() + self.v2.len();
        health.list_rejected = self.rejected.len();
        Ok(())
    }

    /// One block's state of every listed pool: the pools that logged since
    /// the last read read again and the rest carried, or every pool read
    /// whole.
    pub(super) async fn read(
        &mut self,
        resident: &Resident,
        head: &CanonicalHeader,
        observed_at: Instant,
    ) -> anyhow::Result<State> {
        let block = head.block;
        let listed: HashSet<Address> = self
            .v3
            .iter()
            .map(|pool| pool.address)
            .chain(self.v2.iter().map(|pool| pool.address))
            .collect();
        // Pools whose venue is not known to move only with `carry::MOVES`.
        let uncarried: HashSet<Address> = self
            .v3
            .iter()
            .filter(|pool| !carry::carries_v3(pool))
            .map(|pool| pool.address)
            .chain(
                self.v2
                    .iter()
                    .filter(|pool| !carry::carries_v2(pool))
                    .map(|pool| pool.address),
            )
            .collect();
        let pools = async {
            let changed = match (resident.settings.full_read, self.last.as_ref()) {
                (Some(_), Some(last)) => {
                    match changed_since(&resident.rpc, &last.block, head, &listed).await {
                        Ok(changed) => changed.map(|changed| &changed | &uncarried),
                        Err(error) => {
                            tracing::info!(
                                "resident: pool logs unread, reading every pool: {}",
                                sanitized_error(&error)
                            );
                            resident
                                .health
                                .lock()
                                .expect("resident health")
                                .log_failures += 1;
                            None
                        }
                    }
                }
                _ => None,
            };
            let carry_from = match (resident.settings.full_read, self.last.as_ref(), &changed) {
                (Some(every), Some(last), Some(changed)) if last.whole_at.elapsed() < every => {
                    Some((last, changed))
                }
                _ => None,
            };
            let Some((last, changed)) = carry_from else {
                let whole = read_pools(resident, &self.v3, &self.v2, block, observed_at).await?;
                let audit = match (self.last.as_ref(), &changed) {
                    (Some(last), Some(changed)) => {
                        Some(carry::audit(last, changed, &whole, &listed))
                    }
                    _ => None,
                };
                return anyhow::Ok((whole.v3, whole.v2, Read::Whole { audit }));
            };
            let read = carry::to_read(&listed, last, changed);
            let v3: Vec<V3Pool> = self
                .v3
                .iter()
                .filter(|pool| read.contains(&pool.address))
                .cloned()
                .collect();
            let v2: Vec<V2Pool> = self
                .v2
                .iter()
                .filter(|pool| read.contains(&pool.address))
                .cloned()
                .collect();
            let fresh = read_pools(resident, &v3, &v2, block, observed_at).await?;
            let (v3, v2) = carry::merge(&self.v3, &self.v2, &read, &fresh, last);
            Ok((
                v3,
                v2,
                Read::Carried {
                    reread: read.len(),
                    whole_at: last.whole_at,
                },
            ))
        };
        let (settler, (v3, v2, how)) = tokio::try_join!(read_settler(resident, block), pools)?;
        let whole_at = match &how {
            Read::Whole { .. } => observed_at,
            Read::Carried { whole_at, .. } => *whole_at,
        };
        self.last = Some(carry::LastRead::new(block, listed, &v3, &v2, whole_at));
        {
            let mut health = resident.health.lock().expect("resident health");
            match &how {
                Read::Whole { audit } => {
                    health.whole_reads += 1;
                    if let Some((checked, drifted)) = audit {
                        health.audited += *checked as u64;
                        health.drifted += drifted.len() as u64;
                    }
                }
                Read::Carried { reread, .. } => {
                    health.carried_reads += 1;
                    health.last_reread = Some(*reread);
                }
            }
        }
        if let Read::Whole {
            audit: Some((_, drifted)),
        } = &how
            && !drifted.is_empty()
        {
            tracing::warn!(
                "resident: {} pools moved at block {} without a log, now read whole: {}",
                drifted.len(),
                block.number,
                drifted
                    .iter()
                    .take(8)
                    .map(|address| format!("{address:#x}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        let snapshot = Snapshot {
            block: block.number,
            settler,
            v3,
            v2,
            ekubo: Vec::new(),
        };
        Ok(State::new(
            snapshot,
            block,
            &resident.connectors,
            observed_at,
        ))
    }
}

/// How a block's pools were read.
enum Read {
    /// Every pool, with the audit of the carry when the blocks since the
    /// last read were linked: pools checked, and those that drifted.
    Whole {
        audit: Option<(usize, Vec<Address>)>,
    },
    /// Only the pools that logged or are new; the rest carried.
    Carried { reread: usize, whole_at: Instant },
}

/// `v3` and `v2`'s state at `block`, one Lens read.
async fn read_pools(
    resident: &Resident,
    v3: &[V3Pool],
    v2: &[V2Pool],
    block: CanonicalBlock,
    observed_at: Instant,
) -> anyhow::Result<Snapshot> {
    if v3.is_empty() && v2.is_empty() {
        return Ok(Snapshot {
            block: block.number,
            settler: None,
            v3: Vec::new(),
            v2: Vec::new(),
            ekubo: Vec::new(),
        });
    }
    let words = crate::state::bitmap_words()?;
    let ret = crate::lens::peek_pinned(&resident.rpc, words, v3, v2, block, observed_at).await?;
    ensure!(
        ret.block_number == block.number && ret.block_id == BlockId::hash_canonical(block.hash),
        "resident Lens did not read the requested block"
    );
    crate::state::parse_resident_lens(v3, v2, &ret)
}

/// The Settler the registry names at `block`, when execution is enabled.
async fn read_settler(
    resident: &Resident,
    block: CanonicalBlock,
) -> anyhow::Result<Option<Address>> {
    let profile = resident.profile;
    if !profile.execution_enabled() {
        return Ok(None);
    }
    let rpc = &resident.rpc;
    let block_id = BlockId::hash_canonical(block.hash);
    let owner = rpc
        .multicall(
            vec![crate::state::execution_registry_call(profile)?],
            block_id,
        )
        .await?;
    let owner = owner.first().context("registry read is missing")?;
    Ok(
        crate::state::execution_identity_from(profile, rpc, block_id, owner)
            .await?
            .map(|identity| identity.settler),
    )
}

/// The pools of `pools` that moved in the blocks after `last` through
/// `head`. `None` when those blocks do not link to `last` (a reorg, or a node
/// on another branch) or span more than `MAX_STEP_BLOCKS`.
async fn changed_since(
    rpc: &Rpc,
    last: &CanonicalBlock,
    head: &CanonicalHeader,
    pools: &HashSet<Address>,
) -> anyhow::Result<Option<HashSet<Address>>> {
    let span = head.block.number.saturating_sub(last.number);
    if span == 0 || span > MAX_STEP_BLOCKS {
        return Ok(None);
    }
    let between = rpc
        .canonical_headers(last.number + 1..head.block.number)
        .await?;
    let Some(blocks) = carry::linked(last, &between, head) else {
        return Ok(None);
    };
    let answers = rpc
        .logs_batch(
            blocks
                .iter()
                .map(|block| json!({"blockHash": block.hash, "topics": [carry::MOVES]}))
                .collect(),
            head.block.number,
        )
        .await?;
    let changed = blocks
        .iter()
        .zip(&answers)
        .map(|(block, logs)| carry::logged(logs, block, pools))
        .collect::<anyhow::Result<Vec<_>>>()?;
    Ok(Some(changed.into_iter().flatten().collect()))
}

/// The pool list: a JSON array of address pools, each
/// `{"protocol", "address", "token0", "token1", "feePpm"}` with `protocol`
/// a venue id from the profile's table. Read whole or refused whole.
pub(super) async fn fetch_list(
    http: reqwest::Client,
    url: String,
) -> anyhow::Result<Vec<AddressPoolTopology>> {
    let body: Value = http
        .get(&url)
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .map_err(|error| anyhow::anyhow!("pool list request failed: {}", error.without_url()))?
        .json()
        .await
        .map_err(|error| anyhow::anyhow!("pool list is not JSON: {}", error.without_url()))?;
    let items = body
        .as_array()
        .context("the pool list is not a JSON array")?;
    let mut seen = HashSet::new();
    let mut rows = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        let row = list_row(item).with_context(|| format!("pool list row {index}"))?;
        ensure!(
            seen.insert(row.address),
            "the pool list names {:#x} twice",
            row.address
        );
        rows.push(row);
    }
    ensure!(!rows.is_empty(), "the pool list is empty");
    Ok(rows)
}

fn list_row(item: &Value) -> anyhow::Result<AddressPoolTopology> {
    let address = |field: &str| -> anyhow::Result<Address> {
        item[field]
            .as_str()
            .with_context(|| format!("no {field}"))?
            .parse()
            .with_context(|| format!("{field} is not an address"))
    };
    let protocol = item["protocol"].as_str().context("no protocol")?;
    let protocol = CatalogProtocol::known(protocol)
        .filter(|protocol| *protocol != CatalogProtocol::UNIV4)
        .with_context(|| format!("{protocol:?} is not an address-pool protocol"))?;
    let fee_ppm = item["feePpm"]
        .as_u64()
        .and_then(|fee| u32::try_from(fee).ok())
        .filter(|fee| *fee < 1_000_000)
        .context("no valid feePpm")?;
    Ok(AddressPoolTopology {
        protocol,
        address: address("address")?,
        token0: address("token0")?,
        token1: address("token1")?,
        fee_ppm,
        tick_spacing: None,
        created_block: None,
    })
}
