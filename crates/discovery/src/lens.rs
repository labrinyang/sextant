// Bulk state Lens via eth_call state overrides.
//
// lens/QuoteLens.sol is injected at LENS (a vanity pseudo-address, never
// deployed) through the state-override param of each eth_call — the
// public endpoint, the commercial endpoint and anvil all support it
// (verified live). Up to QUERY_CHUNK pools use one call; larger topologies are
// split at a single pinned block to stay below public-node gas caps. The
// in-EVM lens resolves the data dependencies (current tick → bitmap window →
// initialized ticks) that forced the old R3/R4/R5 rounds to be sequential.
//
// Response layout (uint256 words), per query —
//   v3  [ok]                 ok=0: pool dropped, nothing follows
//       [sqrt, tick, liquidity, fee?, spacing?]   (? = flag-gated)
//       [live]               live=0 (sqrt==0): no window follows
//       [(2W+1) bitmap words] [tick word per set bit, (word, bit) ascending]
//   v4  [slot0, liquidity] [live] — live gates on the R3 validation ladder
//       (sqrt, protocolFee, lpFee, in-range liquidity); window as v3
//   v2  [ok]  ok=1: [reserve0, reserve1, fee?]
//   algebra [ok] ok=1: [sqrt, tick, liquidity, baseFee, lastFee,
//       pluginConfig, spacing, plugin, pluginCodehash, live]
//       live=1: [downCount, (tick, liquidityNet)*, upCount, (tick, liquidityNet)*]
//       each run is ascending and contains at most W initialized ticks
// Tick words carry exactly the bytes the multicall rounds used to return
// (ticks() word 1 / raw extsload word), so state.rs keeps its decoders.

use crate::abi::hexbytes;
use crate::pools::{V2Pool, V3Pool};
use crate::rpc::{CanonicalBlock, RevertData, Rpc, RpcRejected};
use crate::venue::Core;
use alloy::eips::BlockId;
use alloy_primitives::{
    Address, B256, Bytes, U256, address,
    aliases::{I24, U24},
};
use alloy_sol_types::{SolCall, SolError, sol};
use anyhow::{Context, ensure};
use futures_util::{FutureExt, StreamExt, TryStreamExt, future::BoxFuture, stream};
use std::collections::HashMap;
use std::ops::Range;
use std::sync::{LazyLock, Mutex};
use tokio::sync::Semaphore;

sol! {
    struct Query {
        uint8 kind;
        uint8 flags;
        address target;
        bytes32 slot;
        int24 spacing;
        uint24 fee;
    }

    function peek(
        uint16 words,
        uint16 maxTicksPerPool,
        Query[] queries
    )
        external view returns (uint256[] memory);

    /// QuoteLens rejects a call whose reserve cannot hold one pool's window,
    /// and names both the pool and the count it wanted.
    error TickBudgetExceeded(address pool, uint256 initialized, uint256 limit);
}

const KIND_V3: u8 = 0;
const KIND_V4: u8 = 1;
const KIND_V2: u8 = 2;
const KIND_ALGEBRA: u8 = 3;
const READ_FEE: u8 = 1;
const READ_SPACING: u8 = 2;
// Keep these in lock-step with QuoteLens.sol. 1,024 ticks is the reserve an
// unmeasured pool is planned with; once measured it carries its own. No live
// pool is silently omitted at any reserve.
const MAX_OUTPUT_WORDS: usize = 32_783;
const MAX_TICKS_PER_POOL: u16 = 1_024;
const QUERY_CHUNK: usize = 128;

// ---- gas ----
//
// A Lens call's gas is planned from what its pools are known to hold. A
// shallow pool costs about its bitmap window; a deep one (Uniswap's
// USDC/WETH 0.05% on Ethereum holds ~1,500 initialized ticks in the default
// window) costs about 10k gas per tick it reads, which no fixed limit fits
// without overpaying everywhere else.

/// The least a Lens call asks for.
const LENS_GAS: u64 = 16_000_000;
/// The most a Lens call asks for: under the 50M `eth_call` cap geth and
/// erigon default to. A node with a lower cap clamps the request itself.
const LENS_GAS_CEILING: u64 = 48_000_000;
/// A chunk closes before its estimate passes this, so a planned call keeps
/// headroom under the ceiling.
const CHUNK_GAS_TARGET: u64 = 32_000_000;
/// A pool's fixed reads (slot0, liquidity, fee and spacing).
const QUERY_BASE_GAS: u64 = 15_000;
/// One `tickBitmap` word.
const BITMAP_WORD_GAS: u64 = 2_600;
/// One initialized tick's `ticks(int24)`: a cold read of its struct.
const TICK_READ_GAS: u64 = 10_000;

/// What one query is expected to cost, from the tick count last measured
/// for its pool (none when unmeasured: the first read finds out).
fn query_gas(words: u16, query: &Query) -> u64 {
    let window = (u64::from(words) * 2 + 1) * BITMAP_WORD_GAS;
    match query.kind {
        KIND_V3 | KIND_V4 => {
            let ticks = observed(words, query).unwrap_or(0);
            QUERY_BASE_GAS + window + u64::from(ticks) * TICK_READ_GAS
        }
        KIND_ALGEBRA => QUERY_BASE_GAS + u64::from(words) * 4 * TICK_READ_GAS,
        _ => QUERY_BASE_GAS,
    }
}

/// The limit a call with this estimate asks for: half again as much, within
/// [`LENS_GAS`, `LENS_GAS_CEILING`].
fn call_gas(estimate: u64) -> u64 {
    estimate
        .saturating_add(estimate / 2)
        .clamp(LENS_GAS, LENS_GAS_CEILING)
}

/// Whether the call may have run out of gas: the node says so, or the Lens
/// reverted with nothing to say — which is how a pool read that ran out of
/// gas inside its own `staticcall` surfaces.
fn may_have_run_out_of_gas(error: &anyhow::Error) -> bool {
    let text = format!("{error:#}").to_ascii_lowercase();
    text.contains("out of gas")
        || text.contains("gas required exceeds")
        || error
            .downcast_ref::<RevertData>()
            .is_some_and(|data| data.0.is_empty())
}

// ---- measured response reserve ----
//
// One `maxTicksPerPool` covers every bitmap pool in a call, so a single
// constant has to serve both a drained V4 pool (zero initialized ticks) and
// the deepest spacing-1 pool on the chain. On a mature chain no constant does
// both: measured on BSC, 118 of the 147 pools on the BNB/USDT route return
// three words each while reserving 1,060, which alone splits the pull into
// five calls — and the deepest PancakeSwap V3 pool holds 4,592 initialized
// ticks, so it rejects whichever call it lands in, every pull, forever.
//
// So the reserve is measured rather than chosen. Every accepted response
// carries each pool's bitmap window, and every rejection names the exact count
// it wanted; both feed this table, and the next plan is drawn against it. A
// budget that turns out too small costs one more round trip and corrects
// itself. It can never drop a pool: the Lens still rejects a call it cannot
// answer in full rather than truncating one.
const BUDGET_CACHE_CAP: usize = 8_192;

/// Smallest reserve worth planning. Below this the saved words are noise, and
/// a pool that gains its first positions between two pulls still fits.
const BUDGET_FLOOR: u32 = 64;

/// One query's data source: the contract it reads plus, for V4, the pool slot
/// inside it. V2 and Algebra frames carry no tick reserve and are not keyed.
type BudgetKey = (u16, Address, B256);

struct Learned {
    ticks: u32,
    seq: u64,
}

static BUDGETS: LazyLock<Mutex<(HashMap<BudgetKey, Learned>, u64)>> =
    LazyLock::new(|| Mutex::new((HashMap::new(), 0)));

fn budget_key(words: u16, query: &Query) -> Option<BudgetKey> {
    matches!(query.kind, KIND_V3 | KIND_V4).then(|| (words, query.target, query.slot))
}

/// Record one pool's observed initialized-tick count at this window width.
fn learn(words: u16, query: &Query, ticks: u32) {
    let Some(key) = budget_key(words, query) else {
        return;
    };
    let mut guard = BUDGETS.lock().expect("lens budget cache");
    let (table, seq) = &mut *guard;
    *seq += 1;
    let stamp = *seq;
    if !table.contains_key(&key)
        && table.len() >= BUDGET_CACHE_CAP
        && let Some(oldest) = table
            .iter()
            .min_by_key(|(key, learned)| (learned.seq, **key))
            .map(|(key, _)| *key)
    {
        table.remove(&oldest);
    }
    table.insert(key, Learned { ticks, seq: stamp });
}

fn observed(words: u16, query: &Query) -> Option<u32> {
    let key = budget_key(words, query)?;
    let guard = BUDGETS.lock().expect("lens budget cache");
    guard.0.get(&key).map(|learned| learned.ticks)
}

/// The reserve this query is planned with. An unmeasured pool keeps the
/// historical constant; a measured one gets its own count plus room to grow,
/// capped at what one response can represent.
fn planned_budget(words: u16, query: &Query) -> anyhow::Result<u16> {
    let Some(ticks) = observed(words, query) else {
        return Ok(if budget_key(words, query).is_some() {
            MAX_TICKS_PER_POOL
        } else {
            0
        });
    };
    let want = u64::from(ticks) + u64::from(ticks) / 4 + 32;
    let ceiling = expanded_tick_budget(words, query)?;
    Ok(u16::try_from(want.max(u64::from(BUDGET_FLOOR)))
        .unwrap_or(u16::MAX)
        .min(ceiling))
}

/// Injection address — spells "LENS"; never a real contract on this chain.
const LENS: Address = address!("4c454e5300000000000000000000000000000000");

static CODE: LazyLock<Bytes> = LazyLock::new(|| {
    Bytes::from(
        hexbytes(include_str!("../../../lens/QuoteLens.bin").trim()).expect("lens bytecode hex"),
    )
});

pub fn i24(v: i32) -> anyhow::Result<I24> {
    I24::try_from(v).map_err(|_| anyhow::anyhow!("{v} does not fit int24"))
}

/// One Query per pool, in (v3pools, v2pools) order — parse_lens walks the
/// response in the same order.
fn queries(v3: &[V3Pool], v2: &[V2Pool]) -> anyhow::Result<Vec<Query>> {
    let mut qs = Vec::with_capacity(v3.len() + v2.len());
    for p in v3 {
        qs.push(if p.protocol.core() == Core::Algebra {
            Query {
                kind: KIND_ALGEBRA,
                flags: 0,
                target: p.address,
                slot: B256::ZERO,
                spacing: I24::ZERO,
                fee: U24::ZERO,
            }
        } else {
            match &p.v4 {
                Some(v4) => Query {
                    kind: KIND_V4,
                    flags: 0,
                    target: p.address,
                    slot: v4.state_slot,
                    spacing: i24(p.tick_spacing)?,
                    fee: U24::from(p.fee_ppm),
                },
                None => Query {
                    kind: KIND_V3,
                    flags: u8::from(p.protocol.core() == Core::Up33Cl) * READ_FEE
                        + u8::from(p.verify_pool_spacing) * READ_SPACING,
                    target: p.address,
                    slot: B256::ZERO,
                    // Pool-verified adapters may carry the factory spacing as
                    // the expected value; the Lens returns the pool value.
                    spacing: i24(p.tick_spacing)?,
                    fee: U24::ZERO,
                },
            }
        });
    }
    for p in v2 {
        qs.push(Query {
            kind: KIND_V2,
            flags: u8::from(p.protocol.core() == Core::Up33V2) * READ_FEE,
            target: p.address,
            slot: B256::ZERO,
            spacing: I24::ZERO,
            fee: U24::ZERO,
        });
    }
    Ok(qs)
}

#[derive(Clone, Debug)]
pub struct PeekResult {
    pub words: Vec<U256>,
    /// The ± tick-bitmap word window this read used around each pool's current
    /// word. Parsers read the window from here.
    pub window_words: u16,
    /// RPC block number paired with `block_id` before any Lens chunk runs.
    pub block_number: u64,
    /// Consensus timestamp from the same canonical header as `block_id`.
    pub block_timestamp: u64,
    /// EIP-1898 canonical hash used by every Lens chunk and dependent read.
    pub block_id: BlockId,
    /// Earliest instant at which the returned block could have been observed.
    /// Engine freshness starts here, not after a multi-chunk pull finishes.
    pub observed_at: std::time::Instant,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ChunkPlan {
    queries: Range<usize>,
    /// `maxTicksPerPool` for this call: the largest reserve any of its queries
    /// asked for, because the Lens applies one scalar to all of them.
    budget: u16,
    response_words: usize,
    /// The call's gas limit (`call_gas` of its queries' estimates).
    gas: u64,
}

fn query_response_words_with_tick_budget(
    words: u16,
    query: &Query,
    max_ticks_per_pool: u16,
) -> anyhow::Result<usize> {
    let bitmap_words = usize::from(words) * 2 + 1;
    Ok(match query.kind {
        KIND_V2 => {
            ensure!(query.flags <= READ_FEE, "invalid v2 query flags");
            3 + usize::from(query.flags & READ_FEE != 0)
        }
        KIND_ALGEBRA => {
            ensure!(query.flags == 0, "invalid Algebra query flags");
            13 + usize::from(words) * 4
        }
        KIND_V4 => {
            ensure!(query.flags == 0, "invalid v4 query flags");
            3 + bitmap_words + usize::from(max_ticks_per_pool)
        }
        KIND_V3 => {
            ensure!(
                query.flags & !(READ_FEE | READ_SPACING) == 0,
                "invalid v3 query flags"
            );
            5 + usize::from(query.flags & READ_FEE != 0)
                + usize::from(query.flags & READ_SPACING != 0)
                + bitmap_words
                + usize::from(max_ticks_per_pool)
        }
        kind => anyhow::bail!("invalid lens query kind {kind}"),
    })
}

#[cfg(test)]
fn query_response_words(words: u16, query: &Query) -> anyhow::Result<usize> {
    query_response_words_with_tick_budget(words, query, MAX_TICKS_PER_POOL)
}

/// Maximum tick budget a single exceptional V3/V4 query can use without
/// exceeding the Lens response-memory contract. It is also capped by the
/// number of bits in the requested bitmap window, so the default ±16-word
/// window can always be represented in full (8,448 initialized ticks).
fn expanded_tick_budget(words: u16, query: &Query) -> anyhow::Result<u16> {
    ensure!(
        matches!(query.kind, KIND_V3 | KIND_V4),
        "only bitmap pools have an expanded tick budget"
    );
    let fixed_words = query_response_words_with_tick_budget(words, query, 0)?;
    ensure!(
        fixed_words < MAX_OUTPUT_WORDS,
        "lens fixed response exceeds its word budget"
    );
    let window_ticks = (usize::from(words) * 2 + 1) * 256;
    let available = MAX_OUTPUT_WORDS - fixed_words;
    u16::try_from(window_ticks.min(available).min(usize::from(u16::MAX)))
        .context("expanded lens tick budget does not fit uint16")
}

/// Whether this query's frame grows with `maxTicksPerPool`. V2 and Algebra
/// frames are fixed, so they cost the same in any chunk.
fn reserves_ticks(query: &Query) -> bool {
    matches!(query.kind, KIND_V3 | KIND_V4)
}

/// A chunk's reserve, mirroring QuoteLens' `worstCaseQueryResponseWords`:
/// every frame at budget zero, plus one budget for each bitmap pool.
fn chunk_reserve(base: usize, bitmap_pools: usize, budget: u16) -> usize {
    base + bitmap_pools * usize::from(budget)
}

/// Deterministic request planner. 128 queries remains a gas/calldata ceiling;
/// the mirrored Rust/Solidity response formula is the hard memory bound.
///
/// `budgets` is the per-query reserve; a chunk is charged at the largest one
/// it contains, so runs of cheap pools pack densely and a dense pool pulls
/// only its own neighbourhood into a bigger reserve.
///
/// `gas` is each query's estimate (`query_gas`): a chunk also closes before
/// its estimate passes `CHUNK_GAS_TARGET`, and asks for `call_gas` of it.
fn query_chunks(
    words: u16,
    queries: &[Query],
    budgets: &[u16],
    gas: &[u64],
) -> anyhow::Result<Vec<ChunkPlan>> {
    ensure!(
        queries.len() == budgets.len() && queries.len() == gas.len(),
        "lens plan has {} queries, {} budgets and {} gas estimates",
        queries.len(),
        budgets.len(),
        gas.len()
    );
    let mut plans = Vec::new();
    let mut start = 0usize;
    let mut base = 0usize;
    let mut bitmap_pools = 0usize;
    let mut budget = 0u16;
    let mut estimate = 0u64;

    for (index, query) in queries.iter().enumerate() {
        let frame_base = query_response_words_with_tick_budget(words, query, 0)?;
        let grows = reserves_ticks(query);
        ensure!(
            chunk_reserve(frame_base, usize::from(grows), budgets[index]) <= MAX_OUTPUT_WORDS,
            "lens query {index} cannot fit in one response"
        );
        let widened = budget.max(budgets[index]);
        let reserve = chunk_reserve(
            base + frame_base,
            bitmap_pools + usize::from(grows),
            widened,
        );
        if index > start
            && (index - start == QUERY_CHUNK
                || reserve > MAX_OUTPUT_WORDS
                || estimate.saturating_add(gas[index]) > CHUNK_GAS_TARGET)
        {
            plans.push(ChunkPlan {
                queries: start..index,
                budget,
                response_words: chunk_reserve(base, bitmap_pools, budget),
                gas: call_gas(estimate),
            });
            start = index;
            base = 0;
            bitmap_pools = 0;
            budget = 0;
            estimate = 0;
        }
        base += frame_base;
        bitmap_pools += usize::from(grows);
        budget = budget.max(budgets[index]);
        estimate = estimate.saturating_add(gas[index]);
    }
    plans.push(ChunkPlan {
        queries: start..queries.len(),
        budget,
        response_words: chunk_reserve(base, bitmap_pools, budget),
        gas: call_gas(estimate),
    });
    Ok(plans)
}

/// Walk one accepted response and read off every bitmap pool's real
/// initialized-tick count. Mirrors the frame layout `parse_lens` consumes; the
/// walk must land exactly on the end of the response, so a layout that ever
/// moves leaves the reserve table untouched instead of poisoning it.
fn observed_ticks(words: u16, queries: &[Query], out: &[U256]) -> Option<Vec<Option<u32>>> {
    let bitmap_words = usize::from(words) * 2 + 1;
    let mut at = 0usize;
    let mut counts = Vec::with_capacity(queries.len());
    for query in queries {
        let leading = match query.kind {
            KIND_V2 => {
                at += if out.get(at)?.is_zero() {
                    1
                } else {
                    3 + usize::from(query.flags & READ_FEE != 0)
                };
                counts.push(None);
                continue;
            }
            KIND_ALGEBRA => {
                if out.get(at)?.is_zero() {
                    at += 1;
                } else if out.get(at + 10)?.is_zero() {
                    at += 11;
                } else {
                    let down = usize::try_from(*out.get(at + 11)?).ok()?;
                    let up_at = at + 12 + down * 2;
                    let up = usize::try_from(*out.get(up_at)?).ok()?;
                    at = up_at + 1 + up * 2;
                }
                counts.push(None);
                continue;
            }
            KIND_V4 => 3,
            KIND_V3 => {
                if out.get(at)?.is_zero() {
                    at += 1;
                    counts.push(None);
                    continue;
                }
                5 + usize::from(query.flags & READ_FEE != 0)
                    + usize::from(query.flags & READ_SPACING != 0)
            }
            _ => return None,
        };
        let live = !out.get(at + leading - 1)?.is_zero();
        at += leading;
        if !live {
            counts.push(Some(0));
            continue;
        }
        let ticks: u32 = out
            .get(at..at + bitmap_words)?
            .iter()
            .map(|word| word.count_ones() as u32)
            .sum();
        at += bitmap_words + ticks as usize;
        counts.push(Some(ticks));
    }
    (at == out.len()).then_some(counts)
}

fn record_observed(words: u16, queries: &[Query], out: &[U256]) {
    let Some(counts) = observed_ticks(words, queries, out) else {
        return;
    };
    for (query, ticks) in queries.iter().zip(counts) {
        if let Some(ticks) = ticks {
            learn(words, query, ticks);
        }
    }
}

/// The count QuoteLens said it needed, and the pool it needed it for.
fn rejected_tick_budget(error: &anyhow::Error) -> Option<(Address, u32)> {
    let data = error.downcast_ref::<RevertData>()?;
    let reported = TickBudgetExceeded::abi_decode(&data.0).ok()?;
    Some((reported.pool, u32::try_from(reported.initialized).ok()?))
}

/// Attribute a reported count to its query. V4 queries all address the same
/// PoolManager, so a chunk holding more than one of them cannot be attributed
/// from the revert alone — the accepted retry measures them exactly instead.
fn note_reported(words: u16, queries: &[Query], pool: Address, initialized: u32) {
    let mut matched = queries.iter().filter(|query| query.target == pool);
    if let (Some(query), None) = (matched.next(), matched.next()) {
        learn(words, query, initialized);
    }
}

/// The reserve that would admit `initialized`, when one response can still
/// hold it for every query in this chunk.
fn raised_budget(words: u16, queries: &[Query], initialized: u32) -> anyhow::Result<Option<u16>> {
    let mut base = 0usize;
    let mut bitmap_pools = 0usize;
    for query in queries {
        base += query_response_words_with_tick_budget(words, query, 0)?;
        bitmap_pools += usize::from(reserves_ticks(query));
    }
    let Ok(want) = u16::try_from(initialized) else {
        return Ok(None);
    };
    if bitmap_pools == 0 || chunk_reserve(base, bitmap_pools, want) > MAX_OUTPUT_WORDS {
        return Ok(None);
    }
    Ok(Some(want))
}

fn merge_chunk_words(chunks: Vec<Vec<U256>>) -> anyhow::Result<Vec<U256>> {
    ensure!(!chunks.is_empty(), "lens returned no chunks");
    let mut merged = Vec::with_capacity(chunks.iter().map(Vec::len).sum());
    for chunk in chunks {
        merged.extend_from_slice(&chunk);
    }
    Ok(merged)
}

async fn call_peek(
    rpc: &Rpc,
    data: Vec<u8>,
    block: BlockId,
    gas: u64,
) -> anyhow::Result<Vec<U256>> {
    let ret = rpc
        .eth_call_overridden(LENS, data, CODE.clone(), block, gas)
        .await?;
    peekCall::abi_decode_returns(&ret).context("decoding lens response")
}

/// Execute one planned chunk, and measure what it returns.
///
/// A pool whose window outgrew its reserve makes the whole injected call
/// revert. The Lens names the pool and the exact count it wanted, so recovery
/// reads that first and re-asks at the reported size; the reserve table keeps
/// it, and the next pull plans the pool correctly from the start. Bisection
/// stays for the two cases the report cannot settle — a reserve too large for
/// one response, and a rejection carrying no decodable payload — and its two
/// halves now run together under the endpoint's fan-out limit. An irreducibly
/// broken single pool still fails the complete snapshot instead of being
/// silently omitted.
///
/// A single pool that runs out of gas is asked once more at the gas
/// ceiling; its measured depth then plans the next pull's gas.
fn call_query_chunk<'a>(
    rpc: &'a Rpc,
    words: u16,
    queries: &'a [Query],
    block: BlockId,
    max_ticks_per_pool: u16,
    gas: u64,
    slots: &'a Semaphore,
) -> BoxFuture<'a, anyhow::Result<Vec<U256>>> {
    async move {
        let data = peekCall {
            words,
            maxTicksPerPool: max_ticks_per_pool,
            queries: queries.to_vec(),
        }
        .abi_encode();
        let result = {
            let _permit = slots
                .acquire()
                .await
                .expect("lens fan-out semaphore is never closed");
            call_peek(rpc, data, block, gas).await
        };
        let error = match result {
            Ok(out) => {
                record_observed(words, queries, &out);
                return Ok(out);
            }
            Err(error) if error.downcast_ref::<RpcRejected>().is_some() => error,
            Err(error) => return Err(error),
        };

        if let Some((pool, initialized)) = rejected_tick_budget(&error) {
            note_reported(words, queries, pool, initialized);
            if let Some(raised) = raised_budget(words, queries, initialized)?
                && raised > max_ticks_per_pool
            {
                return call_query_chunk(rpc, words, queries, block, raised, gas, slots).await;
            }
        }

        if queries.len() > 1 {
            let middle = queries.len() / 2;
            let (mut left, right) = futures_util::try_join!(
                call_query_chunk(
                    rpc,
                    words,
                    &queries[..middle],
                    block,
                    max_ticks_per_pool,
                    gas,
                    slots
                ),
                call_query_chunk(
                    rpc,
                    words,
                    &queries[middle..],
                    block,
                    max_ticks_per_pool,
                    gas,
                    slots
                ),
            )?;
            left.extend(right);
            return Ok(left);
        }

        if may_have_run_out_of_gas(&error) && gas < LENS_GAS_CEILING {
            return call_query_chunk(
                rpc,
                words,
                queries,
                block,
                max_ticks_per_pool,
                LENS_GAS_CEILING,
                slots,
            )
            .await;
        }
        if reserves_ticks(&queries[0]) {
            let expanded = expanded_tick_budget(words, &queries[0])?;
            if expanded > max_ticks_per_pool {
                return call_query_chunk(rpc, words, queries, block, expanded, gas, slots).await;
            }
        }
        Err(error)
    }
    .boxed()
}

/// Every state word for `queries`, read at one block.
pub async fn peek(
    rpc: &Rpc,
    words: u16,
    v3: &[V3Pool],
    v2: &[V2Pool],
    block: BlockId,
) -> anyhow::Result<PeekResult> {
    let observed_at = std::time::Instant::now();
    let canonical = rpc.canonical_block(block).await?;
    peek_pinned(rpc, words, v3, v2, canonical, observed_at).await
}

/// `peek` against a block the caller has already resolved. The indexed
/// snapshot path resolves the canonical block before it can plan anything, and
/// re-resolving it here bought a second full block download for a number the
/// EIP-1898 hash pin already fixes. `observed_at` belongs to the caller too:
/// freshness starts when the block was first seen, not when this call began.
pub async fn peek_pinned(
    rpc: &Rpc,
    words: u16,
    v3: &[V3Pool],
    v2: &[V2Pool],
    canonical: CanonicalBlock,
    observed_at: std::time::Instant,
) -> anyhow::Result<PeekResult> {
    let queries = queries(v3, v2)?;
    let budgets = queries
        .iter()
        .map(|query| planned_budget(words, query))
        .collect::<anyhow::Result<Vec<u16>>>()?;
    let gas: Vec<u64> = queries
        .iter()
        .map(|query| query_gas(words, query))
        .collect();
    let plans = query_chunks(words, &queries, &budgets, &gas)?;
    let block_id = BlockId::hash_canonical(canonical.hash);
    // The fan-out limit now covers recovery as well as the planned chunks, so
    // concurrent bisection can never outgrow what the endpoint accepts.
    let slots = Semaphore::new(rpc.concurrency());
    let calls = plans.len().max(1);
    let chunks: Vec<Vec<U256>> = stream::iter(plans.into_iter().map(|plan| {
        call_query_chunk(
            rpc,
            words,
            &queries[plan.queries],
            block_id,
            plan.budget,
            plan.gas,
            &slots,
        )
    }))
    .buffered(calls)
    .try_collect()
    .await?;
    let merged = merge_chunk_words(chunks)?;
    Ok(PeekResult {
        words: merged,
        window_words: words,
        block_number: canonical.number,
        block_timestamp: canonical.timestamp,
        block_id,
        observed_at,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        BUDGET_FLOOR, ChunkPlan, KIND_ALGEBRA, KIND_V2, KIND_V3, KIND_V4, MAX_OUTPUT_WORDS,
        MAX_TICKS_PER_POOL, QUERY_CHUNK, Query, READ_FEE, READ_SPACING, TickBudgetExceeded,
        call_query_chunk, expanded_tick_budget, merge_chunk_words, observed_ticks, peekCall,
        planned_budget, queries, query_chunks, query_response_words,
        query_response_words_with_tick_budget, record_observed, reserves_ticks,
    };
    use crate::pools::{AlgebraMeta, V2Pool, V3Pool, V3Protocol, V4Meta};
    use crate::rpc::Rpc;
    use crate::venue::VenueId;
    use alloy::eips::BlockId;
    use alloy_primitives::{
        Address, B256, U256,
        aliases::{I24, U24},
    };
    use alloy_sol_types::{SolCall, SolError};
    use axum::{Json, Router, extract::State, routing::post};
    use serde_json::{Value, json};
    use std::sync::{Arc, Mutex};
    use tokio::sync::Semaphore;

    fn query(kind: u8) -> Query {
        Query {
            kind,
            flags: 0,
            target: Address::ZERO,
            slot: B256::ZERO,
            spacing: I24::ONE,
            fee: U24::ZERO,
        }
    }

    fn v3_pool(protocol: V3Protocol, verify_pool_spacing: bool) -> V3Pool {
        V3Pool {
            protocol,
            address: Address::repeat_byte(0x11),
            token0: Address::repeat_byte(0x21),
            token1: Address::repeat_byte(0x22),
            fee_ppm: 500,
            tick_spacing: 10,
            verify_pool_spacing,
            execution: None,
            v4: None,
            algebra: None,
        }
    }

    #[test]
    fn spacing_reads_follow_adapter_configuration_not_protocol_brand() {
        let pools = [
            v3_pool(V3Protocol::PANCAKEV3, false),
            v3_pool(V3Protocol::UNIV3, true),
        ];
        let queries = queries(&pools, &[]).unwrap();
        assert_eq!(queries[0].flags & READ_SPACING, 0);
        assert_eq!(queries[1].flags & READ_SPACING, READ_SPACING);
    }

    /// Every venue by name: the ids compiled in `crate::venue`, then sushiv2
    /// and an id no build knows, both interned as a manifest interns its ids.
    fn venues() -> Vec<VenueId> {
        let compiled = [
            "univ2",
            "univ3",
            "pancakev2",
            "pancakev3",
            "univ4",
            "up33v2",
            "up33cl",
            "swaphoodv3",
            "gigadexv3",
            "sushiv3",
            "robinswapv3",
            "sheriff",
        ]
        .map(|id| VenueId::known(id).expect("a compiled id"));
        let interned = ["sushiv2", "unknownvenue"].map(|id| VenueId::intern(id).unwrap());
        [compiled.as_slice(), interned.as_slice()].concat()
    }

    /// The query every venue's pool and pair asks the Lens, with no fee
    /// state, Algebra's or V4's, and with and without a spacing check. The id
    /// alone picks Algebra's query, so sheriff asks it whatever state it
    /// carries; any other pool with V4 state asks V4's. Only up33cl's pools
    /// and up33v2's pairs read a fee, and only a checked pool its spacing.
    #[test]
    fn queries_by_venue() {
        let algebra = AlgebraMeta {
            fee_0to1_ppm: 1_100,
            fee_1to0_ppm: 1_200,
        };
        let v4 = V4Meta {
            pool_id: B256::repeat_byte(0x41),
            state_slot: B256::repeat_byte(0x42),
            native: false,
            hooks: Address::ZERO,
            swap_fee_0to1_ppm: 4_100,
            swap_fee_1to0_ppm: 4_200,
        };
        let mut v3 = Vec::new();
        let mut want_v3 = Vec::new();
        for venue in venues() {
            let id = venue.as_str();
            for verify_pool_spacing in [false, true] {
                let plain = v3_pool(venue, verify_pool_spacing);
                for (state, pool) in [
                    ("no", plain.clone()),
                    (
                        "Algebra",
                        V3Pool {
                            algebra: Some(algebra),
                            ..plain.clone()
                        },
                    ),
                    (
                        "V4",
                        V3Pool {
                            v4: Some(v4.clone()),
                            ..plain
                        },
                    ),
                ] {
                    let fee = if id == "up33cl" { READ_FEE } else { 0 };
                    let spacing = if verify_pool_spacing { READ_SPACING } else { 0 };
                    let want = match (id, state) {
                        ("sheriff", _) => (KIND_ALGEBRA, 0),
                        (_, "V4") => (KIND_V4, 0),
                        _ => (KIND_V3, fee | spacing),
                    };
                    v3.push(pool);
                    want_v3.push((state, verify_pool_spacing, want));
                }
            }
        }
        let v2: Vec<V2Pool> = venues()
            .into_iter()
            .map(|protocol| V2Pool {
                protocol,
                address: Address::repeat_byte(0x12),
                token0: Address::repeat_byte(0x21),
                token1: Address::repeat_byte(0x22),
                fee_bps: 30,
            })
            .collect();

        let asked = queries(&v3, &v2).unwrap();
        assert_eq!(asked.len(), v3.len() + v2.len());
        for ((query, pool), (state, verify_pool_spacing, want)) in
            asked.iter().zip(&v3).zip(want_v3)
        {
            assert_eq!(
                (query.kind, query.flags),
                want,
                "{} pool with {state} state, spacing checked: {verify_pool_spacing}",
                pool.protocol
            );
        }
        for (query, pair) in asked[v3.len()..].iter().zip(&v2) {
            let fee = if pair.protocol.as_str() == "up33v2" {
                READ_FEE
            } else {
                0
            };
            assert_eq!(
                (query.kind, query.flags),
                (KIND_V2, fee),
                "{} pair",
                pair.protocol
            );
        }
    }

    #[test]
    fn exceptional_single_pool_budget_covers_the_complete_default_window() {
        let query = query(KIND_V3);
        let expanded = expanded_tick_budget(16, &query).unwrap();
        assert_eq!(expanded, 33 * 256);
        assert!(expanded > MAX_TICKS_PER_POOL);
        assert!(
            query_response_words_with_tick_budget(16, &query, expanded).unwrap()
                <= MAX_OUTPUT_WORDS
        );

        // Very wide operator-configured windows remain memory bounded even
        // when every bitmap bit cannot fit in one response.
        let expanded = expanded_tick_budget(8_192, &query).unwrap();
        assert_eq!(
            query_response_words_with_tick_budget(8_192, &query, expanded).unwrap(),
            MAX_OUTPUT_WORDS
        );
    }

    #[derive(Clone, Default)]
    struct DenseRpcState {
        calls: Arc<Mutex<Vec<(usize, u16)>>>,
    }

    async fn dense_rpc(
        State(state): State<DenseRpcState>,
        Json(request): Json<Value>,
    ) -> Json<Value> {
        let input = request["params"][0]
            .get("input")
            .or_else(|| request["params"][0].get("data"))
            .and_then(Value::as_str)
            .expect("eth_call input");
        let call = peekCall::abi_decode(&crate::abi::hexbytes(input).unwrap()).unwrap();
        state
            .calls
            .lock()
            .unwrap()
            .push((call.queries.len(), call.maxTicksPerPool));
        if call.queries.len() > 1
            || (call.queries[0].target == Address::repeat_byte(0x11)
                && call.maxTicksPerPool == MAX_TICKS_PER_POOL)
        {
            return Json(json!({
                "jsonrpc": "2.0",
                "id": request["id"],
                "error": { "code": 3, "message": "TickBudgetExceeded" }
            }));
        }
        let output = vec![U256::from(call.queries[0].target.as_slice()[19])];
        Json(json!({
            "jsonrpc": "2.0",
            "id": request["id"],
            "result": format!("0x{}", alloy_primitives::hex::encode(peekCall::abi_encode_returns(&output)))
        }))
    }

    #[tokio::test]
    async fn rejected_chunk_is_bisected_and_only_the_dense_pool_expands() {
        let state = DenseRpcState::default();
        let app = Router::new()
            .route("/", post(dense_rpc))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let rpc = Rpc::connect(&format!("http://{address}")).unwrap();
        let mut dense = query(KIND_V3);
        dense.target = Address::repeat_byte(0x11);
        let mut normal = query(KIND_V3);
        normal.target = Address::repeat_byte(0x22);

        let slots = Semaphore::new(4);
        let result = call_query_chunk(
            &rpc,
            16,
            &[dense, normal],
            BlockId::latest(),
            MAX_TICKS_PER_POOL,
            super::LENS_GAS,
            &slots,
        )
        .await
        .unwrap();
        assert_eq!(result, vec![U256::from(0x11), U256::from(0x22)]);
        // The halves of a bisection now run together, so the calls form a
        // multiset rather than a sequence.
        let mut calls = state.calls.lock().unwrap().clone();
        calls.sort_unstable();
        assert_eq!(
            calls,
            vec![
                (1, MAX_TICKS_PER_POOL),
                (1, MAX_TICKS_PER_POOL),
                (1, 33 * 256),
                (2, MAX_TICKS_PER_POOL),
            ]
        );
        server.abort();
    }

    /// Gas estimates as an unmeasured pool gets them.
    fn unmeasured_gas(words: u16, queries: &[Query]) -> Vec<u64> {
        queries
            .iter()
            .map(|query| match query.kind {
                KIND_V3 | KIND_V4 => {
                    super::QUERY_BASE_GAS + (u64::from(words) * 2 + 1) * super::BITMAP_WORD_GAS
                }
                KIND_ALGEBRA => super::QUERY_BASE_GAS + u64::from(words) * 4 * super::TICK_READ_GAS,
                _ => super::QUERY_BASE_GAS,
            })
            .collect()
    }

    fn default_budgets(queries: &[Query]) -> Vec<u16> {
        queries
            .iter()
            .map(|query| {
                if reserves_ticks(query) {
                    MAX_TICKS_PER_POOL
                } else {
                    0
                }
            })
            .collect()
    }

    /// Each call a mock node saw: its query count and gas limit.
    type SeenCalls = Arc<Mutex<Vec<(usize, u64)>>>;

    /// A node that refuses any call below 30M gas, as a public endpoint
    /// refuses a deep Ethereum pool's window at the old fixed 16M.
    async fn thirsty_rpc(
        State(state): State<SeenCalls>,
        Json(request): Json<Value>,
    ) -> Json<Value> {
        let call = &request["params"][0];
        let input = call
            .get("input")
            .or_else(|| call.get("data"))
            .and_then(Value::as_str)
            .expect("eth_call input");
        let gas = u64::from_str_radix(
            call["gas"].as_str().expect("gas").trim_start_matches("0x"),
            16,
        )
        .unwrap();
        let peek = peekCall::abi_decode(&crate::abi::hexbytes(input).unwrap()).unwrap();
        state.lock().unwrap().push((peek.queries.len(), gas));
        if gas < 30_000_000 {
            return Json(json!({
                "jsonrpc": "2.0",
                "id": request["id"],
                "error": { "code": -32003, "message": "out of gas: gas required exceeds: 16000000" }
            }));
        }
        let output: Vec<U256> = peek
            .queries
            .iter()
            .map(|query| U256::from(query.target.as_slice()[19]))
            .collect();
        Json(json!({
            "jsonrpc": "2.0",
            "id": request["id"],
            "result": format!("0x{}", alloy_primitives::hex::encode(peekCall::abi_encode_returns(&output)))
        }))
    }

    /// Out of gas, a chunk is bisected like any refusal, and a lone pool is
    /// asked once more at the ceiling instead of failing the snapshot.
    #[tokio::test]
    async fn a_pool_out_of_gas_is_retried_at_the_ceiling() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let app = Router::new()
            .route("/", post(thirsty_rpc))
            .with_state(calls.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let rpc = Rpc::connect(&format!("http://{address}")).unwrap();
        let mut deep = query(KIND_V3);
        deep.target = Address::repeat_byte(0x31);
        let slots = Semaphore::new(4);
        let result = call_query_chunk(
            &rpc,
            16,
            std::slice::from_ref(&deep),
            BlockId::latest(),
            MAX_TICKS_PER_POOL,
            super::LENS_GAS,
            &slots,
        )
        .await
        .unwrap();
        assert_eq!(result, vec![U256::from(0x31)]);
        assert_eq!(
            *calls.lock().unwrap(),
            vec![(1, super::LENS_GAS), (1, super::LENS_GAS_CEILING)]
        );
        server.abort();
    }

    /// Measured depth plans the gas: a deep pool's chunk asks for what its
    /// ticks cost, and pools past the chunk target start a new call. Shallow
    /// pools keep the old 16M, 128 to a call.
    #[test]
    fn measured_depth_plans_each_calls_gas() {
        let shallow = vec![query(KIND_V3); 4];
        let plans = query_chunks(
            16,
            &shallow,
            &default_budgets(&shallow),
            &unmeasured_gas(16, &shallow),
        )
        .unwrap();
        assert_eq!(plans.len(), 1);
        assert_eq!(plans[0].gas, super::LENS_GAS);

        let deep_gas =
            super::QUERY_BASE_GAS + 33 * super::BITMAP_WORD_GAS + 1_457 * super::TICK_READ_GAS;
        let deep = vec![query(KIND_V3); 3];
        let plans = query_chunks(
            16,
            &deep,
            &default_budgets(&deep),
            &[deep_gas, deep_gas, deep_gas],
        )
        .unwrap();
        assert_eq!(
            plans
                .iter()
                .map(|plan| (plan.queries.clone(), plan.gas))
                .collect::<Vec<_>>(),
            vec![
                (0..2, super::call_gas(2 * deep_gas)),
                (2..3, super::call_gas(deep_gas)),
            ]
        );
        assert!(super::call_gas(2 * deep_gas) > super::LENS_GAS);
        assert_eq!(
            super::call_gas(super::CHUNK_GAS_TARGET),
            super::LENS_GAS_CEILING
        );
    }

    #[test]
    fn query_chunks_are_contiguous_and_keep_the_soft_query_limit() {
        assert_eq!(
            query_chunks(16, &[], &[], &[]).unwrap(),
            vec![ChunkPlan {
                queries: 0..0,
                budget: 0,
                response_words: 0,
                gas: super::LENS_GAS,
            }]
        );
        let queries = vec![query(KIND_V2); QUERY_CHUNK * 2 + 3];
        let chunks = query_chunks(
            16,
            &queries,
            &default_budgets(&queries),
            &unmeasured_gas(16, &queries),
        )
        .unwrap();
        assert_eq!(
            chunks
                .iter()
                .map(|chunk| chunk.queries.clone())
                .collect::<Vec<_>>(),
            vec![
                0..QUERY_CHUNK,
                QUERY_CHUNK..QUERY_CHUNK * 2,
                QUERY_CHUNK * 2..QUERY_CHUNK * 2 + 3
            ]
        );
        assert!(
            chunks
                .iter()
                .all(|chunk| chunk.response_words <= MAX_OUTPUT_WORDS)
        );
    }

    #[test]
    fn response_bound_covers_max_words_and_two_dense_default_queries() {
        let algebra = query(KIND_ALGEBRA);
        let queries = std::slice::from_ref(&algebra);
        let max_words = query_chunks(
            8192,
            queries,
            &default_budgets(queries),
            &unmeasured_gas(8192, queries),
        )
        .unwrap();
        assert_eq!(max_words.len(), 1);
        assert_eq!(max_words[0].response_words, MAX_OUTPUT_WORDS - 2);

        let dense = vec![query(KIND_V3), query(KIND_V3)];
        let chunks = query_chunks(
            16,
            &dense,
            &default_budgets(&dense),
            &unmeasured_gas(16, &dense),
        )
        .unwrap();
        assert_eq!(chunks.len(), 1);
        assert_eq!(
            chunks[0].response_words,
            2 * (5 + 33 + usize::from(MAX_TICKS_PER_POOL))
        );
        assert_eq!(
            query_response_words(16, &dense[0]).unwrap(),
            5 + 33 + usize::from(MAX_TICKS_PER_POOL)
        );
    }

    #[test]
    fn chunk_words_preserve_ordered_payloads() {
        let words = merge_chunk_words(vec![
            vec![U256::from(1), U256::from(2)],
            vec![U256::from(3)],
            vec![U256::from(4), U256::from(5)],
        ])
        .unwrap();
        assert_eq!(
            words,
            [1, 2, 3, 4, 5]
                .into_iter()
                .map(U256::from)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn chunk_words_reject_an_absent_chunk_plan() {
        let err = merge_chunk_words(Vec::new()).unwrap_err();
        assert_eq!(err.to_string(), "lens returned no chunks");
    }

    // ---- measured response reserve ----

    /// Bitmap words whose popcount is exactly `ticks`.
    fn bitmap_run(ticks: usize, words: usize) -> Vec<U256> {
        let mut left = ticks;
        (0..words)
            .map(|_| {
                let set = left.min(256);
                left -= set;
                match set {
                    256 => U256::MAX,
                    n => (U256::from(1u8) << n) - U256::from(1u8),
                }
            })
            .collect()
    }

    /// One query's response frame. `live` carries the initialized-tick count;
    /// `None` is a pool the Lens reports as not live.
    fn frame_for(query: &Query, words: u16, live: Option<usize>) -> Vec<U256> {
        let one = U256::from(1u8);
        let mut out = match query.kind {
            KIND_V2 => return vec![one, one, one],
            KIND_V4 => vec![one, one],
            KIND_V3 => vec![one, one, U256::ZERO, one],
            kind => panic!("no frame builder for kind {kind}"),
        };
        let Some(ticks) = live else {
            out.push(U256::ZERO);
            return out;
        };
        out.push(one);
        out.extend(bitmap_run(ticks, usize::from(words) * 2 + 1));
        out.extend(std::iter::repeat_n(U256::ZERO, ticks));
        out
    }

    fn response_for(queries: &[Query], words: u16, live: &[Option<usize>]) -> Vec<U256> {
        queries
            .iter()
            .zip(live)
            .flat_map(|(query, live)| frame_for(query, words, *live))
            .collect()
    }

    #[test]
    fn the_walk_reads_every_frame_shape_and_refuses_a_response_it_cannot_land_on() {
        let words = 16;
        let mut v4 = query(KIND_V4);
        v4.kind = KIND_V4;
        let shapes = [query(KIND_V3), v4, query(KIND_V2), query(KIND_V3)];
        let live = [Some(300), None, None, Some(0)];
        let out = response_for(&shapes, words, &live);

        assert_eq!(
            observed_ticks(words, &shapes, &out),
            Some(vec![Some(300), Some(0), None, Some(0)])
        );
        // A response the walk cannot land exactly on teaches nothing rather
        // than teaching something wrong.
        assert_eq!(observed_ticks(words, &shapes, &out[..out.len() - 1]), None);
    }

    #[derive(Clone)]
    struct ReportingRpcState {
        calls: Arc<Mutex<Vec<(usize, u16)>>>,
        dense: Address,
        needed: u32,
    }

    async fn reporting_rpc(
        State(state): State<ReportingRpcState>,
        Json(request): Json<Value>,
    ) -> Json<Value> {
        let input = request["params"][0]
            .get("input")
            .or_else(|| request["params"][0].get("data"))
            .and_then(Value::as_str)
            .expect("eth_call input");
        let call = peekCall::abi_decode(&crate::abi::hexbytes(input).unwrap()).unwrap();
        state
            .calls
            .lock()
            .unwrap()
            .push((call.queries.len(), call.maxTicksPerPool));
        let dense = call.queries.iter().find(|q| q.target == state.dense);
        if let Some(dense) = dense
            && u32::from(call.maxTicksPerPool) < state.needed
        {
            let data = TickBudgetExceeded {
                pool: dense.target,
                initialized: U256::from(state.needed),
                limit: U256::from(call.maxTicksPerPool),
            }
            .abi_encode();
            return Json(json!({
                "jsonrpc": "2.0",
                "id": request["id"],
                "error": {
                    "code": 3,
                    "message": "execution reverted",
                    "data": format!("0x{}", alloy_primitives::hex::encode(data)),
                }
            }));
        }
        let live: Vec<Option<usize>> = call
            .queries
            .iter()
            .map(|q| {
                Some(if q.target == state.dense {
                    state.needed as usize
                } else {
                    7
                })
            })
            .collect();
        let output = response_for(&call.queries, call.words, &live);
        Json(json!({
            "jsonrpc": "2.0",
            "id": request["id"],
            "result": format!("0x{}", alloy_primitives::hex::encode(peekCall::abi_encode_returns(&output)))
        }))
    }

    /// The Lens names the pool and the exact count it wanted. Answering that
    /// costs one round trip; searching for it costs a bisection per pull.
    #[tokio::test]
    async fn a_reported_reserve_is_answered_instead_of_searched_for() {
        let dense = Address::repeat_byte(0x51);
        let state = ReportingRpcState {
            calls: Arc::new(Mutex::new(Vec::new())),
            dense,
            needed: 2_000,
        };
        let app = Router::new()
            .route("/", post(reporting_rpc))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let rpc = Rpc::connect(&format!("http://{address}")).unwrap();
        let mut dense_query = query(KIND_V3);
        dense_query.target = dense;
        let mut normal = query(KIND_V3);
        normal.target = Address::repeat_byte(0x52);
        let chunk = [dense_query.clone(), normal.clone()];

        let slots = Semaphore::new(4);
        call_query_chunk(
            &rpc,
            16,
            &chunk,
            BlockId::latest(),
            MAX_TICKS_PER_POOL,
            super::LENS_GAS,
            &slots,
        )
        .await
        .unwrap();

        assert_eq!(
            *state.calls.lock().unwrap(),
            vec![(2, MAX_TICKS_PER_POOL), (2, 2_000)],
            "the chunk stays whole: one rejection, one informed retry"
        );
        // Both pools were measured by the accepted response, so the next plan
        // reserves what each one actually needs.
        assert_eq!(planned_budget(16, &dense_query).unwrap(), 2_000 + 500 + 32);
        assert_eq!(planned_budget(16, &normal).unwrap(), BUDGET_FLOOR as u16);
        server.abort();
    }

    /// Measured on BSC: the BNB/USDT route reads 147 pools. 118 are Uniswap V4
    /// pools that return three words each, and three V3 pools hold more
    /// initialized ticks than the flat reserve admits — 4,592 in the deepest.
    /// A flat 1,024 splits that into five calls AND rejects three of them.
    fn bsc_route() -> (Vec<Query>, Vec<Option<usize>>) {
        const V3_TICKS: [usize; 23] = [
            41, 0, 0, 0, 57, 4, 0, 0, 1241, 947, 295, 68, 4592, 1749, 216, 71, 5, 0, 0, 75, 84, 0,
            0,
        ];
        const V4_TICKS: [usize; 6] = [367, 77, 53, 37, 9, 2];
        let manager = Address::repeat_byte(0x9a);
        let mut queries = Vec::new();
        let mut live = Vec::new();
        for index in 0..118u32 {
            let mut q = query(KIND_V4);
            q.target = manager;
            q.slot = B256::from(U256::from(index));
            queries.push(q);
            live.push(V4_TICKS.get(index as usize).copied().or(Some(0)));
        }
        for (index, ticks) in V3_TICKS.iter().enumerate() {
            let mut q = query(KIND_V3);
            let mut bytes = [0u8; 20];
            bytes[0] = 0x9a;
            bytes[16..].copy_from_slice(&(index as u32).to_be_bytes());
            q.target = Address::from(bytes);
            queries.push(q);
            live.push(Some(*ticks));
        }
        for _ in 0..6 {
            queries.push(query(KIND_V2));
            live.push(None);
        }
        (queries, live)
    }

    #[test]
    fn a_measured_reserve_collapses_the_bsc_route_into_one_wave() {
        let words = 16;
        let (queries, live) = bsc_route();
        assert_eq!(queries.len(), 147);

        let flat = query_chunks(
            words,
            &queries,
            &default_budgets(&queries),
            &unmeasured_gas(words, &queries),
        )
        .unwrap();
        assert_eq!(
            flat.len(),
            5,
            "the flat reserve is what splits this route into five calls"
        );
        assert!(
            queries
                .iter()
                .zip(&live)
                .any(|(_, live)| live.is_some_and(|ticks| ticks > usize::from(MAX_TICKS_PER_POOL))),
            "and three of those calls hold a pool it cannot answer"
        );

        record_observed(words, &queries, &response_for(&queries, words, &live));
        let budgets = queries
            .iter()
            .map(|query| planned_budget(words, query))
            .collect::<anyhow::Result<Vec<u16>>>()
            .unwrap();
        let measured =
            query_chunks(words, &queries, &budgets, &unmeasured_gas(words, &queries)).unwrap();

        assert!(
            measured.len() <= 4,
            "measured reserve should fit the route in at most four calls, got {}",
            measured.len()
        );
        assert!(
            measured
                .iter()
                .all(|chunk| chunk.response_words <= MAX_OUTPUT_WORDS),
            "no chunk may exceed the Lens response contract"
        );
        // Every pool is still planned with room for its own window.
        for (index, query) in queries.iter().enumerate() {
            if let Some(ticks) = live[index]
                && reserves_ticks(query)
            {
                let chunk = measured
                    .iter()
                    .find(|chunk| chunk.queries.contains(&index))
                    .expect("every query belongs to a chunk");
                assert!(
                    usize::from(chunk.budget) >= ticks,
                    "pool {index} needs {ticks} ticks but is planned at {}",
                    chunk.budget
                );
            }
        }
    }
}
