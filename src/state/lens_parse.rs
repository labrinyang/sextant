use super::UpstreamIntegrityError;
use super::pool_ids::{v4_key_fee_from_slot0, v4_liquidity_net, v4_slot0, v4_swap_fee};
use super::v4_keys::V4_UNKNOWN_KEY_FEE_PPM;
use crate::abi::{untwos, word_i64};
use crate::chain::{V4_DYNAMIC_FEE_FLAG, V4_MAX_FEE_PPM};
use crate::pools::{TickInfo, V2Pool, V2State, V3Pool, V3State};
use crate::v3math::{MAX_TICK, MIN_TICK};
use crate::venue::Core;
use alloy_primitives::{Address, B256, U256};
use anyhow::{Context, ensure};
use sextant_amm::snapshot::Snapshot;

/// One Lens read of the resident pools, parsed exactly as an indexed
/// snapshot is.
pub(crate) fn parse_resident_lens(
    v3pools: &[V3Pool],
    v2pools: &[V2Pool],
    result: &crate::lens::PeekResult,
) -> anyhow::Result<Snapshot> {
    let parsed = parse_indexed_lens(v3pools, v2pools, result)?;
    ensure_integrity!(
        parsed.sheriff_plugins.is_empty(),
        "resident snapshot unexpectedly contains Algebra state"
    );
    Ok(parsed.snapshot)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct SheriffBinding {
    pub(super) index: usize,
    pub(super) plugin: Address,
    pub(super) codehash: B256,
    pub(super) last_fee: u32,
    pub(super) config: u8,
}

pub(super) struct Cur<'a> {
    pub(super) w: &'a [U256],
    pub(super) i: usize,
}

impl Cur<'_> {
    pub(super) fn take(&mut self) -> anyhow::Result<U256> {
        let v = *self.w.get(self.i).context("lens stream ended early")?;
        self.i += 1;
        Ok(v)
    }
}

pub(super) struct ParsedLens {
    pub(super) snapshot: Snapshot,
    pub(super) sheriff_plugins: Vec<SheriffBinding>,
}

pub(super) fn parse_indexed_lens(
    v3pools: &[V3Pool],
    v2pools: &[V2Pool],
    result: &crate::lens::PeekResult,
) -> anyhow::Result<ParsedLens> {
    parse_lens(v3pools, v2pools, result).map_err(|error| {
        UpstreamIntegrityError::new(format!(
            "indexed EVM Lens response failed validation: {error:#}"
        ))
        .into()
    })
}

/// Rebuild the snapshot from the lens word stream (layout: src/lens.rs).
/// The validation ladder and its prints mirror what the multicall R3 rounds
/// enforced; the lens gated the window fetch on the same conditions, so the
/// stream stays aligned — the trailing-words check would expose any skew.
pub(super) fn parse_lens(
    v3pools: &[V3Pool],
    v2pools: &[V2Pool],
    result: &crate::lens::PeekResult,
) -> anyhow::Result<ParsedLens> {
    let words = &result.words;
    let mask128 = (U256::from(1u8) << 128usize) - U256::from(1u8);
    let mut cur = Cur { w: words, i: 0 };
    let blk = result.block_number;
    // The profile-aware caller fills this after parsing. Quote-only profiles
    // can later leave execution identity absent without changing Lens layout.
    let settler = None;

    let mut v3: Vec<(V3Pool, V3State)> = Vec::new();
    let mut sheriff_plugins = Vec::new();
    let mut v4_empty = 0usize;
    let mut v4_policy_dropped = 0usize;
    for p in v3pools {
        if p.protocol.core() == Core::Algebra {
            if cur.take()?.is_zero() {
                tracing::info!(
                    "snapshot: Sheriff pool {:#x} dropped (state call reverted)",
                    p.address
                );
                continue;
            }
            let sqrtp = cur.take()?;
            let tick = i32::try_from(word_i64(cur.take()?)?).context("tick out of range")?;
            let liquidity = cur.take()?;
            let fee_ppm = u32::try_from(cur.take()?).context("Algebra base fee out of range")?;
            let last_fee = u32::try_from(cur.take()?).context("Algebra last fee out of range")?;
            let plugin_config =
                u8::try_from(cur.take()?).context("Algebra plugin config out of range")?;
            let tick_spacing =
                i32::try_from(word_i64(cur.take()?)?).context("tickSpacing out of range")?;
            let plugin = Address::from_word(cur.take()?.into());
            let plugin_codehash = B256::from(cur.take()?);
            ensure!(
                fee_ppm < 1_000_000,
                "pool {:#x} reports invalid base fee",
                p.address
            );
            ensure!(
                last_fee < 1_000_000,
                "pool {:#x} reports invalid last fee",
                p.address
            );
            ensure!(
                tick_spacing > 0,
                "pool {:#x} reports nonpositive tickSpacing",
                p.address
            );
            if cur.take()?.is_zero() {
                continue; // uninitialized pool (sqrt == 0)
            }

            let down =
                usize::try_from(cur.take()?).context("Algebra down tick count out of range")?;
            let mut infos = Vec::with_capacity(down);
            for _ in 0..down {
                let t =
                    i32::try_from(word_i64(cur.take()?)?).context("Algebra tick out of range")?;
                infos.push(TickInfo {
                    tick: t,
                    liquidity_net: untwos(cur.take()?),
                });
            }
            let up = usize::try_from(cur.take()?).context("Algebra up tick count out of range")?;
            infos.reserve(up);
            for _ in 0..up {
                let t =
                    i32::try_from(word_i64(cur.take()?)?).context("Algebra tick out of range")?;
                infos.push(TickInfo {
                    tick: t,
                    liquidity_net: untwos(cur.take()?),
                });
            }
            if infos.is_empty() {
                tracing::info!(
                    "snapshot: Sheriff pool {:#x} dropped (no tick coverage)",
                    p.address
                );
                continue;
            }
            ensure!(
                infos.windows(2).all(|w| w[0].tick < w[1].tick),
                "Algebra ticks are not strictly ascending"
            );
            let pos = infos.partition_point(|x| x.tick <= tick);
            let lo = infos.first().expect("checked nonempty").tick.max(MIN_TICK);
            let hi = infos.last().expect("checked nonempty").tick.min(MAX_TICK);
            let pool = V3Pool {
                fee_ppm,
                tick_spacing,
                ..p.clone()
            };
            sheriff_plugins.push(SheriffBinding {
                index: v3.len(),
                plugin,
                codehash: plugin_codehash,
                last_fee,
                config: plugin_config,
            });
            v3.push((
                pool,
                V3State {
                    sqrt_price: sqrtp,
                    tick,
                    liquidity,
                    ticks: infos.into(),
                    pos,
                    lo_cover: lo,
                    hi_cover: hi,
                },
            ));
            continue;
        }
        let (pool, sqrtp, tick, liquidity, drop_pool) = if p.v4.is_some() {
            let (sqrtp, tick, protocol_fee, lp_fee) = v4_slot0(cur.take()?);
            let liquidity = cur.take()? & mask128;
            if cur.take()?.is_zero() {
                if sqrtp.is_zero() {
                    // uninitialized
                } else {
                    // Event enumeration surfaces every pool ever initialized;
                    // culling on zero in-range liquidity keeps the drained
                    // ones in the cached topology (they revive when someone
                    // LPs again) but out of the per-quote window fetch.
                    // Casualty: pools holding ONLY out-of-range one-sided
                    // ranges — rare against ~60 drained spam pools per pair.
                    v4_empty += 1;
                }
                continue;
            }
            // Fee facts are decided HERE, not in the lens: slot0 is already
            // in the stream, and Rust is where the invariants can be named.
            let mut pool = p.clone();
            let mut drop_pool = false;
            let key_fee = if p.fee_ppm == V4_UNKNOWN_KEY_FEE_PPM {
                match v4_key_fee_from_slot0(p, lp_fee) {
                    Some(fee) => Some(fee),
                    None => {
                        // Historical Graph rows intentionally carry no trusted
                        // PoolKey fee. A pinned slot0 must prove either its static
                        // LP fee or the dynamic flag back to the indexed PoolId.
                        drop_pool = true;
                        None
                    }
                }
            } else {
                Some(p.fee_ppm)
            };
            if let Some(key_fee) = key_fee {
                pool.fee_ppm = key_fee;
                let dynamic = key_fee == V4_DYNAMIC_FEE_FLAG;
                if dynamic {
                    // slot0 holds the live dynamic fee. Nothing can override it
                    // per-swap (beforeSwap hooks are excluded at discovery), so
                    // it is exact at this block; the spam cap still applies.
                    if lp_fee > V4_MAX_FEE_PPM {
                        drop_pool = true;
                    }
                } else if key_fee > V4_MAX_FEE_PPM {
                    drop_pool = true;
                } else if lp_fee != key_fee {
                    // static pools can never legally diverge — layout-drift guard
                    drop_pool = true;
                }

                // ProtocolFeeLibrary packing: lower 12 bits charge 0→1, upper 1→0,
                // each capped on-chain at 1000 pips (isValidProtocolFee).
                let pf_0to1 = protocol_fee & 0xfff;
                let pf_1to0 = protocol_fee >> 12;
                if pf_0to1 > 1000 || pf_1to0 > 1000 {
                    drop_pool = true;
                }
                if !drop_pool {
                    let meta = pool.v4.as_mut().expect("v4 meta cloned with pool");
                    meta.swap_fee_0to1_ppm = v4_swap_fee(pf_0to1, lp_fee)?;
                    meta.swap_fee_1to0_ppm = v4_swap_fee(pf_1to0, lp_fee)?;
                }
            }
            (pool, sqrtp, tick, liquidity, drop_pool)
        } else {
            if cur.take()?.is_zero() {
                tracing::info!(
                    "snapshot: v3 pool {:#x} dropped (state call reverted)",
                    p.address
                );
                continue;
            }
            let sqrtp = cur.take()?;
            let tickw = cur.take()?;
            let liquidity = cur.take()?;
            let fee_ppm = if p.protocol.core() == Core::Up33Cl {
                u32::try_from(cur.take()?).map_err(|_| anyhow::anyhow!("fee out of range"))?
            } else {
                p.fee_ppm
            };
            let tick_spacing = if p.verify_pool_spacing {
                let ts =
                    i32::try_from(word_i64(cur.take()?)?).context("tickSpacing out of range")?;
                ensure!(
                    ts > 0,
                    "pool {:#x} reports nonpositive tickSpacing",
                    p.address
                );
                if p.execution.is_none() && p.tick_spacing > 0 {
                    ensure!(
                        ts == p.tick_spacing,
                        "pool {:#x} tickSpacing changed after factory validation",
                        p.address
                    );
                }
                ts
            } else {
                p.tick_spacing
            };
            if cur.take()?.is_zero() {
                continue; // uninitialized pool (sqrt == 0)
            }
            let tick = i32::try_from(word_i64(tickw)?).context("tick out of range")?;
            (
                V3Pool {
                    fee_ppm,
                    tick_spacing,
                    ..p.clone()
                },
                sqrtp,
                tick,
                liquidity,
                false,
            )
        };
        let wc = tick.div_euclid(pool.tick_spacing).div_euclid(256);
        let window = i32::from(result.window_words);
        let span = (wc - window)..=(wc + window);
        let mut at: Vec<i32> = Vec::new();
        for w in span.clone() {
            let bm = cur.take()?;
            for bit in 0..256usize {
                if bm.bit(bit) {
                    at.push((w * 256 + bit as i32) * pool.tick_spacing);
                }
            }
        }
        let mut infos: Vec<TickInfo> = Vec::with_capacity(at.len());
        for t in at {
            let w = cur.take()?;
            let net = match &pool.v4 {
                Some(_) => v4_liquidity_net(w), // packed: net in the high half
                None => untwos(w),              // the sign-extended ABI word
            };
            infos.push(TickInfo {
                tick: t,
                liquidity_net: net,
            });
        }
        if drop_pool {
            v4_policy_dropped += 1;
            continue;
        }
        if infos.is_empty() && liquidity.is_zero() {
            continue; // dead pool
        }
        let pos = infos.partition_point(|x| x.tick <= tick);
        let lo = (*span.start() * 256 * pool.tick_spacing).max(MIN_TICK);
        let hi = (((*span.end() + 1) * 256 - 1) * pool.tick_spacing).min(MAX_TICK);
        v3.push((
            pool,
            V3State {
                sqrt_price: sqrtp,
                tick,
                liquidity,
                ticks: infos.into(),
                pos,
                lo_cover: lo,
                hi_cover: hi,
            },
        ));
    }
    if v4_empty > 0 {
        tracing::info!("snapshot: {v4_empty} v4 pools skipped (zero in-range liquidity)");
    }
    if v4_policy_dropped > 0 {
        tracing::info!("snapshot: {v4_policy_dropped} v4 pools skipped (fee or PoolKey policy)");
    }

    let mut v2: Vec<(V2Pool, V2State)> = Vec::new();
    for p in v2pools {
        if cur.take()?.is_zero() {
            tracing::info!(
                "snapshot: v2 pool {:#x} dropped (state call reverted)",
                p.address
            );
            continue;
        }
        let (r0, r1) = (cur.take()?, cur.take()?);
        let pool = if p.protocol.core() == Core::Up33V2 {
            let fee =
                u32::try_from(cur.take()?).map_err(|_| anyhow::anyhow!("fee out of range"))?;
            V2Pool {
                fee_bps: fee,
                ..p.clone()
            }
        } else {
            p.clone()
        };
        if r0.is_zero() || r1.is_zero() {
            continue;
        }
        v2.push((
            pool,
            V2State {
                reserve0: r0,
                reserve1: r1,
            },
        ));
    }
    ensure!(
        cur.i == words.len(),
        "lens stream has {} trailing words",
        words.len() - cur.i
    );
    Ok(ParsedLens {
        snapshot: Snapshot {
            block: blk,
            settler,
            v3,
            v2,
            ekubo: Vec::new(),
        },
        sheriff_plugins,
    })
}
