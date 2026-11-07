// Pool models + exact local simulators.

use crate::depth::{DepthKey, DepthWalk, Ladder};
use crate::v3math::{
    MAX_TICK, MIN_TICK, compute_swap_step, sqrt_limit, sqrt_ratio_at_tick, tick_at_sqrt,
    tick_at_sqrt_range, widen,
};
use crate::venue::Core;
use alloy_primitives::{Address, I256, U256};
use anyhow::{Context, bail, ensure};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

/// A V3-family pool's venue (`crate::venue::VenueId`).
pub type V3Protocol = crate::venue::VenueId;

/// Algebra Integral (Sheriff) specifics. The concentrated-liquidity math is the
/// untouched v3 math; only two things differ, and both live here.
///
/// `fee_0to1_ppm` / `fee_1to0_ppm` are the effective fees returned by the
/// plugin's `beforeSwap` for the next swap in each direction. The pool's
/// `fee()` is only the base, and stored fee factors may be stale because
/// `beforeSwap` recalculates them from the current and oracle ticks.
///
/// These values are valid for one swap only. Execution plans must not reuse a
/// Sheriff pool until the plugin's post-swap state is modeled as well.
///
/// Initialized ticks come from the pool's prev/next LINKED LIST rather than a
/// bitmap, so `V3State.ticks` holds exactly the initialized ticks and the swap
/// loop jumps straight to the neighbour — see `next_boundary`.
#[derive(Clone, Copy, Debug)]
pub struct AlgebraMeta {
    pub fee_0to1_ppm: u32,
    pub fee_1to0_ppm: u32,
}

/// Uniswap V4 pool identity: the PoolKey hash and its precomputed state slot
/// inside PoolManager storage. The concentrated-liquidity math is untouched —
/// only where the state lives and how the swap is encoded differ.
/// `native` marks a (currency0 = ETH) pool routed as a WETH pair: the encoder
/// unwraps the sell slice (or wraps the bought ETH back) around the action —
/// both 1:1 conversions, so quote exactness is unaffected.
#[derive(Clone, Debug)]
pub struct V4Meta {
    pub pool_id: alloy_primitives::B256,
    pub state_slot: alloy_primitives::B256,
    pub native: bool,
    /// PoolKey.hooks — part of the pool id and of the settler fill. Only
    /// swap-transparent hooks are admitted (V4_SWAP_HOOK_FLAGS all clear).
    pub hooks: Address,
    /// Effective swap fee per direction, Pool.sol:307 of the deployed
    /// PoolManager: the directional protocol fee folded into the lpFee.
    /// Snapshot parsing sets both from slot0; until then they poison loudly
    /// (> 100%) so a pre-snapshot read cannot silently under-fee a sim.
    pub swap_fee_0to1_ppm: u32,
    pub swap_fee_1to0_ppm: u32,
}

/// Settler-specific identity for a concentrated-liquidity pool. Quote state
/// and local simulation do not need this metadata; only transaction encoding
/// does. Keeping it optional lets quote-only chain profiles admit pools before
/// their execution adapter is available, without inventing fork/pool id zeroes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct V3ExecutionMeta {
    pub fork_id: u8,
    pub pool_id: u32,
}

#[derive(Clone, Debug)]
pub struct V3Pool {
    pub protocol: V3Protocol,
    /// Pool contract; for Univ4 this is the PoolManager (the eth_call target).
    pub address: Address,
    pub token0: Address,
    pub token1: Address,
    /// Fee charged on input, ppm. For Sheriff this is the plugin's BASE fee —
    /// never what a swap pays; use `fee_ppm_for`.
    pub fee_ppm: u32,
    pub tick_spacing: i32,
    /// QuoteLens must re-read the pool's immutable tick spacing and the parser
    /// must bind it to `tick_spacing`. This is adapter behavior, not a DEX-name
    /// heuristic, so another compatible deployment can select it declaratively.
    pub verify_pool_spacing: bool,
    /// 0x Settler univ3-fork path identity. V4 uses its own action and leaves
    /// this absent; quote-only V3 candidates may also omit it.
    pub execution: Option<V3ExecutionMeta>,
    pub v4: Option<V4Meta>,
    pub algebra: Option<AlgebraMeta>,
}

impl V3Pool {
    /// The market fee charged on swap-loop input in `zero_for_one`.
    /// Algebra differs per side (plugin fee), and so does V4 (directional
    /// protocol fee folded into the lpFee); every other family charges
    /// `fee_ppm` both ways.
    /// V4's `fee_ppm` stays the PoolKey fee — the settler fill and the pool id
    /// need it — and must never price a sim, so this is the only fee seam.
    pub fn fee_ppm_for(&self, zero_for_one: bool) -> anyhow::Result<u32> {
        if let Some(v4) = &self.v4 {
            ensure!(
                self.protocol.core() == Core::UniV4,
                "v4 state attached to non-Univ4 pool"
            );
            return Ok(if zero_for_one {
                v4.swap_fee_0to1_ppm
            } else {
                v4.swap_fee_1to0_ppm
            });
        }
        match (self.protocol.core(), &self.algebra) {
            (Core::UniV4, None) => bail!("Univ4 pool is missing its V4Meta"),
            (Core::Algebra, Some(a)) if zero_for_one => Ok(a.fee_0to1_ppm),
            (Core::Algebra, Some(a)) => Ok(a.fee_1to0_ppm),
            (Core::Algebra, None) => bail!("Sheriff pool is missing beforeSwap fee state"),
            (_, Some(_)) => bail!("Algebra fee state attached to non-Sheriff pool"),
            (_, None) => Ok(self.fee_ppm),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct TickInfo {
    pub tick: i32,
    pub liquidity_net: I256,
}

/// A pool's initialized ticks, ascending and immutable after the snapshot,
/// with each tick's √P computed on first use and kept for every clone.
///
/// A routing walk and every certificate bound cross the same ticks again
/// and again at one block, and `sqrt_ratio_at_tick` is the costliest step
/// of a crossing. Nothing is allocated until a walk first needs a price, so
/// reading a block's state costs no more than it did.
#[derive(Clone)]
pub struct Ticks {
    list: Arc<[TickInfo]>,
    memo: Arc<TickMemo>,
}

/// What walks over one tick list have computed, shared by every clone.
#[derive(Default)]
struct TickMemo {
    sqrt: OnceLock<Box<[OnceLock<U256>]>>,
    /// Depth ladders (`crate::depth`), per walk start and direction, most
    /// recently built last. A block's state and a few states traded on from
    /// it share a list; more starts than that evict the oldest.
    depth: Mutex<Vec<(DepthKey, [Option<Ladder>; 2])>>,
}

/// Walk starts whose ladders a tick list keeps.
const DEPTH_STARTS: usize = 4;

impl Ticks {
    /// √P at `ticks[index]`, as `sqrt_ratio_at_tick` gives it.
    pub fn sqrt_price(&self, index: usize) -> anyhow::Result<U256> {
        let cache = self.memo.sqrt.get_or_init(|| {
            std::iter::repeat_with(OnceLock::new)
                .take(self.list.len())
                .collect()
        });
        let slot = cache.get(index).context("tick index out of range")?;
        if let Some(sqrt) = slot.get() {
            return Ok(*sqrt);
        }
        let sqrt = sqrt_ratio_at_tick(self.list[index].tick)?;
        Ok(*slot.get_or_init(|| sqrt))
    }

    fn depth_walk(
        &self,
        state: &V3State,
        zero_for_one: bool,
        go: impl FnMut(U256) -> anyhow::Result<bool>,
        enough: impl FnMut(U256, U256) -> anyhow::Result<bool>,
    ) -> anyhow::Result<Option<DepthWalk>> {
        let key = DepthKey::of(state);
        // A panic inside `go` leaves every ladder whole: a step is published
        // only once it is complete.
        let mut memo = self
            .memo
            .depth
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let index = match memo.iter().position(|(start, _)| *start == key) {
            Some(index) => index,
            None => {
                if memo.len() == DEPTH_STARTS {
                    memo.remove(0);
                }
                memo.push((key, [None, None]));
                memo.len() - 1
            }
        };
        memo[index].1[usize::from(zero_for_one)]
            .get_or_insert_with(|| Ladder::new(state))
            .walk(state, zero_for_one, go, enough)
    }
}

impl std::ops::Deref for Ticks {
    type Target = [TickInfo];

    fn deref(&self) -> &[TickInfo] {
        &self.list
    }
}

impl From<Arc<[TickInfo]>> for Ticks {
    fn from(list: Arc<[TickInfo]>) -> Self {
        Self {
            list,
            memo: Arc::default(),
        }
    }
}

impl From<Vec<TickInfo>> for Ticks {
    fn from(list: Vec<TickInfo>) -> Self {
        Arc::<[TickInfo]>::from(list).into()
    }
}

impl std::fmt::Debug for Ticks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.list.fmt(f)
    }
}

#[derive(Clone, Debug)]
pub struct V3State {
    pub sqrt_price: U256,
    pub tick: i32,
    pub liquidity: U256,
    pub ticks: Ticks,  // ascending, immutable after snapshot
    pub pos: usize,    // ticks[pos] is the first initialized tick above the current tick
    pub lo_cover: i32, // tick range the snapshot actually covers
    pub hi_cover: i32,
}

impl V3State {
    /// Walk the curve from this state's price while `go(stop)` holds at each
    /// stop (each initialized tick, then the coverage wall), summing the
    /// curve amounts of the ranges walked whole. `go` must be monotone along
    /// the walk. Repeated walks of one state reuse what earlier walks built.
    ///
    /// `enough(out_up, in_down)` is asked with the totals at each step the
    /// walk has to build; a true answer ends the walk with `None`.
    pub fn depth_walk(
        &self,
        zero_for_one: bool,
        go: impl FnMut(U256) -> anyhow::Result<bool>,
        enough: impl FnMut(U256, U256) -> anyhow::Result<bool>,
    ) -> anyhow::Result<Option<DepthWalk>> {
        self.ticks.depth_walk(self, zero_for_one, go, enough)
    }
}

/// A V2-family pool's venue (`crate::venue::VenueId`).
pub type V2Protocol = crate::venue::VenueId;

#[derive(Clone, Debug)]
pub struct V2Pool {
    pub protocol: V2Protocol,
    pub address: Address,
    pub token0: Address,
    pub token1: Address,
    pub fee_bps: u32,
}

#[derive(Clone, Debug)]
pub struct V2State {
    pub reserve0: U256,
    pub reserve1: U256,
}

// ---- V3 tick-walk (exact input) ----

#[derive(Clone, Debug)]
pub struct V3Sim {
    pub amount_out: U256,
    pub consumed: U256, // < amount_in when the modeled depth is exhausted
    pub fee_amount: U256,
    pub sqrt_price: U256,
    pub tick: SimTick,
    pub liquidity: U256,
    pub pos: usize,
}

/// The tick a simulation ends at. A swap that ends between initialized
/// boundaries has only its sqrt price; `tick_at_sqrt` is then computed when
/// the state is committed, if it is committed at all. Most simulations (the
/// greedy scans, discarded probes, polish candidates) never commit, and the
/// tick was a quarter of their cost.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SimTick {
    Known(i32),
    AtSqrtPrice,
}

impl SimTick {
    pub fn resolve(self, sqrt_price: U256) -> anyhow::Result<i32> {
        match self {
            Self::Known(tick) => Ok(tick),
            Self::AtSqrtPrice => tick_at_sqrt(sqrt_price),
        }
    }
}

pub fn cross_liquidity(l: U256, net: I256, down: bool) -> anyhow::Result<U256> {
    let d = if down { net.wrapping_neg() } else { net };
    if d >= I256::ZERO {
        Ok(l + d.into_raw())
    } else {
        let u = d.wrapping_neg().into_raw();
        if u > l {
            bail!("tick data inconsistent: negative liquidity");
        }
        Ok(l - u)
    }
}

/// Algebra keeps a prev/next linked list of initialized ticks, so its swap loop
/// jumps STRAIGHT to the neighbour — none of the bitmap word-edge stops below
/// exist there. Taking them anyway would round the output down once per extra
/// step, which is exactly the parity failure the tests/port.rs test
/// sheriff_linked_list_walk_skips_bitmap_word_edges pins.
fn algebra_boundary(s: &V3State, zero_for_one: bool, pos: usize) -> (i32, bool) {
    if zero_for_one {
        if pos > 0 {
            (s.ticks[pos - 1].tick, true)
        } else {
            (MIN_TICK, false)
        }
    } else if pos < s.ticks.len() {
        (s.ticks[pos].tick, true)
    } else {
        (MAX_TICK, false)
    }
}

/// Next swap-step boundary exactly as TickBitmap.nextInitializedTickWithinOneWord
/// sees it: the nearest initialized tick, but never further than the edge of the
/// current 256-slot bitmap word. The word-edge stops matter — every extra
/// computeSwapStep rounds output down, and the on-chain loop takes them.
fn next_boundary(
    s: &V3State,
    spacing: i32,
    tick: i32,
    zero_for_one: bool,
    pos: usize,
) -> (i32, bool) {
    if zero_for_one {
        let compressed = tick.div_euclid(spacing);
        let word_floor = compressed.div_euclid(256) * 256 * spacing;
        let cand = if pos > 0 {
            s.ticks[pos - 1].tick
        } else {
            i32::MIN
        };
        if cand >= word_floor {
            (cand, true)
        } else {
            (word_floor, false)
        }
    } else {
        let compressed = tick.div_euclid(spacing) + 1;
        let word_ceil = (compressed.div_euclid(256) * 256 + 255) * spacing;
        let cand = if pos < s.ticks.len() {
            s.ticks[pos].tick
        } else {
            i32::MAX
        };
        if cand <= word_ceil {
            (cand, true)
        } else {
            (word_ceil, false)
        }
    }
}

/// Exact-input swap simulation, mirroring UniswapV3Pool.swap's loop step by step
/// (word-bounded targets, per-step rounding, MIN/MAX price limits).
/// Stops early (consumed < amount_in) when the pool runs dry or the walk leaves
/// the snapshotted tick window — the pool then has no modeled depth left and a
/// route must not push more input through it.
pub fn sim_v3(
    p: &V3Pool,
    s: &V3State,
    zero_for_one: bool,
    amount_in: U256,
) -> anyhow::Result<V3Sim> {
    let mut remaining = amount_in;
    let mut out = U256::ZERO;
    let mut fee_amount = U256::ZERO;
    let (mut sqrt_p, mut tick, mut l, mut pos) = (s.sqrt_price, s.tick, s.liquidity, s.pos);
    // Set when the walk ends between boundaries; `tick` then stays stale but
    // the loop is about to exit, so nothing reads it.
    let mut end_tick = None;
    let limit = sqrt_limit(zero_for_one);
    // Algebra charges per side and never stops at a bitmap word edge; both are
    // fixed for the whole swap because the pool resolves the fee once, in
    // beforeSwap, before any step runs.
    let fee_ppm = p.fee_ppm_for(zero_for_one)?;
    let algebra = p.protocol.core() == Core::Algebra;
    while !remaining.is_zero() && sqrt_p != limit {
        let (raw_boundary, initialized) = if algebra {
            algebra_boundary(s, zero_for_one, pos)
        } else {
            next_boundary(s, p.tick_spacing, tick, zero_for_one, pos)
        };
        let boundary = raw_boundary.clamp(MIN_TICK, MAX_TICK);
        if zero_for_one && boundary < s.lo_cover || !zero_for_one && boundary > s.hi_cover {
            break;
        }
        let boundary_ratio = match (initialized, zero_for_one) {
            // An initialized boundary is the neighbouring tick: its price is
            // cached on the tick list.
            (true, true) if s.ticks[pos - 1].tick == boundary => s.ticks.sqrt_price(pos - 1)?,
            (true, false) if s.ticks[pos].tick == boundary => s.ticks.sqrt_price(pos)?,
            _ => sqrt_ratio_at_tick(boundary)?,
        };
        let target = if zero_for_one {
            boundary_ratio.max(limit)
        } else {
            boundary_ratio.min(limit)
        };
        let (sqrt_next, step_in, step_out, step_fee) =
            compute_swap_step(sqrt_p, target, l, remaining, fee_ppm)?;
        remaining = remaining
            .checked_sub(step_in + step_fee)
            .context("swap step consumed more than remaining")?;
        out += step_out;
        fee_amount += step_fee;
        if sqrt_next == boundary_ratio {
            if initialized {
                let net = if zero_for_one {
                    s.ticks[pos - 1].liquidity_net
                } else {
                    s.ticks[pos].liquidity_net
                };
                l = cross_liquidity(l, net, zero_for_one)?;
                if zero_for_one {
                    pos -= 1;
                } else {
                    pos += 1;
                }
            }
            tick = if zero_for_one { boundary - 1 } else { boundary };
        } else if sqrt_next != sqrt_p {
            if remaining.is_zero() {
                // The step consumed the input, so the loop exits; the tick is
                // resolved only if this state is committed.
                tick_at_sqrt_range(sqrt_next)?;
                end_tick = Some(SimTick::AtSqrtPrice);
            } else {
                tick = tick_at_sqrt(sqrt_next)?;
            }
        }
        sqrt_p = sqrt_next;
    }
    Ok(V3Sim {
        amount_out: out,
        consumed: amount_in - remaining,
        fee_amount,
        sqrt_price: sqrt_p,
        tick: end_tick.unwrap_or(SimTick::Known(tick)),
        liquidity: l,
        pos,
    })
}

pub fn commit_v3(s: &mut V3State, r: &V3Sim) {
    s.sqrt_price = r.sqrt_price;
    s.tick = r
        .tick
        .resolve(r.sqrt_price)
        .expect("sim_v3 checked the sqrt price range");
    s.liquidity = r.liquidity;
    s.pos = r.pos;
}

// ---- V2 constant product ----

#[derive(Clone, Debug)]
pub struct V2Sim {
    pub amount_out: U256,
    pub reserve0: U256,
    pub reserve1: U256,
}

/// The on-chain formula in 0x-settler core/UniswapV2.sol (bps-denominated
/// fee). Evaluated in 512 bits — exactly the same quotient, but immune to the
/// U256 overflow the Julia original would hit (and silently wrap) on absurd
/// amount_in.
pub fn sim_v2(
    p: &V2Pool,
    s: &V2State,
    zero_for_one: bool,
    amount_in: U256,
) -> anyhow::Result<V2Sim> {
    let (rin, rout) = if zero_for_one {
        (s.reserve0, s.reserve1)
    } else {
        (s.reserve1, s.reserve0)
    };
    let xf = widen(amount_in) * widen(U256::from(10_000 - p.fee_bps));
    let out_wide = xf * widen(rout) / (xf + widen(rin) * widen(U256::from(10_000u32)));
    let out = U256::from_limbs(out_wide.as_limbs()[..4].try_into().expect("out <= rout")); // out < rout < 2^256
    let (r0, r1) = if zero_for_one {
        (
            s.reserve0
                .checked_add(amount_in)
                .context("v2 reserve overflow")?,
            s.reserve1 - out,
        )
    } else {
        (
            s.reserve0 - out,
            s.reserve1
                .checked_add(amount_in)
                .context("v2 reserve overflow")?,
        )
    };
    Ok(V2Sim {
        amount_out: out,
        reserve0: r0,
        reserve1: r1,
    })
}

pub fn commit_v2(s: &mut V2State, r: &V2Sim) {
    s.reserve0 = r.reserve0;
    s.reserve1 = r.reserve1;
}

#[cfg(test)]
mod tests {
    use super::{AlgebraMeta, V3Pool, V4Meta};
    use crate::venue::VenueId;
    use alloy_primitives::{Address, B256};

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

    /// What every venue's pool charges a swap in each direction with no fee
    /// state, with Algebra's and with V4's: its fee both ways, each side's
    /// own fee, or a refusal. V4 state is univ4's alone and univ4 cannot
    /// price without it; Algebra state is sheriff's alone and sheriff cannot
    /// price without it.
    #[test]
    fn fee_ppm_for_by_venue() {
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
        let refused = [None; 2];
        for venue in venues() {
            let plain = V3Pool {
                protocol: venue,
                address: Address::repeat_byte(0x11),
                token0: Address::repeat_byte(0x21),
                token1: Address::repeat_byte(0x22),
                fee_ppm: 3_000,
                tick_spacing: 60,
                verify_pool_spacing: false,
                execution: None,
                v4: None,
                algebra: None,
            };
            let with_algebra = V3Pool {
                algebra: Some(algebra),
                ..plain.clone()
            };
            let with_v4 = V3Pool {
                v4: Some(v4.clone()),
                ..plain.clone()
            };
            let (want_plain, want_algebra, want_v4) = match venue.as_str() {
                "univ4" => (refused, refused, [Some(4_100), Some(4_200)]),
                "sheriff" => (refused, [Some(1_100), Some(1_200)], refused),
                _ => ([Some(3_000); 2], refused, refused),
            };
            for (state, pool, want) in [
                ("no fee state", plain, want_plain),
                ("Algebra fee state", with_algebra, want_algebra),
                ("V4 state", with_v4, want_v4),
            ] {
                let charged = [true, false].map(|zero_for_one| pool.fee_ppm_for(zero_for_one).ok());
                assert_eq!(charged, want, "{venue} with {state}");
            }
        }
    }
}
