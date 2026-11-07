//! How far a V3 state's price can walk, one direction at a time, with the
//! curve amounts summed range by range.
//!
//! A certificate bound walks every pool from its price until trading stops
//! paying at the dual prices, and its polish asks again at dozens of nearby
//! prices on the same block. The ranges and their curve amounts do not depend
//! on those prices; only where the walk stops does. So each state keeps a
//! ladder per direction, built as deep as some walk has needed, and a later
//! walk is a binary search over it.

use crate::pools::{V3State, cross_liquidity};
use crate::v3math::{
    MAX_SQRT_RATIO, MAX_TICK, MIN_SQRT_RATIO, MIN_TICK, amount0_delta, amount1_delta,
    sqrt_ratio_at_tick,
};
use alloy_primitives::U256;
use anyhow::{Context, bail};

/// What a walk covered.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DepthWalk {
    /// Output from the curve over the ranges walked whole, each range
    /// rounded up.
    pub out_up: U256,
    /// Input to the curve (before the LP fee) over the same ranges, each
    /// range rounded down.
    pub in_down: U256,
    /// The range in which the walk's condition turned false: its entry price
    /// and its liquidity. `None` when the walk ran to the coverage wall, or
    /// when the wall was already behind the price.
    pub stopped_in: Option<(U256, U256)>,
}

/// The walk inputs a ladder was built from. A clone of a state that traded
/// on has a different key, so it never reads a ladder that is not its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DepthKey {
    sqrt_price: U256,
    liquidity: U256,
    pos: usize,
    lo_cover: i32,
    hi_cover: i32,
}

impl DepthKey {
    pub(crate) fn of(state: &V3State) -> Self {
        Self {
            sqrt_price: state.sqrt_price,
            liquidity: state.liquidity,
            pos: state.pos,
            lo_cover: state.lo_cover,
            hi_cover: state.hi_cover,
        }
    }
}

/// One constant-liquidity range, from the previous stop (or the state's
/// price) to `stop`, with the totals up to and including it.
#[derive(Clone, Copy, Debug)]
struct Step {
    stop: U256,
    liquidity: U256,
    out_up: U256,
    in_down: U256,
}

/// Where building resumes.
#[derive(Clone, Copy, Debug)]
struct Cursor {
    sqrt_price: U256,
    liquidity: U256,
    pos: usize,
    /// The last step ended on an initialized tick not yet crossed. Crossing
    /// waits until a walk needs the next step, as the walk itself would.
    cross_pending: bool,
    out_up: U256,
    in_down: U256,
}

#[derive(Clone, Debug)]
enum End {
    /// The coverage wall, or a wall already behind the price.
    Wall,
    /// Building the next step failed. A walk that never needs that step
    /// never sees the error.
    Fault(String),
}

#[derive(Clone, Debug)]
pub(crate) struct Ladder {
    steps: Vec<Step>,
    cursor: Cursor,
    end: Option<End>,
}

impl Ladder {
    pub(crate) fn new(state: &V3State) -> Self {
        Self {
            steps: Vec::new(),
            cursor: Cursor {
                sqrt_price: state.sqrt_price,
                liquidity: state.liquidity,
                pos: state.pos,
                cross_pending: false,
                out_up: U256::ZERO,
                in_down: U256::ZERO,
            },
            end: None,
        }
    }

    /// Walk from the state's price while `go(stop)` holds at each stop.
    ///
    /// `go` must be monotone along the walk — true, then false from some stop
    /// on — which an exact "does trading still pay here" test is: the stops
    /// move one way and the marginal rate with them.
    ///
    /// `enough(out_up, in_down)` is asked at each step a walk adds to the
    /// ladder, with the totals so far; when it answers true the walk ends
    /// there and returns `None`. It lets a caller that only needs to know
    /// whether a walk is worth more than some amount stop a deep one early.
    pub(crate) fn walk(
        &mut self,
        state: &V3State,
        zero_for_one: bool,
        mut go: impl FnMut(U256) -> anyhow::Result<bool>,
        mut enough: impl FnMut(U256, U256) -> anyhow::Result<bool>,
    ) -> anyhow::Result<Option<DepthWalk>> {
        // Build until the last step fails `go` or the ladder ends. Built steps
        // are tested only at the end, so a later walk pays one test per new
        // step plus a binary search.
        let mut last_goes = false;
        loop {
            if let Some(last) = self.steps.last() {
                last_goes = go(last.stop)?;
                if !last_goes {
                    break;
                }
                if enough(last.out_up, last.in_down)? {
                    return Ok(None);
                }
            }
            match &self.end {
                Some(End::Wall) => break,
                Some(End::Fault(error)) => bail!("{error}"),
                None => {}
            }
            if let Err(error) = self.extend(state, zero_for_one) {
                let error = format!("{error:#}");
                self.end = Some(End::Fault(error.clone()));
                bail!("{error}");
            }
        }
        let n = self.steps.len();
        let first_stop = if n == 0 || last_goes {
            n
        } else {
            // go(steps[n - 1]) is false: find the first false.
            let (mut lo, mut hi) = (0, n - 1);
            while lo < hi {
                let mid = lo + (hi - lo) / 2;
                if go(self.steps[mid].stop)? {
                    lo = mid + 1;
                } else {
                    hi = mid;
                }
            }
            lo
        };
        let whole = first_stop.checked_sub(1).map(|i| self.steps[i]);
        Ok(Some(DepthWalk {
            out_up: whole.map_or(U256::ZERO, |step| step.out_up),
            in_down: whole.map_or(U256::ZERO, |step| step.in_down),
            stopped_in: (first_stop < n).then(|| {
                (
                    whole.map_or(state.sqrt_price, |step| step.stop),
                    self.steps[first_stop].liquidity,
                )
            }),
        }))
    }

    /// Build one more step, or end the ladder.
    fn extend(&mut self, state: &V3State, zero_for_one: bool) -> anyhow::Result<()> {
        let mut cursor = self.cursor;
        if cursor.cross_pending {
            let net = if zero_for_one {
                state.ticks[cursor.pos - 1].liquidity_net
            } else {
                state.ticks[cursor.pos].liquidity_net
            };
            cursor.liquidity = cross_liquidity(cursor.liquidity, net, zero_for_one)?;
            if zero_for_one {
                cursor.pos -= 1;
            } else {
                cursor.pos += 1;
            }
            cursor.cross_pending = false;
        }
        let (stop, crosses) = next_stop(state, zero_for_one, cursor.pos)?;
        let behind = if zero_for_one {
            stop > cursor.sqrt_price
        } else {
            stop < cursor.sqrt_price
        };
        if behind {
            // The coverage wall is already past the price: no modelled room.
            self.cursor = cursor;
            self.end = Some(End::Wall);
            return Ok(());
        }
        if stop != cursor.sqrt_price {
            let (lo, hi) = if zero_for_one {
                (stop, cursor.sqrt_price)
            } else {
                (cursor.sqrt_price, stop)
            };
            let (out_curve, in_curve) = if zero_for_one {
                (
                    amount1_delta(lo, hi, cursor.liquidity, true)?,
                    amount0_delta(lo, hi, cursor.liquidity, false)?,
                )
            } else {
                (
                    amount0_delta(lo, hi, cursor.liquidity, true)?,
                    amount1_delta(lo, hi, cursor.liquidity, false)?,
                )
            };
            cursor.out_up = cursor
                .out_up
                .checked_add(out_curve)
                .context("depth output exceeds 256 bits")?;
            cursor.in_down = cursor
                .in_down
                .checked_add(in_curve)
                .context("depth input exceeds 256 bits")?;
            cursor.sqrt_price = stop;
        }
        self.steps.push(Step {
            stop,
            liquidity: cursor.liquidity,
            out_up: cursor.out_up,
            in_down: cursor.in_down,
        });
        if crosses {
            cursor.cross_pending = true;
        } else {
            self.end = Some(End::Wall); // modelled depth ends at the coverage wall
        }
        self.cursor = cursor;
        Ok(())
    }
}

/// Where the walk may next stop, and whether crossing it changes liquidity.
/// Uninitialized stops are the edge of the snapshot's tick coverage — the same
/// wall `sim_v3` refuses to walk past.
pub fn next_stop(state: &V3State, zero_for_one: bool, pos: usize) -> anyhow::Result<(U256, bool)> {
    if zero_for_one {
        if pos > 0 && state.ticks[pos - 1].tick >= state.lo_cover {
            return Ok((state.ticks.sqrt_price(pos - 1)?, true));
        }
        Ok((
            sqrt_ratio_at_tick(state.lo_cover.clamp(MIN_TICK, MAX_TICK))?
                .max(MIN_SQRT_RATIO + U256::ONE),
            false,
        ))
    } else {
        if pos < state.ticks.len() && state.ticks[pos].tick <= state.hi_cover {
            return Ok((state.ticks.sqrt_price(pos)?, true));
        }
        Ok((
            sqrt_ratio_at_tick(state.hi_cover.clamp(MIN_TICK, MAX_TICK))?
                .min(MAX_SQRT_RATIO - U256::ONE),
            false,
        ))
    }
}

#[cfg(test)]
mod tests {
    use crate::pools::{TickInfo, V3State};
    use crate::v3math::sqrt_ratio_at_tick;
    use alloy_primitives::{I256, U256};

    fn never(_: U256, _: U256) -> anyhow::Result<bool> {
        Ok(false)
    }

    fn state() -> V3State {
        let ticks: Vec<TickInfo> = (-40..40)
            .map(|n| TickInfo {
                tick: n * 60,
                liquidity_net: I256::try_from(1_000_000_000_000i64 * i64::from(n % 7 - 3)).unwrap(),
            })
            .collect();
        let pos = ticks.partition_point(|tick| tick.tick <= 30);
        V3State {
            sqrt_price: sqrt_ratio_at_tick(30).unwrap(),
            tick: 30,
            liquidity: U256::from(10u128.pow(20)),
            ticks: ticks.into(),
            pos,
            lo_cover: -2_000,
            hi_cover: 2_000,
        }
    }

    /// The ladder answers exactly what a fresh walk answers, at every
    /// stopping point and in any order of questions.
    #[test]
    fn a_reused_ladder_answers_as_a_fresh_walk() {
        let state = state();
        for zero_for_one in [true, false] {
            let stops: Vec<U256> = (-2_100..=2_100)
                .step_by(37)
                .map(|tick| sqrt_ratio_at_tick(tick).unwrap())
                .collect();
            let order: Vec<usize> = (0..stops.len()).map(|i| (i * 53) % stops.len()).collect();
            let shared = state.clone();
            for &i in &order {
                let limit = stops[i];
                let go = |stop: U256| {
                    Ok(if zero_for_one {
                        stop > limit
                    } else {
                        stop < limit
                    })
                };
                let fresh = super::Ladder::new(&state)
                    .walk(&state, zero_for_one, go, never)
                    .unwrap();
                let reused = shared.depth_walk(zero_for_one, go, never).unwrap();
                assert_eq!(reused, fresh, "zero_for_one={zero_for_one} limit #{i}");
            }
        }
    }

    /// A state that traded on is a different walk: it never reads the
    /// ladder its source state built.
    #[test]
    fn a_moved_clone_does_not_share_its_sources_ladder() {
        let state = state();
        let everything = |_: U256| Ok(true);
        let before = state.depth_walk(true, everything, never).unwrap();
        let mut moved = state.clone();
        moved.sqrt_price = sqrt_ratio_at_tick(-500).unwrap();
        moved.pos = moved.ticks.partition_point(|tick| tick.tick <= -500);
        let after = moved.depth_walk(true, everything, never).unwrap();
        assert_ne!(before, after);
        assert_eq!(
            after,
            super::Ladder::new(&moved)
                .walk(&moved, true, everything, never)
                .unwrap()
        );
        assert_eq!(state.depth_walk(true, everything, never).unwrap(), before);
    }

    /// `enough` ends a walk at the first step whose totals satisfy it, and
    /// the ladder it leaves behind still answers in full.
    #[test]
    fn enough_ends_a_walk_and_leaves_the_ladder_whole() {
        let state = state();
        let everything = |_: U256| Ok(true);
        let full = state.depth_walk(true, everything, never).unwrap().unwrap();
        let half = full.out_up / U256::from(2);
        let mut fresh = state.clone();
        fresh.ticks = fresh.ticks.to_vec().into();
        assert_eq!(
            fresh
                .depth_walk(true, everything, |out_up, _| Ok(out_up >= half))
                .unwrap(),
            None
        );
        assert_eq!(
            fresh.depth_walk(true, everything, never).unwrap(),
            Some(full)
        );
    }
}
