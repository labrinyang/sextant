// Verbatim port of Uniswap v3-core TickMath / SqrtPriceMath / SwapMath
// (exact-input subset). Semantics — including every rounding direction and
// overflow check — mirror the Solidity sources; UP33 CL (Slipstream-style)
// shares this math.
//
// Arithmetic discipline (vs the Julia original): U256 ops that Solidity runs
// unchecked are spelled wrapping_*, everything else is checked — an overflow
// on garbage input surfaces as an error instead of a silently wrapped quote.

use alloy_primitives::{I256, U256, U512, uint};
use anyhow::{Context, anyhow, ensure};

pub const Q96: U256 = uint!(0x1000000000000000000000000_U256);
pub const MIN_TICK: i32 = -887272;
pub const MAX_TICK: i32 = 887272;
pub const MIN_SQRT_RATIO: U256 = uint!(4295128739_U256);
pub const MAX_SQRT_RATIO: U256 = uint!(1461446703485210103287273052203988822378723970342_U256);
pub const U160_MAX: U256 = uint!(0xffffffffffffffffffffffffffffffffffffffff_U256);

const PPM: U256 = uint!(1000000_U256);

fn u512(x: U256) -> U512 {
    U512::from(x)
}

/// Narrow a U512 that is known (or required) to fit into 256 bits.
fn narrow(q: U512) -> anyhow::Result<U256> {
    ensure!(q >> 256usize == U512::ZERO, "does not fit uint256");
    let limbs: [u64; 4] = q.as_limbs()[..4].try_into().expect("4 low limbs");
    Ok(U256::from_limbs(limbs))
}

fn muldiv_rem(a: U256, b: U256, d: U256) -> anyhow::Result<(U256, bool)> {
    ensure!(d != U256::ZERO, "muldiv by zero");
    if let Some(product) = a.checked_mul(b) {
        let (q, r) = product.div_rem(d);
        Ok((q, !r.is_zero()))
    } else {
        // The exact 512-bit product, 4×4 limbs: a 512×512 multiply would
        // do four times the work for the same answer.
        let product: U512 = a.widening_mul(b);
        let (q, r) = product.div_rem(u512(d));
        Ok((
            narrow(q).map_err(|_| anyhow!("muldiv overflow"))?,
            !r.is_zero(),
        ))
    }
}

pub fn muldiv(a: U256, b: U256, d: U256) -> anyhow::Result<U256> {
    Ok(muldiv_rem(a, b, d)?.0)
}

pub fn muldiv_up(a: U256, b: U256, d: U256) -> anyhow::Result<U256> {
    let (q, has_remainder) = muldiv_rem(a, b, d)?;
    if has_remainder {
        q.checked_add(U256::ONE).context("muldiv_up overflow")
    } else {
        Ok(q)
    }
}

pub fn div_up(a: U256, b: U256) -> anyhow::Result<U256> {
    ensure!(b != U256::ZERO, "div_up by zero");
    let (q, r) = a.div_rem(b);
    Ok(if r.is_zero() { q } else { q + U256::ONE })
}

pub fn checked_add(a: U256, b: U256) -> anyhow::Result<U256> {
    a.checked_add(b).context("u256 add overflow")
}

pub fn to_u160(x: U256) -> anyhow::Result<U256> {
    ensure!(x <= U160_MAX, "does not fit uint160");
    Ok(x)
}

// ---- TickMath ----

const TICK_FACTORS: [U256; 19] = [
    uint!(0xfff97272373d413259a46990580e213a_U256),
    uint!(0xfff2e50f5f656932ef12357cf3c7fdcc_U256),
    uint!(0xffe5caca7e10e4e61c3624eaa0941cd0_U256),
    uint!(0xffcb9843d60f6159c9db58835c926644_U256),
    uint!(0xff973b41fa98c081472e6896dfb254c0_U256),
    uint!(0xff2ea16466c96a3843ec78b326b52861_U256),
    uint!(0xfe5dee046a99a2a811c461f1969c3053_U256),
    uint!(0xfcbe86c7900a88aedcffc83b479aa3a4_U256),
    uint!(0xf987a7253ac413176f2b074cf7815e54_U256),
    uint!(0xf3392b0822b70005940c7a398e4b70f3_U256),
    uint!(0xe7159475a2c29b7443b29c7fa6e889d9_U256),
    uint!(0xd097f3bdfd2022b8845ad8f792aa5825_U256),
    uint!(0xa9f746462d870fdf8a65dc1f90e061e5_U256),
    uint!(0x70d869a156d2a1b890bb3df62baf32f7_U256),
    uint!(0x31be135f97d08fd981231505542fcfa6_U256),
    uint!(0x9aa508b5b7a84e1c677de54f3e99bc9_U256),
    uint!(0x5d6af8dedb81196699c329225ee604_U256),
    uint!(0x2216e584f5fa1ea926041bedfe98_U256),
    uint!(0x48a170391f7dc42444e8fa2_U256),
];

/// sqrt(1.0001^tick) as Q64.96 — TickMath.getSqrtRatioAtTick.
pub fn sqrt_ratio_at_tick(tick: i32) -> anyhow::Result<U256> {
    let at = tick.unsigned_abs();
    ensure!(at <= MAX_TICK as u32, "tick {tick} out of range");
    let mut ratio = if at & 1 != 0 {
        uint!(0xfffcb933bd6fad37aa2d162d1a594001_U256)
    } else {
        U256::ONE << 128usize
    };
    for (i, f) in TICK_FACTORS.iter().enumerate() {
        if at & (1 << (i + 1)) != 0 {
            // ratio stays < 2^128 once multiplied by sub-2^128 factors: the
            // 256-bit product cannot overflow (same argument as the Solidity).
            ratio = (ratio * f) >> 128usize;
        }
    }
    if tick > 0 {
        ratio = U256::MAX / ratio;
    }
    let round = if (ratio & ((U256::ONE << 32usize) - U256::ONE)).is_zero() {
        U256::ZERO
    } else {
        U256::ONE
    };
    Ok((ratio >> 32usize) + round)
}

/// `tick_at_sqrt`'s only failure: a price outside the representable range.
/// Callers that defer the tick to commit time check it here, eagerly.
pub fn tick_at_sqrt_range(s: U256) -> anyhow::Result<()> {
    ensure!(
        s >= MIN_SQRT_RATIO && s < MAX_SQRT_RATIO,
        "sqrt ratio out of range"
    );
    Ok(())
}

/// Greatest tick whose sqrt ratio is <= `s` — TickMath.getTickAtSqrtRatio.
pub fn tick_at_sqrt(s: U256) -> anyhow::Result<i32> {
    tick_at_sqrt_range(s)?;

    // Port of TickMath.getTickAtSqrtRatio. `ratio` is Q128.128 and `r`
    // is normalized into [2^127, 2^128) before extracting 14 fractional
    // log2 bits. The final sqrt-ratio comparison resolves the only possible
    // one-tick ambiguity.
    let ratio = s << 32usize;
    let msb = ratio.log2();
    let mut r = if msb >= 128 {
        ratio >> (msb - 127)
    } else {
        ratio << (127 - msb)
    };
    let mut log_2 = ((msb as i128) - 128) << 64;
    for bit in (50..=63).rev() {
        r = (r * r) >> 127usize;
        if r >> 128usize != U256::ZERO {
            log_2 |= 1i128 << bit;
            r >>= 1usize;
        }
    }

    let log_sqrt10001 = I256::try_from(log_2).expect("Q64.64 logarithm fits I256")
        * I256::from_raw(uint!(255738958999603826347141_U256));
    let tick_low = (log_sqrt10001
        - I256::from_raw(uint!(3402992956809132418596140100660247210_U256)))
    .asr(128)
    .as_i32();
    let tick_high = (log_sqrt10001
        + I256::from_raw(uint!(291339464771989622907027621153398088495_U256)))
    .asr(128)
    .as_i32();

    if tick_low == tick_high || sqrt_ratio_at_tick(tick_high)? > s {
        Ok(tick_low)
    } else {
        Ok(tick_high)
    }
}

// ---- SqrtPriceMath ----

fn next_sqrt_from_amount0_up(
    sqrt_p: U256,
    l: U256,
    amount: U256,
    add: bool,
) -> anyhow::Result<U256> {
    if amount.is_zero() {
        return Ok(sqrt_p);
    }
    let numerator1 = l << 96usize;
    if add {
        let product = amount.wrapping_mul(sqrt_p); // wrapping, like unchecked Solidity
        if product / amount == sqrt_p {
            let denominator = numerator1.wrapping_add(product); // wrapping
            if denominator >= numerator1 {
                return muldiv_up(numerator1, sqrt_p, denominator);
            }
        }
        div_up(numerator1, checked_add(numerator1 / sqrt_p, amount)?)
    } else {
        let product = amount.wrapping_mul(sqrt_p);
        ensure!(
            product / amount == sqrt_p && numerator1 > product,
            "price underflow"
        );
        to_u160(muldiv_up(numerator1, sqrt_p, numerator1 - product)?)
    }
}

fn next_sqrt_from_amount1_down(
    sqrt_p: U256,
    l: U256,
    amount: U256,
    add: bool,
) -> anyhow::Result<U256> {
    if add {
        let quotient = if amount <= U160_MAX {
            (amount << 96usize) / l
        } else {
            muldiv(amount, Q96, l)?
        };
        to_u160(checked_add(sqrt_p, quotient)?)
    } else {
        let quotient = if amount <= U160_MAX {
            div_up(amount << 96usize, l)?
        } else {
            muldiv_up(amount, Q96, l)?
        };
        ensure!(sqrt_p > quotient, "price underflow");
        Ok(sqrt_p - quotient)
    }
}

pub fn next_sqrt_from_input(
    sqrt_p: U256,
    l: U256,
    amount_in: U256,
    zero_for_one: bool,
) -> anyhow::Result<U256> {
    ensure!(
        sqrt_p > U256::ZERO && l > U256::ZERO,
        "zero price or liquidity"
    );
    if zero_for_one {
        next_sqrt_from_amount0_up(sqrt_p, l, amount_in, true)
    } else {
        next_sqrt_from_amount1_down(sqrt_p, l, amount_in, true)
    }
}

pub fn amount0_delta(sqrt_a: U256, sqrt_b: U256, l: U256, round_up: bool) -> anyhow::Result<U256> {
    let (sqrt_a, sqrt_b) = if sqrt_a > sqrt_b {
        (sqrt_b, sqrt_a)
    } else {
        (sqrt_a, sqrt_b)
    };
    ensure!(sqrt_a > U256::ZERO, "zero sqrt price");
    let numerator1 = l << 96usize;
    let numerator2 = sqrt_b - sqrt_a;
    if round_up {
        div_up(muldiv_up(numerator1, numerator2, sqrt_b)?, sqrt_a)
    } else {
        Ok(muldiv(numerator1, numerator2, sqrt_b)? / sqrt_a)
    }
}

pub fn amount1_delta(sqrt_a: U256, sqrt_b: U256, l: U256, round_up: bool) -> anyhow::Result<U256> {
    let (sqrt_a, sqrt_b) = if sqrt_a > sqrt_b {
        (sqrt_b, sqrt_a)
    } else {
        (sqrt_a, sqrt_b)
    };
    // l·(√b−√a)/2^96, as muldiv(_up) by Q96 gives it: the divisor is a
    // power of two, so the quotient is a shift and the remainder a mask.
    let (q, has_remainder) = match l.checked_mul(sqrt_b - sqrt_a) {
        Some(product) => (product >> 96usize, !(product & Q96_MASK).is_zero()),
        None => {
            let product: U512 = l.widening_mul(sqrt_b - sqrt_a);
            (
                narrow(product >> 96usize).map_err(|_| anyhow!("muldiv overflow"))?,
                !(product & u512(Q96_MASK)).is_zero(),
            )
        }
    };
    if round_up && has_remainder {
        q.checked_add(U256::ONE).context("muldiv_up overflow")
    } else {
        Ok(q)
    }
}

const Q96_MASK: U256 = uint!(0xffffffffffffffffffffffff_U256);

// ---- SwapMath (exact input) ----

/// One swap step toward `sqrt_target`, exact-input semantics of
/// SwapMath.computeSwapStep. Returns (sqrt_next, amount_in, amount_out, fee).
/// Guarantees amount_in + fee <= amount_remaining, with equality whenever the
/// target is not reached.
pub fn compute_swap_step(
    sqrt_current: U256,
    sqrt_target: U256,
    l: U256,
    amount_remaining: U256,
    fee_pips: u32,
) -> anyhow::Result<(U256, U256, U256, U256)> {
    let zero_for_one = sqrt_current >= sqrt_target;
    let fee = U256::from(fee_pips);
    let remaining_less_fee = muldiv(amount_remaining, PPM - fee, PPM)?;
    let mut amount_in = if zero_for_one {
        amount0_delta(sqrt_target, sqrt_current, l, true)?
    } else {
        amount1_delta(sqrt_current, sqrt_target, l, true)?
    };
    let sqrt_next = if remaining_less_fee >= amount_in {
        sqrt_target
    } else {
        next_sqrt_from_input(sqrt_current, l, remaining_less_fee, zero_for_one)?
    };
    let max_reached = sqrt_next == sqrt_target;
    let amount_out = if zero_for_one {
        if !max_reached {
            amount_in = amount0_delta(sqrt_next, sqrt_current, l, true)?;
        }
        amount1_delta(sqrt_next, sqrt_current, l, false)?
    } else {
        if !max_reached {
            amount_in = amount1_delta(sqrt_current, sqrt_next, l, true)?;
        }
        amount0_delta(sqrt_current, sqrt_next, l, false)?
    };
    let fee_amount = if !max_reached {
        amount_remaining
            .checked_sub(amount_in)
            .context("swap step overconsumed")?
    } else {
        muldiv_up(amount_in, fee, PPM - fee)?
    };
    Ok((sqrt_next, amount_in, amount_out, fee_amount))
}

pub fn sqrt_limit(zero_for_one: bool) -> U256 {
    if zero_for_one {
        MIN_SQRT_RATIO + U256::ONE
    } else {
        MAX_SQRT_RATIO - U256::ONE
    }
}

/// U512 widening helper shared with the v2 simulator.
pub fn widen(x: U256) -> U512 {
    u512(x)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference_muldiv(a: U256, b: U256, d: U256) -> anyhow::Result<(U256, bool)> {
        ensure!(d != U256::ZERO, "muldiv by zero");
        let (q, r) = (u512(a) * u512(b)).div_rem(u512(d));
        Ok((
            narrow(q).map_err(|_| anyhow!("muldiv overflow"))?,
            !r.is_zero(),
        ))
    }

    fn reference_tick_at_sqrt(s: U256) -> anyhow::Result<i32> {
        ensure!(
            s >= MIN_SQRT_RATIO && s < MAX_SQRT_RATIO,
            "sqrt ratio out of range"
        );
        let (mut lo, mut hi) = (MIN_TICK, MAX_TICK);
        while lo < hi {
            let mid = (lo + hi + 1) >> 1;
            if sqrt_ratio_at_tick(mid)? <= s {
                lo = mid;
            } else {
                hi = mid - 1;
            }
        }
        Ok(lo)
    }

    fn next_u64(state: &mut u64) -> u64 {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        *state
    }

    fn next_u256(state: &mut u64) -> U256 {
        U256::from_limbs([
            next_u64(state),
            next_u64(state),
            next_u64(state),
            next_u64(state),
        ])
    }

    /// The shifted `amount1_delta` against muldiv(_up) by Q96, which it
    /// replaces: random widths, so both the 256-bit and the widened product
    /// and the overflow are reached.
    #[test]
    fn amount1_delta_shifts_exactly_as_muldiv_by_q96() {
        let mut state = 0x2545_f491_4f6c_dd1d;
        for i in 0..20_000u32 {
            let width = |x: U256, bits: u32| x >> (256 - bits as usize);
            let l = width(next_u256(&mut state), 1 + i % 256);
            let a = width(next_u256(&mut state), 1 + (i / 7) % 256);
            let b = width(next_u256(&mut state), 1 + (i / 13) % 256);
            let (lo, hi) = if a > b { (b, a) } else { (a, b) };
            assert_eq!(
                amount1_delta(a, b, l, false).ok(),
                muldiv(l, hi - lo, Q96).ok(),
                "{l} {a} {b}"
            );
            assert_eq!(
                amount1_delta(a, b, l, true).ok(),
                muldiv_up(l, hi - lo, Q96).ok(),
                "{l} {a} {b} up"
            );
        }
    }

    #[test]
    fn optimized_muldiv_matches_widened_reference() {
        let cases = [
            (U256::ZERO, U256::MAX, U256::ONE),
            (U256::ONE, U256::ONE, U256::from(3)),
            (U256::MAX, U256::MAX, U256::MAX),
            (U256::MAX, U256::MAX, U256::ONE),
            (U256::MAX, U256::from(2), U256::from(2)),
        ];
        for (a, b, d) in cases {
            let reference = reference_muldiv(a, b, d);
            assert_eq!(muldiv(a, b, d).ok(), reference.as_ref().ok().map(|x| x.0));
            assert_eq!(
                muldiv_up(a, b, d).ok(),
                reference.ok().and_then(|(q, rem)| if rem {
                    q.checked_add(U256::ONE)
                } else {
                    Some(q)
                })
            );
        }

        let mut state = 0x9e37_79b9_7f4a_7c15;
        for _ in 0..10_000 {
            let a = next_u256(&mut state);
            let b = next_u256(&mut state);
            let mut d = next_u256(&mut state);
            if d.is_zero() {
                d = U256::ONE;
            }
            let reference = reference_muldiv(a, b, d);
            assert_eq!(muldiv(a, b, d).ok(), reference.as_ref().ok().map(|x| x.0));
            assert_eq!(
                muldiv_up(a, b, d).ok(),
                reference.ok().and_then(|(q, rem)| if rem {
                    q.checked_add(U256::ONE)
                } else {
                    Some(q)
                })
            );
        }

        assert!(muldiv(U256::ONE, U256::ONE, U256::ZERO).is_err());
        assert!(muldiv_up(U256::ONE, U256::ONE, U256::ZERO).is_err());
    }

    #[test]
    fn optimized_div_up_matches_definition() {
        let mut state = 0xd1b5_4a32_d192_ed03;
        for _ in 0..10_000 {
            let a = next_u256(&mut state);
            let mut b = next_u256(&mut state);
            if b.is_zero() {
                b = U256::ONE;
            }
            let expected = if (a % b).is_zero() {
                a / b
            } else {
                a / b + U256::ONE
            };
            assert_eq!(div_up(a, b).unwrap(), expected);
        }
        assert!(div_up(U256::ONE, U256::ZERO).is_err());
    }

    #[test]
    #[ignore = "exhaustive TickMath proof; run explicitly in the predeploy gate"]
    fn tick_inverse_matches_every_boundary() {
        for tick in MIN_TICK..MAX_TICK {
            let lower = sqrt_ratio_at_tick(tick).unwrap();
            let upper = sqrt_ratio_at_tick(tick + 1).unwrap();
            assert_eq!(
                tick_at_sqrt(lower).unwrap(),
                tick,
                "lower boundary at tick {tick}"
            );
            assert_eq!(
                tick_at_sqrt(upper - U256::ONE).unwrap(),
                tick,
                "upper boundary at tick {tick}"
            );
        }
    }

    #[test]
    fn tick_inverse_matches_binary_search_reference() {
        let span = MAX_SQRT_RATIO - MIN_SQRT_RATIO;
        let mut state = 0xa076_1d64_78bd_642f;
        for _ in 0..10_000 {
            let s = MIN_SQRT_RATIO + next_u256(&mut state) % span;
            assert_eq!(
                tick_at_sqrt(s).unwrap(),
                reference_tick_at_sqrt(s).unwrap(),
                "sqrt ratio {s}"
            );
        }
        assert!(tick_at_sqrt(MIN_SQRT_RATIO - U256::ONE).is_err());
        assert!(tick_at_sqrt(MAX_SQRT_RATIO).is_err());
    }
}
