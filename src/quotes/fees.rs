use crate::route::{Hop, HopKind, Leg, Plan};
use crate::settler::BPS_BASE;
use crate::snapshot::Snapshot;
use crate::v3math::muldiv;
use alloy_primitives::U256;
use alloy_primitives::aliases::{U1024, U4096};
use anyhow::ensure;

pub fn net_after_fee(gross: U256, fee_bps: u32) -> anyhow::Result<U256> {
    Ok(gross - muldiv(gross, U256::from(fee_bps), U256::from(BPS_BASE))?)
}

pub(super) fn price_impact_bps(
    amount_in: U256,
    amount_out: U256,
    fair_in: U256,
    fair_out: U256,
) -> u32 {
    let fair_rate = U1024::from(fair_out) * U1024::from(amount_in);
    let execution_rate = U1024::from(amount_out) * U1024::from(fair_in);
    if execution_rate >= fair_rate {
        return 0;
    }
    let impact =
        ((fair_rate - execution_rate) * U1024::from(BPS_BASE) + fair_rate - U1024::ONE) / fair_rate;
    u32::try_from(impact).expect("price impact is at most 10000 bps")
}

/// LP-fee denominator: v2's `fee_bps` × 100.
pub(super) const PPM_BASE: u32 = 1_000_000;

fn v2_fee_ppm(snap: &Snapshot, hop: &Hop) -> u32 {
    snap.v2[hop.index].0.fee_bps * 100
}

/// Adds every hop's LP fee back onto a leg's output, then scales it to the
/// quote size. Keep the compounded ratio fractional until after scaling: one
/// widened division per leg matches the direct quote formula.
///
/// A fee at or above PPM_BASE would underflow, on the same snapshot invariant
/// `sim_v2` already leans on for `10_000 - fee_bps`.
pub(super) fn fee_free_out(
    snap: &Snapshot,
    leg: &Leg,
    fair_in: U256,
    amount_in: U256,
) -> anyhow::Result<U256> {
    // Routes have at most three hops: 4096 bits hold both quote amounts and
    // three pool-fee ratios without overflow.
    let mut numerator = U4096::from(leg.amount_out) * U4096::from(amount_in);
    let mut denominator = U4096::from(fair_in);
    for hop in leg.path.iter().filter(|hop| hop.kind == HopKind::V2) {
        let fee_ppm = v2_fee_ppm(snap, hop);
        numerator *= U4096::from(PPM_BASE);
        denominator *= U4096::from(PPM_BASE - fee_ppm);
    }
    for loss in &leg.losses {
        numerator *= U4096::from(loss.gross);
        denominator *= U4096::from(loss.net);
    }
    let out = numerator / denominator;
    ensure!(out >> 256usize == U4096::ZERO, "midAmountOut overflow");
    Ok(U256::from_limbs(
        out.as_limbs()[..4].try_into().expect("four low limbs"),
    ))
}

/// The fee-free reference output for `amount_in`: the 1% probe plan's output
/// with every LP fee added back, scaled to full size.
/// It is what the trade would fetch if both size and fees were free, and
/// it is the ONE denominator every quote row on the frontend is scored against
/// — one route's cost can then never sit on a different scale from another's.
///
/// Derived from the probe PLAN rather than a pool's raw mid price on purpose:
/// the reference stays a price that was actually executable at probe size, so
/// a stale or illiquid pool advertising a great mid cannot poison it. The
/// residual error is the probe's own depth cost — it moves 1% of the trade, so
/// a sub-bp share of the full-size move.
pub(super) fn mid_amount_out(
    snap: &Snapshot,
    fair: &Plan,
    fair_in: U256,
    amount_in: U256,
) -> anyhow::Result<U256> {
    let mut acc = U256::ZERO;
    for leg in &fair.legs {
        acc += fee_free_out(snap, leg, fair_in, amount_in)?;
    }
    Ok(acc)
}

pub(super) fn reference_metrics(
    snap: &Snapshot,
    full: &Plan,
    fair: Option<&Plan>,
    fair_in: U256,
    amount_in: U256,
) -> anyhow::Result<(Option<u32>, Option<U256>)> {
    let Some(fair) = fair else {
        return Ok((None, None));
    };
    let mid = mid_amount_out(snap, fair, fair_in, amount_in)?;
    if mid < full.amount_out {
        return Ok((None, None));
    }
    Ok((
        Some(price_impact_bps(
            amount_in,
            full.amount_out,
            fair_in,
            fair.amount_out,
        )),
        Some(mid),
    ))
}
