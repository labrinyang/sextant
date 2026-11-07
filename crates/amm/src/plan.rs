//! A route plan: the legs a Settler executes, in order.
//!
//! Plain data with no behaviour of its own. It lives with the pool families
//! because the router produces it, the encoder consumes it and the tools
//! print it; both sides depend on this crate, so neither depends on the
//! other for it.

use alloy_primitives::{Address, B256, U256};

/// Basis points in a whole: the unit of every share a plan's legs carry.
pub const BPS_BASE: u32 = 10_000;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub enum HopKind {
    V3,
    V2,
    Ekubo,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hop {
    pub kind: HopKind,
    pub index: usize, // into Snapshot.v3 / Snapshot.v2
    pub zero_for_one: bool,
    pub token_in: Address,
    pub token_out: Address,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Leg {
    pub path: Vec<Hop>,
    pub amount_in: U256,
    pub amount_out: U256,
    /// Actual value losses observed while simulating this leg. Keeping both
    /// sides preserves integer rounding in pool fees.
    pub losses: Vec<LossRatio>,
    /// first-segment share of the LIVE Settler balance;
    /// BPS_BASE on the last leg; 0 = not yet quantized
    pub slice_bps: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LossRatio {
    pub gross: U256,
    pub net: U256,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Plan {
    pub legs: Vec<Leg>,
    pub amount_out: U256,
    /// Exact ordered token-skeleton universe used to produce this plan. Manual
    /// execution fixtures may leave it unset; certification never may.
    pub universe_id: Option<B256>,
}
