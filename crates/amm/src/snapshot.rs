//! One block's pool state: what every route, certificate and encoder reads.

use crate::ekubo::{EkuboPool, EkuboState};
use crate::pools::{V2Pool, V2State, V3Pool, V3State};
use alloy_primitives::Address;

#[derive(Clone, Debug)]
pub struct Snapshot {
    pub block: u64,
    /// Resolved execution identity at `block`. Quote-only profiles may omit it;
    /// transaction encoding always requires a nonzero value.
    pub settler: Option<Address>,
    pub v3: Vec<(V3Pool, V3State)>,
    pub v2: Vec<(V2Pool, V2State)>,
    pub ekubo: Vec<(EkuboPool, EkuboState)>,
}

/// Pool state read for pricing and never for routing, at the same canonical
/// block as the snapshot beside it.
///
/// Held outside `Snapshot` deliberately. Every router entry point — path
/// enumeration, simulation, allocation, Settler encoding — takes a `Snapshot`,
/// so a pool absent from one cannot be routed through by any caller, present or
/// future, without a signature change that would be obvious in review. That is
/// the same guarantee `RouteUniverse` gives by keeping screening pairs out of
/// `token_paths`, enforced a second time at the state layer.
#[derive(Clone, Debug, Default)]
pub struct ScreeningPools {
    pub v3: Vec<(V3Pool, V3State)>,
    pub v2: Vec<(V2Pool, V2State)>,
}

impl ScreeningPools {
    pub fn is_empty(&self) -> bool {
        self.v3.is_empty() && self.v2.is_empty()
    }

    pub fn len(&self) -> usize {
        self.v3.len() + self.v2.len()
    }
}
