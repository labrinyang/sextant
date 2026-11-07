//! Sextant's market state: `engine`, which keeps recently quoted pairs'
//! snapshots hot and single-flights their pulls, and `resident`, which reads
//! every pool on a resident list at each new block. Both stand on discovery's
//! snapshots; the engine takes its pulls through a `SnapshotSource`.

pub(crate) use sextant_amm::{pools, snapshot, venue};
pub(crate) use sextant_chain::{catalog, chain};
pub(crate) use sextant_discovery::{indexer, lens, state};
pub(crate) use sextant_io::{rpc, rpc_dispatch};
pub(crate) use sextant_route::{route, topology, universe};

pub mod engine;
pub(crate) mod freshness;
pub mod resident;
