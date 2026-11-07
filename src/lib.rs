// Sextant: a certified split-routing swap solver for EVM chains. One process
// serves one chain profile; quotes execute through that chain's 0x Settler.

pub use sextant_amm::{pools, snapshot, v3math, venue};
pub use sextant_budget::budget;
pub use sextant_chain::{catalog, chain, manifest};
pub use sextant_discovery::{ekubo, indexer, lens, state};
pub use sextant_exec::{settler, simulation};
pub use sextant_io::{abi, process_memory, rpc, rpc_dispatch, work_budget};
pub use sextant_market::{engine, resident};
pub use sextant_rfq::{native_coordinator, rfq};
pub use sextant_route::{certificate, counterfactual, route, topology, universe};

pub mod config;
pub(crate) mod quote_metrics;
pub mod quotes;
pub mod server;
