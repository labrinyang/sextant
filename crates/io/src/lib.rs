//! Sextant's chain I/O: the JSON-RPC client with block-pinned reads, its
//! dispatch admission and per-quote work budgets, and the ABI it speaks.

pub(crate) use sextant_budget::budget;

pub mod abi;
pub mod process_memory;
pub mod rpc;
pub mod rpc_dispatch;
pub mod work_budget;
