//! Native RFQ, the one external liquidity source Sextant composes with its
//! AMM routes: the firm-quote client, validation of Native's calldata,
//! the beneficiary authorization a Native-capable Settler checks, and the
//! cross-instance quota coordinator.

pub(crate) use sextant_budget::budget;
pub(crate) use sextant_chain::chain;
pub(crate) use sextant_io::{abi, rpc, work_budget};

pub mod native_coordinator;
pub mod rfq;
