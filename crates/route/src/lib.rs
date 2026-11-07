//! Sextant's router: route universes, exact split routing, the duality-gap
//! certificate and counterfactual coverage, over one block's snapshot. No
//! I/O: the application reads state and executes plans.

pub(crate) use sextant_amm::{depth, ekubo, plan, pools, snapshot, v3math};
pub(crate) use sextant_budget::budget;
pub(crate) use sextant_chain::chain;

pub mod certificate;
pub mod counterfactual;
pub mod route;
pub mod topology;
pub mod universe;

/// Parses every `SOLVER_*` setting this crate owns and returns the first
/// error, without forcing the lazies that read them at first use. The server
/// calls it at startup, so a typo fails boot instead of the first quote that
/// certifies.
pub fn validate_settings() -> anyhow::Result<()> {
    route::read_alloc_chunks()?;
    route::read_min_share_bps()?;
    route::read_polish()?;
    certificate::read_enabled()?;
    certificate::read_tighten_budget()?;
    counterfactual::read_coverage_ttl()?;
    Ok(())
}
