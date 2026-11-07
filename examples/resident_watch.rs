//! Run the resident reader alone against a chain and print what it does.
//!
//! The reader needs no indexer, Settler or quote server, so this watches the
//! carry on any chain with a venue table: how many blocks were read whole or
//! from logs, how many pools each carried read re-read, and what the audits
//! found. `SOLVER_RESIDENT_FULL_READ_MS=1` reads every block whole and audits
//! each against the carry.
//!
//! SOLVER_CHAIN=bsc SOLVER_RPC=<url> SOLVER_RESIDENT=on \
//!   SOLVER_RESIDENT_POOL_LIST_URL=<url> \
//!   cargo run --release --example resident_watch -- [seconds] [every]

use anyhow::Context;
use sextant::resident::{Resident, Settings};
use sextant::rpc::Rpc;
use std::time::{Duration, Instant};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    sextant_observe::tracing::init(sextant_observe::tracing::LogFormat::Compact, "sextant")?;
    let mut args = std::env::args().skip(1);
    let seconds: u64 = args.next().map_or(Ok(120), |value| value.parse())?;
    let every: u64 = args.next().map_or(Ok(10), |value| value.parse())?;
    let profile = sextant::chain::profile_by_key(&std::env::var("SOLVER_CHAIN")?)?;
    let rpc = Rpc::connect(&std::env::var("SOLVER_RPC").context("SOLVER_RPC")?)?;
    let settings = Settings::from_env(profile)?.context("SOLVER_RESIDENT=on is required")?;
    let resident = Resident::new(profile, rpc, settings)?;
    resident.spawn();
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(seconds) {
        tokio::time::sleep(Duration::from_secs(every)).await;
        let health = resident.health();
        println!(
            "t={}s block={} behind={} reads={} failures={} lastReadMs={} pools={} carry={} lastError={}",
            started.elapsed().as_secs(),
            health["block"],
            health["blocksBehind"],
            health["reads"],
            health["failures"],
            health["lastReadMs"],
            health["pools"],
            health["carry"],
            health["lastError"],
        );
    }
    Ok(())
}
