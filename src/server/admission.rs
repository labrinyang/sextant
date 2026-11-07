use super::App;
use anyhow::Context;
use std::time::{Duration, Instant};
use tokio::sync::OwnedSemaphorePermit;

const DEFAULT_COMPUTE_CONCURRENCY: usize = 2;
const MAX_COMPUTE_CONCURRENCY: usize = 64;
const INFLIGHT_QUOTES_PER_COMPUTE_SLOT: usize = 4;
const MAX_INFLIGHT_QUOTES: usize = 256;
/// Quotes that may wait for a slot, per slot; beyond that a quote is refused at once.
pub(super) const QUEUED_QUOTES_PER_SLOT: usize = 2;
const DEFAULT_QUOTE_ADMISSION_WAIT_MS: u64 = 1_000;
const MAX_QUOTE_ADMISSION_WAIT_MS: u64 = 10_000;

pub(super) fn parse_compute_concurrency(value: Option<&str>) -> anyhow::Result<usize> {
    let concurrency = value
        .unwrap_or("2")
        .parse::<usize>()
        .context("SOLVER_COMPUTE_CONCURRENCY must be a positive integer")?;
    anyhow::ensure!(
        (1..=MAX_COMPUTE_CONCURRENCY).contains(&concurrency),
        "SOLVER_COMPUTE_CONCURRENCY must be in 1..={MAX_COMPUTE_CONCURRENCY}"
    );
    Ok(concurrency)
}

pub(super) fn compute_concurrency_from_env() -> anyhow::Result<usize> {
    match std::env::var("SOLVER_COMPUTE_CONCURRENCY") {
        Ok(value) => parse_compute_concurrency(Some(&value)),
        Err(std::env::VarError::NotPresent) => Ok(DEFAULT_COMPUTE_CONCURRENCY),
        Err(error) => Err(anyhow::anyhow!(
            "reading SOLVER_COMPUTE_CONCURRENCY: {error}"
        )),
    }
}

pub(super) fn parse_max_inflight_quotes(
    value: Option<&str>,
    compute_concurrency: usize,
) -> anyhow::Result<usize> {
    let default = compute_concurrency
        .checked_mul(INFLIGHT_QUOTES_PER_COMPUTE_SLOT)
        .context("default quote concurrency overflow")?;
    let max_inflight = value
        .map_or_else(|| Ok(default), str::parse::<usize>)
        .context("SOLVER_MAX_INFLIGHT_QUOTES must be a positive integer")?;
    anyhow::ensure!(
        (compute_concurrency..=MAX_INFLIGHT_QUOTES).contains(&max_inflight),
        "SOLVER_MAX_INFLIGHT_QUOTES must be in {compute_concurrency}..={MAX_INFLIGHT_QUOTES}"
    );
    Ok(max_inflight)
}

pub(super) fn parse_quote_admission_wait(value: &str) -> anyhow::Result<Duration> {
    let ms = value
        .trim()
        .parse::<u64>()
        .context("SOLVER_QUOTE_ADMISSION_WAIT_MS must be a whole number of milliseconds")?;
    anyhow::ensure!(
        ms <= MAX_QUOTE_ADMISSION_WAIT_MS,
        "SOLVER_QUOTE_ADMISSION_WAIT_MS must be at most {MAX_QUOTE_ADMISSION_WAIT_MS}"
    );
    Ok(Duration::from_millis(ms))
}

pub(super) fn quote_admission_wait_from_env() -> anyhow::Result<Duration> {
    parse_quote_admission_wait(&crate::chain::env_or(
        "SOLVER_QUOTE_ADMISSION_WAIT_MS",
        &DEFAULT_QUOTE_ADMISSION_WAIT_MS.to_string(),
    )?)
}

/// How long one quote may take: `SOLVER_QUOTE_TIMEOUT`, or less when the
/// caller says it stops waiting sooner (`x-quote-timeout-ms`), so the solver
/// neither queues nor works for an answer nobody will read.
pub(super) fn quote_time_limit(configured_secs: u64, header: Option<&str>) -> Duration {
    let configured = Duration::from_secs(configured_secs);
    header
        .and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|ms| *ms > 0)
        .map_or(configured, |ms| configured.min(Duration::from_millis(ms)))
}

pub(super) fn max_inflight_quotes_from_env(compute_concurrency: usize) -> anyhow::Result<usize> {
    match std::env::var("SOLVER_MAX_INFLIGHT_QUOTES") {
        Ok(value) => parse_max_inflight_quotes(Some(&value), compute_concurrency),
        Err(std::env::VarError::NotPresent) => parse_max_inflight_quotes(None, compute_concurrency),
        Err(error) => Err(anyhow::anyhow!(
            "reading SOLVER_MAX_INFLIGHT_QUOTES: {error}"
        )),
    }
}

/// A slot to quote in. With every slot busy the quote waits in arrival order,
/// for at most `SOLVER_QUOTE_ADMISSION_WAIT_MS` and never past its deadline;
/// once `QUEUED_QUOTES_PER_SLOT` quotes per slot are already waiting it is
/// refused at once. A refusal is a 503 with Retry-After.
pub(super) async fn admit_quote(app: &App, deadline: Instant) -> Option<OwnedSemaphorePermit> {
    if let Ok(permit) = app.quote_slots.clone().try_acquire_owned() {
        return Some(permit);
    }
    let wait = app
        .quote_admission_wait
        .min(deadline.saturating_duration_since(Instant::now()));
    if wait.is_zero() {
        return None;
    }
    let _place = app.quote_queue.clone().try_acquire_owned().ok()?;
    let _waiting = app.metrics.waiting();
    tokio::time::timeout(wait, app.quote_slots.clone().acquire_owned())
        .await
        .ok()?
        .ok()
}
