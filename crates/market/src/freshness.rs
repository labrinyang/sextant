//! How old a snapshot may be to start a quote, and how much older to finish it.

use std::time::Duration;

pub(crate) const STALE: Duration = Duration::from_secs(2);
/// How far past `STALE` a quote started on a fresh snapshot may still finish
/// on it. Serving stops at `STALE`, so no quote starts on older state; a solve
/// takes milliseconds. Until 16 Oct 2026 there was none, and a quote started a
/// few milliseconds short of the bound failed with a 502 as it finished: up
/// to a few in a hundred per-pair quotes at 130 ms of RTT.
pub(crate) const FINISH_GRACE: Duration = Duration::from_millis(250);
