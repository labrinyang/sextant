use super::App;
use super::startup::{verify_indexer_startup, verify_native_rfq_adapter, verify_quote_rpc};
use anyhow::Context;
use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex as AsyncMutex;

/// How often a background task re-runs the readiness probes. Quotes and health
/// checks read its last result and never wait on a probe: until 16 Oct 2026 the
/// first request after the result aged 10 s ran the probes itself while every
/// other request queued behind it, about 0.4 s at a 130 ms round trip.
pub(super) const READINESS_REFRESH: Duration = Duration::from_secs(10);
/// A result older than this (the refresher stopped, or none was started) is
/// probed again by the request that finds it, with the others waiting on that
/// one probe.
pub(super) const READINESS_TTL: Duration = Duration::from_secs(30);
// Health probes must fail faster than the load balancer's liveness window.
// Quote traffic retains the RPC client's longer timeout and is unaffected.
pub(super) const READINESS_PROBE_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Copy)]
pub(super) struct ReadinessState {
    pub(super) checked_at: Instant,
    pub(super) rpc_ready: bool,
    pub(super) indexer_ready: bool,
}

impl ReadinessState {
    pub(super) fn new(rpc_ready: bool, indexer_ready: bool) -> Self {
        Self {
            checked_at: Instant::now(),
            rpc_ready,
            indexer_ready,
        }
    }
}

pub(super) fn app_is_ready(app: &App, readiness: ReadinessState) -> bool {
    app.chain_verified
        && readiness.rpc_ready
        && readiness.indexer_ready
        && app.cfg.profile.capabilities.quote
}

pub(super) async fn readiness(app: &App) -> ReadinessState {
    // Boxed: the probes' state machines are large, and every quote and health
    // request awaits this one.
    cached_readiness(
        &app.readiness,
        READINESS_PROBE_TIMEOUT,
        Box::pin(readiness_probe(app)),
    )
    .await
}

/// Re-run the readiness probes every `period` while the app is alive, so no
/// request waits on them.
pub(super) fn spawn_readiness_refresher(app: &Arc<App>, period: Duration) {
    let app = Arc::downgrade(app);
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(period).await;
            let Some(app) = app.upgrade() else {
                return;
            };
            let (rpc_ready, indexer_ready) =
                tokio::time::timeout(READINESS_PROBE_TIMEOUT, Box::pin(readiness_probe(&app)))
                    .await
                    .unwrap_or_default();
            *app.readiness.lock().await = ReadinessState::new(rpc_ready, indexer_ready);
        }
    });
}

async fn readiness_probe(app: &App) -> (bool, bool) {
    {
        let rpc_probe = async {
            verify_quote_rpc(&app.rpc, app.cfg.profile).await?;
            if let Some(config) = app.cfg.native_rfq.as_ref() {
                verify_native_rfq_adapter(
                    &app.rpc,
                    app.cfg.profile,
                    app.native_adapter
                        .context("Native RFQ startup adapter unavailable")?,
                    config.authorizer().address(),
                )
                .await?;
            }
            Ok::<(), anyhow::Error>(())
        };
        let indexer_probe = async {
            match app.indexer.as_deref() {
                Some(indexer) => verify_indexer_startup(app.cfg.profile, indexer)
                    .await
                    .is_ok(),
                // Factory discovery rides the quote RPC, which `rpc_probe`
                // already checks.
                None => !app.cfg.profile.needs_indexer(),
            }
        };
        let (rpc_result, indexer_ready) = tokio::join!(rpc_probe, indexer_probe);
        (rpc_result.is_ok(), indexer_ready)
    }
}

pub(super) async fn cached_readiness<F>(
    state: &AsyncMutex<ReadinessState>,
    probe_timeout: Duration,
    probe: F,
) -> ReadinessState
where
    F: Future<Output = (bool, bool)>,
{
    // The mutex is intentionally held through both probes: concurrent health
    // requests share one upstream check instead of amplifying it.
    let mut cached = state.lock().await;
    if cached.checked_at.elapsed() < READINESS_TTL {
        return *cached;
    }
    let (rpc_ready, indexer_ready) = tokio::time::timeout(probe_timeout, probe)
        .await
        .unwrap_or_default();
    *cached = ReadinessState::new(rpc_ready, indexer_ready);
    *cached
}
