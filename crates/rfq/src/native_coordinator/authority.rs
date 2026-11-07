//! The quota authority: one solver host admits every host's Native firm
//! quotes against the provider's shared ceilings, and serves that over HTTP.
//! It is compiled with rfq's `authority` feature, which the solver enables;
//! the client in the parent module, and Settler encoding through it, need
//! neither the authority nor an HTTP server.

use super::{Acquire, Granted, MAX_BODY, MAX_LEASES, Release, Released};
use alloy_primitives::B256;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use axum::{Json, Router};
use serde::Serialize;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::Mutex as AsyncMutex;

pub(super) struct Lease {
    expires: Instant,
    firm: bool,
    granted: bool,
}
pub(super) struct QuotaState {
    pub(super) leases: HashMap<B256, Lease>,
    pub(super) cancelled: HashMap<B256, Instant>,
    next: Instant,
    pub(super) quiet_until: Instant,
}
#[derive(Clone, Copy, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CoordinatorMetrics {
    pub acquisitions: u64,
    pub releases: u64,
    pub expired: u64,
    pub rejected: u64,
    pub queue_wait_ns: u64,
    pub handler_compute_ns: u64,
    pub active_firm_leases: usize,
    pub active_leases: usize,
}
pub struct NativeQuotaAuthority {
    pub(super) scope: B256,
    token: Vec<u8>,
    qps: u32,
    max_inflight: usize,
    queue_wait: Duration,
    lifetime: Duration,
    pub(super) state: Mutex<QuotaState>,
    pace: AsyncMutex<()>,
    pub(super) metrics: Mutex<CoordinatorMetrics>,
    #[cfg(test)]
    pub(super) admissions: Mutex<Vec<Instant>>,
}
impl NativeQuotaAuthority {
    pub fn new(
        scope: B256,
        token: &str,
        qps: u32,
        max_inflight: usize,
        queue_wait: Duration,
        lifetime: Duration,
    ) -> anyhow::Result<Arc<Self>> {
        anyhow::ensure!(
            token.len() >= 32
                && qps > 0
                && max_inflight > 0
                && !queue_wait.is_zero()
                && lifetime >= queue_wait,
            "invalid authoritative Native quota settings"
        );
        Ok(Arc::new(Self {
            scope,
            token: format!("Bearer {token}").into_bytes(),
            qps,
            max_inflight,
            queue_wait,
            lifetime,
            state: Mutex::new(QuotaState {
                leases: HashMap::new(),
                cancelled: HashMap::new(),
                next: Instant::now(),
                quiet_until: Instant::now(),
            }),
            pace: AsyncMutex::new(()),
            metrics: Mutex::new(CoordinatorMetrics::default()),
            #[cfg(test)]
            admissions: Mutex::new(Vec::new()),
        }))
    }
    pub(super) fn authenticated(&self, headers: &HeaderMap) -> bool {
        let value = headers
            .get("authorization")
            .map_or(&[][..], |v| v.as_bytes());
        let mut diff = value.len() ^ self.token.len();
        for (i, b) in self.token.iter().enumerate() {
            diff |= usize::from(*b ^ value.get(i).copied().unwrap_or(0));
        }
        diff == 0
    }
    fn prune(&self, state: &mut QuotaState) {
        let now = Instant::now();
        let before = state.leases.len();
        state.leases.retain(|_, lease| lease.expires > now);
        state.cancelled.retain(|_, until| *until > now);
        self.metrics.lock().expect("quota metrics").expired += (before - state.leases.len()) as u64;
    }
    pub(super) async fn acquire(&self, request: Acquire) -> Result<Granted, StatusCode> {
        let started = Instant::now();
        if request.scope != self.scope {
            return Err(StatusCode::FORBIDDEN);
        }
        let expires = {
            let mut state = self.state.lock().expect("coordinator quota");
            self.prune(&mut state);
            if state.quiet_until > Instant::now() {
                return Err(StatusCode::SERVICE_UNAVAILABLE);
            }
            if state.cancelled.contains_key(&request.id) {
                return Err(StatusCode::CONFLICT);
            }
            if let Some(lease) = state.leases.get(&request.id) {
                if lease.firm != request.firm || !lease.granted {
                    return Err(StatusCode::CONFLICT);
                }
                return Ok(Granted {
                    handler_compute_ns: started.elapsed().as_nanos() as u64,
                    lifetime_ms: lease
                        .expires
                        .saturating_duration_since(Instant::now())
                        .as_millis() as u64,
                });
            }
            if state.leases.len() >= MAX_LEASES
                || (request.firm
                    && state.leases.values().filter(|l| l.firm).count() >= self.max_inflight)
            {
                self.metrics.lock().expect("quota metrics").rejected += 1;
                return Err(StatusCode::TOO_MANY_REQUESTS);
            }
            let expires = Instant::now() + self.lifetime;
            state.leases.insert(
                request.id,
                Lease {
                    expires,
                    firm: request.firm,
                    granted: !request.pace,
                },
            );
            expires
        };
        // Record bounded state manipulation separately from waiting. No
        // dedicated scheduling core or unbounded per-request work queue.
        let mut handler_ns = started.elapsed().as_nanos() as u64;
        let initial_handler_ns = handler_ns;
        self.metrics
            .lock()
            .expect("quota metrics")
            .handler_compute_ns += initial_handler_ns;
        if request.pace {
            let waited = Instant::now();
            let result = tokio::time::timeout(self.queue_wait, async {
                let _gate = self.pace.lock().await;
                let next = self.state.lock().expect("coordinator quota").next;
                tokio::time::sleep_until(tokio::time::Instant::from_std(next)).await;
                let compute_started = Instant::now();
                let mut state = self.state.lock().expect("coordinator quota");
                let now = Instant::now();
                if state.cancelled.contains_key(&request.id) || expires <= now {
                    return Err(StatusCode::CONFLICT);
                }
                let lease = state
                    .leases
                    .get_mut(&request.id)
                    .ok_or(StatusCode::CONFLICT)?;
                lease.granted = true;
                state.next =
                    now + Duration::from_nanos(1_000_000_000u64.div_ceil(u64::from(self.qps)));
                #[cfg(test)]
                self.admissions.lock().expect("test admissions").push(now);
                handler_ns += compute_started.elapsed().as_nanos() as u64;
                Ok(())
            })
            .await;
            self.metrics.lock().expect("quota metrics").queue_wait_ns +=
                waited.elapsed().as_nanos() as u64;
            match result {
                Ok(Ok(())) => {}
                other => {
                    self.state
                        .lock()
                        .expect("coordinator quota")
                        .leases
                        .remove(&request.id);
                    return Err(match other {
                        Ok(Err(status)) => status,
                        _ => StatusCode::REQUEST_TIMEOUT,
                    });
                }
            }
        }
        {
            let mut metrics = self.metrics.lock().expect("quota metrics");
            metrics.acquisitions += 1;
            metrics.handler_compute_ns += handler_ns.saturating_sub(initial_handler_ns);
        }
        Ok(Granted {
            handler_compute_ns: handler_ns,
            lifetime_ms: expires
                .saturating_duration_since(Instant::now())
                .as_millis() as u64,
        })
    }
    pub(super) fn release(&self, request: Release) -> Result<u64, StatusCode> {
        if request.scope != self.scope {
            return Err(StatusCode::FORBIDDEN);
        }
        let start = Instant::now();
        let mut state = self.state.lock().expect("coordinator quota");
        self.prune(&mut state);
        let removed = state.leases.remove(&request.id);
        // A cancellation can arrive ahead of its acquire response. Remember
        // the ID so a queued acquisition cannot grant the cancelled lease.
        // Clients dispatch an acquire ID once and never retry it after release.
        // A granted lease has no outstanding admission that can resurrect it;
        // retaining every normal release for a full lifetime would make healthy
        // sustained traffic fill the cancellation map and stop all new work.
        let may_still_acquire = removed.is_none_or(|lease| !lease.granted);
        if !may_still_acquire {
            // Normal release; no pending acquisition remains for this ID.
        } else if state.cancelled.len() < MAX_LEASES * 4 {
            state
                .cancelled
                .insert(request.id, Instant::now() + self.lifetime);
        } else {
            // Keep memory bounded without forgetting a pre-acquire cancel.
            // Stop fresh grants until every possibly delayed old ID is outside
            // the supported client lease lifetime; never silently resurrect.
            state.quiet_until = state.quiet_until.max(Instant::now() + self.lifetime);
        }
        let mut metrics = self.metrics.lock().expect("quota metrics");
        metrics.releases += 1;
        let elapsed = start.elapsed().as_nanos() as u64;
        metrics.handler_compute_ns += elapsed;
        Ok(elapsed)
    }
    pub fn metrics(&self) -> CoordinatorMetrics {
        let mut state = self.state.lock().expect("coordinator quota");
        self.prune(&mut state);
        let mut metrics = *self.metrics.lock().expect("quota metrics");
        metrics.active_leases = state.leases.len();
        metrics.active_firm_leases = state.leases.values().filter(|l| l.firm).count();
        metrics
    }
    pub fn router(self: &Arc<Self>) -> Router {
        Router::new()
            .route("/internal/native-quota/acquire", post(acquire_http))
            .route("/internal/native-quota/release", post(release_http))
            .route(
                "/internal/native-quota/health",
                axum::routing::get(health_http),
            )
            .layer(axum::extract::DefaultBodyLimit::max(MAX_BODY))
            .with_state(self.clone())
    }
    pub fn configured_router(
        config: Option<&crate::rfq::NativeRfqConfig>,
    ) -> anyhow::Result<Router> {
        let enabled = std::env::var("SOLVER_NATIVE_QUOTA_COORDINATOR_ENABLED")
            .unwrap_or_else(|_| "false".into());
        anyhow::ensure!(
            matches!(enabled.as_str(), "true" | "false" | "1" | "0"),
            "invalid Native quota authority setting"
        );
        if enabled == "false" || enabled == "0" {
            return Ok(Router::new());
        }
        let config = config.ok_or_else(|| {
            anyhow::anyhow!("Native quota authority needs the configured Native credential scope")
        })?;
        let token = std::env::var("SOLVER_SERVICE_TOKEN")?;
        let lifetime_ms = std::env::var("SOLVER_NATIVE_QUOTA_LEASE_MS")
            .unwrap_or_else(|_| "120000".into())
            .parse::<u64>()?;
        anyhow::ensure!(
            (1000..=120_000).contains(&lifetime_ms),
            "Native lease duration must be 1000..=120000 ms"
        );
        Ok(Self::from_serving_config(config, &token, Duration::from_millis(lifetime_ms))?.router())
    }
    pub fn from_serving_config(
        config: &crate::rfq::NativeRfqConfig,
        token: &str,
        lifetime: Duration,
    ) -> anyhow::Result<Arc<Self>> {
        // This server also serves quotes. Its own provider traffic must use
        // the authority just like remote workers, rather than running an
        // independent process ceiling in parallel with the shared ceiling.
        anyhow::ensure!(
            config.quota_mode() == "coordinated",
            "Native quota authority quote serving requires the shared coordinator URL"
        );
        let owner = Self::new(
            config.quota_scope(),
            token,
            config.qps(),
            config.max_inflight(),
            config.queue_wait(),
            lifetime,
        )?;
        // A restarted in-memory authority waits out prior client leases before
        // granting a fresh ceiling. This state is not claimed durable.
        {
            let mut state = owner.state.lock().expect("coordinator quota");
            state.quiet_until = Instant::now() + owner.lifetime;
            state.next = state.quiet_until;
        }
        Ok(owner)
    }
}
async fn health_http(
    State(owner): State<Arc<NativeQuotaAuthority>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, StatusCode> {
    if !owner.authenticated(&headers) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let blocked = owner
        .state
        .lock()
        .expect("coordinator quota")
        .quiet_until
        .saturating_duration_since(Instant::now())
        .as_millis() as u64;
    Ok(Json(
        serde_json::json!({"metrics":owner.metrics(),"qps":owner.qps,"maxInflight":owner.max_inflight,
        "leaseMs":owner.lifetime.as_millis() as u64,"restartQuietMs":blocked,"scope":"configured_provider_credential"}),
    ))
}
pub(super) async fn acquire_http(
    State(owner): State<Arc<NativeQuotaAuthority>>,
    headers: HeaderMap,
    Json(request): Json<Acquire>,
) -> Result<Json<Granted>, StatusCode> {
    if !owner.authenticated(&headers) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    owner.acquire(request).await.map(Json)
}
async fn release_http(
    State(owner): State<Arc<NativeQuotaAuthority>>,
    headers: HeaderMap,
    Json(request): Json<Release>,
) -> Result<Json<Released>, StatusCode> {
    if !owner.authenticated(&headers) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let handler_compute_ns = owner.release(request)?;
    Ok(Json(Released { handler_compute_ns }))
}
