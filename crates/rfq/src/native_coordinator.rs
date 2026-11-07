//! Optional single-authority coordination across solver hosts. Admission
//! ceilings belong to the authority, never to a caller. Leases bound client
//! attempt lifetimes; expiration is not proof of remote provider termination.
use alloy_primitives::B256;
#[cfg(test)]
use axum::http::HeaderMap;
#[cfg(test)]
use axum::routing::post;
#[cfg(test)]
use axum::{Json, Router};
use reqwest::{StatusCode, Url};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
// Compiled only where a host serves the authority (the `authority` feature).
#[cfg(any(test, feature = "authority"))]
mod authority;
#[cfg(any(test, feature = "authority"))]
pub use authority::*;

const MAX_BODY: usize = 4096;
// Release carries only two 32-byte hex IDs; its response contains one u64.
const RELEASE_RESERVED_BODY_BYTES: usize = 256 + 64;
const MAX_LEASES: usize = 256;
#[derive(Clone, Eq, PartialEq)]
pub struct CoordinatorConfig {
    url: Url,
    token: reqwest::header::HeaderValue,
}
impl CoordinatorConfig {
    pub fn from_env() -> anyhow::Result<Option<Self>> {
        let url = match std::env::var("SOLVER_NATIVE_QUOTA_COORDINATOR_URL") {
            Ok(url) => url,
            Err(std::env::VarError::NotPresent) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let token = std::env::var("SOLVER_SERVICE_TOKEN")?;
        Ok(Some(Self::new(&url, &token)?))
    }
    pub fn new(url: &str, token: &str) -> anyhow::Result<Self> {
        let url: Url = url.parse()?;
        anyhow::ensure!(
            url.scheme() == "https"
                || (url.scheme() == "http"
                    && url.host_str().is_some_and(|h| h == "localhost"
                        || h.parse::<std::net::IpAddr>().is_ok_and(|a| a.is_loopback()))),
            "quota coordinator requires HTTPS or loopback HTTP"
        );
        anyhow::ensure!(
            url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none(),
            "quota coordinator URL must not carry credentials"
        );
        anyhow::ensure!(
            token.len() >= 32,
            "Native quota coordinator requires existing SOLVER_SERVICE_TOKEN"
        );
        let mut token = reqwest::header::HeaderValue::from_str(&format!("Bearer {token}"))?;
        token.set_sensitive(true);
        Ok(Self { url, token })
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
struct Acquire {
    scope: B256,
    id: B256,
    firm: bool,
    pace: bool,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
struct Release {
    scope: B256,
    id: B256,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
struct Granted {
    lifetime_ms: u64,
    handler_compute_ns: u64,
}
#[derive(Deserialize, Serialize)]
struct Released {
    handler_compute_ns: u64,
}

#[derive(Clone)]
pub struct CoordinatorClient {
    config: CoordinatorConfig,
    http: reqwest::Client,
    scope: B256,
    cleanup_slots: Arc<Semaphore>,
}
pub struct CoordinatorPermit {
    client: CoordinatorClient,
    id: B256,
    deadline: Instant,
    work: Option<crate::work_budget::WorkBudget>,
    dispatch_work: Option<crate::work_budget::WorkBudget>,
    cleanup_slot: Option<OwnedSemaphorePermit>,
    armed: bool,
}
impl CoordinatorClient {
    pub fn new(config: CoordinatorConfig, http: reqwest::Client, scope: B256) -> Self {
        // Independently constructed clients for this authority and Native
        // credential scope share the same owner ceiling. A slot is reserved
        // before acquire dispatch and retained until its cleanup terminates,
        // so cancellation never needs an unbounded queue or a second admission.
        static OWNERS: OnceLock<Mutex<HashMap<B256, Weak<Semaphore>>>> = OnceLock::new();
        let mut key = scope.as_slice().to_vec();
        // Calls use absolute /internal/... paths, so configured base-path
        // aliases reach the same authority and must not multiply its owners.
        key.extend_from_slice(config.url.origin().ascii_serialization().as_bytes());
        let key = alloy_primitives::keccak256(key);
        let cleanup_slots = {
            let mut owners = OWNERS
                .get_or_init(Mutex::default)
                .lock()
                .expect("Native quota cleanup owners");
            owners.retain(|_, owner| owner.strong_count() > 0);
            owners.get(&key).and_then(Weak::upgrade).unwrap_or_else(|| {
                // Match the authority's maximum concurrent leases, including
                // pending paced acquisitions. Denials release their slot.
                let slots = Arc::new(Semaphore::new(MAX_LEASES));
                owners.insert(key, Arc::downgrade(&slots));
                slots
            })
        };
        Self {
            config,
            http,
            scope,
            cleanup_slots,
        }
    }
    pub async fn acquire(
        &self,
        firm: bool,
        pace: bool,
        queue_wait: Duration,
        work: Option<&crate::work_budget::WorkBudget>,
    ) -> Result<CoordinatorPermit, crate::rfq::NativeRfqError> {
        let cleanup_slot = self
            .cleanup_slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| crate::rfq::NativeRfqError::Saturated)?;
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let mut bytes = Vec::with_capacity(64);
        bytes.extend_from_slice(self.scope.as_slice());
        bytes.extend_from_slice(&std::process::id().to_be_bytes());
        bytes.extend_from_slice(&NEXT.fetch_add(1, Ordering::Relaxed).to_be_bytes());
        bytes.extend_from_slice(
            &SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
                .to_be_bytes(),
        );
        let id = alloy_primitives::keccak256(bytes);
        // Keep the physical release call and its bounded control body out of
        // optional Native work. This is a lower ceiling, not an early debit:
        // used().rpc_calls still reports actual dispatched attempts only.
        let dispatch_work = work
            .map(|work| {
                work.with_finalization_reserve(
                    crate::work_budget::WorkCharge {
                        rpc_calls: 1,
                        rpc_bytes: RELEASE_RESERVED_BODY_BYTES as u64,
                        ..Default::default()
                    },
                    Duration::ZERO,
                )
                .ok_or(crate::rfq::NativeRfqError::WorkBudget)
            })
            .transpose()?;
        let mut permit = CoordinatorPermit {
            client: self.clone(),
            id,
            deadline: Instant::now() + queue_wait,
            work: work.cloned(),
            dispatch_work,
            cleanup_slot: Some(cleanup_slot),
            armed: false,
        };
        let response = self
            .call(
                "acquire",
                &Acquire {
                    scope: self.scope,
                    id,
                    firm,
                    pace,
                },
                queue_wait,
                permit.dispatch_work.as_ref(),
                Some(&mut permit.armed),
            )
            .await?;
        if !response.status().is_success() {
            if matches!(
                response.status(),
                StatusCode::UNAUTHORIZED
                    | StatusCode::FORBIDDEN
                    | StatusCode::CONFLICT
                    | StatusCode::TOO_MANY_REQUESTS
                    | StatusCode::REQUEST_TIMEOUT
                    | StatusCode::SERVICE_UNAVAILABLE
            ) {
                // These authoritative denials create no live lease. Cleanup
                // is needed only for a grant or an uncertain transport result.
                permit.armed = false;
            }
            return Err(status_error(response.status()));
        }
        let body = read_body(response, work).await?;
        let parse_started = Instant::now();
        let grant: Granted =
            serde_json::from_slice(&body).map_err(|_| crate::rfq::NativeRfqError::InvalidJson)?;
        if let Some(work) = work {
            work.record_compute_duration(
                parse_started.elapsed() + Duration::from_nanos(grant.handler_compute_ns),
                "Native quota decode and authority sections",
            )
            .map_err(|_| crate::rfq::NativeRfqError::WorkBudget)?;
        }
        if grant.lifetime_ms == 0 {
            return Err(crate::rfq::NativeRfqError::QueueTimeout);
        }
        // Subtract request/response time conservatively; the server's lease
        // expiration is authoritative, client wall clocks need not agree.
        permit.deadline = permit.deadline - queue_wait + Duration::from_millis(grant.lifetime_ms);
        Ok(permit)
    }
    async fn call(
        &self,
        method: &str,
        body: &impl Serialize,
        timeout: Duration,
        work: Option<&crate::work_budget::WorkBudget>,
        armed: Option<&mut bool>,
    ) -> Result<reqwest::Response, crate::rfq::NativeRfqError> {
        let encoded_started = Instant::now();
        let encoded =
            serde_json::to_vec(body).map_err(|_| crate::rfq::NativeRfqError::InvalidJson)?;
        if let Some(work) = work {
            if method == "release" {
                let _ =
                    work.record_rpc_dispatch_attempt("Native quota cancellation cleanup dispatch");
                let _ = work.record_rpc_response_bytes(
                    encoded.len(),
                    "Native quota cleanup request body bytes",
                );
                let _ = work.record_compute_duration(
                    encoded_started.elapsed(),
                    "Native quota cleanup encoding",
                );
            } else {
                work.record_compute_duration(
                    encoded_started.elapsed(),
                    "Native quota request encoding",
                )
                .map_err(|_| crate::rfq::NativeRfqError::WorkBudget)?;
                work.charge(
                    crate::work_budget::WorkCharge {
                        rpc_calls: 1,
                        rpc_bytes: encoded.len() as u64,
                        ..Default::default()
                    },
                    "Native quota coordination dispatch",
                )
                .map_err(|_| crate::rfq::NativeRfqError::WorkBudget)?;
            }
        }
        let endpoint = self
            .config
            .url
            .join(&format!("/internal/native-quota/{method}"))
            .map_err(|_| crate::rfq::NativeRfqError::Transport)?;
        let request = self
            .http
            .post(endpoint)
            .header("authorization", self.config.token.clone())
            .header("content-type", "application/json")
            .body(encoded)
            .timeout(timeout)
            .send();
        if let Some(armed) = armed {
            *armed = true;
        }
        if let Some(work) = work {
            work.run("Native quota coordinator wait", request)
                .await
                .map_err(|_| crate::rfq::NativeRfqError::WorkBudget)?
                .map_err(|_| crate::rfq::NativeRfqError::Transport)
        } else {
            request
                .await
                .map_err(|_| crate::rfq::NativeRfqError::Transport)
        }
    }
}
fn status_error(status: StatusCode) -> crate::rfq::NativeRfqError {
    match status {
        StatusCode::TOO_MANY_REQUESTS => crate::rfq::NativeRfqError::Saturated,
        StatusCode::REQUEST_TIMEOUT => crate::rfq::NativeRfqError::QueueTimeout,
        _ => crate::rfq::NativeRfqError::Transport,
    }
}
async fn read_body(
    mut response: reqwest::Response,
    work: Option<&crate::work_budget::WorkBudget>,
) -> Result<Vec<u8>, crate::rfq::NativeRfqError> {
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| crate::rfq::NativeRfqError::Transport)?
    {
        if let Some(work) = work {
            work.record_rpc_response_bytes(chunk.len(), "Native quota coordination response bytes")
                .map_err(|_| crate::rfq::NativeRfqError::WorkBudget)?;
        }
        if body.len() + chunk.len() > MAX_BODY {
            return Err(crate::rfq::NativeRfqError::ResponseTooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}
impl CoordinatorPermit {
    pub fn deadline(&self) -> Instant {
        self.deadline
    }
    pub fn dispatch_work(&self) -> Option<crate::work_budget::WorkBudget> {
        self.dispatch_work.clone()
    }
    /// Transfer cleanup ownership without making a successful provider result
    /// wait for the coordinator response. Drop uses this same one-shot path.
    pub fn release(self) {
        drop(self);
    }
    async fn cleanup(&self) -> Result<(), crate::rfq::NativeRfqError> {
        // Cancellation cleanup is physical work, retaining the original
        // account rather than resetting the request's spent resources.
        let work = self
            .work
            .as_ref()
            .map(|w| w.shared_owner_view(Instant::now() + Duration::from_secs(2)));
        let response = self
            .client
            .call(
                "release",
                &Release {
                    scope: self.client.scope,
                    id: self.id,
                },
                Duration::from_secs(2),
                work.as_ref(),
                None,
            )
            .await?;
        let status = response.status();
        let body = read_body(response, work.as_ref()).await?;
        if !status.is_success() {
            return Err(status_error(status));
        }
        let decoded = Instant::now();
        let result: Released =
            serde_json::from_slice(&body).map_err(|_| crate::rfq::NativeRfqError::InvalidJson)?;
        if let Some(work) = &work {
            let _ = work.record_compute_duration(
                decoded.elapsed() + Duration::from_nanos(result.handler_compute_ns),
                "Native quota release authority sections",
            );
        }
        Ok(())
    }
}
impl Drop for CoordinatorPermit {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let Some(cleanup_slot) = self.cleanup_slot.take() else {
            return;
        };
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            // Runtime/process shutdown cannot dispatch an HTTP cleanup. The
            // authoritative lease expiry remains the bounded fallback.
            return;
        };
        let owner = Self {
            client: self.client.clone(),
            id: self.id,
            deadline: self.deadline,
            work: self.work.clone(),
            dispatch_work: self.dispatch_work.clone(),
            cleanup_slot: Some(cleanup_slot),
            armed: false,
        };
        // The slot travels with the task, including its bounded HTTP/body wait.
        // This sole owner never retries, so a normal release cannot create a
        // second unknown-ID release and fill cancellation tombstones.
        runtime.spawn(async move {
            let _ = owner.cleanup().await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const TOKEN: &str = "controlled-fixture-service-token-00000000";
    async fn serve(
        qps: u32,
        inflight: usize,
        lifetime: Duration,
    ) -> (
        Arc<NativeQuotaAuthority>,
        CoordinatorClient,
        tokio::task::JoinHandle<()>,
        String,
    ) {
        let scope = B256::repeat_byte(0xa4);
        let owner = NativeQuotaAuthority::new(
            scope,
            TOKEN,
            qps,
            inflight,
            Duration::from_millis(500),
            lifetime,
        )
        .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let router = owner.router();
        let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let client = CoordinatorClient::new(
            CoordinatorConfig::new(&url, TOKEN).unwrap(),
            reqwest::Client::new(),
            scope,
        );
        (owner, client, server, url)
    }
    async fn wait_for_cleanup(client: &CoordinatorClient) {
        tokio::time::timeout(Duration::from_secs(2), async {
            while client.cleanup_slots.available_permits() != MAX_LEASES {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("bounded cleanup owner did not finish");
    }

    #[tokio::test]
    async fn explicit_release_survives_caller_cancellation_without_waiting_for_cleanup() {
        let scope = B256::repeat_byte(0xa4);
        let owner = NativeQuotaAuthority::new(
            scope,
            TOKEN,
            10,
            1,
            Duration::from_millis(500),
            Duration::from_secs(30),
        )
        .unwrap();
        let entered = Arc::new(Semaphore::new(0));
        let effect = Arc::new(Semaphore::new(0));
        let response = Arc::new(Semaphore::new(0));
        let release_owner = owner.clone();
        let release_entered = entered.clone();
        let release_effect = effect.clone();
        let release_response = response.clone();
        let router = Router::new()
            .route("/internal/native-quota/acquire", post(acquire_http))
            .route(
                "/internal/native-quota/release",
                post(move |headers: HeaderMap, Json(request): Json<Release>| {
                    let owner = release_owner.clone();
                    let entered = release_entered.clone();
                    let effect = release_effect.clone();
                    let response = release_response.clone();
                    async move {
                        if !owner.authenticated(&headers) {
                            return Err(StatusCode::UNAUTHORIZED);
                        }
                        entered.add_permits(1);
                        effect.acquire().await.unwrap().forget();
                        let handler_compute_ns = owner.release(request)?;
                        response.acquire().await.unwrap().forget();
                        Ok(Json(Released { handler_compute_ns }))
                    }
                }),
            )
            .with_state(owner.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let client = CoordinatorClient::new(
            CoordinatorConfig::new(&url, TOKEN).unwrap(),
            reqwest::Client::new(),
            scope,
        );
        let work = crate::work_budget::WorkBudget::bounded(
            crate::budget::SolverBudget::for_duration(Duration::from_secs(5)),
        );
        let lease = client
            .acquire(true, false, Duration::from_millis(500), Some(&work))
            .await
            .unwrap();
        let before = work.used();
        let returned = Arc::new(Semaphore::new(0));
        let caller_returned = returned.clone();
        let caller_work = work.clone();
        let caller = tokio::spawn(async move {
            caller_work
                .run("controlled explicit-release cancellation", async move {
                    lease.release();
                    caller_returned.add_permits(1);
                    std::future::pending::<()>().await;
                })
                .await
        });
        // Releasing a completed provider result must not wait for even the
        // first authority side effect, let alone a slow response body.
        tokio::time::timeout(Duration::from_millis(200), returned.acquire())
            .await
            .expect("explicit release waited for coordinator HTTP")
            .unwrap()
            .forget();
        tokio::time::timeout(Duration::from_secs(1), entered.acquire())
            .await
            .unwrap()
            .unwrap()
            .forget();
        assert_eq!(owner.metrics().active_firm_leases, 1);
        assert_eq!(client.cleanup_slots.available_permits(), MAX_LEASES - 1);
        work.cancel();
        assert!(caller.await.unwrap().is_err());
        effect.add_permits(1);
        tokio::time::timeout(Duration::from_secs(1), async {
            while owner.metrics().active_firm_leases != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("cancelled caller abandoned its authority lease");
        // The detached owner remains bounded and live through the HTTP body
        // wait, after the initiating future and its cancellation view are gone.
        assert_eq!(client.cleanup_slots.available_permits(), MAX_LEASES - 1);
        response.add_permits(1);
        wait_for_cleanup(&client).await;
        assert_eq!(work.used().rpc_calls, before.rpc_calls + 1);
        assert!(work.used().rpc_bytes > before.rpc_bytes);
        assert_eq!(owner.metrics().releases, 1);
        assert_eq!(owner.metrics().expired, 0);
        assert!(owner.state.lock().unwrap().cancelled.is_empty());
        server.abort();
    }

    #[tokio::test]
    async fn cleanup_capacity_is_reserved_before_dispatch_and_shared_between_clients() {
        let (owner, first, server, url) = serve(10, 1, Duration::from_secs(5)).await;
        let second = CoordinatorClient::new(
            CoordinatorConfig::new(&url, TOKEN).unwrap(),
            reqwest::Client::new(),
            first.scope,
        );
        assert!(Arc::ptr_eq(&first.cleanup_slots, &second.cleanup_slots));
        let held = first
            .cleanup_slots
            .clone()
            .acquire_many_owned(MAX_LEASES as u32)
            .await
            .unwrap();
        let work = crate::work_budget::WorkBudget::bounded(
            crate::budget::SolverBudget::for_duration(Duration::from_secs(2)),
        );
        assert!(matches!(
            second
                .acquire(true, false, Duration::from_millis(500), Some(&work))
                .await,
            Err(crate::rfq::NativeRfqError::Saturated)
        ));
        assert_eq!(work.used().rpc_calls, 0);
        assert_eq!(owner.metrics().acquisitions, 0);
        assert_eq!(owner.metrics().releases, 0);
        drop(held);
        second
            .acquire(true, false, Duration::from_millis(500), Some(&work))
            .await
            .unwrap()
            .release();
        wait_for_cleanup(&first).await;
        assert_eq!(owner.metrics().active_firm_leases, 0);
        assert_eq!(work.used().rpc_calls, 2);
        server.abort();
    }

    #[test]
    fn cleanup_base_path_aliases_share_an_authority_but_origins_and_scopes_do_not() {
        let http = reqwest::Client::new();
        let scope = B256::repeat_byte(0xd4);
        let client = |url, scope| {
            CoordinatorClient::new(
                CoordinatorConfig::new(url, TOKEN).unwrap(),
                http.clone(),
                scope,
            )
        };
        let first = client("https://quota.example", scope);
        let alias = client("https://quota.example/configured/base/", scope);
        assert_eq!(
            first
                .config
                .url
                .join("/internal/native-quota/release")
                .unwrap(),
            alias
                .config
                .url
                .join("/internal/native-quota/release")
                .unwrap()
        );
        assert!(Arc::ptr_eq(&first.cleanup_slots, &alias.cleanup_slots));
        let other_origin = client("https://quota.example:8443", scope);
        let other_scope = client("https://quota.example", B256::repeat_byte(0xd5));
        assert!(!Arc::ptr_eq(
            &first.cleanup_slots,
            &other_origin.cleanup_slots
        ));
        assert!(!Arc::ptr_eq(
            &first.cleanup_slots,
            &other_scope.cleanup_slots
        ));
    }

    #[tokio::test]
    async fn normal_cleanup_dispatches_once_and_leaves_no_cancellation_tombstones() {
        let (owner, client, server, _) = serve(10, 1, Duration::from_secs(5)).await;
        let work = crate::work_budget::WorkBudget::bounded(
            crate::budget::SolverBudget::for_duration(Duration::from_secs(5)),
        );
        for _ in 0..32 {
            client
                .acquire(true, false, Duration::from_millis(500), Some(&work))
                .await
                .unwrap()
                .release();
            wait_for_cleanup(&client).await;
        }
        assert_eq!(owner.metrics().acquisitions, 32);
        assert_eq!(owner.metrics().releases, 32);
        assert_eq!(owner.metrics().active_leases, 0);
        assert_eq!(work.used().rpc_calls, 64);
        let state = owner.state.lock().unwrap();
        assert!(state.cancelled.is_empty());
        assert!(state.quiet_until <= Instant::now());
        server.abort();
    }

    #[tokio::test]
    async fn authority_caps_authentication_cancellation_and_expiration_are_real() {
        let (owner, first, server, url) = serve(10, 1, Duration::from_millis(500)).await;
        let second = CoordinatorClient::new(
            CoordinatorConfig::new(&url, TOKEN).unwrap(),
            reqwest::Client::new(),
            first.scope,
        );
        let lease = first
            .acquire(true, false, Duration::from_millis(500), None)
            .await
            .unwrap();
        assert!(matches!(
            second
                .acquire(true, false, Duration::from_millis(500), None)
                .await,
            Err(crate::rfq::NativeRfqError::Saturated)
        ));
        lease.release();
        wait_for_cleanup(&first).await;
        let lease = second
            .acquire(true, false, Duration::from_millis(500), None)
            .await
            .unwrap();
        drop(lease);
        tokio::time::timeout(Duration::from_secs(2), async {
            while owner.metrics().active_firm_leases != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let abandoned = first
            .acquire(true, false, Duration::from_millis(500), None)
            .await
            .unwrap();
        std::mem::forget(abandoned); // controlled simulated process death
        tokio::time::sleep(Duration::from_millis(550)).await;
        assert_eq!(owner.metrics().active_firm_leases, 0);
        assert!(owner.metrics().expired >= 1);
        let wrong = CoordinatorClient::new(
            CoordinatorConfig::new(&url, "wrong-controlled-service-token-00000000").unwrap(),
            reqwest::Client::new(),
            first.scope,
        );
        assert!(matches!(
            wrong
                .acquire(true, false, Duration::from_millis(500), None)
                .await,
            Err(crate::rfq::NativeRfqError::Transport)
        ));
        let wrong_scope = CoordinatorClient::new(
            CoordinatorConfig::new(&url, TOKEN).unwrap(),
            reqwest::Client::new(),
            B256::repeat_byte(9),
        );
        assert!(
            wrong_scope
                .acquire(true, false, Duration::from_millis(500), None)
                .await
                .is_err()
        );
        server.abort();
    }
    #[tokio::test]
    async fn coordination_spends_actual_calls_body_bytes_and_compute_in_same_account() {
        let (owner, client, server, _) = serve(10, 1, Duration::from_secs(2)).await;
        let work = crate::work_budget::WorkBudget::bounded(
            crate::budget::SolverBudget::for_duration(Duration::from_secs(2)),
        );
        let lease = client
            .acquire(true, false, Duration::from_millis(500), Some(&work))
            .await
            .unwrap();
        let after = work.used();
        assert_eq!(after.rpc_calls, 1);
        assert!(after.rpc_bytes > 0);
        assert!(after.compute_ns > 0);
        work.cancel();
        drop(lease);
        tokio::time::timeout(Duration::from_secs(2), async {
            while owner.metrics().active_firm_leases != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(work.used().rpc_calls, 2);
        assert!(work.used().rpc_bytes > after.rpc_bytes);
        server.abort();
    }
    #[tokio::test]
    async fn rejected_acquire_admission_dispatches_neither_acquire_nor_spurious_cleanup() {
        let (owner, client, server, _) = serve(10, 1, Duration::from_secs(2)).await;
        let mut limits = crate::work_budget::WorkLimits::bounded_default();
        limits.rpc_calls = 1;
        let work = crate::work_budget::WorkBudget::new(
            crate::budget::SolverBudget::for_duration(Duration::from_secs(2)),
            limits,
        );
        assert!(matches!(
            client
                .acquire(true, false, Duration::from_millis(500), Some(&work))
                .await,
            Err(crate::rfq::NativeRfqError::WorkBudget)
        ));
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert_eq!(work.used().rpc_calls, 0);
        assert_eq!(owner.metrics().acquisitions, 0);
        assert_eq!(owner.metrics().releases, 0);
        server.abort();
    }
    #[tokio::test]
    async fn sustained_normal_releases_do_not_fill_cancellation_memory_or_stop_grants() {
        let owner = NativeQuotaAuthority::new(
            B256::repeat_byte(1),
            TOKEN,
            60,
            1,
            Duration::from_millis(30),
            Duration::from_secs(1),
        )
        .unwrap();
        for sequence in 0..(MAX_LEASES * 8) {
            let id = alloy::primitives::keccak256(sequence.to_le_bytes());
            owner
                .acquire(Acquire {
                    scope: owner.scope,
                    id,
                    firm: true,
                    pace: false,
                })
                .await
                .unwrap();
            owner
                .release(Release {
                    scope: owner.scope,
                    id,
                })
                .unwrap();
        }
        let state = owner.state.lock().unwrap();
        assert!(state.leases.is_empty());
        assert!(state.cancelled.is_empty());
        assert!(state.quiet_until <= Instant::now());
        assert_eq!(
            owner.metrics.lock().unwrap().acquisitions,
            (MAX_LEASES * 8) as u64
        );
    }
    #[tokio::test]
    async fn release_before_queued_grant_never_resurrects_and_restart_waits() {
        let owner = NativeQuotaAuthority::new(
            B256::repeat_byte(1),
            TOKEN,
            1,
            1,
            Duration::from_millis(30),
            Duration::from_secs(1),
        )
        .unwrap();
        let id = B256::repeat_byte(2);
        owner
            .release(Release {
                scope: owner.scope,
                id,
            })
            .unwrap();
        assert_eq!(
            owner
                .acquire(Acquire {
                    scope: owner.scope,
                    id,
                    firm: true,
                    pace: false
                })
                .await
                .unwrap_err(),
            StatusCode::CONFLICT
        );
        owner.state.lock().unwrap().quiet_until = Instant::now() + Duration::from_secs(1);
        assert_eq!(
            owner
                .acquire(Acquire {
                    scope: owner.scope,
                    id: B256::repeat_byte(3),
                    firm: true,
                    pace: false
                })
                .await
                .unwrap_err(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }
    // Run by the following parent fixture in a distinct OS process. This is
    // control-plane test configuration, no production credentials or API.
    #[tokio::test(flavor = "current_thread")]
    #[ignore = "spawned by separate-process authority test"]
    async fn process_client_worker() {
        let Ok(url) = std::env::var("SEXTANT_TEST_QUOTA_URL") else {
            return;
        };
        let client = CoordinatorClient::new(
            CoordinatorConfig::new(&url, TOKEN).unwrap(),
            reqwest::Client::new(),
            B256::repeat_byte(0xa4),
        );
        let mut limits = crate::work_budget::WorkLimits::bounded_default();
        limits.rpc_calls = 4;
        limits.rpc_bytes = 8192;
        limits.compute_ns = 1_000_000_000;
        let work = crate::work_budget::WorkBudget::new(
            crate::budget::SolverBudget::for_duration(Duration::from_secs(2)),
            limits,
        );
        let memory = sextant_io::process_memory::ProcessMemory::new(None, 0).unwrap();
        assert!(memory.sample().rss_bytes.is_some_and(|bytes| bytes > 0));
        for _ in 0..2 {
            client
                .acquire(false, true, Duration::from_millis(500), Some(&work))
                .await
                .unwrap()
                .release();
            wait_for_cleanup(&client).await;
        }
        assert_eq!(work.used().rpc_calls, limits.rpc_calls);
        assert!(work.used().rpc_bytes > 0 && work.used().rpc_bytes <= limits.rpc_bytes);
        assert!(work.used().compute_ns > 0 && work.used().compute_ns <= limits.compute_ns);
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn separate_processes_share_one_authoritative_dispatch_clock() {
        let (owner, _, server, url) = serve(10, 1, Duration::from_secs(2)).await;
        let exe = std::env::current_exe().unwrap();
        let mut children = Vec::new();
        for _ in 0..2 {
            children.push(
                tokio::process::Command::new(&exe)
                    .args([
                        "--exact",
                        "native_coordinator::tests::process_client_worker",
                        "--ignored",
                        "--nocapture",
                    ])
                    .env("SEXTANT_TEST_QUOTA_URL", &url)
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped())
                    .spawn()
                    .unwrap(),
            );
        }
        for child in children {
            let output = tokio::time::timeout(Duration::from_secs(10), child.wait_with_output())
                .await
                .unwrap()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        let admissions = owner.admissions.lock().unwrap();
        assert_eq!(admissions.len(), 4);
        assert!(
            admissions
                .windows(2)
                .all(|pair| pair[1].duration_since(pair[0]) >= Duration::from_millis(100))
        );
        assert_eq!(owner.metrics().active_leases, 0);
        server.abort();
    }
}
