// HTTP surface: POST /quote, GET /health, and the operator-only
// POST /rpc-recovery when SOLVER_RPC_RECOVERY_TOKEN is set.

mod admission;
mod readiness;
mod recovery;
mod responses;
mod startup;

use crate::abi::addrhex;
use crate::budget::{SolverBudget, SolverBudgetExceeded};
use crate::chain::DiscoveryProfile;
use crate::config::Config;
use crate::engine::Engine;
use crate::indexer::IndexerClient;
use crate::quote_metrics::{QuoteMetrics, QuoteOutcome};
use crate::quotes::{NoRouteError, QuoteRequest, quote_swap_bounded};
use crate::rfq::{NativeRfqClient, NativeRfqError, NativeRfqSource};
use crate::rpc::{Rpc, sanitized_error};
use crate::rpc_dispatch::RpcCapacity;
use crate::simulation::SimulationFailed;
use admission::{
    QUEUED_QUOTES_PER_SLOT, admit_quote, compute_concurrency_from_env,
    max_inflight_quotes_from_env, quote_admission_wait_from_env, quote_time_limit,
};
use anyhow::Context;
use axum::Router;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderValue, StatusCode};
use axum::response::Response;
use axum::routing::{get, post};
use readiness::{
    READINESS_REFRESH, ReadinessState, app_is_ready, readiness, spawn_readiness_refresher,
};
use recovery::rpc_recovery_router;
use responses::{
    CORS_HEADERS, QuoteGate, error_response, gate_quote_request, json_response,
    native_busy_response, no_route_response, overloaded_response, quote_error_response,
    quote_error_status, simulation_failed_response,
};
use serde_json::json;
use startup::{
    NativeAdapter, configured_native_adapter, validate_config, verify_indexer_startup,
    verify_native_rfq_adapter, verify_quote_rpc, verify_rpc_chain, warmup_for_profile,
};
pub use startup::{configured_indexer, warmup};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex as AsyncMutex, Semaphore};

const MAX_QUOTE_REQUEST_BYTES: usize = 16 * 1024;
const QUOTE_BODY_READ_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_QUOTE_LOG_FIELD_BYTES: usize = 256;

fn quote_log_field(value: &str) -> String {
    let mut escaped = value.chars().flat_map(char::escape_default);
    let mut rendered: String = escaped.by_ref().take(MAX_QUOTE_LOG_FIELD_BYTES).collect();
    if escaped.next().is_some() {
        rendered.truncate(MAX_QUOTE_LOG_FIELD_BYTES - 3);
        rendered.push_str("...");
    }
    rendered
}

struct App {
    cfg: Config,
    rpc: Rpc,
    engine: Arc<Engine>,
    indexer: Option<Arc<IndexerClient>>,
    native_rfq: Option<Arc<dyn NativeRfqSource>>,
    native_adapter: Option<NativeAdapter>,
    quote_slots: Arc<Semaphore>,
    compute_slots: Arc<Semaphore>,
    memory: Arc<crate::process_memory::ProcessMemory>,
    chain_verified: bool,
    readiness: AsyncMutex<ReadinessState>,
    metrics: QuoteMetrics,
    /// Places for quotes waiting on `quote_slots`.
    quote_queue: Arc<Semaphore>,
    quote_admission_wait: Duration,
}

async fn handle_quote(State(app): State<Arc<App>>, request: Request) -> Response {
    let started = Instant::now();
    let rid = crate::quote_metrics::request_id(
        request
            .headers()
            .get("x-request-id")
            .and_then(|value| value.to_str().ok()),
    );
    let limit = quote_time_limit(
        app.cfg.quote_timeout,
        request
            .headers()
            .get("x-quote-timeout-ms")
            .and_then(|value| value.to_str().ok()),
    );
    let (mut response, outcome) = quote_response(&app, request, &rid, started, limit).await;
    app.metrics.record(
        outcome,
        started.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
    );
    if let Ok(value) = HeaderValue::from_str(&rid) {
        response.headers_mut().insert("x-request-id", value);
    }
    response
}

async fn quote_response(
    app: &Arc<App>,
    request: Request,
    rid: &str,
    started: Instant,
    limit: Duration,
) -> (Response, QuoteOutcome) {
    let deadline = started + limit;
    let body = match tokio::time::timeout(
        QUOTE_BODY_READ_TIMEOUT,
        axum::body::to_bytes(request.into_body(), MAX_QUOTE_REQUEST_BYTES),
    )
    .await
    {
        Ok(Ok(body)) => body,
        Ok(Err(_)) => {
            tracing::info!(
                "quote err request_id={rid} status=413 ms=0 error=request body too large"
            );
            return (
                quote_error_response(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    app.cfg.profile,
                    "bad_request",
                    format!("quote request body exceeds {MAX_QUOTE_REQUEST_BYTES} bytes"),
                    None,
                ),
                QuoteOutcome::BadRequest,
            );
        }
        Err(_) => {
            tracing::info!(
                "quote err request_id={rid} status=408 ms={} error=request body timed out",
                started.elapsed().as_millis()
            );
            return (
                quote_error_response(
                    StatusCode::REQUEST_TIMEOUT,
                    app.cfg.profile,
                    "bad_request",
                    "quote request body timed out".to_string(),
                    None,
                ),
                QuoteOutcome::BadRequest,
            );
        }
    };
    let req: QuoteRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            let error = quote_log_field(&e.to_string());
            tracing::info!(
                "quote err request_id={rid} status=400 ms=0 error=bad request body: {error}"
            );
            return (
                quote_error_response(
                    StatusCode::BAD_REQUEST,
                    app.cfg.profile,
                    "bad_request",
                    e.to_string(),
                    None,
                ),
                QuoteOutcome::BadRequest,
            );
        }
    };
    // Slow or malformed ingress must not reserve scarce quote-work capacity.
    // The per-request body bounds above protect parsing; this permit covers
    // every subsequent exit path, including readiness and upstream work.
    let _memory = match app.memory.admit() {
        Ok(permit) => permit,
        Err(_) => {
            return (
                overloaded_response(app.cfg.profile),
                QuoteOutcome::Overloaded,
            );
        }
    };
    let _quote_permit = match admit_quote(app, deadline).await {
        Some(permit) => permit,
        None => {
            tracing::info!(
                "quote rejected request_id={rid} status={} code=overloaded chain={} waited_ms={}",
                StatusCode::SERVICE_UNAVAILABLE.as_u16(),
                app.cfg.profile.chain_id,
                started.elapsed().as_millis()
            );
            return (
                overloaded_response(app.cfg.profile),
                QuoteOutcome::Overloaded,
            );
        }
    };
    if let Err(gate) = gate_quote_request(app.cfg.profile, &req) {
        let (status, code, message, requested) = match gate {
            QuoteGate::ChainMismatch(requested) => (
                StatusCode::CONFLICT,
                "chain_mismatch",
                format!(
                    "chainId mismatch: solver is {}, request is {requested}",
                    app.cfg.profile.chain_id
                ),
                Some(requested),
            ),
            QuoteGate::QuotesUnavailable => (
                StatusCode::NOT_IMPLEMENTED,
                "quotes_unavailable",
                app.cfg
                    .profile
                    .capabilities
                    .unavailable_reason
                    .unwrap_or("quotes are not enabled")
                    .to_string(),
                Some(req.chain_id),
            ),
            QuoteGate::ExecutionUnavailable => (
                StatusCode::NOT_IMPLEMENTED,
                "execution_unavailable",
                format!(
                    "transaction building is not enabled for {}",
                    app.cfg.profile.name
                ),
                Some(req.chain_id),
            ),
        };
        tracing::info!(
            "quote rejected request_id={rid} status={} code={code} chain={} requested={}",
            status.as_u16(),
            app.cfg.profile.chain_id,
            requested.map_or_else(|| "legacy".to_string(), |id| id.to_string())
        );
        return (
            quote_error_response(status, app.cfg.profile, code, message, requested),
            QuoteOutcome::Rejected,
        );
    }
    let current_readiness = readiness(app).await;
    if !app_is_ready(app, current_readiness) {
        tracing::info!(
            "quote rejected request_id={rid} status={} code=not_ready chain={}",
            StatusCode::SERVICE_UNAVAILABLE.as_u16(),
            app.cfg.profile.chain_id
        );
        return (
            quote_error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                app.cfg.profile,
                "not_ready",
                "solver readiness checks are failing".to_string(),
                Some(req.chain_id),
            ),
            QuoteOutcome::NotReady,
        );
    }
    let (tin, tout, amt) = (
        quote_log_field(&req.token_in),
        quote_log_field(&req.token_out),
        quote_log_field(&req.amount_in.to_string()),
    );
    let requested_chain_id = Some(req.chain_id);
    // The time spent reading, queueing and checking readiness counts.
    let quote_timeout = deadline.saturating_duration_since(Instant::now());
    let budget = SolverBudget::for_duration(quote_timeout);
    let timeout_cancellation = budget.clone();
    match tokio::time::timeout(
        quote_timeout,
        quote_swap_bounded(
            &app.cfg,
            &app.engine,
            req,
            budget,
            app.compute_slots.clone(),
            app.native_rfq.as_deref(),
        ),
    )
    .await
    {
        Ok(Ok(resp)) => {
            tracing::info!(
                "quote ok request_id={rid} {tin}->{tout} amount={amt} block={} legs={} gross={} ms={} snapshot_ms={} snapshot_rpc_calls={} source={} solve_ms={} encode_ms={} simulate_ms={} simulation={} repriced={} cert={} gap_bps={} catalog_gap_bps={} graph_gap_bps={} screened_connectors={} screened_pools={} coverage_gain={} coverage_used={} coverage_solves={} coverage_age_ms={} coverage_us={} cert_us={} universe_source={} fallback_stage={} fallback_reason={} universe_scope={} selection_scope={} selector={} protocol_mask={:#x} eligible={} connectors={} truncated={} widening_candidates={} widened={} widening_rounds={} widening_end={} widening_probe_us={} widening_left_out={} widening_thin_left_out={} widening_thin_kept={} universe_id={:#x} adjacency_fences={:?} topology_fences={:?}",
                resp.block,
                resp.route.len(),
                resp.amount_out_gross,
                started.elapsed().as_millis(),
                resp.meta.snapshot_ms,
                resp.meta.snapshot_rpc_calls,
                resp.meta.source,
                resp.meta.solve_ms,
                resp.meta.encode_ms,
                resp.meta.simulate_ms,
                resp.simulation
                    .as_ref()
                    .map_or("-", |simulation| simulation.status),
                resp.meta.repriced,
                resp.certificate.as_ref().map_or("off", |c| c.status),
                resp.certificate
                    .as_ref()
                    .and_then(|c| c.gap_bps.as_deref())
                    .unwrap_or("-"),
                resp.certificate
                    .as_ref()
                    .and_then(|c| c.catalog_gap_bps.as_deref())
                    .unwrap_or("-"),
                resp.certificate
                    .as_ref()
                    .and_then(|c| c.graph_gap_bps.as_deref())
                    .unwrap_or("-"),
                resp.meta.universe_screened_count,
                resp.certificate
                    .as_ref()
                    .and_then(|c| c.screened_pools)
                    .unwrap_or(0),
                // `-` means the coverage question went unasked or unfinished; a
                // measured `0` is a proof that no declined connector helps at
                // this size, so the two must not print alike.
                resp.meta
                    .coverage_gain
                    .map_or_else(|| "-".to_string(), |gain| gain.to_string()),
                resp.meta.coverage_used,
                resp.meta.coverage_solves,
                // Separates a verdict this quote measured from one it reused off
                // the topology lease. `coverage_us` cannot: a reused verdict and
                // a fast measurement both read as a small number.
                resp.meta
                    .coverage_age_ms
                    .map_or_else(|| "-".to_string(), |age| age.to_string()),
                resp.meta.coverage_us,
                resp.meta.certificate_us,
                resp.meta.universe_source,
                resp.meta.universe_fallback_stage.unwrap_or("-"),
                resp.meta.universe_fallback_reason.unwrap_or("-"),
                resp.meta.universe_scope,
                resp.meta.universe_selection_scope,
                resp.meta.universe_selector,
                resp.meta.universe_protocol_mask,
                resp.meta.universe_eligible_count,
                resp.meta.universe_connector_count,
                resp.meta.universe_shortlist_truncated,
                resp.meta.widening_candidates,
                if resp.meta.widened.is_empty() {
                    "-".to_string()
                } else {
                    resp.meta
                        .widened
                        .iter()
                        .map(|token| format!("{token:#x}"))
                        .collect::<Vec<_>>()
                        .join(",")
                },
                resp.meta.widening_rounds,
                resp.meta.widening_end,
                resp.meta.widening_probe_us,
                resp.meta.widening_left_out,
                resp.meta.widening_thin_left_out,
                resp.meta.widening_thin_kept,
                resp.meta.universe_fingerprint,
                resp.meta.adjacency_fences,
                resp.meta.topology_fences,
            );
            app.metrics
                .record_stages(resp.meta.snapshot_ms, resp.meta.simulate_ms);
            (json_response(StatusCode::OK, &resp), QuoteOutcome::Ok)
        }
        Ok(Err(e)) => {
            if e.downcast_ref::<SolverBudgetExceeded>().is_some() {
                tracing::info!(
                    "quote err request_id={rid} {tin}->{tout} amount={amt} status=504 ms={} error=compute deadline exceeded",
                    started.elapsed().as_millis()
                );
                return (
                    quote_error_response(
                        StatusCode::GATEWAY_TIMEOUT,
                        app.cfg.profile,
                        "quote_timeout",
                        format!("quote timed out after {} ms", limit.as_millis()),
                        requested_chain_id,
                    ),
                    QuoteOutcome::Timeout,
                );
            }
            if let Some(no_route) = e.downcast_ref::<NoRouteError>() {
                let universe = &no_route.route_universe;
                tracing::info!(
                    "quote no_route request_id={rid} {tin}->{tout} amount={amt} status=422 ms={} block={} universe_source={} fallback_stage={} fallback_reason={} universe_scope={} selection_scope={} selector={} protocol_mask={:#x} eligible={} connectors={} truncated={} universe_id={} adjacency_fences={:?} topology_fences={:?}",
                    started.elapsed().as_millis(),
                    universe.canonical_block.number,
                    universe.source,
                    universe.fallback_stage.unwrap_or("-"),
                    universe.fallback_reason.unwrap_or("-"),
                    universe.scope,
                    universe.selection_scope,
                    universe.selector,
                    universe.protocol_mask,
                    universe.eligible_count,
                    universe.connector_count,
                    universe.shortlist_truncated,
                    universe.fingerprint,
                    universe.adjacency_fences,
                    universe.topology_fences,
                );
                return (
                    no_route_response(app.cfg.profile, no_route, requested_chain_id),
                    QuoteOutcome::NoRoute,
                );
            }
            if let Some(failed) = e.downcast_ref::<SimulationFailed>() {
                tracing::info!(
                    "quote simulation_failed request_id={rid} {tin}->{tout} amount={amt} status=422 ms={} error={}",
                    started.elapsed().as_millis(),
                    quote_log_field(&failed.to_string())
                );
                return (
                    simulation_failed_response(app.cfg.profile, failed, requested_chain_id),
                    QuoteOutcome::SimulationFailed,
                );
            }
            if e.downcast_ref::<NativeRfqError>()
                .is_some_and(NativeRfqError::is_retryable_capacity)
            {
                tracing::info!(
                    "quote err request_id={rid} {tin}->{tout} amount={amt} status=503 ms={} error=native capacity",
                    started.elapsed().as_millis()
                );
                return (
                    native_busy_response(app.cfg.profile, requested_chain_id),
                    QuoteOutcome::NativeBusy,
                );
            }
            if e.is::<RpcCapacity>() {
                tracing::info!(
                    "quote err request_id={rid} {tin}->{tout} amount={amt} status=503 ms={} error=rpc capacity",
                    started.elapsed().as_millis()
                );
                return (
                    overloaded_response(app.cfg.profile),
                    QuoteOutcome::RpcCapacity,
                );
            }
            // 502 when the failure came from the RPC, whether the transport
            // failed or the node returned a non-retryable JSON-RPC rejection;
            // 400 is reserved for request and solver-domain errors.
            // Never expose the transport error chain for upstream failures:
            // provider errors may contain the paid endpoint URL.
            let status = quote_error_status(&e);
            let message = sanitized_error(&e);
            let log_message = quote_log_field(&message);
            tracing::info!(
                "quote err request_id={rid} {tin}->{tout} amount={amt} status={} ms={} error={log_message}",
                status.as_u16(),
                started.elapsed().as_millis()
            );
            (
                quote_error_response(
                    status,
                    app.cfg.profile,
                    "quote_failed",
                    message,
                    requested_chain_id,
                ),
                QuoteOutcome::Error,
            )
        }
        Err(_) => {
            timeout_cancellation.cancel();
            tracing::info!(
                "quote err request_id={rid} {tin}->{tout} amount={amt} status=504 ms={} error=timed out",
                started.elapsed().as_millis()
            );
            (
                quote_error_response(
                    StatusCode::GATEWAY_TIMEOUT,
                    app.cfg.profile,
                    "quote_timeout",
                    format!("quote timed out after {} ms", limit.as_millis()),
                    requested_chain_id,
                ),
                QuoteOutcome::Timeout,
            )
        }
    }
}

async fn handle_health(State(app): State<Arc<App>>) -> Response {
    let readiness = readiness(&app).await;
    let ready = app_is_ready(&app, readiness);
    let pairs: Vec<_> = app
        .engine
        .status()
        .iter()
        .map(|p| {
            json!({
                "pair": format!("{}/{}", addrhex(p.tokens.0), addrhex(p.tokens.1)),
                "block": p.block,
                "ageMs": p.age.as_millis() as u64,
                "hot": p.hot,
            })
        })
        .collect();
    let mut protocols = app.cfg.profile.quote_protocols();
    if app.native_rfq.is_some() {
        protocols.push("nativerfq");
    }
    let native_config = app.cfg.native_rfq.as_ref();
    json_response(
        if ready {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        },
        &json!({
            "ok": true,
            "ready": ready,
            "chainVerified": app.chain_verified,
            "rpcReady": readiness.rpc_ready,
            "indexerReady": readiness.indexer_ready,
            "chain": app.cfg.profile.key,
            "chainId": app.cfg.profile.chain_id,
            "processMemory": app.memory.sample(),
            "capabilities": {
                "quote": app.cfg.profile.capabilities.quote,
                "execution": app.cfg.profile.execution_enabled(),
                "protocols": protocols,
                "nativeRfq": {
                    "supported": app.cfg.profile.native_supported(),
                    "configured": app.native_rfq.is_some(),
                    "mode": "single_native_stage",
                    "qps": native_config.map(|config| config.qps()),
                    "queueWaitMs": native_config
                        .map(|config| config.queue_wait().as_millis() as u64),
                    "maxInflight": native_config.map(|config| config.max_inflight()),
                    "quotaScope": native_config.map(|config| config.quota_mode()),
                },
                "poolDiscovery": app.cfg.profile.pool_discovery(),
                "routeUniverseMode": crate::state::dynamic_connector_mode(),
                "connectorScreening": crate::state::connector_screening(),
                "rankedConnectors": crate::state::ranked_connectors(),
                "connectorAdmission": crate::state::connector_admission(),
                "connectorMinBps": crate::state::connector_min_bps_e4(),
            },
            "rpc": {
                "unknownDispatches": app.rpc.unknown_dispatches(),
                "unknownEpoch": app.rpc.unknown_dispatch_epoch(),
            },
            "quotes": app.metrics.json(),
            "resident": app
                .engine
                .resident()
                .map_or_else(|| json!({"enabled": false}), |resident| resident.health()),
            "pairs": pairs,
        }),
    )
}

/// The quote counters and timings, and the capacity they ran against, in
/// Prometheus text. The listener is private to the backend's network, as
/// `/health` is.
async fn handle_metrics(State(app): State<Arc<App>>) -> Response {
    let mut text = String::new();
    app.metrics.prometheus(&mut text);
    text.push_str("# HELP solver_quote_slots_available Quote slots free now.\n# TYPE solver_quote_slots_available gauge\n");
    text.push_str(&format!(
        "solver_quote_slots_available {}\n",
        app.quote_slots.available_permits()
    ));
    text.push_str("# HELP solver_rpc_unknown_dispatches RPC requests whose outcome is unknown, each holding its slot.\n# TYPE solver_rpc_unknown_dispatches gauge\n");
    text.push_str(&format!(
        "solver_rpc_unknown_dispatches {}\n",
        app.rpc.unknown_dispatches()
    ));
    if let Some(resident) = app.engine.resident() {
        resident.prometheus(&mut text);
    }
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/plain; version=0.0.4")
        .body(Body::from(text))
        .expect("valid response")
}

async fn preflight() -> Response {
    let mut builder = Response::builder().status(StatusCode::NO_CONTENT);
    for (k, v) in CORS_HEADERS {
        builder = builder.header(k, v);
    }
    builder.body(Body::empty()).expect("valid response")
}

async fn fallback() -> Response {
    error_response(StatusCode::NOT_FOUND, "not found".to_string())
}

fn router(app: Arc<App>) -> Router {
    Router::new()
        .route("/quote", post(handle_quote).options(preflight))
        .route("/health", get(handle_health).options(preflight))
        .route("/metrics", get(handle_metrics))
        .fallback(fallback)
        .with_state(app)
}

async fn shutdown_signal() {
    let ctrl_c = async { tokio::signal::ctrl_c().await.expect("ctrl_c handler") };
    #[cfg(unix)]
    let term = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("sigterm handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {},
        _ = term => {},
    }
}

pub async fn serve(cfg: Config) -> anyhow::Result<()> {
    validate_config(&cfg)?;
    let native_adapter = cfg
        .native_rfq
        .as_ref()
        .map(|_| configured_native_adapter(cfg.profile))
        .transpose()?;
    let compute_concurrency = compute_concurrency_from_env()?;
    let max_inflight_quotes = max_inflight_quotes_from_env(compute_concurrency)?;
    let quote_admission_wait = quote_admission_wait_from_env()?;
    crate::state::validate_settings(
        cfg.profile,
        (cfg.profile.discovery == DiscoveryProfile::Robinhood).then_some(cfg.logs_rpc_url.as_str()),
    )?;
    sextant_route::validate_settings()?;
    crate::quotes::validate_settings()?;
    if cfg.profile.capabilities.quote {
        warmup_for_profile(cfg.profile)?;
    }
    let rpc = Rpc::connect(&cfg.rpc_url)?;
    verify_quote_rpc(&rpc, cfg.profile).await?;
    if let Some(config) = cfg.native_rfq.as_ref() {
        verify_native_rfq_adapter(
            &rpc,
            cfg.profile,
            native_adapter.context("Native RFQ startup adapter unavailable")?,
            config.authorizer().address(),
        )
        .await
        .context("Native RFQ startup identity check failed")?;
    }
    let native_rfq = cfg
        .native_rfq
        .clone()
        .map(|config| NativeRfqClient::new(config, rpc.clone()))
        .transpose()?
        .map(|client| Arc::new(client) as Arc<dyn NativeRfqSource>);
    let indexer = configured_indexer(&cfg)?;
    if let Some(indexer) = indexer.as_deref() {
        verify_indexer_startup(cfg.profile, indexer)
            .await
            .context("pool indexer startup check failed")?;
    } else if cfg.profile.pool_discovery() == "factories" {
        crate::state::verify_factory_discovery(cfg.profile, &rpc)
            .await
            .context("factory pool discovery startup check failed")?;
    }
    if cfg.profile.discovery == DiscoveryProfile::Robinhood {
        let logs_rpc = Rpc::connect(&cfg.logs_rpc_url)?;
        verify_rpc_chain(&logs_rpc, cfg.profile.chain_id, "logs").await?;
        crate::state::configure_logs_rpc(logs_rpc)?;
    }
    // Resident pool state starts reading in the background; until its first
    // block is published every quote takes the per-pair path.
    let resident = match crate::resident::Settings::from_env(cfg.profile)? {
        Some(settings) => {
            let resident = crate::resident::Resident::new(cfg.profile, rpc.clone(), settings)?;
            resident.spawn();
            Some(resident)
        }
        None => None,
    };
    let resident_mode = if resident.is_some() { "on" } else { "off" };
    let engine =
        Engine::for_profile_with_resident(rpc.clone(), cfg.profile, indexer.clone(), resident);
    tracing::info!(
        "sextant listening port={} chain={} chain_id={} rpc={} resident={} route_universe_mode={} compute_concurrency={} max_inflight_quotes={} quote_admission_wait_ms={}",
        cfg.port,
        cfg.profile.key,
        cfg.profile.chain_id,
        if cfg.rpc_url == cfg.profile.public_rpc {
            "public"
        } else {
            "private"
        },
        resident_mode,
        crate::state::dynamic_connector_mode(),
        compute_concurrency,
        max_inflight_quotes,
        quote_admission_wait.as_millis(),
    );
    let compute_slots = Arc::new(Semaphore::new(compute_concurrency));
    let memory = crate::process_memory::ProcessMemory::from_env()?;
    memory.start();
    let quota_router = crate::native_coordinator::NativeQuotaAuthority::configured_router(
        cfg.native_rfq.as_ref(),
    )?;
    let recovery_router = rpc_recovery_router(rpc.clone())?;
    let app = Arc::new(App {
        metrics: QuoteMetrics::default(),
        cfg: cfg.clone(),
        rpc,
        engine,
        indexer,
        native_rfq,
        native_adapter,
        quote_slots: Arc::new(Semaphore::new(max_inflight_quotes)),
        quote_queue: Arc::new(Semaphore::new(max_inflight_quotes * QUEUED_QUOTES_PER_SLOT)),
        quote_admission_wait,
        compute_slots,
        memory,
        chain_verified: true,
        readiness: AsyncMutex::new(ReadinessState::new(true, true)),
    });
    spawn_readiness_refresher(&app, READINESS_REFRESH);
    let listener = tokio::net::TcpListener::bind(("0.0.0.0", cfg.port)).await?;
    axum::serve(
        listener,
        router(app).merge(quota_router).merge(recovery_router),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests;
