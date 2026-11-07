use crate::abi::tohex;
use crate::budget::SolverBudgetExceeded;
use crate::chain::ChainProfile;
use crate::quotes::{NoRouteError, QuoteRequest};
use crate::rfq::NativeRfqError;
use crate::rpc::{RpcRejected, RpcUnavailable};
use crate::rpc_dispatch::RpcCapacity;
use crate::simulation::SimulationFailed;
use crate::state::UpstreamIntegrityError;
use crate::topology::IndexerError;
use axum::body::Body;
use axum::http::header::RETRY_AFTER;
use axum::http::{HeaderValue, StatusCode};
use axum::response::Response;
use serde::Serialize;
use serde_json::json;

pub(super) const CORS_HEADERS: [(&str, &str); 4] = [
    ("Access-Control-Allow-Origin", "*"),
    ("Access-Control-Allow-Methods", "POST, GET, OPTIONS"),
    ("Access-Control-Allow-Headers", "Content-Type"),
    ("Access-Control-Expose-Headers", "Retry-After"),
];

const NO_ROUTE_SCHEMA_VERSION: u8 = 1;

pub(super) fn json_response<T: Serialize>(status: StatusCode, obj: &T) -> Response {
    let mut builder = Response::builder()
        .status(status)
        .header("Content-Type", "application/json");
    for (k, v) in CORS_HEADERS {
        builder = builder.header(k, v);
    }
    builder
        .body(Body::from(
            serde_json::to_vec(obj).expect("serializable response"),
        ))
        .expect("valid response")
}

pub(super) fn error_response(status: StatusCode, msg: String) -> Response {
    json_response(status, &json!({ "error": msg }))
}

pub(super) fn quote_error_response(
    status: StatusCode,
    profile: &ChainProfile,
    code: &'static str,
    msg: String,
    requested_chain_id: Option<u64>,
) -> Response {
    json_response(
        status,
        &json!({
            "error": msg,
            "code": code,
            "chain": profile.key,
            "chainId": profile.chain_id,
            "requestedChainId": requested_chain_id,
        }),
    )
}

pub(super) fn overloaded_response(profile: &ChainProfile) -> Response {
    let mut response = quote_error_response(
        StatusCode::SERVICE_UNAVAILABLE,
        profile,
        "overloaded",
        "solver is at capacity; retry shortly".to_string(),
        None,
    );
    response
        .headers_mut()
        .insert(RETRY_AFTER, HeaderValue::from_static("1"));
    response
}

pub(super) fn native_busy_response(
    profile: &ChainProfile,
    requested_chain_id: Option<u64>,
) -> Response {
    let mut response = quote_error_response(
        StatusCode::SERVICE_UNAVAILABLE,
        profile,
        "native_busy",
        "Native RFQ is at capacity; retry shortly".to_string(),
        requested_chain_id,
    );
    response
        .headers_mut()
        .insert(RETRY_AFTER, HeaderValue::from_static("1"));
    response
}

/// The built transaction reverted at the simulation block. Quote again; the
/// route, its state or the taker's funds changed.
pub(super) fn simulation_failed_response(
    profile: &ChainProfile,
    error: &SimulationFailed,
    requested_chain_id: Option<u64>,
) -> Response {
    json_response(
        StatusCode::UNPROCESSABLE_ENTITY,
        &json!({
            "error": error.to_string(),
            "code": "simulation_failed",
            "chain": profile.key,
            "chainId": profile.chain_id,
            "requestedChainId": requested_chain_id,
            "block": error.block.number,
            "blockHash": format!("{:#x}", error.block.hash),
            "revertSelector": error
                .revert
                .as_ref()
                .filter(|data| data.len() >= 4)
                .map(|data| tohex(&data[..4])),
        }),
    )
}

pub(super) fn no_route_response(
    profile: &ChainProfile,
    error: &NoRouteError,
    requested_chain_id: Option<u64>,
) -> Response {
    json_response(
        StatusCode::UNPROCESSABLE_ENTITY,
        &json!({
            "schemaVersion": NO_ROUTE_SCHEMA_VERSION,
            "error": error.to_string(),
            "code": "no_route",
            "chain": profile.key,
            "chainId": profile.chain_id,
            "requestedChainId": requested_chain_id,
            "routeUniverse": &error.route_universe,
        }),
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum QuoteGate {
    ChainMismatch(u64),
    QuotesUnavailable,
    ExecutionUnavailable,
}

pub(super) fn gate_quote_request(
    profile: &ChainProfile,
    req: &QuoteRequest,
) -> Result<(), QuoteGate> {
    if req.chain_id != profile.chain_id {
        return Err(QuoteGate::ChainMismatch(req.chain_id));
    }
    if !profile.capabilities.quote {
        return Err(QuoteGate::QuotesUnavailable);
    }
    if !profile.execution_enabled()
        && (req.recipient.is_some() || req.fee_bps.is_some_and(|fee_bps| fee_bps > 0))
    {
        return Err(QuoteGate::ExecutionUnavailable);
    }
    Ok(())
}

pub(super) fn quote_error_status(error: &anyhow::Error) -> StatusCode {
    if error.downcast_ref::<SolverBudgetExceeded>().is_some() {
        StatusCode::GATEWAY_TIMEOUT
    } else if error.downcast_ref::<NoRouteError>().is_some()
        || error.downcast_ref::<SimulationFailed>().is_some()
    {
        StatusCode::UNPROCESSABLE_ENTITY
    } else if error
        .downcast_ref::<NativeRfqError>()
        .is_some_and(NativeRfqError::is_retryable_capacity)
        || error.is::<RpcCapacity>()
    {
        StatusCode::SERVICE_UNAVAILABLE
    } else if error.downcast_ref::<RpcUnavailable>().is_some()
        || error.downcast_ref::<RpcRejected>().is_some()
        || error.downcast_ref::<IndexerError>().is_some()
        || error.downcast_ref::<UpstreamIntegrityError>().is_some()
    {
        StatusCode::BAD_GATEWAY
    } else {
        StatusCode::BAD_REQUEST
    }
}
