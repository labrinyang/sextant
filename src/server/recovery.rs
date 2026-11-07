use super::responses::json_response;
use crate::rpc::Rpc;
use alloy_primitives::keccak256;
use axum::Router;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::post;
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;

struct RpcRecovery {
    rpc: Rpc,
    token: Vec<u8>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RpcRecoveryRequest {
    expected_unknown_epoch: u64,
    provider_termination_confirmed: bool,
    evidence_reference: String,
}

/// An RPC request whose outcome is unknown keeps its dispatch slot, because
/// the provider may still be running it. Only an operator holding the
/// provider's confirmation that every unresolved request has ended releases
/// that debt, for the epoch /health reported. Without a token there is no route.
pub(super) fn rpc_recovery_router(rpc: Rpc) -> anyhow::Result<Router> {
    let token = crate::chain::env_or("SOLVER_RPC_RECOVERY_TOKEN", "")?;
    if token.is_empty() {
        return Ok(Router::new());
    }
    let service_token = crate::chain::env_or("SOLVER_SERVICE_TOKEN", "")?;
    anyhow::ensure!(
        token.len() >= 32 && token != service_token,
        "SOLVER_RPC_RECOVERY_TOKEN must have at least 32 bytes and differ from SOLVER_SERVICE_TOKEN"
    );
    Ok(Router::new()
        .route("/rpc-recovery", post(handle_rpc_recovery))
        .with_state(Arc::new(RpcRecovery {
            rpc,
            token: token.into_bytes(),
        })))
}

fn token_matches(expected: &[u8], actual: &[u8]) -> bool {
    let mut difference = expected.len() ^ actual.len();
    for (index, byte) in expected.iter().enumerate() {
        difference |= usize::from(*byte ^ actual.get(index).copied().unwrap_or(0));
    }
    difference == 0 && !expected.is_empty()
}

async fn handle_rpc_recovery(
    State(recovery): State<Arc<RpcRecovery>>,
    request: Request,
) -> Response {
    let bearer = request
        .headers()
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .unwrap_or("");
    if !token_matches(&recovery.token, bearer.as_bytes()) {
        return json_response(
            StatusCode::UNAUTHORIZED,
            &json!({"code": "unauthorized_rpc_recovery"}),
        );
    }
    let invalid = || {
        json_response(
            StatusCode::BAD_REQUEST,
            &json!({"code": "invalid_recovery_evidence"}),
        )
    };
    let body = match tokio::time::timeout(
        Duration::from_secs(2),
        axum::body::to_bytes(request.into_body(), 4096),
    )
    .await
    {
        Ok(Ok(body)) => body,
        _ => return invalid(),
    };
    let Ok(receipt) = serde_json::from_slice::<RpcRecoveryRequest>(&body) else {
        return invalid();
    };
    if !receipt.provider_termination_confirmed
        || receipt.evidence_reference.trim().is_empty()
        || receipt.evidence_reference.len() > 512
    {
        return invalid();
    }
    match recovery
        .rpc
        .reconcile_unknown_dispatches(receipt.expected_unknown_epoch)
    {
        Ok(released) => {
            // The log keeps only a digest of the operator's evidence.
            let evidence = keccak256(receipt.evidence_reference.as_bytes());
            tracing::warn!(
                "RPC operator recovery epoch={} released={released} evidence={evidence:#x}",
                receipt.expected_unknown_epoch
            );
            json_response(
                StatusCode::OK,
                &json!({
                    "releasedUnknownDispatches": released,
                    "unknownEpoch": recovery.rpc.unknown_dispatch_epoch(),
                    "evidenceHash": format!("{evidence:#x}"),
                }),
            )
        }
        Err(_) => json_response(
            StatusCode::CONFLICT,
            &json!({"code": "rpc_recovery_epoch_conflict"}),
        ),
    }
}
