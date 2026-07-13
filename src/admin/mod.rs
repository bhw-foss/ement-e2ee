pub mod ctl;

use std::sync::Arc;

use axum::Json;
use axum::extract::Request;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};

use crate::error::ProxyError;
use crate::proxy::AppState;
use crate::session::AccountContext;

fn json_error(status: StatusCode, message: impl std::fmt::Display) -> Response {
    (
        status,
        Json(serde_json::json!({"error": message.to_string()})),
    )
        .into_response()
}

/// Handle a request under /_ement/.
pub async fn handle(state: &AppState, sub: &str, req: Request) -> Result<Response, ProxyError> {
    if let Some(expected) = &state.config.admin_token {
        let ok = req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .is_some_and(|t| t == expected);
        if !ok {
            return Ok(json_error(
                StatusCode::UNAUTHORIZED,
                "missing or invalid admin token",
            ));
        }
    }

    let method = req.method().clone();
    match (method.as_str(), sub) {
        ("GET", "status") => status(state).await,
        ("POST", "bootstrap") => {
            let body = read_json_body(req).await?;
            bootstrap(state, body).await
        }
        _ => Ok(json_error(
            StatusCode::NOT_FOUND,
            format!("unknown admin route: {method} {sub}"),
        )),
    }
}

async fn read_json_body(req: Request) -> Result<serde_json::Value, ProxyError> {
    let bytes = axum::body::to_bytes(req.into_body(), 1024 * 1024)
        .await
        .map_err(|e| ProxyError::BadRequest(format!("failed to read body: {e}")))?;
    if bytes.is_empty() {
        return Ok(serde_json::Value::Null);
    }
    serde_json::from_slice(&bytes)
        .map_err(|e| ProxyError::BadRequest(format!("body is not JSON: {e}")))
}

/// Pick the session an admin command applies to: an explicit user_id, or the
/// only active session.
pub async fn resolve_session(
    state: &AppState,
    user_id: Option<&str>,
) -> Result<Arc<AccountContext>, Response> {
    let sessions = state.sessions.list().await;
    match user_id {
        Some(user_id) => sessions
            .into_iter()
            .find(|ctx| ctx.user_id.as_str() == user_id)
            .ok_or_else(|| {
                json_error(
                    StatusCode::NOT_FOUND,
                    format!("no active session for {user_id}"),
                )
            }),
        None => match sessions.len() {
            0 => Err(json_error(
                StatusCode::CONFLICT,
                "no active sessions — connect ement through the proxy first",
            )),
            1 => Ok(sessions.into_iter().next().unwrap()),
            _ => Err(json_error(
                StatusCode::CONFLICT,
                format!(
                    "multiple sessions active, pass user_id: {}",
                    sessions
                        .iter()
                        .map(|c| c.user_id.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            )),
        },
    }
}

async fn status(state: &AppState) -> Result<Response, ProxyError> {
    let mut sessions = Vec::new();
    for ctx in state.sessions.list().await {
        let cross_signing = ctx.olm.cross_signing_status().await;
        let backup_machine = ctx.olm.backup_machine();
        let backup_keys = backup_machine.get_backup_keys().await.ok();
        sessions.push(serde_json::json!({
            "user_id": ctx.user_id.as_str(),
            "device_id": ctx.device_id.as_str(),
            "identity_keys": ctx.olm.identity_keys(),
            "cross_signing": {
                "has_master": cross_signing.has_master,
                "has_self_signing": cross_signing.has_self_signing,
                "has_user_signing": cross_signing.has_user_signing,
            },
            "backup": {
                "enabled": backup_machine.enabled().await,
                "version": backup_keys.and_then(|k| k.backup_version),
            },
        }));
    }
    let body = serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "homeserver": state.config.homeserver.to_string(),
        "sessions": sessions,
    });
    Ok(Json(body).into_response())
}

async fn bootstrap(state: &AppState, body: serde_json::Value) -> Result<Response, ProxyError> {
    let recovery_key = body
        .get("recovery_key")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ProxyError::BadRequest("missing recovery_key".into()))?;
    let user_id = body.get("user_id").and_then(|v| v.as_str());

    let ctx = match resolve_session(state, user_id).await {
        Ok(ctx) => ctx,
        Err(response) => return Ok(response),
    };

    match crate::crypto::ssss::bootstrap(&ctx, recovery_key).await {
        Ok(report) => Ok(Json(serde_json::to_value(report).unwrap()).into_response()),
        Err(e) => {
            tracing::error!(error = ?e, "bootstrap failed");
            Ok(json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("{e:#}"),
            ))
        }
    }
}
