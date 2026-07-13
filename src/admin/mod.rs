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
    let query = parse_query(req.uri().query());
    let parts: Vec<&str> = sub.split('/').filter(|s| !s.is_empty()).collect();
    match (method.as_str(), parts.as_slice()) {
        ("GET", ["status"]) => status(state).await,
        ("POST", ["bootstrap"]) => {
            let body = read_json_body(req).await?;
            bootstrap(state, body).await
        }
        ("GET", ["verify"]) => {
            let (ctx, with_user) = match verify_target(state, &query).await {
                Ok(t) => t,
                Err(response) => return Ok(response),
            };
            Ok(Json(crate::crypto::verify::list(&ctx, &with_user).await).into_response())
        }
        ("POST", ["verify", "start"]) => {
            let body = read_json_body(req).await?;
            let params = json_params(&body);
            let (ctx, _) = match verify_target(state, &params).await {
                Ok(t) => t,
                Err(response) => return Ok(response),
            };
            let Some(device_id) = params.get("device_id").cloned() else {
                return Ok(json_error(StatusCode::BAD_REQUEST, "missing device_id"));
            };
            verify_result(crate::crypto::verify::start(&ctx, &device_id).await)
        }
        ("GET", ["verify", flow]) => {
            let flow = (*flow).to_owned();
            let (ctx, with_user) = match verify_target(state, &query).await {
                Ok(t) => t,
                Err(response) => return Ok(response),
            };
            verify_result(crate::crypto::verify::show(&ctx, &with_user, &flow).await)
        }
        ("POST", ["verify", flow, action]) => {
            let flow = (*flow).to_owned();
            let action = (*action).to_owned();
            let body = read_json_body(req).await?;
            let params = json_params(&body);
            let (ctx, with_user) = match verify_target(state, &params).await {
                Ok(t) => t,
                Err(response) => return Ok(response),
            };
            use crate::crypto::verify;
            let result = match action.as_str() {
                "accept" => verify::accept(&ctx, &with_user, &flow).await,
                "start-sas" => verify::start_sas(&ctx, &with_user, &flow).await,
                "sas-accept" => verify::sas_accept(&ctx, &with_user, &flow).await,
                "confirm" => verify::confirm(&ctx, &with_user, &flow).await,
                "cancel" => verify::cancel(&ctx, &with_user, &flow).await,
                _ => {
                    return Ok(json_error(
                        StatusCode::NOT_FOUND,
                        format!("unknown verify action: {action}"),
                    ));
                }
            };
            verify_result(result)
        }
        _ => Ok(json_error(
            StatusCode::NOT_FOUND,
            format!("unknown admin route: {method} {sub}"),
        )),
    }
}

fn parse_query(query: Option<&str>) -> std::collections::HashMap<String, String> {
    query
        .unwrap_or_default()
        .split('&')
        .filter_map(|kv| {
            let (k, v) = kv.split_once('=')?;
            Some((k.to_owned(), v.to_owned()))
        })
        .collect()
}

fn json_params(body: &serde_json::Value) -> std::collections::HashMap<String, String> {
    body.as_object()
        .map(|o| {
            o.iter()
                .filter_map(|(k, v)| Some((k.clone(), v.as_str()?.to_owned())))
                .collect()
        })
        .unwrap_or_default()
}

/// Resolve the session and the "other user" of a verification from request
/// parameters (`user_id` selects the session, `with_user` the counterpart;
/// both default sensibly for the single-account own-device case).
async fn verify_target(
    state: &AppState,
    params: &std::collections::HashMap<String, String>,
) -> Result<(Arc<AccountContext>, ruma::OwnedUserId), Response> {
    let ctx = resolve_session(state, params.get("user_id").map(String::as_str)).await?;
    let with_user = match params.get("with_user") {
        Some(user) => user.parse().map_err(|_| {
            json_error(
                StatusCode::BAD_REQUEST,
                format!("invalid with_user: {user}"),
            )
        })?,
        None => ctx.user_id.clone(),
    };
    Ok((ctx, with_user))
}

fn verify_result(result: anyhow::Result<serde_json::Value>) -> Result<Response, ProxyError> {
    match result {
        Ok(value) => Ok(Json(value).into_response()),
        Err(e) => Ok(json_error(StatusCode::CONFLICT, format!("{e:#}"))),
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
