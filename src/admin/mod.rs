pub mod ctl;

use axum::Json;
use axum::extract::Request;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};

use crate::error::ProxyError;
use crate::proxy::AppState;

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
            return Ok((
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": "missing or invalid admin token"})),
            )
                .into_response());
        }
    }

    match (req.method().as_str(), sub) {
        ("GET", "status") => status(state).await,
        _ => Ok((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": format!("unknown admin route: {sub}")})),
        )
            .into_response()),
    }
}

async fn status(state: &AppState) -> Result<Response, ProxyError> {
    let mut sessions = Vec::new();
    for ctx in state.sessions.list().await {
        sessions.push(serde_json::json!({
            "user_id": ctx.user_id.as_str(),
            "device_id": ctx.device_id.as_str(),
            "identity_keys": ctx.olm.identity_keys(),
        }));
    }
    let body = serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "homeserver": state.config.homeserver.to_string(),
        "sessions": sessions,
    });
    Ok(Json(body).into_response())
}
