use axum::body::Body;
use axum::extract::Request;
use axum::http::header;
use axum::response::Response;
use ruma::UserId;

use crate::crypto::{device, machine};
use crate::error::ProxyError;
use crate::proxy::AppState;

/// Intercept POST /login: forward it, with the device ID the proxy has
/// chosen for it, and on success eagerly create the account context so device
/// keys are uploaded before the first sync.
pub async fn handle_login(state: &AppState, req: Request) -> Result<Response, ProxyError> {
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_owned())
        .unwrap_or_else(|| "/".to_owned());

    let body_bytes = axum::body::to_bytes(req.into_body(), 1024 * 1024)
        .await
        .map_err(|e| ProxyError::BadRequest(format!("failed to read login body: {e}")))?;

    // ement asks for the same device ID on every login. Which device this
    // login continues, if any, depends on the stores at hand.
    let plan = device::plan_login(&state.config.store_dir, &body_bytes);
    let upstream_body = match plan.body {
        Some(body) => body.into(),
        None => body_bytes,
    };

    let upstream_resp = state
        .upstream
        .http
        .post(state.upstream.url(&path_and_query))
        .header(header::CONTENT_TYPE, "application/json")
        .body(upstream_body)
        .send()
        .await?;

    let status = upstream_resp.status();
    let content_type = upstream_resp.headers().get(header::CONTENT_TYPE).cloned();
    let bytes = upstream_resp.bytes().await?;

    if status.is_success() {
        match serde_json::from_slice::<serde_json::Value>(&bytes) {
            Ok(json) => {
                if let Some(requested) = &plan.requested {
                    note_device(state, &json, requested);
                }
                if let Err(e) = state
                    .sessions
                    .insert_from_login(&state.config, &state.upstream, &json)
                    .await
                {
                    // Crypto will be retried lazily via whoami on first sync.
                    tracing::warn!(error = ?e, "login succeeded but session init failed");
                }
            }
            Err(e) => tracing::warn!(error = ?e, "login response is not JSON"),
        }
    }

    let mut builder = Response::builder().status(status.as_u16());
    if let Some(ct) = content_type {
        builder = builder.header(header::CONTENT_TYPE, ct);
    }
    builder
        .body(Body::from(bytes))
        .map_err(|e| ProxyError::Internal(e.into()))
}

/// Where a login got another device ID than the client asked for, note which
/// one, so that the next login asking for the same finds this device again.
fn note_device(state: &AppState, login_response: &serde_json::Value, requested: &str) {
    let (Some(user_id), Some(device_id)) = (
        login_response["user_id"]
            .as_str()
            .and_then(|user_id| <&UserId>::try_from(user_id).ok()),
        login_response["device_id"].as_str(),
    ) else {
        return;
    };
    if device_id == requested {
        return;
    }
    tracing::info!(device_id, requested, "login: the proxy chose the device ID");
    let dir = machine::account_store_dir(&state.config, user_id, device_id.into());
    if let Err(e) = device::record_login(&dir, device_id, requested) {
        tracing::warn!(error = ?e, "could not note the login's device");
    }
}
