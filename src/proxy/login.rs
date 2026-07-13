use axum::body::Body;
use axum::extract::Request;
use axum::http::header;
use axum::response::Response;

use crate::error::ProxyError;
use crate::proxy::AppState;

/// Intercept POST /login: forward verbatim, and on success eagerly create the
/// account context so device keys are uploaded before the first sync.
pub async fn handle_login(state: &AppState, req: Request) -> Result<Response, ProxyError> {
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_owned())
        .unwrap_or_else(|| "/".to_owned());

    let body_bytes = axum::body::to_bytes(req.into_body(), 1024 * 1024)
        .await
        .map_err(|e| ProxyError::BadRequest(format!("failed to read login body: {e}")))?;

    let upstream_resp = state
        .upstream
        .http
        .post(state.upstream.url(&path_and_query))
        .header(header::CONTENT_TYPE, "application/json")
        .body(body_bytes)
        .send()
        .await?;

    let status = upstream_resp.status();
    let content_type = upstream_resp.headers().get(header::CONTENT_TYPE).cloned();
    let bytes = upstream_resp.bytes().await?;

    if status.is_success() {
        match serde_json::from_slice::<serde_json::Value>(&bytes) {
            Ok(json) => {
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
