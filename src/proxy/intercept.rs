use std::sync::Arc;

use anyhow::Context as _;
use axum::body::Body;
use axum::extract::Request;
use axum::http::header;
use axum::response::Response;
use ruma::OwnedRoomId;

use crate::crypto::decrypt;
use crate::error::ProxyError;
use crate::proxy::AppState;
use crate::proxy::routes::Route;
use crate::session::AccountContext;

/// Build a response from raw bytes, preserving the upstream content type.
pub fn raw_response(
    status: u16,
    content_type: Option<header::HeaderValue>,
    bytes: Vec<u8>,
) -> Result<Response, ProxyError> {
    let mut builder = Response::builder().status(status);
    if let Some(ct) = content_type {
        builder = builder.header(header::CONTENT_TYPE, ct);
    }
    builder
        .body(Body::from(bytes))
        .map_err(|e| ProxyError::Internal(e.into()))
}

/// Forward a GET request upstream with the session's token and parse the JSON
/// response. Returns Err(raw response) for non-success statuses so callers can
/// relay upstream errors verbatim.
pub async fn forward_get_json(
    state: &AppState,
    ctx: &AccountContext,
    path_and_query: &str,
) -> Result<Result<(Option<header::HeaderValue>, serde_json::Value), Response>, ProxyError> {
    let upstream_resp = state
        .upstream
        .http
        .get(state.upstream.url(path_and_query))
        .bearer_auth(&ctx.token)
        .send()
        .await?;

    let status = upstream_resp.status();
    let content_type = upstream_resp.headers().get(header::CONTENT_TYPE).cloned();
    let bytes = upstream_resp.bytes().await?;

    if !status.is_success() {
        return Ok(Err(raw_response(
            status.as_u16(),
            content_type,
            bytes.to_vec(),
        )?));
    }
    let body: serde_json::Value =
        serde_json::from_slice(&bytes).context("upstream response is not valid JSON")?;
    Ok(Ok((content_type, body)))
}

/// Intercept history-fetching GETs (/messages, /context/{e}, /event/{e}) and
/// decrypt any m.room.encrypted events in the response.
pub async fn handle_history_get(
    state: &AppState,
    ctx: Arc<AccountContext>,
    req: Request,
    route: Route,
) -> Result<Response, ProxyError> {
    // Extract what we need and drop the request: holding &Request across an
    // await would make this future non-Send.
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_owned())
        .unwrap_or_else(|| "/".to_owned());
    drop(req);

    let (content_type, mut body) = match forward_get_json(state, &ctx, &path_and_query).await? {
        Ok(ok) => ok,
        Err(error_response) => return Ok(error_response),
    };

    let room_id: Option<OwnedRoomId> = match &route {
        Route::Messages { room_id } | Route::Context { room_id } | Route::RoomEvent { room_id } => {
            room_id.parse().ok()
        }
        _ => None,
    };

    if let Some(room_id) = room_id {
        match route {
            Route::Messages { .. } => {
                decrypt::process_messages_body(&ctx, &room_id, &mut body).await
            }
            Route::Context { .. } => decrypt::process_context_body(&ctx, &room_id, &mut body).await,
            Route::RoomEvent { .. } => decrypt::process_event_body(&ctx, &room_id, &mut body).await,
            _ => {}
        }
    }

    let bytes =
        serde_json::to_vec(&body).map_err(|e| ProxyError::Internal(anyhow::Error::from(e)))?;
    raw_response(200, content_type, bytes)
}
