pub mod intercept;
pub mod login;
pub mod passthrough;
pub mod routes;

use std::sync::Arc;

use axum::Router;
use axum::extract::{Request, State};
use axum::http::header;
use axum::response::Response;

use crate::config::Config;
use crate::crypto::device::{DeviceConflict, DeviceUnchecked};
use crate::error::ProxyError;
use crate::logbuf::LogBuffer;
use crate::session::{AccountContext, SessionManager};
use crate::upstream::Upstream;

use self::passthrough::passthrough;
use self::routes::{Route, classify};

/// Replaces the log filter of the running process (e.g. "debug",
/// "ement_e2ee=trace").
pub type LogControl = Arc<dyn Fn(&str) -> anyhow::Result<()> + Send + Sync>;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub upstream: Upstream,
    pub sessions: SessionManager,
    pub started: std::time::SystemTime,
    /// Recent log lines, for `ctl debug logs`.
    pub logs: Arc<LogBuffer>,
    /// None where this process does not own the logging setup.
    pub log_control: Option<LogControl>,
}

impl AppState {
    pub async fn new(config: Arc<Config>) -> anyhow::Result<Self> {
        let upstream = Upstream::new(config.homeserver.clone())?;
        Ok(Self {
            config,
            upstream,
            sessions: SessionManager::default(),
            started: std::time::SystemTime::now(),
            logs: Arc::default(),
            log_control: None,
        })
    }
}

pub fn router(state: AppState) -> Router {
    Router::new().fallback(handle).with_state(state)
}

/// Extract the client's access token (Authorization header or, legacy,
/// ?access_token= query parameter).
fn bearer_token(req: &Request) -> Option<String> {
    if let Some(token) = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
    {
        return Some(token.to_owned());
    }
    req.uri().query().and_then(|q| {
        q.split('&')
            .find_map(|kv| kv.strip_prefix("access_token=").map(ToOwned::to_owned))
    })
}

/// Get the account context for a token; on failure log and return None so
/// the caller can fall back to plain passthrough (the upstream will produce
/// the authoritative auth error). A session held back over its device's keys
/// is an error instead: its token is good, and passed through it would send
/// in the clear.
async fn context_for(
    state: &AppState,
    token: Option<String>,
) -> Result<Option<Arc<AccountContext>>, ProxyError> {
    let Some(token) = token else {
        return Ok(None);
    };
    let error = match state
        .sessions
        .get_or_init(&state.config, &state.upstream, &token)
        .await
    {
        Ok(ctx) => return Ok(Some(ctx)),
        Err(e) => e,
    };
    let error = match error.downcast::<DeviceConflict>() {
        Ok(conflict) => return Err(conflict.into()),
        Err(other) => other,
    };
    let error = match error.downcast::<DeviceUnchecked>() {
        Ok(unchecked) => return Err(unchecked.into()),
        Err(other) => other,
    };
    tracing::warn!(?error, "could not initialize session; passing through");
    Ok(None)
}

async fn handle(State(state): State<AppState>, req: Request) -> Result<Response, ProxyError> {
    let route = classify(req.method(), req.uri().path());
    tracing::trace!(method = %req.method(), path = %req.uri().path(), ?route, "request");
    // Token must be extracted before any await: holding &Request across an
    // await point would make this future non-Send.
    let token = bearer_token(&req);

    match route {
        Route::Admin(sub) => crate::admin::handle(&state, &sub, req).await,
        Route::Login => login::handle_login(&state, req).await,
        Route::Sync => match context_for(&state, token).await? {
            Some(ctx) => crate::crypto::sync::handle_sync(&state, ctx, req).await,
            None => passthrough(&state, req).await,
        },
        route @ (Route::Messages { .. }
        | Route::Context { .. }
        | Route::RoomEvent { .. }
        | Route::Notifications) => {
            match context_for(&state, token).await? {
                Some(ctx) => intercept::handle_history_get(&state, ctx, req, route).await,
                None => passthrough(&state, req).await,
            }
        }
        Route::Send {
            room_id,
            event_type,
            txn_id,
        } => match context_for(&state, token).await? {
            Some(ctx) => {
                crate::crypto::encrypt::handle_send(&state, ctx, req, room_id, event_type, txn_id)
                    .await
            }
            None => passthrough(&state, req).await,
        },
        Route::MediaUpload => match context_for(&state, token).await? {
            Some(ctx) => crate::crypto::media::handle_upload(&state, ctx, req).await,
            None => passthrough(&state, req).await,
        },
        Route::MediaDownload {
            server,
            media_id,
            authenticated,
        } => {
            // The legacy download path (used by ement for avatars) carries no
            // Bearer token; borrow any active session's upstream credentials.
            let ctx = if authenticated {
                context_for(&state, token).await?
            } else {
                state.sessions.list().await.into_iter().next()
            };
            match ctx {
                Some(ctx) => {
                    crate::crypto::media::handle_download(&state, ctx, server, media_id).await
                }
                None => passthrough(&state, req).await,
            }
        }
        // Everything else passes through unchanged.
        _ => passthrough(&state, req).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(uri: &str, authorization: Option<&str>) -> Request {
        let mut builder = Request::builder().uri(uri);
        if let Some(value) = authorization {
            builder = builder.header(header::AUTHORIZATION, value);
        }
        builder.body(axum::body::Body::empty()).unwrap()
    }

    #[test]
    fn bearer_token_from_header_or_query() {
        let req = request("/_matrix/client/r0/sync", Some("Bearer syt_abc"));
        assert_eq!(bearer_token(&req).as_deref(), Some("syt_abc"));

        // Legacy clients pass the token in the query string.
        let req = request("/_matrix/client/r0/sync?timeout=0&access_token=syt_q", None);
        assert_eq!(bearer_token(&req).as_deref(), Some("syt_q"));

        // The header wins when both are present.
        let req = request("/sync?access_token=query", Some("Bearer header"));
        assert_eq!(bearer_token(&req).as_deref(), Some("header"));
    }

    #[test]
    fn bearer_token_absent_or_unusable() {
        assert_eq!(bearer_token(&request("/sync", None)), None);
        assert_eq!(bearer_token(&request("/sync?timeout=0", None)), None);
        // Other auth schemes are not access tokens.
        assert_eq!(bearer_token(&request("/sync", Some("Basic dXNlcjpwYXNz"))), None);
        // A parameter that merely ends in the same name is not the token.
        assert_eq!(bearer_token(&request("/sync?not_access_token=x", None)), None);
    }
}
