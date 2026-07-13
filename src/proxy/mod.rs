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
use crate::error::ProxyError;
use crate::session::{AccountContext, SessionManager};
use crate::upstream::Upstream;

use self::passthrough::passthrough;
use self::routes::{Route, classify};

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub upstream: Upstream,
    pub sessions: SessionManager,
}

impl AppState {
    pub async fn new(config: Arc<Config>) -> anyhow::Result<Self> {
        let upstream = Upstream::new(config.homeserver.clone())?;
        Ok(Self {
            config,
            upstream,
            sessions: SessionManager::default(),
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
/// the authoritative auth error).
async fn context_for(state: &AppState, token: Option<String>) -> Option<Arc<AccountContext>> {
    let token = token?;
    match state
        .sessions
        .get_or_init(&state.config, &state.upstream, &token)
        .await
    {
        Ok(ctx) => Some(ctx),
        Err(e) => {
            tracing::warn!(error = ?e, "could not initialize session; passing through");
            None
        }
    }
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
        Route::Sync => match context_for(&state, token).await {
            Some(ctx) => crate::crypto::sync::handle_sync(&state, ctx, req).await,
            None => passthrough(&state, req).await,
        },
        route @ (Route::Messages { .. } | Route::Context { .. } | Route::RoomEvent { .. }) => {
            match context_for(&state, token).await {
                Some(ctx) => intercept::handle_history_get(&state, ctx, req, route).await,
                None => passthrough(&state, req).await,
            }
        }
        // Interception for send + media lands in later milestones; everything
        // else passes through unchanged.
        _ => passthrough(&state, req).await,
    }
}
