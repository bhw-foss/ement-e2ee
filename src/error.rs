use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

use crate::crypto::device::{DeviceConflict, DeviceUnchecked};

/// Errors surfaced to the client as Matrix-style JSON errors.
#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("upstream request failed: {0}")]
    Upstream(#[from] reqwest::Error),
    #[error("{0}")]
    Internal(#[from] anyhow::Error),
    #[error("{0}")]
    BadRequest(String),
    #[error("{0}")]
    DeviceConflict(#[from] DeviceConflict),
    #[error("{0}")]
    DeviceUnchecked(#[from] DeviceUnchecked),
}

impl IntoResponse for ProxyError {
    fn into_response(self) -> Response {
        let status = match &self {
            ProxyError::Upstream(_) => StatusCode::BAD_GATEWAY,
            ProxyError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            ProxyError::BadRequest(_) => StatusCode::BAD_REQUEST,
            ProxyError::DeviceConflict(_) => StatusCode::CONFLICT,
            // The homeserver's failure, and ement syncs again after a 502.
            ProxyError::DeviceUnchecked(_) => StatusCode::BAD_GATEWAY,
        };
        tracing::error!(error = ?self, "request failed");
        let body = serde_json::json!({
            "errcode": "M_UNKNOWN",
            "error": format!("ement-e2ee: {self}"),
        });
        (status, Json(body)).into_response()
    }
}
