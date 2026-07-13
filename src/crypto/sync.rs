use std::collections::BTreeMap;
use std::sync::Arc;

use anyhow::Context as _;
use axum::body::Body;
use axum::extract::Request;
use axum::http::header;
use axum::response::Response;
use matrix_sdk_crypto::EncryptionSyncChanges;
use ruma::api::client::sync::sync_events::DeviceLists;
use ruma::events::AnyToDeviceEvent;
use ruma::serde::Raw;
use ruma::{OneTimeKeyAlgorithm, UInt};

use crate::crypto::machine;
use crate::error::ProxyError;
use crate::proxy::AppState;
use crate::session::AccountContext;

/// Intercept GET /sync: forward verbatim, feed the crypto-relevant sections
/// into the OlmMachine *before* handing the response (and thus next_batch)
/// back to ement, then return the (later: rewritten) body.
pub async fn handle_sync(
    state: &AppState,
    ctx: Arc<AccountContext>,
    req: Request,
) -> Result<Response, ProxyError> {
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");

    let upstream_resp = state
        .upstream
        .http
        .get(state.upstream.url(path_and_query))
        .bearer_auth(&ctx.token)
        .send()
        .await?;

    let status = upstream_resp.status();
    let content_type = upstream_resp
        .headers()
        .get(header::CONTENT_TYPE)
        .cloned();
    let bytes = upstream_resp.bytes().await?;

    if !status.is_success() {
        return raw_response(status.as_u16(), content_type, bytes.to_vec());
    }

    let mut body: serde_json::Value =
        serde_json::from_slice(&bytes).context("sync response is not valid JSON")?;

    receive_sync_changes(&ctx, &body).await?;

    // Rewrite pass (decryption of m.room.encrypted timeline events, room
    // state tracking) — filled in by the receive path.
    process_sync_body(&ctx, &mut body).await;

    // Pump *after* receive_sync_changes: sync may have queued key uploads,
    // key queries for changed devices, etc. Fire and forget.
    tokio::spawn({
        let ctx = ctx.clone();
        async move { machine::pump(&ctx).await }
    });

    let bytes = serde_json::to_vec(&body).context("failed to re-serialize sync response")?;
    raw_response(200, content_type, bytes)
}

async fn receive_sync_changes(
    ctx: &AccountContext,
    body: &serde_json::Value,
) -> Result<(), ProxyError> {
    let to_device_events: Vec<Raw<AnyToDeviceEvent>> = body
        .pointer("/to_device/events")
        .map(|v| serde_json::from_value(v.clone()))
        .transpose()
        .context("invalid to_device.events in sync response")?
        .unwrap_or_default();

    let changed_devices: DeviceLists = body
        .get("device_lists")
        .map(|v| serde_json::from_value(v.clone()))
        .transpose()
        .context("invalid device_lists in sync response")?
        .unwrap_or_default();

    let one_time_keys_counts: BTreeMap<OneTimeKeyAlgorithm, UInt> = body
        .get("device_one_time_keys_count")
        .map(|v| serde_json::from_value(v.clone()))
        .transpose()
        .context("invalid device_one_time_keys_count in sync response")?
        .unwrap_or_default();

    let unused_fallback_keys: Option<Vec<OneTimeKeyAlgorithm>> = body
        .get("device_unused_fallback_key_types")
        .or_else(|| body.get("org.matrix.msc2732.device_unused_fallback_key_types"))
        .map(|v| serde_json::from_value(v.clone()))
        .transpose()
        .context("invalid device_unused_fallback_key_types in sync response")?;

    let next_batch = body
        .get("next_batch")
        .and_then(|v| v.as_str())
        .map(ToOwned::to_owned);

    let n_to_device = to_device_events.len();
    let (_processed, room_key_infos) = ctx
        .olm
        .receive_sync_changes(
            EncryptionSyncChanges {
                to_device_events,
                changed_devices: &changed_devices,
                one_time_keys_counts: &one_time_keys_counts,
                unused_fallback_keys: unused_fallback_keys.as_deref(),
                next_batch_token: next_batch,
            },
            &machine::decryption_settings(),
        )
        .await
        .context("receive_sync_changes failed")?;

    if n_to_device > 0 || !room_key_infos.is_empty() {
        tracing::debug!(
            to_device = n_to_device,
            new_room_keys = room_key_infos.len(),
            "processed sync crypto changes"
        );
    }
    Ok(())
}

/// Placeholder for the receive-path rewrite (M3): decrypt encrypted timeline
/// events and track room encryption state.
async fn process_sync_body(_ctx: &AccountContext, _body: &mut serde_json::Value) {}

fn raw_response(
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
