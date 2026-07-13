use std::sync::Arc;

use anyhow::Context as _;
use axum::extract::Request;
use axum::response::Response;
use matrix_sdk_crypto::EncryptionSettings;
use ruma::events::AnyMessageLikeEventContent;
use ruma::serde::Raw;
use ruma::{OwnedRoomId, RoomId};
use serde_json::Value;

use crate::crypto::{machine, media, rooms};
use crate::error::ProxyError;
use crate::proxy::AppState;
use crate::proxy::intercept::raw_response;
use crate::proxy::passthrough::passthrough;
use crate::session::AccountContext;

/// Intercept PUT /rooms/{room}/send/{type}/{txn}: if the room is encrypted,
/// establish sessions, share the room key, encrypt the content, and forward
/// as m.room.encrypted. Unencrypted rooms pass through untouched.
pub async fn handle_send(
    state: &AppState,
    ctx: Arc<AccountContext>,
    req: Request,
    room_id: String,
    event_type: String,
    txn_id: String,
) -> Result<Response, ProxyError> {
    let Ok(room_id) = room_id.parse::<OwnedRoomId>() else {
        return passthrough(state, req).await;
    };
    // Never double-encrypt (nothing sends m.room.encrypted through us today,
    // but be safe).
    if event_type == "m.room.encrypted" {
        return passthrough(state, req).await;
    }

    // Fail closed: if we cannot determine the room's encryption state, do NOT
    // forward plaintext — it could leak into an encrypted room.
    let encrypted = rooms::is_room_encrypted(&ctx, &room_id)
        .await
        .context("could not determine room encryption state")?;

    let original_path = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_owned())
        .unwrap_or_else(|| "/".to_owned());
    let body_bytes = axum::body::to_bytes(req.into_body(), 4 * 1024 * 1024)
        .await
        .map_err(|e| ProxyError::BadRequest(format!("failed to read send body: {e}")))?;
    let mut content: Value = serde_json::from_slice(&body_bytes)
        .map_err(|e| ProxyError::BadRequest(format!("send body is not JSON: {e}")))?;

    let (path, wire_content) = if encrypted {
        // Media contents reference an mxc we encrypted at upload time: move
        // the url into the spec `file` object so recipients can decrypt.
        media::rewrite_content_for_encrypted_room(&ctx, &mut content);
        let encrypted_content = encrypt_content(&ctx, &room_id, &event_type, content)
            .await
            .context("failed to encrypt event")?;
        // Forward as m.room.encrypted, preserving the client's transaction ID
        // so ement's local echo and dedup logic keep working.
        let path = format!(
            "/_matrix/client/v3/rooms/{}/send/m.room.encrypted/{}",
            machine::enc(room_id.as_str()),
            machine::enc(&txn_id)
        );
        (path, encrypted_content)
    } else {
        // All uploads are encrypted by the proxy; media sent into an
        // unencrypted room must be re-uploaded as plaintext first.
        media::reupload_plaintext_if_needed(state, &ctx, &mut content)
            .await
            .context("media fix-up for unencrypted room failed")?;
        (original_path, content)
    };

    let (status, response_body) = ctx
        .upstream
        .json_request(reqwest::Method::PUT, &path, &ctx.token, Some(&wire_content))
        .await
        .context("failed to forward send")?;

    if encrypted {
        tracing::info!(%room_id, %event_type, %status, "sent encrypted event");
    }
    raw_response(
        status.as_u16(),
        Some(axum::http::HeaderValue::from_static("application/json")),
        serde_json::to_vec(&response_body).map_err(|e| ProxyError::Internal(e.into()))?,
    )
}

/// The full encrypt dance: track members, claim one-time keys, share the room
/// key, then megolm-encrypt the content.
async fn encrypt_content(
    ctx: &Arc<AccountContext>,
    room_id: &RoomId,
    event_type: &str,
    content: Value,
) -> anyhow::Result<Value> {
    let members = rooms::joined_members(ctx, room_id).await?;

    // Serialize the whole claim/share section per account: concurrent sends
    // must not race on session establishment.
    let _guard = ctx.share_lock.lock().await;

    ctx.olm
        .update_tracked_users(members.iter().map(AsRef::as_ref))
        .await
        .context("update_tracked_users failed")?;
    // Flush the key queries produced by update_tracked_users (and anything
    // else pending) before claiming sessions.
    machine::pump(ctx).await;

    if let Some((txn_id, request)) = ctx
        .olm
        .get_missing_sessions(members.iter().map(AsRef::as_ref))
        .await
        .context("get_missing_sessions failed")?
    {
        machine::send_keys_claim(ctx, &txn_id, &request)
            .await
            .context("keys/claim for missing sessions failed")?;
    }

    let settings = encryption_settings(ctx, room_id).await?;
    let to_device_requests = ctx
        .olm
        .share_room_key(room_id, members.iter().map(AsRef::as_ref), settings)
        .await
        .context("share_room_key failed")?;
    let n_shares = to_device_requests.len();
    for request in to_device_requests {
        machine::send_to_device(ctx, &request)
            .await
            .context("sending room key share failed")?;
    }
    if n_shares > 0 {
        tracing::debug!(%room_id, count = n_shares, "shared room key");
    }

    let raw_content: Raw<AnyMessageLikeEventContent> =
        serde_json::from_value(content).context("invalid event content")?;
    let encrypted = ctx
        .olm
        .encrypt_room_event_raw(room_id, event_type, &raw_content)
        .await
        .context("encrypt_room_event_raw failed")?;

    let value: Value = serde_json::from_str(encrypted.content.json().get())
        .context("encrypted content is not valid JSON")?;
    Ok(value)
}

/// Send a RoomMessageRequest produced by the verification machine, encrypting
/// it when the target room is encrypted, and feed the response back.
pub(crate) async fn send_room_message_request(
    ctx: &Arc<AccountContext>,
    request: &matrix_sdk_crypto::types::requests::RoomMessageRequest,
) -> anyhow::Result<()> {
    use ruma::api::IncomingResponse as _;
    use ruma::events::MessageLikeEventContent as _;

    let event_type = request.content.event_type().to_string();
    let content = serde_json::to_value(&request.content)?;

    let (wire_type, wire_content) = if rooms::is_room_encrypted(ctx, &request.room_id).await? {
        (
            "m.room.encrypted".to_owned(),
            encrypt_content(ctx, &request.room_id, &event_type, content).await?,
        )
    } else {
        (event_type, content)
    };

    let path = format!(
        "/_matrix/client/v3/rooms/{}/send/{}/{}",
        machine::enc(request.room_id.as_str()),
        machine::enc(&wire_type),
        machine::enc(request.txn_id.as_str())
    );
    let (status, response_body) = ctx
        .upstream
        .json_request(reqwest::Method::PUT, &path, &ctx.token, Some(&wire_content))
        .await?;
    if !status.is_success() {
        anyhow::bail!("in-room verification send failed: {status} {response_body}");
    }
    let http_response = http::Response::builder()
        .status(200)
        .body(serde_json::to_vec(&response_body)?)?;
    let response =
        ruma::api::client::message::send_message_event::v3::Response::try_from_http_response(
            http_response,
        )?;
    ctx.olm
        .mark_request_as_sent(&request.txn_id, &response)
        .await?;
    Ok(())
}

/// Build EncryptionSettings from the room's persisted settings and history
/// visibility.
async fn encryption_settings(
    ctx: &AccountContext,
    room_id: &RoomId,
) -> anyhow::Result<EncryptionSettings> {
    let room_settings = ctx
        .olm
        .room_settings(room_id)
        .await?
        .unwrap_or_default();
    let mut settings = EncryptionSettings {
        algorithm: room_settings.algorithm,
        history_visibility: rooms::history_visibility_or_fetch(ctx, room_id).await,
        ..Default::default()
    };
    if let Some(period) = room_settings.session_rotation_period {
        settings.rotation_period = period;
    }
    if let Some(msgs) = room_settings.session_rotation_period_messages {
        settings.rotation_period_msgs = msgs as u64;
    }
    Ok(settings)
}
