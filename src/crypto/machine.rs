use anyhow::Context as _;
use matrix_sdk_crypto::{OlmMachine, OlmMachineBuilder};
use matrix_sdk_crypto::types::requests::{AnyOutgoingRequest, OutgoingRequest, ToDeviceRequest};
use matrix_sdk_sqlite::SqliteCryptoStore;
use ruma::api::IncomingResponse;
use ruma::api::client::{
    keys::{
        claim_keys::v3::Response as KeysClaimResponse, get_keys::v3::Response as KeysQueryResponse,
        upload_keys::v3::Response as KeysUploadResponse,
        upload_signatures::v3::Response as SignatureUploadResponse,
    },
    message::send_message_event::v3::Response as RoomMessageResponse,
    to_device::send_event_to_device::v3::Response as ToDeviceResponse,
};
use ruma::events::MessageLikeEventContent as _;
use ruma::{DeviceId, UserId};
use serde_json::json;

use crate::config::Config;
use crate::session::{AccountContext, sanitize_for_path};

/// Open (or create) the persistent OlmMachine for a user/device pair.
pub async fn open_machine(
    config: &Config,
    user_id: &UserId,
    device_id: &DeviceId,
) -> anyhow::Result<OlmMachine> {
    let dir = config
        .store_dir
        .join(sanitize_for_path(user_id.as_str()))
        .join(sanitize_for_path(device_id.as_str()));
    let store = SqliteCryptoStore::open(&dir, config.store_passphrase.as_deref())
        .await
        .with_context(|| format!("failed to open crypto store at {}", dir.display()))?;
    let olm = OlmMachineBuilder::new(user_id, device_id)
        .with_crypto_store(std::sync::Arc::new(store))
        .build()
        .await
        .context("failed to build OlmMachine")?;
    Ok(olm)
}

/// Drain the machine's outgoing request queue, sending each request upstream
/// and feeding the response back. Errors are logged, not propagated: requests
/// stay queued and are retried on the next pump.
pub async fn pump(ctx: &AccountContext) {
    let _guard = ctx.pump_lock.lock().await;
    loop {
        let requests = match ctx.olm.outgoing_requests().await {
            Ok(r) => r,
            Err(e) => {
                tracing::error!(error = ?e, "outgoing_requests failed");
                return;
            }
        };
        if requests.is_empty() {
            return;
        }
        for request in requests {
            if let Err(e) = send_and_mark(ctx, &request).await {
                tracing::warn!(
                    request_id = %request.request_id(),
                    error = ?e,
                    "outgoing crypto request failed; will retry on next pump"
                );
                return;
            }
        }
    }
}

pub(crate) fn enc(segment: &str) -> String {
    use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
    const SAFE: &percent_encoding::AsciiSet = &NON_ALPHANUMERIC
        .remove(b'-')
        .remove(b'_')
        .remove(b'.')
        .remove(b'~');
    utf8_percent_encode(segment, SAFE).to_string()
}

fn to_device_path(request: &ToDeviceRequest) -> String {
    format!(
        "/_matrix/client/v3/sendToDevice/{}/{}",
        enc(&request.event_type.to_string()),
        enc(request.txn_id.as_str())
    )
}

pub(crate) async fn send_and_mark(
    ctx: &AccountContext,
    request: &OutgoingRequest,
) -> anyhow::Result<()> {
    use reqwest::Method;

    let (method, path, body): (Method, String, serde_json::Value) = match request.request() {
        AnyOutgoingRequest::KeysUpload(r) => {
            let mut body = serde_json::Map::new();
            if let Some(device_keys) = &r.device_keys {
                body.insert("device_keys".into(), serde_json::to_value(device_keys)?);
            }
            if !r.one_time_keys.is_empty() {
                body.insert(
                    "one_time_keys".into(),
                    serde_json::to_value(&r.one_time_keys)?,
                );
            }
            if !r.fallback_keys.is_empty() {
                body.insert(
                    "fallback_keys".into(),
                    serde_json::to_value(&r.fallback_keys)?,
                );
            }
            (
                Method::POST,
                "/_matrix/client/v3/keys/upload".into(),
                body.into(),
            )
        }
        AnyOutgoingRequest::KeysQuery(r) => {
            let mut body = json!({ "device_keys": r.device_keys });
            if let Some(timeout) = r.timeout {
                body["timeout"] = json!(timeout.as_millis() as u64);
            }
            (Method::POST, "/_matrix/client/v3/keys/query".into(), body)
        }
        AnyOutgoingRequest::KeysClaim(r) => {
            let mut body = json!({ "one_time_keys": r.one_time_keys });
            if let Some(timeout) = r.timeout {
                body["timeout"] = json!(timeout.as_millis() as u64);
            }
            (Method::POST, "/_matrix/client/v3/keys/claim".into(), body)
        }
        AnyOutgoingRequest::ToDeviceRequest(r) => (
            Method::PUT,
            to_device_path(r),
            json!({ "messages": r.messages }),
        ),
        AnyOutgoingRequest::SignatureUpload(r) => (
            Method::POST,
            "/_matrix/client/v3/keys/signatures/upload".into(),
            serde_json::to_value(&r.signed_keys)?,
        ),
        AnyOutgoingRequest::RoomMessage(r) => (
            Method::PUT,
            format!(
                "/_matrix/client/v3/rooms/{}/send/{}/{}",
                enc(r.room_id.as_str()),
                enc(&r.content.event_type().to_string()),
                enc(r.txn_id.as_str())
            ),
            serde_json::to_value(&r.content)?,
        ),
    };

    tracing::debug!(%method, %path, request_id = %request.request_id(), "sending crypto request");
    let (status, response_body) = ctx
        .upstream
        .json_request(method, &path, &ctx.token, Some(&body))
        .await?;
    if !status.is_success() {
        anyhow::bail!("upstream returned {status}: {response_body}");
    }

    mark_as_sent(ctx, request, &response_body).await
}

/// Convert the upstream JSON response into the ruma response type matching the
/// request variant, and feed it back into the OlmMachine.
async fn mark_as_sent(
    ctx: &AccountContext,
    request: &OutgoingRequest,
    response_body: &serde_json::Value,
) -> anyhow::Result<()> {
    let http_response = http::Response::builder()
        .status(200)
        .body(serde_json::to_vec(response_body)?)
        .expect("valid response");
    let id = request.request_id();

    match request.request() {
        AnyOutgoingRequest::KeysUpload(_) => {
            let response = KeysUploadResponse::try_from_http_response(http_response)?;
            ctx.olm.mark_request_as_sent(id, &response).await?;
        }
        AnyOutgoingRequest::KeysQuery(_) => {
            let response = KeysQueryResponse::try_from_http_response(http_response)?;
            ctx.olm.mark_request_as_sent(id, &response).await?;
        }
        AnyOutgoingRequest::KeysClaim(_) => {
            let response = KeysClaimResponse::try_from_http_response(http_response)?;
            ctx.olm.mark_request_as_sent(id, &response).await?;
        }
        AnyOutgoingRequest::ToDeviceRequest(_) => {
            let response = ToDeviceResponse::try_from_http_response(http_response)?;
            ctx.olm.mark_request_as_sent(id, &response).await?;
        }
        AnyOutgoingRequest::SignatureUpload(_) => {
            let response = SignatureUploadResponse::try_from_http_response(http_response)?;
            ctx.olm.mark_request_as_sent(id, &response).await?;
        }
        AnyOutgoingRequest::RoomMessage(_) => {
            let response = RoomMessageResponse::try_from_http_response(http_response)?;
            ctx.olm.mark_request_as_sent(id, &response).await?;
        }
    }
    Ok(())
}

/// Send a one-off (transaction_id, ruma request) pair that is not part of the
/// outgoing_requests queue (e.g. KeysClaim from get_missing_sessions).
pub async fn send_keys_claim(
    ctx: &AccountContext,
    id: &ruma::TransactionId,
    request: &ruma::api::client::keys::claim_keys::v3::Request,
) -> anyhow::Result<()> {
    let mut body = json!({ "one_time_keys": request.one_time_keys });
    if let Some(timeout) = request.timeout {
        body["timeout"] = json!(timeout.as_millis() as u64);
    }
    let (status, response_body) = ctx
        .upstream
        .json_request(
            reqwest::Method::POST,
            "/_matrix/client/v3/keys/claim",
            &ctx.token,
            Some(&body),
        )
        .await?;
    if !status.is_success() {
        anyhow::bail!("keys/claim returned {status}: {response_body}");
    }
    let http_response = http::Response::builder()
        .status(200)
        .body(serde_json::to_vec(&response_body)?)
        .expect("valid response");
    let response = KeysClaimResponse::try_from_http_response(http_response)?;
    ctx.olm.mark_request_as_sent(id, &response).await?;
    Ok(())
}

/// Send a single ToDeviceRequest (e.g. room key shares) and mark it as sent.
pub async fn send_to_device(
    ctx: &AccountContext,
    request: &ToDeviceRequest,
) -> anyhow::Result<()> {
    let (status, response_body) = ctx
        .upstream
        .json_request(
            reqwest::Method::PUT,
            &to_device_path(request),
            &ctx.token,
            Some(&json!({ "messages": request.messages })),
        )
        .await?;
    if !status.is_success() {
        anyhow::bail!("sendToDevice returned {status}: {response_body}");
    }
    let http_response = http::Response::builder()
        .status(200)
        .body(serde_json::to_vec(&response_body)?)
        .expect("valid response");
    let response = ToDeviceResponse::try_from_http_response(http_response)?;
    ctx.olm.mark_request_as_sent(&request.txn_id, &response).await?;
    Ok(())
}

/// Decryption policy used everywhere: decrypt regardless of sender trust
/// (ement has no UI to distinguish, and refusing would show UTDs instead).
pub fn decryption_settings() -> matrix_sdk_crypto::DecryptionSettings {
    matrix_sdk_crypto::DecryptionSettings {
        sender_device_trust_requirement: matrix_sdk_crypto::TrustRequirement::Untrusted,
    }
}
