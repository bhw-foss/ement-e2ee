use anyhow::Context as _;
use matrix_sdk_crypto::OlmMachine;
use matrix_sdk_crypto::types::requests::{AnyOutgoingRequest, OutgoingRequest, ToDeviceRequest};
use matrix_sdk_sqlite::SqliteCryptoStore;
use ruma::api::error::FromHttpResponseError;
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

/// Per-account on-disk state directory.
pub fn account_store_dir(
    config: &Config,
    user_id: &UserId,
    device_id: &DeviceId,
) -> std::path::PathBuf {
    config
        .store_dir
        .join(sanitize_for_path(user_id.as_str()))
        .join(sanitize_for_path(device_id.as_str()))
}

/// Open (or create) the persistent OlmMachine for a user/device pair.
pub async fn open_machine(
    config: &Config,
    user_id: &UserId,
    device_id: &DeviceId,
) -> anyhow::Result<OlmMachine> {
    let dir = account_store_dir(config, user_id, device_id);
    let store = SqliteCryptoStore::open(&dir, config.store_passphrase.as_deref())
        .await
        .with_context(|| format!("failed to open crypto store at {}", dir.display()))?;
    let olm = OlmMachine::with_store(user_id, device_id, store, None)
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
            break;
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
    // With the queue drained, push any new room keys to the server-side
    // backup (no-op unless `ctl bootstrap` enabled backups).
    if let Err(e) = upload_pending_backups(ctx).await {
        tracing::warn!(error = ?e, "backup upload failed; will retry on next pump");
    }
}

/// Encrypt-and-upload not-yet-backed-up room keys, mirroring matrix-sdk's
/// `Backups::backup_room_keys`.
async fn upload_pending_backups(ctx: &AccountContext) -> anyhow::Result<()> {
    let backup_machine = ctx.olm.backup_machine();
    if !backup_machine.enabled().await {
        return Ok(());
    }
    // Bounded loop: each `backup()` call returns one batch.
    for _ in 0..100 {
        let Some((txn_id, request)) = backup_machine.backup().await? else {
            return Ok(());
        };
        let path = format!(
            "/_matrix/client/v3/room_keys/keys?version={}",
            enc(&request.version)
        );
        let body = serde_json::json!({ "rooms": request.rooms });
        let (status, response_body) = ctx
            .upstream
            .json_request(reqwest::Method::PUT, &path, &ctx.token, Some(&body))
            .await?;
        if !status.is_success() {
            anyhow::bail!("room_keys upload returned {status}: {response_body}");
        }
        let response: ruma::api::client::backup::add_backup_keys::v3::Response =
            parse_response(&response_body)?;
        ctx.olm.mark_request_as_sent(&txn_id, &response).await?;
        tracing::debug!("uploaded a batch of room keys to backup");
    }
    Ok(())
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
    let id = request.request_id();

    match request.request() {
        AnyOutgoingRequest::KeysUpload(_) => {
            let response: KeysUploadResponse = parse_response(response_body)?;
            ctx.olm.mark_request_as_sent(id, &response).await?;
        }
        AnyOutgoingRequest::KeysQuery(_) => {
            let response: KeysQueryResponse = parse_response(response_body)?;
            ctx.olm.mark_request_as_sent(id, &response).await?;
        }
        AnyOutgoingRequest::KeysClaim(_) => {
            let response: KeysClaimResponse = parse_response(response_body)?;
            ctx.olm.mark_request_as_sent(id, &response).await?;
        }
        AnyOutgoingRequest::ToDeviceRequest(_) => {
            let response: ToDeviceResponse = parse_response(response_body)?;
            ctx.olm.mark_request_as_sent(id, &response).await?;
        }
        AnyOutgoingRequest::SignatureUpload(_) => {
            let response: SignatureUploadResponse = parse_response(response_body)?;
            ctx.olm.mark_request_as_sent(id, &response).await?;
        }
        AnyOutgoingRequest::RoomMessage(_) => {
            let response: RoomMessageResponse = parse_response(response_body)?;
            ctx.olm.mark_request_as_sent(id, &response).await?;
        }
    }
    Ok(())
}

/// Parse the JSON body of a successful upstream response into the matching
/// ruma response type (which is what `mark_request_as_sent` wants).
pub(crate) fn parse_response<R>(body: &serde_json::Value) -> anyhow::Result<R>
where
    R: IncomingResponse,
    FromHttpResponseError<R::EndpointError>: std::error::Error + Send + Sync + 'static,
{
    let bytes = serde_json::to_vec(body)?;
    let http_response = http::Response::builder()
        .status(200)
        .body(bytes.as_slice())?;
    Ok(R::try_from_http_response(http_response)?)
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
    let response: KeysClaimResponse = parse_response(&response_body)?;
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
    let response: ToDeviceResponse = parse_response(&response_body)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enc_escapes_matrix_sigils_for_path_segments() {
        assert_eq!(enc("!abc:example.org"), "%21abc%3Aexample.org");
        assert_eq!(enc("$event/with+odd?chars#"), "%24event%2Fwith%2Bodd%3Fchars%23");
        assert_eq!(enc("@alice:example.org"), "%40alice%3Aexample.org");
        // Unreserved characters stay readable; everything else is escaped.
        assert_eq!(enc("m.room.message-1_2~3"), "m.room.message-1_2~3");
        assert_eq!(enc("a b%c"), "a%20b%25c");
        assert_eq!(enc("ü"), "%C3%BC");
    }

    #[test]
    fn store_dir_is_per_user_and_device() {
        let config = Config {
            listen: "127.0.0.1:0".parse().unwrap(),
            homeserver: "https://example.org".parse().unwrap(),
            store_dir: "/stores".into(),
            log_level: "info".to_owned(),
            store_passphrase: None,
            admin_token: None,
        };
        let user: &UserId = "@alice:example.org".try_into().unwrap();
        assert_eq!(
            account_store_dir(&config, user, "DEVICE1".into()),
            std::path::PathBuf::from("/stores/@alice:example.org/DEVICE1")
        );
        // Device IDs are chosen by the server; they must not escape the store.
        assert_eq!(
            account_store_dir(&config, user, "../../etc".into()),
            std::path::PathBuf::from("/stores/@alice:example.org/.._.._etc")
        );
    }

    #[test]
    fn parse_response_accepts_homeserver_bodies() {
        let response: KeysUploadResponse =
            parse_response(&json!({ "one_time_key_counts": { "signed_curve25519": 50 } }))
                .unwrap();
        let count = response.one_time_key_counts[&ruma::OneTimeKeyAlgorithm::SignedCurve25519];
        assert_eq!(count, 50u32.into());

        // Empty-object responses, as sendToDevice returns.
        parse_response::<ToDeviceResponse>(&json!({})).unwrap();
        let response: RoomMessageResponse =
            parse_response(&json!({ "event_id": "$abc" })).unwrap();
        assert_eq!(response.event_id, "$abc");
    }

    #[test]
    fn parse_response_rejects_wrong_shapes() {
        // A body that does not match the endpoint must surface as an error so
        // the request stays queued, not be marked as sent.
        assert!(parse_response::<RoomMessageResponse>(&json!({})).is_err());
        assert!(
            parse_response::<KeysUploadResponse>(&json!({ "one_time_key_counts": "many" }))
                .is_err()
        );
    }
}
