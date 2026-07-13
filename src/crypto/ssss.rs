//! Bootstrap this device from the user's existing secret storage (SSSS),
//! mirroring matrix-sdk's `SecretStore::import_secrets()` flow
//! (crates/matrix-sdk/src/encryption/secret_storage/secret_store.rs) over the
//! proxy's own HTTP plumbing.

use anyhow::Context as _;
use matrix_sdk_crypto::secret_storage::{AesHmacSha2EncryptedData, SecretStorageKey};
use matrix_sdk_crypto::store::types::CrossSigningKeyExport;
use ruma::api::IncomingResponse as _;
use ruma::api::client::keys::get_keys::v3::Response as KeysQueryResponse;
use ruma::events::EventContentFromType as _;
use ruma::events::secret::request::SecretName;
use ruma::events::secret_storage::key::SecretStorageKeyEventContent;

use crate::crypto::{backup, machine};
use crate::session::AccountContext;

#[derive(Debug, serde::Serialize)]
pub struct BootstrapReport {
    pub imported_master_key: bool,
    pub imported_self_signing_key: bool,
    pub imported_user_signing_key: bool,
    pub own_device_signed: bool,
    pub backup: backup::BackupRestoreReport,
}

/// Fetch a global account-data event's content; None on 404.
pub async fn fetch_account_data(
    ctx: &AccountContext,
    event_type: &str,
) -> anyhow::Result<Option<serde_json::Value>> {
    let path = format!(
        "/_matrix/client/v3/user/{}/account_data/{}",
        machine::enc(ctx.user_id.as_str()),
        machine::enc(event_type)
    );
    let (status, body) = ctx
        .upstream
        .json_request(reqwest::Method::GET, &path, &ctx.token, None)
        .await?;
    if status == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !status.is_success() {
        anyhow::bail!("fetching account data {event_type} failed: {status} {body}");
    }
    Ok(Some(body))
}

/// Open the default secret store: fetch the default key description and
/// validate the user-supplied recovery key (or passphrase) against it.
/// Mirrors `SecretStorage::open_secret_store`.
async fn open_secret_storage_key(
    ctx: &AccountContext,
    recovery_key: &str,
) -> anyhow::Result<SecretStorageKey> {
    let default_key = fetch_account_data(ctx, "m.secret_storage.default_key")
        .await?
        .context("no m.secret_storage.default_key account data: secret storage is not set up")?;
    let key_id = default_key
        .get("key")
        .and_then(|v| v.as_str())
        .context("malformed m.secret_storage.default_key content")?
        .to_owned();

    let event_type = format!("m.secret_storage.key.{key_id}");
    let key_content = fetch_account_data(ctx, &event_type)
        .await?
        .with_context(|| format!("missing account data {event_type}"))?;

    let raw = serde_json::value::to_raw_value(&key_content)?;
    let content = SecretStorageKeyEventContent::from_parts(&event_type, &raw)
        .context("malformed secret storage key description")?;

    SecretStorageKey::from_account_data(recovery_key, content)
        .context("recovery key/passphrase does not match the secret storage key")
}

/// Fetch and decrypt one SSSS secret. Mirrors `SecretStore::get_secret`.
async fn get_secret(
    ctx: &AccountContext,
    key: &SecretStorageKey,
    secret_name: &SecretName,
) -> anyhow::Result<Option<String>> {
    let Some(content) = fetch_account_data(ctx, secret_name.as_str()).await? else {
        return Ok(None);
    };
    let Some(encrypted) = content
        .pointer(&format!("/encrypted/{}", key.key_id()))
        .cloned()
    else {
        tracing::warn!(
            secret = secret_name.as_str(),
            "secret exists but is not encrypted with the default key"
        );
        return Ok(None);
    };
    let data: AesHmacSha2EncryptedData = serde_json::from_value(encrypted)
        .with_context(|| format!("malformed encrypted data for {secret_name}"))?;
    let decrypted = key
        .decrypt(&data, secret_name)
        .with_context(|| format!("MAC check failed decrypting {secret_name}"))?;
    Ok(Some(String::from_utf8(decrypted).with_context(|| {
        format!("secret {secret_name} is not valid UTF-8")
    })?))
}

/// Run a /keys/query for our own user and feed the response to the machine,
/// so the public cross-signing identity is known/refreshed.
async fn query_own_keys(ctx: &AccountContext) -> anyhow::Result<()> {
    let (request_id, request) = ctx.olm.query_keys_for_users([ctx.user_id.as_ref()].into_iter());
    let body = serde_json::json!({ "device_keys": request.device_keys });
    let (status, response_body) = ctx
        .upstream
        .json_request(
            reqwest::Method::POST,
            "/_matrix/client/v3/keys/query",
            &ctx.token,
            Some(&body),
        )
        .await?;
    if !status.is_success() {
        anyhow::bail!("keys/query failed: {status} {response_body}");
    }
    let http_response = http::Response::builder()
        .status(200)
        .body(serde_json::to_vec(&response_body)?)?;
    let response = KeysQueryResponse::try_from_http_response(http_response)?;
    ctx.olm.mark_request_as_sent(&request_id, &response).await?;
    Ok(())
}

/// The full bootstrap: decrypt cross-signing secrets + backup key from SSSS,
/// import them, self-sign this device, and restore room keys from the backup.
pub async fn bootstrap(
    ctx: &AccountContext,
    recovery_key: &str,
) -> anyhow::Result<BootstrapReport> {
    let key = open_secret_storage_key(ctx, recovery_key).await?;
    tracing::info!(key_id = key.key_id(), "opened secret storage");

    let export = CrossSigningKeyExport {
        master_key: get_secret(ctx, &key, &SecretName::CrossSigningMasterKey).await?,
        self_signing_key: get_secret(ctx, &key, &SecretName::CrossSigningSelfSigningKey).await?,
        user_signing_key: get_secret(ctx, &key, &SecretName::CrossSigningUserSigningKey).await?,
    };
    let imported_master = export.master_key.is_some();
    let imported_self_signing = export.self_signing_key.is_some();
    let imported_user_signing = export.user_signing_key.is_some();

    // The machine compares the private keys against the server-side public
    // identity before importing, so make sure it is present first.
    query_own_keys(ctx).await?;

    let status = ctx
        .olm
        .import_cross_signing_keys(export)
        .await
        .context("importing cross-signing keys failed (do they match the server identity?)")?;
    tracing::info!(?status, "imported cross-signing keys");

    let mut own_device_signed = false;
    if status.has_self_signing {
        let device = ctx
            .olm
            .get_device(&ctx.user_id, &ctx.device_id, None)
            .await?
            .context("own device not found in store")?;
        let signature_upload = device.verify().await.context("self-signing device failed")?;
        let (status_code, response_body) = ctx
            .upstream
            .json_request(
                reqwest::Method::POST,
                "/_matrix/client/v3/keys/signatures/upload",
                &ctx.token,
                Some(&serde_json::to_value(&signature_upload.signed_keys)?),
            )
            .await?;
        if !status_code.is_success() {
            anyhow::bail!("signature upload failed: {status_code} {response_body}");
        }
        // Refresh so the new signature is reflected in our own device record.
        query_own_keys(ctx).await?;
        own_device_signed = true;
        tracing::info!("own device is now cross-signed");
    }

    let backup_secret = get_secret(ctx, &key, &SecretName::RecoveryKey).await?;
    let backup = match backup_secret {
        Some(secret) => backup::restore_from_backup(ctx, &secret).await?,
        None => {
            tracing::info!("no m.megolm_backup.v1 secret in secret storage");
            backup::BackupRestoreReport::default()
        }
    };

    machine::pump(ctx).await;

    Ok(BootstrapReport {
        imported_master_key: imported_master,
        imported_self_signing_key: imported_self_signing,
        imported_user_signing_key: imported_user_signing,
        own_device_signed,
        backup,
    })
}
