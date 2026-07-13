//! Room-key backup: enable from the SSSS-recovered decryption key and restore
//! all backed-up room keys. Mirrors matrix-sdk's `Backups::maybe_enable_backups`
//! and `handle_downloaded_room_keys` (crates/matrix-sdk/src/encryption/backups/mod.rs).

use anyhow::Context as _;
use matrix_sdk_crypto::olm::ExportedRoomKey;
use matrix_sdk_crypto::store::types::BackupDecryptionKey;
use matrix_sdk_crypto::types::RoomKeyBackupInfo;
use ruma::api::IncomingResponse as _;
use ruma::api::client::backup::get_backup_keys;

use crate::session::AccountContext;

#[derive(Debug, Default, serde::Serialize)]
pub struct BackupRestoreReport {
    pub backup_version: Option<String>,
    pub enabled: bool,
    pub total_keys_in_backup: usize,
    pub imported_keys: usize,
}

#[derive(Debug, serde::Deserialize)]
struct BackupVersionInfo {
    version: String,
    algorithm: String,
    auth_data: serde_json::Value,
}

/// Fetch the current backup version from the server; None if no backup exists.
async fn current_backup_version(
    ctx: &AccountContext,
) -> anyhow::Result<Option<BackupVersionInfo>> {
    let (status, body) = ctx
        .upstream
        .json_request(
            reqwest::Method::GET,
            "/_matrix/client/v3/room_keys/version",
            &ctx.token,
            None,
        )
        .await?;
    if status == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !status.is_success() {
        anyhow::bail!("room_keys/version failed: {status} {body}");
    }
    Ok(Some(
        serde_json::from_value(body).context("malformed room_keys/version response")?,
    ))
}

/// Enable backups with the recovered decryption key and download + import all
/// room keys.
pub async fn restore_from_backup(
    ctx: &AccountContext,
    backup_secret_base64: &str,
) -> anyhow::Result<BackupRestoreReport> {
    let decryption_key = BackupDecryptionKey::from_base64(backup_secret_base64)
        .context("m.megolm_backup.v1 secret is not a valid backup key")?;

    let Some(version_info) = current_backup_version(ctx).await? else {
        tracing::warn!("a backup decryption key exists but the server has no backup version");
        return Ok(BackupRestoreReport::default());
    };

    let backup_info: RoomKeyBackupInfo = serde_json::from_value(serde_json::json!({
        "algorithm": version_info.algorithm,
        "auth_data": version_info.auth_data,
    }))
    .context("malformed backup auth_data")?;

    if !decryption_key.backup_key_matches(&backup_info) {
        anyhow::bail!(
            "the recovered backup key does not match the active server-side backup \
             (version {}); was the backup reset after the recovery key was created?",
            version_info.version
        );
    }

    let backup_machine = ctx.olm.backup_machine();
    let stored = backup_machine.get_backup_keys().await?;
    let already_enabled = stored.backup_version.as_deref() == Some(version_info.version.as_str());

    if !already_enabled {
        // Reset any previous backup association, then persist key + version
        // and enable, exactly like matrix-sdk's maybe_enable_backups.
        backup_machine.disable_backup().await?;
        let backup_key = decryption_key.megolm_v1_public_key();
        backup_key.set_version(version_info.version.clone());
        backup_machine
            .save_decryption_key(
                Some(decryption_key.clone()),
                Some(version_info.version.clone()),
            )
            .await?;
        backup_machine.enable_backup_v1(backup_key).await?;
        tracing::info!(version = %version_info.version, "backup enabled");
    }

    // Download the whole backup. Not paginated per spec; fine at personal scale.
    let path = format!(
        "/_matrix/client/v3/room_keys/keys?version={}",
        crate::crypto::machine::enc(&version_info.version)
    );
    let (status, body) = ctx
        .upstream
        .json_request(reqwest::Method::GET, &path, &ctx.token, None)
        .await?;
    if !status.is_success() {
        anyhow::bail!("downloading room keys failed: {status} {body}");
    }
    let http_response = http::Response::builder()
        .status(200)
        .body(serde_json::to_vec(&body)?)?;
    let downloaded = get_backup_keys::v3::Response::try_from_http_response(http_response)
        .context("malformed room_keys/keys response")?;

    // Decrypt each session and import, mirroring handle_downloaded_room_keys.
    let mut total = 0usize;
    let mut decrypted_room_keys = Vec::new();
    for (room_id, room_keys) in downloaded.rooms {
        for (session_id, room_key) in room_keys.sessions {
            total += 1;
            let room_key = match room_key.deserialize() {
                Ok(k) => k,
                Err(e) => {
                    tracing::warn!(%session_id, error = ?e, "undeserializable backed-up room key");
                    continue;
                }
            };
            match decryption_key.decrypt_session_data(room_key.session_data) {
                Ok(k) => decrypted_room_keys.push(ExportedRoomKey::from_backed_up_room_key(
                    room_id.clone(),
                    session_id,
                    k,
                )),
                Err(e) => {
                    tracing::warn!(%session_id, error = ?e, "could not decrypt backed-up room key");
                }
            }
        }
    }

    let result = ctx
        .olm
        .store()
        .import_room_keys(decrypted_room_keys, Some(&version_info.version), |_, _| {})
        .await
        .context("importing room keys failed")?;
    tracing::info!(
        imported = result.imported_count,
        total,
        "restored room keys from backup"
    );

    Ok(BackupRestoreReport {
        backup_version: Some(version_info.version),
        enabled: true,
        total_keys_in_backup: total,
        imported_keys: result.imported_count,
    })
}
