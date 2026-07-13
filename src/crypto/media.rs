//! Encrypted attachments: encrypt every upload (keys cached per mxc URI),
//! decrypt intercepted downloads, and rewrite `url` <-> `file` in message
//! contents. AES-CTR + SHA-256 per the Matrix spec, via matrix-sdk-crypto's
//! AttachmentEncryptor/AttachmentDecryptor.

use std::io::{Cursor, Read as _};
use std::path::Path;
use std::sync::{Arc, Mutex};

use anyhow::Context as _;
use axum::body::Body;
use axum::extract::Request;
use axum::http::header;
use axum::response::Response;
use matrix_sdk_crypto::{AttachmentDecryptor, AttachmentEncryptor, MediaEncryptionInfo};
use ruma::events::room::EncryptedFile;
use serde_json::Value;

use crate::crypto::machine;
use crate::error::ProxyError;
use crate::proxy::AppState;
use crate::proxy::intercept::raw_response;
use crate::session::AccountContext;

const MAX_UPLOAD_BYTES: usize = 512 * 1024 * 1024;

/// Persistent mxc -> encryption-key cache (survives proxy restarts; without
/// it, previously received encrypted media could no longer be decrypted).
pub struct MediaKeyCache {
    conn: Mutex<rusqlite::Connection>,
}

pub struct MediaEntry {
    pub info: MediaEncryptionInfo,
    pub mimetype: Option<String>,
    pub filename: Option<String>,
}

impl MediaKeyCache {
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        let conn = rusqlite::Connection::open(path)
            .with_context(|| format!("failed to open media cache at {}", path.display()))?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS media_keys (
                mxc TEXT PRIMARY KEY,
                key_json TEXT NOT NULL,
                mimetype TEXT,
                filename TEXT
            );",
        )?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    pub fn insert(
        &self,
        mxc: &str,
        info: &MediaEncryptionInfo,
        mimetype: Option<&str>,
        filename: Option<&str>,
    ) -> anyhow::Result<()> {
        let key_json = serde_json::to_string(info)?;
        self.conn.lock().unwrap().execute(
            "INSERT OR REPLACE INTO media_keys (mxc, key_json, mimetype, filename)
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![mxc, key_json, mimetype, filename],
        )?;
        Ok(())
    }

    pub fn get(&self, mxc: &str) -> Option<MediaEntry> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT key_json, mimetype, filename FROM media_keys WHERE mxc = ?1",
            [mxc],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                ))
            },
        )
        .ok()
        .and_then(|(key_json, mimetype, filename)| {
            Some(MediaEntry {
                info: serde_json::from_str(&key_json).ok()?,
                mimetype,
                filename,
            })
        })
    }
}

pub fn encrypt_attachment(data: &[u8]) -> anyhow::Result<(Vec<u8>, MediaEncryptionInfo)> {
    let mut cursor = Cursor::new(data);
    let mut encryptor = AttachmentEncryptor::new(&mut cursor);
    let mut encrypted = Vec::with_capacity(data.len());
    encryptor.read_to_end(&mut encrypted)?;
    Ok((encrypted, encryptor.finish()))
}

pub fn decrypt_attachment(data: &[u8], info: MediaEncryptionInfo) -> anyhow::Result<Vec<u8>> {
    let mut cursor = Cursor::new(data);
    let mut decryptor =
        AttachmentDecryptor::new(&mut cursor, info).context("bad media encryption info")?;
    let mut decrypted = Vec::with_capacity(data.len());
    decryptor
        .read_to_end(&mut decrypted)
        .context("media decryption failed (hash mismatch?)")?;
    Ok(decrypted)
}

/// Intercept POST /_matrix/media/*/upload: encrypt the payload, upload the
/// ciphertext (as octet-stream, without the filename), remember the key.
pub async fn handle_upload(
    state: &AppState,
    ctx: Arc<AccountContext>,
    req: Request,
) -> Result<Response, ProxyError> {
    let query = req.uri().query().unwrap_or_default();
    let filename = query.split('&').find_map(|kv| {
        kv.strip_prefix("filename=").map(|v| {
            percent_encoding::percent_decode_str(v)
                .decode_utf8_lossy()
                .into_owned()
        })
    });
    let content_type = req
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(ToOwned::to_owned);

    let body = axum::body::to_bytes(req.into_body(), MAX_UPLOAD_BYTES)
        .await
        .map_err(|e| ProxyError::BadRequest(format!("failed to read upload: {e}")))?;

    let (encrypted, info) =
        encrypt_attachment(&body).map_err(ProxyError::Internal)?;

    // Upload ciphertext: opaque content type, no filename (metadata hygiene).
    let upstream_resp = state
        .upstream
        .http
        .post(state.upstream.url("/_matrix/media/v3/upload"))
        .bearer_auth(&ctx.token)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .body(encrypted)
        .send()
        .await?;
    let status = upstream_resp.status();
    let bytes = upstream_resp.bytes().await?;

    if status.is_success() {
        if let Some(mxc) = serde_json::from_slice::<Value>(&bytes)
            .ok()
            .and_then(|v| v.get("content_uri").and_then(|u| u.as_str()).map(ToOwned::to_owned))
        {
            ctx.media
                .insert(&mxc, &info, content_type.as_deref(), filename.as_deref())
                .map_err(ProxyError::Internal)?;
            tracing::info!(%mxc, "uploaded encrypted attachment");
        }
    }
    raw_response(
        status.as_u16(),
        Some(header::HeaderValue::from_static("application/json")),
        bytes.to_vec(),
    )
}

/// Intercept media downloads (both the authenticated client/v1 path and the
/// legacy tokenless path ement uses for avatars): decrypt when the mxc is in
/// the key cache, otherwise relay the plaintext bytes.
pub async fn handle_download(
    state: &AppState,
    ctx: Arc<AccountContext>,
    server: String,
    media_id: String,
) -> Result<Response, ProxyError> {
    let mxc = format!("mxc://{server}/{media_id}");
    let entry = ctx.media.get(&mxc);

    // Always fetch via the authenticated endpoint using our upstream token:
    // it works for both plaintext and encrypted media, including when the
    // client's own request arrived tokenless (legacy avatar path).
    let path = format!(
        "/_matrix/client/v1/media/download/{}/{}",
        machine::enc(&server),
        machine::enc(&media_id)
    );
    let upstream_resp = state
        .upstream
        .http
        .get(state.upstream.url(&path))
        .bearer_auth(&ctx.token)
        .send()
        .await?;
    let status = upstream_resp.status();
    let upstream_ct = upstream_resp.headers().get(header::CONTENT_TYPE).cloned();
    let bytes = upstream_resp.bytes().await?;

    let Some(entry) = entry else {
        return raw_response(status.as_u16(), upstream_ct, bytes.to_vec());
    };
    if !status.is_success() {
        return raw_response(status.as_u16(), upstream_ct, bytes.to_vec());
    }

    let decrypted = decrypt_attachment(&bytes, entry.info).map_err(ProxyError::Internal)?;
    let content_type = entry
        .mimetype
        .as_deref()
        .and_then(|m| header::HeaderValue::from_str(m).ok())
        .unwrap_or(header::HeaderValue::from_static("application/octet-stream"));

    let mut builder = Response::builder()
        .status(200)
        .header(header::CONTENT_TYPE, content_type);
    if let Some(filename) = &entry.filename {
        if let Ok(disposition) =
            header::HeaderValue::from_str(&format!("inline; filename=\"{filename}\""))
        {
            builder = builder.header(header::CONTENT_DISPOSITION, disposition);
        }
    }
    builder
        .body(Body::from(decrypted))
        .map_err(|e| ProxyError::Internal(e.into()))
}

/// Outgoing content rewrite for encrypted rooms: turn `url` into an
/// `EncryptedFile`-shaped `file` object using the cached upload key.
pub fn rewrite_content_for_encrypted_room(ctx: &AccountContext, content: &mut Value) {
    let Some(mxc) = content.get("url").and_then(|v| v.as_str()).map(ToOwned::to_owned) else {
        return;
    };
    let Some(entry) = ctx.media.get(&mxc) else {
        // Plaintext upload (e.g. from before the proxy); nothing we can do.
        return;
    };
    let Ok(mut file) = serde_json::to_value(&entry.info) else {
        return;
    };
    file["url"] = mxc.into();
    let content_obj = match content.as_object_mut() {
        Some(o) => o,
        None => return,
    };
    content_obj.remove("url");
    content_obj.insert("file".into(), file);
    // Make sure the mimetype survives (ement may not set info at all).
    if let Some(mimetype) = &entry.mimetype {
        let info = content_obj
            .entry("info")
            .or_insert_with(|| serde_json::json!({}));
        if let Some(info) = info.as_object_mut() {
            info.entry("mimetype".to_owned())
                .or_insert_with(|| mimetype.clone().into());
        }
    }
}

/// Incoming content rewrite after decryption: harvest keys from `file` /
/// `info.thumbnail_file` and expose plain `url`s so ement's media rendering
/// works unchanged (downloads come back through handle_download).
pub fn harvest_and_rewrite_decrypted(ctx: &AccountContext, event: &mut Value) {
    let Some(content) = event.get_mut("content").and_then(Value::as_object_mut) else {
        return;
    };

    let filename_hint = content
        .get("body")
        .and_then(|v| v.as_str())
        .map(ToOwned::to_owned);
    let mimetype_hint = content
        .get("info")
        .and_then(|i| i.get("mimetype"))
        .and_then(|v| v.as_str())
        .map(ToOwned::to_owned);

    if let Some(file_value) = content.get("file").cloned() {
        if let Some(url) = harvest_file(
            ctx,
            file_value,
            mimetype_hint.as_deref(),
            filename_hint.as_deref(),
        ) {
            content.remove("file");
            content.insert("url".into(), url.into());
        }
    }

    if let Some(info) = content.get_mut("info").and_then(Value::as_object_mut) {
        if let Some(thumb_value) = info.get("thumbnail_file").cloned() {
            let thumb_mime = info
                .get("thumbnail_info")
                .and_then(|i| i.get("mimetype"))
                .and_then(|v| v.as_str())
                .map(ToOwned::to_owned);
            if let Some(url) = harvest_file(ctx, thumb_value, thumb_mime.as_deref(), None) {
                info.remove("thumbnail_file");
                info.insert("thumbnail_url".into(), url.into());
            }
        }
    }
}

fn harvest_file(
    ctx: &AccountContext,
    file_value: Value,
    mimetype: Option<&str>,
    filename: Option<&str>,
) -> Option<String> {
    let file: EncryptedFile = serde_json::from_value(file_value).ok()?;
    let url = file.url.to_string();
    let info = MediaEncryptionInfo::from(file);
    if let Err(e) = ctx.media.insert(&url, &info, mimetype, filename) {
        tracing::warn!(%url, error = ?e, "failed to cache media key");
        return None;
    }
    Some(url)
}

/// Fix-up for sending previously-uploaded (thus encrypted) media into an
/// UNencrypted room: download + decrypt + re-upload as plaintext, and point
/// the content at the new mxc.
pub async fn reupload_plaintext_if_needed(
    state: &AppState,
    ctx: &Arc<AccountContext>,
    content: &mut Value,
) -> anyhow::Result<()> {
    let Some(mxc) = content.get("url").and_then(|v| v.as_str()).map(ToOwned::to_owned) else {
        return Ok(());
    };
    let Some(entry) = ctx.media.get(&mxc) else {
        return Ok(());
    };

    let (server, media_id) = mxc
        .strip_prefix("mxc://")
        .and_then(|rest| rest.split_once('/'))
        .context("malformed mxc URI")?;
    let path = format!(
        "/_matrix/client/v1/media/download/{}/{}",
        machine::enc(server),
        machine::enc(media_id)
    );
    let resp = state
        .upstream
        .http
        .get(state.upstream.url(&path))
        .bearer_auth(&ctx.token)
        .send()
        .await?;
    anyhow::ensure!(resp.status().is_success(), "download for re-upload failed");
    let encrypted = resp.bytes().await?;
    let plaintext = decrypt_attachment(&encrypted, entry.info)?;

    let mut upload_url = state.upstream.url("/_matrix/media/v3/upload");
    if let Some(filename) = &entry.filename {
        upload_url.query_pairs_mut().append_pair("filename", filename);
    }
    let resp = state
        .upstream
        .http
        .post(upload_url)
        .bearer_auth(&ctx.token)
        .header(
            header::CONTENT_TYPE,
            entry.mimetype.as_deref().unwrap_or("application/octet-stream"),
        )
        .body(plaintext)
        .send()
        .await?;
    anyhow::ensure!(resp.status().is_success(), "plaintext re-upload failed");
    let body: Value = resp.json().await?;
    let new_mxc = body
        .get("content_uri")
        .and_then(|v| v.as_str())
        .context("upload response missing content_uri")?;

    tracing::info!(old = %mxc, new = %new_mxc, "re-uploaded media as plaintext for unencrypted room");
    content["url"] = new_mxc.into();
    Ok(())
}
