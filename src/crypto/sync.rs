use std::collections::{BTreeMap, HashSet, VecDeque};
use std::hash::BuildHasher;
use std::sync::Arc;
use std::time::SystemTime;

use anyhow::Context as _;
use axum::extract::Request;
use axum::http::header;
use axum::response::Response;
use matrix_sdk_crypto::EncryptionSyncChanges;
use ruma::api::client::sync::sync_events::DeviceLists;
use ruma::events::AnyToDeviceEvent;
use ruma::serde::Raw;
use ruma::{OneTimeKeyAlgorithm, UInt};
use tokio::sync::Mutex;

use crate::crypto::machine;
use crate::error::ProxyError;
use crate::proxy::AppState;
use crate::proxy::intercept::raw_response;
use crate::session::AccountContext;

/// Counters over the client's sync stream, for `ctl debug`.
#[derive(Clone, Debug, Default)]
pub struct SyncStats {
    pub client_syncs: u64,
    pub last_client_sync: Option<SystemTime>,
    pub to_device_events: u64,
    /// To-device events delivered more than once and processed only once.
    pub to_device_duplicates: u64,
    pub room_keys_received: u64,
}

/// How many to-device events to remember for de-duplication. A repeat
/// arrives with the very next sync, if at all.
const SEEN_TO_DEVICE_CAPACITY: usize = 4096;

/// Recently processed to-device events, by keyed hash of their JSON.
pub struct SeenToDevice {
    hasher: std::hash::RandomState,
    order: VecDeque<u64>,
    set: HashSet<u64>,
}

impl Default for SeenToDevice {
    fn default() -> Self {
        Self {
            // Keyed per process, so a sender cannot craft an event that
            // collides with (and thereby suppresses) someone else's.
            hasher: std::hash::RandomState::new(),
            order: VecDeque::new(),
            set: HashSet::new(),
        }
    }
}

impl SeenToDevice {
    fn key(&self, event: &serde_json::Value) -> u64 {
        // serde_json hashes objects independently of key order.
        self.hasher.hash_one(event)
    }

    /// Remember an event; false if it was already seen.
    fn insert(&mut self, key: u64) -> bool {
        if !self.set.insert(key) {
            return false;
        }
        self.order.push_back(key);
        if self.order.len() > SEEN_TO_DEVICE_CAPACITY
            && let Some(oldest) = self.order.pop_front()
        {
            self.set.remove(&oldest);
        }
        true
    }

    fn forget(&mut self, key: u64) {
        if self.set.remove(&key) {
            self.order.retain(|k| *k != key);
        }
    }
}

/// Per-account bookkeeping for the processing of sync responses.
#[derive(Default)]
pub struct SyncState {
    /// Serializes the processing of sync responses, so that a to-device
    /// event delivered twice is handed to the OlmMachine exactly once and in
    /// order.
    seen: Mutex<SeenToDevice>,
    stats: std::sync::Mutex<SyncStats>,
}

/// While held, no sync response is processed for the account.
pub struct SyncPause<'a>(#[allow(dead_code)] tokio::sync::MutexGuard<'a, SeenToDevice>);

impl SyncState {
    pub fn stats(&self) -> SyncStats {
        self.stats.lock().unwrap().clone()
    }

    /// Hold off sync processing, for work that must not interleave with it
    /// (the SDK garbage-collects ended verification flows when it processes
    /// a sync).
    pub async fn pause(&self) -> SyncPause<'_> {
        SyncPause(self.seen.lock().await)
    }

    fn update(&self, update: impl FnOnce(&mut SyncStats)) {
        update(&mut self.stats.lock().unwrap());
    }
}

/// Intercept GET /sync: forward verbatim, feed the crypto-relevant sections
/// into the OlmMachine *before* handing the response (and thus next_batch)
/// back to ement, then return the rewritten body.
pub async fn handle_sync(
    state: &AppState,
    ctx: Arc<AccountContext>,
    req: Request,
) -> Result<Response, ProxyError> {
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_owned())
        .unwrap_or_else(|| "/".to_owned());
    let since = query_param(req.uri().query().unwrap_or_default(), "since");
    drop(req);

    // Listen before looking, so a repair that becomes possible while the
    // upstream request is pending is not missed.
    let repair_ready = ctx.repairs.woken();
    tokio::pin!(repair_ready);
    repair_ready.as_mut().enable();

    let upstream_request = state
        .upstream
        .http
        .get(state.upstream.url(&path_and_query))
        .bearer_auth(&ctx.token)
        .send();
    let upstream_resp = match &since {
        // An incremental sync long-polls upstream, possibly for a long time.
        // If a placeholder can be repaired meanwhile, answer at once.
        Some(since) => {
            if ctx.repairs.has_ready() {
                return repair_only_response(&ctx, since).await;
            }
            tokio::select! {
                response = upstream_request => response?,
                () = &mut repair_ready => return repair_only_response(&ctx, since).await,
            }
        }
        None => upstream_request.await?,
    };

    let status = upstream_resp.status();
    let content_type = upstream_resp
        .headers()
        .get(header::CONTENT_TYPE)
        .cloned();
    let bytes = upstream_resp.bytes().await?;

    if !status.is_success() {
        // A dead token means this context is stale; evict so a future token
        // re-initializes cleanly (the on-disk stores are preserved).
        if is_unknown_token(status, &bytes) {
            tracing::info!(user_id = %ctx.user_id, "access token invalidated; evicting session");
            state.sessions.remove(&ctx.token).await;
        }
        return raw_response(status.as_u16(), content_type, bytes.to_vec());
    }

    let mut body: serde_json::Value =
        serde_json::from_slice(&bytes).context("sync response is not valid JSON")?;

    receive_sync_changes(&ctx, &body).await?;

    // Rewrite pass: track room encryption state and decrypt m.room.encrypted
    // timeline events. Must run after receive_sync_changes so room keys from
    // this very sync are usable.
    crate::crypto::decrypt::process_sync_body(&ctx, &mut body).await;

    // Pump *after* receive_sync_changes: sync may have queued key uploads,
    // key queries for changed devices, etc. Fire and forget.
    tokio::spawn({
        let ctx = ctx.clone();
        async move { machine::pump(&ctx).await }
    });

    let bytes = serde_json::to_vec(&body).context("failed to re-serialize sync response")?;
    raw_response(200, content_type, bytes)
}

/// Answer a client /sync with nothing but placeholder repairs. The response
/// hands the client's own `since` back as next_batch: nothing from upstream
/// was consumed, so its next request resumes exactly where this one stood.
async fn repair_only_response(
    ctx: &Arc<AccountContext>,
    since: &str,
) -> Result<Response, ProxyError> {
    let mut body = serde_json::json!({ "next_batch": since });
    crate::crypto::repair::inject(ctx, &mut body).await;
    let bytes = serde_json::to_vec(&body).context("failed to serialize sync response")?;
    raw_response(
        200,
        Some(header::HeaderValue::from_static("application/json")),
        bytes,
    )
}

fn query_param(query: &str, name: &str) -> Option<String> {
    query.split('&').find_map(|pair| {
        let (key, value) = pair.split_once('=')?;
        (key == name).then(|| {
            percent_encoding::percent_decode_str(value)
                .decode_utf8_lossy()
                .into_owned()
        })
    })
}

/// Feed the crypto-relevant sections of a /sync response into the
/// OlmMachine.
async fn receive_sync_changes(
    ctx: &AccountContext,
    body: &serde_json::Value,
) -> Result<(), ProxyError> {
    // The homeserver delivers a to-device event on every sync until a later
    // request's `since` acknowledges it. The proxy processes a response
    // before the client has even seen it, so a client that asks again from
    // the same position (a retry after a lost response, a restart) brings
    // the same events back. Olm messages can only be decrypted once: drop
    // the repeats.
    let mut seen = ctx.sync.seen.lock().await;
    let mut to_device_events: Vec<Raw<AnyToDeviceEvent>> = Vec::new();
    let mut new_keys = Vec::new();
    let mut duplicates = 0u64;
    let incoming = body
        .pointer("/to_device/events")
        .and_then(|v| v.as_array())
        .map(Vec::as_slice)
        .unwrap_or_default();
    for event in incoming {
        let key = seen.key(event);
        if !seen.insert(key) {
            duplicates += 1;
            continue;
        }
        new_keys.push(key);
        to_device_events.push(
            serde_json::from_value(event.clone())
                .context("invalid to_device.events in sync response")?,
        );
    }

    let result = process_sync_changes(ctx, body, to_device_events).await;
    match &result {
        Ok(room_keys) => {
            let now = SystemTime::now();
            ctx.sync.update(|stats| {
                stats.client_syncs += 1;
                stats.last_client_sync = Some(now);
                stats.to_device_events += new_keys.len() as u64;
                stats.to_device_duplicates += duplicates;
                stats.room_keys_received += *room_keys as u64;
            });
        }
        // Nothing was processed: let a later delivery of the same events
        // through instead of treating it as a repeat.
        Err(_) => new_keys.iter().for_each(|key| seen.forget(*key)),
    }
    result.map(|_| ())
}

/// Returns the number of room keys received.
async fn process_sync_changes(
    ctx: &AccountContext,
    body: &serde_json::Value,
    to_device_events: Vec<Raw<AnyToDeviceEvent>>,
) -> Result<usize, ProxyError> {
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
    let has_key_counts = body.get("device_one_time_keys_count").is_some();
    let changes = EncryptionSyncChanges {
        to_device_events,
        changed_devices: &changed_devices,
        one_time_keys_counts: &one_time_keys_counts,
        unused_fallback_keys: unused_fallback_keys.as_deref(),
        next_batch_token: next_batch,
    };
    let settings = machine::decryption_settings();
    // The spec has every /sync response carry the one-time-key counts, an
    // unlisted algorithm meaning zero, and that is how the SDK reads them.
    // Some homeservers leave the whole field out when nothing changed;
    // reading that as "zero keys left" would publish a fresh batch on every
    // sync. For those responses use the variant where absent means unchanged.
    let result = if has_key_counts {
        ctx.olm.receive_sync_changes(changes, &settings).await
    } else {
        ctx.olm.receive_sync_changes_msc4186(changes, &settings).await
    };
    let (_processed, room_key_infos) = result.context("receive_sync_changes failed")?;

    ctx.repairs
        .note_room_keys(room_key_infos.iter().map(|info| info.session_id.clone()));
    // The SDK forgets finished verification flows on the next sync.
    crate::crypto::verify::record_finished(ctx);

    if n_to_device > 0 || !room_key_infos.is_empty() {
        tracing::debug!(
            to_device = n_to_device,
            new_room_keys = room_key_infos.len(),
            "processed sync crypto changes"
        );
    }
    Ok(room_key_infos.len())
}

/// Is this the homeserver telling us the access token is dead?
fn is_unknown_token(status: reqwest::StatusCode, body: &[u8]) -> bool {
    status == reqwest::StatusCode::UNAUTHORIZED
        && serde_json::from_slice::<serde_json::Value>(body)
            .ok()
            .and_then(|v| v.get("errcode").and_then(|c| c.as_str()).map(ToOwned::to_owned))
            .as_deref()
            == Some("M_UNKNOWN_TOKEN")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_device_repeats_are_recognised_whatever_the_key_order() {
        let mut seen = SeenToDevice::default();
        let event: serde_json::Value = serde_json::from_str(
            r#"{"type":"m.room.encrypted","sender":"@a:b","content":{"x":1,"y":[1,2]}}"#,
        )
        .unwrap();
        let reordered: serde_json::Value = serde_json::from_str(
            r#"{"content":{"y":[1,2],"x":1},"sender":"@a:b","type":"m.room.encrypted"}"#,
        )
        .unwrap();
        let different: serde_json::Value = serde_json::from_str(
            r#"{"type":"m.room.encrypted","sender":"@a:b","content":{"x":2,"y":[1,2]}}"#,
        )
        .unwrap();

        assert!(seen.insert(seen.key(&event)));
        assert!(!seen.insert(seen.key(&event)));
        assert!(!seen.insert(seen.key(&reordered)));
        assert!(seen.insert(seen.key(&different)));

        // A failed batch is forgotten so its redelivery is processed.
        seen.forget(seen.key(&event));
        assert!(seen.insert(seen.key(&reordered)));
    }

    #[test]
    fn to_device_memory_is_bounded() {
        let mut seen = SeenToDevice::default();
        for i in 0..SEEN_TO_DEVICE_CAPACITY + 10 {
            assert!(seen.insert(seen.key(&serde_json::json!({ "n": i }))));
        }
        assert_eq!(seen.set.len(), SEEN_TO_DEVICE_CAPACITY);
        assert_eq!(seen.order.len(), SEEN_TO_DEVICE_CAPACITY);
        // The oldest entries have been evicted, the newest are still known.
        assert!(seen.insert(seen.key(&serde_json::json!({ "n": 0 }))));
        assert!(!seen.insert(seen.key(&serde_json::json!({ "n": SEEN_TO_DEVICE_CAPACITY + 9 }))));
    }

    #[test]
    fn unknown_token_detection() {
        let unauthorized = reqwest::StatusCode::UNAUTHORIZED;
        assert!(is_unknown_token(unauthorized, br#"{"errcode":"M_UNKNOWN_TOKEN"}"#));
        // Other 401s (e.g. M_MISSING_TOKEN) and other statuses are transient
        // or someone else's problem: they must not evict the session.
        assert!(!is_unknown_token(unauthorized, br#"{"errcode":"M_MISSING_TOKEN"}"#));
        assert!(!is_unknown_token(unauthorized, b"not json"));
        assert!(!is_unknown_token(
            reqwest::StatusCode::FORBIDDEN,
            br#"{"errcode":"M_UNKNOWN_TOKEN"}"#
        ));
    }
}
