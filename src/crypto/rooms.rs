use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use matrix_sdk_crypto::store::types::RoomSettings;
use matrix_sdk_crypto::types::EventEncryptionAlgorithm;
use ruma::events::room::history_visibility::HistoryVisibility;
use ruma::{OwnedRoomId, OwnedUserId, RoomId};
use tokio::sync::{Mutex, RwLock};

use crate::session::AccountContext;

const MEMBER_CACHE_TTL: Duration = Duration::from_secs(600);

/// Per-account room metadata the proxy tracks from sync traffic.
#[derive(Default)]
pub struct RoomTracker {
    history_visibility: RwLock<HashMap<OwnedRoomId, HistoryVisibility>>,
    members: RwLock<HashMap<OwnedRoomId, MemberCache>>,
    /// Rooms confirmed to have no m.room.encryption state (negative cache,
    /// invalidated when an encryption event shows up in sync).
    unencrypted: RwLock<HashSet<OwnedRoomId>>,
    /// Megolm session IDs for which a room key request was already sent.
    pub requested_sessions: Mutex<HashSet<String>>,
}

struct MemberCache {
    at: Instant,
    members: Vec<OwnedUserId>,
}

impl RoomTracker {
    pub async fn history_visibility(&self, room_id: &RoomId) -> Option<HistoryVisibility> {
        self.history_visibility.read().await.get(room_id).cloned()
    }

    pub async fn cached_members(&self, room_id: &RoomId) -> Option<Vec<OwnedUserId>> {
        let map = self.members.read().await;
        let cache = map.get(room_id)?;
        (cache.at.elapsed() < MEMBER_CACHE_TTL).then(|| cache.members.clone())
    }

    pub async fn cache_members(&self, room_id: &RoomId, members: Vec<OwnedUserId>) {
        self.members.write().await.insert(
            room_id.to_owned(),
            MemberCache {
                at: Instant::now(),
                members,
            },
        );
    }

    pub async fn invalidate_members(&self, room_id: &RoomId) {
        self.members.write().await.remove(room_id);
    }

    pub async fn is_known_unencrypted(&self, room_id: &RoomId) -> bool {
        self.unencrypted.read().await.contains(room_id)
    }

    pub async fn mark_unencrypted(&self, room_id: &RoomId) {
        self.unencrypted.write().await.insert(room_id.to_owned());
    }

    async fn mark_encrypted(&self, room_id: &RoomId) {
        self.unencrypted.write().await.remove(room_id);
    }
}

/// Is this room encrypted? Checks the negative cache, then the persisted
/// RoomSettings, then falls back to asking the homeserver for the
/// m.room.encryption state event.
pub async fn is_room_encrypted(ctx: &AccountContext, room_id: &RoomId) -> anyhow::Result<bool> {
    if ctx.rooms.is_known_unencrypted(room_id).await {
        return Ok(false);
    }
    if ctx.olm.room_settings(room_id).await?.is_some() {
        return Ok(true);
    }

    let path = format!(
        "/_matrix/client/v3/rooms/{}/state/m.room.encryption",
        crate::crypto::machine::enc(room_id.as_str())
    );
    let (status, body) = ctx
        .upstream
        .json_request(reqwest::Method::GET, &path, &ctx.token, None)
        .await?;
    if status == reqwest::StatusCode::NOT_FOUND {
        ctx.rooms.mark_unencrypted(room_id).await;
        return Ok(false);
    }
    if !status.is_success() {
        anyhow::bail!("failed to fetch m.room.encryption state: {status} {body}");
    }
    // The state endpoint returns the event *content* directly.
    let Some(settings) = room_settings_from_content(&body) else {
        anyhow::bail!("malformed m.room.encryption content: {body}");
    };
    ctx.rooms.mark_encrypted(room_id).await;
    if let Err(e) = ctx.olm.set_room_settings(room_id, &settings).await {
        tracing::debug!(%room_id, error = ?e, "set_room_settings rejected");
    }
    Ok(true)
}

/// Full joined member list for a room (sync state is lazy-loaded, so room key
/// sharing must use this endpoint), cached with a TTL.
pub async fn joined_members(
    ctx: &AccountContext,
    room_id: &RoomId,
) -> anyhow::Result<Vec<OwnedUserId>> {
    if let Some(members) = ctx.rooms.cached_members(room_id).await {
        return Ok(members);
    }
    let path = format!(
        "/_matrix/client/v3/rooms/{}/joined_members",
        crate::crypto::machine::enc(room_id.as_str())
    );
    let (status, body) = ctx
        .upstream
        .json_request(reqwest::Method::GET, &path, &ctx.token, None)
        .await?;
    if !status.is_success() {
        anyhow::bail!("joined_members failed: {status} {body}");
    }
    let members: Vec<OwnedUserId> = body
        .get("joined")
        .and_then(|v| v.as_object())
        .map(|joined| {
            joined
                .keys()
                .filter_map(|k| k.parse::<OwnedUserId>().ok())
                .collect()
        })
        .unwrap_or_default();
    if members.is_empty() {
        anyhow::bail!("joined_members returned no members for {room_id}");
    }
    ctx.rooms.cache_members(room_id, members.clone()).await;
    Ok(members)
}

/// History visibility for room key sharing; tracked from sync, fetched on
/// demand otherwise, defaulting to the spec default (shared).
pub async fn history_visibility_or_fetch(
    ctx: &AccountContext,
    room_id: &RoomId,
) -> HistoryVisibility {
    if let Some(v) = ctx.rooms.history_visibility(room_id).await {
        return v;
    }
    let path = format!(
        "/_matrix/client/v3/rooms/{}/state/m.room.history_visibility",
        crate::crypto::machine::enc(room_id.as_str())
    );
    let visibility = match ctx
        .upstream
        .json_request(reqwest::Method::GET, &path, &ctx.token, None)
        .await
    {
        Ok((status, body)) if status.is_success() => body
            .get("history_visibility")
            .and_then(|v| v.as_str())
            .map(HistoryVisibility::from)
            .unwrap_or(HistoryVisibility::Shared),
        _ => HistoryVisibility::Shared,
    };
    ctx.rooms
        .history_visibility
        .write()
        .await
        .insert(room_id.to_owned(), visibility.clone());
    visibility
}

/// Parse an m.room.encryption event's content into RoomSettings.
pub fn room_settings_from_content(content: &serde_json::Value) -> Option<RoomSettings> {
    let algorithm = content.get("algorithm")?.as_str()?;
    Some(RoomSettings {
        algorithm: EventEncryptionAlgorithm::from(algorithm),
        only_allow_trusted_devices: false,
        session_rotation_period: content
            .get("rotation_period_ms")
            .and_then(|v| v.as_u64())
            .map(Duration::from_millis),
        session_rotation_period_messages: content
            .get("rotation_period_msgs")
            .and_then(|v| v.as_u64())
            .map(|v| v as usize),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_encryption_content() {
        let settings = room_settings_from_content(&serde_json::json!({
            "algorithm": "m.megolm.v1.aes-sha2",
            "rotation_period_ms": 604800000u64,
            "rotation_period_msgs": 100,
        }))
        .unwrap();
        assert_eq!(
            settings.algorithm,
            EventEncryptionAlgorithm::MegolmV1AesSha2
        );
        assert_eq!(
            settings.session_rotation_period,
            Some(Duration::from_millis(604800000))
        );
        assert_eq!(settings.session_rotation_period_messages, Some(100));

        // Defaults: only algorithm is required.
        let settings =
            room_settings_from_content(&serde_json::json!({"algorithm": "m.megolm.v1.aes-sha2"}))
                .unwrap();
        assert_eq!(settings.session_rotation_period, None);

        // Missing algorithm -> None.
        assert!(room_settings_from_content(&serde_json::json!({})).is_none());
    }
}

/// Scan state events (from sync `state.events`, timeline state events, or
/// /messages `state`) for room metadata the proxy cares about.
pub async fn scan_state_events(
    ctx: &AccountContext,
    room_id: &RoomId,
    events: &[serde_json::Value],
) {
    for event in events {
        // Only state events (they carry a state_key).
        if event.get("state_key").and_then(|v| v.as_str()).is_none() {
            continue;
        }
        let Some(event_type) = event.get("type").and_then(|v| v.as_str()) else {
            continue;
        };
        match event_type {
            "m.room.encryption" => {
                let Some(content) = event.get("content") else {
                    continue;
                };
                let Some(settings) = room_settings_from_content(content) else {
                    continue;
                };
                ctx.rooms.mark_encrypted(room_id).await;
                if let Err(e) = ctx.olm.set_room_settings(room_id, &settings).await {
                    // A differing re-configuration is rejected as a downgrade
                    // by matrix-sdk-crypto; the original settings stay active.
                    tracing::debug!(%room_id, error = ?e, "set_room_settings rejected");
                } else {
                    tracing::info!(%room_id, "room is encrypted");
                }
            }
            "m.room.history_visibility" => {
                if let Some(visibility) = event
                    .pointer("/content/history_visibility")
                    .and_then(|v| v.as_str())
                {
                    ctx.rooms
                        .history_visibility
                        .write()
                        .await
                        .insert(room_id.to_owned(), HistoryVisibility::from(visibility));
                }
            }
            "m.room.member" => {
                ctx.rooms.invalidate_members(room_id).await;
            }
            _ => {}
        }
    }
}
