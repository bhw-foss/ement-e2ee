use std::sync::Arc;

use matrix_sdk_crypto::RoomEventDecryptionResult;
use matrix_sdk_crypto::types::events::room::encrypted::EncryptedEvent;
use ruma::serde::Raw;
use ruma::{OwnedRoomId, RoomId};
use serde_json::{Value, json};

use crate::crypto::{machine, rooms};
use crate::session::AccountContext;

/// Rewrite a /sync response body in place: track room state and decrypt
/// m.room.encrypted timeline events.
pub async fn process_sync_body(ctx: &Arc<AccountContext>, body: &mut Value) {
    let Some(rooms_value) = body.get_mut("rooms") else {
        return;
    };
    for section in ["join", "leave"] {
        let Some(section_rooms) = rooms_value.get_mut(section).and_then(Value::as_object_mut)
        else {
            continue;
        };
        for (room_id_str, room) in section_rooms.iter_mut() {
            let Ok(room_id) = room_id_str.parse::<OwnedRoomId>() else {
                continue;
            };
            if let Some(events) = room.pointer("/state/events").and_then(Value::as_array) {
                rooms::scan_state_events(ctx, &room_id, events).await;
            }
            // State events can also arrive in the timeline section.
            if let Some(events) = room.pointer("/timeline/events").and_then(Value::as_array) {
                rooms::scan_state_events(ctx, &room_id, events).await;
            }
            if let Some(events) = room
                .pointer_mut("/timeline/events")
                .and_then(Value::as_array_mut)
            {
                decrypt_events(ctx, &room_id, events).await;
            }
        }
    }
}

/// Rewrite a GET /rooms/{id}/messages response body.
pub async fn process_messages_body(ctx: &Arc<AccountContext>, room_id: &RoomId, body: &mut Value) {
    if let Some(events) = body.get("state").and_then(Value::as_array) {
        rooms::scan_state_events(ctx, room_id, events).await;
    }
    if let Some(events) = body.get_mut("chunk").and_then(Value::as_array_mut) {
        decrypt_events(ctx, room_id, events).await;
    }
}

/// Rewrite a GET /rooms/{id}/context/{event} response body.
pub async fn process_context_body(ctx: &Arc<AccountContext>, room_id: &RoomId, body: &mut Value) {
    if let Some(events) = body.get("state").and_then(Value::as_array) {
        rooms::scan_state_events(ctx, room_id, events).await;
    }
    for key in ["events_before", "events_after"] {
        if let Some(events) = body.get_mut(key).and_then(Value::as_array_mut) {
            decrypt_events(ctx, room_id, events).await;
        }
    }
    if let Some(event) = body.get_mut("event") {
        decrypt_event(ctx, room_id, event).await;
    }
}

/// Rewrite a GET /rooms/{id}/event/{event} response body (the body is the
/// event itself).
pub async fn process_event_body(ctx: &Arc<AccountContext>, room_id: &RoomId, body: &mut Value) {
    decrypt_event(ctx, room_id, body).await;
}

pub async fn decrypt_events(ctx: &Arc<AccountContext>, room_id: &RoomId, events: &mut [Value]) {
    for event in events {
        decrypt_event(ctx, room_id, event).await;
    }
}

async fn decrypt_event(ctx: &Arc<AccountContext>, room_id: &RoomId, event: &mut Value) {
    if event.get("type").and_then(|v| v.as_str()) != Some("m.room.encrypted") {
        return;
    }
    let raw: Raw<EncryptedEvent> = match serde_json::from_value(event.clone()) {
        Ok(raw) => raw,
        Err(e) => {
            tracing::warn!(error = ?e, "malformed m.room.encrypted event");
            return;
        }
    };

    match ctx
        .olm
        .try_decrypt_room_event(&raw, room_id, &machine::decryption_settings())
        .await
    {
        Ok(RoomEventDecryptionResult::Decrypted(decrypted)) => {
            let mut new_event: Value = match serde_json::from_str(decrypted.event.json().get()) {
                Ok(v) => v,
                Err(e) => {
                    tracing::error!(error = ?e, "decrypted event is not valid JSON");
                    return;
                }
            };

            // Merge the envelope's unsigned back in (transaction_id is what
            // lets ement resolve its local echo; age/relations matter too).
            // Keys already present on the decrypted event win: they may
            // contain decrypted bundled relations.
            let original_unsigned = event.get("unsigned").and_then(Value::as_object).cloned();
            let new_unsigned = new_event
                .as_object_mut()
                .expect("decrypted event is an object")
                .entry("unsigned")
                .or_insert_with(|| json!({}));
            if let (Some(new_unsigned), Some(original)) =
                (new_unsigned.as_object_mut(), original_unsigned)
            {
                for (key, value) in original {
                    new_unsigned.entry(key).or_insert(value);
                }
                new_unsigned.insert(
                    "ement_e2ee".to_owned(),
                    json!({
                        "decrypted": true,
                        "encryption_info": serde_json::to_value(&*decrypted.encryption_info)
                            .unwrap_or(Value::Null),
                    }),
                );
            }

            *event = new_event;
        }
        Ok(RoomEventDecryptionResult::UnableToDecrypt(info)) => {
            let reason = format!("{:?}", info.reason);
            tracing::debug!(%room_id, session_id = ?info.session_id, %reason, "unable to decrypt");
            maybe_request_room_key(ctx, room_id, &raw, info.session_id.as_deref()).await;
            *event = utd_placeholder(event, &reason, info.session_id.as_deref());
        }
        Err(e) => {
            tracing::error!(error = ?e, "decryption failed with store error");
        }
    }
}

/// Replace an undecryptable event with a readable m.room.message so ement
/// (which drops m.room.encrypted silently) shows *something*.
fn utd_placeholder(original: &Value, reason: &str, session_id: Option<&str>) -> Value {
    let mut placeholder = json!({
        "type": "m.room.message",
        "content": {
            "msgtype": "m.text",
            "body": format!(
                "🔒 [undecryptable: {reason}] If keys arrive later, close and reopen the room to retry."
            ),
        },
    });
    for key in ["event_id", "sender", "origin_server_ts", "room_id"] {
        if let Some(v) = original.get(key) {
            placeholder[key] = v.clone();
        }
    }
    let mut unsigned = original
        .get("unsigned")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    unsigned.insert(
        "ement_e2ee".to_owned(),
        json!({ "utd": true, "session_id": session_id }),
    );
    placeholder["unsigned"] = Value::Object(unsigned);
    placeholder
}

/// Ask other own-devices / original sender for the missing room key, once per
/// megolm session.
async fn maybe_request_room_key(
    ctx: &Arc<AccountContext>,
    room_id: &RoomId,
    raw: &Raw<EncryptedEvent>,
    session_id: Option<&str>,
) {
    let Some(session_id) = session_id else { return };
    {
        let mut requested = ctx.rooms.requested_sessions.lock().await;
        if !requested.insert(session_id.to_owned()) {
            return;
        }
    }

    let ctx = ctx.clone();
    let room_id = room_id.to_owned();
    let raw = raw.clone();
    let session_id = session_id.to_owned();
    tokio::spawn(async move {
        let result = async {
            let (cancellation, request) = ctx.olm.request_room_key(&raw, &room_id).await?;
            if let Some(cancellation) = cancellation {
                machine::send_and_mark(&ctx, &cancellation).await?;
            }
            machine::send_and_mark(&ctx, &request).await?;
            anyhow::Ok(())
        }
        .await;
        match result {
            Ok(()) => tracing::info!(%room_id, %session_id, "room key requested"),
            Err(e) => {
                tracing::warn!(%room_id, %session_id, error = ?e, "room key request failed");
                // Allow a retry on a later UTD for this session.
                ctx.rooms.requested_sessions.lock().await.remove(&session_id);
            }
        }
    });
}
