use std::sync::Arc;

use matrix_sdk_crypto::RoomEventDecryptionResult;
use matrix_sdk_crypto::types::events::room::encrypted::EncryptedEvent;
use ruma::serde::Raw;
use ruma::{OwnedRoomId, RoomId};
use serde_json::{Value, json};

use crate::crypto::{machine, repair, rooms};
use crate::session::AccountContext;

/// Whether a placeholder emitted for an undecryptable event can later be
/// replaced in the client (see `repair`).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Placeholder {
    /// The event goes into a room timeline the client keeps: remember it
    /// and repair it when its key arrives.
    Repairable,
    /// The event is shown somewhere edits do not reach (notifications).
    Final,
}

/// Rewrite a /sync response body in place: track room state, decrypt
/// m.room.encrypted timeline events, and append repairs for placeholders
/// whose keys have arrived since.
pub async fn process_sync_body(ctx: &Arc<AccountContext>, body: &mut Value) {
    if let Some(rooms_value) = body.get_mut("rooms") {
        for section in ["join", "leave"] {
            let Some(section_rooms) = rooms_value.get_mut(section).and_then(Value::as_object_mut)
            else {
                continue;
            };
            for (room_id_str, room) in section_rooms.iter_mut() {
                let Ok(room_id) = room_id_str.parse::<OwnedRoomId>() else {
                    continue;
                };
                if section == "join" {
                    ctx.rooms
                        .note_joined(&room_id, room.get("unread_notifications"));
                } else {
                    ctx.rooms.note_left(&room_id);
                }
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
    repair::inject(ctx, body).await;
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
        decrypt_event(ctx, room_id, event, Placeholder::Repairable).await;
    }
}

/// Rewrite a GET /rooms/{id}/event/{event} response body (the body is the
/// event itself).
pub async fn process_event_body(ctx: &Arc<AccountContext>, room_id: &RoomId, body: &mut Value) {
    decrypt_event(ctx, room_id, body, Placeholder::Repairable).await;
}

/// Rewrite a GET /notifications response body. Unlike the per-room history
/// endpoints, notifications span rooms: each entry names its own room_id next
/// to the event. (Encrypted DMs notify on the m.room.encrypted envelope via
/// the `.m.rule.encrypted_room_one_to_one` push rule, so without this ement's
/// notifications buffer only ever sees ciphertext for them.)
pub async fn process_notifications_body(ctx: &Arc<AccountContext>, body: &mut Value) {
    let Some(notifications) = body.get_mut("notifications").and_then(Value::as_array_mut) else {
        return;
    };
    for notification in notifications {
        let Some(room_id) = notification
            .get("room_id")
            .and_then(Value::as_str)
            .and_then(|id| id.parse::<OwnedRoomId>().ok())
        else {
            continue;
        };
        if let Some(event) = notification.get_mut("event") {
            // The notifications buffer is not a room timeline: a later edit
            // would not find these entries.
            decrypt_event(ctx, &room_id, event, Placeholder::Final).await;
        }
    }
}

async fn decrypt_events(ctx: &Arc<AccountContext>, room_id: &RoomId, events: &mut [Value]) {
    for event in events {
        decrypt_event(ctx, room_id, event, Placeholder::Repairable).await;
    }
}

/// What became of an attempt to decrypt one m.room.encrypted event.
pub(crate) enum Decryption {
    /// The plaintext event, ready for the client.
    Decrypted(Value),
    /// No usable key (yet).
    Undecryptable {
        reason: String,
        session_id: Option<String>,
        raw: Raw<EncryptedEvent>,
    },
    /// Not an encrypted event, or a failure that is not about keys: the
    /// event is passed on as it came.
    Untouched,
}

/// Decrypt one event without modifying it.
pub(crate) async fn decrypt(
    ctx: &Arc<AccountContext>,
    room_id: &RoomId,
    event: &Value,
) -> Decryption {
    if event.get("type").and_then(|v| v.as_str()) != Some("m.room.encrypted") {
        return Decryption::Untouched;
    }
    let raw: Raw<EncryptedEvent> = match serde_json::from_value(event.clone()) {
        Ok(raw) => raw,
        Err(e) => {
            tracing::warn!(error = ?e, "malformed m.room.encrypted event");
            return Decryption::Untouched;
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
                    return Decryption::Untouched;
                }
            };

            // Merge the envelope's unsigned back in (transaction_id is what
            // lets ement resolve its local echo; age/relations matter too).
            // Keys already present on the decrypted event win: they may
            // contain decrypted bundled relations.
            let original_unsigned = event.get("unsigned").and_then(Value::as_object).cloned();
            let Some(new_object) = new_event.as_object_mut() else {
                tracing::error!("decrypted event is not a JSON object");
                return Decryption::Untouched;
            };
            let new_unsigned = new_object.entry("unsigned").or_insert_with(|| json!({}));
            if let Some(new_unsigned) = new_unsigned.as_object_mut() {
                for (key, value) in original_unsigned.unwrap_or_default() {
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

            maybe_feed_verification(ctx, &new_event).await;
            // Harvest attachment keys and expose plain URLs for ement.
            crate::crypto::media::harvest_and_rewrite_decrypted(ctx, &mut new_event);
            Decryption::Decrypted(new_event)
        }
        Ok(RoomEventDecryptionResult::UnableToDecrypt(info)) => Decryption::Undecryptable {
            reason: format!("{:?}", info.reason),
            session_id: info.session_id,
            raw,
        },
        Err(e) => {
            tracing::error!(error = ?e, "decryption failed with store error");
            Decryption::Untouched
        }
    }
}

async fn decrypt_event(
    ctx: &Arc<AccountContext>,
    room_id: &RoomId,
    event: &mut Value,
    placeholder: Placeholder,
) {
    match decrypt(ctx, room_id, event).await {
        Decryption::Decrypted(new_event) => *event = new_event,
        Decryption::Undecryptable {
            reason,
            session_id,
            raw,
        } => {
            let session_id = session_id.as_deref();
            tracing::debug!(%room_id, ?session_id, %reason, "unable to decrypt");
            maybe_request_room_key(ctx, room_id, &raw, session_id).await;
            let repairable = placeholder == Placeholder::Repairable;
            if repairable {
                ctx.repairs.track(room_id, event, session_id);
            }
            *event = utd_placeholder(event, &reason, session_id, repairable);
        }
        Decryption::Untouched => {}
    }
}

/// Feed decrypted in-room verification events to the verification machine so
/// `ctl verify` also works for in-room (other-user DM) flows.
async fn maybe_feed_verification(ctx: &Arc<AccountContext>, event: &Value) {
    let event_type = event.get("type").and_then(|v| v.as_str()).unwrap_or_default();
    let is_verification = event_type.starts_with("m.key.verification.")
        || (event_type == "m.room.message"
            && event.pointer("/content/msgtype").and_then(|v| v.as_str())
                == Some("m.key.verification.request"));
    if !is_verification {
        return;
    }
    match serde_json::from_value::<ruma::events::AnyMessageLikeEvent>(event.clone()) {
        Ok(parsed) => {
            if let Err(e) = ctx.olm.receive_verification_event(&parsed).await {
                tracing::warn!(error = ?e, "receive_verification_event failed");
            }
        }
        Err(e) => tracing::debug!(error = ?e, "unparsable in-room verification event"),
    }
}

/// Replace an undecryptable event with a readable m.room.message so ement
/// (which drops m.room.encrypted silently) shows *something*.
fn utd_placeholder(
    original: &Value,
    reason: &str,
    session_id: Option<&str>,
    repairable: bool,
) -> Value {
    let hint = if repairable {
        " This message will update in place if its key arrives."
    } else {
        ""
    };
    let mut placeholder = json!({
        "type": "m.room.message",
        "content": {
            "msgtype": "m.text",
            "body": format!("🔒 [undecryptable: {reason}]{hint}"),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utd_placeholder_preserves_envelope() {
        let original = json!({
            "type": "m.room.encrypted",
            "event_id": "$abc",
            "sender": "@alice:example.org",
            "origin_server_ts": 1234,
            "content": {"algorithm": "m.megolm.v1.aes-sha2", "ciphertext": "..."},
            "unsigned": {"transaction_id": "1-999", "age": 5},
        });
        let placeholder = utd_placeholder(&original, "MissingRoomKey", Some("sess"), true);
        assert_eq!(placeholder["type"], "m.room.message");
        assert_eq!(placeholder["event_id"], "$abc");
        assert_eq!(placeholder["sender"], "@alice:example.org");
        assert_eq!(placeholder["origin_server_ts"], 1234);
        // ement's local-echo resolution needs transaction_id to survive.
        assert_eq!(placeholder["unsigned"]["transaction_id"], "1-999");
        assert_eq!(placeholder["unsigned"]["ement_e2ee"]["utd"], true);
        assert!(
            placeholder["content"]["body"]
                .as_str()
                .unwrap()
                .contains("MissingRoomKey")
        );
    }

    #[test]
    fn utd_placeholder_copes_with_sparse_events() {
        // No unsigned, no session ID (e.g. a malformed event).
        let original = json!({ "type": "m.room.encrypted", "event_id": "$abc" });
        let placeholder = utd_placeholder(&original, "MalformedEncryptedEvent", None, false);
        assert_eq!(placeholder["event_id"], "$abc");
        assert_eq!(placeholder["content"]["msgtype"], "m.text");
        assert_eq!(placeholder["unsigned"]["ement_e2ee"]["utd"], true);
        assert!(placeholder["unsigned"]["ement_e2ee"]["session_id"].is_null());
        // Absent envelope fields are not invented.
        assert!(placeholder.get("sender").is_none());
        assert!(placeholder.get("origin_server_ts").is_none());
        // The ciphertext is dropped, not carried along.
        assert!(!placeholder.to_string().contains("ciphertext"));
    }

    #[test]
    fn utd_placeholder_keeps_room_id_for_history_endpoints() {
        let original = json!({
            "type": "m.room.encrypted",
            "event_id": "$abc",
            "room_id": "!room:example.org",
            "content": { "ciphertext": "..." },
        });
        let placeholder = utd_placeholder(&original, "MissingRoomKey", Some("sess"), false);
        assert_eq!(placeholder["room_id"], "!room:example.org");
        assert_eq!(placeholder["unsigned"]["ement_e2ee"]["session_id"], "sess");
    }

    #[test]
    fn utd_placeholder_only_promises_what_will_happen() {
        let original = json!({ "type": "m.room.encrypted", "event_id": "$abc" });
        let body = |repairable| {
            utd_placeholder(&original, "MissingRoomKey", None, repairable)["content"]["body"]
                .as_str()
                .unwrap()
                .to_owned()
        };
        assert!(body(true).contains("update in place"));
        // Notifications are never repaired: no such promise there.
        assert_eq!(body(false), "🔒 [undecryptable: MissingRoomKey]");
    }
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
            // The request sits in the machine's outgoing queue until marked
            // as sent; without the pump lock a concurrent pump sends it too.
            let _guard = ctx.pump_lock.lock().await;
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
