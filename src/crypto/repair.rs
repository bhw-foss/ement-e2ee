//! Late-key repair. The proxy is a pass-through: once ement has rendered an
//! "undecryptable" placeholder, a key that arrives later cannot rewrite it.
//! So remember the events that were delivered as placeholders and, when
//! their room key turns up, hand ement a synthetic `m.replace` edit through
//! its next /sync: ement swaps the placeholder for the real content in place.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};

use ruma::{OwnedRoomId, RoomId};
use serde_json::{Value, json};

use crate::crypto::decrypt::{self, Decryption};
use crate::session::AccountContext;

/// How many placeholders to remember per account. Beyond this the oldest
/// are forgotten; they still decrypt when the room's history is refetched.
const MAX_PENDING: usize = 2000;

/// An event the client was shown as a placeholder.
#[derive(Clone)]
pub struct PendingRepair {
    pub room_id: OwnedRoomId,
    pub event_id: String,
    pub session_id: Option<String>,
    /// The original m.room.encrypted event, as the homeserver sent it.
    pub event: Value,
}

#[derive(Default)]
struct Inner {
    pending: HashMap<String, PendingRepair>,
    /// Event IDs in arrival order, for bounding `pending`.
    order: VecDeque<String>,
    /// Megolm sessions whose key arrived since the last client sync.
    ready_sessions: HashSet<String>,
    /// Keys were imported in bulk (key file, backup): retry everything.
    retry_all: bool,
}

impl Inner {
    fn is_ready(&self, repair: &PendingRepair) -> bool {
        self.retry_all
            || repair
                .session_id
                .as_ref()
                .is_some_and(|id| self.ready_sessions.contains(id))
    }

    fn any_ready(&self) -> bool {
        self.pending.values().any(|repair| self.is_ready(repair))
    }
}

/// Per-account queue of placeholders awaiting their keys.
#[derive(Default)]
pub struct RepairQueue {
    inner: Mutex<Inner>,
    /// Signalled when a repair becomes possible, so a client /sync that is
    /// long-polling upstream can be answered right away.
    wake: tokio::sync::Notify,
}

impl RepairQueue {
    /// Remember an event that is being delivered as a placeholder.
    pub fn track(&self, room_id: &RoomId, event: &Value, session_id: Option<&str>) {
        let Some(event_id) = event.get("event_id").and_then(Value::as_str) else {
            return;
        };
        let mut inner = self.inner.lock().unwrap();
        if inner.pending.contains_key(event_id) {
            return;
        }
        inner.pending.insert(
            event_id.to_owned(),
            PendingRepair {
                room_id: room_id.to_owned(),
                event_id: event_id.to_owned(),
                session_id: session_id.map(ToOwned::to_owned),
                event: event.clone(),
            },
        );
        inner.order.push_back(event_id.to_owned());
        while inner.order.len() > MAX_PENDING {
            if let Some(oldest) = inner.order.pop_front() {
                inner.pending.remove(&oldest);
            }
        }
    }

    /// Room keys for these megolm sessions have just arrived.
    pub fn note_room_keys(&self, session_ids: impl IntoIterator<Item = String>) {
        let mut inner = self.inner.lock().unwrap();
        if inner.pending.is_empty() {
            return;
        }
        inner.ready_sessions.extend(session_ids);
        if inner.any_ready() {
            self.wake.notify_waiters();
        } else {
            // Keys nobody is waiting for: nothing to remember.
            inner.ready_sessions.clear();
        }
    }

    /// Many keys arrived at once (key import, backup restore).
    pub fn note_bulk_import(&self) {
        let mut inner = self.inner.lock().unwrap();
        if inner.pending.is_empty() {
            return;
        }
        inner.retry_all = true;
        self.wake.notify_waiters();
    }

    pub fn has_ready(&self) -> bool {
        self.inner.lock().unwrap().any_ready()
    }

    /// Resolves the next time a repair becomes possible.
    pub fn woken(&self) -> tokio::sync::futures::Notified<'_> {
        self.wake.notified()
    }

    /// Remove and return the placeholders whose keys should now be there.
    fn take_ready(&self) -> Vec<PendingRepair> {
        let mut inner = self.inner.lock().unwrap();
        let ready: Vec<String> = inner
            .pending
            .values()
            .filter(|repair| inner.is_ready(repair))
            .map(|repair| repair.event_id.clone())
            .collect();
        inner.ready_sessions.clear();
        inner.retry_all = false;
        // Oldest first, so repairs land in the timeline in a stable order.
        let mut taken = Vec::with_capacity(ready.len());
        let ready: HashSet<String> = ready.into_iter().collect();
        let mut order = std::mem::take(&mut inner.order);
        order.retain(|event_id| {
            if !ready.contains(event_id) {
                return true;
            }
            if let Some(repair) = inner.pending.remove(event_id) {
                taken.push(repair);
            }
            false
        });
        inner.order = order;
        taken
    }

    /// Put back a placeholder whose key turned out not to be there after all.
    fn requeue(&self, repair: PendingRepair) {
        let mut inner = self.inner.lock().unwrap();
        inner.order.push_back(repair.event_id.clone());
        inner.pending.insert(repair.event_id.clone(), repair);
    }

    /// Snapshot of what is waiting, for `ctl debug`.
    pub fn pending(&self) -> Vec<PendingRepair> {
        let inner = self.inner.lock().unwrap();
        inner
            .order
            .iter()
            .filter_map(|event_id| inner.pending.get(event_id).cloned())
            .collect()
    }
}

/// Decrypt the placeholders whose keys have arrived and append the
/// replacing edits to the client's /sync response.
pub async fn inject(ctx: &Arc<AccountContext>, body: &mut Value) -> usize {
    let ready = ctx.repairs.take_ready();
    if ready.is_empty() {
        return 0;
    }
    // Events this very response delivers (now decrypted) need no repair.
    let delivered = delivered_event_ids(body);

    let mut repaired = 0;
    for repair in ready {
        if delivered.contains(&repair.event_id) {
            continue;
        }
        let Decryption::Decrypted(plain) =
            decrypt::decrypt(ctx, &repair.room_id, &repair.event).await
        else {
            ctx.repairs.requeue(repair);
            continue;
        };
        let Some(edit) = synthetic_edit(&plain) else {
            continue;
        };
        if push_into_sync(ctx, body, &repair.room_id, edit) {
            repaired += 1;
            tracing::info!(room_id = %repair.room_id, event_id = %repair.event_id, "repaired placeholder with late key");
        }
    }
    repaired
}

fn delivered_event_ids(body: &Value) -> HashSet<String> {
    body.pointer("/rooms/join")
        .and_then(Value::as_object)
        .into_iter()
        .flat_map(|rooms| rooms.values())
        .filter_map(|room| room.pointer("/timeline/events")?.as_array())
        .flatten()
        .filter_map(|event| event.get("event_id")?.as_str())
        .map(ToOwned::to_owned)
        .collect()
}

/// Append an event to a joined room's timeline in a /sync body. Returns
/// false if the client is no longer in the room.
fn push_into_sync(ctx: &AccountContext, body: &mut Value, room_id: &RoomId, event: Value) -> bool {
    if !body.is_object() {
        return false;
    }
    let exists = body
        .pointer("/rooms/join")
        .and_then(Value::as_object)
        .is_some_and(|rooms| rooms.contains_key(room_id.as_str()));
    if !exists {
        // The homeserver had nothing to say about this room. ement replaces
        // a room's unread counts with whatever each room entry carries, so
        // an entry of our own must repeat the last ones it was given.
        let Some(unread) = ctx.rooms.last_unread_notifications(room_id) else {
            return false;
        };
        let mut entry = json!({ "timeline": { "events": [], "limited": false } });
        if let Some(unread) = unread {
            entry["unread_notifications"] = unread;
        }
        body["rooms"]["join"][room_id.as_str()] = entry;
    }
    let room = &mut body["rooms"]["join"][room_id.as_str()];
    if !room["timeline"]["events"].is_array() {
        room["timeline"]["events"] = json!([]);
    }
    room["timeline"]["events"]
        .as_array_mut()
        .expect("just ensured")
        .push(event);
    true
}

/// Build the event that makes the client replace a placeholder with the
/// decrypted event `plain`. The placeholder was an m.room.message carrying
/// the original event ID, so this is an `m.replace` edit of that ID with the
/// same sender and timestamp.
pub fn synthetic_edit(plain: &Value) -> Option<Value> {
    let event_id = plain.get("event_id")?.as_str()?;
    let event_type = plain.get("type")?.as_str()?;

    let mut new_content = match event_type {
        "m.room.message" => {
            let content = plain.get("content")?;
            // An edit of some other message: show what it changed the text to.
            let is_edit = content
                .pointer("/m.relates_to/rel_type")
                .and_then(Value::as_str)
                == Some("m.replace");
            match content.get("m.new_content") {
                Some(inner) if is_edit => inner.clone(),
                _ => content.clone(),
            }
        }
        // An edit cannot change an event's type; say what it was instead.
        "m.reaction" => {
            let key = plain
                .pointer("/content/m.relates_to/key")
                .and_then(Value::as_str)
                .unwrap_or("?");
            json!({ "msgtype": "m.notice", "body": format!("🔓 reacted with {key}") })
        }
        other => json!({
            "msgtype": "m.notice",
            "body": format!("🔓 [{other}] decrypted; reopen the room to render it"),
        }),
    };
    let new_content_object = new_content.as_object_mut()?;
    // A reply stays a reply; any other relation belongs to the original.
    let reply = new_content_object
        .remove("m.relates_to")
        .and_then(|relation| relation.get("m.in_reply_to").cloned());

    // ement renders an edit from its top-level msgtype/url/info and takes
    // the body from m.new_content, so carry the content in both places.
    let mut content = new_content.clone();
    content["m.new_content"] = new_content;
    content["m.relates_to"] = json!({ "rel_type": "m.replace", "event_id": event_id });
    if let Some(reply) = reply {
        content["m.relates_to"]["m.in_reply_to"] = reply;
    }

    let mut marker = plain
        .pointer("/unsigned/ement_e2ee")
        .cloned()
        .unwrap_or_else(|| json!({}));
    marker["repairs"] = event_id.into();

    let mut edit = json!({
        "type": "m.room.message",
        "event_id": format!("{event_id}~decrypted"),
        "content": content,
        "unsigned": { "ement_e2ee": marker },
    });
    for key in ["sender", "origin_server_ts", "room_id"] {
        if let Some(value) = plain.get(key) {
            edit[key] = value.clone();
        }
    }
    Some(edit)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn room() -> OwnedRoomId {
        "!room:example.org".parse().unwrap()
    }

    fn encrypted(event_id: &str) -> Value {
        json!({ "type": "m.room.encrypted", "event_id": event_id, "content": {} })
    }

    fn ids(repairs: &[PendingRepair]) -> Vec<&str> {
        repairs.iter().map(|r| r.event_id.as_str()).collect()
    }

    #[test]
    fn repairs_become_ready_when_their_session_key_arrives() {
        let queue = RepairQueue::default();
        queue.track(&room(), &encrypted("$a"), Some("session1"));
        queue.track(&room(), &encrypted("$b"), Some("session2"));
        queue.track(&room(), &encrypted("$c"), Some("session1"));
        assert!(!queue.has_ready());
        assert!(queue.take_ready().is_empty());

        queue.note_room_keys(["session1".to_owned()]);
        assert!(queue.has_ready());
        assert_eq!(ids(&queue.take_ready()), ["$a", "$c"]);
        // Taken once; the other session's event keeps waiting.
        assert!(!queue.has_ready());
        assert_eq!(ids(&queue.pending()), ["$b"]);
    }

    #[test]
    fn unrelated_keys_wake_nobody() {
        let queue = RepairQueue::default();
        // Nothing pending at all: the key is not even remembered, so an
        // event tracked afterwards is not considered ready by mistake.
        queue.note_room_keys(["session1".to_owned()]);
        queue.track(&room(), &encrypted("$a"), Some("session1"));
        assert!(!queue.has_ready());

        queue.note_room_keys(["other".to_owned()]);
        assert!(!queue.has_ready());
        assert_eq!(queue.pending().len(), 1);
    }

    #[test]
    fn bulk_import_retries_everything_including_sessionless_events() {
        let queue = RepairQueue::default();
        queue.track(&room(), &encrypted("$a"), Some("session1"));
        queue.track(&room(), &encrypted("$b"), None);
        queue.note_bulk_import();
        assert!(queue.has_ready());
        assert_eq!(ids(&queue.take_ready()), ["$a", "$b"]);
        // The retry is one-shot.
        queue.track(&room(), &encrypted("$c"), Some("session9"));
        assert!(!queue.has_ready());
    }

    #[test]
    fn failed_repairs_wait_for_the_next_key() {
        let queue = RepairQueue::default();
        queue.track(&room(), &encrypted("$a"), Some("session1"));
        queue.note_room_keys(["session1".to_owned()]);
        let taken = queue.take_ready();
        queue.requeue(taken.into_iter().next().unwrap());
        assert!(!queue.has_ready());
        queue.note_room_keys(["session1".to_owned()]);
        assert_eq!(ids(&queue.take_ready()), ["$a"]);
    }

    #[test]
    fn tracking_is_idempotent_and_bounded() {
        let queue = RepairQueue::default();
        queue.track(&room(), &encrypted("$a"), Some("first"));
        // Seen again (say via /messages): the first record stands.
        queue.track(&room(), &encrypted("$a"), Some("second"));
        assert_eq!(queue.pending().len(), 1);
        assert_eq!(queue.pending()[0].session_id.as_deref(), Some("first"));
        // Events without an ID cannot be targeted by an edit.
        queue.track(&room(), &json!({ "type": "m.room.encrypted" }), Some("s"));
        assert_eq!(queue.pending().len(), 1);

        for i in 0..MAX_PENDING + 5 {
            queue.track(&room(), &encrypted(&format!("$n{i}")), Some("s"));
        }
        let pending = queue.pending();
        assert_eq!(pending.len(), MAX_PENDING);
        assert_eq!(pending[0].event_id, "$n5");
    }

    fn plain_message(content: Value) -> Value {
        json!({
            "type": "m.room.message",
            "event_id": "$orig",
            "sender": "@alice:example.org",
            "origin_server_ts": 1234,
            "content": content,
            "unsigned": { "age": 5, "ement_e2ee": { "decrypted": true } },
        })
    }

    #[test]
    fn edit_replaces_the_placeholder_in_place() {
        let edit =
            synthetic_edit(&plain_message(json!({ "msgtype": "m.text", "body": "hi" }))).unwrap();
        assert_eq!(edit["type"], "m.room.message");
        // Its own ID, but the original's author and time: ement puts the
        // edit where the placeholder was and shows the original timestamp.
        assert_eq!(edit["event_id"], "$orig~decrypted");
        assert_eq!(edit["sender"], "@alice:example.org");
        assert_eq!(edit["origin_server_ts"], 1234);
        assert_eq!(
            edit["content"]["m.relates_to"],
            json!({ "rel_type": "m.replace", "event_id": "$orig" })
        );
        assert_eq!(
            edit["content"]["m.new_content"],
            json!({ "msgtype": "m.text", "body": "hi" })
        );
        // ement reads msgtype (and media fields) from the top level.
        assert_eq!(edit["content"]["msgtype"], "m.text");
        assert_eq!(edit["content"]["body"], "hi");
        assert_eq!(edit["unsigned"]["ement_e2ee"]["decrypted"], true);
        assert_eq!(edit["unsigned"]["ement_e2ee"]["repairs"], "$orig");
    }

    #[test]
    fn edit_keeps_media_and_reply_rendering() {
        let edit = synthetic_edit(&plain_message(json!({
            "msgtype": "m.image",
            "body": "cat.png",
            "url": "mxc://example.org/abc",
            "info": { "mimetype": "image/png" },
            "m.relates_to": { "m.in_reply_to": { "event_id": "$parent" } },
        })))
        .unwrap();
        let content = &edit["content"];
        assert_eq!(content["msgtype"], "m.image");
        assert_eq!(content["url"], "mxc://example.org/abc");
        assert_eq!(content["info"]["mimetype"], "image/png");
        assert_eq!(content["m.relates_to"]["rel_type"], "m.replace");
        assert_eq!(
            content["m.relates_to"]["m.in_reply_to"]["event_id"],
            "$parent"
        );
        // m.new_content itself carries no relation, per the spec.
        assert!(content["m.new_content"].get("m.relates_to").is_none());
        assert_eq!(content["m.new_content"]["url"], "mxc://example.org/abc");
    }

    #[test]
    fn edit_of_an_edit_shows_the_new_text() {
        let edit = synthetic_edit(&plain_message(json!({
            "msgtype": "m.text",
            "body": "* fixed",
            "m.new_content": { "msgtype": "m.text", "body": "fixed" },
            "m.relates_to": { "rel_type": "m.replace", "event_id": "$other" },
        })))
        .unwrap();
        assert_eq!(edit["content"]["m.new_content"]["body"], "fixed");
        assert_eq!(edit["content"]["body"], "fixed");
        // It replaces the placeholder, not the message the original edited.
        assert_eq!(edit["content"]["m.relates_to"]["event_id"], "$orig");
    }

    #[test]
    fn non_message_events_become_a_one_line_note() {
        let reaction = json!({
            "type": "m.reaction",
            "event_id": "$orig",
            "sender": "@alice:example.org",
            "origin_server_ts": 1,
            "content": {
                "m.relates_to": { "rel_type": "m.annotation", "event_id": "$target", "key": "👍" },
            },
        });
        let edit = synthetic_edit(&reaction).unwrap();
        assert_eq!(edit["type"], "m.room.message");
        assert_eq!(edit["content"]["msgtype"], "m.notice");
        assert_eq!(
            edit["content"]["m.new_content"]["body"],
            "🔓 reacted with 👍"
        );
        assert_eq!(edit["content"]["m.relates_to"]["event_id"], "$orig");

        let mut sticker = reaction.clone();
        sticker["type"] = "m.sticker".into();
        let edit = synthetic_edit(&sticker).unwrap();
        assert!(
            edit["content"]["body"]
                .as_str()
                .unwrap()
                .contains("[m.sticker]")
        );
    }

    #[test]
    fn events_without_identity_cannot_be_repaired() {
        assert!(synthetic_edit(&json!({ "type": "m.room.message", "content": {} })).is_none());
        assert!(synthetic_edit(&json!({ "event_id": "$a", "content": {} })).is_none());
        assert!(synthetic_edit(&json!({ "type": "m.room.message", "event_id": "$a" })).is_none());
    }

    #[test]
    fn delivered_ids_cover_all_joined_rooms() {
        let body = json!({
            "rooms": { "join": {
                "!a:hs": { "timeline": { "events": [{ "event_id": "$1" }, { "event_id": "$2" }] } },
                "!b:hs": { "timeline": { "events": [{ "event_id": "$3" }, {}] } },
                "!c:hs": {},
            } },
        });
        let ids = delivered_event_ids(&body);
        assert_eq!(ids.len(), 3);
        assert!(ids.contains("$3"));
        assert!(delivered_event_ids(&json!({ "next_batch": "s1" })).is_empty());
    }
}
